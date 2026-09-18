use super::overall_dial_timeout;
use super::routing::{build_connection_info, connection_chains};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

use futures::{FutureExt, StreamExt};
use std::collections::{HashMap, HashSet};

use crate::connection_tracker::{
    CloseAction, CloseCompletion, CloseSignal, ConnectionOwner, captured_groups,
};

async fn wait_for_close(close: Option<&CloseCompletion>) {
    match close {
        Some(close) => close.0.cancelled().await,
        None => std::future::pending().await,
    }
}
#[cfg(feature = "native-api")]
use crate::native_api::{
    catalog::CatalogIdentity,
    flows::FlowGuard,
    observation::{NativeAttempt, native_selection_path},
};

#[cfg(feature = "native-api")]
struct TcpNativeDial {
    flow: Arc<FlowGuard>,
    generation: u64,
    catalog: Arc<CatalogIdentity>,
    config: Arc<Config>,
    evaluation_id: Option<String>,
    routed_outbound: String,
    mode_override: &'static str,
}

#[cfg(feature = "native-api")]
impl TcpNativeDial {
    fn selected(&self, chain: &[String], node: &Node) {
        if matches!(
            node.protocol(),
            honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block
        ) {
            self.flow.selected(Vec::new());
            return;
        }
        let group_count = chain
            .len()
            .saturating_sub(usize::from(chain.last() == Some(&node.name)));
        let groups: Option<Vec<_>> = chain
            .iter()
            .take(group_count)
            .map(|name| self.catalog.groups.get(name).cloned())
            .collect();
        if let Some(mut chain) = groups {
            chain.push(node.id.to_string());
            self.flow.selected(chain);
        }
    }
}

#[cfg(feature = "native-api")]
fn native_tcp_target_kind(node: &Node, domain: Option<&str>) -> &'static str {
    match node.protocol() {
        honk_config::types::NodeProtocol::Block => "none",
        honk_config::types::NodeProtocol::Direct => "ip",
        _ if domain.is_some() => "domain",
        _ => "ip",
    }
}

mod dial;

async fn write_sniff_prefix(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    mut buffered: &[u8],
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    while !buffered.is_empty() {
        let written = stream.write(buffered).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        on_write(written);
        buffered = &buffered[written..];
    }
    Ok(())
}

type UnpackedTcpScorePlan = (
    Vec<Node>,
    SelectionPlanMode,
    HashMap<uuid::Uuid, crate::group::ScoreFeedback>,
    HashMap<uuid::Uuid, Vec<String>>,
    HashMap<uuid::Uuid, Vec<String>>,
    IpVersion,
);

struct TcpDnsRoute {
    decision: super::routing::RoutingDecision,
    config: Arc<Config>,
    group_manager: Arc<honk_outbound::group::GroupManager>,
    runtime: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    #[cfg(feature = "native-api")]
    native: Option<(u64, Arc<CatalogIdentity>)>,
}

fn tcp_score_context(
    target: SocketAddr,
    domain: Option<&str>,
    health_family: IpVersion,
) -> crate::group::ScoreSelectionContext {
    let target_family = if target.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    crate::group::ScoreSelectionContext {
        network: SelectionNetwork::Tcp,
        probe_domain: ProbeDomain::Tcp,
        target_family: Some(target_family),
        health_family,
        target: Some(match domain {
            Some(domain) => crate::group::ScoreTarget::domain(domain, target.port()),
            None => target.into(),
        }),
    }
}

fn unpack_tcp_score_plan(plan: crate::control::reload::ResolvedScorePlan) -> UnpackedTcpScorePlan {
    let mut seen = HashSet::new();
    let mut nodes = Vec::with_capacity(plan.nodes.len());
    let mut feedback = HashMap::new();
    let mut selection_chains = HashMap::new();
    let mut final_owners = HashMap::new();
    for (((node, value), selection_chain), used_final_owners) in plan
        .nodes
        .into_iter()
        .zip(plan.feedback)
        .zip(plan.selection_chains)
        .zip(plan.final_owners)
    {
        if !seen.insert(node.id) {
            continue;
        }
        if let Some(value) = value {
            feedback.insert(node.id, value);
        }
        selection_chains.insert(node.id, selection_chain);
        if !used_final_owners.is_empty() {
            final_owners.insert(node.id, used_final_owners);
        }
        nodes.push(node);
    }
    (
        nodes,
        plan.mode,
        feedback,
        selection_chains,
        final_owners,
        plan.health_family,
    )
}

fn timeout_started_score_reporters(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) {
    for reporter in reporters.lock().iter() {
        reporter.setup_failed(crate::group::ScoreOutcome::Timeout);
    }
}

#[cfg(test)]
fn started_score_reporter_count(
    reporters: &parking_lot::Mutex<Vec<crate::group::ScoreReporter>>,
) -> usize {
    reporters.lock().len()
}

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are dropped with their accepted connection owner.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}

impl ControlPlaneHandle {
    async fn pin_tcp_dns_route(
        &self,
        handoff: &super::handoff::HandoffResult,
    ) -> anyhow::Result<TcpDnsRoute> {
        let config = self.config.read().await;
        let backend = self.ebpf.read().await;
        anyhow::ensure!(
            handoff.routing_generation != 0
                && handoff.routing_generation == backend.routing_policy_generation(),
            "TCP DNS routing generation is stale"
        );
        let group = handoff
            .outbound
            .checked_sub(OutboundIndex::UserBase as u8)
            .filter(|_| handoff.outbound < OutboundIndex::MustRules as u8)
            .and_then(|index| config.groups.get(index as usize))
            .ok_or_else(|| anyhow::anyhow!("invalid terminal TCP DNS outbound"))?;
        let decision = super::routing::RoutingDecision {
            outbound: group.name.clone(),
            must: true,
            mark: handoff.mark,
            matched_rule: None,
            reroute_by_sniffed_domain: false,
            #[cfg(feature = "native-api")]
            native_route: None,
        };
        drop(backend);
        Ok(TcpDnsRoute {
            decision,
            config: Arc::clone(&config),
            group_manager: self.group_manager.read().clone(),
            runtime: self.runtime_registry.read().clone(),
            #[cfg(feature = "native-api")]
            native: self.native.as_ref().map(|native| {
                (
                    self.diagnostics.read().generation,
                    native.catalog.snapshot(),
                )
            }),
        })
    }

    pub(in crate::control) async fn serve_connection(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        debug!("TPROXY TCP connection from {}", client_addr);

        let original_dst = match get_original_dst(&stream) {
            Ok(d) => d,
            Err(e) => {
                // When the eBPF datapath delivers the SYN directly with
                // bpf_sk_assign(), the kernel does not set SO_ORIGINAL_DST.
                // The transparent socket's local address is the original
                // destination, so fall back to that.
                match stream.local_addr() {
                    Ok(d) => {
                        trace!(
                            "SO_ORIGINAL_DST unavailable for {} ({}); using local_addr {}",
                            client_addr, e, d
                        );
                        d
                    }
                    Err(le) => {
                        warn!(
                            "Failed to get original destination for {}: {}; local_addr also failed: {}",
                            client_addr, e, le
                        );
                        return Err(anyhow::anyhow!(
                            "original destination unavailable for {}: {} (local_addr: {})",
                            client_addr,
                            e,
                            le
                        ));
                    }
                }
            }
        };
        debug!("Original destination: {}", original_dst);
        #[cfg(feature = "native-api")]
        let native_flow = self.native.as_ref().and_then(|native| {
            let guard = native.flows.begin("tcp", client_addr, original_dst);
            (!guard.id().is_empty()).then(|| Arc::new(guard))
        });
        let close = self
            .connection_tracker
            .is_enabled()
            .then(|| CloseCompletion(CloseSignal::new()));
        let result = async {
        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            6, // TCP
        );
        let (mut flow, handoff) = self.adopt_tcp_flow(stream, tuples).await?;
        #[cfg(feature = "native-api")]
        if let (Some(native), Some(handoff)) = (&native_flow, &handoff) {
            native.update_input(
                None, None, handoff.process_name().as_deref(),
                (handoff.pid != 0).then_some(handoff.pid), handoff.mac_address(),
                Some(handoff.dscp), Some(handoff.mark),
            );
            native.step("input", None, serde_json::json!({
                "source": "kernel",
                "values": {
                    "src": client_addr.to_string(), "dst": original_dst.to_string(),
                    "domain": null, "domain_source": null, "pname": handoff.process_name(),
                    "pid": (handoff.pid != 0).then_some(handoff.pid), "process_path": null,
                    "src_mac": handoff.mac_address(), "ingress": null, "domain_rule_ids": null,
                    "dscp": (handoff.dscp <= 63).then_some(handoff.dscp), "mark": handoff.mark,
                },
            }));
        }
        #[cfg(feature = "native-api")]
        let kernel_evaluation_id = native_flow.as_ref().zip(handoff.as_ref()).map(|(native, handoff)| {
            let evaluation_id = uuid::Uuid::new_v4().to_string();
            let outbound = match handoff.outbound {
                x if x == OutboundIndex::Direct as u8 => Some("direct"),
                x if x == OutboundIndex::Block as u8 => Some("block"),
                _ => None,
            };
            native.step("route", None, serde_json::json!({
                "evaluation_id": evaluation_id, "chain": "traffic", "plane": "kernel",
                "rule_id": null, "rules": [], "outbound": outbound,
                "must": handoff.must != 0, "mark": handoff.mark,
                "input": null, "dns_action": null,
            }));
            evaluation_id
        });

        let pinned_dns_route = if original_dst.port() == 53 {
            let handoff = handoff
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("transparent TCP DNS has no routing handoff"))?;
            if handoff.outbound == OutboundIndex::Block as u8 {
                None
            } else if handoff.must != 0 {
                Some(self.pin_tcp_dns_route(handoff).await?)
            } else {
                self.dns_controller
                    .handle_tcp_dns(flow.stream_mut(), client_addr, original_dst)
                    .await?;
                #[cfg(feature = "native-api")]
                if let Some(native) = &native_flow {
                    native.finish("closed", "dns_intercept_completed");
                }
                return Ok(());
            }
        } else {
            None
        };

        #[cfg(feature = "native-api")]
        let dial_mode_generation;
        let (dial_mode, connect_timeout, overall_dial_timeout) = {
            let current_config;
            let config = if let Some(snapshot) = &pinned_dns_route {
                &snapshot.config
            } else {
                current_config = self.config.read().await;
                &*current_config
            };
            #[cfg(feature = "native-api")]
            {
                dial_mode_generation = if let Some(snapshot) = &pinned_dns_route {
                    snapshot.native.as_ref().map(|(generation, _)| *generation)
                } else {
                    native_flow.as_ref().map(|_| self.diagnostics.read().generation)
                };
            }
            let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
            (
                config
                    .global
                    .dial_mode
                    .parse::<DialMode>()
                    .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?,
                connect_timeout,
                overall_dial_timeout(connect_timeout),
            )
        };

        // Skip sniffing when the datapath already made a final decision.
        // In ip mode we always dial by original_dst.
        let mut skip_sniff = matches!(dial_mode, DialMode::Ip);
        if let Some(ref ho) = handoff {
            let final_handoff = matches!(
                ho.outbound,
                x if x == OutboundIndex::Direct as u8
                    || x == OutboundIndex::Block as u8
                    || x == OutboundIndex::MustRules as u8
            ) || (ho.must != 0
                && ho.outbound != OutboundIndex::ControlPlaneRouting as u8);
            if !skip_sniff && final_handoff {
                debug!(
                    "Skip TCP sniffing by final eBPF handoff for {} (outbound={})",
                    original_dst, ho.outbound
                );
                skip_sniff = true;
            }
            let cache_key = (original_dst, ho.outbound);
            let now = std::time::Instant::now();
            if !skip_sniff && self.tcp_sniff_neg_cache.should_skip_sniff(&cache_key, now) {
                debug!("Skip TCP sniffing by negative cache for {}", original_dst);
                skip_sniff = true;
            }
        }

        let sniff_result = if skip_sniff {
            sniffing::SniffResult::unknown()
        } else {
            sniffing::sniff_tcp(flow.stream_mut()).await
        };
        let sniffed_domain = sniff_result.domain.clone();
        if let Some(ref domain) = sniffed_domain {
            debug!("SNI sniffed domain: {}", domain);
        }
        #[cfg(feature = "native-api")]
        let domain_source = match &sniff_result.traffic_type {
            sniffing::TrafficType::Tls { sni: Some(_) } => Some("tls_sni"),
            sniffing::TrafficType::Http { host: Some(_) } => Some("http_host"),
            _ => None,
        };
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            native.update_input(
                sniff_result.domain.as_deref(), domain_source,
                handoff.as_ref().and_then(|ho| ho.process_name()).as_deref(),
                handoff.as_ref().and_then(|ho| (ho.pid != 0).then_some(ho.pid)),
                handoff.as_ref().and_then(|ho| ho.mac_address()),
                handoff.as_ref().map(|ho| ho.dscp), handoff.as_ref().map(|ho| ho.mark),
            );
        }
        let (domain, domain_verified, domain_verification) = self
            .apply_domain_reality_check(
                dial_mode,
                sniffed_domain,
                original_dst.ip(),
                client_addr,
            )
            .await;
        #[cfg(not(feature = "native-api"))]
        let _ = domain_verification;

        if !skip_sniff && let Some(ref ho) = handoff {
            let cache_key = (original_dst, ho.outbound);
            let now = std::time::Instant::now();
            if domain.is_some() {
                self.tcp_sniff_neg_cache.clear_sniff_negative(&cache_key);
            } else {
                self.tcp_sniff_neg_cache.note_sniff_failure(cache_key, now);
            }
        }

        let conn_info = build_connection_info(
            domain.clone(),
            original_dst,
            client_addr,
            "tcp",
            handoff.as_ref(),
        );
        #[cfg(feature = "native-api")]
        let mut pinned_native = pinned_dns_route.as_ref().and_then(|snapshot| snapshot.native.clone());
        let (route, pinned_generation) = if let Some(snapshot) = pinned_dns_route {
            (
                snapshot.decision,
                Some((snapshot.config, snapshot.group_manager, snapshot.runtime)),
            )
        } else {
            (
                self.prepare_routing(dial_mode, &conn_info, domain_verified, handoff.as_ref())
                    .await,
                None,
            )
        };
        #[cfg(feature = "native-api")]
        let native_route = route.native_route;
        #[cfg(feature = "native-api")]
        let native_evaluation_id = native_route.as_ref()
            .filter(|route| route.plane == "userspace")
            .map(|route| route.evaluation_id.clone())
            .or_else(|| kernel_evaluation_id.clone());
        #[cfg(feature = "native-api")]
        let native_routed_outbound = native_flow.as_ref().map(|_| route.outbound.clone());
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            if let Some(capture) = &native_route && capture.plane == "userspace" {
                native.step("route", capture.generation, serde_json::json!({
                    "evaluation_id": capture.evaluation_id, "chain": "traffic", "plane": capture.plane,
                    "rule_id": capture.rule_id, "rules": [], "outbound": route.outbound,
                    "must": route.must, "mark": route.mark, "input": capture.input, "dns_action": null,
                }));
            }
            native.step("reroute", native_route.as_ref().and_then(|capture| capture.generation), serde_json::json!({
                "performed": route.reroute_by_sniffed_domain,
                "reason": if route.reroute_by_sniffed_domain { "sniffed_domain" } else { "not_required" },
                "from_evaluation_id": kernel_evaluation_id,
                "to_evaluation_id": native_evaluation_id,
            }));
        }
        let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
        let matched_rule = route.matched_rule;
        let mode_decision = self.apply_mode_override(route.outbound, route.must).await;
        let outbound_name = mode_decision.name;
        let mode_constraint = mode_decision.constraint;
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            native.routed(&outbound_name,
                native_route.as_ref().and_then(|capture| capture.rule_id.as_deref()),
                native_route.as_ref().and_then(|capture| capture.rule_expression.as_deref()),
                if native_route.as_ref().is_some_and(|capture| capture.rule_id.is_some()) { "evaluation" } else { "unknown" });
        }

        // Seed current predicate facts so later flows need not repeat sniffing.
        if let Some(domain) = &domain
            && Self::should_write_sniffed_domain_bitmap(handoff.as_ref(), reroute_by_sniffed_domain)
        {
            self.push_sniffed_domain_bitmap(domain, original_dst.ip())
                .await;
        }

        // If eBPF already decided this flow should go direct (not just punted
        // it to userspace), skip userspace proxy dial, DNS, and relay entirely.
        // For ControlPlaneRouting handoffs we must relay in userspace even if
        // the final routing decision is direct, because eBPF has not installed
        // the flow state needed to forward the accepted socket.
        let ebpf_offload = outbound_name == "direct"
            && handoff
                .as_ref()
                .map(|ho| {
                    ho.outbound == OutboundIndex::Direct as u8
                        && ho.mark != 0
                        && ho.outbound != OutboundIndex::ControlPlaneRouting as u8
                })
                .unwrap_or(false);
        if ebpf_offload {
            debug!(
                network = "tcp",
                outbound = %outbound_name,
                ip = %original_dst,
                src = %client_addr,
                ebpf_offload = true,
                "TCP offloaded to eBPF: {} -> {}",
                client_addr,
                original_dst,
            );
            self.stats.record_connection(&outbound_name, crate::stats::OutboundKind::Builtin);
            self.stats.record_close(&outbound_name, crate::stats::OutboundKind::Builtin);
            #[cfg(feature = "native-api")]
            if let Some(native) = &native_flow {
                native.finish("unknown", "kernel_handoff");
            }
            return Ok(());
        }

        let ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (generation_config, generation_group_manager, runtime_generation) =
            if let Some(snapshot) = pinned_generation {
                snapshot
            } else {
                // Config's publication guard pins the group and runtime handles.
                let config = self.config.read().await;
                #[cfg(feature = "native-api")]
                if native_flow.is_some() || close.is_some() || mode_decision.group_id.is_some() {
                    pinned_native = self.native.as_ref().map(|native| {
                        (self.diagnostics.read().generation, native.catalog.snapshot())
                    });
                }
                (
                    Arc::clone(&config),
                    self.group_manager.read().clone(),
                    self.runtime_registry.read().clone(),
                )
            };
        #[cfg(feature = "native-api")]
        let mode_constraint = if mode_decision.group_id.as_ref().is_some_and(|expected| pinned_native.as_ref().and_then(|(_,catalog)|catalog.groups.get(&outbound_name)) != Some(expected)) {
            crate::control::reload::OutboundConstraint::Unavailable
        } else { mode_constraint };
        let outbound_kind = crate::stats::OutboundKind::routed(&generation_config, &outbound_name);
        let outbound_guard = self.stats.track_connection(&outbound_name, outbound_kind);
        #[cfg(feature = "native-api")]
        let close_catalog = pinned_native.as_ref().map(|(_, catalog)| Arc::clone(catalog));
        #[cfg(feature = "native-api")]
        let native_dial = native_flow.as_ref().map(|flow| {
            let (generation, catalog) = pinned_native.expect("native selection capture");
            let routed_outbound = native_routed_outbound.expect("native route capture");
            let mode_override = if routed_outbound == outbound_name {
                "none"
            } else if outbound_name == "direct" {
                "direct"
            } else {
                "global"
            };
            TcpNativeDial {
                flow: Arc::clone(flow), generation, catalog,
                config: Arc::clone(&generation_config),
                evaluation_id: native_evaluation_id,
                routed_outbound, mode_override,
            }
        });
        let (
            mut candidates,
            selection_mode,
            score_feedback,
            mut selection_chains,
            final_owners,
            health_ipver,
        ) = {
            let context = tcp_score_context(original_dst, domain.as_deref(), ipver);
            let plan = crate::control::reload::resolve_outbound_plan_for_target(&generation_config, &generation_group_manager, &outbound_name, &context, mode_constraint);
            unpack_tcp_score_plan(plan)
        };
        // Only an unmeasured URLTest group is allowed to speculate. Its
        // candidate set is bounded before spawning so a large group cannot
        // turn one client flow into an unbounded dial storm.
        if selection_mode == SelectionPlanMode::ColdUrlTest {
            candidates.truncate(3);
        } else {
            candidates.truncate(1);
        }

        if candidates.is_empty() {
            warn!(
                "No available candidate nodes for outbound '{}' ({})",
                outbound_name, client_addr
            );
            // Trigger emergency probes to recover dead nodes (leaf
            // expansion: sub-group tags carry no probe state).
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name, outbound_kind);
            drop(outbound_guard);
            #[cfg(feature = "native-api")]
            if let Some(native) = &native_flow {
                native.finish("failed", "no_available_nodes");
            }
            return Ok(());
        }

        // Domain targets are meaningful only for non-reserved proxy
        // outbounds. Direct and block always use the original IP.
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            domain.clone()
        };
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            let configured = match dial_mode {
                DialMode::Ip => "ip", DialMode::Domain => "domain",
                DialMode::DomainPlus => "domain+", DialMode::DomainPlusPlus => "domain++",
            };
            let target_kind = native_tcp_target_kind(&candidates[0], target_domain.as_deref());
            let target_kind = if candidates.iter().all(|node| native_tcp_target_kind(node, target_domain.as_deref()) == target_kind) {
                target_kind
            } else {
                "unknown"
            };
            native.step("dial_mode", dial_mode_generation, serde_json::json!({
                "configured": configured,
                "effective_target": target_kind,
                "domain": sniff_result.domain, "domain_source": domain_source,
                "verification": domain_verification,
                "reason": match target_kind { "none" => "policy_block", "domain" => "sniffed_domain", "ip" => "original_destination", _ => "candidate_dependent" },
            }));
        }

        let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
        let candidate_refs: Vec<&Node> = candidates.iter().collect();
        let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
        let raced = self
            .race_candidates(
                &candidate_refs,
                original_dst,
                target_domain.clone(),
                &outbound_name,
                outbound_kind,
                connect_timeout,
                dial_deadline,
                Arc::clone(&runtime_generation),
                health_ipver,
                &score_feedback,
                cold_urltest,
                #[cfg(feature = "native-api")]
                &selection_chains,
                #[cfg(feature = "native-api")]
                native_dial.as_ref(),
            )
            .await;
        let (mut proxy_stream, node, score_reporter) = match raced {
            Ok(Some(pair)) => pair,
            Err(error) => {
                drop(outbound_guard);
                return Err(error);
            }
            Ok(None) => {
                let mut retried = None;
                if selection_mode == SelectionPlanMode::Authoritative
                    && candidates.len() == 1
                    && matches!(mode_constraint, crate::control::reload::OutboundConstraint::Any)
                    && !runtime_generation.is_shutdown()
                {
                    let failed_node = candidates[0].id;
                    let context =
                        tcp_score_context(original_dst, target_domain.as_deref(), health_ipver);
                    let mut plan = crate::control::reload::resolve_urltest_retry_plan_for_target(
                        &generation_group_manager,
                        &outbound_name,
                        &context,
                    );
                    // URLTest retains its existing fresh retry-round budget.
                    let mut retry_deadline = tokio::time::Instant::now() + overall_dial_timeout;
                    if plan.nodes.is_empty()
                        && score_feedback.contains_key(&failed_node)
                        && tokio::time::Instant::now() < dial_deadline
                    {
                        plan = crate::control::reload::resolve_score_retry_plan_for_target(
                            &generation_group_manager,
                            &outbound_name,
                            &context,
                            failed_node,
                            final_owners
                                .get(&failed_node)
                                .map(Vec::as_slice)
                                .unwrap_or_default(),
                        );
                        retry_deadline = dial_deadline;
                    }
                    let (retry_nodes, _, retry_feedback, retry_chains, _, retry_health_ipver) =
                        unpack_tcp_score_plan(plan);
                    if retry_nodes.len() > 1
                        || retry_nodes
                            .first()
                            .is_some_and(|node| node.id != failed_node)
                    {
                        let nodes: Vec<_> = retry_nodes.iter().take(3).collect();
                        retried = match self
                            .race_candidates(
                                &nodes,
                                original_dst,
                                target_domain.clone(),
                                &outbound_name,
                                outbound_kind,
                                connect_timeout,
                                retry_deadline,
                                Arc::clone(&runtime_generation),
                                retry_health_ipver,
                                &retry_feedback,
                                false,
                                #[cfg(feature = "native-api")]
                                &retry_chains,
                                #[cfg(feature = "native-api")]
                                native_dial.as_ref(),
                            )
                            .await
                        {
                            Ok(retry) => retry,
                            Err(error) => {
                                drop(outbound_guard);
                                return Err(error);
                            }
                        };
                        #[cfg(feature = "native-api")]
                        if retried.is_none()
                            && retry_nodes.iter().take(3).all(|node| node.protocol() == honk_config::types::NodeProtocol::Block)
                            && let Some(native) = &native_flow
                        {
                            native.finish("blocked", "policy_block");
                        }
                        if retried.is_some() {
                            selection_chains = retry_chains;
                        }
                    }
                }
                match retried {
                    Some(pair) => pair,
                    None => {
                        drop(outbound_guard);
                        #[cfg(feature = "native-api")]
                        if let Some(native) = &native_flow {
                            if outbound_name == "block" || candidates.iter().all(|node| node.protocol() == honk_config::types::NodeProtocol::Block) {
                                native.finish("blocked", "policy_block");
                            } else {
                                native.finish("failed", "dial_failed");
                            }
                        }
                        return Ok(());
                    }
                }
            }
        };
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            if let Some(capture) = &native_dial {
                capture.selected(selection_chains.get(&node.id).map(Vec::as_slice).unwrap_or_default(), &node);
            }
            native.transition("active", "dial_succeeded", "transport_ready", None);
        }

        let dscp_val = handoff.as_ref().map(|ho| ho.dscp).unwrap_or(0);

        let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (outbound_upload, outbound_download) = self.stats.byte_counters(&outbound_name, outbound_kind);
        if let Some(close) = &close {
            let groups = captured_groups(
                selection_chains.get(&node.id).map(Vec::as_slice).unwrap_or_default(),
                &node.name,
                &generation_config,
                {
                    #[cfg(feature = "native-api")]
                    { close_catalog.as_ref().map(|catalog| &catalog.groups) }
                    #[cfg(not(feature = "native-api"))]
                    { None }
                },
            );
            if let Some(conn_id) = flow.track_if_enabled(|| {
                let id = uuid::Uuid::new_v4().to_string();
                let (rule, rule_payload) = matched_rule.unwrap_or_else(|| ("Fallback".to_string(), String::new()));
                crate::connection_tracker::ConnectionEntry {
                    id,
                    source: client_addr.to_string(),
                    destination: original_dst.to_string(),
                    proxy: node.name.clone(),
                    #[cfg(feature = "native-api")]
                    routed_outbound: self.connection_tracker.native_enabled().then(|| outbound_name.clone()),
                    #[cfg(feature = "native-api")]
                    native_flow_id: native_flow.as_ref().map(|flow| flow.id().to_owned()),
                    rule,
                    rule_payload,
                    chains: connection_chains(selection_chains.remove(&node.id).unwrap_or_default(), &node.name),
                    upload: conn_upload.clone(),
                    download: conn_download.clone(),
                    start_time: std::time::Instant::now(),
                    domain: target_domain.clone(),
                    network: "tcp".to_string(),
                    process: handoff.as_ref().and_then(|ho| ho.process_name()),
                    process_path: None,
                }
            }, ConnectionOwner { signal: Arc::clone(&close.0), action: CloseAction::Tcp, groups }) {
                #[cfg(feature = "native-api")]
                if let Some(native) = &native_flow { native.attach_connection(&conn_id); }
                self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
            }
        }

        debug!(
            network = "tcp",
            outbound = %outbound_name,
            dialer = %node.name,
            sniffed = target_domain.as_deref().unwrap_or(""),
            ip = %original_dst,
            dscp = dscp_val,
            src = %client_addr,
            "TCP connection: {} <-> {}", client_addr, original_dst,
        );

        let mut intentionally_closed = false;
        let prefix_result = tokio::select! {
            biased;
            _ = wait_for_close(close.as_ref()) => {
                intentionally_closed = true;
                Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "connection closed"))
            }
            result = write_sniff_prefix(
                &mut *proxy_stream.stream, &sniff_result.buffered, |bytes| {
                    conn_upload.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
                    outbound_upload.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
                    if let Some(reporter) = &score_reporter {
                        reporter.tx(bytes as u64);
                    }
                },
            ) => result,
        };
        match prefix_result {
            Ok(()) => {}
            Err(error) => {
                #[cfg(feature = "native-api")]
                if let Some(native) = &native_flow {
                    if intentionally_closed { native.finish("closed", "intentional_retirement"); }
                    else { native.finish("failed", "prefix_write_failed"); }
                }
                if !intentionally_closed {
                    warn!("Failed to write sniffed bytes to proxy: {}", error);
                    self.stats.record_error(&outbound_name, outbound_kind);
                }
                drop(outbound_guard);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(if intentionally_closed { crate::group::ScoreOutcome::Cancelled } else { crate::group::ScoreOutcome::Io(error.kind()) });
                }
                drop(proxy_stream);
                anyhow::ensure!(flow.retire().await, "TCP retirement failed");
                return Ok(());
            }
        };

        // Zero-copy fast path: a direct dial yields plain `TcpStream`s on
        // both ends, so relay through `splice(2)` (with automatic lossless
        // fallback to the copy relay when the kernel rejects it). TLS- or
        // protocol-wrapped proxy streams keep the userspace copy relay.
        // Both paths update the connection's live byte counters as data flows.
        let first_response = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move || reporter.first_response())
                as std::sync::Arc<dyn Fn() + Send + Sync>
        });
        #[cfg(feature = "native-api")]
        let first_response = match &native_flow {
            Some(native) => {
                let native = Arc::clone(native);
                Some(Arc::new(move || {
                    if let Some(callback) = &first_response { callback(); }
                    if native.first_reply() {
                        native.transition("active", "response_received", "first_reply", Some(true));
                    }
                }) as Arc<dyn Fn() + Send + Sync>)
            }
            None => first_response,
        };
        let on_transfer = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move |upload, download| {
                if upload != 0 {
                    reporter.tx(upload);
                }
                if download != 0 {
                    reporter.rx(download);
                }
            }) as std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>
        });
        let conn_progress = relay::RelayProgress {
            upload: conn_upload.clone(),
            download: conn_download.clone(),
            outbound_upload: Some(outbound_upload),
            outbound_download: Some(outbound_download),
            first_response,
            on_transfer,
        };
        let relay_result = tokio::select! {
            biased;
            _ = wait_for_close(close.as_ref()) => None,
            result = async { match proxy_stream.into_tcp_stream() {
                Ok(upstream) => relay::splice::relay_splice(
                    flow.stream_mut(), upstream, client_addr, original_dst, Some(conn_progress.clone()),
                ).await,
                Err(proxy_stream) => relay::splice::relay_auto(
                    flow.stream_mut(), proxy_stream.stream, client_addr, original_dst, Some(conn_progress),
                ).await,
            }} => Some(result),
        };
        let Some(relay_result) = relay_result else {
            if let Some(reporter) = &score_reporter {
                reporter.finish(crate::group::ScoreOutcome::Cancelled);
            }
            #[cfg(feature = "native-api")]
            if let Some(native) = &native_flow { native.finish("closed", "intentional_retirement"); }
            anyhow::ensure!(flow.retire().await, "TCP retirement failed");
            return Ok(());
        };
        #[cfg(feature = "native-api")]
        if let Some(native) = &native_flow {
            if relay_result.is_ok() {
                native.finish("closed", "relay_closed");
            } else {
                native.finish("failed", "relay_failed");
            }
        }
        anyhow::ensure!(flow.retire().await, "TCP retirement failed");

        match relay_result {
            Ok(_) => {
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Success);
                }
                drop(outbound_guard);

                // Deposit a fresh connection for future reuse. Ready-capable
                // handlers get a fully-dialed, target-bound stream (handshake
                // paid here, off the critical path); others get a bare TCP
                // to the proxy server.
                if outbound_name != "direct" && outbound_name != "block" {
                    let node = node.clone();
                    let node_addr = format!("{}:{}", node.host(), node.port);
                    let pool = self.connection_pool.clone();
                    let registry = self.proxy_registry.clone();
                    let target_domain = target_domain.clone();
                    let generation = Arc::clone(&runtime_generation);
                    let pool_feedback = score_reporter.as_ref().map(|reporter| {
                        reporter
                            .feedback()
                            .with_source(crate::group::ScoreSource::Warmup)
                    });
                    let pool_health_family = health_ipver;
                    let _ = runtime_generation.spawn_background(async move {
                        let (ready_capable, bare_capable) = registry
                            .find(node.protocol())
                            .map(|entry| {
                                (
                                    (entry.descriptor.pool_ready_streams)(&node),
                                    (entry.descriptor.pool_bare_tcp)(&node),
                                )
                            })
                            .unwrap_or((false, false));
                        if ready_capable {
                            let key = ConnectionPool::ready_key(
                                generation.generation(),
                                node.id,
                                original_dst,
                                target_domain.as_deref(),
                            );
                            // Only hot targets earn a speculative ready
                            // dial; a one-off flow gets none.
                            if !pool.note_target(generation.generation(), &key) {
                                return;
                            }
                            let pool_reporter =
                                pool_feedback.as_ref().map(|feedback| feedback.start());
                            match registry
                                .dial_runtime(
                                    Arc::clone(&generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                            {
                                Ok(stream) => {
                                    if generation.is_shutdown() {
                                        if let Some(reporter) = &pool_reporter {
                                            reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                        }
                                        return;
                                    }
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_succeeded();
                                        reporter.finish_setup_only();
                                    }
                                    pool.deposit_ready(generation.generation(), &key, stream)
                                        .await;
                                }
                                Err(e) => {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter
                                            .setup_failed(score_runtime_outcome(&generation, &e));
                                    }
                                    debug!(
                                        "Pool deposit: ready dial to {} via {} failed: {}",
                                        original_dst, node_addr, e
                                    );
                                }
                            }
                            return;
                        }
                        if !bare_capable {
                            // Multiplexed protocols pool whole sessions
                            // instead; a bare TCP is useless to them.
                            return;
                        }
                        let pool_reporter = pool_feedback.as_ref().map(|feedback| {
                            feedback
                                .clone()
                                .with_context(crate::group::ScoreSelectionContext::aggregate(
                                    SelectionNetwork::Tcp,
                                    ProbeDomain::Tcp,
                                    pool_health_family,
                                ))
                                .start()
                        });
                        match generation
                            .scope_dials(honk_outbound::util::connect_outbound(
                                &node_addr,
                                connect_timeout,
                            ))
                            .await
                        {
                            Ok(stream) => {
                                if generation.is_shutdown() {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.finish(crate::group::ScoreOutcome::Shutdown);
                                    }
                                    return;
                                }
                                if pool.deposit_tcp(&node_addr, stream).await {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_succeeded();
                                        reporter.finish_setup_only();
                                    }
                                } else {
                                    if let Some(reporter) = &pool_reporter {
                                        reporter.setup_failed(crate::group::ScoreOutcome::Io(
                                            std::io::ErrorKind::ConnectionReset,
                                        ));
                                    }
                                    debug!("Pool deposit: stream to {} is dead", node_addr);
                                }
                            }
                            Err(e) => {
                                if let Some(reporter) = &pool_reporter {
                                    reporter.setup_failed(if generation.is_shutdown() {
                                        crate::group::ScoreOutcome::Shutdown
                                    } else {
                                        crate::group::ScoreOutcome::Io(e.kind())
                                    });
                                }
                                debug!("Pool deposit: connect to {} failed: {}", node_addr, e);
                            }
                        }
                    });
                }
            }
            Err(e) => {
                let io_err = e.downcast_ref::<std::io::Error>();
                if let Some(io_err) = io_err {
                    if relay::is_ignorable_connection_error(io_err) {
                        debug!(
                            "TCP relay closed for {} -> {}: {}",
                            client_addr, original_dst, io_err
                        );
                    } else {
                        warn!("Relay error for {} -> {}: {}", client_addr, original_dst, e);
                    }
                } else {
                    warn!("Relay error for {} -> {}: {}", client_addr, original_dst, e);
                }
                self.stats.record_error(&outbound_name, outbound_kind);
                drop(outbound_guard);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::from_error(&e));
                }
            }
        }

        Ok(())
        }.await;
        if let Some(close) = &close {
            close.0.finish(result.is_ok());
        }
        #[cfg(feature = "native-api")]
        if result.is_err()
            && let Some(native) = &native_flow
        {
            native.finish("failed", "connection_failed");
        }
        result
    }
}

#[cfg(test)]
mod score_tests {
    use super::*;

    #[tokio::test]
    async fn sniff_prefix_reports_accepted_bytes_before_write_failure() {
        use tokio::io::AsyncReadExt;
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let mut accepted = 0;
        let (result, ()) = tokio::join!(
            write_sniff_prefix(&mut writer, b"prefix", |bytes| accepted += bytes),
            async move {
                let mut prefix = [0; 3];
                reader.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"pre");
                drop(reader);
            },
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(accepted, 3);
    }

    #[test]
    fn tcp_score_context_uses_target_family_not_health_family() {
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let context = tcp_score_context(target, Some("example.com"), IpVersion::V6);

        assert_eq!(context.target_family, Some(IpVersion::V4));
        assert_eq!(context.health_family, IpVersion::V6);
        assert_eq!(
            context.target,
            Some(crate::group::ScoreTarget::domain("example.com", 443))
        );
    }

    #[test]
    fn unpack_tcp_score_plan_deduplicates_shared_leaf_metadata() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "shared".into(),
            ..Default::default()
        };
        let plan = crate::control::reload::ResolvedScorePlan {
            mode: SelectionPlanMode::ColdUrlTest,
            nodes: vec![node.clone(), node],
            health_family: IpVersion::V4,
            feedback: vec![None, None],
            selection_chains: vec![
                vec!["outer".into(), "shared".into()],
                vec!["duplicate".into(), "shared".into()],
            ],
            final_owners: vec![Vec::new(), Vec::new()],
        };
        let (nodes, mode, feedback, selection_chains, _, family) = unpack_tcp_score_plan(plan);

        assert_eq!(nodes.len(), 1);
        assert_eq!(mode, SelectionPlanMode::ColdUrlTest);
        assert!(feedback.is_empty());
        assert_eq!(
            selection_chains[&nodes[0].id],
            ["outer".to_owned(), "shared".to_owned()]
        );
        assert_eq!(family, IpVersion::V4);
    }

    #[test]
    fn timeout_helper_finishes_started_reporter_before_abort_drop() {
        let nodes = [
            Node {
                id: uuid::Uuid::new_v4(),
                name: "a".into(),
                ..Default::default()
            },
            Node {
                id: uuid::Uuid::new_v4(),
                name: "b".into(),
                ..Default::default()
            },
        ];
        let group = honk_config::group::Group {
            name: "score".into(),
            policy: honk_config::group::GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        };
        let manager = crate::group::GroupManager::new(&[group], &nodes);
        let context = tcp_score_context("192.0.2.1:443".parse().unwrap(), None, IpVersion::V4);
        let feedback = manager
            .feedback_for_node(nodes[0].id, context.clone())
            .unwrap();
        let reporters = parking_lot::Mutex::new(vec![feedback.start()]);
        assert_eq!(started_score_reporter_count(&reporters), 1);
        timeout_started_score_reporters(&reporters);
        drop(reporters);

        assert_eq!(
            manager.selection_plan_for_target("score", &context).entries[0]
                .node
                .id,
            nodes[1].id
        );
    }
}

#[cfg(test)]
#[path = "cold_urltest_tests.rs"]
mod cold_urltest_tests;
#[cfg(test)]
#[path = "dial_permit_scope_tests.rs"]
mod dial_permit_scope_tests;

#[cfg(all(test, feature = "native-api"))]
#[path = "tcp_native_flow_tests.rs"]
mod tcp_native_flow_tests;

#[cfg(test)]
mod native_accounting_tests {
    use super::write_sniff_prefix;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn native_prefix_partial_failure_keeps_only_written_bytes() {
        let connection = AtomicU64::new(0);
        let outbound = AtomicU64::new(7);
        let (mut writer, mut reader) = tokio::io::duplex(3);
        let (result, received) = tokio::join!(
            write_sniff_prefix(&mut writer, b"abcdef", |bytes| {
                connection.fetch_add(bytes as u64, Ordering::Relaxed);
                outbound.fetch_add(bytes as u64, Ordering::Relaxed);
            }),
            async move {
                let mut received = [0; 3];
                reader.read_exact(&mut received).await.unwrap();
                drop(reader);
                received
            }
        );
        assert_eq!(&received, b"abc");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        assert_eq!(connection.load(Ordering::Relaxed), 3);
        assert_eq!(outbound.load(Ordering::Relaxed), 10);
    }
}
