use super::overall_dial_timeout;
#[cfg(feature = "ebpf")]
use super::routing::final_udp_rule_mark;
use super::routing::{RoutingDecision, build_connection_info, connection_chains};
use crate::control::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};

#[cfg(feature = "native-api")]
fn native_udp_target_kind(node: &Node, target_is_domain: bool) -> &'static str {
    match node.protocol() {
        honk_config::types::NodeProtocol::Direct => "ip",
        honk_config::types::NodeProtocol::Block => "none",
        _ if target_is_domain => "domain",
        _ => "ip",
    }
}

enum PreparedEndpointTransport {
    Flow(honk_outbound::proxy::PreparedUdpTransport),
    #[cfg(feature = "rprx")]
    Source(crate::control::udp_endpoint::VlessSourcePreparation),
}

enum CommittedEndpointTransport {
    Flow(Arc<dyn honk_outbound::proxy::PacketTransport>),
    #[cfg(feature = "rprx")]
    Source(crate::control::udp_endpoint::SourceAttachment),
}

#[cfg(feature = "rprx")]
fn vless_source_path(node: &Node, port: u16) -> Option<honk_config::node::VlessUdpPath> {
    let path = node.vless()?.udp_path(port)?;
    matches!(
        path,
        honk_config::node::VlessUdpPath::Xudp
            | honk_config::node::VlessUdpPath::CoolShared
            | honk_config::node::VlessUdpPath::CoolSeparate
    )
    .then_some(path)
}

impl ControlPlaneHandle {
    pub(in crate::control) async fn serve_udp_connection(
        &self,
        lease: UdpInitLease,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "ebpf")]
        let pending_cleanup = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        #[cfg(feature = "native-api")]
        let mut native_flow = self.native.as_ref().and_then(|native| {
            let flow = native
                .flows
                .begin("udp", lease.client_addr(), lease.original_dst());
            (!flow.id().is_empty()).then(|| Arc::new(flow))
        });
        let cancellation = lease.wait_cancellation();
        tokio::select! {
            _ = cancellation => {
                #[cfg(feature = "native-api")]
                if let Some(flow) = &native_flow {
                    flow.finish("failed", "initializer_cancelled");
                }
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup {
                    verdicts.cancel(*identity).await?;
                }
                Ok(())
            }
            result = self.initialize_udp_connection(
                lease,
                #[cfg(feature = "native-api")]
                &mut native_flow,
            ) => {
                let Err(error) = result else {
                    return Ok(());
                };
                #[cfg(feature = "native-api")]
                if let Some(flow) = &native_flow {
                    flow.finish("failed", "setup_failed");
                }
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup
                    && let Err(cancel_error) = verdicts.cancel(*identity).await
                {
                    return Err(error.context(format!(
                        "staged UDP cleanup also failed: {cancel_error}"
                    )));
                }
                Err(error)
            }
        }
    }

    async fn initialize_udp_connection(
        &self,
        mut lease: UdpInitLease,
        #[cfg(feature = "native-api")] native_flow: &mut Option<
            Arc<crate::native_api::flows::FlowGuard>,
        >,
    ) -> anyhow::Result<()> {
        let client_addr = lease.client_addr();
        let original_dst = lease.original_dst();
        let data = lease.first_payload();
        let raw_dns_group = lease.raw_dns_group();
        #[cfg(feature = "ebpf")]
        let pending = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        debug!(
            "UDP datagram from {} -> {} ({} bytes, decision token {})",
            client_addr,
            original_dst,
            data.len(),
            lease.decision_token()
        );

        let dial_mode = if raw_dns_group.is_some() {
            anyhow::ensure!(
                original_dst.port() == 53 && lease.decision_token() == 0,
                "raw DNS ownership requires an unstaged UDP/53 lease"
            );
            DialMode::Ip
        } else {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?
        };

        // A staged early exit must retire its held originals immediately.
        if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
            #[cfg(feature = "native-api")]
            if let Some(flow) = native_flow.as_ref() {
                flow.finish("failed", "internal_address_skipped");
            }
            trace!(
                "Skipping honk-internal UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }
        if is_broadcast_or_multicast(&original_dst.ip()) {
            #[cfg(feature = "native-api")]
            if let Some(flow) = native_flow.as_ref() {
                flow.finish("failed", "special_address_skipped");
            }
            trace!(
                "Skipping broadcast/multicast UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }

        let handoff = if raw_dns_group.is_some() {
            None
        } else {
            let tuples = build_tuples_key(
                original_dst.ip(),
                original_dst.port(),
                client_addr.ip(),
                client_addr.port(),
                17, // UDP
            );
            self.lookup_udp_handoff(&tuples, lease.decision_token())
                .await?
        };
        #[cfg(feature = "native-api")]
        if let (Some(flow), Some(handoff)) = (native_flow.as_ref(), handoff.as_ref()) {
            flow.step(
                "input",
                None,
                serde_json::json!({
                    "source": "kernel",
                    "values": {
                        "src": client_addr.to_string(), "dst": original_dst.to_string(),
                        "domain": null, "domain_source": null, "pname": handoff.process_name(),
                        "pid": (handoff.pid != 0).then_some(handoff.pid), "process_path": null,
                        "src_mac": handoff.mac_address(), "ingress": null, "domain_rule_ids": null,
                        "dscp": handoff.dscp, "mark": handoff.mark,
                    },
                }),
            );
        }
        let skip_sniff = matches!(dial_mode, DialMode::Ip)
            || handoff.as_ref().is_some_and(|ho| {
                ho.must != 0
                    || matches!(
                        ho.outbound,
                        x if x == OutboundIndex::Direct as u8
                            || x == OutboundIndex::Block as u8
                            || x == OutboundIndex::MustRules as u8
                    )
            });
        let mut follower_rx = None;
        let mut sniffed_followers = Vec::new();
        let quic_domain: Option<String> = if skip_sniff {
            None
        } else {
            use crate::control::packet_sniffer::QuicSniffOutcome;
            let sniffer_key =
                crate::control::packet_sniffer::PacketSnifferKey::new(client_addr, original_dst);
            let mut outcome = self.sniffer_pool.feed_quic_initial(sniffer_key, &data);
            // A fragmented ClientHello: collect the rest of the Initial
            // flight before deciding which outbound owns the flow.
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                follower_rx = lease.take_queue_receiver();
                if let Some(rx) = follower_rx.as_mut() {
                    (outcome, sniffed_followers) =
                        self.collect_initial_fragments(sniffer_key, rx).await;
                }
            }
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                #[cfg(feature = "native-api")]
                if let Some(flow) = native_flow.as_ref() {
                    flow.finish("failed", "quic_sniff_incomplete");
                }
                debug!(
                    "QUIC ClientHello unresolved within budget; dropping for retransmit {} -> {}",
                    client_addr, original_dst
                );
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending {
                    verdicts.cancel(*identity).await?;
                }
                return Ok(());
            }
            outcome.into_domain()
        };
        #[cfg(feature = "native-api")]
        if let Some(flow) = native_flow.as_ref() {
            flow.update_input(
                quic_domain.as_deref(),
                quic_domain.as_ref().map(|_| "quic_sni"),
                handoff
                    .as_ref()
                    .and_then(|handoff| handoff.process_name())
                    .as_deref(),
                handoff
                    .as_ref()
                    .and_then(|handoff| (handoff.pid != 0).then_some(handoff.pid)),
                handoff.as_ref().and_then(|handoff| handoff.mac_address()),
                handoff.as_ref().map(|handoff| handoff.dscp),
                handoff.as_ref().map(|handoff| handoff.mark),
            );
        }
        let (quic_domain, domain_verified, _native_verification) = self
            .apply_domain_reality_check(dial_mode, quic_domain, original_dst.ip(), client_addr.ip())
            .await;

        let route_started_at = std::time::Instant::now();
        let route = if let Some(raw_dns_group) = raw_dns_group.as_deref() {
            RoutingDecision {
                outbound: raw_dns_group.to_owned(),
                must: true,
                mark: 0,
                matched_rule: None,
                reroute_by_sniffed_domain: false,
                #[cfg(feature = "native-api")]
                native_route: None,
            }
        } else {
            let conn_info = build_connection_info(
                quic_domain.clone(),
                original_dst,
                client_addr,
                "udp",
                handoff.as_ref(),
            );
            self.prepare_routing(dial_mode, &conn_info, domain_verified, handoff.as_ref())
                .await
        };
        #[cfg(feature = "native-api")]
        let native_route = route.native_route;
        #[cfg(feature = "native-api")]
        let native_routed_outbound = native_flow.as_ref().map(|_| route.outbound.clone());
        #[cfg(feature = "native-api")]
        if let Some(flow) = native_flow.as_ref() {
            if let Some(capture) = &native_route {
                flow.step("route", capture.generation, serde_json::json!({
                    "evaluation_id": capture.evaluation_id, "chain": "traffic", "plane": capture.plane,
                    "rule_id": null, "rules": [], "outbound": route.outbound, "must": route.must,
                    "mark": route.mark, "input": capture.input, "dns_action": null,
                }));
            }
            flow.step("reroute", native_route.as_ref().and_then(|route| route.generation), serde_json::json!({
                "performed": route.reroute_by_sniffed_domain, "reason": "sniff_routing_decision",
                "from_evaluation_id": null,
                "to_evaluation_id": if route.reroute_by_sniffed_domain {
                    native_route.as_ref().map(|route| route.evaluation_id.as_str())
                } else { None },
            }));
        }
        #[cfg(feature = "ebpf")]
        let reroute_by_sniffed_domain = route.reroute_by_sniffed_domain;
        #[cfg(feature = "ebpf")]
        let routed_direct = route.outbound == "direct";
        let routed_mark = route.mark;
        let matched_rule = route.matched_rule;
        let outbound_name = self.apply_mode_override(route.outbound, route.must).await;
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            quic_domain.as_deref().map(Arc::<str>::from)
        };
        let target_is_domain = target_domain.is_some();
        #[cfg(feature = "native-api")]
        if let Some(flow) = native_flow.as_ref() {
            flow.routed(&outbound_name, None, "unknown");
            flow.step("dial_mode", native_route.as_ref().and_then(|route| route.generation), serde_json::json!({
                "configured": dial_mode,
                "effective_target": match outbound_name.as_str() { "block" => "none", "direct" => "ip", _ => "unknown" },
                "domain": quic_domain,
                "domain_source": quic_domain.as_ref().map(|_| "quic_sni"),
                "verification": _native_verification,
                "reason": "dial_mode_applied",
            }));
            if outbound_name == "block" {
                flow.finish("blocked", "routing_block");
            }
        }
        #[cfg(feature = "ebpf")]
        let final_rule_mark = final_udp_rule_mark(routed_direct, &outbound_name, routed_mark);
        #[cfg(not(feature = "ebpf"))]
        let _ = routed_mark;
        self.stats
            .record_udp_route_latency(route_started_at.elapsed());
        #[cfg(feature = "ebpf")]
        if let Some((verdicts, identity)) = &pending {
            match outbound_name.as_str() {
                "direct" => {
                    verdicts
                        .activate_direct(*identity, &mut lease, final_rule_mark)
                        .await?;
                    if let Some(domain) = &quic_domain
                        && Self::should_write_sniffed_domain_bitmap(
                            handoff.as_ref(),
                            reroute_by_sniffed_domain,
                        )
                    {
                        self.push_sniffed_domain_bitmap(domain, original_dst.ip())
                            .await;
                    }
                    debug!(
                        network = "udp",
                        outbound = %outbound_name,
                        ip = %original_dst,
                        src = %client_addr,
                        sniffed = quic_domain.as_deref().unwrap_or(""),
                        ebpf_offload = true,
                        "UDP offloaded to eBPF: {} -> {}",
                        client_addr,
                        original_dst,
                    );
                    #[cfg(feature = "native-api")]
                    if let Some(flow) = native_flow.as_ref() {
                        flow.finish("unknown", "kernel_handoff");
                    }
                    return Ok(());
                }
                "block" => {
                    verdicts.block(*identity, &mut lease).await?;
                    return Ok(());
                }
                _ => {
                    let final_outbound = self.outbound_name_to_index(&outbound_name).await;
                    verdicts
                        .activate_proxy(*identity, &lease, final_outbound, final_rule_mark)
                        .await?;
                }
            }
        }
        let requested_ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        #[cfg(feature = "native-api")]
        let mut native_plan = None;
        let (plan, selection_chains, outbound_kind) = {
            let config = self.config.read().await;
            #[cfg(feature = "native-api")]
            let native_identity = native_flow
                .as_ref()
                .and(self.native.as_ref())
                .map(|native| {
                    (
                        self.diagnostics.read().generation,
                        native.catalog.snapshot(),
                    )
                });
            let gm = self.group_manager.read();
            let plan = crate::control::reload::resolve_udp_outbound_plan_for_target(
                &config,
                &gm,
                &outbound_name,
                &crate::group::ScoreSelectionContext {
                    network: SelectionNetwork::Udp,
                    probe_domain: ProbeDomain::DataUdp,
                    target_family: Some(requested_ipver),
                    health_family: requested_ipver,
                    target: Some(match target_domain.as_deref() {
                        Some(domain) => {
                            crate::group::ScoreTarget::domain(domain, original_dst.port())
                        }
                        None => original_dst.into(),
                    }),
                },
            );
            let selection_chains = plan.selection_chains.clone();
            #[cfg(feature = "native-api")]
            if let Some((generation, catalog)) = native_identity {
                let paths: Vec<_> = plan
                    .nodes
                    .iter()
                    .zip(&selection_chains)
                    .map(|(node, chain)| {
                        crate::native_api::observation::native_selection_path(
                            &config, &catalog, chain, node,
                        )
                    })
                    .collect();
                native_plan = Some(Arc::new((generation, catalog, paths)));
            }
            let kind = crate::stats::OutboundKind::routed(&config, &outbound_name);
            (plan, selection_chains, kind)
        };
        let outbound_tracker = self.stats.outbound_tracker(&outbound_name, outbound_kind);
        // The same accounting identity survives candidate selection and driver publication.
        lease.set_connection_guard(self.stats.track_outbound(outbound_tracker.clone()));

        if plan.nodes.is_empty() {
            warn!(
                "No available candidate nodes for UDP outbound '{}' ({})",
                outbound_name, client_addr
            );
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            outbound_tracker.increment_errors();
            #[cfg(feature = "native-api")]
            if let Some(flow) = native_flow.as_ref() {
                flow.finish("failed", "no_available_candidate");
            }
            return Ok(());
        }
        let all_block = plan
            .nodes
            .iter()
            .all(|node| node.protocol() == honk_config::types::NodeProtocol::Block);

        let (connect_timeout, transport_deadline) = {
            let config = self.config.read().await;
            let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
            (
                connect_timeout,
                tokio::time::Instant::now() + overall_dial_timeout(connect_timeout),
            )
        };

        // Cold URLTest preparation owns no endpoint state: no lease binding,
        // reply socket, driver, tracker, or application packet exists until
        // a single eligible transport winner has been drained and accepted.
        let scheduler_ipver = plan.ipver;
        let plan_mode = plan.mode;
        let score_feedback = plan.feedback;
        let runtime_generation = self.runtime_registry.read().clone();
        let prepare_generation = Arc::clone(&runtime_generation);
        let prepare: UdpPrepare<(
            PreparedEndpointTransport,
            Option<crate::group::ScoreReporter>,
            Vec<String>,
        )> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            let feedback = score_feedback.clone();
            #[cfg(feature = "rprx")]
            let udp_pool = Arc::clone(&self.udp_pool);
            #[cfg(feature = "rprx")]
            let alive_set = Arc::clone(&self.alive_set);
            let target_domain = target_domain.clone();
            #[cfg(feature = "native-api")]
            let native_flow = native_flow.clone();
            #[cfg(feature = "native-api")]
            let native_plan = native_plan.clone();
            #[cfg(feature = "native-api")]
            let native_evaluation = native_route
                .as_ref()
                .map(|route| route.evaluation_id.clone());
            #[cfg(feature = "native-api")]
            let native_outbound = native_flow.as_ref().map(|_| outbound_name.clone());
            Arc::new(move |index: usize, node: Node| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&prepare_generation);
                let feedback = feedback.get(index).cloned().flatten();
                let selection_chain = selection_chains.get(index).cloned().unwrap_or_default();
                #[cfg(feature = "rprx")]
                let udp_pool = Arc::clone(&udp_pool);
                #[cfg(feature = "rprx")]
                let alive_set = Arc::clone(&alive_set);
                let target_domain = target_domain.clone();
                #[cfg(feature = "native-api")]
                let native_flow = native_flow.clone();
                #[cfg(feature = "native-api")]
                let native_plan = native_plan.clone();
                #[cfg(feature = "native-api")]
                let native_evaluation = native_evaluation.clone();
                #[cfg(feature = "native-api")]
                let native_routed_outbound = native_routed_outbound.clone();
                #[cfg(feature = "native-api")]
                let native_outbound = native_outbound.clone();
                Box::pin(async move {
                    #[cfg(feature = "native-api")]
                    let mut native_attempt = native_flow.as_ref().map(|flow| {
                        let target_kind = native_udp_target_kind(&node, target_is_domain);
                        crate::native_api::observation::NativeAttempt::new(
                            Arc::clone(flow), native_plan.as_ref().map(|plan| plan.0),
                            serde_json::json!({
                                "parent_attempt_id": null, "kind": "leaf",
                                "evaluation_id": native_evaluation,
                                "routing_source": if native_evaluation.is_some() { "evaluation" } else { "forced" },
                                "routed_outbound": native_routed_outbound,
                                "effective_outbound": native_outbound,
                                "mode_override": if native_routed_outbound == native_outbound { "none" }
                                    else if native_outbound.as_deref() == Some("direct") { "direct" } else { "global" },
                                "selection_path": native_plan.as_ref().and_then(|plan| plan.2.get(index)).cloned().unwrap_or_default(),
                                "leaf_node_id": node.id.to_string(), "leaf_node_name": node.name,
                                "target": match target_kind {
                                    "none" => None,
                                    "domain" => target_domain.as_deref().map(|domain| format!("{domain}:{}", original_dst.port())),
                                    _ => Some(original_dst.to_string()),
                                },
                                "target_kind": target_kind,
                                "dial_ip": (node.protocol() == honk_config::types::NodeProtocol::Direct).then(|| original_dst.ip().to_string()),
                                "server_addr": null,
                                "resolution_location": match node.protocol() {
                                    honk_config::types::NodeProtocol::Direct => "original_ip",
                                    honk_config::types::NodeProtocol::Block => "not_applicable",
                                    _ => "unknown",
                                },
                            }),
                        )
                    });
                    let reporter = feedback.map(|feedback| feedback.start());
                    let dial_started_at = std::time::Instant::now();
                    let result = {
                        #[cfg(feature = "rprx")]
                        if let Some(path) = vless_source_path(&node, original_dst.port()) {
                            let runtime = runtime_generation.get(&node.id).ok_or_else(|| {
                                #[cfg(feature = "native-api")]
                                if let Some(attempt) = &mut native_attempt {
                                    attempt.finish("failed", Some("runtime_generation_missing"));
                                }
                                anyhow::anyhow!(
                                    "node {} is not in the captured runtime generation",
                                    node.id
                                )
                            })?;
                            udp_pool
                                .prepare_vless_source(
                                    Arc::clone(&runtime_generation),
                                    runtime,
                                    client_addr,
                                    path,
                                    target_is_domain.then_some(original_dst),
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                    Arc::clone(&alive_set),
                                    Arc::clone(&stats),
                                    scheduler_ipver,
                                )
                                .await
                                .map(PreparedEndpointTransport::Source)
                        } else if plan_mode == SelectionPlanMode::ColdUrlTest {
                            registry
                                .dial_udp_transport_speculative(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(PreparedEndpointTransport::Flow)
                        } else {
                            registry
                                .dial_udp_transport_runtime(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(honk_outbound::proxy::PreparedUdpTransport::ready)
                                .map(PreparedEndpointTransport::Flow)
                        }
                        #[cfg(not(feature = "rprx"))]
                        if plan_mode == SelectionPlanMode::ColdUrlTest {
                            registry
                                .dial_udp_transport_speculative(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(PreparedEndpointTransport::Flow)
                        } else {
                            registry
                                .dial_udp_transport_runtime(
                                    Arc::clone(&runtime_generation),
                                    node.id,
                                    original_dst,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                                .map(honk_outbound::proxy::PreparedUdpTransport::ready)
                                .map(PreparedEndpointTransport::Flow)
                        }
                    };
                    #[cfg(feature = "native-api")]
                    if let Some(attempt) = &mut native_attempt {
                        match &result {
                            Ok(_) => attempt.finish("succeeded", None),
                            Err(_) => attempt.finish("failed", Some("udp_prepare_failed")),
                        }
                    }
                    stats.record_udp_dial_latency(dial_started_at.elapsed());
                    match result {
                        Ok(transport) => Ok((transport, reporter, selection_chain)),
                        Err(error) => {
                            if let Some(reporter) = &reporter {
                                reporter.setup_failed(score_runtime_outcome(
                                    &runtime_generation,
                                    &error,
                                ));
                            }
                            Err(error)
                        }
                    }
                })
            })
        };
        let callbacks = UdpStaggerCallbacks {
            allows_target: Arc::new(move |node| {
                honk_outbound::descriptor::udp_target_allowed(node, original_dst.port())
            }),
            is_eligible: {
                let group_manager = self.group_manager.clone();
                Arc::new(move |node| {
                    group_manager.read().is_node_selectable_for_domain(
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                let runtime_generation = Arc::clone(&runtime_generation);
                Arc::new(move |node| {
                    report_dial_failure_if_current(
                        &runtime_generation,
                        &alive_set,
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    );
                })
            },
            on_attempt: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_attempt())
            },
            on_winner: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_winner())
            },
            on_cancellation: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_cancellation())
            },
        };
        #[cfg(feature = "native-api")]
        if let Some(flow) = native_flow.as_ref() {
            flow.transition("dialing", "udp_prepare_started", "unknown", Some(false));
        }
        let Some((node, (prepared_transport, score_reporter, selection_chain))) = prepare_udp_plan(
            plan_mode,
            plan.nodes,
            transport_deadline,
            prepare,
            callbacks,
        )
        .await?
        else {
            debug!(
                "All UDP transport preparations failed for '{}'",
                outbound_name
            );
            if !all_block {
                outbound_tracker.increment_errors();
            }
            #[cfg(feature = "native-api")]
            if let Some(flow) = native_flow.as_ref() {
                if all_block {
                    flow.selected(Vec::new());
                    flow.finish("blocked", "policy_block");
                } else {
                    flow.finish("failed", "udp_prepare_failed");
                }
            }
            return Ok(());
        };
        #[cfg(feature = "native-api")]
        if let (Some(flow), Some(plan)) = (native_flow.as_ref(), native_plan.as_ref()) {
            flow.step("dial_mode", Some(plan.0), serde_json::json!({
                "configured": dial_mode, "effective_target": native_udp_target_kind(&node, target_is_domain),
                "domain": quic_domain, "domain_source": quic_domain.as_ref().map(|_| "quic_sni"),
                "verification": _native_verification, "reason": "leaf_target_selected",
            }));
            if matches!(
                node.protocol(),
                honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block
            ) {
                flow.selected(Vec::new());
            } else {
                let group_count = selection_chain
                    .len()
                    .saturating_sub(usize::from(selection_chain.last() == Some(&node.name)));
                let groups: Option<Vec<_>> = selection_chain
                    .iter()
                    .take(group_count)
                    .map(|name| plan.1.groups.get(name).cloned())
                    .collect();
                if let Some(mut chain) = groups {
                    chain.push(node.id.to_string());
                    flow.selected(chain);
                }
            }
        }

        // The prepared winner is bound only after every speculative loser has
        // been aborted/drained. Close the death-before-bind race again before
        // creating endpoint state or allowing the driver to send.
        if !lease.bind_selected_node(node.id) {
            if let Some(reporter) = &score_reporter {
                reporter.finish(crate::group::ScoreOutcome::Cancelled);
            }
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before winner bind"
            ));
        }
        if !lease.still_initializing()
            || !self.group_manager.read().is_node_selectable_for_domain(
                node.id,
                ProbeDomain::DataUdp,
                scheduler_ipver,
            )
        {
            lease.clear_selected_node();
            if let Some(reporter) = &score_reporter {
                reporter.finish(crate::group::ScoreOutcome::Cancelled);
            }
            return Err(anyhow::anyhow!(
                "UDP winner '{}' became ineligible before endpoint setup",
                node.name
            ));
        }
        // Final promotion remains pre-publication and inside the unchanged
        // absolute preparation deadline.
        #[cfg(feature = "rprx")]
        let source_pool = Arc::clone(&self.udp_pool);
        let transport = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(transport_deadline) => {
                #[cfg(feature = "native-api")]
                if let Some(flow) = native_flow.as_ref() {
                    flow.finish("failed", "udp_commit_timeout");
                }
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Timeout);
                }
                return Err(anyhow::anyhow!(
                    "UDP transport preparation exceeded its overall deadline"
                ));
            }
            result = async move {
                match prepared_transport {
                    PreparedEndpointTransport::Flow(prepared) => prepared
                        .commit()
                        .await
                        .map(CommittedEndpointTransport::Flow),
                    #[cfg(feature = "rprx")]
                    PreparedEndpointTransport::Source(prepared) => prepared
                        .commit(&source_pool)
                        .await
                        .map(CommittedEndpointTransport::Source),
                }
            } => match result {
                Ok(transport) => transport,
                Err(error) => {
                    #[cfg(feature = "native-api")]
                    if let Some(flow) = native_flow.as_ref() {
                        flow.finish("failed", "udp_commit_failed");
                    }
                    if let Some(reporter) = &score_reporter {
                        reporter.finish(score_runtime_outcome(&runtime_generation, &error));
                    }
                    return Err(error);
                }
            }
        };
        if let Some(reporter) = &score_reporter {
            reporter.setup_succeeded();
        }

        // Both capacity (at reservation time) and anyfrom creation happen
        // after the winner is finalized and before the only first send. Any
        // failure is fail-closed; there is no listener-socket fallback.
        let reply_ready_started = std::time::Instant::now();
        let reply_socket = match self.udp_pool.create_reply_socket(original_dst) {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                #[cfg(feature = "native-api")]
                if let Some(flow) = native_flow.as_ref() {
                    flow.finish("failed", "reply_socket_failed");
                }
                self.stats
                    .record_udp_reply_ready_latency(reply_ready_started.elapsed());
                outbound_tracker.increment_errors();
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Cancelled);
                }
                return Err(error.into());
            }
        };
        self.stats
            .record_udp_reply_ready_latency(reply_ready_started.elapsed());

        let endpoint = match transport {
            CommittedEndpointTransport::Flow(transport) => {
                let relay_addr = transport.relay_addr();
                let endpoint = UdpEndpoint::new_scored(
                    transport,
                    relay_addr,
                    target_is_domain,
                    node.id,
                    scheduler_ipver,
                    score_reporter,
                );
                endpoint.record_pending_reply_peer(relay_addr);
                endpoint
            }
            #[cfg(feature = "rprx")]
            CommittedEndpointTransport::Source(attachment) => UdpEndpoint::new_source_scored(
                attachment,
                original_dst,
                target_domain.as_deref(),
                Arc::clone(&reply_socket),
                outbound_tracker.clone(),
                node.id,
                scheduler_ipver,
                score_reporter,
            ),
        };
        #[cfg(feature = "native-api")]
        let endpoint = {
            let mut endpoint = endpoint;
            endpoint.set_native_flow(native_flow.take(), &self.udp_pool);
            endpoint
        };
        let endpoint = Arc::new(endpoint);

        let tracker_id = if let Some(conn_id) = self.connection_tracker.register_if_enabled(|| {
            let id = uuid::Uuid::new_v4().to_string();
            let (rule, rule_payload) =
                matched_rule.unwrap_or_else(|| ("Fallback".to_string(), String::new()));
            let (upload, download) = endpoint.byte_counters();
            crate::connection_tracker::ConnectionEntry {
                id,
                source: client_addr.to_string(),
                destination: original_dst.to_string(),
                proxy: node.name.clone(),
                #[cfg(feature = "native-api")]
                routed_outbound: self
                    .connection_tracker
                    .native_enabled()
                    .then(|| outbound_name.clone()),
                #[cfg(feature = "native-api")]
                native_flow_id: endpoint
                    .native_flow()
                    .filter(|flow| !flow.id().is_empty())
                    .map(|flow| flow.id().to_owned()),
                rule,
                rule_payload,
                chains: connection_chains(selection_chain, &node.name),
                upload,
                download,
                start_time: std::time::Instant::now(),
                domain: quic_domain.clone(),
                network: "udp".to_string(),
                process: handoff.as_ref().and_then(|ho| ho.process_name()),
                process_path: None,
            }
        }) {
            endpoint.set_tracker(conn_id.clone());
            #[cfg(feature = "native-api")]
            if let Some(flow) = endpoint.native_flow() {
                flow.attach_connection(&conn_id);
            }
            if !lease.set_tracker_id(conn_id.clone()) {
                #[cfg(feature = "native-api")]
                if let Some(flow) = endpoint.native_flow() {
                    flow.finish("failed", "initializer_cancelled");
                }
                // The generation was cancelled between route selection and
                // registration. No pool entry owns this tracker, so retire it
                // directly rather than leaking it.
                self.connection_tracker.remove(&conn_id);
                return Err(anyhow::anyhow!(
                    "UDP initializer generation was cancelled before tracker attachment"
                ));
            }
            Some(conn_id)
        } else {
            None
        };

        let queue_rx = match follower_rx {
            // Already taken while collecting a fragmented ClientHello.
            Some(rx) => rx,
            None => lease.take_queue_receiver().ok_or_else(|| {
                #[cfg(feature = "native-api")]
                if let Some(flow) = endpoint.native_flow() {
                    flow.finish("failed", "initializer_queue_missing");
                }
                anyhow::anyhow!("UDP initializer lost its bounded queue before driver start")
            })?,
        };
        let mut driver = self.udp_pool.spawn_driver(
            client_addr,
            original_dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            reply_socket,
            self.alive_set.clone(),
            self.stats.clone(),
            outbound_tracker.clone(),
        );
        driver.wait_ready().await?;
        #[cfg(feature = "native-api")]
        if let Some(flow) = endpoint.native_flow() {
            flow.transition(
                "active",
                "udp_transport_ready",
                "transport_ready",
                Some(false),
            );
        }
        if !lease.still_initializing() {
            #[cfg(feature = "native-api")]
            if let Some(flow) = endpoint.native_flow() {
                flow.finish("failed", "initializer_cancelled");
            }
            return Err(anyhow::anyhow!(
                "UDP initializer generation was retired before ready commit"
            ));
        }
        if !lease.commit_ready(Arc::clone(&endpoint)) {
            #[cfg(feature = "native-api")]
            if let Some(flow) = endpoint.native_flow() {
                flow.finish("failed", "initializer_cancelled");
            }
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before ready commit"
            ));
        }
        let first = lease.take_first().ok_or_else(|| {
            #[cfg(feature = "native-api")]
            if let Some(flow) = endpoint.native_flow() {
                flow.finish("failed", "initializer_first_packet_missing");
            }
            anyhow::anyhow!("UDP initializer lost its first packet before driver start")
        })?;
        driver.start_with_followers(first, sniffed_followers)?;
        if let Some(conn_id) = tracker_id {
            self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
        }
        if let Err(error) = driver.wait_first_ack().await {
            // First-send failures are terminal for this endpoint; once the
            // transport call starts, the packet is never replayed.
            outbound_tracker.increment_errors();
            return Err(error.into());
        }
        debug!(
            network = "udp",
            outbound = %outbound_name,
            dialer = %node.name,
            sniffed = quic_domain.as_deref().unwrap_or(""),
            ip = %original_dst,
            src = %client_addr,
            "UDP connection: {} -> {} via {} (endpoint driver ready)",
            client_addr,
            original_dst,
            node.name,
        );
        Ok(())
    }

    /// A fragmented ClientHello: feed queued follower Initials to the
    /// sniffer until it resolves, or the packet/time budget runs out.
    /// Fragments of one flight arrive back-to-back, so the budget is small
    /// and the common single-Initial path never enters this loop. Retained
    /// followers are returned in receive order for the canonical UDP
    /// endpoint driver.
    async fn collect_initial_fragments(
        &self,
        sniffer_key: crate::control::packet_sniffer::PacketSnifferKey,
        rx: &mut tokio::sync::mpsc::Receiver<crate::control::udp_endpoint::QueuedDatagram>,
    ) -> (
        crate::control::packet_sniffer::QuicSniffOutcome,
        Vec<crate::control::udp_endpoint::QueuedDatagram>,
    ) {
        use crate::control::packet_sniffer::QuicSniffOutcome;
        const MAX_FRAGMENTS: u32 = 8;
        const MAX_WAIT: Duration = Duration::from_millis(250);
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        let mut outcome = QuicSniffOutcome::Incomplete;
        let mut collected = Vec::with_capacity(MAX_FRAGMENTS as usize);
        for _ in 0..MAX_FRAGMENTS {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(datagram)) => {
                    outcome = self
                        .sniffer_pool
                        .feed_quic_initial(sniffer_key, datagram.payload());
                    collected.push(datagram);
                    if !matches!(outcome, QuicSniffOutcome::Incomplete) {
                        break;
                    }
                }
                _ => break,
            }
        }
        (outcome, collected)
    }
}
