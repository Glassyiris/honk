use std::{net::SocketAddr, sync::Arc};

use honk_config::{
    Config,
    node::Node,
    types::{DialMode, NodeProtocol},
};
use honk_ebpf_common::OutboundIndex;

use super::{handoff::HandoffResult, routing::RoutingDecision};
use crate::{
    native_api::{
        catalog::CatalogIdentity,
        flows::{
            FlowGuard,
            record::{
                FlowError, Input, InputValues, OutboundAttempt, RouteInput, Selection, StepData,
            },
        },
        observation::NativeObservation,
    },
    routing::{ConnectionInfo, RouteMatch, Router},
};

#[derive(Debug, Clone)]
pub(super) struct RouteObservation {
    generation: Option<u64>,
    rule_id: Option<String>,
    rule_expression: Option<String>,
    evaluation_id: String,
    plane: &'static str,
    input: Option<RouteInput>,
}

impl RouteObservation {
    pub(super) fn kernel() -> Self {
        Self {
            generation: None,
            rule_id: None,
            rule_expression: None,
            evaluation_id: uuid::Uuid::new_v4().to_string(),
            plane: "kernel",
            input: None,
        }
    }

    pub(super) fn userspace(
        instance: &str,
        generation: u64,
        input: &ConnectionInfo,
        router: &Router,
        matched: Option<&RouteMatch<'_>>,
    ) -> Self {
        Self {
            generation: Some(generation),
            rule_id: Some(crate::native_api::routing::rule_id(
                instance,
                generation,
                matched.map(|route| route.rule_id),
            )),
            rule_expression: Some(match matched {
                Some(route) => router
                    .compiled_routes()
                    .iter()
                    .find(|compiled| compiled.id == route.rule_id)
                    .map(|compiled| crate::routing::native::rule_expression(&compiled.conditions))
                    .expect("matched compiled rule"),
                None => "fallback".to_owned(),
            }),
            evaluation_id: uuid::Uuid::new_v4().to_string(),
            plane: "userspace",
            input: Some(RouteInput {
                network: input.protocol,
                src_ip: input.src_ip,
                src_port: input.src_port,
                dst_ip: input.dst_ip,
                dst_port: input.dst_port,
                domain: input.domain.clone(),
                pname: input.process_name.clone(),
                src_mac: input.mac.clone(),
                dscp: input.dscp,
                mark: (),
                ingress: (),
                domain_rule_ids: (),
            }),
        }
    }

    pub(super) fn retain_kernel_decision(&mut self) {
        self.generation = None;
        self.rule_id = None;
        self.rule_expression = None;
        self.plane = "kernel";
        self.input = None;
    }
}

#[derive(Clone, Default)]
pub(super) struct ConnectionObservation {
    recorded: Option<RecordedConnection>,
}

#[derive(Clone)]
struct RecordedConnection {
    flow: Arc<FlowGuard>,
    network: &'static str,
    source: SocketAddr,
    destination: SocketAddr,
    kernel_evaluation: Option<String>,
    evaluation: Option<String>,
    route: Option<RouteObservation>,
    routed_outbound: Option<String>,
    effective_outbound: Option<String>,
    dial_mode_generation: Option<u64>,
    selection: Option<SelectionGeneration>,
}

#[derive(Clone)]
struct SelectionGeneration {
    generation: u64,
    catalog: Arc<CatalogIdentity>,
    config: Arc<Config>,
}

impl ConnectionObservation {
    pub(super) fn begin(
        native: Option<&NativeObservation>,
        network: &'static str,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        Self {
            recorded: native.and_then(|native| {
                let flow = native.flows.begin(network, source, destination);
                (!flow.id().is_empty()).then(|| RecordedConnection {
                    flow: Arc::new(flow),
                    network,
                    source,
                    destination,
                    kernel_evaluation: None,
                    evaluation: None,
                    route: None,
                    routed_outbound: None,
                    effective_outbound: None,
                    dial_mode_generation: None,
                    selection: None,
                })
            }),
        }
    }

    pub(super) fn is_recording(&self) -> bool {
        self.recorded.is_some()
    }

    pub(super) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.recorded.as_ref().map(|record| &record.flow)
    }

    pub(super) fn take_flow(&mut self) -> Option<Arc<FlowGuard>> {
        self.recorded.take().map(|record| record.flow)
    }

    pub(super) fn shared(&self) -> Option<Arc<Self>> {
        self.is_recording().then(|| Arc::new(self.clone()))
    }

    pub(super) fn handoff(&mut self, handoff: Option<&HandoffResult>) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let Some(handoff) = handoff else { return };
        if record.network == "tcp" {
            update_input(&record.flow, None, None, Some(handoff));
        }
        record.flow.step(
            None,
            StepData::Input {
                source: "kernel",
                values: InputValues {
                    input: Input {
                        src: record.source,
                        dst: record.destination,
                        domain: None,
                        domain_source: None,
                        pid: (handoff.pid != 0).then_some(handoff.pid),
                        process_path: (),
                        src_mac: handoff.mac_address(),
                        ingress: (),
                        domain_rule_ids: (),
                        dscp: (record.network == "udp" || handoff.dscp <= 63)
                            .then_some(handoff.dscp),
                        mark: Some(handoff.mark),
                    },
                    pname: handoff.process_name(),
                },
            },
        );
        if record.network == "tcp" {
            let evaluation_id = uuid::Uuid::new_v4().to_string();
            let outbound = match handoff.outbound {
                x if x == OutboundIndex::Direct as u8 => Some("direct"),
                x if x == OutboundIndex::Block as u8 => Some("block"),
                _ => None,
            };
            record.flow.step(
                None,
                StepData::Route {
                    evaluation_id: evaluation_id.clone(),
                    chain: "traffic",
                    plane: "kernel",
                    rule_id: None,
                    rules: [],
                    outbound: outbound.map(str::to_owned),
                    must: handoff.must != 0,
                    mark: handoff.mark,
                    input: None,
                    dns_action: (),
                },
            );
            record.kernel_evaluation = Some(evaluation_id);
        }
    }

    pub(super) fn tcp_sniffed(
        &self,
        sniff: &crate::sniffing::SniffResult,
        handoff: Option<&HandoffResult>,
    ) {
        self.sniffed(sniff.domain.as_deref(), tcp_domain_source(sniff), handoff);
    }

    pub(super) fn udp_sniffed(&self, domain: Option<&str>, handoff: Option<&HandoffResult>) {
        self.sniffed(domain, domain.map(|_| "quic_sni"), handoff);
    }

    fn sniffed(
        &self,
        domain: Option<&str>,
        source: Option<&'static str>,
        handoff: Option<&HandoffResult>,
    ) {
        if let Some(flow) = self.flow() {
            update_input(flow, domain, source, handoff);
        }
    }

    pub(super) fn routed(&mut self, decision: &mut RoutingDecision) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let mut route = decision.native_route.take();
        record.routed_outbound = Some(decision.outbound.clone());
        record.evaluation = route
            .as_ref()
            .filter(|route| record.network == "udp" || route.plane == "userspace")
            .map(|route| route.evaluation_id.clone())
            .or_else(|| record.kernel_evaluation.clone());
        if let Some(capture) = &mut route
            && (record.network == "udp" || capture.plane == "userspace")
        {
            record.flow.step(
                capture.generation,
                StepData::Route {
                    evaluation_id: capture.evaluation_id.clone(),
                    chain: "traffic",
                    plane: capture.plane,
                    rule_id: capture.rule_id.clone(),
                    rules: [],
                    outbound: Some(decision.outbound.clone()),
                    must: decision.must,
                    mark: decision.mark,
                    input: capture.input.take(),
                    dns_action: (),
                },
            );
        }
        let performed = decision.reroute_by_sniffed_domain;
        record.flow.step(
            route.as_ref().and_then(|route| route.generation),
            StepData::Reroute {
                performed,
                reason: if record.network == "udp" {
                    "sniff_routing_decision"
                } else if performed {
                    "sniffed_domain"
                } else {
                    "not_required"
                },
                from_evaluation_id: record.kernel_evaluation.take(),
                to_evaluation_id: (record.network == "tcp" || performed)
                    .then(|| record.evaluation.clone())
                    .flatten(),
            },
        );
        record.route = route;
    }

    pub(super) fn mode_applied(&mut self, outbound: &str) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        record.effective_outbound = Some(outbound.to_owned());
        let rule = record.route.as_ref();
        record.flow.routed(
            outbound,
            rule.and_then(|route| route.rule_id.as_deref()),
            rule.and_then(|route| route.rule_expression.as_deref()),
            if rule.is_some_and(|route| route.rule_id.is_some()) {
                "evaluation"
            } else {
                "unknown"
            },
        );
    }

    pub(super) fn pin_dial_mode(&mut self, generation: Option<u64>) {
        if let Some(record) = &mut self.recorded {
            record.dial_mode_generation = generation;
        }
    }

    pub(super) fn pin_selection(
        &mut self,
        generation: u64,
        catalog: &Arc<CatalogIdentity>,
        config: &Arc<Config>,
    ) {
        if let Some(record) = &mut self.recorded {
            record.selection = Some(SelectionGeneration {
                generation,
                catalog: Arc::clone(catalog),
                config: Arc::clone(config),
            });
        }
    }

    pub(super) fn release_selection(&mut self) {
        if let Some(record) = &mut self.recorded {
            record.selection = None;
        }
    }

    pub(super) fn tcp_dial_mode(
        &self,
        configured: DialMode,
        sniff: &crate::sniffing::SniffResult,
        verification: &'static str,
        candidates: &[Node],
        domain: Option<&str>,
    ) {
        let Some(record) = &self.recorded else { return };
        let target = target_kind(&candidates[0], domain);
        let target = if candidates
            .iter()
            .all(|node| target_kind(node, domain) == target)
        {
            target
        } else {
            "unknown"
        };
        record.flow.step(
            record.dial_mode_generation,
            StepData::DialMode {
                configured,
                effective_target: target,
                domain: sniff.domain.clone(),
                domain_source: tcp_domain_source(sniff),
                verification,
                reason: match target {
                    "none" => "policy_block",
                    "domain" => "sniffed_domain",
                    "ip" => "original_destination",
                    _ => "candidate_dependent",
                },
            },
        );
    }

    pub(super) fn udp_dial_mode(
        &self,
        configured: DialMode,
        domain: Option<&str>,
        verification: &'static str,
        selected: Option<(&Node, Option<&str>)>,
    ) {
        let Some(record) = &self.recorded else { return };
        let (generation, target, reason) = match selected {
            Some((node, target)) => (
                record
                    .selection
                    .as_ref()
                    .map(|selection| selection.generation),
                target_kind(node, target),
                "leaf_target_selected",
            ),
            None => (
                record.route.as_ref().and_then(|route| route.generation),
                match record.effective_outbound.as_deref() {
                    Some("block") => "none",
                    Some("direct") => "ip",
                    _ => "unknown",
                },
                "dial_mode_applied",
            ),
        };
        record.flow.step(
            generation,
            StepData::DialMode {
                configured,
                effective_target: target,
                domain: domain.map(str::to_owned),
                domain_source: domain.map(|_| "quic_sni"),
                verification,
                reason,
            },
        );
        if selected.is_none() && record.effective_outbound.as_deref() == Some("block") {
            record.flow.finish("blocked", "routing_block");
        }
    }

    pub(super) fn selected(&self, chain: &[String], node: &Node) {
        let Some(record) = &self.recorded else { return };
        if matches!(node.protocol(), NodeProtocol::Direct | NodeProtocol::Block) {
            record.flow.selected(Vec::new());
            return;
        }
        let Some(selection) = &record.selection else {
            return;
        };
        let count = chain
            .len()
            .saturating_sub(usize::from(chain.last() == Some(&node.name)));
        let groups: Option<Vec<_>> = chain
            .iter()
            .take(count)
            .map(|name| selection.catalog.groups.get(name).cloned())
            .collect();
        if let Some(mut chain) = groups {
            chain.push(node.id.to_string());
            record.flow.selected(chain);
        }
    }

    pub(super) fn attempt(
        &self,
        chain: &[String],
        node: &Node,
        domain: Option<&str>,
    ) -> Option<ConnectionAttempt> {
        let record = self.recorded.as_ref()?;
        let selection = record
            .selection
            .as_ref()
            .expect("captured selection generation");
        let target_kind = target_kind(node, domain);
        let data = OutboundAttempt {
            parent_attempt_id: None,
            kind: "leaf",
            evaluation_id: record.evaluation.clone(),
            routing_source: if record.evaluation.is_some() {
                "evaluation"
            } else if record.network == "udp" {
                "forced"
            } else {
                "unknown"
            },
            routed_outbound: record.routed_outbound.clone(),
            effective_outbound: record.effective_outbound.clone(),
            mode_override: if record.routed_outbound == record.effective_outbound {
                "none"
            } else if record.effective_outbound.as_deref() == Some("direct") {
                "direct"
            } else {
                "global"
            },
            selection_path: selection_path(&selection.config, &selection.catalog, chain, node),
            leaf_node_id: node.id.to_string(),
            leaf_node_name: Some(node.name.clone()),
            target: match target_kind {
                "none" => None,
                "domain" => domain.map(|domain| format!("{domain}:{}", record.destination.port())),
                _ => Some(record.destination.to_string()),
            },
            target_kind,
            dial_ip: (record.network == "udp" && node.protocol() == NodeProtocol::Direct)
                .then(|| record.destination.ip()),
            server_addr: (),
            resolution_location: if target_kind == "none" {
                "not_applicable"
            } else if node.protocol() == NodeProtocol::Direct
                || (record.network == "tcp" && target_kind == "ip")
            {
                "original_ip"
            } else {
                "unknown"
            },
        };
        Some(ConnectionAttempt::new(
            Arc::clone(&record.flow),
            selection.generation,
            data,
        ))
    }

    pub(super) fn finish(&self, state: &'static str, reason: &'static str) {
        if let Some(flow) = self.flow() {
            flow.finish(state, reason);
        }
    }

    pub(super) fn tcp_connected(&self, chain: &[String], node: &Node) {
        self.selected(chain, node);
        if let Some(flow) = self.flow() {
            flow.transition("active", "dial_succeeded", "transport_ready", None);
        }
    }

    pub(super) fn tcp_dial_exhausted(&self, candidates: &[Node], outbound: &str) {
        if outbound == "block"
            || candidates
                .iter()
                .all(|node| node.protocol() == NodeProtocol::Block)
        {
            self.finish("blocked", "policy_block");
        } else {
            self.finish("failed", "dial_failed");
        }
    }

    pub(super) fn tcp_prefix_failed(&self, intentional: bool) {
        if intentional {
            self.finish("closed", "intentional_retirement");
        } else {
            self.finish("failed", "prefix_write_failed");
        }
    }

    pub(super) fn tcp_relay_finished(&self, succeeded: bool) {
        if succeeded {
            self.finish("closed", "relay_closed");
        } else {
            self.finish("failed", "relay_failed");
        }
    }

    pub(super) fn first_response(
        &self,
        previous: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let Some(flow) = self.flow() else {
            return previous;
        };
        let flow = Arc::clone(flow);
        Some(Arc::new(move || {
            if let Some(callback) = &previous {
                callback();
            }
            if flow.first_reply() {
                flow.transition("active", "response_received", "first_reply", Some(true));
            }
        }))
    }

    pub(super) fn udp_preparing(&self) {
        if let Some(flow) = self.flow() {
            flow.transition("dialing", "udp_prepare_started", "unknown", Some(false));
        }
    }

    pub(super) fn udp_prepare_exhausted(&self, all_block: bool) {
        if let Some(flow) = self.flow() {
            if all_block {
                flow.selected(Vec::new());
                flow.finish("blocked", "policy_block");
            } else {
                flow.finish("failed", "udp_prepare_failed");
            }
        }
    }
}

fn update_input(
    flow: &FlowGuard,
    domain: Option<&str>,
    source: Option<&'static str>,
    handoff: Option<&HandoffResult>,
) {
    flow.update_input(
        domain,
        source,
        handoff
            .and_then(|handoff| handoff.process_name())
            .as_deref(),
        handoff.and_then(|handoff| (handoff.pid != 0).then_some(handoff.pid)),
        handoff.and_then(|handoff| handoff.mac_address()),
        handoff.map(|handoff| handoff.dscp),
        handoff.map(|handoff| handoff.mark),
    );
}

fn tcp_domain_source(sniff: &crate::sniffing::SniffResult) -> Option<&'static str> {
    match &sniff.traffic_type {
        crate::sniffing::TrafficType::Tls { sni: Some(_) } => Some("tls_sni"),
        crate::sniffing::TrafficType::Http { host: Some(_) } => Some("http_host"),
        _ => None,
    }
}

fn target_kind(node: &Node, domain: Option<&str>) -> &'static str {
    match node.protocol() {
        NodeProtocol::Block => "none",
        NodeProtocol::Direct => "ip",
        _ if domain.is_some() => "domain",
        _ => "ip",
    }
}

pub(super) struct ConnectionAttempt {
    flow: Arc<FlowGuard>,
    generation: u64,
    attempt_id: String,
    data: Option<OutboundAttempt>,
}

impl ConnectionAttempt {
    fn new(flow: Arc<FlowGuard>, generation: u64, data: OutboundAttempt) -> Self {
        let attempt_id = uuid::Uuid::new_v4().to_string();
        flow.step(
            Some(generation),
            StepData::Outbound {
                attempt_id: attempt_id.clone(),
                attempt: data.clone(),
                status: "started",
                error: None,
            },
        );
        Self {
            flow,
            generation,
            attempt_id,
            data: Some(data),
        }
    }

    fn finish(&mut self, status: &'static str, error: Option<FlowError>) {
        let Some(attempt) = self.data.take() else {
            return;
        };
        self.flow.step(
            Some(self.generation),
            StepData::Outbound {
                attempt_id: std::mem::take(&mut self.attempt_id),
                attempt,
                status,
                error,
            },
        );
    }

    pub(super) fn tcp_finished(&mut self, error: Option<&anyhow::Error>, node: &Node) {
        let Some(error) = error else {
            self.finish("succeeded", None);
            return;
        };
        let code = if node.protocol() == NodeProtocol::Block {
            FlowError::PolicyBlock
        } else if honk_outbound::proxy::is_packet_rejection(error) {
            FlowError::LocalRefusal
        } else if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
        {
            FlowError::DialTimeout
        } else {
            FlowError::DialFailed
        };
        self.finish("failed", Some(code));
    }

    pub(super) fn udp_finished(&mut self, succeeded: bool) {
        if succeeded {
            self.finish("succeeded", None);
        } else {
            self.finish("failed", Some(FlowError::UdpPrepareFailed));
        }
    }

    #[cfg(feature = "rprx")]
    pub(super) fn runtime_missing(&mut self) {
        self.finish("failed", Some(FlowError::RuntimeGenerationMissing));
    }
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        self.finish("cancelled", Some(FlowError::Cancelled));
    }
}

fn selection_path(
    config: &Config,
    catalog: &CatalogIdentity,
    chain: &[String],
    node: &Node,
) -> Vec<Selection> {
    chain
        .iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let group_id = catalog.groups.get(name)?;
            let group = config
                .groups
                .iter()
                .rev()
                .find(|group| &group.name == name)?;
            let next = chain
                .get(index + 1)
                .and_then(|name| {
                    catalog
                        .groups
                        .get(name)
                        .map(|id| (id.clone(), name.clone()))
                })
                .unwrap_or_else(|| (node.id.to_string(), node.name.clone()));
            let policy = match group.policy {
                honk_config::group::GroupPolicy::Selector => "selector",
                honk_config::group::GroupPolicy::URLTest => "urltest",
                honk_config::group::GroupPolicy::LoadBalance => "loadbalance",
                honk_config::group::GroupPolicy::Fallback => "fallback",
                honk_config::group::GroupPolicy::Score => "score",
            };
            Some(Selection {
                group_id: group_id.clone(),
                member_id: next.0,
                member_name: Some(next.1),
                policy,
                reason: "captured_plan",
                selection: (),
            })
        })
        .collect()
}
