use std::{net::SocketAddr, sync::Arc};

use honk_config::{
    Config,
    node::Node,
    types::{DialMode, NodeProtocol},
};
use honk_outbound::{alive::IpVersion, runtime::flow_observation::FlowObserver};

use super::{handoff::HandoffResult, routing::RoutingDecision};
use crate::{
    native_api::{
        catalog::CatalogIdentity,
        flows::{
            FlowGuard,
            record::{
                EvaluationInput, FlowError, Input, InputValues, OutboundAttempt, RouteInput,
                Selection, StepData,
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
    rules: Vec<crate::native_api::routing::RuleEvaluation>,
    truncated: bool,
}

impl RouteObservation {
    pub(super) fn kernel() -> Self {
        Self {
            generation: None,
            rule_id: None,
            rule_expression: None,
            evaluation_id: String::new(),
            plane: "kernel",
            input: None,
            rules: Vec::new(),
            truncated: false,
        }
    }

    pub(super) fn userspace(
        instance: &str,
        generation: u64,
        input: &ConnectionInfo,
        router: &Router,
        matched: Option<&RouteMatch<'_>>,
        rules: Vec<crate::native_api::routing::RuleEvaluation>,
        truncated: bool,
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
                    .map(|compiled| compiled.expression.clone())
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
                ingress: None,
                domain_rule_ids: None,
                domain_fact_bitmap: None,
                domain_fact_state: None,
            }),
            rules,
            truncated,
        }
    }
}

#[derive(Clone, Default)]
pub(in crate::control) struct ConnectionObservation {
    recorded: Option<RecordedConnection>,
}

#[derive(Clone)]
struct RecordedConnection {
    flow: Arc<FlowGuard>,
    network: &'static str,
    source: SocketAddr,
    destination: SocketAddr,
    kernel_evaluation: Option<String>,
    kernel_route: Option<RouteObservation>,
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
    decisions: Arc<[Selection]>,
    health_family: Option<&'static str>,
}

impl ConnectionObservation {
    pub(in crate::control) fn begin(
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
                    kernel_route: None,
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

    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        self.recorded.as_ref().map(|record| &record.flow)
    }

    pub(in crate::control) fn observer(
        &self,
        generation: u64,
        purpose: &'static str,
    ) -> Option<FlowObserver> {
        self.flow()?.observer(generation, None, purpose)
    }

    pub(super) fn routing_started(&self) {
        if let Some(flow) = self.flow() {
            flow.transition("routing", "routing_started", "unknown", None);
        }
    }

    pub(super) fn selection_observed(
        &mut self,
        observation: Option<&Arc<honk_outbound::group::observation::SelectionObservation>>,
        family: IpVersion,
    ) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let Some(selection) = &mut record.selection else {
            record.flow.mark_gap("not_instrumented");
            return;
        };
        selection.health_family = Some(match family {
            IpVersion::V4 => "ipv4",
            IpVersion::V6 => "ipv6",
        });
        let Some(observation) = observation else {
            return;
        };
        let Some(observer) = record
            .flow
            .observer(selection.generation, None, "dial_target")
        else {
            return;
        };
        let decisions = crate::native_api::flows::producer::map_selection_observation(
            observation,
            &selection.catalog,
            &observer,
        );
        record
            .flow
            .observe_selection(selection.generation, decisions.clone());
        selection.decisions = decisions.into();
    }

    pub(super) fn take_flow(&mut self) -> Option<Arc<FlowGuard>> {
        self.recorded.take().map(|record| record.flow)
    }

    pub(super) fn shared(&self) -> Option<Arc<Self>> {
        self.is_recording().then(|| Arc::new(self.clone()))
    }

    pub(super) fn handoff(&mut self, handoff: Option<&HandoffResult>, expected: bool) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        let Some(handoff) = handoff else {
            if expected {
                record.flow.mark_gap("not_instrumented");
            }
            return;
        };
        if handoff.capture_gap == Some("kernel_handoff_ambiguous") {
            record.flow.mark_gap("not_instrumented");
            return;
        }
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
        if let Some(capture) = &handoff.capture {
            Self::record_kernel(record, capture.clone());
        } else {
            record
                .flow
                .mark_gap(handoff.capture_gap.unwrap_or("not_instrumented"));
        }
    }

    pub(in crate::control) fn packet_route(
        &mut self,
        capture: Result<crate::native_api::flows::kernel::CapturedKernelRoute, &'static str>,
    ) {
        let Some(record) = &mut self.recorded else {
            return;
        };
        match capture {
            Ok(capture) => Self::record_kernel(record, capture),
            Err(reason) => record.flow.mark_gap(reason),
        }
    }

    fn record_kernel(
        record: &mut RecordedConnection,
        capture: crate::native_api::flows::kernel::CapturedKernelRoute,
    ) {
        if capture.truncated {
            record.flow.mark_overflow();
        }
        if capture.ambiguous {
            record.flow.mark_gap("started_late");
        }
        if let Some(gap) = capture.gap {
            record.flow.mark_gap(gap);
        }
        let rule_expression = capture.rule_id.as_ref().and_then(|id| {
            capture
                .rules
                .iter()
                .find(|rule| &rule.rule_id == id)
                .map(|rule| rule.expression.clone())
        });
        record.kernel_evaluation = Some(capture.evaluation_id.clone());
        record.kernel_route = Some(RouteObservation {
            generation: Some(capture.generation),
            rule_id: capture.rule_id.clone(),
            rule_expression,
            evaluation_id: capture.evaluation_id.clone(),
            plane: "kernel",
            input: None,
            rules: Vec::new(),
            truncated: false,
        });
        let mut input = capture.input;
        input.domain_fact_bitmap = Some(capture.domain_bitmap);
        input.domain_fact_state = Some(capture.fact_state);
        record.route = record.kernel_route.clone();
        record.evaluation = record.kernel_evaluation.clone();
        record.routed_outbound = capture
            .effective_outbound
            .clone()
            .or_else(|| capture.outbound.clone());
        record.flow.step(
            Some(capture.generation),
            StepData::Route {
                evaluation_id: capture.evaluation_id,
                chain: "traffic",
                plane: "kernel",
                rule_id: capture.rule_id,
                rules: capture.rules,
                outbound: capture.outbound,
                must: Some(capture.must),
                mark: Some(capture.mark),
                input: Some(EvaluationInput::Traffic(input)),
                dns_action: None,
            },
        );
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
        if route.as_ref().is_some_and(|route| route.plane == "kernel") {
            route = record.kernel_route.clone().or(route);
        }
        record.routed_outbound = Some(decision.outbound.clone());
        record.evaluation = route
            .as_ref()
            .filter(|route| route.plane == "userspace")
            .map(|route| route.evaluation_id.clone())
            .or_else(|| record.kernel_evaluation.clone());
        if let Some(capture) = &mut route
            && capture.plane == "userspace"
        {
            if capture.truncated {
                record.flow.mark_overflow();
            }
            record.flow.step(
                capture.generation,
                StepData::Route {
                    evaluation_id: capture.evaluation_id.clone(),
                    chain: "traffic",
                    plane: capture.plane,
                    rule_id: capture.rule_id.clone(),
                    rules: std::mem::take(&mut capture.rules),
                    outbound: Some(decision.outbound.clone()),
                    must: Some(decision.must),
                    mark: Some(
                        decision
                            .mark
                            .map_or(0, honk_outbound::proxy::DirectMark::get),
                    ),
                    input: capture.input.take().map(EvaluationInput::Traffic),
                    dns_action: None,
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
                from_evaluation_id: record.kernel_evaluation.clone(),
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
            if rule.is_some_and(|route| route.plane == "kernel") {
                "kernel"
            } else if rule.is_some_and(|route| route.rule_id.is_some()) {
                "evaluation"
            } else if record.routed_outbound.is_none() {
                "forced"
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
                decisions: Arc::from([]),
                health_family: None,
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
        let Some(first) = candidates.first() else {
            record.flow.step(
                record.dial_mode_generation,
                StepData::DialMode {
                    configured,
                    effective_target: "none",
                    domain: sniff.domain.clone(),
                    domain_source: tcp_domain_source(sniff),
                    verification,
                    reason: "no_eligible_candidates",
                },
            );
            return;
        };
        let target = target_kind(first, domain);
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
            lookup_id: None,
            kind: "leaf",
            evaluation_id: record.evaluation.clone(),
            routing_source: if record.evaluation.is_some() {
                "evaluation"
            } else if record.routed_outbound.is_none() {
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
            selection_path: selection_path(selection, chain, node),
            leaf_node_id: Some(node.id.to_string()),
            leaf_node_name: Some(node.name.clone()),
            target: match target_kind {
                "none" => None,
                "domain" => domain.map(|domain| format!("{domain}:{}", record.destination.port())),
                _ => Some(record.destination.to_string()),
            },
            target_kind,
            dial_ip: (record.network == "udp" && node.protocol() == NodeProtocol::Direct)
                .then(|| record.destination.ip()),
            server_addr: None,
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
            if node.protocol() == NodeProtocol::Direct {
                "dial_target"
            } else {
                "proxy_server"
            },
        ))
    }

    pub(in crate::control) fn finish(&self, state: &'static str, reason: &'static str) {
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

    pub(super) fn tcp_deadline(&self) {
        let Some(record) = &self.recorded else { return };
        let generation = record
            .selection
            .as_ref()
            .map(|selection| selection.generation)
            .or(record.dial_mode_generation);
        record.flow.step(
            generation,
            StepData::Connection {
                state: "dialing",
                reason: "dial_deadline_exceeded",
                milestone: "unknown",
                attempt_id: None,
                reply_received: None,
                error: Some(FlowError::DialTimeout),
                selections: Vec::new(),
                lookup_id: None,
                server_addr: None,
            },
        );
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
    attempt_id: uuid::Uuid,
    data: Option<OutboundAttempt>,
    dns_purpose: &'static str,
}

impl ConnectionAttempt {
    fn new(
        flow: Arc<FlowGuard>,
        generation: u64,
        data: OutboundAttempt,
        dns_purpose: &'static str,
    ) -> Self {
        let attempt_id = uuid::Uuid::new_v4();
        flow.step(
            Some(generation),
            StepData::Outbound {
                attempt_id: attempt_id.to_string(),
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
            dns_purpose,
        }
    }

    pub(super) fn finish(&mut self, status: &'static str, error: Option<FlowError>) {
        let Some(attempt) = self.data.take() else {
            return;
        };
        self.flow.step(
            Some(self.generation),
            StepData::Outbound {
                attempt_id: self.attempt_id.to_string(),
                attempt,
                status,
                error,
            },
        );
    }

    pub(super) fn id(&self) -> uuid::Uuid {
        self.attempt_id
    }

    pub(super) fn observer(&self) -> Option<FlowObserver> {
        self.flow
            .observer(self.generation, Some(self.attempt_id), self.dns_purpose)
    }

    pub(super) fn udp_prepared(&self) {
        self.flow.step(
            Some(self.generation),
            StepData::Connection {
                state: "dialing",
                reason: "udp_prepared",
                milestone: "unknown",
                attempt_id: Some(self.attempt_id.to_string()),
                reply_received: None,
                error: None,
                selections: Vec::new(),
                lookup_id: None,
                server_addr: None,
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
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        self.finish("cancelled", Some(FlowError::Cancelled));
    }
}

fn selection_path(
    selection: &SelectionGeneration,
    chain: &[String],
    node: &Node,
) -> Vec<Selection> {
    let catalog = &selection.catalog;
    chain
        .iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let group_id = catalog.groups.get(name)?;
            let next = chain
                .get(index + 1)
                .and_then(|name| {
                    catalog
                        .groups
                        .get(name)
                        .map(|id| (id.clone(), name.clone()))
                })
                .unwrap_or_else(|| (node.id.to_string(), node.name.clone()));
            let compatible = |row: &&Selection| {
                &row.group_id == group_id
                    && row.health_family == selection.health_family
                    && (row.member_id.is_none()
                        || row.member_id.as_deref() == Some(next.0.as_str()))
            };
            if let Some(captured) = selection
                .decisions
                .iter()
                .rev()
                .filter(compatible)
                .find(|row| row.applied == Some(true))
                .or_else(|| selection.decisions.iter().rev().find(compatible))
            {
                let mut captured = captured.clone();
                captured.member_id = Some(next.0);
                captured.member_name = Some(next.1);
                return Some(captured);
            }
            let group = selection
                .config
                .groups
                .iter()
                .rev()
                .find(|group| &group.name == name)?;
            let policy = match group.policy {
                honk_config::group::GroupPolicy::Selector => "selector",
                honk_config::group::GroupPolicy::URLTest => "urltest",
                honk_config::group::GroupPolicy::LoadBalance => "loadbalance",
                honk_config::group::GroupPolicy::Fallback => "fallback",
                honk_config::group::GroupPolicy::Score => "score",
            };
            Some(Selection {
                group_id: group_id.clone(),
                member_id: Some(next.0),
                member_name: Some(next.1),
                policy,
                reason: "captured_plan",
                selection: None,
                health_family: selection.health_family,
                applied: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_connection_begin_has_no_recorded_guard() {
        let native = NativeObservation::new(&Config::default());
        let observation = ConnectionObservation::begin(
            Some(&native),
            "tcp",
            "127.0.0.1:31000".parse().unwrap(),
            "127.0.0.2:443".parse().unwrap(),
        );
        assert!(!observation.is_recording());
        assert!(observation.flow().is_none());
    }
}
