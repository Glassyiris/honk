//! Captured flow evidence; only these fields can cross the recorder boundary.

use std::{
    mem::size_of,
    net::{IpAddr, SocketAddr},
};

use honk_config::types::DialMode;
use serde::Serialize;

use super::{MAX_STEPS, safe_text};

#[derive(Clone, Serialize)]
pub(super) struct Summary {
    pub id: String,
    pub instance_id: String,
    pub revision: u64,
    pub network: &'static str,
    pub state: &'static str,
    pub pname: Option<String>,
    pub connection_id: Option<String>,
    pub outbound: Option<String>,
    pub chain: Vec<String>,
    pub chain_source: &'static str,
    pub rule_id: Option<String>,
    pub rule_expression: Option<String>,
    pub rule_source: &'static str,
    pub ingress: (),
    pub domain_source: Option<&'static str>,
    pub observed_by: &'static str,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub trace_status: &'static str,
}

impl Summary {
    pub(super) fn heap_bytes(&self) -> usize {
        self.id.capacity()
            + self.instance_id.capacity()
            + self.started_at.capacity()
            + optional_bytes([
                &self.pname,
                &self.connection_id,
                &self.outbound,
                &self.rule_id,
                &self.rule_expression,
                &self.ended_at,
            ])
            + self.chain.capacity() * size_of::<String>()
            + self.chain.iter().map(String::capacity).sum::<usize>()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Input {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub domain: Option<String>,
    pub domain_source: Option<&'static str>,
    pub pid: Option<u32>,
    pub process_path: (),
    pub src_mac: Option<String>,
    pub ingress: (),
    pub domain_rule_ids: (),
    pub dscp: Option<u8>,
    pub mark: Option<u32>,
}

impl Input {
    pub(super) fn heap_bytes(&self) -> usize {
        optional_bytes([&self.domain, &self.src_mac])
    }

    fn redact(&mut self, redacted: &mut bool) {
        redact_display(&mut self.domain, redacted);
        redact_display(&mut self.src_mac, redacted);
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct InputValues {
    #[serde(flatten)]
    pub input: Input,
    pub pname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteInput {
    pub network: &'static str,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub domain: Option<String>,
    pub pname: Option<String>,
    pub src_mac: Option<String>,
    pub dscp: Option<u8>,
    pub mark: (),
    pub ingress: (),
    pub domain_rule_ids: (),
}

impl RouteInput {
    fn heap_bytes(&self) -> usize {
        optional_bytes([&self.domain, &self.pname, &self.src_mac])
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct Selection {
    pub group_id: String,
    pub member_id: String,
    pub member_name: Option<String>,
    pub policy: &'static str,
    pub reason: &'static str,
    pub selection: (),
}

#[derive(Clone, Serialize)]
pub(crate) struct OutboundAttempt {
    pub parent_attempt_id: Option<String>,
    pub kind: &'static str,
    pub evaluation_id: Option<String>,
    pub routing_source: &'static str,
    pub routed_outbound: Option<String>,
    pub effective_outbound: Option<String>,
    pub mode_override: &'static str,
    pub selection_path: Vec<Selection>,
    pub leaf_node_id: String,
    pub leaf_node_name: Option<String>,
    pub target: Option<String>,
    pub target_kind: &'static str,
    pub dial_ip: Option<IpAddr>,
    pub server_addr: (),
    pub resolution_location: &'static str,
}

impl OutboundAttempt {
    fn heap_bytes(&self) -> usize {
        optional_bytes([
            &self.parent_attempt_id,
            &self.evaluation_id,
            &self.routed_outbound,
            &self.effective_outbound,
            &self.leaf_node_name,
            &self.target,
        ]) + self.leaf_node_id.capacity()
            + self.selection_path.capacity() * size_of::<Selection>()
            + self
                .selection_path
                .iter()
                .map(|row| {
                    row.group_id.capacity()
                        + row.member_id.capacity()
                        + optional_bytes([&row.member_name])
                })
                .sum::<usize>()
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FlowError {
    PolicyBlock,
    DialFailed,
    DialTimeout,
    LocalRefusal,
    UdpPrepareFailed,
    #[cfg(feature = "rprx")]
    RuntimeGenerationMissing,
    Cancelled,
}

#[derive(Serialize)]
#[serde(tag = "stage", content = "data", rename_all = "snake_case")]
pub(crate) enum StepData {
    Input {
        values: InputValues,
        source: &'static str,
    },
    Route {
        evaluation_id: String,
        chain: &'static str,
        plane: &'static str,
        rule_id: Option<String>,
        rules: [(); 0],
        outbound: Option<String>,
        must: bool,
        mark: u32,
        input: Option<RouteInput>,
        dns_action: (),
    },
    DialMode {
        configured: DialMode,
        effective_target: &'static str,
        domain: Option<String>,
        domain_source: Option<&'static str>,
        verification: &'static str,
        reason: &'static str,
    },
    Reroute {
        performed: bool,
        reason: &'static str,
        from_evaluation_id: Option<String>,
        to_evaluation_id: Option<String>,
    },
    Outbound {
        attempt_id: String,
        #[serde(flatten)]
        attempt: OutboundAttempt,
        status: &'static str,
        error: Option<FlowError>,
    },
    Connection {
        state: &'static str,
        reason: &'static str,
        milestone: &'static str,
        attempt_id: Option<String>,
        reply_received: Option<bool>,
        error: Option<FlowError>,
    },
}

#[derive(Serialize)]
pub(super) struct Step {
    pub seq: usize,
    pub observed_at: String,
    pub elapsed_us: Option<u64>,
    pub generation_id: Option<String>,
    pub evidence: &'static str,
    #[serde(flatten)]
    pub data: StepData,
}

#[derive(Serialize)]
pub(super) struct SnapshotRow {
    #[serde(flatten)]
    pub summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
}

impl SnapshotRow {
    pub(super) fn heap_bytes(&self) -> usize {
        self.summary.heap_bytes() + self.input.as_ref().map_or(0, Input::heap_bytes)
    }
}

impl Step {
    pub(super) fn heap_bytes(&self) -> usize {
        self.observed_at.capacity() + optional_bytes([&self.generation_id]) + self.data.heap_bytes()
    }
}

impl StepData {
    pub(super) fn heap_bytes(&self) -> usize {
        match self {
            Self::Input { values, .. } => {
                values.input.heap_bytes() + optional_bytes([&values.pname])
            }
            Self::Route {
                evaluation_id,
                rule_id,
                outbound,
                input,
                ..
            } => {
                evaluation_id.capacity()
                    + optional_bytes([rule_id, outbound])
                    + input.as_ref().map_or(0, RouteInput::heap_bytes)
            }
            Self::DialMode { domain, .. } => optional_bytes([domain]),
            Self::Reroute {
                from_evaluation_id,
                to_evaluation_id,
                ..
            } => optional_bytes([from_evaluation_id, to_evaluation_id]),
            Self::Outbound {
                attempt_id,
                attempt,
                ..
            } => attempt_id.capacity() + attempt.heap_bytes(),
            Self::Connection { attempt_id, .. } => optional_bytes([attempt_id]),
        }
    }

    pub(super) fn sanitize(&mut self, redacted: &mut bool, overflow: &mut bool) -> bool {
        match self {
            Self::Input { values, source } => {
                values.input.redact(redacted);
                redact_display(&mut values.pname, redacted);
                safe_text(source) && values.input.domain_source.is_none_or(safe_text)
            }
            Self::Route {
                evaluation_id,
                chain,
                plane,
                rule_id,
                outbound,
                input,
                ..
            } => {
                redact_display(outbound, redacted);
                if let Some(input) = input {
                    redact_display(&mut input.domain, redacted);
                    redact_display(&mut input.pname, redacted);
                    redact_display(&mut input.src_mac, redacted);
                    if !safe_text(input.network) {
                        return false;
                    }
                }
                [evaluation_id.as_str(), *chain, *plane]
                    .into_iter()
                    .all(safe_text)
                    && rule_id.as_deref().is_none_or(safe_text)
            }
            Self::DialMode {
                effective_target,
                domain,
                domain_source,
                verification,
                reason,
                ..
            } => {
                redact_display(domain, redacted);
                [*effective_target, *verification, *reason]
                    .into_iter()
                    .all(safe_text)
                    && domain_source.is_none_or(safe_text)
            }
            Self::Reroute {
                reason,
                from_evaluation_id,
                to_evaluation_id,
                ..
            } => {
                safe_text(reason)
                    && from_evaluation_id.as_deref().is_none_or(safe_text)
                    && to_evaluation_id.as_deref().is_none_or(safe_text)
            }
            Self::Outbound {
                attempt_id,
                attempt,
                status,
                ..
            } => {
                if attempt.selection_path.len() > MAX_STEPS {
                    *overflow = true;
                    return false;
                }
                for display in [
                    &mut attempt.routed_outbound,
                    &mut attempt.effective_outbound,
                    &mut attempt.leaf_node_name,
                    &mut attempt.target,
                ] {
                    redact_display(display, redacted);
                }
                for row in &mut attempt.selection_path {
                    redact_display(&mut row.member_name, redacted);
                    if ![
                        row.group_id.as_str(),
                        &row.member_id,
                        row.policy,
                        row.reason,
                    ]
                    .into_iter()
                    .all(safe_text)
                    {
                        return false;
                    }
                }
                [
                    attempt_id.as_str(),
                    attempt.kind,
                    attempt.routing_source,
                    attempt.mode_override,
                    &attempt.leaf_node_id,
                    attempt.target_kind,
                    attempt.resolution_location,
                    *status,
                ]
                .into_iter()
                .all(safe_text)
                    && attempt.parent_attempt_id.as_deref().is_none_or(safe_text)
                    && attempt.evaluation_id.as_deref().is_none_or(safe_text)
            }
            Self::Connection {
                state,
                reason,
                milestone,
                attempt_id,
                ..
            } => {
                [*state, *reason, *milestone].into_iter().all(safe_text)
                    && attempt_id.as_deref().is_none_or(safe_text)
            }
        }
    }
}

fn optional_bytes<const N: usize>(values: [&Option<String>; N]) -> usize {
    values.into_iter().flatten().map(String::capacity).sum()
}

fn redact_display(value: &mut Option<String>, redacted: &mut bool) {
    if value.as_deref().is_some_and(|text| !safe_text(text)) {
        *value = None;
        *redacted = true;
    }
}
