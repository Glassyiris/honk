//! Source callbacks share the recorder's identity, privacy and retention boundary.

use std::sync::{Arc, atomic::Ordering};
use std::time::{Instant, SystemTime};

use honk_outbound::runtime::flow_observation::{self, FlowContext, FlowEvent, FlowObserver};
use uuid::Uuid;

use super::{
    FlowGuard, MAX_RULE_VALUES, MAX_STEPS, MAX_TEXT, bounded_display,
    record::{FlowError, Input, InputValues, OutboundAttempt, Selection, StepData},
    safe_optional, safe_text, timestamp,
};

impl FlowGuard {
    pub(crate) fn observer(
        self: &Arc<Self>,
        generation: u64,
        attempt_id: Option<Uuid>,
        dns_purpose: &'static str,
    ) -> Option<FlowObserver> {
        if self.id.is_empty() {
            return None;
        }
        let store = self.store.upgrade()?;
        if !store
            .inner
            .lock()
            .records
            .iter()
            .any(|record| record.id() == self.id && record.ended.is_none())
        {
            return None;
        }
        let flow_id = self.id.parse().expect("recorder UUID");
        let weak = Arc::downgrade(self);
        Some(FlowObserver::new(
            FlowContext {
                flow_id,
                generation,
                attempt_id,
                lookup_id: None,
                dns_purpose,
            },
            Arc::new(move |context, event| {
                if context.flow_id == flow_id
                    && let Some(flow) = weak.upgrade()
                {
                    flow.observe(context, event);
                }
            }),
        ))
    }

    fn observe(&self, context: FlowContext, event: FlowEvent) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        match event {
            FlowEvent::Gap(reason) => self.mark_gap(reason),
            FlowEvent::Dns(data) => {
                if data.attempt_id != context.attempt_id
                    || (context.lookup_id != Some(data.lookup_id)
                        && context.lookup_id != data.parent_lookup_id)
                    || data.parent_lookup_id == Some(data.lookup_id)
                {
                    self.mark_gap("not_instrumented");
                    return;
                }
                store.record_step(&self.id, Some(context.generation), StepData::Dns(data));
            }
            FlowEvent::Transport {
                attempt_id,
                server_addr,
                status,
                resolution_location,
                error,
            } => {
                if context.attempt_id == Some(attempt_id) {
                    self.mark_gap("not_instrumented");
                    return;
                }
                store.record_with(&self.id, Some(context.generation), |record| {
                    let parent_id = context.attempt_id.map(|id| id.to_string());
                    let parent = parent_id.as_ref().and_then(|parent| {
                        record.steps.iter().rev().find_map(|step| match &step.data {
                            StepData::Outbound {
                                attempt_id,
                                attempt,
                                ..
                            } if attempt_id == parent => Some(attempt),
                            _ => None,
                        })
                    });
                    let data = OutboundAttempt {
                        parent_attempt_id: parent_id.clone(),
                        lookup_id: context.lookup_id.map(|id| id.to_string()),
                        kind: "transport",
                        evaluation_id: parent.and_then(|parent| parent.evaluation_id.clone()),
                        routing_source: parent.map_or(
                            if parent_id.is_some() {
                                "unknown"
                            } else {
                                "builtin"
                            },
                            |parent| parent.routing_source,
                        ),
                        routed_outbound: parent.and_then(|parent| parent.routed_outbound.clone()),
                        effective_outbound: parent
                            .and_then(|parent| parent.effective_outbound.clone()),
                        mode_override: parent.map_or(
                            if parent_id.is_some() {
                                "unknown"
                            } else {
                                "none"
                            },
                            |parent| parent.mode_override,
                        ),
                        selection_path: Vec::new(),
                        leaf_node_id: None,
                        leaf_node_name: None,
                        target: server_addr.map(|address| address.to_string()),
                        target_kind: if server_addr.is_some() {
                            "ip"
                        } else {
                            "unknown"
                        },
                        dial_ip: server_addr.map(|address| address.ip()),
                        server_addr,
                        resolution_location,
                    };
                    Some(StepData::Outbound {
                        attempt_id: attempt_id.to_string(),
                        attempt: data,
                        status,
                        error: error.map(FlowError::Code),
                    })
                });
            }
            FlowEvent::TransportAttached { server_addr, .. } => {
                store.record_with(&self.id, Some(context.generation), |record| {
                    Some(StepData::Connection {
                        state: record.summary.state,
                        reason: if context.lookup_id.is_some() {
                            "dns_transport_attached"
                        } else {
                            "transport_attached"
                        },
                        milestone: "transport_ready",
                        attempt_id: context.attempt_id.map(|id| id.to_string()),
                        reply_received: None,
                        error: None,
                        selections: Vec::new(),
                        lookup_id: context.lookup_id.map(|id| id.to_string()),
                        server_addr,
                    })
                });
            }
            FlowEvent::Session { reason, error } => {
                store.record_with(&self.id, Some(context.generation), |record| {
                    Some(StepData::Connection {
                        state: record.summary.state,
                        reason,
                        milestone: "unknown",
                        attempt_id: context.attempt_id.map(|id| id.to_string()),
                        reply_received: None,
                        error: error.map(FlowError::Code),
                        selections: Vec::new(),
                        lookup_id: context.lookup_id.map(|id| id.to_string()),
                        server_addr: None,
                    })
                });
            }
            FlowEvent::Milestone { milestone } => {
                let reason = match (context.lookup_id.is_some(), milestone) {
                    (false, "transport_ready") => "transport_ready",
                    (false, "target_request_sent") => "protocol_request_sent",
                    (false, "target_confirmed") => "target_confirmed",
                    (true, "transport_ready") => "dns_transport_ready",
                    (true, "target_request_sent") => "dns_request_sent",
                    (true, "target_confirmed") => "dns_target_confirmed",
                    _ => {
                        self.mark_gap("not_instrumented");
                        return;
                    }
                };
                store.record_with(&self.id, Some(context.generation), |record| {
                    Some(StepData::Connection {
                        state: record.summary.state,
                        reason,
                        milestone,
                        attempt_id: context.attempt_id.map(|id| id.to_string()),
                        reply_received: None,
                        error: None,
                        selections: Vec::new(),
                        lookup_id: context.lookup_id.map(|id| id.to_string()),
                        server_addr: None,
                    })
                });
            }
        }
    }

    pub(crate) fn observe_selection(&self, generation: u64, selections: Vec<Selection>) {
        if selections.is_empty() {
            return;
        }
        if let Some(store) = self.store.upgrade() {
            store.record_with(&self.id, Some(generation), |record| {
                Some(StepData::Connection {
                    state: record.summary.state,
                    reason: "selection_evaluated",
                    milestone: "unknown",
                    attempt_id: None,
                    reply_received: None,
                    error: None,
                    selections,
                    lookup_id: None,
                    server_addr: None,
                })
            });
        }
    }

    pub(crate) fn accepted_send(&self) {
        if self.id.is_empty() || self.sent.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Some(store) = self.store.upgrade() {
            store.record_with(&self.id, None, |record| {
                Some(StepData::Connection {
                    state: record.summary.state,
                    reason: "application_send_accepted",
                    milestone: "unknown",
                    attempt_id: record.selected_attempt.clone(),
                    reply_received: Some(self.replied.load(Ordering::Relaxed)),
                    error: None,
                    selections: Vec::new(),
                    lookup_id: None,
                    server_addr: None,
                })
            });
        }
    }
}

impl FlowGuard {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Returns true only for the first observed reply; callers need not record every packet.
    pub(crate) fn first_reply(&self) -> bool {
        !self.id.is_empty() && !self.replied.swap(true, Ordering::Relaxed)
    }

    pub(crate) fn step(&self, generation: Option<u64>, mut data: StepData) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        if let StepData::Connection {
            reply_received: Some(reply_received),
            ..
        } = &mut data
        {
            *reply_received |= self.replied.load(Ordering::Relaxed);
        }
        store.record_step(&self.id, generation, data);
    }

    pub(crate) fn mark_gap(&self, reason: &'static str) {
        if let Some(store) = self.store.upgrade() {
            store.mark_gap(&self.id, reason);
        }
    }

    pub(crate) fn mark_overflow(&self) {
        self.mark_gap("buffer_overflow");
    }

    pub(crate) fn select_attempt(&self, attempt: &str) {
        if let Some(store) = self.store.upgrade() {
            store.mutate(&self.id, |record| {
                if !safe_text(attempt) {
                    return record.mark_gap("redacted");
                }
                if record.selected_attempt.as_deref() == Some(attempt) {
                    return false;
                }
                record.selected_attempt = Some(attempt.to_owned());
                true
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_input(
        &self,
        domain: Option<&str>,
        source: Option<&'static str>,
        pname: Option<&str>,
        pid: Option<u32>,
        src_mac: Option<String>,
        dscp: Option<u8>,
        mark: Option<u32>,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let mut redacted = record.redacted;
            let domain = domain
                .and_then(|value| bounded_display(value, &mut redacted, &mut record.overflow));
            let pname =
                pname.and_then(|value| bounded_display(value, &mut redacted, &mut record.overflow));
            let src_mac = src_mac
                .as_deref()
                .and_then(|value| bounded_display(value, &mut redacted, &mut record.overflow));
            let source = source.map(domain_source);
            let dscp = dscp.filter(|value| *value <= 63);
            let input = Input {
                src: record.input.src,
                dst: record.input.dst,
                domain,
                domain_source: source,
                pid,
                process_path: (),
                src_mac,
                ingress: (),
                domain_rule_ids: (),
                dscp,
                mark,
            };
            let changed = record.redacted != redacted
                || record.input != input
                || record.summary.pname != pname
                || record.summary.domain_source != source;
            record.redacted = redacted;
            record.input = input;
            record.summary.pname = pname;
            record.summary.domain_source = source;
            let input_source = match source {
                Some("dns_mapping") => Some("dns_mapping"),
                Some("tls_sni" | "http_host" | "quic_sni") => Some("sniffer"),
                _ => None,
            };
            if changed && let Some(input_source) = input_source {
                record.push_step(
                    None,
                    StepData::Input {
                        values: InputValues {
                            input: record.input.clone(),
                            pname: record.summary.pname.clone(),
                        },
                        source: input_source,
                    },
                );
            }
            changed
        });
    }

    pub(crate) fn routed(
        &self,
        outbound: &str,
        rule_id: Option<&str>,
        expression: Option<&str>,
        source: &'static str,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let mut redacted = record.redacted;
            let outbound = bounded_display(outbound, &mut redacted, &mut record.overflow);
            let rule_id = safe_optional(rule_id, &mut redacted);
            let expression = if record.summary.rule_id == rule_id && rule_id.is_some() {
                record.summary.rule_expression.clone()
            } else {
                expression.and_then(|expression| {
                    bounded_display(expression, &mut redacted, &mut record.overflow)
                })
            };
            let reason = if record.summary.outbound == outbound {
                "mode_preserved"
            } else if outbound.as_deref() == Some("direct") {
                "mode_direct"
            } else if record.summary.outbound.is_none() {
                "forced_outbound"
            } else {
                "mode_global"
            };
            let gap_changed = source == "unknown" && record.mark_gap("not_instrumented");
            let source = rule_source(source);
            let changed = record.summary.outbound != outbound
                || record.summary.rule_id != rule_id
                || record.summary.rule_expression != expression
                || record.summary.rule_source != source
                || record.redacted != redacted
                || !record.mode_recorded
                || gap_changed;
            record.summary.outbound = outbound;
            record.summary.rule_id = rule_id;
            record.summary.rule_expression = expression;
            record.summary.rule_source = source;
            record.redacted = redacted;
            if changed {
                record.mode_recorded = true;
                record.push_step(
                    None,
                    StepData::Connection {
                        state: record.summary.state,
                        reason,
                        milestone: "unknown",
                        attempt_id: None,
                        reply_received: None,
                        error: None,
                        selections: Vec::new(),
                        lookup_id: None,
                        server_addr: None,
                    },
                );
            }
            changed
        });
    }

    pub(crate) fn selected(&self, chain: Vec<String>) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            if chain.len() > MAX_STEPS {
                return record.mark_gap("buffer_overflow");
            }
            let chain = chain
                .iter()
                .filter_map(|part| {
                    bounded_display(part, &mut record.redacted, &mut record.overflow)
                })
                .collect::<Vec<_>>();
            if record.summary.chain == chain && record.summary.chain_source == "evaluation" {
                return false;
            }
            record.summary.chain = chain;
            record.summary.chain_source = "evaluation";
            true
        });
    }

    pub(crate) fn attach_connection(&self, id: &str) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            if !safe_text(id) {
                return !std::mem::replace(&mut record.redacted, true);
            }
            if record.summary.connection_id.as_deref() == Some(id) {
                return false;
            }
            record.summary.connection_id = Some(id.to_owned());
            true
        });
    }

    pub(crate) fn transition(
        &self,
        state: &'static str,
        reason: &'static str,
        milestone: &'static str,
        reply_received: Option<bool>,
    ) {
        let Some(store) = self.store.upgrade() else {
            return;
        };
        store.mutate(&self.id, |record| {
            let state = connection_state(state);
            let milestone = match milestone {
                "transport_ready"
                | "target_request_sent"
                | "target_confirmed"
                | "first_reply"
                | "terminal" => milestone,
                _ => "unknown",
            };
            let redacted = !safe_text(reason);
            let reason = if redacted { "redacted" } else { reason };
            let changed = record.summary.state != state
                || milestone == "terminal"
                || matches!(state, "closed" | "blocked" | "failed")
                || (redacted && !record.redacted);
            record.redacted |= redacted;
            record.summary.state = state;
            if milestone == "terminal" || matches!(state, "closed" | "blocked" | "failed") {
                if state == "unknown" || record.has_open_operations() {
                    record.mark_gap("not_instrumented");
                }
                record.ended = Some(Instant::now());
                record.summary.ended_at = Some(timestamp(SystemTime::now()));
            }
            record.push_step(
                None,
                StepData::Connection {
                    state,
                    reason,
                    milestone,
                    attempt_id: record.selected_attempt.clone(),
                    reply_received,
                    error: None,
                    selections: Vec::new(),
                    lookup_id: None,
                    server_addr: None,
                },
            ) || changed
        });
    }

    pub(crate) fn finish(&self, state: &'static str, reason: &'static str) {
        let state = match state {
            "closed" | "blocked" | "failed" => state,
            _ => "unknown",
        };
        self.transition(
            state,
            reason,
            "terminal",
            Some(self.replied.load(Ordering::Relaxed)),
        );
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        self.finish("failed", "cancelled");
    }
}

pub(super) fn connection_state(value: &str) -> &'static str {
    match value {
        "observed" => "observed",
        "routing" => "routing",
        "dialing" => "dialing",
        "active" => "active",
        "closed" => "closed",
        "blocked" => "blocked",
        "failed" => "failed",
        _ => "unknown",
    }
}

fn domain_source(value: &str) -> &'static str {
    match value {
        "tls_sni" => "tls_sni",
        "http_host" => "http_host",
        "quic_sni" => "quic_sni",
        "dns_mapping" => "dns_mapping",
        "explicit" => "explicit",
        _ => "unknown",
    }
}

/// The wire vocabulary knows a kernel decision and userspace evidence. The
/// userspace connection paths name their route `evaluation`; that is the
/// recomputed kind, not an unknown one.
fn rule_source(value: &str) -> &'static str {
    match value {
        "kernel" => "kernel",
        "recomputed" | "evaluation" => "recomputed",
        _ => "unknown",
    }
}

pub(crate) fn bounded(value: &str) -> String {
    if value.len() > MAX_TEXT
        && let Some(observer) = flow_observation::current()
    {
        observer.publish(FlowEvent::Gap("buffer_overflow"));
    }
    let mut end = value.len().min(MAX_TEXT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

pub(crate) fn map_selection_observation(
    observation: &honk_outbound::group::observation::SelectionObservation,
    catalog: &crate::native_api::catalog::CatalogIdentity,
    observer: &FlowObserver,
) -> Vec<super::record::Selection> {
    use honk_outbound::group::observation::ObservedMember;
    fn member(
        value: &ObservedMember,
        catalog: &crate::native_api::catalog::CatalogIdentity,
        observer: &FlowObserver,
    ) -> Option<(String, Option<String>)> {
        match value {
            ObservedMember::Node { id, name } => {
                Some((id.to_string(), name.as_deref().map(bounded)))
            }
            ObservedMember::Group { name } => match catalog.groups.get(name) {
                Some(id) => Some((id.clone(), Some(bounded(name)))),
                None => {
                    observer.publish(FlowEvent::Gap("not_instrumented"));
                    None
                }
            },
        }
    }
    if observation.truncated || observation.decisions.len() > 64 {
        observer.publish(FlowEvent::Gap("buffer_overflow"));
    }
    let mut remaining = MAX_RULE_VALUES;
    observation
        .decisions
        .iter()
        .take(64)
        .filter_map(|decision| {
            let Some(group_id) = catalog.groups.get(&decision.group_name) else {
                observer.publish(FlowEvent::Gap("not_instrumented"));
                return None;
            };
            let selected = decision
                .selected_member
                .as_ref()
                .and_then(|value| member(value, catalog, observer));
            let previous = decision
                .previous_member
                .as_ref()
                .and_then(|value| member(value, catalog, observer));
            let count = decision.candidates.len().min(remaining);
            remaining -= count;
            if count != decision.candidates.len() {
                observer.publish(FlowEvent::Gap("buffer_overflow"));
            }
            let candidates = decision
                .candidates
                .iter()
                .take(count)
                .filter_map(|candidate| {
                    let (member_id, member_name) = member(&candidate.member, catalog, observer)?;
                    Some(super::record::SelectionCandidate {
                        member_id,
                        member_name,
                        leaf_node_id: candidate.leaf_node_id.map(|id| id.to_string()),
                        leaf_node_name: candidate.leaf_node_name.as_deref().map(bounded),
                        eligible: candidate.eligible,
                        sorting_latency_ms: candidate.sorting_latency_ms,
                        score: candidate.score,
                        selected: candidate.selected,
                        reason: candidate.reason,
                    })
                })
                .collect();
            Some(super::record::Selection {
                group_id: group_id.clone(),
                member_id: selected.as_ref().map(|(id, _)| id.clone()),
                member_name: selected.and_then(|(_, name)| name),
                policy: decision.policy,
                reason: decision.reason,
                health_family: Some(match decision.health_family {
                    honk_outbound::alive::IpVersion::V4 => "ipv4",
                    honk_outbound::alive::IpVersion::V6 => "ipv6",
                }),
                applied: Some(decision.applied),
                selection: Some(super::record::SelectionDecision {
                    previous_member_id: previous.map(|(id, _)| id),
                    metric: decision.metric,
                    previous_leaf_node_id: decision.previous_leaf_node_id.map(|id| id.to_string()),
                    tolerance_ms: decision.tolerance_ms,
                    candidates,
                }),
            })
        })
        .collect()
}
