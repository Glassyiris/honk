//! Source callbacks share the recorder's identity, privacy and retention boundary.

use std::sync::{Arc, atomic::Ordering};

use honk_outbound::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
use uuid::Uuid;

use super::{
    FlowGuard,
    record::{FlowError, OutboundAttempt, Selection, StepData},
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
