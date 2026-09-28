//! Where DNS evidence lands: flow steps and the client query log.

use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use super::flows::{FlowStore, record::StepData};
use crate::dns::{outcome::DnsOutcome, query::IngressProfile};

pub(crate) trait DnsLog: Send + Sync {
    fn recording(&self) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn capture(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    );
}

pub(crate) struct DnsRecorder {
    instance: String,
    flows: Weak<FlowStore>,
    log: Arc<dyn DnsLog>,
}

impl DnsRecorder {
    pub(crate) fn new(instance: String, flows: Weak<FlowStore>, log: Arc<dyn DnsLog>) -> Self {
        Self {
            instance,
            flows,
            log,
        }
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    pub(crate) fn record_flow(
        &self,
        context: honk_outbound::runtime::flow_observation::FlowContext,
        data: StepData,
    ) -> bool {
        self.flows.upgrade().is_some_and(|flows| {
            flows.record_step(&context.flow_id.to_string(), Some(context.generation), data)
        })
    }

    pub(crate) fn recording(&self) -> bool {
        self.log.recording()
    }

    pub(crate) fn observe_client(
        &self,
        query: &[u8],
        ingress: IngressProfile,
        source: Option<SocketAddr>,
        outcome: Option<&DnsOutcome>,
        response: &[u8],
        elapsed: Duration,
    ) {
        self.log
            .capture(query, ingress, source, outcome, response, elapsed);
    }
}
