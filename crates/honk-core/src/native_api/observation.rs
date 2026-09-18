use std::sync::Arc;

use honk_config::Config;
use serde_json::{Value, json};

use super::{
    catalog::Catalog,
    events::EventHub,
    flows::{FlowGuard, FlowStore},
};

pub(crate) struct NativeObservation {
    pub(crate) instance_id: String,
    pub(crate) events: Arc<EventHub>,
    pub(crate) flows: Arc<FlowStore>,
    pub(crate) record_flows: bool,
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) telemetry: super::telemetry::Telemetry,
    pub(crate) configuration: Arc<super::config::ConfigService>,
}

impl NativeObservation {
    pub(crate) fn new(config: &Config) -> Self {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let events = Arc::new(EventHub::new(instance_id.clone()));
        let flows = Arc::new(FlowStore::new(instance_id.clone(), Arc::clone(&events)));
        flows.set_recording(config.experimental.native_api.record_flows);
        let operations = Arc::new(super::operations::OperationStore::new(
            instance_id.clone(),
            Arc::clone(&events),
        ));
        let configuration = Arc::new(super::config::ConfigService::new(
            config.experimental.native_api.clone(),
            instance_id.clone(),
            operations,
        ));
        Self {
            instance_id,
            events,
            flows,
            catalog: Arc::new(Catalog::new(config)),
            record_flows: config.experimental.native_api.record_flows,
            telemetry: super::telemetry::Telemetry::new(
                config.experimental.native_api.record_traffic,
                config.experimental.native_api.record_memory,
            ),
            configuration,
        }
    }

    pub(crate) fn committed(&self, config: &Config, previous: u64, generation: u64) {
        self.catalog.install(config);
        self.configuration
            .generation_committed(&self.catalog.snapshot().revision, generation);
        if previous != generation {
            self.events.publish(
                "generation.changed",
                json!({
                    "previous_generation_id": format!("{}:{previous}", self.instance_id),
                    "generation_id": format!("{}:{generation}", self.instance_id),
                }),
                None,
            );
        }
        self.events.publish("runtime.updated", json!({}), None);
    }
}

#[derive(Debug)]
pub(crate) struct NativeRoute {
    pub(crate) generation: Option<u64>,
    pub(crate) evaluation_id: String,
    pub(crate) plane: &'static str,
    pub(crate) input: Option<Value>,
}

pub(crate) struct NativeAttempt {
    flow: Arc<FlowGuard>,
    generation: Option<u64>,
    data: Value,
    finished: bool,
}

impl NativeAttempt {
    pub(crate) fn new(flow: Arc<FlowGuard>, generation: Option<u64>, mut data: Value) -> Self {
        data["attempt_id"] = Value::String(uuid::Uuid::new_v4().to_string());
        data["status"] = Value::String("started".into());
        data["error"] = Value::Null;
        flow.step("outbound", generation, data.clone());
        Self {
            flow,
            generation,
            data,
            finished: false,
        }
    }

    pub(crate) fn finish(&mut self, status: &'static str, error: Option<&'static str>) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.data["status"] = Value::String(status.into());
        self.data["error"] = error
            .map(|code| Value::String(code.into()))
            .unwrap_or(Value::Null);
        self.flow
            .step("outbound", self.generation, self.data.clone());
    }
}

impl Drop for NativeAttempt {
    fn drop(&mut self) {
        self.finish("cancelled", Some("cancelled"));
    }
}
pub(crate) fn native_selection_path(
    config: &Config,
    catalog: &super::catalog::CatalogIdentity,
    chain: &[String],
    node: &honk_config::node::Node,
) -> Vec<Value> {
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
            Some(
                json!({"group_id":group_id,"member_id":next.0,"member_name":next.1,
            "policy":policy,"reason":"captured_plan","selection":null}),
            )
        })
        .collect()
}
