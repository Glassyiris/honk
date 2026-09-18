//! Wire types for the pinned native API contract.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    AuthenticationRequired,
    PermissionDenied,
    ResourceNotFound,
    CapabilityNotSupported,
    StateConflict,
    IdempotencyConflict,
    EventCursorExpired,
    SnapshotUnavailable,
    SnapshotExpired,
    FlowExpired,
    StaleRevision,
    RequestTooLarge,
    UnsupportedMediaType,
    UnsupportedValue,
    PreconditionRequired,
    RateLimited,
    TemporarilyUnavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    status: StatusCode,
    error: ErrorBody,
    request_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorBody {
    code: ErrorCode,
    message: &'static str,
    details: Option<Value>,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: ErrorCode,
        message: &'static str,
        request_id: Option<String>,
    ) -> Self {
        Self {
            status,
            error: ErrorBody {
                code,
                message,
                details: None,
            },
            request_id,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.error.details = Some(details);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let mut response = (
            self.status,
            [
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
            ],
            Json(self),
        )
            .into_response();
        if matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            response
                .headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from_static("1"));
        }
        response
    }
}

#[derive(Clone)]
pub(super) struct RequestId(pub String);

#[derive(Clone, Serialize)]
pub(super) struct Runtime {
    pub(super) observed_at: String,
    pub(super) instance_id: String,
    pub(super) lifecycle: Lifecycle,
    pub(super) generation: Generation,
    pub(super) datapath: DatapathSummary,
    pub(super) traffic: TrafficSummary,
    pub(super) process: Process,
    pub(super) last_reload: Option<Value>,
}

#[derive(Clone, Serialize)]
pub(super) struct Lifecycle {
    pub(super) state: &'static str,
    pub(super) started_at: Option<String>,
    pub(super) uptime_seconds: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct Generation {
    pub(super) active_id: String,
    pub(super) config_revision: Option<String>,
    pub(super) state: &'static str,
    pub(super) activated_at: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct DatapathSummary {
    pub(super) kind: &'static str,
    pub(super) state: &'static str,
    pub(super) visibility: &'static str,
    // No kernel inspection is performed by the M1 API.
    pub(super) ebpf: (),
}

#[derive(Clone, Serialize)]
pub(super) struct Process {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) pid: Option<u32>,
    pub(super) cpu_percent: Option<f64>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficSummary {
    pub(super) scope: &'static str,
    pub(super) observed_by: &'static str,
    pub(super) counter_since: Option<String>,
    pub(super) sampled_at: Option<String>,
    pub(super) connections: TrafficConnections,
    pub(super) bytes: TrafficBytes,
    pub(super) rates: Option<TrafficRates>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficConnections {
    pub(super) tcp: Option<u64>,
    pub(super) udp: Option<u64>,
    pub(super) total: Option<u64>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficBytes {
    pub(super) upload: Option<String>,
    pub(super) download: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct TrafficRates {
    pub(super) window_seconds: f64,
    pub(super) upload_bytes_per_second: Option<String>,
    pub(super) download_bytes_per_second: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct Connection {
    pub(super) id: String,
    pub(super) flow_id: Option<String>,
    pub(super) pname: Option<String>,
    pub(super) state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) dst: Option<String>,
    // Outer None omits summary data; Some(None) retains full-detail unknowns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) domain: Option<Option<String>>,
    pub(super) outbound: Option<String>,
    pub(super) chain: Vec<String>,
    pub(super) chain_source: &'static str,
    pub(super) rule_id: Option<String>,
    pub(super) rule_expression: Option<String>,
    pub(super) rule_source: &'static str,
    pub(super) ingress: Option<&'static str>,
    pub(super) domain_source: Option<&'static str>,
    pub(super) started_at: Option<String>,
    pub(super) observed_by: &'static str,
    pub(super) upload_bytes: Option<String>,
    pub(super) download_bytes: Option<String>,
    pub(super) upload_bytes_per_second: Option<String>,
    pub(super) download_bytes_per_second: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct ConnectionList {
    pub(super) observed_at: String,
    pub(super) instance_id: String,
    pub(super) visibility: &'static str,
    pub(super) truncated: bool,
    pub(super) tcp: Vec<Connection>,
    pub(super) udp: Vec<Connection>,
    pub(super) total_tcp: u64,
    pub(super) total_udp: u64,
}

pub(super) fn discovery() -> Value {
    json!({
        "name": "dae/honk-native",
        "status": "draft",
        "api_major": 1,
        "base_path": "/api/v1",
        "links": {
            "version": "/api/v1/version",
            "capabilities": "/api/v1/capabilities",
            "config": "/api/v1/config",
            "config_validate": "/api/v1/config/validate",
            "runtime": "/api/v1/runtime",
            "runtime_outbounds": "/api/v1/runtime/outbounds",
            "traffic_history": "/api/v1/runtime/traffic/history",
            "memory_history": "/api/v1/runtime/memory/history",
            "runtime_mode": "/api/v1/runtime/mode",
            "logs": "/api/v1/logs",
            "providers": "/api/v1/providers",
            "rules": "/api/v1/rules",
            "operations": "/api/v1/operations/{id}",
        },
    })
}

pub(super) fn version() -> Value {
    json!({
        "api": {"name": "dae/honk-native", "major": 1, "status": "draft"},
        "engine": {"name": "honk", "version": crate::VERSION},
    })
}

pub(super) fn capabilities(state: &super::NativeState) -> Value {
    let config = &state.observation.configuration;
    let telemetry = &state.observation.telemetry;
    let mut kinds = vec![
        "stream.ready",
        "runtime.updated",
        "flow.updated",
        "flow.gap",
        "generation.changed",
    ];
    if config.running() {
        kinds.push("operation.updated");
    }
    json!({
        "observed_at": chrono::Utc::now().to_rfc3339(),
        "profiles": ["base"],
        "limits": {
            "max_request_target_bytes": 4096,
            "max_header_bytes": 16384,
            "max_json_body_bytes": 65536,
        },
        "resources": {
            "config": {"available":config.available(),"content":config.content_enabled(),"writable":config.writable(),"max_bytes":super::config::MAX_SOURCE_BYTES,"max_sources":super::config::MAX_SOURCES},
            "config_validate": {"available":config.running(),"modes":["syntax","full"],"max_bytes":super::config::MAX_SOURCE_BYTES,"max_sources":super::config::MAX_SOURCES},
            "runtime": {"available": true},
            "runtime_memory": {"available":true,"metrics":telemetry.metrics()},
            "runtime_outbounds": {"available":true},
            "traffic_history": {"available":telemetry.record_traffic(),"max_window_seconds":600,"max_points":600},
            "memory_history": {"available":telemetry.record_memory(),"max_window_seconds":600,"max_points":600},
            "runtime_mode": {"available": false},
            "datapath": {"available": false},
            "nodes": {"available": true},
            "providers": {"available": false},
            "groups": {"available": true, "config_patch": false, "selection": false, "max_patch_operations":32},
            "probes": {"available": false},
            "connections": {
                "available": true,
                "can_close": false,
                "max_bulk_close": 1000,
            },
            "flows": {"available": true, "recording": if state.settings.record_flows { "on" } else { "off" }, "scopes":["userspace_tcp","userspace_udp"], "max_flows":1024, "max_steps_per_flow":64, "retention_seconds":300, "snapshot_ttl_seconds":30, "max_page_size":1000},
            "routing_trace": {"available": false},
            "rules": {"available": false},
            "events": {"available":true,"kinds":kinds,"retention_seconds":60,"max_buffered_events":512,"max_clients":16,"heartbeat_seconds":15},
            "logs": {"available": false},
            "dns_query": {"available": false},
            "dns_cache": {"available": false},
            "dns_log": {"available": false},
            "runtime_settings": {"available": false},
            "operations": {"available":config.running(),"retention_seconds":300},
            "reload": {"available":config.running()},
            "suspend": {"available": false},
            "resume": {"available": false},
        },
    })
}
