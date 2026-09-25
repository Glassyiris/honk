//! Bounded native DNS diagnostics and Exact cache control.

use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    net::SocketAddr,
    sync::Weak,
    time::{Duration, SystemTime},
};

use axum::{
    body::{Body, to_bytes},
    extract::{Query, Request},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, error, full_detail, invalid_query, timestamp,
    types::RequestId,
};
use crate::dns::{
    DiagnosticError, DiagnosticFailure,
    forwarder::{CacheAccess, ResolveOptions},
    outcome::{DnsOutcome, Provenance, RequestRoute},
    planner::UpstreamTag,
    query::IngressProfile,
};

mod cache;
mod log;
mod records;
#[cfg(test)]
mod tests;

pub(crate) use records::record_type;

pub(super) const MAX_RESPONSE_BYTES: usize = 262_144;
const TYPES: &[u16] = &[1, 2, 5, 6, 12, 15, 16, 28, 33, 64, 65, 257];

pub(crate) struct DnsApi {
    instance: String,
    rate: super::security::RequestRate,
    snapshots: tokio::sync::Mutex<VecDeque<cache::Snapshot>>,
    log: log::LogStore,
    flows: Weak<super::flows::FlowStore>,
}

impl DnsApi {
    pub(crate) fn new(
        instance_id: String,
        recording: bool,
        flows: Weak<super::flows::FlowStore>,
    ) -> Self {
        Self {
            log: log::LogStore::new(instance_id.clone(), recording),
            instance: instance_id,
            rate: super::security::RequestRate::new(),
            snapshots: tokio::sync::Mutex::new(VecDeque::new()),
            flows,
        }
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    pub(crate) fn record_flow(
        &self,
        context: honk_outbound::runtime::flow_observation::FlowContext,
        data: super::flows::record::StepData,
    ) -> bool {
        self.flows.upgrade().is_some_and(|flows| {
            flows.record_step(&context.flow_id.to_string(), Some(context.generation), data)
        })
    }
    pub(crate) fn set_log_limit(&self, limit: usize) {
        self.log.set_limit(limit);
    }
    pub(crate) fn set_recording(&self, recording: bool) {
        self.log.set_recording(recording);
    }
    pub(crate) fn recording(&self) -> bool {
        self.log.recording()
    }
    pub(crate) fn query_capability(&self) -> Value {
        json!({"available":true,"record_types":TYPES.iter().map(|&value| records::record_type(value)).collect::<Vec<_>>(),
            "limits":{"max_types_per_request":8,"query_timeout_ms":10000,"max_response_bytes":MAX_RESPONSE_BYTES,
            "per_principal_requests_per_minute":30,"global_requests_per_minute":30}})
    }
    pub(crate) fn cache_capability(&self) -> Value {
        json!({"available":true,"read":true,"delete_entry":true,"delete_name":true,"flush":true,"entry_kinds":["positive","negative"]})
    }
    pub(crate) fn log_capability(&self) -> Value {
        self.log.capability()
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
    #[cfg(test)]
    pub(crate) fn log_for_test(&self) -> &log::LogStore {
        &self.log
    }
}

pub(super) fn validate_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'_')
        })
}

fn canonical_name(name: &str, id: &RequestId) -> Result<String, ApiError> {
    if !validate_name(name) {
        return Err(invalid_query(id));
    }
    if name == "." {
        return Ok(name.to_owned());
    }
    Ok(format!(
        "{}.",
        name.trim_end_matches('.').to_ascii_lowercase()
    ))
}

fn parameters(
    uri: &Uri,
    allowed: &[&str],
    id: &RequestId,
) -> Result<(HashMap<String, String>, Vec<u16>), ApiError> {
    let Query(pairs) =
        Query::<Vec<(String, String)>>::try_from_uri(uri).map_err(|_| invalid_query(id))?;
    let mut values = HashMap::new();
    let mut types = Vec::new();
    for (key, value) in pairs {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_query(id));
        }
        if key == "type" {
            let qtype = records::parse_type(&value).ok_or_else(|| invalid_query(id))?;
            if types.contains(&qtype) {
                return Err(invalid_query(id));
            }
            types.push(qtype);
        } else if values.insert(key, value).is_some() {
            return Err(invalid_query(id));
        }
    }
    Ok((values, types))
}

pub(super) async fn query(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (values, mut types) = parameters(
        uri,
        &["domain", "type", "upstream", "cache_mode", "detail"],
        id,
    )?;
    let domain = canonical_name(values.get("domain").ok_or_else(|| invalid_query(id))?, id)?;
    if types.is_empty() {
        types.push(1);
    }
    if types.len() > 8 {
        return Err(error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "Too many DNS record types",
            id,
        ));
    }
    if types.iter().any(|value| !TYPES.contains(value)) {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnsupportedValue,
            "Unsupported DNS record type",
            id,
        ));
    }
    let full = full_detail(&values, id)?;
    let cache_mode = values
        .get("cache_mode")
        .map(String::as_str)
        .unwrap_or("normal");
    let options = ResolveOptions {
        cache: match cache_mode {
            "normal" => CacheAccess::Normal,
            "bypass" => CacheAccess::Bypass,
            _ => return Err(invalid_query(id)),
        },
        forced_upstream: values
            .get("upstream")
            .map(|name| UpstreamTag::new(name))
            .transpose()
            .map_err(|_| invalid_query(id))?,
    };
    state.require_running().map_err(|_| unavailable(id))?;
    state.observation.dns.rate.admit(id)?;
    let query_time = timestamp(SystemTime::now());
    let results = state
        .dns
        .diagnostic(
            &domain,
            &types,
            &options,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .map_err(|error| match error {
            DiagnosticError::UnknownUpstream => error_response_upstream(id),
            DiagnosticError::Unavailable => unavailable(id),
        })?;
    let mut budget = MAX_RESPONSE_BYTES.saturating_sub(4096);
    let mut rows = Vec::with_capacity(results.len());
    for result in results {
        let question =
            records::question(&result.query, IngressProfile::Api).map_err(|_| unavailable(id))?;
        let mut row = json!({"type": question.rtype, "question": question, "elapsed_ms": result.elapsed.as_millis().min(9_007_199_254_740_991) as u64});
        match result.outcome {
            Ok(outcome) => {
                let cached = matches!(outcome.provenance(), Provenance::Cache | Provenance::Stale);
                row["cached"] = json!(cached);
                row["cache_entry_id"] = json!(outcome.cache_entry_id());
                row["upstream"] = json!(if cached {
                    None
                } else {
                    outcome.final_upstream()
                });
                row["route"] = json!(outcome.request_route());
                row["status"] = json!(records::status(outcome.rendered()));
                if full {
                    row["answers"] = json!(
                        records::project(
                            &result.query,
                            outcome.rendered(),
                            IngressProfile::Api,
                            &mut budget
                        )
                        .map_err(|_| unavailable(id))?
                    );
                }
            }
            Err(failure) => {
                row["cached"] = json!(false);
                row["cache_entry_id"] = Value::Null;
                row["upstream"] = Value::Null;
                row["route"] = json!(RequestRoute {
                    source: result.route,
                    rule: None
                });
                row["status"] = json!(match failure {
                    DiagnosticFailure::Timeout => "TIMEOUT",
                    DiagnosticFailure::Refused => "REFUSED",
                    DiagnosticFailure::Error => "ERROR",
                });
                if full {
                    row["answers"] = json!([]);
                }
            }
        }
        rows.push(row);
    }
    bounded_response(
        &json!({"domain": domain, "cache_mode": cache_mode, "query_time": query_time, "results": rows}),
        id,
    )
}

fn error_response_upstream(id: &RequestId) -> ApiError {
    error(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "Unknown configured DNS upstream",
        id,
    )
}

fn unavailable(id: &RequestId) -> ApiError {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "DNS observation is temporarily unavailable",
        id,
    )
    .with_retry_after(1)
}

struct BoundedJson(Vec<u8>, usize);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > self.1 {
            return Err(io::Error::other("DNS response budget exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_response(value: &impl Serialize, id: &RequestId) -> Result<Response, ApiError> {
    json_response(value, MAX_RESPONSE_BYTES, id)
}
fn json_response(value: &impl Serialize, cap: usize, id: &RequestId) -> Result<Response, ApiError> {
    let mut writer = BoundedJson(Vec::new(), cap);
    serde_json::to_writer(&mut writer, value).map_err(|_| unavailable(id))?;
    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(writer.0),
    )
        .into_response())
}

pub(super) async fn cache(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    cache::serve(state, uri, id).await
}
pub(super) async fn log(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    log::serve(state, uri, id).await
}

async fn empty_body(request: Request, allow_object: bool, id: &RequestId) -> Result<(), ApiError> {
    let content_types = request.headers().get_all(header::CONTENT_TYPE);
    let json_type = content_types.iter().count() == 1
        && content_types
            .iter()
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    let body = to_bytes(request.into_body(), 65_536).await.map_err(|_| {
        error(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "DNS request body is too large",
            id,
        )
    })?;
    if body.is_empty() {
        return Ok(());
    }
    if !allow_object {
        return Err(invalid_query(id));
    }
    if !json_type {
        return Err(error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            id,
        ));
    }
    if serde_json::from_slice::<Value>(&body).ok() == Some(json!({})) {
        Ok(())
    } else {
        Err(invalid_query(id))
    }
}

pub(super) async fn delete_name(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (values, types) = parameters(request.uri(), &["name", "type"], id)?;
    let name = canonical_name(values.get("name").ok_or_else(|| invalid_query(id))?, id)?;
    empty_body(request, false, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::Name { name, types })
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(
        &json!({"matched":result.matched,"deleted":result.deleted}),
        id,
    )
}

pub(super) async fn delete_entry(
    state: &NativeState,
    entry_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parameters(request.uri(), &[], id)?;
    empty_body(request, false, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::Id(
            entry_id.to_owned(),
        ))
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(&json!({"deleted":result.deleted}), id)
}

pub(super) async fn flush(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parameters(request.uri(), &[], id)?;
    empty_body(request, true, id).await?;
    let result = state
        .dns
        .invalidate_cache(crate::dns::cache::CacheInvalidation::All)
        .await
        .map_err(|_| unavailable(id))?;
    bounded_response(
        &json!({"matched":result.matched,"deleted":result.deleted}),
        id,
    )
}
