//! One transition owner for runtime-only native recorder settings.

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::Config;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, observation::NativeObservation, parse_query, types::RequestId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
impl Level {
    pub(crate) fn configured(value: &str) -> Self {
        if value.eq_ignore_ascii_case("trace") {
            Self::Trace
        } else if value.eq_ignore_ascii_case("debug") {
            Self::Debug
        } else if value.eq_ignore_ascii_case("warn") || value.eq_ignore_ascii_case("warning") {
            Self::Warn
        } else if value.eq_ignore_ascii_case("error") {
            Self::Error
        } else {
            Self::Info
        }
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy)]
struct Values {
    level: Level,
    logs: usize,
    dns: usize,
    flows: usize,
    retention: u64,
    overridden: bool,
}
impl Values {
    fn configured(config: &Config) -> Self {
        Self {
            level: Level::configured(&config.global.log_level),
            logs: 512,
            dns: 512,
            flows: 1024,
            retention: 300,
            overridden: false,
        }
    }
    fn json(self) -> Value {
        json!({"observed_at":chrono::Utc::now().to_rfc3339(),"source":if self.overridden {"runtime"} else {"config"},
            "log":{"level":self.level,"buffered_records":self.logs},"dns_log":{"max_records":self.dns},
            "flows":{"max_flows":self.flows,"retention_seconds":self.retention}})
    }
    fn apply(self, owner: &NativeObservation) {
        owner.logs.set_level(self.level.as_str());
        owner.logs.set_limit(self.logs);
        owner.dns.set_log_limit(self.dns);
        owner.flows.set_limits(self.flows, self.retention);
    }
}

pub(crate) struct Settings(Mutex<Values>);
impl Settings {
    pub(crate) fn new(config: &Config) -> Self {
        Self(Mutex::new(Values::configured(config)))
    }
    pub(crate) fn activate(&self, owner: &NativeObservation, config: &Config) {
        let mut current = self.0.lock();
        let next = Values::configured(config);
        next.apply(owner);
        *current = next;
    }
    fn snapshot(&self) -> Value {
        self.0.lock().json()
    }
    fn patch(
        &self,
        owner: &NativeObservation,
        settings: &honk_config::experimental::NativeApiConfig,
        patch: Patch,
        id: &RequestId,
    ) -> Result<Value, ApiError> {
        let mut current = self.0.lock();
        let mut next = *current;
        if patch.log.is_none() && patch.dns_log.is_none() && patch.flows.is_none() {
            return Err(invalid(id));
        }
        if let Some(log) = patch.log {
            if !settings.record_logs || (log.level.is_none() && log.buffered_records.is_none()) {
                return Err(invalid(id));
            }
            if let Some(level) = log.level {
                next.level = level;
            }
            if let Some(count) = log.buffered_records {
                if !(64..=512).contains(&count) {
                    return Err(invalid(id));
                }
                next.logs = count;
            }
        }
        if let Some(dns) = patch.dns_log {
            let Some(count) = dns.max_records else {
                return Err(invalid(id));
            };
            if !settings.record_dns_log || !(64..=512).contains(&count) {
                return Err(invalid(id));
            }
            next.dns = count;
        }
        if let Some(flows) = patch.flows {
            if !settings.record_flows
                || (flows.max_flows.is_none() && flows.retention_seconds.is_none())
            {
                return Err(invalid(id));
            }
            if let Some(count) = flows.max_flows {
                if !(64..=1024).contains(&count) {
                    return Err(invalid(id));
                }
                next.flows = count;
            }
            if let Some(seconds) = flows.retention_seconds {
                if !(1..=300).contains(&seconds) {
                    return Err(invalid(id));
                }
                next.retention = seconds;
            }
        }
        next.overridden = true;
        next.apply(owner);
        *current = next;
        Ok(next.json())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    log: Option<LogPatch>,
    dns_log: Option<DnsPatch>,
    flows: Option<FlowPatch>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogPatch {
    level: Option<Level>,
    buffered_records: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsPatch {
    max_records: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowPatch {
    max_flows: Option<usize>,
    retention_seconds: Option<u64>,
}

pub(super) fn capability(settings: &honk_config::experimental::NativeApiConfig) -> Value {
    let mut fields = Vec::new();
    if settings.record_logs {
        fields.extend(["log.level", "log.buffered_records"]);
    }
    if settings.record_dns_log {
        fields.push("dns_log.max_records");
    }
    if settings.record_flows {
        fields.extend(["flows.max_flows", "flows.retention_seconds"]);
    }
    json!({"available":true,"fields":fields})
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    Ok(Json(state.observation.settings.snapshot()).into_response())
}

pub(super) async fn patch(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let mut types = request.headers().get_all("content-type").iter();
    if !types
        .next()
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        })
        || types.next().is_some()
    {
        return Err(super::error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            id,
        ));
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| {
            super::error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Request body exceeds its limit",
                id,
            )
        })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid(id))?;
    if value
        .as_object()
        .is_none_or(|object| object.values().any(Value::is_null))
        || value.as_object().is_some_and(|object| {
            object
                .values()
                .filter_map(Value::as_object)
                .any(|object| object.values().any(Value::is_null))
        })
    {
        return Err(invalid(id));
    }
    let patch: Patch = serde_json::from_value(value).map_err(|_| invalid(id))?;
    let _config = state.config.read().await;
    Ok(Json(
        state
            .observation
            .settings
            .patch(&state.observation, &state.settings, patch, id)?,
    )
    .into_response())
}

fn invalid(id: &RequestId) -> ApiError {
    super::error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Unsupported or invalid runtime setting",
        id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_cross_recorder_patch_is_atomic_and_activation_restores_config() {
        let mut config = Config::default();
        config.global.log_level = "WARN".into();
        let owner = NativeObservation::new(&config);
        let id = RequestId("settings-test".into());
        let first:Patch=serde_json::from_value(json!({"log":{"level":"debug","buffered_records":64},"flows":{"max_flows":64,"retention_seconds":1}})).unwrap();
        let current = owner
            .settings
            .patch(&owner, &config.experimental.native_api, first, &id)
            .unwrap();
        assert_eq!(current["source"], "runtime");
        let bad: Patch =
            serde_json::from_value(json!({"log":{"level":"trace"},"dns_log":{"max_records":513}}))
                .unwrap();
        assert!(
            owner
                .settings
                .patch(&owner, &config.experimental.native_api, bad, &id)
                .is_err()
        );
        let unchanged = owner.settings.snapshot();
        assert_eq!(unchanged["log"], current["log"]);
        assert_eq!(unchanged["flows"], current["flows"]);
        owner.settings.activate(&owner, &config);
        let restored = owner.settings.snapshot();
        assert_eq!(restored["source"], "config");
        assert_eq!(restored["log"]["level"], "warn");
        assert_eq!(restored["flows"]["max_flows"], 1024);
    }
}
