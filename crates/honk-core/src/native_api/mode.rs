//! Native mode wire contract; mutations are owned by the control command loop.

use std::time::SystemTime;

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use super::{
    ApiError, ErrorCode, NativeState, catalog::CatalogIdentity, parse_query, timestamp,
    types::RequestId,
};
use crate::mode::{DatapathFlagsHandle, ModeSource, ModeState, ModeTarget};

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutboundMode {
    Rule,
    Direct,
    Global,
}

impl OutboundMode {
    fn canonical(self) -> &'static str {
        match self {
            Self::Rule => "Rule",
            Self::Direct => "Direct",
            Self::Global => "Global",
        }
    }
}

#[derive(Debug)]
pub(crate) enum ModeRequest {
    Runtime {
        mode: OutboundMode,
        target: Option<String>,
    },
    #[cfg(feature = "clash-api")]
    ClashMode(String),
    #[cfg(feature = "clash-api")]
    ClashSelection(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    mode: OutboundMode,
    #[serde(default, deserialize_with = "target_string")]
    target: Option<String>,
}

fn target_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn decode(bytes: &[u8]) -> Result<ModeRequest, ApiError> {
    let request: WireRequest = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if matches!(request.mode, OutboundMode::Global) != request.target.is_some()
        || request.target.as_ref().is_some_and(String::is_empty)
    {
        return Err(invalid());
    }
    Ok(ModeRequest::Runtime {
        mode: request.mode,
        target: request.target,
    })
}

pub(crate) fn value(mode: &ModeState) -> Value {
    json!({
        "observed_at": timestamp(SystemTime::now()),
        "mode": if mode.is_global() { "global" } else if mode.is_direct() { "direct" } else { "rule" },
        "target": if mode.is_global() { mode.target.as_ref().map(ModeTarget::id) } else { None },
        "source": match mode.source { ModeSource::Config => "config", ModeSource::Runtime => "runtime" },
    })
}

/// Called by the daemon-owned command loop under its reload serialization and
/// config read barrier. Never await this while the HTTP task retains that barrier.
pub(crate) async fn apply(
    config: &honk_config::Config,
    catalog: &CatalogIdentity,
    flags: &DatapathFlagsHandle,
    request: ModeRequest,
) -> Result<Value, ApiError> {
    let mode = match request {
        ModeRequest::Runtime { mode, target } => {
            if !flags.snapshot().native_enabled {
                return Err(unsupported());
            }
            if matches!(mode, OutboundMode::Global) != target.is_some()
                || target.as_ref().is_some_and(String::is_empty)
            {
                return Err(invalid());
            }
            let target = target
                .as_deref()
                .map(|id| {
                    ModeTarget::from_id(id, config, &catalog.groups).ok_or_else(|| {
                        ApiError::new(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            ErrorCode::UnsupportedValue,
                            "Mode target was not found",
                            None,
                        )
                    })
                })
                .transpose()?;
            flags
                .set_native_mode(mode.canonical(), target, config, &catalog.groups)
                .await
        }
        #[cfg(feature = "clash-api")]
        ModeRequest::ClashMode(mode) => {
            if ModeState::normalize(&mode).is_none() {
                return Err(invalid());
            }
            flags.set_clash_mode(&mode, config, &catalog.groups).await
        }
        #[cfg(feature = "clash-api")]
        ModeRequest::ClashSelection(selection) => {
            if flags.snapshot().native_enabled
                && ModeTarget::from_name(&selection, config, &catalog.groups).is_none()
            {
                return Err(invalid());
            }
            flags
                .set_clash_global_selection(selection, config, &catalog.groups)
                .await
        }
    }
    .map_err(|_| unavailable())?;
    Ok(value(&mode))
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let flags = state.datapath_flags.as_ref().ok_or_else(unsupported)?;
    let mode = flags.snapshot();
    if !mode.native_enabled {
        return Err(unsupported());
    }
    Ok(Json(value(&mode)).into_response())
}

pub(super) async fn put(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let mut types = request.headers().get_all("content-type").iter();
    if !types
        .next()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        })
        || types.next().is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            None,
        ));
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65_536)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Request body exceeds its limit",
                None,
            )
        })?;
    let request = decode(&bytes)?;
    let (reply, response) = oneshot::channel();
    state
        .control_tx
        .try_send(crate::control::ControlCommand::SetRuntimeMode { request, reply })
        .map_err(|_| unavailable())?;
    let value = response.await.map_err(|_| unavailable())??;
    Ok(Json(value).into_response())
}

fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid mode or target",
        None,
    )
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Mode transition is unavailable",
        None,
    )
    .with_retry_after(1)
}
fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Runtime mode is unavailable",
        None,
    )
}

#[cfg(test)]
mod tests;
