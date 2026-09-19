//! Synchronous managed-entry actions use the daemon-owned source coordinator.

use std::sync::Arc;

use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::{ApiError, ErrorCode, NativeState, config, parse_query, types::RequestId};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeCreate {
    pub(super) name: String,
    pub(super) link: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderCreate {
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) url: String,
}

pub(super) enum Action {
    CreateNode,
    CreateProvider,
    DeleteNode(String),
    DeleteProvider(String),
}

pub(super) enum Mutation {
    CreateNode(NodeCreate),
    CreateProvider(ProviderCreate),
    DeleteNode(String),
    DeleteProvider(String),
}

impl Mutation {
    pub(super) fn deleting(&self) -> bool {
        matches!(self, Self::DeleteNode(_) | Self::DeleteProvider(_))
    }
}

pub(super) enum Completion {
    Created {
        collection: &'static str,
        id: Uuid,
        value: serde_json::Value,
    },
    Deleted(u8),
}

impl Completion {
    pub(super) fn response(self) -> Response {
        match self {
            Self::Created {
                collection,
                id,
                value,
            } => (
                StatusCode::CREATED,
                [(header::LOCATION, format!("/api/v1/{collection}/{id}"))],
                Json(value),
            )
                .into_response(),
            Self::Deleted(deleted) => Json(json!({"deleted":deleted})).into_response(),
        }
    }
}

pub(super) fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "This resource is not managed by the writable main source",
        None,
    )
}

pub(super) fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid management request",
        None,
    )
}

pub(super) fn unsupported_value() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "The engine cannot represent or admit this name, share link or subscription URL",
        None,
    )
}

pub(super) fn conflict() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "A resource with this name already exists",
        None,
    )
}

pub(super) fn activation_error(
    stage: &'static str,
    written: Option<bool>,
    durability: Option<bool>,
    committed: Option<bool>,
) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Managed configuration change did not complete successfully",
        None,
    )
    .with_details(json!({"stage":stage,"written":written,
            "durability_confirmed":durability,"committed":committed}))
}

pub(super) async fn mutate(
    state: &Arc<NativeState>,
    action: Action,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    if !state.observation.configuration.can_manage() {
        return Err(unsupported());
    }
    let deleting = matches!(action, Action::DeleteNode(_) | Action::DeleteProvider(_));
    let result = async {
        parse_query(request.uri(), &[], id)?;
        if !deleting {
            config::json_type(&request)?;
        }
        let body = to_bytes(request.into_body(), 65536).await.map_err(|_| {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Management request body exceeds its limit",
                None,
            )
        })?;
        let mutation = match action {
            Action::DeleteNode(_) | Action::DeleteProvider(_) if !body.is_empty() => {
                return Err(invalid());
            }
            Action::DeleteNode(target) => Mutation::DeleteNode(target),
            Action::DeleteProvider(target) => Mutation::DeleteProvider(target),
            Action::CreateNode => {
                let input: NodeCreate = serde_json::from_slice(&body).map_err(|_| invalid())?;
                if !(1..=64).contains(&input.name.chars().count())
                    || !(1..=8192).contains(&input.link.chars().count())
                {
                    return Err(unsupported_value());
                }
                Mutation::CreateNode(input)
            }
            Action::CreateProvider => {
                let input: ProviderCreate = serde_json::from_slice(&body).map_err(|_| invalid())?;
                if input.kind != "subscription"
                    || !(1..=64).contains(&input.name.len())
                    || !input
                        .name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    || !(1..=4096).contains(&input.url.chars().count())
                    || !(input.url.starts_with("http://") || input.url.starts_with("https://"))
                    || reqwest::Url::parse(&input.url)
                        .ok()
                        .is_none_or(|url| url.host_str().is_none())
                {
                    return Err(unsupported_value());
                }
                Mutation::CreateProvider(input)
            }
        };
        let completion = state
            .observation
            .configuration
            .manage(
                mutation,
                Arc::clone(&state.observation.catalog),
                Arc::clone(&state.group_manager),
                Arc::clone(&state.alive_set),
            )
            .await?;
        Ok(completion.response())
    }
    .await;
    result.map_err(|error| error.for_management(deleting))
}
