//! Source-owned restricted RFC 6902 group edits; selection remains runtime state.

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use honk_config::{group::Group, parser::source_edit::GroupField};
use honk_outbound::group::NativeGroupMember;
use serde_json::{Value, json};

use super::{
    ApiError, ErrorCode, NativeState, config, operations::OperationKind, parse_query,
    types::RequestId,
};

pub(crate) const MUTABLE_CONFIG: [&str; 7] = [
    "policy",
    "default_member_id",
    "final_outbound",
    "tolerance",
    "idle_timeout",
    "interrupt_connections",
    "check_url",
];
const PATHS: [&str; 7] = [
    "/policy",
    "/config/default_member_id",
    "/config/final_outbound",
    "/config/tolerance",
    "/config/idle_timeout",
    "/config/interrupt_connections",
    "/config/check_url",
];
const FIELDS: [GroupField; 7] = [
    GroupField::Policy,
    GroupField::Default,
    GroupField::Final,
    GroupField::Tolerance,
    GroupField::IdleTimeout,
    GroupField::InterruptConnections,
    GroupField::CheckUrl,
];
const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
const MAX_CHECK_URL_BYTES: usize = 2048;

pub(super) struct GroupPatch {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) revision: String,
    pub(super) expected: Result<String, ApiError>,
    group: Group,
    members: Vec<(String, String)>,
    operations: Value,
}

fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid or unsupported group patch",
        None,
    )
}

pub(super) fn read_only() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Group source is not writable",
        None,
    )
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::UnsupportedValue,
        "Group patch field or value is unsupported",
        None,
    )
}

fn field(path: &str) -> Result<usize, ApiError> {
    PATHS
        .iter()
        .position(|candidate| *candidate == path)
        .ok_or_else(unsupported)
}

fn integer(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .or_else(|| {
            value
                .as_f64()
                .filter(|value| {
                    *value >= 0.0 && *value <= MAX_SAFE_INTEGER as f64 && value.fract() == 0.0
                })
                .map(|value| value as u64)
        })
}

/// The stored form of a supported value, as GET reports it.
fn normalized(index: usize, value: &Value) -> Option<Value> {
    let valid = match index {
        0 => value.as_object().is_some_and(|policy| {
            policy.len() == 2
                && policy
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        ["selector", "urltest", "loadbalance", "fallback", "score"].contains(&kind)
                            && policy.get("native").and_then(Value::as_str) == Some(kind)
                    })
        }),
        1 | 2 => value.is_null() || value.as_str().is_some_and(|value| !value.is_empty()),
        3 | 4 if !value.is_null() => return integer(value).map(Value::from),
        5 => value.is_boolean(),
        6 if !value.is_null() => return value.as_str().and_then(check_url).map(Value::from),
        3 | 4 | 6 => true,
        _ => false,
    };
    valid.then(|| value.clone())
}

/// The contract's SafeHttpUrl in the normalized form the probe sends: health
/// checks split on commas and the source edit needs a usable quote.
fn check_url(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))?;
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if authority.contains('@')
        || value
            .chars()
            .any(|char| char.is_whitespace() || char.is_control())
    {
        return None;
    }
    super::catalog::normalized_check_url(value).filter(|url| {
        url.len() <= MAX_CHECK_URL_BYTES
            && !url.contains(',')
            && !(url.contains('\'') && url.contains('"'))
    })
}

impl GroupPatch {
    pub(super) fn changes(&self) -> Result<Vec<(GroupField, Option<String>)>, ApiError> {
        let policy = serde_json::to_value(self.group.policy).map_err(|_| invalid())?;
        let default = self
            .group
            .default
            .as_ref()
            .and_then(|name| self.members.iter().find(|(_, member)| member == name))
            .map(|(id, _)| id);
        let initial = [
            json!({"kind":policy,"native":policy}),
            json!(default),
            json!(self.group.final_outbound),
            json!(self.group.tolerance),
            json!(self.group.idle_timeout),
            json!(self.group.interrupt_connections),
            json!(super::catalog::check_url(&self.group)),
        ];
        let mut values = initial.clone().map(Some);
        let operations = self
            .operations
            .as_array()
            .filter(|operations| !operations.is_empty())
            .ok_or_else(invalid)?;
        if operations.len() > 32 {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Group patch operation limit exceeded",
                None,
            ));
        }
        for operation in operations {
            let operation = operation.as_object().ok_or_else(invalid)?;
            let op = operation
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let path = field(
                operation
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid)?,
            )?;
            match op {
                "add" | "replace" | "test" => {
                    if operation.len() != 3 || !operation.contains_key("value") {
                        return Err(invalid());
                    }
                    let value = normalized(path, &operation["value"]).ok_or_else(unsupported)?;
                    if op != "add" && values[path].is_none() {
                        return Err(invalid());
                    }
                    if op == "test" {
                        if values[path].as_ref() != Some(&value) {
                            return Err(ApiError::new(
                                StatusCode::CONFLICT,
                                ErrorCode::StateConflict,
                                "Group patch test failed",
                                None,
                            ));
                        }
                    } else {
                        values[path] = Some(value);
                    }
                }
                "remove" => {
                    if operation.len() != 2 || values[path].take().is_none() {
                        return Err(invalid());
                    }
                }
                "copy" | "move" => {
                    if operation.len() != 3 {
                        return Err(invalid());
                    }
                    let from = field(
                        operation
                            .get("from")
                            .and_then(Value::as_str)
                            .ok_or_else(invalid)?,
                    )?;
                    let value = values[from].as_ref().ok_or_else(invalid)?;
                    let value = normalized(path, value).ok_or_else(unsupported)?;
                    if op == "move" {
                        values[from] = None;
                    }
                    values[path] = Some(value);
                }
                _ => return Err(invalid()),
            }
        }
        let mut changes = Vec::new();
        for (index, value) in values.iter().enumerate() {
            if value.as_ref() == Some(&initial[index]) {
                continue;
            }
            let value = match value.as_ref().filter(|value| !value.is_null()) {
                None => None,
                Some(value) if index == 0 => {
                    Some(value["kind"].as_str().ok_or_else(invalid)?.to_owned())
                }
                Some(value) if index == 1 => {
                    let id = value.as_str().ok_or_else(invalid)?;
                    let (_, name) = self
                        .members
                        .iter()
                        .find(|(member, _)| member == id)
                        .ok_or_else(unsupported)?;
                    // Dae defaults are names: reject identities shadowed by an earlier same-name member.
                    if self
                        .members
                        .iter()
                        .find(|(_, member)| member == name)
                        .map(|(member, _)| member.as_str())
                        != Some(id)
                    {
                        return Err(unsupported());
                    }
                    Some(name.clone())
                }
                Some(value) => Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                ),
            };
            changes.push((FIELDS[index], value));
        }
        Ok(changes)
    }
}

pub(super) async fn patch(
    state: &NativeState,
    group_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    if !service.writable() {
        return Err(read_only());
    }
    if config::request_header(&request, "content-type")?
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| {
            !value
                .trim()
                .eq_ignore_ascii_case("application/json-patch+json")
        })
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json-patch+json",
            None,
        ));
    }
    let expected = config::request_header(&request, "if-match").and_then(|tag| {
        let tag = tag.ok_or_else(|| {
            ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                ErrorCode::PreconditionRequired,
                "A strong group revision is required",
                None,
            )
        })?;
        let value = tag
            .strip_prefix('"')
            .and_then(|tag| tag.strip_suffix('"'))
            .filter(|tag| {
                !tag.is_empty()
                    && tag
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b',')
            })
            .ok_or_else(invalid)?;
        Ok(value.to_owned())
    });
    let key = config::request_header(&request, "idempotency-key")?.map(str::to_owned);
    let path = request.uri().path().to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Group patch exceeds its body limit",
                None,
            )
        })?;
    let operations: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let reservation = state.observation.operations.reserve(
        state.principal(),
        "PATCH",
        &path,
        key.as_deref(),
        &bytes,
        OperationKind::GroupUpdate,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let captured = async {
            let _config = state.config.read().await;
            let identity = state.observation.catalog.snapshot();
            let name = identity
                .groups
                .iter()
                .find(|(_, value)| value.as_str() == group_id)
                .map(|(name, _)| name)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::NOT_FOUND,
                        ErrorCode::ResourceNotFound,
                        "Group was not found",
                        None,
                    )
                })?;
            let manager = state.group_manager.read().clone();
            let group = manager.native_group(name).ok_or_else(invalid)?.clone();
            let members = manager
                .native_members(name)
                .filter_map(|member| match member {
                    NativeGroupMember::Node(node) => Some((node.id.to_string(), node.name.clone())),
                    NativeGroupMember::Group(group) => identity
                        .groups
                        .get(&group.name)
                        .map(|id| (id.clone(), group.name.clone())),
                })
                .collect();
            Ok::<_, ApiError>(GroupPatch {
                id: group_id.to_owned(),
                name: name.clone(),
                revision: service.sources.revision().ok_or_else(invalid)?,
                expected,
                group,
                members,
                operations,
            })
        }
        .await;
        match captured {
            Ok(patch) => service.enqueue_group_patch(patch, reservation)?,
            Err(error) => {
                state.observation.operations.reject(&reservation.id, error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionBody {
    member_id: String,
    network: SelectionNetwork,
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum SelectionNetwork {
    Tcp,
    Udp,
    Both,
}

pub(super) async fn select(
    state: &NativeState,
    group_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    state.require_running()?;
    config::json_type(&request)?;
    if config::request_header(&request, "idempotency-key")?.is_some_and(str::is_empty) {
        return Err(invalid());
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| {
            super::error(
                StatusCode::PAYLOAD_TOO_LARGE,
                ErrorCode::RequestTooLarge,
                "Selection request exceeds its limit",
                id,
            )
        })?;
    let body: SelectionBody = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if body.member_id.is_empty() || body.member_id.len() > 256 {
        return Err(invalid());
    }
    let networks = match body.network {
        SelectionNetwork::Tcp => honk_outbound::group::SelectorNetworks::Tcp,
        SelectionNetwork::Udp => honk_outbound::group::SelectorNetworks::Udp,
        SelectionNetwork::Both => honk_outbound::group::SelectorNetworks::Both,
    };
    let (reply, response) = tokio::sync::oneshot::channel();
    state
        .control_tx
        .try_send(crate::control::ControlCommand::SetSelector {
            request: crate::control::client::SelectionRequest::Native {
                group_id: group_id.to_owned(),
                member_id: body.member_id.clone(),
                networks,
            },
            reply,
        })
        .map_err(|_| {
            super::error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "Control queue is unavailable",
                id,
            )
        })?;
    let selected = response
        .await
        .map_err(|_| {
            super::error(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "Control owner is unavailable",
                id,
            )
        })?
        .map_err(|reason| {
            let (status, code) = match reason {
                crate::control::client::ControlError::NotFound => {
                    (StatusCode::NOT_FOUND, ErrorCode::ResourceNotFound)
                }
                crate::control::client::ControlError::Unsupported => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    ErrorCode::UnsupportedValue,
                ),
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::TemporarilyUnavailable,
                ),
            };
            super::error(
                status,
                code,
                "Selection transition could not be confirmed",
                id,
            )
        })?;
    Ok(axum::Json(json!({"group_id":group_id,"member_id":body.member_id,"network":body.network,"source":"runtime","selection_revision":format!("{}:selection:{}",state.instance_id,selected.revision),"connections_interrupted":selected.interrupted})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operations: Value) -> GroupPatch {
        GroupPatch {
            id: "group".into(),
            name: "G".into(),
            revision: "r".into(),
            expected: Ok("r".into()),
            group: Group::default(),
            members: vec![("node".into(), "A".into())],
            operations,
        }
    }

    #[test]
    fn sequential_patch_move_copy_test_and_failure_are_atomic() {
        let patch = request(json!([
            {"op":"test","path":"/config/tolerance","value":50.0},
            {"op":"copy","from":"/config/tolerance","path":"/config/idle_timeout"},
            {"op":"move","from":"/config/idle_timeout","path":"/config/tolerance"},
            {"op":"add","path":"/config/default_member_id","value":"node"}
        ]));
        assert_eq!(
            patch.changes().unwrap(),
            vec![
                (GroupField::Default, Some("A".into())),
                (GroupField::IdleTimeout, None)
            ]
        );
        for operations in [
            json!([{"op":"replace","path":"/config/tolerance","value":9},{"op":"test","path":"/config/tolerance","value":50}]),
            json!([{"op":"remove","path":"/config/tolerance"},{"op":"replace","path":"/config/tolerance","value":1}]),
            json!([{"op":"copy","path":"/policy","from":"/config/tolerance"}]),
            json!([{"op":"replace","path":"/config/check_url","value":"localhost/"}]),
            json!([{"op":"replace","path":"/config/tolerance","value":0.5}]),
            json!(vec![
                json!({"op":"test","path":"/config/tolerance","value":50});
                33
            ]),
        ] {
            assert!(request(operations).changes().is_err());
        }
    }

    #[test]
    fn check_url_patch_accepts_safe_http_urls_and_null() {
        let change = |value: Value| {
            request(json!([{"op":"replace","path":"/config/check_url","value":value}])).changes()
        };
        for (url, written) in [
            ("https://www.gstatic.com/generate_204", None),
            ("http://127.0.0.1:8080/probe?x=1", None),
            ("https://[::1]/a@b", None),
            ("https://example.test/it's", None),
            ("http://example.test", Some("http://example.test/")),
            (
                "https://example.test/p#frag",
                Some("https://example.test/p"),
            ),
            ("http://Example.Test:80/x", Some("http://example.test/x")),
            ("http://example.test?x", Some("http://example.test/?x")),
        ] {
            assert_eq!(
                change(json!(url)).unwrap(),
                vec![(GroupField::CheckUrl, Some(written.unwrap_or(url).into()))]
            );
        }
        assert!(change(Value::Null).unwrap().is_empty());
        let long = format!("https://example.test/{}", "a".repeat(2048));
        for url in [
            "ftp://example.test/",
            "https://user:pass@example.test/",
            "https://user@example.test/",
            "example.test/generate_204",
            "HTTPS://example.test/",
            "https:///path",
            "https://a.test/,https://b.test/",
            " https://example.test/",
            "https://example.test/a\u{a0}b",
            "https://example.test/a\u{85}b",
            "https://example.test/'\"",
            long.as_str(),
        ] {
            assert!(change(json!(url)).is_err(), "{url}");
        }
        assert!(change(json!(204)).is_err());
    }

    #[test]
    fn check_url_test_compares_the_catalog_form() {
        let mut patch = request(json!([
            {"op":"test","path":"/config/check_url","value":"http://example.test/"},
            {"op":"remove","path":"/config/check_url"}
        ]));
        patch.group.check_url = Some("example.test".into());
        assert_eq!(patch.changes().unwrap(), vec![(GroupField::CheckUrl, None)]);
        patch.operations =
            json!([{"op":"replace","path":"/config/check_url","value":"http://example.test/"}]);
        assert!(patch.changes().unwrap().is_empty());
    }
}
