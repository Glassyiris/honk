//! Native file permissions, HTTP projections and configuration work admission.

mod coordinator;

use axum::body::HttpBody;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::{
    Json,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::{
    Config,
    diagnostic::{DetailedDiagnostic, Severity},
    experimental::NativeApiConfig,
    parser::SourceSnapshot,
};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use super::operations::{OperationStore, Reservation};
use super::{ApiError, ErrorCode, NativeState, error, parse_query, timestamp, types::RequestId};
use crate::configuration::{
    Accepted, AcceptedSources, MAX_SOURCE_BYTES, MAX_SOURCES, SourceUpdate, limits,
    same_dependencies,
};

/// What `GET /config` shows in place of a private source path.
pub(crate) const REDACTED_PATH: &str = "<redacted>";

pub(crate) struct ConfigService {
    settings: NativeApiConfig,
    instance_id: String,
    operations: Arc<OperationStore>,
    pub(crate) sources: Arc<AcceptedSources>,
    sender: Mutex<Option<mpsc::Sender<Work>>>,
    last_reload: RwLock<Option<Value>>,
    phase: RwLock<Option<tokio::sync::watch::Receiver<crate::control::EnginePhase>>>,
    #[cfg(test)]
    before_replace: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

enum Work {
    GeoUpdate {
        plan: Box<super::geodata::GeoUpdatePlan>,
        reservation: Reservation,
    },
    Manage {
        mutation: super::management::Mutation,
        catalog: Arc<super::catalog::Catalog>,
        group_manager: honk_outbound::group::SharedGroupManager,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        response: oneshot::Sender<Result<super::management::Completion, ApiError>>,
    },
    Lifecycle {
        resume: bool,
        reservation: Reservation,
    },
    GroupPatch {
        patch: Box<super::groups::GroupPatch>,
        reservation: Reservation,
    },
    Replace {
        source_id: String,
        content: String,
        if_match: Result<String, ApiError>,
        reservation: Reservation,
    },
    Reload {
        reservation: Reservation,
    },
    Validate {
        request: ValidationRequest,
        response: oneshot::Sender<Result<Value, ApiError>>,
    },
    Sighup,
}

impl ConfigService {
    pub(crate) fn new(
        settings: NativeApiConfig,
        instance_id: String,
        operations: Arc<OperationStore>,
    ) -> Self {
        Self {
            settings,
            instance_id,
            operations,
            sources: Arc::new(AcceptedSources::default()),
            sender: Mutex::new(None),
            last_reload: RwLock::new(None),
            phase: RwLock::new(None),
            #[cfg(test)]
            before_replace: Mutex::new(None),
        }
    }

    pub(crate) fn writable(&self) -> bool {
        self.sources.available()
            && self.settings.config_write
            && !self.settings.secret.is_empty()
            && self.sender.lock().is_some()
    }
    pub(crate) fn can_manage(&self) -> bool {
        self.sender
            .lock()
            .as_ref()
            .is_some_and(|sender| !sender.is_closed())
            && self
                .sources
                .accepted
                .read()
                .as_ref()
                .is_some_and(|accepted| self.source_writable(accepted, 0))
    }

    pub(super) async fn manage(
        &self,
        mutation: super::management::Mutation,
        catalog: Arc<super::catalog::Catalog>,
        group_manager: honk_outbound::group::SharedGroupManager,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    ) -> Result<super::management::Completion, ApiError> {
        let deleting = mutation.deleting();
        let (response, wait) = oneshot::channel();
        self.enqueue(Work::Manage {
            mutation,
            catalog,
            group_manager,
            alive_set,
            response,
        })
        .map_err(|error| error.for_management(deleting))?;
        wait.await.map_err(|_| {
            super::management::activation_error("coordinator_stopped", None, None, None)
        })?
    }

    pub(super) fn queue_geodata(
        &self,
        plan: super::geodata::GeoUpdatePlan,
        reservation: Reservation,
    ) -> Result<(), ApiError> {
        self.enqueue(Work::GeoUpdate {
            plan: Box::new(plan),
            reservation,
        })
    }
    pub(crate) fn content_enabled(&self) -> bool {
        self.sources.available() && self.settings.config_content && !self.settings.secret.is_empty()
    }
    pub(crate) fn running(&self) -> bool {
        self.sources.available() && self.sender.lock().is_some()
    }
    pub(crate) fn attach_phase(
        &self,
        phase: tokio::sync::watch::Receiver<crate::control::EnginePhase>,
    ) {
        *self.phase.write() = Some(phase);
    }
    pub(crate) fn coordinator_running(&self) -> bool {
        self.sender.lock().is_some()
    }
    fn engine_phase(&self) -> Option<crate::control::EnginePhase> {
        self.phase.read().as_ref().map(|phase| *phase.borrow())
    }
    pub(crate) fn last_reload(&self) -> Option<Value> {
        self.last_reload.read().clone()
    }

    fn credential_source(&self, source: &SourceSnapshot) -> bool {
        source.contains_api_secret
            || (!self.settings.secret.is_empty() && source.content.contains(&self.settings.secret))
    }

    fn source_writable(&self, accepted: &Accepted, index: usize) -> bool {
        if !self.settings.config_write
            || self.settings.secret.is_empty()
            || self.credential_source(&accepted.update.sources[index])
        {
            return false;
        }
        if index == 0 {
            return true;
        }
        let Some(root) = accepted.update.sources[0].path.parent() else {
            return false;
        };
        let Ok(relative) = accepted.update.sources[index].path.strip_prefix(root) else {
            return false;
        };
        self.settings
            .writable_includes
            .iter()
            .any(|path| Path::new(path) == relative)
    }

    pub(crate) fn group_writable(&self, name: &str) -> bool {
        self.writable()
            && self
                .sources
                .accepted
                .read()
                .as_ref()
                .is_some_and(|accepted| {
                    accepted
                        .group_sources
                        .get(name)
                        .is_some_and(|index| self.source_writable(accepted, *index))
                })
    }

    pub(super) fn enqueue_group_patch(
        &self,
        patch: super::groups::GroupPatch,
        reservation: Reservation,
    ) -> Result<(), ApiError> {
        self.enqueue(Work::GroupPatch {
            patch: Box::new(patch),
            reservation,
        })
    }

    pub(crate) fn rule_source(
        &self,
        index: Option<usize>,
    ) -> Option<(String, honk_config::parser::source_edit::RuleSourceLocation)> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        let location = match index {
            Some(index) => accepted.rule_sources.rules.get(index)?,
            None => accepted.rule_sources.fallback.as_ref()?,
        };
        let source = &accepted.update.sources[location.source_index];
        if self.credential_source(source) {
            return None;
        }
        Some((accepted.ids[&source.path].clone(), location.clone()))
    }

    fn source_value(&self, accepted: &Accepted, index: usize) -> Value {
        let source = &accepted.update.sources[index];
        let mut value = json!({
            "id":accepted.ids[&source.path], "path":REDACTED_PATH, "kind":if index==0 {"main"} else {"include"},
            "content_sha256":accepted.hashes[index], "bytes":source.content.len(),
            "writable":self.source_writable(accepted,index), "loaded_at":timestamp(accepted.accepted_at),
            "line_count":source.content.lines().count(),
        });
        if self.settings.config_content
            && !self.settings.secret.is_empty()
            && !self.credential_source(source)
        {
            value["content"] = json!(source.content.as_ref());
        }
        value
    }

    pub(crate) fn snapshot(&self) -> Option<Value> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        Some(
            json!({"generation_id":format!("{}:{}",self.instance_id,accepted.generation),"revision":accepted.revision,
            "sources":(0..accepted.update.sources.len()).map(|index| self.source_value(accepted,index)).collect::<Vec<_>>(),
            "diagnostics":[],"secrets_redacted":true}),
        )
    }

    fn check_phase(&self, work: &Work) -> Result<(), ApiError> {
        use crate::control::EnginePhase;
        if matches!(work, Work::Validate { .. }) {
            return Ok(());
        }
        let phase = self.engine_phase();
        let expected = if matches!(work, Work::Lifecycle { resume: true, .. }) {
            EnginePhase::Suspended
        } else {
            EnginePhase::Running
        };
        if phase == Some(expected) {
            return Ok(());
        }
        if matches!(work, Work::Manage { .. }) {
            return Err(unavailable());
        }
        Err(
            if matches!(
                phase,
                None | Some(EnginePhase::Starting | EnginePhase::Failed | EnginePhase::Draining)
            ) {
                unavailable()
            } else {
                ApiError::new(
                    StatusCode::CONFLICT,
                    ErrorCode::StateConflict,
                    "Engine lifecycle prevents this transition",
                    None,
                )
            },
        )
    }

    fn enqueue(&self, work: Work) -> Result<(), ApiError> {
        if let Err(error) = self.check_phase(&work) {
            match &work {
                Work::Replace { reservation, .. }
                | Work::GeoUpdate { reservation, .. }
                | Work::GroupPatch { reservation, .. }
                | Work::Reload { reservation }
                | Work::Lifecycle { reservation, .. } => {
                    self.operations.reject(&reservation.id, error.clone());
                }
                _ => {}
            }
            return Err(error);
        }
        self.sender
            .lock()
            .as_ref()
            .ok_or_else(unavailable)?
            .try_send(work)
            .map_err(|_| unavailable())
    }

    pub(crate) fn request_sighup(&self) -> Result<(), ApiError> {
        self.enqueue(Work::Sighup)
    }
}

fn same_source_documents(left: &[SourceSnapshot], right: &[SourceSnapshot]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.path == right.path && left.parent == right.parent && left.content == right.content
        })
}

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Configuration coordinator is unavailable",
        None,
    )
}
fn denied() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "Configuration administration is not permitted",
        None,
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Configuration source was not found",
        None,
    )
}
fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "Configuration source budget exceeded",
        None,
    )
}
fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Configuration sources are unavailable",
        None,
    )
}
fn invalid() -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid configuration request",
        None,
    )
}
fn stale() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        ErrorCode::StaleRevision,
        "Configuration changed on disk",
        None,
    )
}

pub(super) fn request_header<'a>(
    request: &'a Request,
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    let mut values = request.headers().get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid());
    }
    first
        .map(|value| value.to_str().map_err(|_| invalid()))
        .transpose()
}
fn if_match(request: &Request) -> Result<String, ApiError> {
    let tag = request_header(request, "if-match")?.ok_or_else(|| {
        ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            ErrorCode::PreconditionRequired,
            "A strong source revision is required",
            None,
        )
    })?;
    let hash = tag
        .strip_prefix('"')
        .and_then(|tag| tag.strip_suffix('"'))
        .filter(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(invalid)?;
    Ok(hash.to_owned())
}
pub(super) fn json_type(request: &Request) -> Result<(), ApiError> {
    if request_header(request, "content-type")?
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
            "Expected application/json",
            None,
        ))
    }
}
fn principal(state: &NativeState) -> &'static str {
    if state.settings.secret.is_empty() {
        "anonymous"
    } else {
        "control"
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationSource {
    id: Option<String>,
    path: Option<String>,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationRequest {
    sources: Vec<ValidationSource>,
    mode: String,
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let mut value = state.observation.configuration.snapshot().ok_or_else(|| {
        error(
            StatusCode::NOT_FOUND,
            ErrorCode::CapabilityNotSupported,
            "Configuration sources are unavailable",
            id,
        )
    })?;
    let accepted = state.observation.configuration.sources.accepted.read();
    let accepted = accepted
        .as_ref()
        .expect("source snapshot pinned by config publication guard");
    let active = state.diagnostics.read();
    value["generation_id"] = json!(format!("{}:{}", state.instance_id, active.generation));
    let diagnostics = active
        .buckets
        .static_diagnostics
        .iter()
        .chain(active.buckets.providers.iter().flat_map(|(_, rows)| rows));
    value["diagnostics"] = json!(
        diagnostics
            .map(|diagnostic| project_diagnostic(
                diagnostic,
                &accepted.update.sources,
                &accepted.ids,
                None
            ))
            .collect::<Vec<_>>()
    );
    Ok(Json(value).into_response())
}

pub(super) async fn source(
    state: &NativeState,
    source_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let _config = state.config.read().await;
    let accepted = state.observation.configuration.sources.accepted.read();
    let accepted = accepted.as_ref().ok_or_else(unsupported)?;
    let index = accepted
        .update
        .sources
        .iter()
        .position(|source| accepted.ids[&source.path] == source_id)
        .ok_or_else(not_found)?;
    Ok(Json(
        state
            .observation
            .configuration
            .source_value(accepted, index),
    )
    .into_response())
}

pub(super) async fn replace(
    state: &NativeState,
    source_id: String,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if !state.observation.configuration.sources.available() {
        return Err(unsupported());
    }
    if !state.observation.configuration.writable() {
        return Err(denied());
    }
    json_type(&request)?;
    let expected = if_match(&request);
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let path = request.uri().path().to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let replacement: Replacement = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let reservation = state.observation.configuration.operations.reserve(
        principal(state),
        "PUT",
        &path,
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        state.observation.configuration.enqueue(Work::Replace {
            source_id,
            content: replacement.content,
            if_match: expected,
            reservation,
        })?;
    }
    Ok(admission.await?.into_response())
}

pub(super) async fn reload(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if !state.observation.configuration.running() {
        return Err(unsupported());
    }
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    let has_body = request.body().size_hint().upper() != Some(0);
    if has_body {
        json_type(&request)?;
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    if !bytes.is_empty() {
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !value.as_object().is_some_and(|object| object.is_empty()) {
            return Err(invalid());
        }
    }
    let reservation = state.observation.configuration.operations.reserve(
        principal(state),
        "POST",
        "/api/v1/operations/reload",
        key.as_deref(),
        &bytes,
        crate::native_api::operations::OperationKind::Reload,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        state
            .observation
            .configuration
            .enqueue(Work::Reload { reservation })?;
    }
    Ok(admission.await?.into_response())
}

pub(super) async fn lifecycle(
    state: &NativeState,
    request: Request,
    id: &RequestId,
    resume: bool,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let service = &state.observation.configuration;
    if !service.coordinator_running() {
        return Err(unsupported());
    }
    let key = request_header(&request, "idempotency-key")?.map(str::to_owned);
    if request.body().size_hint().upper() != Some(0) {
        json_type(&request)?;
    }
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    if !bytes.is_empty()
        && !serde_json::from_slice::<Value>(&bytes)
            .ok()
            .is_some_and(|body| body.as_object().is_some_and(|object| object.is_empty()))
    {
        return Err(invalid());
    }
    let (path, kind) = if resume {
        (
            "/api/v1/operations/resume",
            super::operations::OperationKind::Resume,
        )
    } else {
        (
            "/api/v1/operations/suspend",
            super::operations::OperationKind::Suspend,
        )
    };
    let reservation = state.observation.operations.reserve(
        principal(state),
        "POST",
        path,
        key.as_deref(),
        &bytes,
        kind,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        service.enqueue(Work::Lifecycle {
            resume,
            reservation,
        })?;
    }
    Ok(admission.await?.into_response())
}

pub(super) async fn validate(
    state: &NativeState,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    if !state.observation.configuration.running() {
        return Err(unsupported());
    }
    parse_query(request.uri(), &[], id)?;
    json_type(&request)?;
    let bytes = axum::body::to_bytes(request.into_body(), 65536)
        .await
        .map_err(|_| too_large())?;
    let request: ValidationRequest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.sources.is_empty() || request.sources.len() > MAX_SOURCES {
        return Err(if request.sources.is_empty() {
            invalid()
        } else {
            too_large()
        });
    }
    if !matches!(request.mode.as_str(), "syntax" | "full") {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::UnsupportedValue,
            "Validation mode is not supported",
            None,
        ));
    }
    let mut seen = HashSet::new();
    let mut paths = HashSet::new();
    let mut total = 0usize;
    for (index, source) in request.sources.iter().enumerate() {
        let name = source
            .id
            .clone()
            .unwrap_or_else(|| format!("source-{}", index + 1));
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || !seen.insert(name)
        {
            return Err(invalid());
        }
        if let Some(path) = &source.path
            && path != REDACTED_PATH
            && (path.is_empty() || !paths.insert(path))
        {
            return Err(invalid());
        }
        total = total
            .checked_add(source.content.len())
            .ok_or_else(too_large)?;
    }
    if total > MAX_SOURCE_BYTES {
        return Err(too_large());
    }
    let (response, result) = oneshot::channel();
    state
        .observation
        .configuration
        .enqueue(Work::Validate { request, response })?;
    Ok(Json(result.await.map_err(|_| unavailable())??).into_response())
}

fn project_diagnostic(
    diagnostic: &DetailedDiagnostic,
    sources: &[SourceSnapshot],
    ids: &HashMap<PathBuf, String>,
    fallback: Option<&str>,
) -> Value {
    let source = sources
        .iter()
        .find(|source| source.source.same_source(&diagnostic.source));
    let metadata = diagnostic.source.sources().metadata();
    let mapped = source.and_then(|source| ids.get(&source.path)).or_else(|| {
        fallback
            .and_then(|_| metadata.get(diagnostic.source.index())?.path.as_ref())
            .and_then(|path| ids.get(path))
    });
    let source_id = mapped
        .map(String::as_str)
        .or(fallback)
        .or_else(|| {
            sources
                .first()
                .and_then(|source| ids.get(&source.path))
                .map(String::as_str)
        })
        .unwrap_or("source-1");
    let exact = mapped.is_some();
    json!({"level":match diagnostic.severity{Severity::Error=>"error",Severity::Warning=>"warning",Severity::Info=>"info"},
        "source_id":source_id,"line":if exact{diagnostic.line}else{None},"column":if exact{diagnostic.byte_column}else{None},
        "span":null,"code":diagnostic.code,"message":diagnostic.message})
}

fn resolve_source_path(root: &Path, label: &str) -> Result<PathBuf, ApiError> {
    let input = Path::new(label);
    let path = if input.is_absolute() {
        input.strip_prefix(root).map_err(|_| denied())?
    } else {
        input
    };
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
        || path.extension().and_then(|value| value.to_str()) != Some("dae")
    {
        return Err(denied());
    }
    let joined = root.join(path);
    let resolved = if joined.exists() {
        std::fs::canonicalize(&joined).map_err(|_| unavailable())?
    } else {
        let parent =
            std::fs::canonicalize(joined.parent().ok_or_else(invalid)?).map_err(|_| denied())?;
        parent.join(joined.file_name().ok_or_else(invalid)?)
    };
    if !resolved.starts_with(root) {
        return Err(denied());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests;
