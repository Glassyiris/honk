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
    parser::{SourceSnapshot, cursor::Document, lexer::Source},
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

/// Shorter secrets are not masked: a one-byte value would erase every
/// occurrence of that byte from every response.
pub(crate) const MIN_MASKED_SECRET: usize = 8;

/// The listener secret values a response must not carry. Building one parses every source that
/// holds an API secret, so `ConfigService` keeps the set for the accepted sources and rebuilds it
/// only when they change.
#[derive(Clone)]
pub(crate) struct ListenerSecrets {
    values: Vec<String>,
}

impl ListenerSecrets {
    pub(crate) fn new(sources: &[SourceSnapshot], native_secret: &str) -> Self {
        let mut values = Vec::new();
        if native_secret.len() >= MIN_MASKED_SECRET {
            values.push(native_secret.to_owned());
        }
        for source in sources.iter().filter(|source| source.contains_api_secret) {
            let Ok(document) = Document::parse(
                Source::new(&source.content, source.source.clone()),
                &mut Vec::new(),
            ) else {
                if !source.content.is_empty() {
                    values.push(source.content.to_string());
                }
                continue;
            };
            for field in document
                .sections()
                .filter(|root| root.header() == "experimental")
                .filter_map(|root| root.body())
                .flatten()
                .filter(|section| matches!(section.header().trim(), "native_api" | "clash_api"))
                .filter_map(|section| section.body())
                .flatten()
            {
                let span = field.header_span();
                let Some((key, value)) = source.content[span.start..span.end].split_once(':')
                else {
                    continue;
                };
                if key.trim() != "secret" {
                    continue;
                }
                let value = value.trim();
                let start = span.start + source.content[span.start..span.end].trim_end().len()
                    - value.len();
                let end = start + value.len();
                let quoted = document
                    .tokens()
                    .iter()
                    .flat_map(|token| &token.quoted)
                    .any(|quote| quote.start == start && quote.end == end);
                let value = if quoted {
                    &source.content[start + 1..end - 1]
                } else {
                    value
                };
                if value.len() >= MIN_MASKED_SECRET {
                    values.push(value.to_owned());
                }
            }
        }
        values.sort_unstable();
        values.dedup();
        Self { values }
    }

    pub(crate) fn from_config(config: &Config) -> Self {
        Self::new(&[], &config.experimental.native_api.secret)
            .with_clash(&config.experimental.clash_api.secret)
    }

    pub(crate) fn with_clash(mut self, secret: &str) -> Self {
        if secret.len() >= MIN_MASKED_SECRET && !self.values.iter().any(|value| value == secret) {
            self.values.push(secret.to_owned());
        }
        self
    }

    fn spellings(&self) -> impl Iterator<Item = std::borrow::Cow<'_, str>> {
        self.values.iter().flat_map(|value| {
            let quoted = serde_json::to_string(value).expect("listener secret is a string");
            [
                std::borrow::Cow::Borrowed(value.as_str()),
                std::borrow::Cow::Owned(quoted[1..quoted.len() - 1].to_owned()),
            ]
        })
    }

    fn contains(&self, text: &str) -> bool {
        self.spellings().any(|value| text.contains(value.as_ref()))
    }

    pub(crate) fn mask(&self, text: &str) -> (String, bool) {
        if !self.contains(text) {
            return (text.to_owned(), false);
        }
        let mut hidden = vec![false; text.len()];
        for secret in self.spellings() {
            let mut offset = 0;
            while let Some(relative) = text[offset..].find(secret.as_ref()) {
                let start = offset + relative;
                hidden[start..start + secret.len()].fill(true);
                offset = start + text[start..].chars().next().unwrap().len_utf8();
            }
        }
        let mut masked = String::new();
        let mut hiding = false;
        for (index, character) in text.char_indices() {
            if hidden[index] {
                if !hiding {
                    masked.push_str("<redacted>");
                }
                if matches!(character, '\r' | '\n') {
                    masked.push(character);
                }
            } else {
                masked.push(character);
            }
            hiding = hidden[index];
        }
        (masked, true)
    }

    fn mask_display(&self, value: &mut Value) -> bool {
        let Some(text) = value.as_str() else {
            return false;
        };
        let (masked, changed) = self.mask(text);
        *value = json!(masked);
        changed
    }

    fn mask_value(&self, value: &mut Value) -> bool {
        let masked = match value {
            Value::Array(values) => values
                .iter_mut()
                .fold(false, |masked, value| self.mask_value(value) | masked),
            Value::Object(values) => values.iter_mut().fold(false, |masked, (key, value)| {
                let changed = if matches!(
                    key.as_str(),
                    "expression"
                        | "rule_expression"
                        | "domain"
                        | "pname"
                        | "src_mac"
                        | "outbound"
                        | "routed_outbound"
                        | "effective_outbound"
                        | "leaf_node_name"
                        | "member_name"
                        | "target"
                        | "name"
                        | "from_upstream"
                        | "upstream"
                        | "file"
                        | "path"
                        | "absolute_path"
                        | "url_redacted"
                        | "source_redacted"
                ) {
                    self.mask_display(value)
                } else if key == "chain"
                    && let Some(chain) = value.as_array_mut()
                {
                    chain
                        .iter_mut()
                        .fold(false, |masked, value| self.mask_display(value) | masked)
                } else {
                    self.mask_value(value)
                };
                changed | masked
            }),
            _ => false,
        };
        if masked && let Some(object) = value.as_object_mut() {
            if object.contains_key("trace_status") {
                object.insert("trace_status".into(), json!("partial"));
            }
            if let Some(trace) = object.get_mut("trace").and_then(Value::as_object_mut) {
                trace.insert("status".into(), json!("partial"));
                if let Some(missing) = trace.get_mut("missing").and_then(Value::as_array_mut)
                    && !missing.contains(&json!("redacted"))
                {
                    missing.push(json!("redacted"));
                }
            }
        }
        masked
    }
}

fn source_path(accepted: &Accepted, index: usize) -> &Path {
    let root = accepted.update.sources[0]
        .path
        .parent()
        .expect("accepted entry has a parent directory");
    accepted.update.sources[index]
        .path
        .strip_prefix(root)
        .expect("accepted sources are confined to the entry directory")
}

pub(crate) struct ConfigService {
    settings: NativeApiConfig,
    instance_id: String,
    operations: Arc<OperationStore>,
    pub(crate) sources: Arc<AcceptedSources>,
    sender: Mutex<Option<mpsc::Sender<Work>>>,
    last_reload: RwLock<Option<Value>>,
    phase: RwLock<Option<tokio::sync::watch::Receiver<crate::control::EnginePhase>>>,
    /// The secret set for the accepted sources, keyed by the `SourceUpdate` it was built from.
    secrets: Mutex<Option<(Arc<SourceUpdate>, Arc<ListenerSecrets>)>>,
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
            secrets: Mutex::new(None),
            #[cfg(test)]
            before_replace: Mutex::new(None),
        }
    }

    pub(crate) fn writable(&self) -> bool {
        self.sources.available()
            && self.settings.config_write
            && self.settings.credentialed()
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
        self.sources.available()
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

    /// The secret set for `accepted`, rebuilt only when its sources are a new `SourceUpdate`.
    pub(crate) fn secrets(&self, accepted: Option<&Accepted>) -> Arc<ListenerSecrets> {
        let Some(accepted) = accepted else {
            return Arc::new(ListenerSecrets::new(&[], &self.settings.secret));
        };
        let mut cached = self.secrets.lock();
        if let Some((update, secrets)) = cached.as_ref()
            && Arc::ptr_eq(update, &accepted.update)
        {
            return Arc::clone(secrets);
        }
        let secrets = Arc::new(ListenerSecrets::new(
            &accepted.update.sources,
            &self.settings.secret,
        ));
        *cached = Some((Arc::clone(&accepted.update), Arc::clone(&secrets)));
        secrets
    }

    pub(crate) fn mask_text(&self, text: &str) -> (String, bool) {
        let guard = self.sources.accepted.read();
        self.secrets(guard.as_ref()).mask(text)
    }

    fn source_writable(&self, accepted: &Accepted, index: usize) -> bool {
        let secrets = self.secrets(Some(accepted));
        self.source_writable_with_secrets(accepted, index, &secrets)
    }

    fn source_writable_with_secrets(
        &self,
        accepted: &Accepted,
        index: usize,
        secrets: &ListenerSecrets,
    ) -> bool {
        let source = &accepted.update.sources[index];
        self.settings.config_write
            && self.settings.credentialed()
            && !source.contains_api_secret
            && !secrets.contains(&source.content)
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
    ) -> Option<(
        String,
        String,
        honk_config::parser::source_edit::RuleSourceLocation,
    )> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        let location = match index {
            Some(index) => accepted.rule_sources.rules.get(index)?,
            None => accepted.rule_sources.fallback.as_ref()?,
        };
        let source = &accepted.update.sources[location.source_index];
        let secrets = self.secrets(Some(accepted));
        let mut location = location.clone();
        location.expression = secrets.mask(&location.expression).0;
        Some((
            accepted.ids[&source.path].clone(),
            secrets
                .mask(&source_path(accepted, location.source_index).to_string_lossy())
                .0,
            location,
        ))
    }

    fn source_value(
        &self,
        accepted: &Accepted,
        index: usize,
        secrets: &ListenerSecrets,
    ) -> (Value, bool) {
        let source = &accepted.update.sources[index];
        let (content, redacted) = secrets.mask(&source.content);
        let (path, path_redacted) = secrets.mask(&source_path(accepted, index).to_string_lossy());
        let (absolute_path, absolute_redacted) = secrets.mask(&source.path.to_string_lossy());
        let value = json!({
            "id":accepted.ids[&source.path], "path":path,
            "absolute_path":absolute_path, "kind":if index==0 {"main"} else {"include"},
            "content_sha256":accepted.hashes[index], "bytes":source.content.len(),
            "writable":self.source_writable_with_secrets(accepted,index,secrets), "loaded_at":timestamp(accepted.accepted_at),
            "line_count":source.content.lines().count(), "content":content,
        });
        (value, redacted || path_redacted || absolute_redacted)
    }

    pub(crate) fn snapshot(&self) -> Option<Value> {
        let guard = self.sources.accepted.read();
        let accepted = guard.as_ref()?;
        let secrets = self.secrets(Some(accepted));
        let mut secrets_redacted = false;
        let sources = (0..accepted.update.sources.len())
            .map(|index| {
                let (value, redacted) = self.source_value(accepted, index, &secrets);
                secrets_redacted |= redacted;
                value
            })
            .collect::<Vec<_>>();
        Some(
            json!({"generation_id":format!("{}:{}",self.instance_id,accepted.generation),"revision":accepted.revision,
            "sources":sources,"diagnostics":[],"secrets_redacted":secrets_redacted}),
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
pub(super) fn denied() -> ApiError {
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
pub(super) fn invalid() -> ApiError {
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
    state.principal()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    content: String,
    #[serde(default, rename = "secrets_redacted")]
    _secrets_redacted: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationSource {
    id: Option<String>,
    path: Option<String>,
    content: String,
    #[serde(default, rename = "secrets_redacted")]
    _secrets_redacted: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationRequest {
    sources: Vec<ValidationSource>,
    mode: String,
    #[serde(default, rename = "secrets_redacted")]
    _secrets_redacted: Option<bool>,
}

pub(super) fn administrative_projection(
    state: &NativeState,
    mut value: Value,
) -> Result<Value, ApiError> {
    let accepted = state.observation.configuration.sources.accepted.read();
    let secrets = state
        .observation
        .configuration
        .secrets(accepted.as_ref())
        .as_ref()
        .clone()
        .with_clash(&state.clash_secret);
    secrets.mask_value(&mut value);
    Ok(value)
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
    let secrets = state.observation.configuration.secrets(Some(accepted));
    Ok(Json(
        state
            .observation
            .configuration
            .source_value(accepted, index, &secrets)
            .0,
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

pub(super) fn resolve_source_path(root: &Path, label: &str) -> Result<PathBuf, ApiError> {
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
