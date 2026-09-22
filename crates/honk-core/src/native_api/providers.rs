//! Provider observations and supervisor-owned refresh admission.

use std::{
    collections::{HashMap, VecDeque},
    mem::size_of,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    body::to_bytes,
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::subscription::Subscription;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ApiError, ErrorCode, NativeState, invalid_query,
    operations::{OperationKind, OperationResult, OperationStore, Reservation},
    parse_query, timestamp,
    types::RequestId,
};
use crate::{
    control::ReloadOutcome,
    subscription::{ProviderLoad, SubscriptionMergeReply, SubscriptionSupervisorHandle},
};

const MAX_PAGE_SIZE: usize = 1000;
const MAX_SNAPSHOTS: usize = 8;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize)]
pub(crate) struct Provider {
    id: String,
    name: String,
    kind: &'static str,
    url_redacted: Option<String>,
    node_count: usize,
    updated_at: Option<String>,
    expires_at: Option<String>,
    traffic: Option<()>,
    status: &'static str,
    last_error: Option<ProviderError>,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Provider")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("node_count", &self.node_count)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProviderError {
    code: &'static str,
    message: &'static str,
    details: Option<Value>,
}

impl Provider {
    fn inline(node_count: usize) -> Self {
        Self {
            id: "inline".into(),
            name: "inline".into(),
            kind: "inline",
            url_redacted: None,
            node_count,
            updated_at: None,
            expires_at: None,
            traffic: None,
            status: "ok",
            last_error: None,
        }
    }

    fn observed(subscription: &Subscription, load: ProviderLoad, node_count: usize) -> Self {
        Self {
            id: subscription.id.to_string(),
            name: subscription.name.clone(),
            kind: "subscription",
            url_redacted: Some(subscription.url.clone()),
            node_count,
            updated_at: load.updated_at.map(timestamp),
            expires_at: None,
            traffic: None,
            status: if load.error.is_some() && node_count == 0 {
                "error"
            } else if load.updated_at.is_none()
                || load.cached
                || load.error.is_some()
                || !subscription.enabled
                || node_count == 0
            {
                "stale"
            } else {
                "ok"
            },
            last_error: load.error.map(|code| ProviderError {
                code,
                message: "Provider loading or runtime publication did not complete successfully.",
                details: None,
            }),
        }
    }

    fn mask_listener_secrets(
        mut self,
        config: &honk_config::Config,
        sources: Option<&super::config::ConfigService>,
    ) -> Self {
        let secrets = super::config::ListenerSecrets::from_config(config);
        for value in std::iter::once(&mut self.name).chain(self.url_redacted.iter_mut()) {
            *value = secrets.mask(value).0;
            if let Some(sources) = sources {
                *value = sources.mask_text(value).0;
            }
        }
        self
    }

    fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.id.capacity()
            + self.name.capacity()
            + self.url_redacted.as_ref().map_or(0, String::capacity)
            + self.updated_at.as_ref().map_or(0, String::capacity)
    }
}

struct Snapshot {
    id: Uuid,
    instance: String,
    created: Instant,
    rows: Vec<Provider>,
    bytes: usize,
}

impl Snapshot {
    fn page(&self, offset: usize, limit: usize) -> Response {
        let end = offset.saturating_add(limit).min(self.rows.len());
        Json(json!({"providers": &self.rows[offset..end], "next_cursor": (end < self.rows.len()).then(|| format!("{}:{end}", self.id))})).into_response()
    }
}

pub(crate) struct ProviderApi {
    supervisor: RwLock<Option<SubscriptionSupervisorHandle>>,
    snapshots: Mutex<VecDeque<Snapshot>>,
}

impl ProviderApi {
    pub(crate) fn new() -> Self {
        Self {
            supervisor: RwLock::new(None),
            snapshots: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn attach(&self, supervisor: SubscriptionSupervisorHandle) {
        *self.supervisor.write() = Some(supervisor);
    }

    pub(crate) fn capability(&self) -> Value {
        json!({"available": true, "can_refresh": self.supervisor.read().as_ref().is_some_and(SubscriptionSupervisorHandle::running), "max_page_size": MAX_PAGE_SIZE})
    }

    fn resume(
        &self,
        cursor: &str,
        instance: &str,
        limit: usize,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        let (snapshot, offset) = cursor.split_once(':').ok_or_else(|| invalid_query(id))?;
        let snapshot = Uuid::parse_str(snapshot).map_err(|_| invalid_query(id))?;
        let offset: usize = offset.parse().map_err(|_| invalid_query(id))?;
        let mut snapshots = self.snapshots.lock();
        snapshots.retain(|snapshot| snapshot.created.elapsed() < SNAPSHOT_TTL);
        let snapshot = snapshots
            .iter()
            .find(|candidate| candidate.id == snapshot && candidate.instance == instance)
            .ok_or_else(|| invalid_query(id))?;
        if offset == 0 || offset >= snapshot.rows.len() {
            return Err(invalid_query(id));
        }
        Ok(snapshot.page(offset, limit))
    }

    fn page(&self, snapshot: Snapshot, limit: usize) -> Result<Response, ApiError> {
        let response = snapshot.page(0, limit);
        if snapshot.rows.len() > limit {
            let mut snapshots = self.snapshots.lock();
            snapshots.retain(|snapshot| snapshot.created.elapsed() < SNAPSHOT_TTL);
            while snapshots.len() >= MAX_SNAPSHOTS
                || snapshots.iter().map(|s| s.bytes).sum::<usize>() + snapshot.bytes
                    > MAX_SNAPSHOT_BYTES
            {
                if snapshots.pop_front().is_none() {
                    return Err(unavailable());
                }
            }
            snapshots.push_back(snapshot);
        }
        Ok(response)
    }
}

pub(super) async fn list(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["limit", "cursor"], id)?;
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(invalid_query(id));
    }
    let service = &state.observation.providers;
    if let Some(cursor) = query.get("cursor") {
        return service.resume(cursor, &state.observation.instance_id, limit, id);
    }
    let config = state.config.read().await;
    if config
        .subscriptions
        .iter()
        .fold(0usize, |bytes, subscription| {
            bytes
                .saturating_add(size_of::<Provider>() + 256)
                .saturating_add(subscription.name.len())
                .saturating_add(subscription.url.len())
        })
        >= MAX_SNAPSHOT_BYTES
    {
        return Err(unavailable());
    }
    let mut counts: HashMap<_, usize> = config.subscriptions.iter().map(|s| (s.id, 0)).collect();
    let mut inline_count = 0;
    for node in &config.nodes {
        if let Some(count) = node.subscription_id.and_then(|id| counts.get_mut(&id)) {
            *count += 1;
        } else if super::catalog::is_inline_node(node) {
            inline_count += 1;
        }
    }
    let supervisor = service.supervisor.read().clone();
    let inline = Provider::inline(inline_count);
    let mut bytes =
        size_of::<Snapshot>() + state.observation.instance_id.len() + inline.retained_bytes();
    let mut rows = Vec::with_capacity(config.subscriptions.len() + 1);
    rows.push(inline);
    for subscription in &config.subscriptions {
        let load = supervisor
            .as_ref()
            .map(|owner| owner.observation(subscription))
            .unwrap_or_default();
        let row = Provider::observed(subscription, load, counts[&subscription.id])
            .mask_listener_secrets(&config, Some(&state.observation.configuration));
        bytes += row.retained_bytes();
        if bytes > MAX_SNAPSHOT_BYTES {
            return Err(unavailable());
        }
        rows.push(row);
    }
    rows[1..].sort_unstable_by(|a, b| a.id.cmp(&b.id));
    service.page(
        Snapshot {
            id: Uuid::new_v4(),
            instance: state.observation.instance_id.clone(),
            created: Instant::now(),
            rows,
            bytes,
        },
        limit,
    )
}

pub(super) async fn detail(
    state: &NativeState,
    provider_id: &str,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    if provider_id == "inline" {
        let config = state.config.read().await;
        let count = config
            .nodes
            .iter()
            .filter(|node| super::catalog::is_inline_node(node))
            .count();
        return Ok(Json(Provider::inline(count)).into_response());
    }
    let provider_id = Uuid::parse_str(provider_id).map_err(|_| not_found())?;
    let config = state.config.read().await;
    provider_value(
        &config,
        state.observation.providers.supervisor.read().as_ref(),
        provider_id,
        Some(&state.observation.configuration),
    )
    .map(|value| Json(value).into_response())
    .ok_or_else(not_found)
}

pub(super) fn provider_value(
    config: &honk_config::Config,
    supervisor: Option<&SubscriptionSupervisorHandle>,
    provider_id: Uuid,
    sources: Option<&super::config::ConfigService>,
) -> Option<Value> {
    let subscription = config.subscriptions.iter().find(|s| s.id == provider_id)?;
    let load = supervisor
        .map(|s| s.observation(subscription))
        .unwrap_or_default();
    let count = config
        .nodes
        .iter()
        .filter(|node| node.subscription_id == Some(provider_id))
        .count();
    serde_json::to_value(
        Provider::observed(subscription, load, count).mask_listener_secrets(config, sources),
    )
    .ok()
}

pub(super) async fn refresh(
    state: &NativeState,
    provider_id: &str,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    if provider_id == "inline" {
        return Err(not_refreshable());
    }
    let mut keys = request.headers().get_all("idempotency-key").iter();
    let key = keys
        .next()
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|_| invalid_query(id))?;
    if keys.next().is_some() {
        return Err(invalid_query(id));
    }
    let body = to_bytes(request.into_body(), 65536).await.map_err(|_| {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RequestTooLarge,
            "Refresh request body exceeds its limit.",
            Some(id.0.clone()),
        )
    })?;
    let operations = &state.observation.operations;
    let path = format!("/api/v1/providers/{provider_id}/refresh");
    let reservation = operations.reserve(
        state.principal(),
        "POST",
        &path,
        key.as_deref(),
        &body,
        OperationKind::ProviderRefresh,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let prepared = async {
            if !body.is_empty() {
                return Err(invalid_query(id));
            }
            state.require_running()?;
            let provider_id = Uuid::parse_str(provider_id).map_err(|_| not_found())?;
            let config = state.config.read().await;
            state.require_running()?;
            let subscription = config
                .subscriptions
                .iter()
                .find(|s| s.id == provider_id)
                .ok_or_else(not_found)?
                .clone();
            if !subscription.enabled {
                return Err(not_refreshable());
            }
            let supervisor = state
                .observation
                .providers
                .supervisor
                .read()
                .clone()
                .ok_or_else(unavailable)?;
            let display = Provider::observed(&subscription, ProviderLoad::default(), 0)
                .mask_listener_secrets(&config, Some(&state.observation.configuration));
            Ok((subscription, supervisor, display))
        }
        .await;
        match prepared {
            Ok((subscription, supervisor, display)) => supervisor.refresh(
                subscription,
                RefreshOperation {
                    reservation,
                    operations: Arc::clone(operations),
                    instance: state.observation.instance_id.clone(),
                    display_name: display.name,
                    display_url: display.url_redacted.expect("subscription URL is present"),
                },
            )?,
            Err(error) => {
                operations.reject(&reservation.id, error.clone());
                return Err(error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

pub(crate) struct RefreshOperation {
    pub(crate) reservation: Reservation,
    pub(crate) operations: Arc<OperationStore>,
    pub(crate) instance: String,
    pub(crate) display_name: String,
    pub(crate) display_url: String,
}

impl RefreshOperation {
    pub(crate) fn accept(&self) {
        self.operations.accept(&self.reservation.id);
    }
    pub(crate) fn running(&self) {
        self.operations.running(&self.reservation.id);
    }
    pub(crate) fn reject(self, error: ApiError) {
        self.operations.reject(&self.reservation.id, error);
    }

    pub(crate) fn finish(
        self,
        subscription: &Subscription,
        load: ProviderLoad,
        result: Result<SubscriptionMergeReply, &'static str>,
    ) {
        let id = &self.reservation.id;
        match result {
            Ok(reply) => {
                match reply.outcome {
                    ReloadOutcome::Noop { .. } | ReloadOutcome::Committed { .. } => {
                        let mut provider = Provider::observed(subscription, load, reply.node_count);
                        provider.name = self.display_name;
                        provider.url_redacted = Some(self.display_url);
                        self.operations
                            .succeed(id, OperationResult::ProviderRefresh(provider));
                    }
                    ReloadOutcome::CommittedDegraded { generation } => {
                        self.operations.fail(id, "publication_degraded", "Provider nodes were committed but the runtime is degraded.", Some(json!({"committed": true, "active_generation_id": format!("{}:{generation}", self.instance), "datapath_generation_id": generation.to_string()})));
                    }
                    ReloadOutcome::Rejected => {
                        self.operations.fail(id, "publication_rejected", "Provider runtime publication was rejected; active nodes were retained.", None);
                    }
                }
            }
            Err(code) => {
                self.operations.fail(
                    id,
                    code,
                    "Provider refresh did not complete successfully.",
                    None,
                );
            }
        }
    }
}

pub(crate) fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Provider refresh admission is temporarily unavailable.",
        None,
    )
    .with_retry_after(1)
}
pub(crate) fn busy() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "A refresh for this provider is already in flight.",
        None,
    )
}
pub(crate) fn paused() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::StateConflict,
        "Provider refresh is unavailable while the runtime is suspended or transitioning.",
        None,
    )
}
pub(crate) fn not_refreshable() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "This provider cannot be refreshed.",
        None,
    )
}
fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Provider was not found.",
        None,
    )
}

#[cfg(test)]
mod tests;
