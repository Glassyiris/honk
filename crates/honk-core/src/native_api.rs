//! Independent, opt-in native observation API.

pub(crate) mod auth;
pub(crate) mod catalog;
pub(crate) mod config;
mod config_write;
mod connections;
mod datapath;
pub(crate) mod dns;
pub(crate) mod events;
pub(crate) mod flows;
pub(crate) mod geodata;
mod groups;
mod handlers;
pub(crate) mod logs;
mod management;
pub(crate) mod observation;
pub(crate) mod offline;
pub(crate) mod operations;
pub(crate) mod probes;
pub(crate) mod providers;
pub(crate) mod routing;
mod security;
mod server;
mod settings;
pub(crate) mod store;
pub(crate) mod telemetry;
mod types;
mod ui;

pub use server::NativeServer;
pub use types::{ApiError, ErrorCode};

use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

use axum::extract::{Extension, Query, Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use honk_config::{Config, experimental::NativeApiConfig};
use tokio::sync::{RwLock, watch};

use crate::connection_tracker::{ConnectionEntry, ConnectionTracker};
use crate::control::{ControlPlane, EnginePhase};
use crate::stats::StatsManager;
use types::*;

/// Process-owned handles; constructing a router never starts observers or I/O.
pub struct NativeState {
    settings: NativeApiConfig,
    /// Restart-required like every listener secret; read here so masking never
    /// waits on the configuration lock.
    clash_secret: String,
    security: security::Security,
    /// Present only in password mode: the administrator record, the live sessions and login admission.
    pub(crate) auth: Option<Arc<auth::Auth>>,
    /// Stored geodata sources and the update schedule; absent without a state db.
    pub(crate) geodata: Option<Arc<geodata::Sources>>,
    ui: Option<ui::Ui>,
    instance_id: String,
    started_at: SystemTime,
    started: Instant,
    config: Arc<RwLock<Arc<Config>>>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    stats: Arc<StatsManager>,
    tracker: Arc<ConnectionTracker>,
    observation: Arc<observation::NativeObservation>,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    group_manager: honk_outbound::group::SharedGroupManager,
    dns: crate::dns::DnsService,
    traffic_router: Arc<RwLock<crate::routing::Router>>,
    backend: Arc<RwLock<Box<dyn crate::ebpf::EbpfBackend>>>,
    control_tx: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    proxy_registry: Arc<crate::proxy::ProxyRegistry>,
    phase: watch::Receiver<EnginePhase>,
    healthy: Arc<AtomicBool>,
    #[cfg(test)]
    after_generation: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    sample: parking_lot::RwLock<Option<TrafficSummary>>,
}

impl NativeState {
    pub async fn new(
        control: &mut ControlPlane,
        listen: SocketAddr,
        started_at: SystemTime,
        started: Instant,
    ) -> anyhow::Result<Self> {
        let config = control.config_handle();
        let (settings, clash_secret, data_dir) = {
            let config = config.read().await;
            (
                config.experimental.native_api.clone(),
                config.experimental.clash_api.secret.clone(),
                std::path::PathBuf::from(&config.global.data_dir),
            )
        };
        for (api, secret) in [
            ("native_api", &settings.secret),
            ("clash_api", &clash_secret),
        ] {
            if !secret.is_empty() && secret.len() < config::MIN_MASKED_SECRET {
                tracing::warn!(
                    api,
                    "listener secret shorter than {} bytes is not masked in native API responses",
                    config::MIN_MASKED_SECRET
                );
            }
        }
        // Password mode needs its record before the listener answers anything.
        let auth = if settings.password_auth {
            let db = control.state_db();
            Some(Arc::new(
                tokio::task::spawn_blocking(move || {
                    let db = match db {
                        Some(db) => db,
                        None => {
                            Arc::new(crate::state::StateDb::open(&data_dir).map_err(|error| {
                                anyhow::anyhow!(
                                    "native API password login needs the state db: {error}"
                                )
                            })?)
                        }
                    };
                    auth::Auth::open(db, &data_dir).map_err(|error| {
                        anyhow::anyhow!(
                            "native API password login cannot use the state db: {error}"
                        )
                    })
                })
                .await??,
            ))
        } else {
            None
        };
        let geodata = control.state_db().and_then(|db| {
            geodata::Sources::open(db, &settings)
                .inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        "geodata settings cannot be stored; geodata sources are not configurable"
                    );
                })
                .ok()
                .map(Arc::new)
        });
        let observation = control.native_observation();
        observation.telemetry.discover().await;
        let phase = control.observe_phase();
        observation.configuration.attach_phase(phase.clone());
        Ok(Self {
            security: security::Security::new(&settings, listen),
            auth,
            geodata,
            ui: ui::load(&settings.ui).await?,
            settings,
            clash_secret,
            instance_id: observation.instance_id.clone(),
            observation,
            alive_set: control.alive_set(),
            group_manager: control.group_manager(),
            dns: control.dns_service(),
            traffic_router: control.traffic_router(),
            backend: control.ebpf_handle(),
            control_tx: control.command_sender(),
            runtime_registry: control.runtime_registry(),
            proxy_registry: control.proxy_registry(),
            started_at,
            started,
            config,
            diagnostics: control.diagnostics_handle(),
            stats: control.stats_handle(),
            tracker: control.connection_tracker(),
            phase,
            #[cfg(test)]
            after_generation: parking_lot::Mutex::new(None),
            healthy: control.datapath_health_handle(),
            sample: parking_lot::RwLock::new(None),
        })
    }

    /// Who owns the operations this listener's callers start: the administrator when a credential protects the
    /// listener, the anonymous loopback caller otherwise. Sessions are not principals: an operation survives logout.
    pub(crate) fn principal(&self) -> &'static str {
        if self.settings.credentialed() {
            "control"
        } else {
            "anonymous"
        }
    }

    /// The bearer token a request carries, for the endpoints that need to name a session.
    pub(crate) fn security_bearer<'a>(
        &self,
        request: &'a axum::extract::Request,
    ) -> Option<&'a str> {
        self.security.bearer(request)
    }

    /// The authentication mode this listener runs in, as discovery reports it.
    pub(crate) fn auth_discovery(&self) -> types::AuthDiscovery {
        match &self.auth {
            Some(auth) => types::AuthDiscovery {
                mode: "password",
                setup_required: auth.store.setup_required(),
                anonymous_loopback: false,
            },
            None => types::AuthDiscovery {
                mode: "token",
                setup_required: false,
                anonymous_loopback: self.security.anonymous_loopback(),
            },
        }
    }

    pub(crate) fn require_running(&self) -> Result<(), ApiError> {
        match *self.phase.borrow() {
            EnginePhase::Running if self.healthy.load(Ordering::Acquire) => Ok(()),
            _ => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::TemporarilyUnavailable,
                "Engine is not ready for this operation",
                None,
            )),
        }
    }
}

/// The peer address of the accepted socket. Never derived from a header: a proxy cannot claim to be private.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Peer(pub(crate) IpAddr);

impl Peer {
    /// Loopback, RFC 1918, RFC 4193 ULA and link-local peers may claim an uninitialized account.
    pub(crate) fn may_set_up(self) -> bool {
        match self.0 {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
                    || (ip.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }
}

/// An IPv4-mapped IPv6 peer is the IPv4 address it carries, so one rule covers both stacks.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        other => other,
    }
}

pub fn router(state: Arc<NativeState>) -> Router {
    let router = handlers::routes();
    let router = if state.settings.ui.is_empty() {
        router.fallback(not_found)
    } else {
        router.fallback(ui_fallback)
    };
    router
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            observation_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            security::boundary,
        ))
        .with_state(state)
}

async fn observation_request(
    State(state): State<Arc<NativeState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let get = request.method() == axum::http::Method::GET;
    let path = request.uri().path();
    let flow_demand = matches!(path, "/api/v1/flows")
        || path
            .strip_prefix("/api/v1/flows/")
            .is_some_and(|id| !id.is_empty() && !id.contains('/'));
    let poll = get && (flow_demand || path == "/api/v1/dns/log");
    let response = next.run(request).await;
    if poll && response.status().is_success() {
        state
            .observation
            .settings
            .renew(&state.observation, flow_demand);
    }
    response
}

async fn ui_fallback(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    if matches!(request.uri().path(), "/" | "/ui") || request.uri().path().starts_with("/ui/") {
        return state
            .ui
            .as_ref()
            .expect("configured UI was validated at startup")
            .serve(request)
            .await;
    }
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Resource not found",
        &id,
    )
    .into_response()
}

fn error(status: StatusCode, code: ErrorCode, message: &'static str, id: &RequestId) -> ApiError {
    ApiError::new(status, code, message, Some(id.0.clone()))
}

async fn not_found(Extension(id): Extension<RequestId>) -> Response {
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::ResourceNotFound,
        "Resource not found",
        &id,
    )
    .into_response()
}

fn parse_query(
    uri: &Uri,
    allowed: &[&str],
    id: &RequestId,
) -> Result<HashMap<String, String>, ApiError> {
    let Query(pairs) =
        Query::<Vec<(String, String)>>::try_from_uri(uri).map_err(|_| invalid_query(id))?;
    let mut values = HashMap::with_capacity(pairs.len());
    for (key, value) in pairs {
        if !allowed.contains(&key.as_str()) || values.insert(key, value).is_some() {
            return Err(invalid_query(id));
        }
    }
    Ok(values)
}

fn invalid_query(id: &RequestId) -> ApiError {
    error(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "Invalid query parameters",
        id,
    )
}

fn full_detail(values: &HashMap<String, String>, id: &RequestId) -> Result<bool, ApiError> {
    match values
        .get("detail")
        .map(String::as_str)
        .unwrap_or("summary")
    {
        "summary" => Ok(false),
        "full" => Ok(true),
        _ => Err(invalid_query(id)),
    }
}

fn timestamp(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn runtime(state: &NativeState, uri: &Uri, id: &RequestId) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["detail"], id)?;
    let full = full_detail(&query, id)?;
    let (
        generation,
        phase,
        healthy,
        reloading,
        activated_at,
        config_revision,
        last_reload,
        datapath_observation,
    ) = {
        let _config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        #[cfg(test)]
        {
            let hook = state.after_generation.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let phase = *state.phase.borrow();
        (
            generation,
            phase,
            state.healthy.load(Ordering::Acquire),
            state.observation.reloading(),
            state.observation.activated_at(generation),
            state.observation.configuration.sources.revision(),
            state.observation.configuration.last_reload(),
            state.backend.read().await.observe_datapath(),
        )
    };
    let lifecycle = match phase {
        EnginePhase::Starting => "starting",
        EnginePhase::Running if !healthy => "degraded",
        EnginePhase::Running if reloading => "reloading",
        EnginePhase::Running => "running",
        EnginePhase::Draining => "draining",
        EnginePhase::Failed => "failed",
    };
    let traffic = state
        .sample
        .read()
        .clone()
        .unwrap_or_else(|| TrafficSummary {
            scope: "visible",
            observed_by: "userspace",
            counter_since: Some(timestamp(state.stats.counter_since())),
            sampled_at: None,
            connections: TrafficConnections {
                tcp: None,
                udp: None,
                total: None,
            },
            bytes: TrafficBytes {
                upload: None,
                download: None,
            },
            rates: None,
        });
    Ok(Json(Runtime {
        observed_at: timestamp(SystemTime::now()),
        instance_id: state.instance_id.clone(),
        lifecycle: Lifecycle {
            state: lifecycle,
            started_at: Some(timestamp(state.started_at)),
            uptime_seconds: Some(state.started.elapsed().as_secs().to_string()),
        },
        generation: Generation {
            active_id: format!("{}:{generation}", state.instance_id),
            config_revision,
            state: if reloading { "reloading" } else { "active" },
            activated_at: activated_at.map(timestamp),
        },
        datapath: datapath::summary(&datapath_observation, &state.instance_id, healthy),
        traffic,
        process: Process {
            pid: full.then_some(std::process::id()),
            cpu_percent: None,
        },
        last_reload,
    })
    .into_response())
}

struct Candidate {
    observed: Instant,
    tcp: bool,
    value: Connection,
}
impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.observed == other.observed && self.value.id == other.value.id
    }
}
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .observed
            .cmp(&self.observed)
            .then_with(|| self.value.id.cmp(&other.value.id))
    }
}

fn connection(state: &NativeState, entry: &ConnectionEntry, full: bool) -> Connection {
    let evidence = entry
        .native_flow_id
        .as_deref()
        .and_then(|id| state.observation.flows.connection_evidence(id));
    Connection {
        id: entry.id.clone(),
        flow_id: entry.native_flow_id.clone(),
        pname: entry.process.clone(),
        state: "active",
        src: full.then(|| entry.source.clone()),
        dst: full.then(|| entry.destination.clone()),
        domain: full.then(|| entry.domain.clone()),
        outbound: entry.routed_outbound.clone(),
        chain: evidence
            .as_ref()
            .map(|value| value.chain.clone())
            .unwrap_or_default(),
        chain_source: evidence
            .as_ref()
            .map_or("unknown", |value| value.chain_source),
        rule_id: evidence.as_ref().and_then(|value| value.rule_id.clone()),
        rule_expression: evidence
            .as_ref()
            .and_then(|value| value.rule_expression.clone()),
        rule_source: evidence
            .as_ref()
            .map_or("unknown", |value| value.rule_source),
        ingress: None,
        domain_source: evidence.as_ref().and_then(|value| value.domain_source),
        started_at: evidence.map(|value| value.started_at),
        observed_by: "userspace",
        upload_bytes: Some(entry.upload.load(Ordering::Relaxed).to_string()),
        download_bytes: Some(entry.download.load(Ordering::Relaxed).to_string()),
        upload_bytes_per_second: None,
        download_bytes_per_second: None,
    }
}

fn connections(state: &NativeState, uri: &Uri, id: &RequestId) -> Result<Response, ApiError> {
    let query = parse_query(uri, &["type", "src", "limit", "detail"], id)?;
    let full = full_detail(&query, id)?;
    let kind = query.get("type").map(String::as_str).unwrap_or("all");
    if !matches!(kind, "all" | "tcp" | "udp") {
        return Err(invalid_query(id));
    }
    let source = query
        .get("src")
        .map(|value| value.parse::<IpAddr>().map(|ip| ip.to_canonical()))
        .transpose()
        .map_err(|_| invalid_query(id))?;
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(invalid_query(id));
    }
    let mut total_tcp = 0;
    let mut total_udp = 0;
    let mut selected: BinaryHeap<Candidate> = BinaryHeap::with_capacity(limit);
    state.tracker.visit(|entry| {
        let tcp = match entry.network.as_str() {
            "tcp" => true,
            "udp" => false,
            _ => return,
        };
        if (kind != "all" && kind != entry.network)
            || source.is_some_and(|ip| {
                entry
                    .source
                    .parse::<SocketAddr>()
                    .ok()
                    .map(|addr| addr.ip().to_canonical())
                    != Some(ip)
            })
        {
            return;
        }
        if tcp {
            total_tcp += 1;
        } else {
            total_udp += 1;
        }
        if selected.len() == limit {
            let worst = selected.peek().expect("nonzero limit");
            if entry.start_time < worst.observed
                || (entry.start_time == worst.observed && entry.id >= worst.value.id)
            {
                return;
            }
            selected.pop();
        }
        selected.push(Candidate {
            observed: entry.start_time,
            tcp,
            value: connection(state, entry, full),
        });
    });
    let truncated = total_tcp + total_udp > selected.len() as u64;
    let mut tcp = Vec::new();
    let mut udp = Vec::new();
    for entry in selected.into_sorted_vec() {
        if entry.tcp {
            tcp.push(entry.value);
        } else {
            udp.push(entry.value);
        }
    }
    let response = ConnectionList {
        observed_at: timestamp(SystemTime::now()),
        instance_id: state.instance_id.clone(),
        visibility: "partial",
        truncated,
        tcp,
        udp,
        total_tcp,
        total_udp,
    };
    Ok(Json(config::administrative_projection(
        state,
        serde_json::json!(response),
    )?)
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::server::sample_traffic;
    use super::*;
    use std::time::Duration;

    pub(super) async fn state() -> Arc<NativeState> {
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.allow_anonymous_loopback = true;
        config.ensure_builtin_nodes();
        let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
        let forwarder = resolver.forwarder();
        let mut control = ControlPlane::new(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            crate::routing::Router::new(&[], "direct").unwrap(),
            Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        let state = NativeState::new(
            &mut control,
            "127.0.0.1:9527".parse().unwrap(),
            SystemTime::now(),
            Instant::now(),
        )
        .await
        .unwrap();
        control.publish_phase(EnginePhase::Running);
        Arc::new(state)
    }

    async fn runtime_body(state: &NativeState) -> serde_json::Value {
        let response = runtime(
            state,
            &"/api/v1/runtime".parse().unwrap(),
            &RequestId("test".into()),
        )
        .await
        .unwrap();
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn runtime_reports_reloading_and_activation_time() {
        let state = state().await;
        let idle = runtime_body(&state).await;
        assert_eq!(idle["generation"]["state"], "active");
        let started = idle["generation"]["activated_at"]
            .as_str()
            .expect("startup generation has an activation time")
            .to_owned();
        let reloading = state.observation.begin_reload();
        let during = runtime_body(&state).await;
        assert_eq!(during["lifecycle"]["state"], "reloading");
        assert_eq!(during["generation"]["state"], "reloading");
        assert_eq!(during["generation"]["activated_at"], started.as_str());
        drop(reloading);
        {
            let _writer = state.config.write().await;
            state.diagnostics.write().generation = 1;
        }
        let uncommitted = runtime_body(&state).await;
        assert!(uncommitted["generation"]["activated_at"].is_null());
        state
            .observation
            .committed(state.observation.catalog.snapshot(), 0, 1);
        let after = runtime_body(&state).await;
        assert_eq!(after["lifecycle"]["state"], "running");
        assert_eq!(after["generation"]["state"], "active");
        assert!(after["generation"]["activated_at"].as_str().unwrap() >= started.as_str());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_snapshot_fences_generation_and_health() {
        let state = state().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *state.after_generation.lock() = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let read_state = Arc::clone(&state);
        let reader = tokio::spawn(async move { runtime_body(&read_state).await });
        entered_rx.await.unwrap();
        let commit = async {
            let writer = state.config.write().await;
            state.diagnostics.write().generation = 1;
            drop(writer);
            state.healthy.store(false, Ordering::Release);
        };
        tokio::pin!(commit);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut commit)
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        let before = reader.await.unwrap();
        commit.await;
        let after = runtime_body(&state).await;
        assert!(
            before["generation"]["active_id"]
                .as_str()
                .unwrap()
                .ends_with(":0")
        );
        assert_eq!(before["lifecycle"]["state"], "running");
        assert!(
            after["generation"]["active_id"]
                .as_str()
                .unwrap()
                .ends_with(":1")
        );
        assert_eq!(after["lifecycle"]["state"], "degraded");
    }

    #[tokio::test(start_paused = true)]
    async fn native_sampler_reset_and_overflow_are_unknown() {
        let state = state().await;
        let (upload, _) = state
            .stats
            .byte_counters("first", crate::stats::OutboundKind::Node);
        upload.store(100, Ordering::Relaxed);
        let (stop, receiver) = watch::channel(false);
        let sampler = tokio::spawn(sample_traffic(state.clone(), receiver));
        while state.sample.read().is_none() {
            tokio::task::yield_now().await;
        }
        assert!(state.sample.read().as_ref().unwrap().rates.is_none());
        upload.store(50, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(1)).await;
        while state
            .sample
            .read()
            .as_ref()
            .unwrap()
            .bytes
            .upload
            .as_deref()
            != Some("50")
        {
            tokio::task::yield_now().await;
        }
        assert!(state.sample.read().as_ref().unwrap().rates.is_none());
        state
            .stats
            .record_bytes("second", crate::stats::OutboundKind::Node, u64::MAX, 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        while state.sample.read().as_ref().unwrap().bytes.upload.is_some() {
            tokio::task::yield_now().await;
        }
        assert!(state.sample.read().as_ref().unwrap().rates.is_none());
        stop.send(true).unwrap();
        sampler.await.unwrap();
    }

    #[tokio::test]
    async fn flow_capability_reports_runtime_limits() {
        let state = state().await;
        let request = axum::http::Request::patch("/api/v1/runtime/settings")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"flows":{"max_flows":64,"retention_seconds":60}}"#,
            ))
            .unwrap();
        settings::patch(&state, request, &RequestId("test".into()))
            .await
            .unwrap();
        let flows = &types::capabilities(&state).await["resources"]["flows"];
        assert_eq!(flows["max_flows"], 64);
        assert_eq!(flows["retention_seconds"], 60);
    }

    #[tokio::test]
    async fn flow_capability_scopes_include_dns_intercept_coverage() {
        let state = state().await;
        let flows = &types::capabilities(&state).await["resources"]["flows"];
        assert_eq!(
            flows["scopes"],
            serde_json::json!(["userspace_tcp", "userspace_udp", "dns_intercept"])
        );
    }

    #[tokio::test]
    async fn memory_capability_lists_metrics_before_the_first_sample() {
        let state = state().await;
        let metrics = &types::capabilities(&state).await["resources"]["runtime_memory"]["metrics"];
        assert!(
            metrics
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("process.rss_bytes"))
        );
    }

    #[tokio::test]
    async fn observed_at_uses_the_shared_millisecond_format() {
        let state = state().await;
        let response = settings::get(
            &state,
            &"/api/v1/runtime/settings".parse().unwrap(),
            &RequestId("test".into()),
        )
        .await
        .unwrap();
        let settings: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        for observed in [
            &types::capabilities(&state).await["observed_at"],
            &settings["observed_at"],
        ] {
            let observed = observed.as_str().unwrap();
            let parsed = chrono::DateTime::parse_from_rfc3339(observed).unwrap();
            assert_eq!(observed, timestamp(parsed.into()));
        }
    }
}
