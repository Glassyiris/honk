//! Independent, opt-in native observation API.

pub(crate) mod catalog;
pub(crate) mod config;
mod config_write;
pub(crate) mod events;
pub(crate) mod flows;
pub(crate) mod observation;
pub(crate) mod offline;
pub(crate) mod operations;
mod security;
pub(crate) mod telemetry;
mod types;
mod ui;

pub use types::{ApiError, ErrorCode};

use std::collections::{BinaryHeap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{Extension, Query, Request, State};
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Json, Router};
use honk_config::{Config, experimental::NativeApiConfig};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::connection_tracker::{ConnectionEntry, ConnectionTracker};
use crate::control::{ControlPlane, EnginePhase};
use crate::stats::StatsManager;
use types::*;

/// Process-owned handles; constructing a router never starts observers or I/O.
pub struct NativeState {
    settings: NativeApiConfig,
    security: security::Security,
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
    phase: watch::Receiver<EnginePhase>,
    healthy: Arc<AtomicBool>,
    #[cfg(test)]
    after_generation: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    mock_mode: bool,
    sample: parking_lot::RwLock<Option<TrafficSummary>>,
}

impl NativeState {
    pub async fn new(
        control: &mut ControlPlane,
        listen: SocketAddr,
        started_at: SystemTime,
        started: Instant,
        mock_mode: bool,
    ) -> anyhow::Result<Self> {
        let config = control.config_handle();
        let settings = config.read().await.experimental.native_api.clone();
        let observation = control.native_observation();
        Ok(Self {
            security: security::Security::new(&settings, listen),
            ui: ui::load(&settings.ui).await?,
            settings,
            instance_id: observation.instance_id.clone(),
            observation,
            alive_set: control.alive_set(),
            group_manager: control.group_manager(),
            started_at,
            started,
            config,
            diagnostics: control.diagnostics_handle(),
            stats: control.stats_handle(),
            tracker: control.connection_tracker(),
            phase: control.observe_phase(),
            #[cfg(test)]
            after_generation: parking_lot::Mutex::new(None),
            healthy: control.datapath_health_handle(),
            mock_mode,
            sample: parking_lot::RwLock::new(None),
        })
    }
}

pub(super) struct RouteInfo {
    pub template: &'static str,
    pub methods: &'static [&'static str],
}

const ROUTES: &[(&str, &[&str])] = &[
    ("/api", &["GET"]),
    ("/api/v1/version", &["GET"]),
    ("/api/v1/capabilities", &["GET"]),
    ("/api/v1/config", &["GET"]),
    ("/api/v1/config/validate", &["POST"]),
    ("/api/v1/config/sources/{source_id}", &["GET", "PUT"]),
    ("/api/v1/runtime", &["GET"]),
    ("/api/v1/runtime/memory", &["GET"]),
    ("/api/v1/runtime/outbounds", &["GET"]),
    ("/api/v1/runtime/traffic/history", &["GET"]),
    ("/api/v1/runtime/memory/history", &["GET"]),
    ("/api/v1/runtime/mode", &["GET", "PUT"]),
    ("/api/v1/datapath", &["GET"]),
    ("/api/v1/nodes", &["GET"]),
    ("/api/v1/providers", &["GET"]),
    ("/api/v1/providers/{id}", &["GET"]),
    ("/api/v1/providers/{id}/refresh", &["POST"]),
    ("/api/v1/groups", &["GET"]),
    ("/api/v1/groups/{groupId}", &["GET", "PATCH"]),
    ("/api/v1/groups/{groupId}/selection", &["PUT", "DELETE"]),
    ("/api/v1/probes", &["POST"]),
    ("/api/v1/connections", &["GET", "DELETE"]),
    ("/api/v1/connections/{connection_id}", &["DELETE"]),
    ("/api/v1/flows", &["GET"]),
    ("/api/v1/flows/{flow_id}", &["GET"]),
    ("/api/v1/routing/trace", &["POST"]),
    ("/api/v1/rules", &["GET"]),
    ("/api/v1/events", &["GET"]),
    ("/api/v1/logs", &["GET"]),
    ("/api/v1/runtime/settings", &["GET", "PATCH"]),
    ("/api/v1/dns/query", &["GET"]),
    ("/api/v1/dns/log", &["GET"]),
    ("/api/v1/dns/cache", &["GET", "DELETE"]),
    ("/api/v1/dns/cache/{entry_id}", &["DELETE"]),
    ("/api/v1/dns/cache/flush", &["POST"]),
    ("/api/v1/operations/reload", &["POST"]),
    ("/api/v1/operations/suspend", &["POST"]),
    ("/api/v1/operations/resume", &["POST"]),
    ("/api/v1/operations/{id}", &["GET"]),
];

pub(super) fn route_info(path: &str) -> Option<RouteInfo> {
    if let Some(&(template, methods)) = ROUTES.iter().find(|(template, _)| *template == path) {
        return Some(RouteInfo { template, methods });
    }
    ROUTES.iter().find_map(|&(template, methods)| {
        let mut actual = path.split('/');
        let matches = template.split('/').all(|part| {
            actual.next().is_some_and(|value| {
                if part.starts_with('{') {
                    !value.is_empty()
                } else {
                    part == value
                }
            })
        }) && actual.next().is_none();
        matches.then_some(RouteInfo { template, methods })
    })
}

pub fn router(state: Arc<NativeState>) -> Router {
    let mut router = Router::new();
    for &(path, _) in ROUTES {
        router = router.route(path, any(dispatch));
    }
    let router = if state.settings.ui.is_empty() {
        router.fallback(not_found)
    } else {
        router.fallback(ui_fallback)
    };
    router
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            security::boundary,
        ))
        .with_state(state)
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

async fn dispatch(
    State(state): State<Arc<NativeState>>,
    Extension(id): Extension<RequestId>,
    request: Request,
) -> Response {
    let path = request.uri().path();
    let method = if request.method() == Method::HEAD {
        "GET"
    } else {
        request.method().as_str()
    };
    let Some(route) = route_info(path).filter(|route| route.methods.contains(&method)) else {
        return error(
            StatusCode::NOT_FOUND,
            ErrorCode::ResourceNotFound,
            "Resource not found",
            &id,
        )
        .into_response();
    };
    if route.template == "/api/v1/events" && method == "GET" {
        return events::serve(&state, request, &id)
            .await
            .unwrap_or_else(IntoResponse::into_response);
    }
    match (method, route.template) {
        ("PUT", "/api/v1/config/sources/{source_id}") => {
            return config::replace(
                &state,
                path.trim_start_matches("/api/v1/config/sources/")
                    .to_owned(),
                request,
                &id,
            )
            .await
            .unwrap_or_else(|error| error.with_request_id(id.0.clone()).into_response());
        }
        ("POST", "/api/v1/config/validate") => {
            return config::validate(&state, request, &id)
                .await
                .unwrap_or_else(|error| error.with_request_id(id.0.clone()).into_response());
        }
        ("POST", "/api/v1/operations/reload") => {
            return config::reload(&state, request, &id)
                .await
                .unwrap_or_else(|error| error.with_request_id(id.0.clone()).into_response());
        }
        _ => {}
    }
    if method == "GET" {
        let result = match route.template {
            "/api" | "/api/v1/version" | "/api/v1/capabilities" => {
                parse_query(request.uri(), &[], &id).map(|_| match path {
                    "/api" => Json(discovery()).into_response(),
                    "/api/v1/version" => Json(version()).into_response(),
                    _ => Json(capabilities(&state)).into_response(),
                })
            }
            "/api/v1/runtime" => runtime(&state, request.uri(), &id).await,
            "/api/v1/runtime/memory" => telemetry::memory(&state, request.uri(), &id).await,
            "/api/v1/runtime/outbounds" => telemetry::outbounds(&state, request.uri(), &id).await,
            "/api/v1/runtime/traffic/history" => {
                telemetry::traffic_history(&state, request.uri(), &id).await
            }
            "/api/v1/runtime/memory/history" => {
                telemetry::memory_history(&state, request.uri(), &id).await
            }
            "/api/v1/config" => config::get(&state, request.uri(), &id).await,
            "/api/v1/config/sources/{source_id}" => {
                config::source(
                    &state,
                    path.trim_start_matches("/api/v1/config/sources/"),
                    request.uri(),
                    &id,
                )
                .await
            }
            "/api/v1/operations/{id}" => config::operation(
                &state,
                path.trim_start_matches("/api/v1/operations/"),
                request.uri(),
                &id,
            ),
            "/api/v1/connections" => connections(&state, request.uri(), &id),
            "/api/v1/flows" => flows::list(&state, request.uri(), &id),
            "/api/v1/flows/{flow_id}" => flows::detail(
                &state,
                path.trim_start_matches("/api/v1/flows/"),
                request.uri(),
                &id,
            ),
            "/api/v1/nodes" => catalog::nodes(&state, request.uri(), &id).await,
            "/api/v1/groups" => catalog::groups(&state, request.uri(), &id).await,
            "/api/v1/groups/{groupId}" => {
                catalog::group(
                    &state,
                    path.trim_start_matches("/api/v1/groups/"),
                    request.uri(),
                    &id,
                )
                .await
            }
            _ => Err(error(
                StatusCode::NOT_FOUND,
                ErrorCode::CapabilityNotSupported,
                "Capability is not supported",
                &id,
            )),
        };
        return result.unwrap_or_else(|error| error.with_request_id(id.0.clone()).into_response());
    }
    error(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Capability is not supported",
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
    let (generation, phase, healthy, config_revision, last_reload) = {
        let _config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        #[cfg(test)]
        {
            let hook = state.after_generation.lock().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        (
            generation,
            *state.phase.borrow(),
            state.healthy.load(Ordering::Acquire),
            state.observation.configuration.revision(),
            state.observation.configuration.last_reload(),
        )
    };
    let lifecycle = match phase {
        EnginePhase::Starting => "starting",
        EnginePhase::Running if !healthy => "degraded",
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
            state: "active",
            activated_at: None,
        },
        // The control plane's own health flag is the engine's verdict on its
        // datapath; only the kernel detail (attachments, maps) is out of view.
        datapath: DatapathSummary {
            kind: if state.mock_mode { "mock" } else { "ebpf" },
            state: if state.mock_mode {
                "disabled"
            } else if !healthy {
                "degraded"
            } else {
                "active"
            },
            visibility: "none",
            ebpf: (),
        },
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
        rule_id: None,
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
    Ok(Json(ConnectionList {
        observed_at: timestamp(SystemTime::now()),
        instance_id: state.instance_id.clone(),
        visibility: "partial",
        truncated,
        tcp,
        udp,
        total_tcp,
        total_udp,
    })
    .into_response())
}

async fn sample_traffic(state: Arc<NativeState>, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut previous: Option<(Instant, Option<(u64, u64)>)> = None;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = interval.tick() => {
                state.observation.flows.maintain();
                let now = Instant::now();
                let totals = state.stats.traffic_totals();
                let rates = previous.and_then(|(instant, old)| {
                    let elapsed = now.duration_since(instant);
                    let (old_up, old_down) = old?;
                    let (up, down) = totals?;
                    let up = up.checked_sub(old_up)?;
                    let down = down.checked_sub(old_down)?;
                    if elapsed.is_zero() { return None; }
                    let rate = |bytes: u64| u64::try_from(u128::from(bytes) * 1_000_000_000 / elapsed.as_nanos()).ok().map(|value| value.to_string());
                    Some(TrafficRates { window_seconds: elapsed.as_secs_f64(), upload_bytes_per_second: rate(up), download_bytes_per_second: rate(down) })
                });
                let (mut tcp, mut udp) = (0u64, 0u64);
                state.tracker.visit(|entry| match entry.network.as_str() { "tcp" => tcp += 1, "udp" => udp += 1, _ => {} });
                *state.sample.write() = Some(TrafficSummary {
                    scope: "visible", observed_by: "userspace", counter_since: Some(timestamp(state.stats.counter_since())), sampled_at: Some(timestamp(SystemTime::now())),
                    connections: TrafficConnections { tcp: Some(tcp), udp: Some(udp), total: Some(tcp + udp) },
                    bytes: TrafficBytes { upload: totals.map(|bytes| bytes.0.to_string()), download: totals.map(|bytes| bytes.1.to_string()) }, rates,
                });
                previous = Some((now, totals));
                let sample = state.sample.read().clone().expect("sample published above");
                state.observation.telemetry.sample(&sample).await;
                state.observation.events.publish("runtime.updated", serde_json::json!({}), None);
            }
        }
    }
}

struct NativeConsumer(Arc<ConnectionTracker>);
impl Drop for NativeConsumer {
    fn drop(&mut self) {
        self.0.disable_native();
    }
}

/// Owns every native connection and observer through bounded shutdown.
pub struct NativeServer {
    stop: watch::Sender<bool>,
    supervisor: JoinHandle<()>,
}

impl NativeServer {
    pub fn start(listener: TcpListener, state: Arc<NativeState>) -> Self {
        let (stop, receiver) = watch::channel(false);
        state.tracker.enable_native();
        let consumer = NativeConsumer(Arc::clone(&state.tracker));
        let supervisor = tokio::spawn(supervise(listener, state, receiver, consumer));
        Self { stop, supervisor }
    }

    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        if self.supervisor.await.is_err() {
            tracing::error!("native HTTP supervisor failed");
        }
    }
}
struct NativeIo {
    stream: tokio::net::TcpStream,
    idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_idle: std::pin::Pin<Box<tokio::time::Sleep>>,
    write_pending: bool,
}

impl NativeIo {
    fn new(stream: tokio::net::TcpStream) -> Self {
        Self {
            stream,
            idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_idle: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
            write_pending: false,
        }
    }

    fn progress(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + Duration::from_secs(30));
    }

    fn pending_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::future::Future;
        if !self.write_pending {
            self.write_pending = true;
            self.write_idle
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(30));
        }
        if self.write_idle.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()))
        } else {
            std::task::Poll::Pending
        }
    }
}

impl tokio::io::AsyncRead for NativeIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::future::Future;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.progress();
        }
        if result.is_pending() && self.idle.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::TimedOut.into()));
        }
        result
    }
}

impl tokio::io::AsyncWrite for NativeIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.stream).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result
            && n > 0
        {
            self.progress();
            self.write_pending = false;
        }
        if result.is_pending() {
            self.pending_write(cx)
        } else {
            result
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn supervise(
    listener: TcpListener,
    state: Arc<NativeState>,
    mut stop: watch::Receiver<bool>,
    _consumer: NativeConsumer,
) {
    let router = router(Arc::clone(&state));
    let observation = Arc::clone(&state.observation);
    let (sampler_stop, sampler_receiver) = watch::channel(false);
    let (connections_stop, connection_receiver) = watch::channel(false);
    let mut sampler = tokio::spawn(sample_traffic(state, sampler_receiver));
    let mut sampler_running = true;
    let mut children = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = &mut sampler => {
                sampler_running = false;
                tracing::error!("native HTTP sampler stopped unexpectedly");
                break;
            }
            child = children.join_next(), if !children.is_empty() => {
                if child.is_some_and(|result| result.is_err()) {
                    tracing::error!("native HTTP connection task failed");
                    break;
                }
            }
            accepted = listener.accept(), if children.len() < 64 => {
                let Ok((stream, _)) = accepted else {
                    tracing::error!("native HTTP listener failed");
                    break;
                };
                let service = TowerToHyperService::new(router.clone());
                let mut stop = connection_receiver.clone();
                children.spawn(async move {
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_headers(100).max_buf_size(32768);
                    let connection = builder.serve_connection(TokioIo::new(NativeIo::new(stream)), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        result = &mut connection => { let _ = result; }
                        _ = stop.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    observation.events.shutdown();
    let _ = sampler_stop.send(true);
    if sampler_running {
        let _ = sampler.await;
    }
    let _ = connections_stop.send(true);
    if tokio::time::timeout(Duration::from_secs(5), async {
        while children.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        children.abort_all();
        while children.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> Arc<NativeState> {
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
            false,
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
}
