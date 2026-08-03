//! Clash-compatible REST API server for zashboard / Metacubexd dashboards.
//!
//! Enabled via `experimental.clash_api.external_controller` and compiled in
//! with the `clash-api` cargo feature (on by default). Implements the
//! sing-box `experimental/clashapi` minimal endpoint set: proxies, rules,
//! connections, configs/mode, delay tests, cache flush, log/traffic
//! websocket streams (with a chunked-HTTP fallback for plain GET clients),
//! `/dns/query`, proxy providers, and optional external UI hosting with
//! automatic dashboard download.

pub mod doh;
pub mod logs;
pub mod ui;

use axum::{
    Router,
    body::Body,
    extract::{
        FromRequestParts, Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
};
use bytes::Bytes;
use honk_config::Config;
use honk_config::group::GroupPolicy;
use honk_config::node::{Group, Node};
use honk_config::routing::RoutingOutbound;
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::{GroupManager, SharedGroupManager};
use honk_outbound::urltest::{urltest_group, urltest_node};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const STREAM_CHANNEL_CAPACITY: usize = 16;

/// Lazily populated fan-out for high-frequency API streams. A sampler checks
/// receiver count before it snapshots or serializes any data.
pub struct StreamSamplers {
    connections: dashmap::DashMap<Duration, tokio::sync::broadcast::Sender<Arc<Bytes>>>,
    traffic: tokio::sync::broadcast::Sender<Arc<Bytes>>,
    traffic_started: std::sync::atomic::AtomicBool,
    memory: tokio::sync::broadcast::Sender<Arc<Bytes>>,
    memory_started: std::sync::atomic::AtomicBool,
}

impl StreamSamplers {
    pub fn new() -> Self {
        let (traffic, _) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);
        let (memory, _) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);
        Self {
            connections: dashmap::DashMap::new(),
            traffic,
            traffic_started: std::sync::atomic::AtomicBool::new(false),
            memory,
            memory_started: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Default for StreamSamplers {
    fn default() -> Self {
        Self::new()
    }
}

use crate::mode::{ModeState, SharedModeState};
pub(crate) fn parse_dashboard_storage(value: Option<&str>) -> serde_json::Value {
    value
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}))
}

pub struct ClashState {
    pub config: Arc<tokio::sync::RwLock<Config>>,
    pub config_path: std::path::PathBuf,
    pub command_tx: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    pub subscription_refresh: Arc<crate::subscription::SubscriptionRefreshCoordinator>,
    pub dashboard_storage: parking_lot::RwLock<serde_json::Value>,
    pub ui_update_lock: Arc<tokio::sync::Mutex<()>>,
    pub stats: Arc<crate::stats::StatsManager>,
    pub alive_set: Arc<AliveDialerSet>,
    /// Hot-swappable group manager cell; a config reload swaps the inner
    /// manager and this API sees the new groups on the next request.
    pub group_manager: SharedGroupManager,
    pub cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    pub connection_tracker: Arc<crate::connection_tracker::ConnectionTracker>,
    pub proxy_registry: Arc<honk_outbound::proxy::ProxyRegistry>,
    /// Shared clash mode + GLOBAL selection (also held by the control
    /// plane, which applies the mode override on the outbound path).
    pub mode_state: SharedModeState,
    /// Bearer secret from `experimental.clash_api.secret`; empty = no auth.
    pub secret: String,
    /// Shared connection pool (ready-pool hit/miss metrics in `/stats`).
    pub connection_pool: Arc<crate::pool::ConnectionPool>,
    /// External UI directory (`experimental.clash_api.external_ui`).
    pub external_ui: String,
    pub ui_download_url: Option<String>,
    /// Broadcast channel fed by the clash log tracing layer.
    pub log_tx: tokio::sync::broadcast::Sender<logs::LogEvent>,
    pub dns_service: crate::dns::DnsService,
    /// Shared lazy samplers for high-fanout websocket/HTTP streams.
    pub stream_samplers: Arc<StreamSamplers>,
}

pub fn router(state: Arc<ClashState>) -> Router {
    let mut app = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route(
            "/configs",
            get(get_configs).put(put_configs).patch(patch_configs),
        )
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(put_proxy))
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group/{name}/delay", get(get_group_delay))
        .route("/rules", get(get_rules))
        .route(
            "/connections",
            get(get_connections).delete(delete_connections),
        )
        .route("/connections/{id}", delete(delete_connection))
        .route("/traffic", get(get_traffic))
        .route("/memory", get(get_memory))
        .route("/stats", get(get_outbound_stats))
        .route("/logs", get(get_logs))
        .route("/dns/query", get(get_dns_query))
        .route("/cache/fakeip/flush", post(flush_fakeip))
        .route("/cache/dns/flush", post(flush_dns))
        .route("/providers/proxies", get(get_proxy_providers))
        .route("/providers/rules", get(get_rule_providers))
        .route(
            "/storage/zashboard",
            get(get_dashboard_storage)
                .put(put_dashboard_storage)
                .delete(delete_dashboard_storage),
        )
        .route("/upgrade/ui", post(upgrade_ui))
        .route(
            "/providers/proxies/{provider}",
            axum::routing::put(refresh_proxy_provider),
        )
        .route(
            "/providers/proxies/{provider}/healthcheck",
            get(healthcheck_proxy_provider),
        )
        .route(
            "/providers/proxies/{provider}/{proxy}/healthcheck",
            get(healthcheck_provider_proxy),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // External UI hosting (outside auth, mirroring sing-box).
    if !state.external_ui.is_empty() {
        // sing-box server_resources.go: download the dashboard in the
        // background when the directory is missing/empty; ServeDir keeps
        // returning 404 until the files land (never blocks startup).
        ui::spawn_ui_download_if_needed(
            state.external_ui.clone(),
            Arc::clone(&state.ui_update_lock),
            state.ui_download_url.clone(),
        );
        app = app
            // 301 Moved Permanently, matching sing-box's RedirectHandler.
            .route(
                "/ui",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::MOVED_PERMANENTLY)
                        .header(header::LOCATION, "/ui/")
                        .body(axum::body::Body::empty())
                        .expect("static redirect response")
                }),
            )
            .nest_service(
                "/ui/",
                tower_http::services::ServeDir::new(&state.external_ui),
            );
    }

    // Dashboards are served from a different origin; allow cross-origin
    // calls the same way sing-box does (AccessControlAllowOrigin: *).
    app.layer(tower_http::cors::CorsLayer::permissive())
        .with_state(state)
}

pub async fn serve(state: Arc<ClashState>, listen: std::net::SocketAddr) {
    let app = router(state);
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("clash API failed to bind {}: {}", listen, e);
            return;
        }
    };
    tracing::info!("clash API listening on http://{listen}");
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("clash API server error: {}", e);
    }
}

/// Optional websocket upgrade: `None` when the request has no valid WS
/// handshake headers (plain GET). Used so endpoints can serve both the
/// JSON document and the WS stream on the same path.
struct MaybeWs(Option<WebSocketUpgrade>);

impl<S> FromRequestParts<S> for MaybeWs
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .ok(),
        ))
    }
}

/// When `secret` is configured, every request needs
/// `Authorization: Bearer <secret>` — except websocket upgrades, which may
/// pass `?token=<secret>` because browsers cannot set headers on WS
/// handshakes. The query token is percent-decoded before comparison so
/// secrets containing reserved characters (`+`, `=`, `&`, ...) match.
/// Failures get 401 `{"message":"Unauthorized"}`.
async fn auth_middleware(
    State(s): State<Arc<ClashState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if s.secret.is_empty() {
        return next.run(req).await;
    }

    let is_ws_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if is_ws_upgrade
        && let Some(token) = req
            .uri()
            .query()
            .and_then(|q| query_param(q, "token"))
            .filter(|t| !t.is_empty())
    {
        let decoded = percent_encoding::percent_decode_str(token).decode_utf8_lossy();
        if decoded.as_ref() == s.secret.as_str() {
            return next.run(req).await;
        }
        return unauthorized();
    }

    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|h| h == format!("Bearer {}", s.secret))
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        unauthorized()
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"message": "Unauthorized"})),
    )
        .into_response()
}

/// Extract `key` from a raw `a=1&b=2` query string. The value is returned
/// verbatim (not percent-decoded); callers decode as needed — the WS auth
/// path percent-decodes the token before comparing it to the secret.
fn query_param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v)
    })
}

/// JSON error body in the clash `{"message": ...}` shape.
fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"message": message}))).into_response()
}

/// GET / — health check; redirects browsers to the UI when one is hosted.
async fn hello(State(s): State<Arc<ClashState>>, headers: HeaderMap) -> Response {
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false);
    if !s.external_ui.is_empty() && !accepts_json {
        // 302 Found, same as a dashboard would follow after login.
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/ui/")
            .body(axum::body::Body::empty())
            .expect("static redirect response");
    }
    Json(serde_json::json!({"hello": "clash"})).into_response()
}

/// GET /version — select zashboard's sing-box-compatible capability profile.
async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": concat!("sing-box honk ", env!("CARGO_PKG_VERSION")),
    }))
}

/// GET /configs — current configuration snapshot in Clash-compatible format.
async fn get_configs(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let mode = s.mode_state.read().mode.clone();
    let config = s.config.read().await;
    Json(serde_json::json!({
        "mode": mode,
        "mode-list": ["Rule", "Global", "Direct"],
        "modes": ["Rule", "Global", "Direct"],
        "tproxy-port": config.global.tproxy_port,
        "port": 0,
        "socks-port": 0,
        "redir-port": 0,
        "mixed-port": 0,
        "allow-lan": false,
        "ipv6": false,
        "bind-address": "*",
        "log-level": config.global.log_level,
        "tun": {"enable": false},
    }))
}

#[derive(Debug, Default, serde::Deserialize)]
struct PutConfigsQuery {
    #[serde(default)]
    reload: bool,
    #[serde(default)]
    force: bool,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PutConfigsBody {
    #[serde(default)]
    path: String,
    #[serde(default)]
    payload: String,
}

async fn put_configs(
    State(s): State<Arc<ClashState>>,
    Query(query): Query<PutConfigsQuery>,
    body: Bytes,
) -> Response {
    let body = if body.is_empty() {
        PutConfigsBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(error) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {error}"));
            }
        }
    };
    if !query.reload || query.force || !body.path.is_empty() || !body.payload.is_empty() {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "config replacement is unsupported; edit the dae file and use reload=true",
        );
    }

    let (completion, acknowledged) = tokio::sync::oneshot::channel();
    if s.command_tx
        .send(crate::control::ControlCommand::ReloadConfig {
            path: s.config_path.clone(),
            completion,
        })
        .await
        .is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload owner is unavailable",
        );
    }
    match acknowledged.await {
        Ok(Ok(publication)) => {
            s.subscription_refresh
                .reconcile(&publication.subscriptions)
                .await;
            s.subscription_refresh
                .refresh_now(publication.refresh_subscriptions);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(crate::control::ReloadFailure::Invalid(error))) => {
            error_response(StatusCode::BAD_REQUEST, &error)
        }
        Ok(Err(crate::control::ReloadFailure::Rejected(error))) => {
            error_response(StatusCode::CONFLICT, &error)
        }
        Ok(Err(crate::control::ReloadFailure::Internal(error))) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, &error)
        }
        Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "reload acknowledgement is unavailable",
        ),
    }
}

/// PATCH /configs accepts only a mode mutation.
async fn patch_configs(State(s): State<Arc<ClashState>>, body: Bytes) -> Response {
    let body: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(error) => {
            return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {error}"));
        }
    };
    let Some(object) = body.as_object() else {
        return error_response(StatusCode::BAD_REQUEST, "invalid body: expected object");
    };
    if let Some(field) = object.keys().find(|field| field.as_str() != "mode") {
        return error_response(
            StatusCode::BAD_REQUEST,
            &format!("unsupported config field: {field}"),
        );
    }
    let Some(mode_text) = object.get("mode").and_then(serde_json::Value::as_str) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid config field: mode");
    };
    let Some(mode) = ModeState::normalize(mode_text) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid mode (expected Rule/Global/Direct)",
        );
    };
    s.mode_state.write().mode = mode.clone();
    if let Some(db) = &s.cache_db {
        db.save_clash_mode(&mode);
    }
    tracing::info!(mode = %mode, "clash mode updated");
    StatusCode::NO_CONTENT.into_response()
}

async fn get_dashboard_storage(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    Json(s.dashboard_storage.read().clone())
}

async fn put_dashboard_storage(State(s): State<Arc<ClashState>>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) if value.is_object() => value,
        Ok(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid dashboard storage: expected object",
            );
        }
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("invalid dashboard storage: {error}"),
            );
        }
    };
    let compact = serde_json::to_string(&value).expect("JSON value serialization cannot fail");
    *s.dashboard_storage.write() = value;
    if let Some(cache_db) = &s.cache_db {
        cache_db.set("zashboard:storage", &compact);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_dashboard_storage(State(s): State<Arc<ClashState>>) -> StatusCode {
    *s.dashboard_storage.write() = serde_json::json!({});
    if let Some(cache_db) = &s.cache_db {
        cache_db.remove("zashboard:storage");
    }
    StatusCode::NO_CONTENT
}

async fn upgrade_ui(State(s): State<Arc<ClashState>>) -> Response {
    if s.external_ui.is_empty() {
        return error_response(StatusCode::CONFLICT, "external UI is not configured");
    }
    let _update = s.ui_update_lock.lock().await;
    let result = match s.ui_download_url.as_deref() {
        Some(url) => ui::replace_external_ui_from_url(&s.external_ui, url).await,
        None => ui::replace_external_ui(&s.external_ui).await,
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("external UI update failed: {error:#}"),
        ),
    }
}

/// Map a node protocol to a Clash-compatible type name.
fn clash_protocol_type(protocol: NodeProtocol) -> &'static str {
    match protocol {
        NodeProtocol::SS => "Shadowsocks",
        NodeProtocol::SSR => "ShadowsocksR",
        NodeProtocol::Trojan => "Trojan",
        NodeProtocol::VMess => "Vmess",
        NodeProtocol::VLess => "Vless",
        NodeProtocol::TrojanGo => "Trojan",
        NodeProtocol::Socks5 => "Socks5",
        NodeProtocol::HTTP => "Http",
        NodeProtocol::Hysteria2 => "Hysteria2",
        NodeProtocol::Tuic => "Tuic",
        NodeProtocol::Juicity => "Juicity",
        NodeProtocol::AnyTLS => "AnyTLS",
    }
}

/// Map a GroupPolicy to a Clash-compatible type name.
fn clash_group_type(policy: GroupPolicy) -> &'static str {
    match policy {
        GroupPolicy::Selector => "selector",
        GroupPolicy::URLTest => "url_test",
        GroupPolicy::LoadBalance => "load_balance",
        GroupPolicy::Fallback => "fallback",
    }
}

/// Build a single proxy info object used by zashboard/Metacubexd for a group.
fn build_group_proxy_info(
    group: &Group,
    nodes: &[Node],
    group_manager: &GroupManager,
    alive_set: &AliveDialerSet,
) -> serde_json::Value {
    let node_names = group_manager.node_names_in_group(&group.name);
    let now = match group.policy {
        GroupPolicy::Selector => group_manager
            .get_selector_choice(&group.name)
            .or_else(|| group.default.clone())
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        GroupPolicy::URLTest => group_manager
            .get_urltest_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
        // Round-robin has no stable selection to display; show the first.
        GroupPolicy::LoadBalance => node_names.first().cloned().unwrap_or_default(),
        GroupPolicy::Fallback => group_manager
            .get_fallback_selection(&group.name)
            .or_else(|| node_names.first().cloned())
            .unwrap_or_default(),
    };

    let mut history: Vec<serde_json::Value> = Vec::new();
    for name in &node_names {
        if let Some((latency, at)) =
            alive_set.get_last_real_sample(name, ProbeDomain::Tcp, IpVersion::V4)
        {
            history.push(delay_history_entry(latency.as_millis() as u64, at));
        }
    }

    let udp = group_manager
        .leaf_node_names_in_group(&group.name)
        .iter()
        .any(|name| {
            nodes.iter().any(|node| {
                node.name == *name
                    && honk_outbound::runtime::OutboundCapabilities::for_node(node).udp
            })
        });
    let mut info = serde_json::json!({
        "name": group.name,
        "type": clash_group_type(group.policy),
        "all": node_names,
        "now": now,
        "udp": udp,
        "history": history,
    });
    if let Some(test_url) = &group.check_url {
        info["testUrl"] = serde_json::Value::String(test_url.clone());
    }
    info
}

/// Build a proxy info object for an individual node.
///
/// Includes the per-node delay history (clash `{time, delay}` shape) so
/// dashboards can render per-node latencies — group members included.
fn build_node_proxy_info(node: &Node, alive_set: &AliveDialerSet) -> serde_json::Value {
    // The built-in `direct` node displays as Direct (clash convention)
    // rather than by its marker protocol (HTTP).
    let display_type = if node.name == Config::BUILTIN_DIRECT_NODE {
        "Direct"
    } else {
        clash_protocol_type(node.protocol)
    };
    let mut info = serde_json::json!({
        "name": node.name,
        "type": display_type,
        "udp": honk_outbound::runtime::OutboundCapabilities::for_node(node).udp,
        "history": [],
    });
    if let Some((latency, at)) =
        alive_set.get_last_real_sample(&node.name, ProbeDomain::Tcp, IpVersion::V4)
    {
        let ms = latency.as_millis() as u64;
        info["history"] = serde_json::json!([delay_history_entry(ms, at)]);
    }
    info
}

/// A clash-shaped delay history entry: the measurement's own wall-clock
/// time, not the render time (dashboards treat "now" timestamps as fresh).
fn delay_history_entry(ms: u64, at: std::time::SystemTime) -> serde_json::Value {
    serde_json::json!({
        "time": chrono::DateTime::<chrono::Utc>::from(at).to_rfc3339(),
        "delay": ms,
    })
}

/// Build the synthetic GLOBAL selector group: every group plus every node
/// (clash semantics), with a virtual "Proxy" entry first for dashboard
/// compatibility. `now` comes from the shared mode state.
fn build_global_proxy_info(config: &Config, global_selection: &str) -> serde_json::Value {
    let mut all: Vec<String> = Vec::new();
    let mut push_unique = |name: &str| {
        if name != "Direct" && name != "Block" && !all.iter().any(|n| n == name) {
            all.push(name.to_string());
        }
    };
    for group in &config.groups {
        push_unique(&group.name);
    }
    for node in &config.nodes {
        push_unique(&node.name);
    }
    if !all.is_empty() {
        all.insert(0, "Proxy".to_string());
    }
    let now = if global_selection.is_empty() {
        "Proxy"
    } else {
        global_selection
    };
    serde_json::json!({
        "name": "GLOBAL",
        "type": "selector",
        "all": all,
        "now": now,
        "udp": config.nodes.iter().any(|node| {
            honk_outbound::runtime::OutboundCapabilities::for_node(node).udp
        }),
    })
}

async fn get_proxies(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let global_selection = s.mode_state.read().global_selection.clone();
    let group_manager = s.group_manager.read().clone();
    let mut proxies = serde_json::Map::new();

    // Emit every node as a top-level proxy — including group members. Clash
    // dashboards resolve group members through these entries to display node
    // names and per-node delay history (real Clash behaves the same way).
    for node in &config.nodes {
        proxies.insert(node.name.clone(), build_node_proxy_info(node, &s.alive_set));
    }

    for group in &config.groups {
        proxies.insert(
            group.name.clone(),
            build_group_proxy_info(group, &config.nodes, &group_manager, &s.alive_set),
        );
    }

    proxies.insert(
        "GLOBAL".to_string(),
        build_global_proxy_info(&config, &global_selection),
    );

    Json(serde_json::json!({"proxies": proxies}))
}

async fn get_proxy(State(s): State<Arc<ClashState>>, Path(name): Path<String>) -> Response {
    let config = s.config.read().await;
    let group_manager = s.group_manager.read().clone();

    if name == "GLOBAL" {
        let global_selection = s.mode_state.read().global_selection.clone();
        return Json(build_global_proxy_info(&config, &global_selection)).into_response();
    }

    if let Some(group) = config.groups.iter().find(|g| g.name == name) {
        return Json(build_group_proxy_info(
            group,
            &config.nodes,
            &group_manager,
            &s.alive_set,
        ))
        .into_response();
    }

    if let Some(node) = config.nodes.iter().find(|n| n.name == name) {
        return Json(build_node_proxy_info(node, &s.alive_set)).into_response();
    }

    error_response(StatusCode::NOT_FOUND, "proxy not found")
}

/// Body for `/proxies/{name}` PUT: `{"name": "target_node"}`.
#[derive(Debug, serde::Deserialize)]
struct PutProxyBody {
    name: String,
}

async fn put_proxy(
    State(s): State<Arc<ClashState>>,
    Path(group_name): Path<String>,
    body: Bytes,
) -> Response {
    // Dashboards (metacubexd/zashboard) PUT the selection without a JSON
    // Content-Type; accept any content type (mihomo parity) and fail only
    // on a genuinely malformed body.
    let body: PutProxyBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    // GLOBAL is a synthetic selector backed by the shared mode state.
    if group_name == "GLOBAL" {
        let config = s.config.read().await;
        let valid = body.name == "Proxy"
            || config.groups.iter().any(|g| g.name == body.name)
            || config.nodes.iter().any(|n| n.name == body.name);
        drop(config);
        if !valid {
            return error_response(StatusCode::BAD_REQUEST, "unknown proxy name");
        }
        s.mode_state.write().global_selection = body.name.clone();
        if let Some(ref db) = s.cache_db {
            db.save_selector_choice("GLOBAL", &body.name);
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    let config = s.config.read().await;
    let Some(group) = config.groups.iter().find(|g| g.name == group_name) else {
        return error_response(StatusCode::NOT_FOUND, "group not found");
    };
    if group.policy != GroupPolicy::Selector {
        return error_response(StatusCode::BAD_REQUEST, "must be a Selector group");
    }
    // Members are member TAGS (node names + nested sub-group tags): picking
    // a sub-group defers to its own selection (sing-box drill-down). A leaf
    // inside a sub-group is not a direct member and is rejected here.
    let is_member = {
        let gm = s.group_manager.read();
        gm.node_names_in_group(&group_name)
            .iter()
            .any(|t| t == &body.name)
    };
    drop(config);
    if !is_member {
        return error_response(StatusCode::BAD_REQUEST, "node is not a member of the group");
    }

    // cache.db persistence runs through the group manager's persist
    // callback, wired by ControlPlane::init_cache_db.
    s.group_manager
        .read()
        .set_selector_choice(&group_name, &body.name);
    StatusCode::NO_CONTENT.into_response()
}

/// Query params for delay endpoints: `?url=<url>&timeout=<ms>`.
#[derive(Debug, serde::Deserialize)]
struct DelayQuery {
    #[serde(default)]
    url: String,
    #[serde(default)]
    timeout: Option<u64>,
}

impl DelayQuery {
    fn timeout(&self) -> Duration {
        // Zero means "use the urltest default" (urltest_node normalizes).
        self.timeout
            .map(Duration::from_millis)
            .unwrap_or(Duration::ZERO)
    }
}

/// Clamp a measured latency to clash's uint16 delay range.
fn delay_ms(d: Duration) -> u64 {
    (d.as_millis() as u64).min(u16::MAX as u64)
}

async fn measure_node_delay(
    state: &ClashState,
    node: &Node,
    url: &str,
    timeout: Duration,
) -> Result<u64, String> {
    let Some(handler) = state.proxy_registry.find(node.protocol) else {
        return Err("no handler for the node protocol".to_owned());
    };
    match urltest_node(node, handler, url, timeout).await {
        Ok(latency) => {
            state.alive_set.record_probe_latency(
                &node.name,
                ProbeDomain::Tcp,
                IpVersion::V4,
                latency,
            );
            Ok(delay_ms(latency))
        }
        Err(error) => {
            state
                .alive_set
                .record_dial_failure(&node.name, ProbeDomain::Tcp, IpVersion::V4);
            Err(format!("An error occurred in the delay test: {error}"))
        }
    }
}

/// GET /proxies/{name}/delay — live latency measurement (HEAD request
/// through the node / group members). Successes refresh the alive-set
/// latency history; failures clear it and return 503.
async fn get_proxy_delay(
    State(s): State<Arc<ClashState>>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let config = s.config.read().await;

    if let Some(node) = config.nodes.iter().find(|n| n.name == name).cloned() {
        drop(config);
        return match measure_node_delay(&s, &node, &query.url, query.timeout()).await {
            Ok(delay) => Json(serde_json::json!({"delay": delay})).into_response(),
            Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, &error),
        };
    }

    // Group: measure the flattened members (sub-groups measured through
    // their representative leaf), report the current selection's delay.
    if config.groups.iter().any(|g| g.name == name) {
        let members = {
            let gm = s.group_manager.read();
            gm.delay_test_members(&name)
        };
        drop(config);
        if members.is_empty() {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "group has no members");
        }
        let leaves: Vec<Node> = members.iter().map(|(_, leaf)| leaf.clone()).collect();
        let results = urltest_group(
            &leaves,
            &s.proxy_registry,
            &s.alive_set,
            &query.url,
            query.timeout(),
        )
        .await;
        // sing-box performUpdateCheck: an explicit delay test immediately
        // re-evaluates the URLTest selection with the fresh measurements
        // (tolerance hysteresis applies). Without this the group's `now`
        // would only update on the next real dial.
        {
            let gm = s.group_manager.read().clone();
            if gm.get_group_policy(&name) == Some(GroupPolicy::URLTest) {
                let _ = gm.select_node_for_domain(&name, ProbeDomain::Tcp, IpVersion::V4);
            }
        }
        // The current selection is a member TAG (node name or sub-group
        // tag); its delay is the measurement of that member's leaf.
        let current = {
            let gm = s.group_manager.read();
            gm.get_selector_choice(&name)
                .or_else(|| gm.get_urltest_selection(&name))
        }
        .or_else(|| members.first().map(|(tag, _)| tag.clone()));
        if let Some(current) = current
            && let Some((_, leaf)) = members.iter().find(|(tag, _)| tag == &current)
            && let Some((_, Ok(latency))) = results.iter().find(|(n, _)| n == &leaf.name)
        {
            return Json(serde_json::json!({"delay": delay_ms(*latency)})).into_response();
        }
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        );
    }

    error_response(StatusCode::NOT_FOUND, "proxy not found")
}

/// GET /group/{name}/delay — clash-meta group delay test: measures every
/// member concurrently and returns `{"<memberTag>": ms, ...}`; failed
/// members are omitted (sing-box api_meta_group.go semantics). Nested
/// sub-groups are measured through their representative leaf and reported
/// under their own tag.
async fn get_group_delay(
    State(s): State<Arc<ClashState>>,
    Path(name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let config = s.config.read().await;
    if !config.groups.iter().any(|g| g.name == name) {
        return error_response(StatusCode::NOT_FOUND, "group not found");
    }
    let members = {
        let gm = s.group_manager.read();
        gm.delay_test_members(&name)
    };
    drop(config);

    let leaves: Vec<Node> = members.iter().map(|(_, leaf)| leaf.clone()).collect();
    let results = urltest_group(
        &leaves,
        &s.proxy_registry,
        &s.alive_set,
        &query.url,
        query.timeout(),
    )
    .await;
    // sing-box performUpdateCheck: re-evaluate the URLTest selection with
    // the fresh measurements (see get_proxy_delay's group branch).
    {
        let gm = s.group_manager.read().clone();
        if gm.get_group_policy(&name) == Some(GroupPolicy::URLTest) {
            let _ = gm.select_node_for_domain(&name, ProbeDomain::Tcp, IpVersion::V4);
        }
    }
    let mut delays = serde_json::Map::new();
    for (tag, leaf) in &members {
        if let Some((_, Ok(latency))) = results.iter().find(|(n, _)| n == &leaf.name) {
            delays.insert(tag.clone(), serde_json::json!(delay_ms(*latency)));
        }
    }
    Json(serde_json::Value::Object(delays)).into_response()
}

/// Extract the proxy tag name from a RoutingOutbound.
fn outbound_tag(outbound: &RoutingOutbound) -> String {
    match outbound {
        RoutingOutbound::Simple(name) => name.clone(),
        RoutingOutbound::Complex { outbounds, .. } => outbounds
            .first()
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
    }
}

async fn get_rules(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let mut rules = Vec::with_capacity(config.routing.rules.len() + 1);

    for (index, rule) in config.routing.rules.iter().enumerate() {
        let (rule_type, payload) = rule
            .condition
            .clash_rule_parts()
            .unwrap_or_else(|| ("Match", String::new()));
        rules.push(serde_json::json!({
            "type": rule_type,
            "payload": payload,
            "proxy": outbound_tag(&rule.outbound),
            "index": index,
            "size": -1,
        }));
    }
    rules.push(serde_json::json!({
        "type": "Match",
        "payload": "",
        "proxy": config.routing.default_outbound,
        "index": config.routing.rules.len(),
        "size": -1,
    }));

    Json(serde_json::json!({"rules": rules}))
}

fn udp_histogram_json(histogram: &crate::stats::UdpLatencyHistogramSnapshot) -> serde_json::Value {
    // The source histogram is a fixed 64-element atomic array. Snapshot
    // serialization allocates only this response array; it does not create
    // labels or unbounded metric state on the packet path.
    serde_json::json!({
        "count": histogram.count,
        "sumNanos": histogram.sum_nanos,
        "buckets": histogram.buckets.to_vec(),
    })
}

/// Per-outbound counters from the userspace stats manager (the datum the
/// retired debug API exposed at `/debug/stats`). Not part of the clash API
/// standard; handy for headless ops.
async fn get_outbound_stats(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let snap = s.stats.snapshot();
    let per_outbound: Vec<serde_json::Value> = snap
        .iter()
        .map(|(name, v)| {
            serde_json::json!({
                "name": name,
                "totalConns": v.total_conns,
                "activeConns": v.active_conns,
                "upload": v.tx_bytes,
                "download": v.rx_bytes,
                "errors": v.errors,
            })
        })
        .collect();
    let pool = s.connection_pool.ready_metrics();
    let udp = s.stats.udp_snapshot();
    Json(serde_json::json!({
        "outbounds": per_outbound,
        "pool": {
            "readyHits": pool.hits,
            "readyMisses": pool.misses,
            "entries": pool.entries,
        },
        "udp": {
            "endpoint": {
                "hits": udp.endpoint_hits,
                "misses": udp.endpoint_misses,
            },
            "latency": {
                "route": udp_histogram_json(&udp.route_latency),
                "dial": udp_histogram_json(&udp.dial_latency),
                "replyReady": udp_histogram_json(&udp.reply_ready_latency),
                "firstSend": udp_histogram_json(&udp.first_send_latency),
                "firstReply": udp_histogram_json(&udp.first_reply_latency),
            },
            "capacity": {
                "rejected": udp.capacity_rejections,
            },
            "slowPermit": {
                "accepted": udp.slow_permit_accepted,
                "rejected": udp.slow_permit_rejected,
                "closed": udp.slow_permit_closed,
            },
            "queue": {
                "accepted": udp.queue_accepted,
                "full": udp.queue_full,
                "flowFull": udp.flow_queue_full,
                "globalPayloadFull": udp.global_payload_full,
                "closed": udp.queue_closed,
            },
            "firstSend": {
                "failures": udp.first_send_failures,
            },
            "stagger": {
                "attempts": udp.stagger_attempts,
                "winners": udp.stagger_winners,
                "cancellations": udp.stagger_cancellations,
            },
            "warm": {
                "attempts": udp.warm_attempts,
                "successes": udp.warm_successes,
                "failures": udp.warm_failures,
            },
        },
    }))
}

#[derive(Debug, serde::Deserialize)]
struct ConnectionsQuery {
    /// WS push interval in milliseconds (default 1000).
    #[serde(default)]
    interval: Option<u64>,
}

/// Split a connection endpoint into the IP and port fields expected by
/// zashboard. Valid SocketAddr values are parsed first so IPv6 addresses keep
/// their complete host portion; malformed embedder/test values retain the
/// legacy final-colon split.
fn connection_endpoint_parts(endpoint: &str) -> (String, String) {
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        return (address.ip().to_string(), address.port().to_string());
    }

    endpoint
        .rsplit_once(':')
        .map(|(host, port)| {
            (
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
                port.to_string(),
            )
        })
        .unwrap_or_else(|| (endpoint.to_string(), String::new()))
}

/// Build the clash connections document from the tracker snapshot.
fn connections_json(s: &ClashState) -> serde_json::Value {
    let snapshots = s.connection_tracker.snapshot();
    let connections: Vec<serde_json::Value> = snapshots
        .iter()
        .map(|e| {
            let (src_ip, src_port) = connection_endpoint_parts(&e.source);
            let (dst_ip, dst_port) = connection_endpoint_parts(&e.destination);
            let host = e.domain.clone().unwrap_or_default();
            let start = std::time::SystemTime::now()
                .checked_sub(e.start_time.elapsed())
                .map(|time| chrono::DateTime::<chrono::Utc>::from(time).to_rfc3339())
                .unwrap_or_default();

            serde_json::json!({
                "id": e.id,
                "metadata": {
                    "destinationGeoIP": "",
                    "destinationIP": dst_ip,
                    "destinationIPASN": "",
                    "destinationPort": dst_port,
                    "dnsMode": "normal",
                    "dscp": e.dscp,
                    "host": host.clone(),
                    "inboundIP": "",
                    "inboundName": "",
                    "inboundPort": "",
                    "inboundUser": "",
                    "network": e.network,
                    "process": "",
                    "processPath": "",
                    "remoteDestination": "",
                    "sniffHost": host,
                    "sourceGeoIP": "",
                    "sourceIP": src_ip,
                    "sourceIPASN": "",
                    "sourcePort": src_port,
                    "specialProxy": "",
                    "specialRules": "",
                    "type": e.network,
                    "uid": 0,
                    "smartBlock": "",
                },
                "upload": e.upload,
                "download": e.download,
                "start": start,
                "chains": e.chains,
                "rule": e.rule,
                "rulePayload": e.rule_payload,
            })
        })
        .collect();

    let (upload, download) = s.connection_tracker.combined_traffic_totals(&s.stats);
    serde_json::json!({
        "downloadTotal": download,
        "uploadTotal": upload,
        "connections": connections,
    })
}

async fn get_connections(
    State(s): State<Arc<ClashState>>,
    Query(query): Query<ConnectionsQuery>,
    ws: MaybeWs,
) -> Response {
    if let Some(ws) = ws.0 {
        let interval = Duration::from_millis(query.interval.unwrap_or(1000).max(100));
        return ws.on_upgrade(move |socket| connections_ws(socket, s, interval));
    }
    Json(connections_json(&s)).into_response()
}

/// Push the full connections snapshot every `interval` until the client
/// disconnects.
async fn connections_ws(mut socket: WebSocket, s: Arc<ClashState>, interval: Duration) {
    let mut frames = connection_sampler(&s, interval).subscribe();
    loop {
        match frames.recv().await {
            Ok(frame) => {
                if socket
                    .send(Message::Text(
                        std::str::from_utf8(frame.as_ref())
                            .expect("connections JSON is UTF-8")
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn connection_sampler(
    s: &Arc<ClashState>,
    interval: Duration,
) -> tokio::sync::broadcast::Sender<Arc<Bytes>> {
    if let Some(existing) = s.stream_samplers.connections.get(&interval) {
        return existing.clone();
    }
    let (tx, _) = tokio::sync::broadcast::channel(STREAM_CHANNEL_CAPACITY);
    s.stream_samplers
        .connections
        .entry(interval)
        .or_insert_with(|| {
            let sampler_tx = tx.clone();
            let sampler_state = Arc::clone(s);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    if sampler_tx.receiver_count() == 0 {
                        continue;
                    }
                    let frame = Arc::new(Bytes::from(connections_json(&sampler_state).to_string()));
                    let _ = sampler_tx.send(frame);
                }
            });
            tx.clone()
        })
        .clone()
}

fn signal_all_connection_closes(tracker: &crate::connection_tracker::ConnectionTracker) {
    for snapshot in tracker.snapshot() {
        tracker.close_connection(&snapshot.id);
    }
}

fn signal_connection_close(tracker: &crate::connection_tracker::ConnectionTracker, id: &str) {
    tracker.close_connection(id);
}

async fn delete_connections(State(s): State<Arc<ClashState>>) -> StatusCode {
    signal_all_connection_closes(&s.connection_tracker);
    StatusCode::NO_CONTENT
}

async fn delete_connection(State(s): State<Arc<ClashState>>, Path(id): Path<String>) -> StatusCode {
    signal_connection_close(&s.connection_tracker, &id);
    StatusCode::NO_CONTENT
}

async fn traffic_totals(s: &ClashState) -> (u64, u64) {
    s.connection_tracker.combined_traffic_totals(&s.stats)
}

async fn get_traffic(State(s): State<Arc<ClashState>>, ws: MaybeWs) -> Response {
    let Some(ws) = ws.0 else {
        return chunked_json_response(traffic_chunk_stream(s));
    };
    ws.on_upgrade(move |socket| traffic_ws(socket, s))
}

async fn traffic_ws(mut socket: WebSocket, s: Arc<ClashState>) {
    ensure_traffic_sampler(&s);
    let mut frames = s.stream_samplers.traffic.subscribe();
    loop {
        match frames.recv().await {
            Ok(frame) => {
                if socket
                    .send(Message::Text(
                        std::str::from_utf8(frame.as_ref())
                            .expect("traffic JSON is UTF-8")
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}
fn ensure_traffic_sampler(s: &Arc<ClashState>) {
    if s.stream_samplers
        .traffic_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let state = Arc::clone(s);
    let tx = state.stream_samplers.traffic.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous = traffic_totals(&state).await;
        loop {
            tick.tick().await;
            let current = traffic_totals(&state).await;
            let up = current.0.saturating_sub(previous.0);
            let down = current.1.saturating_sub(previous.1);
            previous = current;
            if tx.receiver_count() == 0 {
                continue;
            }
            let frame = Arc::new(Bytes::from(
                serde_json::json!({
                    "up": up,
                    "down": down,
                })
                .to_string(),
            ));
            let _ = tx.send(frame);
        }
    });
}

/// Chunked-HTTP fallback for `/traffic`: the same per-second delta frames
/// as the WS stream, one JSON document per line.
fn traffic_chunk_stream(
    s: Arc<ClashState>,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    ensure_traffic_sampler(&s);
    let receiver = s.stream_samplers.traffic.subscribe();
    futures::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(frame) => {
                    let mut line = Vec::with_capacity(frame.len() + 1);
                    line.extend_from_slice(frame.as_ref());
                    line.push(b'\n');
                    return Some((Ok(Bytes::from(line)), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}
/// Return the process resident set size in bytes from Linux `/proc`.
///
/// The proc file is intentionally read into a fixed stack buffer: statm is a
/// short, fixed-shape record and this avoids an allocation on every sampler
/// tick. Invalid, zero, or overflowing values are reported to the caller.
fn process_resident_bytes() -> io::Result<u64> {
    let mut file = std::fs::File::open("/proc/self/statm")?;
    let mut buffer = [0_u8; 128];
    let length = file.read(&mut buffer)?;
    let text = std::str::from_utf8(&buffer[..length])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let resident_pages = text
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing resident pages"))?
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if resident_pages == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resident pages is zero",
        ));
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "system page size is nonpositive",
        ));
    }
    resident_pages
        .checked_mul(page_size as u64)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "resident bytes overflow"))
}

async fn get_memory(State(s): State<Arc<ClashState>>, ws: MaybeWs) -> Response {
    if let Err(error) = process_resident_bytes() {
        tracing::warn!("clash memory preflight failed: {error}");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "memory is unavailable");
    }
    let Some(ws) = ws.0 else {
        return chunked_json_response(memory_chunk_stream(s));
    };
    ws.on_upgrade(move |socket| memory_ws(socket, s))
}

async fn memory_ws(mut socket: WebSocket, s: Arc<ClashState>) {
    ensure_memory_sampler(&s);
    let mut frames = s.stream_samplers.memory.subscribe();
    loop {
        match frames.recv().await {
            Ok(frame) => {
                if socket
                    .send(Message::Text(
                        std::str::from_utf8(frame.as_ref())
                            .expect("memory JSON is UTF-8")
                            .into(),
                    ))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn ensure_memory_sampler(s: &Arc<ClashState>) {
    if s.stream_samplers
        .memory_started
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let state = Arc::clone(s);
    let tx = state.stream_samplers.memory.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if tx.receiver_count() == 0 {
                continue;
            }
            let resident = match process_resident_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!("clash memory sampler failed: {error}");
                    continue;
                }
            };
            let frame = Arc::new(Bytes::from(
                serde_json::json!({"inuse": resident}).to_string(),
            ));
            let _ = tx.send(frame);
        }
    });
}

fn memory_chunk_stream(
    s: Arc<ClashState>,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    ensure_memory_sampler(&s);
    let receiver = s.stream_samplers.memory.subscribe();
    futures::stream::unfold(receiver, |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(frame) => {
                    let mut line = Vec::with_capacity(frame.len() + 1);
                    line.extend_from_slice(frame.as_ref());
                    line.push(b'\n');
                    return Some((Ok(Bytes::from(line)), receiver));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

/// Wrap a JSON-lines stream into a chunked `application/json` response.
fn chunked_json_response<S>(stream: S) -> Response
where
    S: futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("chunked stream response")
}

#[derive(Debug, serde::Deserialize)]
struct LogsQuery {
    #[serde(default)]
    level: Option<String>,
}

async fn get_logs(
    State(s): State<Arc<ClashState>>,
    Query(query): Query<LogsQuery>,
    ws: MaybeWs,
) -> Response {
    let level_text = query.level.as_deref().unwrap_or("info");
    let Some(filter) = logs::parse_level(level_text) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid log level");
    };
    let Some(ws) = ws.0 else {
        return match filter {
            logs::LogFilter::Level(level) => chunked_json_response(logs_chunk_stream(s, level)),
            logs::LogFilter::Off => chunked_json_response(logs_off_chunk_stream()),
        };
    };
    ws.on_upgrade(move |socket| logs_ws(socket, s, filter))
}

/// Stream broadcast log events as `{"type": level, "payload": line}`.
async fn logs_ws(mut socket: WebSocket, s: Arc<ClashState>, filter: logs::LogFilter) {
    let level = match filter {
        logs::LogFilter::Level(level) => level,
        logs::LogFilter::Off => {
            while let Some(message) = socket.recv().await {
                if matches!(message, Err(_) | Ok(Message::Close(_))) {
                    break;
                }
            }
            return;
        }
    };
    let mut rx = s.log_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(event) => {
                if event.level > level {
                    continue;
                }
                let msg = serde_json::json!({
                    "type": event.level.as_str().to_lowercase(),
                    "payload": event.payload,
                });
                if socket
                    .send(Message::Text(msg.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Chunked-HTTP fallback for `/logs`: the same event documents as the WS
/// stream, one JSON object per line.
fn logs_chunk_stream(
    s: Arc<ClashState>,
    level: tracing::Level,
) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    let rx = s.log_tx.subscribe();
    futures::stream::unfold(rx, move |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if event.level > level {
                        continue;
                    }
                    let line = format!(
                        "{}\n",
                        serde_json::json!({
                            "type": event.level.as_str().to_lowercase(),
                            "payload": event.payload,
                        })
                    );
                    return Some((Ok(Bytes::from(line)), rx));
                }
                // Lagging subscribers skip ahead; a closed channel ends it.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

fn logs_off_chunk_stream()
-> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    futures::stream::pending()
}

/// Query params for `/dns/query`: `?name=<domain>&type=<A|AAAA|...>`.
#[derive(Debug, serde::Deserialize)]
struct DnsQueryParams {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "type")]
    qtype: Option<String>,
}

/// GET /dns/query — resolve a name through the control plane's DNS
/// forwarder and return a DoH-style JSON document:
/// `{"Status":0,"Question":[...],"Answer":[{"name","type","TTL","data"}]}`.
/// NXDOMAIN maps to Status 3, upstream failures to Status 2 (SERVFAIL);
/// a missing `name` is a 400.
async fn get_dns_query(
    State(s): State<Arc<ClashState>>,
    Query(q): Query<DnsQueryParams>,
) -> Response {
    let Some(name) = q.name.filter(|n| !n.trim().is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "missing name parameter");
    };
    let name = name.trim().trim_end_matches('.').to_string();
    let qtype = match q.qtype.as_deref() {
        None => 1, // default: A
        Some(t) => match doh::parse_qtype(t) {
            Some(v) => v,
            None => {
                return error_response(StatusCode::BAD_REQUEST, "invalid type parameter");
            }
        },
    };

    let query = crate::dns::forwarder::build_dns_query(&name, qtype);
    let result = s
        .dns_service
        .resolve(&query, crate::dns::query::IngressProfile::Api)
        .await;
    match result {
        Ok(resp) => Json(doh::response_json(&name, qtype, &resp)).into_response(),
        // Upstream error or negative-cache hit: report SERVFAIL-style.
        Err(e) => {
            tracing::debug!("/dns/query {} type {} failed: {:#}", name, qtype, e);
            Json(serde_json::json!({
                "Status": 2,
                "Question": [{"name": name, "type": qtype}],
                "Answer": [],
            }))
            .into_response()
        }
    }
}

async fn flush_fakeip(State(s): State<Arc<ClashState>>) -> StatusCode {
    if let Some(ref db) = s.cache_db {
        db.flush_prefix("fakeip:");
    }
    StatusCode::NO_CONTENT
}

async fn flush_dns(State(s): State<Arc<ClashState>>) -> StatusCode {
    match s.dns_service.flush_cache().await {
        Ok(true) => {}
        Ok(false) => {
            if let Some(ref db) = s.cache_db {
                db.flush_dns();
            }
        }
        Err(error) => {
            tracing::warn!(%error, "DNS persistence flush command failed");
        }
    }
    StatusCode::NO_CONTENT
}

fn provider_test_url(config: &Config) -> String {
    config
        .global
        .tcp_check_url
        .first()
        .filter(|url| !url.is_empty())
        .cloned()
        .unwrap_or_else(|| honk_outbound::urltest::DEFAULT_URLTEST_URL.to_owned())
}

async fn get_proxy_providers(State(s): State<Arc<ClashState>>) -> Json<serde_json::Value> {
    let config = s.config.read().await;
    let test_url = provider_test_url(&config);
    let mut providers = serde_json::Map::new();

    for subscription in config
        .subscriptions
        .iter()
        .filter(|subscription| subscription.enabled)
    {
        if providers.contains_key(&subscription.name) {
            tracing::warn!(
                provider = %subscription.name,
                "duplicate subscription provider name ignored"
            );
            continue;
        }
        let proxies = config
            .nodes
            .iter()
            .filter(|node| node.subscription_id == Some(subscription.id))
            .map(|node| build_node_proxy_info(node, &s.alive_set))
            .collect::<Vec<_>>();
        let updated_at = subscription
            .last_updated
            .unwrap_or(subscription.created_at)
            .to_rfc3339();
        providers.insert(
            subscription.name.clone(),
            serde_json::json!({
                "name": subscription.name,
                "type": "Proxy",
                "vehicleType": "HTTP",
                "updatedAt": updated_at,
                "testUrl": test_url,
                "proxies": proxies,
            }),
        );
    }
    Json(serde_json::json!({"providers": providers}))
}

async fn healthcheck_provider_proxy(
    State(s): State<Arc<ClashState>>,
    Path((provider_name, proxy_name)): Path<(String, String)>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let config = s.config.read().await;
    let Some(subscription) = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == provider_name)
    else {
        return error_response(StatusCode::NOT_FOUND, "provider not found");
    };
    if !subscription.enabled {
        return error_response(StatusCode::CONFLICT, "provider is disabled");
    }
    let Some(node) = config
        .nodes
        .iter()
        .find(|node| node.name == proxy_name && node.subscription_id == Some(subscription.id))
        .cloned()
    else {
        return error_response(StatusCode::NOT_FOUND, "provider proxy not found");
    };
    drop(config);

    match measure_node_delay(&s, &node, &query.url, query.timeout()).await {
        Ok(delay) => Json(serde_json::json!({"delay": delay})).into_response(),
        Err(error) => error_response(StatusCode::SERVICE_UNAVAILABLE, &error),
    }
}

async fn healthcheck_proxy_provider(
    State(s): State<Arc<ClashState>>,
    Path(provider_name): Path<String>,
    Query(query): Query<DelayQuery>,
) -> Response {
    let config = s.config.read().await;
    let Some(subscription) = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == provider_name)
    else {
        return error_response(StatusCode::NOT_FOUND, "provider not found");
    };
    if !subscription.enabled {
        return error_response(StatusCode::CONFLICT, "provider is disabled");
    }
    let nodes = config
        .nodes
        .iter()
        .filter(|node| node.subscription_id == Some(subscription.id))
        .cloned()
        .collect::<Vec<_>>();
    let test_url = provider_test_url(&config);
    drop(config);

    let results = urltest_group(
        &nodes,
        &s.proxy_registry,
        &s.alive_set,
        &test_url,
        query.timeout(),
    )
    .await;
    let mut delays = serde_json::Map::new();
    for (name, result) in results {
        if let Ok(latency) = result {
            delays.insert(name, serde_json::json!(delay_ms(latency)));
        }
    }
    Json(serde_json::Value::Object(delays)).into_response()
}

async fn refresh_proxy_provider(
    State(s): State<Arc<ClashState>>,
    Path(provider_name): Path<String>,
) -> Response {
    let config = s.config.read().await;
    let Some(subscription) = config
        .subscriptions
        .iter()
        .find(|subscription| subscription.name == provider_name)
        .cloned()
    else {
        return error_response(StatusCode::NOT_FOUND, "provider not found");
    };
    drop(config);
    if !subscription.enabled {
        return error_response(StatusCode::CONFLICT, "provider is disabled");
    }

    match s.subscription_refresh.refresh(subscription).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(crate::subscription::SubscriptionRefreshError::Fetch(error)) => {
            error_response(StatusCode::BAD_GATEWAY, &error)
        }
        Err(crate::subscription::SubscriptionRefreshError::Unavailable) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "subscription refresh is unavailable",
        ),
        Err(crate::subscription::SubscriptionRefreshError::Rejected(error)) => {
            error_response(StatusCode::CONFLICT, &error)
        }
    }
}

async fn get_rule_providers() -> Json<serde_json::Value> {
    Json(serde_json::json!({"providers": {}}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_storage_restores_only_objects() {
        assert_eq!(parse_dashboard_storage(None), serde_json::json!({}));
        assert_eq!(
            parse_dashboard_storage(Some("not-json")),
            serde_json::json!({})
        );
        assert_eq!(parse_dashboard_storage(Some("[]")), serde_json::json!({}));
        assert_eq!(
            parse_dashboard_storage(Some(r#"{"theme":"dark"}"#)),
            serde_json::json!({"theme": "dark"})
        );
    }

    fn tcp_entry(
        id: &str,
        close: tokio::sync::oneshot::Sender<()>,
    ) -> crate::connection_tracker::ConnectionEntry {
        crate::connection_tracker::ConnectionEntry {
            id: id.into(),
            source: "127.0.0.1:1000".into(),
            destination: "127.0.0.1:2000".into(),
            proxy: "proxy".into(),
            rule: "Match".into(),
            rule_payload: String::new(),
            chains: vec!["proxy".into()],
            upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
            domain: None,
            network: "tcp".into(),
            dscp: 0,
            close_handle: crate::connection_tracker::ConnectionCloseHandle::tcp(close),
        }
    }

    #[test]
    fn connection_delete_helpers_signal_each_tcp_handle_once() {
        let tracker = crate::connection_tracker::ConnectionTracker::new();
        let (first_close, mut first_closed) = tokio::sync::oneshot::channel();
        let (second_close, mut second_closed) = tokio::sync::oneshot::channel();
        tracker.register(tcp_entry("first", first_close));
        tracker.register(tcp_entry("second", second_close));

        signal_connection_close(&tracker, "first");
        signal_connection_close(&tracker, "first");
        signal_connection_close(&tracker, "missing");
        assert_eq!(first_closed.try_recv(), Ok(()));
        assert!(matches!(
            second_closed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        signal_all_connection_closes(&tracker);
        signal_all_connection_closes(&tracker);
        assert_eq!(second_closed.try_recv(), Ok(()));
        assert_eq!(tracker.snapshot().len(), 2);
    }
}
