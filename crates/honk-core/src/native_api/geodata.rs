use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use honk_config::experimental::{NativeApiConfig, parse_geodata_url};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::{Instant, timeout_at};

use super::operations::{OperationKind, Reservation};
use super::probes::Policy;
use super::{ApiError, ErrorCode, NativeState, config, parse_query, timestamp, types::RequestId};
use crate::download_route::{self, Outbounds};
use crate::routing::{GeoAssetSnapshot, GeoRequirements};

mod sources;
#[cfg(test)]
mod tests;

pub(crate) use sources::{Fetched, Patch as SourcesPatch, Route, Sources};

pub(crate) const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const UPDATE_PATH: &str = "/api/v1/geodata/update";
const MAX_CHECKSUM_BYTES: usize = 1024;

#[derive(Serialize)]
pub(crate) struct GeoData {
    observed_at: String,
    assets: Vec<GeoAsset>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    status: Option<Value>,
}

#[derive(Serialize)]
struct GeoAsset {
    kind: &'static str,
    sha256: String,
    size_bytes: String,
    modified_at: Option<String>,
    source_redacted: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    origin: Option<Origin>,
}

#[derive(Serialize)]
struct Origin {
    fetched_url_redacted: Option<String>,
    verified: bool,
    download_route: Option<Value>,
}

impl std::fmt::Debug for GeoData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeoData")
            .field("observed_at", &self.observed_at)
            .field("asset_count", &self.assets.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct GeoUpdatePlan {
    pub(crate) traffic_router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    pub(crate) dns: crate::dns::DnsService,
    pub(crate) assets: Vec<GeoAssetSnapshot>,
    pub(crate) revision: String,
    /// Each asset's URLs in fallback order, resolved when the update was queued.
    pub(crate) urls: Vec<Vec<String>>,
    /// The route every request takes, resolved when the update was queued.
    pub(crate) route: Route,
    pub(crate) group_manager: honk_outbound::group::SharedGroupManager,
    pub(crate) proxy_registry: Arc<crate::proxy::ProxyRegistry>,
    pub(crate) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    pub(crate) catalog: Arc<super::catalog::Catalog>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) sources: Option<Arc<Sources>>,
}

/// How an update's requests reach their URLs.
pub(crate) struct Egress<'a> {
    pub(crate) bootstrap: &'a str,
    pub(crate) route: &'a Route,
    pub(crate) outbounds: Outbounds<'a>,
}

pub(crate) async fn capture(state: &NativeState) -> Result<Vec<GeoAssetSnapshot>, ApiError> {
    capture_assets(&state.traffic_router, &state.config, &state.dns).await
}

pub(crate) async fn capture_assets(
    traffic_router: &tokio::sync::RwLock<crate::routing::Router>,
    config: &tokio::sync::RwLock<Arc<honk_config::Config>>,
    dns: &crate::dns::DnsService,
) -> Result<Vec<GeoAssetSnapshot>, ApiError> {
    // Reload publishes under the same router-before-config lock order.
    let router = traffic_router.read().await;
    let _config = config.read().await;
    let mut assets = router.geo_assets().to_vec();
    for asset in dns.geo_assets() {
        if let Some(previous) = assets
            .iter_mut()
            .find(|previous| previous.kind == asset.kind)
        {
            if previous.path != asset.path
                || previous.sha256 != asset.sha256
                || previous.size_bytes != asset.size_bytes
            {
                return Err(unsupported());
            }
            if previous.modified_at != asset.modified_at {
                previous.modified_at = None;
            }
        } else {
            assets.push(asset);
        }
    }
    assets.sort_by_key(|asset| if asset.kind == "geosite" { 0 } else { 1 });
    Ok(assets)
}

/// The configuration file's download URL for `kind`, empty when it names none.
pub(crate) fn file_url<'a>(settings: &'a NativeApiConfig, kind: &str) -> &'a str {
    match kind {
        "geosite" => &settings.geosite_download_url,
        "geoip" => &settings.geoip_download_url,
        _ => "",
    }
}

/// The URLs for `kind`, in fallback order: the stored or built-in sources when
/// they are configurable, otherwise the configuration file's one URL.
pub(crate) fn urls(
    settings: &NativeApiConfig,
    sources: Option<&Sources>,
    kind: &str,
) -> Vec<String> {
    if let Some(sources) = sources {
        return sources.effective().urls(kind).to_vec();
    }
    let url = file_url(settings, kind);
    if url.is_empty() {
        Vec::new()
    } else {
        vec![url.to_owned()]
    }
}

/// The route in force: the stored one when sources are configurable,
/// otherwise the configuration file's, and routing when it names none.
fn route(settings: &NativeApiConfig, sources: Option<&Sources>) -> Route {
    match sources {
        Some(sources) => sources.effective().download,
        None => Route::from_detour(&settings.geodata_download_detour).unwrap_or_default(),
    }
}

/// A URL as `source_redacted` shows it.
pub(crate) fn redact(
    url: &str,
    secrets: &config::ListenerSecrets,
    service: &config::ConfigService,
) -> String {
    service.mask_text(&secrets.mask(url).0).0
}

/// A URL without userinfo, query and fragment, then masked like
/// `source_redacted`, for `fetched_url_redacted` and callers without control.
pub(crate) fn redact_fully(
    url: &str,
    secrets: &config::ListenerSecrets,
    service: &config::ConfigService,
) -> String {
    let stripped = match parse_geodata_url(url) {
        Some(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        None => url.split(['?', '#']).next().unwrap_or_default().to_owned(),
    };
    redact(&stripped, secrets, service)
}

pub(crate) fn project(
    assets: Vec<GeoAssetSnapshot>,
    geodata: Option<&Sources>,
    active: &honk_config::Config,
    sources: &config::ConfigService,
    group_id: impl Fn(&str) -> Option<String>,
) -> GeoData {
    let secrets = config::ListenerSecrets::from_config(active);
    let status = geodata.map(|geodata| {
        let requirements = GeoRequirements::for_traffic(&active.routing.rules).union(
            &crate::dns::routing::DnsRouter::geo_requirements(&active.dns),
        );
        let mut status = geodata.status_json(timestamp);
        status["required_codes"] = assets
            .iter()
            .map(|asset| (asset.kind.to_owned(), json!(requirements.codes(asset.kind))))
            .collect::<serde_json::Map<_, _>>()
            .into();
        status
    });
    GeoData {
        observed_at: timestamp(SystemTime::now()),
        assets: assets
            .into_iter()
            .map(|asset| {
                let source_redacted = urls(&active.experimental.native_api, geodata, asset.kind)
                    .first()
                    .map(|url| redact(url, &secrets, sources));
                let origin = geodata.map(|geodata| {
                    let fetched = geodata.fetched(asset.kind, &asset.sha256);
                    Origin {
                        verified: fetched.as_ref().is_some_and(|fetched| fetched.verified),
                        download_route: fetched.as_ref().map(|fetched| {
                            let mut route = fetched.route.json(&group_id);
                            route["group_id"] = json!(fetched.group.as_deref().and_then(&group_id));
                            route
                        }),
                        fetched_url_redacted: fetched
                            .map(|fetched| redact_fully(&fetched.url, &secrets, sources)),
                    }
                });
                GeoAsset {
                    kind: asset.kind,
                    sha256: asset.sha256,
                    size_bytes: asset.size_bytes.to_string(),
                    modified_at: asset.modified_at.map(timestamp),
                    source_redacted,
                    origin,
                }
            })
            .collect(),
        status,
    }
}

/// The API id of the group named `name`, while it exists.
pub(crate) fn group_id(catalog: &super::catalog::Catalog, name: &str) -> Option<String> {
    catalog.snapshot().groups.get(name).cloned()
}

fn updatable(state: &NativeState, settings: &NativeApiConfig, assets: &[GeoAssetSnapshot]) -> bool {
    state.observation.configuration.writable()
        && !assets.is_empty()
        && assets.iter().all(|asset| {
            asset.path.is_some() && !urls(settings, state.geodata.as_deref(), asset.kind).is_empty()
        })
}

pub(super) async fn capability(state: &NativeState) -> Value {
    match capture(state).await {
        Ok(assets) => {
            let active = state.config.read().await;
            let can_update = updatable(state, &active.experimental.native_api, &assets);
            let mut value = json!({"available": true, "can_update": can_update,
                "assets": assets.iter().map(|asset| asset.kind).collect::<Vec<_>>()});
            if state.geodata.as_ref().is_some() {
                value["configurable_sources"] = json!(true);
            }
            value
        }
        Err(_) => json!({"available": false}),
    }
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let assets = capture(state).await?;
    let active = state.config.read().await;
    Ok(axum::Json(project(
        assets,
        state.geodata.as_deref(),
        &active,
        &state.observation.configuration,
        |name| group_id(&state.observation.catalog, name),
    ))
    .into_response())
}

pub(super) async fn update(
    state: &Arc<NativeState>,
    request: Request,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(request.uri(), &[], id)?;
    let key = config::request_header(&request, "idempotency-key")?.map(str::to_owned);
    let body = axum::body::to_bytes(request.into_body(), 0)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
                "Geodata update takes no request body.",
                None,
            )
        })?;
    let reservation = state.observation.operations.reserve(
        state.principal(),
        "POST",
        UPDATE_PATH,
        key.as_deref(),
        &body,
        OperationKind::GeodataUpdate,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        queue(state, reservation).await;
    }
    Ok(admission.await?.into_response())
}

/// Hands a fresh reservation to the coordinator, or rejects it with the
/// reason no update can run.
async fn queue(state: &Arc<NativeState>, reservation: Reservation) -> bool {
    let prepared = async {
        let assets = capture(state).await?;
        let settings = state.config.read().await.experimental.native_api.clone();
        if !updatable(state, &settings, &assets) {
            return Err(unsupported());
        }
        let revision = state
            .observation
            .configuration
            .sources
            .revision()
            .ok_or_else(unsupported)?;
        let sources = state.geodata.clone();
        Ok::<_, ApiError>(GeoUpdatePlan {
            traffic_router: Arc::clone(&state.traffic_router),
            dns: state.dns.clone(),
            urls: assets
                .iter()
                .map(|asset| urls(&settings, sources.as_deref(), asset.kind))
                .collect(),
            route: route(&settings, sources.as_deref()),
            group_manager: Arc::clone(&state.group_manager),
            proxy_registry: Arc::clone(&state.proxy_registry),
            runtime_registry: Arc::clone(&state.runtime_registry),
            catalog: Arc::clone(&state.observation.catalog),
            assets,
            revision,
            policy: Arc::new(Policy::new(&state.settings)),
            sources,
        })
    }
    .await;
    match prepared {
        Ok(plan) => state
            .observation
            .configuration
            .queue_geodata(plan, reservation)
            .is_ok(),
        Err(error) => {
            state.observation.operations.reject(&reservation.id, error);
            false
        }
    }
}

/// Runs `geodata_update` when the schedule says so. A manual update in
/// progress holds the operation; its outcome moves the schedule instead.
pub(super) async fn schedule(state: Arc<NativeState>, mut stop: watch::Receiver<bool>) {
    let Some(sources) = state.geodata.clone() else {
        let _ = stop.wait_for(|stopped| *stopped).await;
        return;
    };
    loop {
        let changed = sources.changed();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let due = sources.next_check_at().map(|at| {
            tokio::time::Instant::now() + at.duration_since(SystemTime::now()).unwrap_or_default()
        });
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = &mut changed => {}
            _ = tokio::time::sleep_until(due.unwrap_or_else(tokio::time::Instant::now)), if due.is_some() => {
                match state.observation.operations.reserve(
                    state.principal(),
                    "POST",
                    UPDATE_PATH,
                    None,
                    &[],
                    OperationKind::GeodataUpdate,
                ) {
                    Ok(reservation) => {
                        if queue(&state, reservation).await {
                            sources.postpone();
                        } else {
                            sources.record(Err("update_unavailable".into()));
                        }
                    }
                    Err(error) => {
                        if error.into_response().status() == StatusCode::CONFLICT {
                            sources.postpone();
                        } else {
                            sources.record(Err("update_unavailable".into()));
                        }
                    }
                }
            }
        }
    }
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Loaded geodata is unavailable for this operation.",
        None,
    )
}

/// Downloads `kind` from the first URL that yields a usable file. A URL is
/// skipped on any download failure, and when fetching the sha256 published
/// beside it fails with anything but a 404 or the digest does not match; the
/// error of the last URL tried is returned. Every request takes the route in
/// `egress`; one it cannot carry fails like a connection and never goes
/// direct instead. `policy` applies to every URL but `exempt`, the one the
/// administrator wrote in the configuration file.
pub(crate) async fn fetch(
    kind: &'static str,
    urls: &[String],
    egress: &Egress<'_>,
    max_bytes: usize,
    policy: &Policy,
    exempt: &str,
) -> Result<(Arc<[u8]>, Fetched), &'static str> {
    let mut last = "invalid_source";
    for url in urls {
        let policy = (url != exempt).then_some(policy);
        let deadline = Instant::now() + NETWORK_TIMEOUT;
        let (bytes, group) = match download(url, egress, deadline, max_bytes, policy).await {
            Ok(downloaded) => downloaded,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let sha256 = crate::configuration::digest(&bytes);
        let Some(mut checksum) = parse_geodata_url(url) else {
            last = "invalid_source";
            continue;
        };
        checksum.set_path(&format!("{}.sha256sum", checksum.path()));
        let published = download(
            checksum.as_str(),
            egress,
            deadline,
            MAX_CHECKSUM_BYTES,
            policy,
        )
        .await;
        let verified = match published {
            Ok((published, _)) => {
                let matches = std::str::from_utf8(&published)
                    .ok()
                    .and_then(|text| text.split_whitespace().next())
                    .is_some_and(|expected| expected.eq_ignore_ascii_case(&sha256));
                if !matches {
                    last = "checksum_mismatch";
                    continue;
                }
                true
            }
            Err("http_not_found") => false,
            Err(_) => {
                last = "checksum_unavailable";
                continue;
            }
        };
        return Ok((
            bytes,
            Fetched {
                kind,
                url: url.clone(),
                sha256,
                verified,
                route: egress.route.clone(),
                group,
            },
        ));
    }
    Err(last)
}

const DETOUR_SETTING: &str = "geodata.download";
const PURPOSE: &str = "geodata download";

/// Fetches `url` through the route, with the group it went through.
async fn download(
    url: &str,
    egress: &Egress<'_>,
    deadline: Instant,
    max_bytes: usize,
    policy: Option<&Policy>,
) -> Result<(Arc<[u8]>, Option<String>), &'static str> {
    let url = parse_geodata_url(url).ok_or("invalid_source")?;
    let host = url.host_str().ok_or("invalid_source")?;
    let port = url.port_or_known_default().ok_or("invalid_source")?;
    if policy.is_some_and(|policy| !policy.http_port(port, url.scheme() == "https")) {
        return Err("destination_rejected");
    }
    let detour = match egress.route {
        Route::Direct => {
            return download_direct(url.as_str(), egress.bootstrap, deadline, max_bytes, policy)
                .await
                .map(|bytes| (bytes, None));
        }
        Route::Routing => None,
        Route::Group(group) => Some(group.as_str()),
    };
    let decision = timeout_at(
        deadline,
        egress
            .outbounds
            .decide(detour, DETOUR_SETTING, PURPOSE, (host, port), None),
    )
    .await
    .map_err(|_| "download_timeout")?
    .map_err(|_| "group_unavailable")?;
    match decision.route {
        download_route::Route::Block => Err("route_blocked"),
        download_route::Route::Direct { .. } => {
            download_direct(url.as_str(), egress.bootstrap, deadline, max_bytes, policy)
                .await
                .map(|bytes| (bytes, decision.group))
        }
        download_route::Route::Proxy { node, .. } => {
            // The node's egress resolves a domain; only a literal address can be checked here.
            if let Some(ip) = download_route::parse_host_ip(host)
                && policy.is_some_and(|policy| !policy.address(ip))
            {
                return Err("destination_rejected");
            }
            let tunnel = timeout_at(deadline, egress.outbounds.tunnel(&node, (host, port)))
                .await
                .map_err(|_| "download_timeout")?
                .map_err(|_| "connection_failed")?;
            let result = match timeout_at(deadline, tunnel.dial()).await {
                Err(_) => Err("download_timeout"),
                Ok(Err(_)) => Err("connection_failed"),
                Ok(Ok(stream)) => exchange(stream, &url, deadline, max_bytes).await,
            };
            if let Err(error) = tunnel.close().await {
                tracing::warn!(%error, "geodata download tunnel did not close cleanly");
            }
            result.map(|bytes| (bytes, decision.group))
        }
    }
}

/// Fetches `url` straight from its host, resolved with the bootstrap
/// resolver, over the bypass mark.
pub(crate) async fn download_direct(
    url: &str,
    bootstrap: &str,
    deadline: Instant,
    max_bytes: usize,
    policy: Option<&Policy>,
) -> Result<Arc<[u8]>, &'static str> {
    let url = parse_geodata_url(url).ok_or("invalid_source")?;
    let host = url
        .host_str()
        .ok_or("invalid_source")?
        .trim_matches(['[', ']']);
    let port = url.port_or_known_default().ok_or("invalid_source")?;
    if policy.is_some_and(|policy| !policy.http_port(port, url.scheme() == "https")) {
        return Err("destination_rejected");
    }
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        let resolver = honk_outbound::bootstrap::BootstrapResolver::parse(bootstrap)
            .ok_or("bootstrap_unavailable")?;
        timeout_at(deadline, resolver.query(host))
            .await
            .map_err(|_| "download_timeout")?
            .map_err(|_| "resolution_failed")?
    };
    let mut connected = None;
    let mut rejected = false;
    for ip in addresses {
        if policy.is_some_and(|policy| !policy.address(ip)) {
            rejected = true;
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = timeout_at(
            deadline,
            honk_outbound::util::connect_marked_addr(
                SocketAddr::new(ip, port),
                Some(honk_ebpf_common::DAE_BYPASS_MARK),
                remaining,
            ),
        )
        .await
        .map_err(|_| "download_timeout")?;
        if let Ok(stream) = result {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or(if rejected {
        "destination_rejected"
    } else {
        "connection_failed"
    })?;
    exchange(stream, &url, deadline, max_bytes).await
}

/// TLS for https, then one HTTP/1.1 GET.
async fn exchange<S>(
    stream: S,
    url: &reqwest::Url,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Arc<[u8]>, &'static str>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if url.scheme() == "https" {
        let host = url
            .host_str()
            .ok_or("invalid_source")?
            .trim_matches(['[', ']']);
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x08http/1.1")
            .map_err(|_| "tls_failed")?;
        let stream = timeout_at(deadline, connector.connect(host, stream))
            .await
            .map_err(|_| "download_timeout")?
            .map_err(|_| "tls_failed")?;
        receive(stream, url, deadline, max_bytes).await
    } else {
        receive(stream, url, deadline, max_bytes).await
    }
}

async fn receive<S>(
    stream: S,
    url: &reqwest::Url,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Arc<[u8]>, &'static str>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::Builder::new()
            .max_headers(64)
            .max_buf_size(32768)
            .handshake::<_, Body>(hyper_util::rt::TokioIo::new(stream)),
    )
    .await
    .map_err(|_| "download_timeout")?
    .map_err(|_| "http_failed")?;
    let mut drivers = tokio::task::JoinSet::new();
    drivers.spawn(connection);
    let result = timeout_at(deadline, async {
        let uri: Uri = url.as_str().parse().map_err(|_| "invalid_source")?;
        let request = Request::builder()
            .uri(uri.path_and_query().ok_or("invalid_source")?.clone())
            .header("host", uri.authority().ok_or("invalid_source")?.as_str())
            .header("connection", "close")
            .header("accept-encoding", "identity")
            .body(Body::empty())
            .map_err(|_| "invalid_source")?;
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|_| "http_failed")?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err("http_not_found");
        }
        if response.status() != StatusCode::OK {
            return Err("http_status_rejected");
        }
        if response.headers().contains_key("content-encoding") {
            return Err("content_encoding_rejected");
        }
        if response
            .body()
            .size_hint()
            .upper()
            .is_some_and(|size| size > max_bytes as u64)
        {
            return Err("asset_too_large");
        }
        let mut bytes = Vec::new();
        while let Some(frame) =
            std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx)).await
        {
            let frame = frame.map_err(|_| "http_failed")?;
            if let Ok(data) = frame.into_data() {
                if data.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err("asset_too_large");
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(Arc::from(bytes))
    })
    .await
    .unwrap_or(Err("download_timeout"));
    drop(sender);
    drivers.abort_all();
    while drivers.join_next().await.is_some() {}
    result
}
