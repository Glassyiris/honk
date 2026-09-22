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
use tokio::time::{Instant, timeout_at};

use super::operations::OperationKind;
use super::{ApiError, ErrorCode, NativeState, config, parse_query, timestamp, types::RequestId};
use crate::routing::GeoAssetSnapshot;

pub(crate) const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
pub(crate) struct GeoData {
    observed_at: String,
    assets: Vec<GeoAsset>,
}

#[derive(Serialize)]
struct GeoAsset {
    kind: &'static str,
    sha256: String,
    size_bytes: String,
    modified_at: Option<String>,
    source_redacted: Option<String>,
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

pub(crate) fn configured_url<'a>(settings: &'a NativeApiConfig, kind: &str) -> &'a str {
    match kind {
        "geosite" => &settings.geosite_download_url,
        "geoip" => &settings.geoip_download_url,
        _ => "",
    }
}

pub(crate) fn project(assets: Vec<GeoAssetSnapshot>, settings: &NativeApiConfig) -> GeoData {
    GeoData {
        observed_at: timestamp(SystemTime::now()),
        assets: assets
            .into_iter()
            .map(|asset| {
                let url = configured_url(settings, asset.kind);
                let source_redacted = (!url.is_empty()).then(|| url.to_owned());
                GeoAsset {
                    kind: asset.kind,
                    sha256: asset.sha256,
                    size_bytes: asset.size_bytes.to_string(),
                    modified_at: asset.modified_at.map(timestamp),
                    source_redacted,
                }
            })
            .collect(),
    }
}

fn updatable(state: &NativeState, assets: &[GeoAssetSnapshot]) -> bool {
    state.observation.configuration.writable()
        && !assets.is_empty()
        && assets.iter().all(|asset| {
            asset.path.is_some()
                && parse_geodata_url(configured_url(&state.settings, asset.kind)).is_some()
        })
}

pub(super) async fn capability(state: &NativeState) -> Value {
    if state.settings.secret.is_empty() {
        return json!({"available": false, "can_update": false});
    }
    match capture(state).await {
        Ok(assets) => json!({"available": true, "can_update": updatable(state, &assets),
            "assets": assets.iter().map(|asset| asset.kind).collect::<Vec<_>>()}),
        Err(_) => json!({"available": false}),
    }
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    super::types::require_administrator(state)?;
    Ok(axum::Json(project(capture(state).await?, &state.settings)).into_response())
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
        if state.settings.secret.is_empty() {
            "anonymous"
        } else {
            "control"
        },
        "POST",
        "/api/v1/geodata/update",
        key.as_deref(),
        &body,
        OperationKind::GeodataUpdate,
    )?;
    let admission = reservation.admission();
    if reservation.fresh {
        let prepared = async {
            let assets = capture(state).await?;
            if !updatable(state, &assets) {
                return Err(unsupported());
            }
            let revision = state
                .observation
                .configuration
                .sources
                .revision()
                .ok_or_else(unsupported)?;
            Ok::<_, ApiError>(GeoUpdatePlan {
                traffic_router: Arc::clone(&state.traffic_router),
                dns: state.dns.clone(),
                assets,
                revision,
            })
        }
        .await;
        match prepared {
            Ok(plan) => state
                .observation
                .configuration
                .queue_geodata(plan, reservation)?,
            Err(error) => {
                state.observation.operations.reject(&reservation.id, error);
            }
        }
    }
    Ok(admission.await?.into_response())
}

fn unsupported() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        ErrorCode::CapabilityNotSupported,
        "Loaded geodata is unavailable for this operation.",
        None,
    )
}

pub(crate) async fn download(
    url: &str,
    bootstrap: &str,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Arc<[u8]>, &'static str> {
    let url = parse_geodata_url(url).ok_or("invalid_source")?;
    let host = url
        .host_str()
        .ok_or("invalid_source")?
        .trim_matches(['[', ']']);
    let port = url.port_or_known_default().ok_or("invalid_source")?;
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
    for ip in addresses {
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
    let stream = connected.ok_or("connection_failed")?;
    if url.scheme() == "https" {
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x08http/1.1")
            .map_err(|_| "tls_failed")?;
        let stream = timeout_at(deadline, connector.connect(host, stream))
            .await
            .map_err(|_| "download_timeout")?
            .map_err(|_| "tls_failed")?;
        receive(stream, &url, deadline, max_bytes).await
    } else {
        receive(stream, &url, deadline, max_bytes).await
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
