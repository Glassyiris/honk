//! Shared HTTP boundary for the native API and its public static UI.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, HttpBody};
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::BytesMut;
use futures::future::poll_fn;
use honk_config::experimental::{NativeApiConfig, parse_native_authority, parse_native_origin};
use serde::de::IgnoredAny;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::types::{ApiError, ErrorCode, RequestId};
use super::{NativeState, RouteInfo, route_info};

const MAX_TARGET_BYTES: usize = 4096;
const MAX_HEADER_BYTES: usize = 16384;
const MAX_BODY_BYTES: usize = 65536;
const ALLOW_HEADERS: &str =
    "Authorization, Last-Event-ID, Content-Type, If-Match, Idempotency-Key, Accept";

pub(super) struct Security {
    expected: Option<[u8; 32]>,
    anonymous_loopback: bool,
    hosts: HashSet<(String, u16)>,
    origins: HashSet<(String, String, u16)>,
}

impl Security {
    pub(super) fn new(config: &NativeApiConfig, listen: SocketAddr) -> Self {
        let mut hosts = HashSet::new();
        if !listen.ip().is_unspecified() {
            hosts.insert((listen.ip().to_string(), listen.port()));
        }
        if listen.ip().is_loopback() {
            for host in ["localhost", "127.0.0.1", "::1"] {
                hosts.insert((host.to_owned(), listen.port()));
            }
        }
        // Extra proxy Hosts do not establish a trustworthy scheme or Origin.
        let mut origins: HashSet<_> = hosts
            .iter()
            .map(|(host, port)| ("http".to_owned(), host.clone(), *port))
            .collect();
        hosts.extend(config.allowed_hosts.iter().map(|host| {
            parse_native_authority(host, 80).expect("validated native host authority")
        }));
        origins.extend(
            config
                .allow_origins
                .iter()
                .map(|origin| parse_native_origin(origin).expect("validated native origin")),
        );
        Self {
            expected: (!config.secret.is_empty())
                .then(|| Sha256::digest(config.secret.as_bytes()).into()),
            anonymous_loopback: config.secret.is_empty()
                && config.allow_anonymous_loopback
                && listen.ip().is_loopback(),
            hosts,
            origins,
        }
    }

    fn check_origin(
        &self,
        headers: &HeaderMap,
        request_id: &str,
    ) -> Result<Option<HeaderValue>, ApiError> {
        single_header(headers, "host")
            .ok()
            .flatten()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| parse_native_authority(value, 80))
            .filter(|authority| self.hosts.contains(authority))
            .ok_or_else(|| forbidden(request_id))?;
        let origin = single_header(headers, "origin").map_err(|()| forbidden(request_id))?;
        if let Some(origin) = origin {
            let allowed = origin
                .to_str()
                .ok()
                .and_then(parse_native_origin)
                .is_some_and(|origin| self.origins.contains(&origin));
            if !allowed {
                return Err(forbidden(request_id));
            }
        }
        if self.anonymous_loopback {
            let site =
                single_header(headers, "sec-fetch-site").map_err(|()| forbidden(request_id))?;
            if let Some(site) = site {
                let site = site.to_str().map_err(|_| forbidden(request_id))?;
                if site.eq_ignore_ascii_case("cross-site") {
                    return Err(forbidden(request_id));
                }
            }
        }
        Ok(origin.cloned())
    }

    fn authenticate(&self, request: &Request, request_id: &str) -> Result<(), ApiError> {
        let authorization = single_header(request.headers(), "authorization")
            .map_err(|()| unauthorized(request_id))?;
        match (&self.expected, authorization) {
            (Some(expected), Some(value)) => {
                let (_, token) = value
                    .to_str()
                    .ok()
                    .and_then(|value| value.split_once(' '))
                    .filter(|(scheme, token)| {
                        scheme.eq_ignore_ascii_case("Bearer")
                            && honk_config::experimental::valid_native_bearer_token(token)
                    })
                    .ok_or_else(|| unauthorized(request_id))?;
                let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                if !bool::from(expected.ct_eq(&actual)) {
                    return Err(unauthorized(request_id));
                }
            }
            (None, None) if self.anonymous_loopback => {}
            _ => return Err(unauthorized(request_id)),
        }
        // Decode keys with the same form parser as API queries; never accept query credentials.
        let Query(parameters) = Query::<Vec<(String, IgnoredAny)>>::try_from_uri(request.uri())
            .map_err(|_| invalid_request(request_id))?;
        if parameters
            .iter()
            .any(|(name, _)| name == "token" || name == "access_token")
        {
            return Err(unauthorized(request_id));
        }
        Ok(())
    }
}

pub(super) async fn boundary(
    State(state): State<Arc<NativeState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path();
    let is_api = path == "/api" || path.starts_with("/api/");
    let is_ui = state.ui.is_some() && (matches!(path, "/" | "/ui") || path.starts_with("/ui/"));
    let route = route_info(path);
    let template = route.as_ref().map_or("unmatched", |route| route.template);
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let mut origin = None;
    let result: Result<Response, ApiError> = async {
        let header_bytes = check_bounds(&request, &request_id)?;
        origin = state
            .security
            .check_origin(request.headers(), &request_id)?;
        if is_api && method == Method::OPTIONS {
            return preflight(&request, route.as_ref(), origin.is_some(), &request_id);
        }
        if is_api {
            state.security.authenticate(&request, &request_id)?;
            let (parts, body) = request.into_parts();
            let bytes = read_body(body, header_bytes, &request_id).await?;
            if matches!(method, Method::GET | Method::HEAD) && !bytes.is_empty() {
                return Err(invalid_request(&request_id));
            }
            request = Request::from_parts(parts, Body::from(bytes.freeze()));
        }
        Ok(next.run(request).await)
    }
    .await;
    let boundary_error = result.is_err();
    let mut response = match result {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    if is_api || boundary_error {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
    }
    if is_ui && boundary_error {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        response
            .headers_mut()
            .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    if is_api && response.status() == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        response.headers_mut().insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("Location, Retry-After, ETag"),
        );
    }
    if method == Method::HEAD {
        if !response.headers().contains_key(header::CONTENT_LENGTH)
            && response.status() != StatusCode::NO_CONTENT
            && response.status() != StatusCode::NOT_MODIFIED
            && !response.status().is_informational()
            && let Some(length) = response.body().size_hint().exact()
        {
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        *response.body_mut() = Body::empty();
    }
    let logged_method = match method {
        Method::GET
        | Method::HEAD
        | Method::POST
        | Method::PUT
        | Method::DELETE
        | Method::CONNECT
        | Method::OPTIONS
        | Method::TRACE
        | Method::PATCH => method.as_str(),
        _ => "OTHER",
    };
    tracing::info!(
        method = logged_method,
        route = template,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
        request_id = %request_id,
        "native HTTP request"
    );
    response
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a HeaderValue>, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        Err(())
    } else {
        Ok(value)
    }
}

fn header_bytes(headers: &HeaderMap) -> usize {
    headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
    })
}

// Hyper normalizes targets and headers before this boundary (including fragment
// removal and equal Content-Length coalescing); these are application-view limits.
fn check_bounds(request: &Request, request_id: &str) -> Result<usize, ApiError> {
    let uri = request.uri();
    let target_bytes = uri.path_and_query().map_or(0, |value| value.as_str().len())
        + uri.scheme_str().map_or(0, |value| value.len() + 3)
        + uri.authority().map_or(0, |value| value.as_str().len());
    let header_bytes = header_bytes(request.headers());
    if target_bytes > MAX_TARGET_BYTES || header_bytes > MAX_HEADER_BYTES {
        return Err(too_large(request_id));
    }
    if let Some(length) = single_header(request.headers(), "content-length")
        .map_err(|()| invalid_request(request_id))?
    {
        let length = length.to_str().map_err(|_| invalid_request(request_id))?;
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_request(request_id));
        }
        if length
            .parse::<u64>()
            .map_or(true, |length| length > MAX_BODY_BYTES as u64)
        {
            return Err(too_large(request_id));
        }
    }
    if uri.scheme().is_some() || uri.authority().is_some() || !uri.path().starts_with('/') {
        return Err(invalid_request(request_id));
    }
    Ok(header_bytes)
}

async fn read_body(
    mut body: Body,
    mut headers_size: usize,
    request_id: &str,
) -> Result<BytesMut, ApiError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|_| invalid_request(request_id))?;
        match frame.into_data() {
            Ok(data) => {
                if data.len() > MAX_BODY_BYTES - bytes.len() {
                    return Err(too_large(request_id));
                }
                bytes.extend_from_slice(&data);
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    headers_size = headers_size.saturating_add(header_bytes(&trailers));
                    if headers_size > MAX_HEADER_BYTES {
                        return Err(too_large(request_id));
                    }
                }
            }
        }
    }
    Ok(bytes)
}

fn preflight(
    request: &Request,
    route: Option<&RouteInfo>,
    has_origin: bool,
    request_id: &str,
) -> Result<Response, ApiError> {
    let method = single_header(request.headers(), "access-control-request-method")
        .ok()
        .flatten()
        .and_then(|value| value.to_str().ok())
        .filter(|_| has_origin)
        .ok_or_else(|| invalid_request(request_id))?;
    let route = route
        .filter(|route| {
            route.methods.contains(&method) || (method == "HEAD" && route.methods.contains(&"GET"))
        })
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                ErrorCode::ResourceNotFound,
                "The requested resource was not found.",
                Some(request_id.to_owned()),
            )
        })?;
    for value in request
        .headers()
        .get_all(header::ACCESS_CONTROL_REQUEST_HEADERS)
    {
        let value = value.to_str().map_err(|_| invalid_request(request_id))?;
        for name in value.split(',').map(|name| name.trim_matches([' ', '\t'])) {
            if name.is_empty() {
                return Err(invalid_request(request_id));
            }
            if !ALLOW_HEADERS
                .split(", ")
                .any(|allowed| allowed.eq_ignore_ascii_case(name))
            {
                return Err(forbidden(request_id));
            }
        }
    }
    let mut methods = route.methods.join(", ");
    if route.methods.contains(&"GET") {
        methods.push_str(", HEAD");
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_str(&methods).expect("native route methods are HTTP tokens"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
    response.headers_mut().append(
        header::VARY,
        HeaderValue::from_static("Access-Control-Request-Method, Access-Control-Request-Headers"),
    );
    Ok(response)
}

fn invalid_request(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::BAD_REQUEST,
        ErrorCode::InvalidRequest,
        "The request is invalid.",
        Some(request_id.to_owned()),
    )
}

fn unauthorized(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        ErrorCode::AuthenticationRequired,
        "Valid bearer credentials are required.",
        Some(request_id.to_owned()),
    )
}

fn forbidden(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::PermissionDenied,
        "The request is not permitted by the HTTP security policy.",
        Some(request_id.to_owned()),
    )
}

fn too_large(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        ErrorCode::RequestTooLarge,
        "The request exceeds an HTTP size limit.",
        Some(request_id.to_owned()),
    )
}
