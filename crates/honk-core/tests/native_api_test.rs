//! Native HTTP boundary regressions using owned loopback servers, not UI conformance.

#![cfg(feature = "native-api")]

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};

use honk_config::Config;
use honk_core::connection_tracker::ConnectionEntry;
use honk_core::control::ControlPlane;
use honk_core::dns::DnsResolver;
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use honk_core::dns::routing::DnsRouter;
use honk_core::ebpf::mock::MockEbpfBackend;
use honk_core::native_api::{NativeServer, NativeState};
use honk_core::routing::Router;
use honk_outbound::proxy::ProxyRegistry;
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;

const SECRET: &str = "native-test-only-secret";
const IO_TIMEOUT: Duration = Duration::from_secs(3);

struct NoDns;

#[async_trait::async_trait]
impl DnsUpstreamPool for NoDns {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("observing the native API must not issue DNS queries")
    }
}

fn control_plane(config: Config) -> ControlPlane {
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::new(NoDns),
        Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).unwrap()),
    ));
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let resolver = DnsResolver::new(&config.dns).unwrap();
    ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap()
}

struct TestApp {
    addr: SocketAddr,
    client: Client,
    control: ControlPlane,
    state: Weak<NativeState>,
    server: NativeServer,
}

impl TestApp {
    async fn new(configure: impl FnOnce(&mut Config)) -> Self {
        Self::bound("127.0.0.1:0", configure).await
    }

    async fn bound(bind: &str, configure: impl FnOnce(&mut Config)) -> Self {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.listen = addr.to_string();
        config.experimental.native_api.secret = SECRET.into();
        config.ensure_builtin_nodes();
        configure(&mut config);
        let mut control = control_plane(config);
        let state = Arc::new(
            NativeState::new(&mut control, addr, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let weak = Arc::downgrade(&state);
        let server = NativeServer::start(listener, state);
        Self {
            addr,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(IO_TIMEOUT)
                .build()
                .unwrap(),
            control,
            state: weak,
            server,
        }
    }

    fn url(&self, path: &str) -> String {
        // A wildcard bind is reached through loopback.
        let addr = if self.addr.ip().is_unspecified() {
            SocketAddr::new("127.0.0.1".parse().unwrap(), self.addr.port())
        } else {
            self.addr
        };
        format!("http://{addr}{path}")
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client.get(self.url(path)).bearer_auth(SECRET)
    }

    async fn shutdown(self) {
        drop(self.client);
        timeout(Duration::from_secs(6), self.server.shutdown())
            .await
            .expect("native server exceeded its shutdown budget");
        assert!(
            self.state.upgrade().is_none(),
            "native state still owned after shutdown"
        );
    }
}

fn api_headers(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

fn error_body(body: &Value, code: &str) {
    assert_eq!(body["error"]["code"], code);
    assert!(body["error"]["message"].is_string());
    assert_eq!(body["error"].get("details"), Some(&Value::Null));
    uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();
    assert!(!body.to_string().contains(SECRET));
}

async fn error_response(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    api_headers(&response);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    if status == StatusCode::UNAUTHORIZED {
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
    error_body(&response.json::<Value>().await.unwrap(), code);
}

async fn response_json(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    api_headers(&response);
    response.json().await.unwrap()
}

#[tokio::test]
async fn routing_reads_that_cannot_pin_the_router_are_retryable_snapshot_unavailable() {
    let app = TestApp::new(|_| {}).await;
    let router = app.control.traffic_router();
    let reload = router.write().await;
    let wait = Duration::from_secs(10);
    let (rules, trace) = tokio::join!(
        app.get("/api/v1/rules").timeout(wait).send(),
        app.client
            .post(app.url("/api/v1/routing/trace"))
            .bearer_auth(SECRET)
            .json(&json!({"input":{"network":"tcp","dst_ip":"198.51.100.20","dst_port":443}}))
            .timeout(wait)
            .send(),
    );
    drop(reload);
    for response in [rules.unwrap(), trace.unwrap()] {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "1");
        error_response(
            response,
            StatusCode::SERVICE_UNAVAILABLE,
            "snapshot_unavailable",
        )
        .await;
    }
    app.shutdown().await;
}

#[tokio::test]
async fn diagnostic_json_requests_reject_duplicate_and_unsupported_media_types() {
    let app = TestApp::new(|_| {}).await;
    for path in ["/api/v1/probes", "/api/v1/routing/trace"] {
        for (content_types, status, code) in [
            (
                &["application/json", "application/json"][..],
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                &[][..],
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            ),
            (
                &["text/plain"][..],
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            ),
        ] {
            let mut request = app
                .client
                .post(app.url(path))
                .bearer_auth(SECRET)
                .body("{}");
            for content_type in content_types {
                request = request.header("content-type", *content_type);
            }
            error_response(request.send().await.unwrap(), status, code).await;
        }
    }
    app.shutdown().await;
}

struct RawResponse {
    status: u16,
    headers: String,
    body: Vec<u8>,
}

async fn read_raw_response(stream: &mut TcpStream) -> RawResponse {
    let mut bytes = Vec::new();
    timeout(IO_TIMEOUT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let boundary = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let headers = std::str::from_utf8(&bytes[..boundary])
        .unwrap()
        .to_ascii_lowercase();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    RawResponse {
        status,
        headers,
        body: bytes[boundary + 4..].to_vec(),
    }
}

async fn raw_request(app: &TestApp, target: &str, headers: &str, body: &[u8]) -> RawResponse {
    let mut stream = TcpStream::connect(app.addr).await.unwrap();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n{headers}\r\n",
        app.addr,
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    read_raw_response(&mut stream).await
}

fn raw_error(response: RawResponse, status: u16, code: &str) {
    assert_eq!(response.status, status);
    assert!(response.headers.contains("\r\ncache-control: no-store"));
    assert!(
        response
            .headers
            .contains("\r\nx-content-type-options: nosniff")
    );
    error_body(
        &serde_json::from_slice::<Value>(&response.body).unwrap(),
        code,
    );
}

#[tokio::test]
async fn authentication_precedes_capability_and_query_validation() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.allow_anonymous_loopback = true;
    })
    .await;
    // Discovery tells a client how to authenticate, so it answers without a credential.
    let discovery = app.client.get(app.url("/api")).send().await.unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    for (method, path) in [
        (Method::GET, "/api/v1/version"),
        (Method::GET, "/api/v1/capabilities"),
        (Method::GET, "/api/v1/config"),
        (Method::GET, "/api/v1/missing"),
        (Method::GET, "/api/v1/runtime?unknown=x"),
        (Method::GET, "/api/v1/runtime/mode?unknown=x"),
        (Method::POST, "/api/v1/runtime"),
    ] {
        error_response(
            app.client
                .request(method, app.url(path))
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    for authorization in [
        "Bearer wrong",
        "Basic native-test-only-secret",
        "Bearer",
        "Bearer ",
        "Bearer native-test-only-secret,other",
    ] {
        error_response(
            app.client
                .get(app.url("/api"))
                .header("authorization", authorization)
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    error_response(
        app.get("/api")
            .header("authorization", "Bearer wrong")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for query in [
        "token=native-test-only-secret",
        "%74oken=native-test-only-secret",
        "access_token=native-test-only-secret",
    ] {
        error_response(
            app.get(&format!("/api?{query}")).send().await.unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    response_json(app.get("/api").send().await.unwrap()).await;
    app.shutdown().await;
}

#[tokio::test]
async fn anonymous_loopback_does_not_forgive_credentials_or_cross_site_requests() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.secret.clear();
        config.experimental.native_api.allow_anonymous_loopback = true;
    })
    .await;
    response_json(app.client.get(app.url("/api")).send().await.unwrap()).await;
    for authorization in ["Bearer wrong", "Basic value", "Bearer"] {
        error_response(
            app.client
                .get(app.url("/api"))
                .header("authorization", authorization)
                .send()
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    error_response(
        app.client
            .get(app.url("/api?token=ignored"))
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    error_response(
        app.client
            .get(app.url("/api"))
            .header("sec-fetch-site", "cross-site")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn host_origin_and_proxy_authorities_are_not_inferred_from_forwarded_headers() {
    let app = TestApp::new(|config| {
        config.experimental.native_api.allowed_hosts =
            vec!["Panel.Example".into(), "panel.example:443".into()];
        config.experimental.native_api.allow_origins = vec!["https://panel.example".into()];
    })
    .await;
    for host in [
        format!("LOCALHOST:{}", app.addr.port()),
        format!("[::1]:{}", app.addr.port()),
        "PANEL.EXAMPLE".into(),
        "panel.example:80".into(),
        "panel.example:443".into(),
    ] {
        let response = app
            .get("/api")
            .header("host", host)
            .header("origin", "https://PANEL.EXAMPLE:443")
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://PANEL.EXAMPLE:443"
        );
        response_json(response).await;
    }
    response_json(
        app.get("/api")
            .header("origin", format!("http://localhost:{}", app.addr.port()))
            .send()
            .await
            .unwrap(),
    )
    .await;
    for host in [
        "attacker.example",
        "panel.example:81",
        "user@panel.example",
        "::1",
    ] {
        error_response(
            app.get("/api")
                .header("host", host)
                .header("x-forwarded-host", app.addr.to_string())
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    for origin in [
        "null",
        "http://panel.example",
        "https://panel.example:444",
        "https://panel.example/path",
        "https://user@panel.example",
        "https://attacker.example",
    ] {
        error_response(
            app.get("/api")
                .header("host", "panel.example")
                .header("origin", origin)
                .header("x-forwarded-proto", "https")
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    raw_error(
        raw_request(
            &app,
            "/api",
            &format!("Authorization: Bearer {SECRET}\r\nHost: attacker.example\r\n"),
            b"",
        )
        .await,
        403,
        "permission_denied",
    );
    raw_error(
        raw_request(
            &app,
            &app.url("/api"),
            &format!("Authorization: Bearer {SECRET}\r\n"),
            b"",
        )
        .await,
        400,
        "invalid_request",
    );
    app.shutdown().await;
}

#[tokio::test]
async fn wildcard_bind_accepts_its_own_ip_literal_authorities_but_no_names() {
    let app = TestApp::bound("0.0.0.0:0", |_| {}).await;
    let port = app.addr.port();
    for host in [
        format!("127.0.0.1:{port}"),
        format!("192.0.2.7:{port}"),
        format!("[2001:db8::7]:{port}"),
        format!("localhost:{port}"),
    ] {
        response_json(app.get("/api").header("host", &host).send().await.unwrap()).await;
        // The listener's own plain-HTTP origin follows its Host; the UI it hosts posts with it.
        let response = app
            .get("/api")
            .header("host", &host)
            .header("origin", format!("http://{host}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            format!("http://{host}")
        );
        response_json(response).await;
    }
    for host in [
        format!("192.0.2.7:{}", port.wrapping_add(1)),
        "192.0.2.7".to_string(),
        format!("panel.example:{port}"),
    ] {
        error_response(
            app.get("/api").header("host", &host).send().await.unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    // Only plain HTTP is the listener's own scheme; a TLS proxy still declares its origin.
    error_response(
        app.get("/api")
            .header("host", format!("192.0.2.7:{port}"))
            .header("origin", format!("https://192.0.2.7:{port}"))
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn preflight_uses_route_methods_but_never_grants_authorization() {
    let app = TestApp::new(|_| {}).await;
    let origin = format!("http://localhost:{}", app.addr.port());
    let preflight = |path: &str, method: &str| {
        app.client
            .request(Method::OPTIONS, app.url(path))
            .header("origin", &origin)
            .header("access-control-request-method", method)
            .header(
                "access-control-request-headers",
                "authorization, Content-Type",
            )
    };
    for (path, method) in [
        ("/api", "GET"),
        ("/api", "HEAD"),
        ("/api/v1/connections", "DELETE"),
        ("/api/v1/providers/raw%2Fid/refresh", "POST"),
        ("/api/v1/dns/cache/flush", "POST"),
        ("/api/v1/runtime/mode", "PUT"),
    ] {
        let response = preflight(path, method).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        api_headers(&response);
        assert_eq!(response.headers()["access-control-allow-origin"], origin);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-credentials")
        );
        assert!(
            response.headers()["access-control-allow-methods"]
                .to_str()
                .unwrap()
                .split(", ")
                .any(|value| value == method)
        );
    }
    // A permitted preflight still grants nothing: the protected request after it needs its bearer.
    error_response(
        app.client
            .get(app.url("/api/v1/version"))
            .header("origin", &origin)
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for (path, method) in [
        ("/api", "PUT"),
        ("/api/v1/missing", "GET"),
        ("/api/v1/dns/cache/flush", "DELETE"),
        ("/api/v1/dns/cache/%66lush", "POST"),
    ] {
        error_response(
            preflight(path, method).send().await.unwrap(),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }
    error_response(
        preflight("/api", "GET")
            .header("access-control-request-headers", "x-not-allowed")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    error_response(
        preflight("/api", "GET")
            .header("origin", "https://attacker.example")
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    app.shutdown().await;
}

#[tokio::test]
async fn disabled_actions_unknown_resources_and_methods_are_distinct_json_errors() {
    let app = TestApp::new(|_| {}).await;
    for (method, path, code) in [
        (Method::GET, "/api/v1/config", "capability_not_supported"),
        (
            Method::POST,
            "/api/v1/config/validate",
            "capability_not_supported",
        ),
        (
            Method::GET,
            "/api/v1/runtime/mode?unknown=x",
            "capability_not_supported",
        ),
        (
            Method::PUT,
            "/api/v1/runtime/mode",
            "capability_not_supported",
        ),
        (
            Method::DELETE,
            "/api/v1/groups/group/selection",
            "capability_not_supported",
        ),
        (
            Method::GET,
            "/api/v1/no-such-resource",
            "resource_not_found",
        ),
        (Method::POST, "/api/v1/runtime", "resource_not_found"),
        (
            Method::GET,
            "/api/v1/connections/live-id",
            "resource_not_found",
        ),
        (Method::PUT, "/api/v1/config", "resource_not_found"),
    ] {
        error_response(
            app.client
                .request(method, app.url(path))
                .bearer_auth(SECRET)
                .send()
                .await
                .unwrap(),
            StatusCode::NOT_FOUND,
            code,
        )
        .await;
    }
    for (path, status) in [
        ("/api", StatusCode::OK),
        ("/api/v1/config", StatusCode::NOT_FOUND),
        ("/api/v1/runtime/mode", StatusCode::NOT_FOUND),
        ("/api/v1/missing", StatusCode::NOT_FOUND),
    ] {
        let get = app.get(path).send().await.unwrap();
        assert_eq!(get.status(), status);
        let content_type = get.headers()["content-type"].clone();
        let length = get.bytes().await.unwrap().len().to_string();
        let response = app
            .client
            .head(app.url(path))
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        api_headers(&response);
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(response.headers()["content-length"], length);
        assert!(response.bytes().await.unwrap().is_empty());
    }
    let ui = app.client.get(app.url("/ui/")).send().await.unwrap();
    assert_eq!(ui.status(), StatusCode::NOT_FOUND);
    assert!(
        !ui.headers()
            .get("content-type")
            .is_some_and(|value| value.to_str().unwrap().starts_with("text/html"))
    );
    app.shutdown().await;
}

#[tokio::test]
async fn encoded_resource_segments_are_not_decoded_into_other_ids() {
    let app = TestApp::new(|config| {
        config.groups.push(honk_config::node::Group {
            name: "route-identity".into(),
            ..Default::default()
        });
    })
    .await;
    let groups = response_json(app.get("/api/v1/groups").send().await.unwrap()).await;
    let group_id = groups[0]["id"].as_str().unwrap();
    response_json(
        app.get(&format!("/api/v1/groups/{group_id}"))
            .send()
            .await
            .unwrap(),
    )
    .await;
    let encoded_id = format!("%{:02X}{}", group_id.as_bytes()[0], &group_id[1..]);
    for path in [
        format!("/api/v1/groups/{encoded_id}"),
        "/api/v1/groups/raw%2Fid".into(),
        "/api/v1/groups/%FF".into(),
        "/api/v1/%76ersion".into(),
    ] {
        error_response(
            app.get(&path).send().await.unwrap(),
            StatusCode::NOT_FOUND,
            "resource_not_found",
        )
        .await;
    }
    app.shutdown().await;
}

#[tokio::test]
async fn query_parameters_reject_ambiguity_and_out_of_range_values() {
    let app = TestApp::new(|_| {}).await;
    for query in [
        "limit=0",
        "limit=1001",
        "limit=-1",
        "limit=abc",
        "type=icmp",
        "src=192.0.2.1:80",
        "src=host.example",
        "detail=verbose",
        "unknown=1",
        "limit=1&limit=2",
        "type=tcp&type=udp",
        "src=192.0.2.1&src=192.0.2.2",
        "detail=summary&detail=full",
    ] {
        error_response(
            app.get(&format!("/api/v1/connections?{query}"))
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    for path in [
        "/api?unknown=1",
        "/api/v1/runtime?detail=full&detail=summary",
        "/api/v1/runtime?detail=verbose",
    ] {
        error_response(
            app.get(path).send().await.unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    app.shutdown().await;
}

fn entry(id: &str, network: &str, source: &str, observed: Instant) -> ConnectionEntry {
    ConnectionEntry {
        id: id.into(),
        source: source.into(),
        destination: "198.51.100.10:443".into(),
        proxy: "current-leaf-must-not-be-used".into(),
        routed_outbound: Some("routed-group".into()),
        native_flow_id: None,
        rule: "private-legacy-rule".into(),
        rule_payload: "private-legacy-payload".into(),
        chains: vec!["private-legacy-chain".into()],
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: observed,
        domain: None,
        network: network.into(),
        process: None,
        process_path: Some("/private/process/path".into()),
    }
}

#[tokio::test]
async fn authenticated_request_limits_cover_declared_and_chunked_bodies() {
    let app = TestApp::new(|_| {}).await;
    error_response(
        app.get(&format!("/api?padding={}", "x".repeat(4096)))
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    error_response(
        app.get("/api")
            .header("x-padding", "x".repeat(17000))
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    error_response(
        app.get("/api").body("x").send().await.unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    for (size, status, code) in [
        (65536, StatusCode::NOT_FOUND, "capability_not_supported"),
        (65537, StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
    ] {
        error_response(
            app.client
                .post(app.url("/api/v1/config/validate"))
                .bearer_auth(SECRET)
                .body(vec![b'x'; size])
                .send()
                .await
                .unwrap(),
            status,
            code,
        )
        .await;
    }
    raw_error(
        raw_request(
            &app,
            "/api",
            &format!("Authorization: Bearer {SECRET}\r\nContent-Length: 65537\r\n"),
            b"",
        )
        .await,
        413,
        "request_too_large",
    );
    raw_error(
        raw_request(
            &app,
            "/api",
            &format!("Authorization: Bearer {SECRET}\r\nTransfer-Encoding: chunked\r\n"),
            b"1\r\nx\r\n0\r\n\r\n",
        )
        .await,
        400,
        "invalid_request",
    );
    let body = format!("10001\r\n{}\r\n0\r\n\r\n", "x".repeat(65537));
    raw_error(
        raw_request(
            &app,
            "/api",
            &format!("Authorization: Bearer {SECRET}\r\nTransfer-Encoding: chunked\r\n"),
            body.as_bytes(),
        )
        .await,
        413,
        "request_too_large",
    );
    let trailers = format!("0\r\nX-Padding: {}\r\n\r\n", "x".repeat(8192));
    raw_error(raw_request(&app, "/api", &format!("Authorization: Bearer {SECRET}\r\nTransfer-Encoding: chunked\r\nTrailer: X-Padding\r\nX-Initial: {}\r\n", "x".repeat(8192)), trailers.as_bytes()).await, 413, "request_too_large");
    response_json(app.get("/api").send().await.unwrap()).await;
    app.shutdown().await;
}

#[tokio::test]
async fn shutdown_reclaims_an_authenticated_incomplete_body_and_state() {
    let app = TestApp::new(|_| {}).await;
    let mut stream = TcpStream::connect(app.addr).await.unwrap();
    stream.write_all(format!("GET /api HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n", app.addr).as_bytes()).await.unwrap();
    let mut continued = [0; 25];
    timeout(IO_TIMEOUT, stream.read_exact(&mut continued))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&continued, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"x").await.unwrap();
    let weak = app.state.clone();
    app.shutdown().await;
    let mut remaining = Vec::new();
    timeout(IO_TIMEOUT, stream.read_to_end(&mut remaining))
        .await
        .unwrap()
        .unwrap();
    assert!(
        remaining.is_empty(),
        "incomplete request unexpectedly completed"
    );
    assert!(weak.upgrade().is_none());
    tokio::task::yield_now().await;
}

#[path = "native_api_test/observations.rs"]
mod observations;
#[path = "native_api_test/ui.rs"]
mod ui;

#[cfg(feature = "clash-api")]
#[tokio::test]
async fn native_and_clash_tokens_do_not_cross_authorize() {
    use honk_core::clash_api::{self, ClashState};
    use honk_core::mode::ModeState;

    let mut app = TestApp::new(|config| {
        config.experimental.clash_api.secret = "clash-test-only-secret".into();
    })
    .await;
    let mode = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "direct")));
    app.control.set_mode_state(mode.clone());
    app.control.start_datapath_flags_coordinator().unwrap();
    let state = Arc::new(ClashState {
        config: app.control.config_handle(),
        diagnostics: app.control.diagnostics_handle(),
        stats: app.control.stats_handle(),
        alive_set: app.control.alive_set(),
        group_manager: app.control.group_manager(),
        cache_db: None,
        connection_tracker: app.control.connection_tracker(),
        proxy_registry: app.control.proxy_registry(),
        runtime_registry: app.control.runtime_registry(),
        mode_state: mode,
        datapath_flags: app.control.datapath_flags_handle().unwrap(),
        control: Some(app.control.control_client()),
        ui_download: app.control.ui_download_handle(),
        secret: "clash-test-only-secret".into(),
        connection_pool: app.control.connection_pool(),
        external_ui: String::new(),
        router: app.control.traffic_router(),
        log_handle: clash_api::logs::layer::<tracing_subscriber::Registry>().1,
        dns_service: app.control.dns_service(),
        stream_samplers: Arc::new(clash_api::StreamSamplers::new()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let clash_url = format!("http://{}/version", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, clash_api::router(state))
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    assert_eq!(
        app.client
            .get(&clash_url)
            .bearer_auth("clash-test-only-secret")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.client
            .get(&clash_url)
            .bearer_auth(SECRET)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    error_response(
        app.client
            .get(app.url("/api"))
            .bearer_auth("clash-test-only-secret")
            .send()
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    response_json(app.get("/api").send().await.unwrap()).await;
    stop.send(()).unwrap();
    timeout(IO_TIMEOUT, server).await.unwrap().unwrap();
    app.shutdown().await;
}

#[path = "native_api_test/password_auth.rs"]
mod password_auth;
