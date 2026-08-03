//! On-demand URLTest latency measurement (sing-box `urltest` semantics).
//!
//! Dials a liveness URL through a proxy node and times the exchange up to
//! the response headers: HTTP/1.1 `HEAD /` or a real HTTP/2 request when the
//! server negotiates h2 via ALPN (dispatched per connection — the probe
//! offers `h2,http/1.1` and speaks whichever the server picks, Go-client
//! style). Successful measurements feed the node's latency history in
//! [`AliveDialerSet`]; failed ones clear it (sing-box "delete history"
//! semantics), so a failed node immediately sorts last in URLTest selection.
//!
//! Used by the clash API delay endpoints; the periodic health check loop in
//! `alive` is unaffected by these ad-hoc measurements.

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use crate::proxy::{ProxyHandler, ProxyRegistry};
use anyhow::{Context, anyhow};
use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default liveness URL (sing-box / clash convention).
pub const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";

/// Default per-node measurement timeout.
pub const DEFAULT_URLTEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Optional resolver for check-URL hosts: `(host, port) → addr`.
/// honk-core installs the DNS-forwarder-backed resolver so delay
/// measurements share the internal DNS stack; unset means the raw system
/// resolver (tests, tools).
pub type UrltestResolver = std::sync::Arc<
    dyn Fn(
            String,
            u16,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<SocketAddr>> + Send>>
        + Send
        + Sync,
>;

static URLTEST_RESOLVER: std::sync::LazyLock<parking_lot::RwLock<Option<UrltestResolver>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(None));

/// Install the resolver used for subsequent [`urltest_node`] measurements.
pub fn set_urltest_resolver(hook: UrltestResolver) {
    *URLTEST_RESOLVER.write() = Some(hook);
}

/// direct urltest target override, installed by honk-core alongside
/// `AliveDialerSet::set_direct_check_addr`. Falls back to the bootstrap
/// resolver address, then to [`crate::alive::DEFAULT_DIRECT_CHECK_ADDR`].
/// Kept separate from the bootstrap global so measurements never race
/// bootstrap resolver users (ECH discovery, node dials).
static URLTEST_DIRECT_TARGET: std::sync::LazyLock<parking_lot::RwLock<Option<SocketAddr>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(None));

/// Install the direct urltest target (`host:port` of the direct probe).
pub fn set_urltest_direct_target(target: SocketAddr) {
    *URLTEST_DIRECT_TARGET.write() = Some(target);
}

fn direct_target() -> SocketAddr {
    URLTEST_DIRECT_TARGET
        .read()
        .or_else(crate::bootstrap::global_server)
        .unwrap_or_else(|| crate::alive::DEFAULT_DIRECT_CHECK_ADDR.parse().unwrap())
}

/// Maximum concurrent node measurements inside [`urltest_group`]
/// (matches sing-box's health check concurrency).
pub const URLTEST_MAX_CONCURRENT: usize = 10;

/// Measure the round-trip latency to `url` through `node` via `handler`.
///
/// Dials the URL's host on port 443 (https) or 80 (http) through the proxy
/// handler. For https URLs the stream is then wrapped in a real TLS
/// handshake (server_name = host, standard webpki verification) and the
/// probe issues a HEAD request over HTTP/1.1 or HTTP/2, whichever ALPN
/// negotiated; the measurement runs from dial start until the response
/// headers are fully received. A TLS handshake failure counts as a
/// measurement failure.
///
/// An empty `url` — or one starting with `http://` — falls back to
/// [`DEFAULT_URLTEST_URL`]. A zero `timeout` falls back to
/// [`DEFAULT_URLTEST_TIMEOUT`].
pub async fn urltest_node(
    node: &Node,
    handler: &dyn ProxyHandler,
    url: &str,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let url = normalize_url(url);
    let timeout = if timeout.is_zero() {
        DEFAULT_URLTEST_TIMEOUT
    } else {
        timeout
    };
    // direct: the check URL is chosen for proxied egress and is commonly
    // unreachable over a direct connection (e.g. google-analytics from CN),
    // so measure a raw connect against the bootstrap resolver instead —
    // the same target the periodic direct probe uses. A failed exchange
    // here previously also cleared direct's latency history (sing-box
    // delete-on-failure), leaving dashboards with no direct delay at all.
    if node.protocol == honk_config::types::NodeProtocol::Direct {
        let target = direct_target();
        let start = Instant::now();
        tokio::time::timeout(
            timeout,
            crate::util::connect_marked_addr(
                target,
                Some(honk_ebpf_common::DAE_BYPASS_MARK),
                timeout,
            ),
        )
        .await
        .context("direct urltest timed out")?
        .context("direct urltest connect failed")?;
        return Ok(start.elapsed());
    }
    let (host, port, is_https) = parse_url_host_port(url)?;

    let addr = {
        let hook = URLTEST_RESOLVER.read().clone();
        match hook {
            Some(hook) => hook(host.clone(), port)
                .await
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
            None => tokio::net::lookup_host(format!("{host}:{port}"))
                .await
                .with_context(|| format!("failed to resolve '{host}:{port}'"))?
                .next()
                .ok_or_else(|| anyhow!("no address resolved for '{host}:{port}'"))?,
        }
    };

    measure_head_exchange(node, handler, &host, is_https, addr, timeout).await
}

/// [`urltest_node`] with a caller-chosen destination address (e.g. an
/// explicit v4/v6 target) — TLS SNI/Host still come from `url`.
pub async fn urltest_node_addr(
    node: &Node,
    handler: &dyn ProxyHandler,
    url: &str,
    addr: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let url = normalize_url(url);
    let (host, _, is_https) = parse_url_host_port(url)?;
    measure_head_exchange(node, handler, &host, is_https, addr, timeout).await
}

/// Dial `addr` through the node and time the full exchange up to the first
/// response bytes (TLS handshake + HEAD for https, plain HEAD for http).
async fn measure_head_exchange(
    node: &Node,
    handler: &dyn ProxyHandler,
    host: &str,
    is_https: bool,
    addr: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let fut = async {
        let start = Instant::now();
        let proxy = handler.dial(node, addr, Some(host), timeout).await?;
        tracing::debug!(node = %node.name, %addr, "urltest: dial established");
        let stream = proxy.stream;

        if is_https {
            let connector = https_connector()?;
            let tls = connector
                .connect(host, stream)
                .await
                .context("TLS handshake failed")?;
            tracing::debug!(
                node = %node.name,
                alpn = ?tls.ssl().selected_alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
                "urltest: TLS established"
            );
            // The probe offers `h2,http/1.1`; speak whatever was negotiated.
            match tls.ssl().selected_alpn_protocol() {
                Some(b"h2") => exchange_head_h2(tls, host).await?,
                _ => {
                    let mut tls = tls;
                    exchange_head(&mut tls, host).await?;
                }
            }
        } else {
            let mut stream = stream;
            exchange_head(&mut stream, host).await?;
        }
        tracing::debug!(node = %node.name, elapsed_ms = start.elapsed().as_millis(), "urltest: exchange complete");
        Ok(start.elapsed())
    };

    match tokio::time::timeout(timeout, fut).await {
        Ok(res) => res,
        Err(_) => Err(anyhow!("urltest timed out after {:?}", timeout)),
    }
}

/// BoringSSL connector with webpki root verification for urltest.
/// Built once and reused across measurements (it never changes at runtime).
/// Offers `h2,http/1.1`; the exchange dispatches on the negotiated ALPN.
fn https_connector() -> anyhow::Result<crate::tls::TlsConnector> {
    static CONNECTOR: std::sync::OnceLock<anyhow::Result<crate::tls::TlsConnector>> =
        std::sync::OnceLock::new();
    let connector = CONNECTOR.get_or_init(|| crate::tls::build_http_probe_connector(false));
    match connector {
        Ok(c) => Ok(c.clone()),
        Err(e) => Err(anyhow!("failed to build urltest TLS connector: {e:#}")),
    }
}

/// HTTP/2 variant of [`exchange_head`]: one HEAD request over a fresh H2
/// session (same layer as the DoH transport), resolved when the response
/// HEADERS arrive — the same measurement point as the HTTP/1.1 path.
async fn exchange_head_h2<S>(stream: S, host: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = h2::client::handshake(stream)
        .await
        .map_err(|e| anyhow!("HTTP/2 handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("HEAD")
        .uri(format!("https://{host}/"))
        .header("user-agent", "honk-urltest/1.0")
        .body(())
        .map_err(|e| anyhow!("h2 request build: {e}"))?;
    let (response_fut, _send_stream) = sender
        .send_request(req, true)
        .map_err(|e| anyhow!("h2 send_request: {e}"))?;
    let response = response_fut
        .await
        .map_err(|e| anyhow!("h2 response: {e}"))?;

    let code = response.status().as_u16();
    if !(200..500).contains(&code) {
        return Err(anyhow!("bad status code: {}", code));
    }
    Ok(())
}

/// Send a minimal HTTP/1.1 HEAD request and wait for the response
/// headers, validating the status line (200–499 counts as reachable).
async fn exchange_head<S>(stream: &mut S, host: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: honk-urltest/1.0\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 16 * 1024 {
            break;
        }
    }
    validate_status(&buf)
}

/// Measure every member of a group concurrently (at most
/// [`URLTEST_MAX_CONCURRENT`] at a time) and fold the results into the
/// alive set: successes record the measured TCP latency, failures clear
/// the node's latency history (sing-box deletes history on failure).
///
/// Returns one `(node_name, result)` entry per member, in member order.
pub async fn urltest_group(
    members: &[Node],
    registry: &Arc<ProxyRegistry>,
    alive_set: &Arc<AliveDialerSet>,
    url: &str,
    timeout: Duration,
) -> Vec<(String, anyhow::Result<Duration>)> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(URLTEST_MAX_CONCURRENT));
    let url = normalize_url(url).to_string();
    let mut join_set = tokio::task::JoinSet::new();

    for node in members {
        let node = node.clone();
        let registry = registry.clone();
        let alive_set = alive_set.clone();
        let url = url.clone();
        let permit = semaphore.clone();
        join_set.spawn(async move {
            let _permit = permit.acquire_owned().await;
            let result = match registry.find(node.protocol) {
                Some(handler) => urltest_node(&node, handler, &url, timeout).await,
                None => Err(anyhow!("no handler for protocol {:?}", node.protocol)),
            };
            match &result {
                Ok(latency) => {
                    alive_set.record_probe_latency(
                        &node.name,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                        *latency,
                    );
                }
                Err(_) => {
                    alive_set.record_dial_failure(&node.name, ProbeDomain::Tcp, IpVersion::V4);
                }
            }
            (node.name.clone(), result)
        });
    }

    let mut results = Vec::with_capacity(members.len());
    while let Some(res) = join_set.join_next().await {
        if let Ok(pair) = res {
            results.push(pair);
        }
    }
    let order: std::collections::HashMap<&str, usize> = members
        .iter()
        .enumerate()
        .map(|(i, n)| (n.name.as_str(), i))
        .collect();
    results.sort_by_key(|(name, _)| order.get(name.as_str()).copied().unwrap_or(usize::MAX));
    results
}

/// Empty or plain-HTTP URLs fall back to the default HTTPS liveness URL.
fn normalize_url(url: &str) -> &str {
    let url = url.trim();
    if url.is_empty() || url.starts_with("http://") {
        DEFAULT_URLTEST_URL
    } else {
        url
    }
}

/// Split a URL into (host, port, is_https): scheme default 443/80,
/// explicit `:port` suffix wins. A schemeless URL is treated as https.
fn parse_url_host_port(url: &str) -> anyhow::Result<(String, u16, bool)> {
    let (default_port, rest, is_https) = if let Some(r) = url.strip_prefix("https://") {
        (443u16, r, true)
    } else if let Some(r) = url.strip_prefix("http://") {
        (80u16, r, false)
    } else {
        (443u16, url, true)
    };
    let authority = rest.split('/').next().unwrap_or(rest).trim();
    if let Some((host, port)) = authority.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        if host.is_empty() {
            return Err(anyhow!("empty host in URL '{}'", url));
        }
        return Ok((host.to_string(), port, is_https));
    }
    if authority.is_empty() {
        return Err(anyhow!("empty host in URL '{}'", url));
    }
    Ok((authority.to_string(), default_port, is_https))
}

/// Validate the HTTP response status line; 200–499 count as reachable
/// (same convention as the periodic HTTP health check).
fn validate_status(buf: &[u8]) -> anyhow::Result<()> {
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let status_line = String::from_utf8_lossy(&buf[..line_end]);
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(anyhow!("malformed HTTP response: '{}'", status_line.trim()));
    }
    let code: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code in '{}'", status_line.trim()))?
        .parse()
        .context("invalid status code")?;
    if !(200..500).contains(&code) {
        return Err(anyhow!("bad status code: {}", code));
    }
    Ok(())
}

#[cfg(test)]
mod resolver_hook_tests {
    use super::*;

    /// The installed hook is consulted before the system resolver.
    #[tokio::test]
    async fn hook_supplies_urltest_addresses() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called2 = called.clone();
        set_urltest_resolver(std::sync::Arc::new(move |host, port| {
            let called2 = called2.clone();
            Box::pin(async move {
                called2.store(true, std::sync::atomic::Ordering::Relaxed);
                assert_eq!(host, "example.invalid");
                assert_eq!(port, 443);
                vec!["127.0.0.1:443".parse().unwrap()]
            })
        }));
        let node = Node::default();
        // The dial itself fails (nothing on 127.0.0.1:443) but the hook
        // must have been consulted first.
        let handler = crate::proxy::direct::DirectHandler::new();
        let _ = urltest_node(
            &node,
            &handler,
            "https://example.invalid/",
            Duration::from_millis(50),
        )
        .await;
        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
        *URLTEST_RESOLVER.write() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyStream;
    use honk_config::types::NodeProtocol;
    use std::net::SocketAddr;

    /// Mock handler: dials the requested target with a plain TcpStream
    /// (no proxy protocol, no SO_MARK). Nodes named "bad" always fail.
    struct MockHandler;

    #[async_trait::async_trait]
    impl ProxyHandler for MockHandler {
        fn protocol(&self) -> NodeProtocol {
            NodeProtocol::Socks5
        }

        async fn dial(
            &self,
            node: &Node,
            target: SocketAddr,
            target_domain: Option<&str>,
            _connect_timeout: Duration,
        ) -> anyhow::Result<ProxyStream> {
            if node.name == "bad" {
                return Err(anyhow!("simulated dial failure"));
            }
            let stream = tokio::net::TcpStream::connect(target).await?;
            Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(|s| s.to_string()),
            })
        }

        async fn test_connectivity(&self, _node: &Node) -> bool {
            true
        }
    }

    fn make_node(name: &str) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: NodeProtocol::Socks5,
            ..Default::default()
        }
    }

    /// Spawn a minimal HTTP server answering every request with 204.
    async fn spawn_mock_http_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        addr
    }

    /// Spawn a minimal HTTP/2 server answering every request with 204.
    async fn spawn_h2_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(sock).await.unwrap();
                    while let Some(result) = conn.accept().await {
                        let (_request, mut respond) = result.unwrap();
                        let response = http::Response::builder().status(204).body(()).unwrap();
                        respond.send_response(response, true).unwrap();
                    }
                });
            }
        });
        addr
    }

    /// The h2 probe path completes against an h2-only server — this is the
    /// gstatic case that used to fail with "malformed HTTP response".
    #[tokio::test]
    async fn test_exchange_head_h2() {
        let addr = spawn_h2_server().await;
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_head_h2(stream, "localhost")
            .await
            .expect("h2 HEAD exchange must succeed");

        // A non-2xx..4xx status is a measurement failure.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut conn = h2::server::handshake(sock).await.unwrap();
            let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(500).body(()).unwrap();
            respond.send_response(response, true).unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(exchange_head_h2(stream, "localhost").await.is_err());
    }

    #[test]
    fn test_normalize_and_parse_url() {
        assert_eq!(normalize_url(""), DEFAULT_URLTEST_URL);
        assert_eq!(
            normalize_url("http://www.gstatic.com/generate_204"),
            DEFAULT_URLTEST_URL
        );
        assert_eq!(
            normalize_url("https://example.com/x"),
            "https://example.com/x"
        );

        assert_eq!(
            parse_url_host_port(DEFAULT_URLTEST_URL).unwrap(),
            ("www.gstatic.com".to_string(), 443, true)
        );
        assert_eq!(
            parse_url_host_port("https://127.0.0.1:8080/").unwrap(),
            ("127.0.0.1".to_string(), 8080, true)
        );
        // Schemeless URLs are treated as https on port 443.
        assert_eq!(
            parse_url_host_port("example.com/204").unwrap(),
            ("example.com".to_string(), 443, true)
        );
        assert!(parse_url_host_port("https://").is_err());
    }

    /// The HEAD exchange itself is protocol-agnostic; exercise it over a
    /// plain stream against a local HTTP server.
    #[tokio::test]
    async fn test_exchange_head_plain_http() {
        let addr = spawn_mock_http_server().await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        exchange_head(&mut stream, "localhost")
            .await
            .expect("HEAD exchange against local HTTP server should succeed");
    }

    /// Regression test for the plaintext-over-443 bug: an https URL must
    /// run a real TLS handshake, so a plaintext HTTP server fails the
    /// measurement instead of answering a cleartext HEAD.
    #[tokio::test]
    async fn test_urltest_node_https_requires_tls() {
        let addr = spawn_mock_http_server().await;
        let node = make_node("good");
        let handler = MockHandler;
        let url = format!("https://{}:{}/", addr.ip(), addr.port());

        let result = urltest_node(&node, &handler, &url, Duration::from_secs(5)).await;
        assert!(
            result.is_err(),
            "https measurement against a plaintext server must fail"
        );
    }

    #[tokio::test]
    async fn test_urltest_node_failure() {
        // Nothing listens on 127.0.0.1:1 → dial fails.
        let node = make_node("good");
        let handler = MockHandler;
        let result = urltest_node(
            &node,
            &handler,
            "https://127.0.0.1:1/",
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());

        // A node named "bad" fails inside the handler.
        let bad = make_node("bad");
        let result = urltest_node(
            &bad,
            &handler,
            "https://127.0.0.1:1/",
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_urltest_group_clears_latency_on_failure() {
        // Plaintext HTTP server: every https measurement fails the TLS
        // handshake, so the group run must clear latency history for both
        // the dial-failing and the handshake-failing member.
        let addr = spawn_mock_http_server().await;
        let url = format!("https://{}:{}/", addr.ip(), addr.port());

        let mut registry = ProxyRegistry::new();
        registry.register(Box::new(MockHandler));
        let registry = Arc::new(registry);
        let alive_set = Arc::new(AliveDialerSet::new());

        let members = vec![make_node("good"), make_node("bad")];
        for m in &members {
            alive_set.record_probe_latency(
                &m.name,
                ProbeDomain::Tcp,
                IpVersion::V4,
                Duration::from_millis(999),
            );
        }

        let results = urltest_group(
            &members,
            &registry,
            &alive_set,
            &url,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(results.len(), 2);
        // Member order preserved.
        assert_eq!(results[0].0, "good");
        assert_eq!(results[1].0, "bad");
        assert!(results[0].1.is_err());
        assert!(results[1].1.is_err());

        // Failure → history replaced by the synthetic penalty sample, so the
        // stale 999ms no longer ranks the node.
        for m in &members {
            assert_eq!(
                alive_set.get_last_latency(&m.name, ProbeDomain::Tcp, IpVersion::V4),
                Some(Duration::from_secs(10))
            );
        }
    }
}

#[cfg(test)]
mod direct_urltest_tests {
    use super::*;

    /// direct is measured against the direct target (a raw connect to the
    /// bootstrap resolver address), never against the proxy check URL
    /// through the node. Uses the dedicated injection point so the test
    /// never races bootstrap resolver users (ECH discovery tests).
    #[tokio::test]
    async fn direct_urltest_uses_direct_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        set_urltest_direct_target(addr);
        let node = Node {
            name: honk_config::Config::BUILTIN_DIRECT_NODE.to_string(),
            protocol: honk_config::types::NodeProtocol::Direct,
            ..Default::default()
        };
        let handler = crate::proxy::direct::DirectHandler::new();
        let latency = urltest_node(
            &node,
            &handler,
            "http://unreachable.invalid",
            Duration::from_secs(2),
        )
        .await
        .expect("direct urltest measures the direct-target connect");
        assert!(latency < Duration::from_secs(2));
        *URLTEST_DIRECT_TARGET.write() = None;
    }
}
