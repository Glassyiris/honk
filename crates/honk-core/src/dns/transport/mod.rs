//! Encrypted and pooled DNS transports (DoT / DoH / DoQ / DoH3).
//!
//! Design goals (performance-first):
//! - Never TLS/QUIC-handshake per query when a live session exists.
//! - DoT: small idle pool of TLS streams (sequential req/resp per stream).
//! - DoH: long-lived HTTP/2 session (`h2`) multiplexing concurrent queries.
//! - DoQ: one QUIC connection, one bi-stream per query (RFC 9250).
//! - DoH3: one QUIC+H3 session, POST `application/dns-message`.
//! - TCP plain: idle stream pool (same shape as DoT without TLS).
//!
//! All direct dials use `DAE_BYPASS_MARK` so eBPF does not re-intercept
//! control-plane DNS. Hostnames resolve via `honk_outbound::bootstrap`.

mod doh;
mod doh3;
mod doq;
mod dot;
mod framing;
mod lifecycle;
mod owned_task;
mod tcp_pool;

#[cfg(test)]
mod idle_pool_tests;
#[cfg(test)]
mod tests_proto;
#[cfg(test)]
mod upstream_lifecycle_tests;

pub use doh::DohClient;
pub use doh3::Doh3Client;
pub use doq::DoqClient;
pub use dot::DotPool;
pub use framing::{exchange_length_prefixed, force_dns_id_zero, restore_dns_id};
pub(crate) use lifecycle::LifecycleSlot;
pub use tcp_pool::TcpPool;

use std::sync::Arc;
use std::time::Duration;

use super::endpoint::DnsEndpoint;
use crate::proxy::ProxyRegistry;
use honk_config::node::Node;

/// Shared dial context for transports that may go direct or via a proxy node.
#[derive(Clone)]
pub struct DialContext {
    pub endpoint: DnsEndpoint,
    pub query_timeout: Duration,
    pub dial_timeout: Duration,
    /// When set, TCP/TLS is established through this proxy to `endpoint`.
    pub proxy: Option<ProxyDial>,
}

#[derive(Clone)]
pub struct ProxyDial {
    pub registry: Arc<ProxyRegistry>,
    pub node: Node,
}

impl DialContext {
    /// Dial a plain TCP stream to the upstream (marked, or via proxy).
    ///
    /// Tries every bootstrap-resolved address (IPv4 preferred) so a single
    /// unreachable AAAA does not fail the whole DoH/DoT dial.
    pub async fn dial_tcp(&self) -> anyhow::Result<tokio::net::TcpStream> {
        if self.proxy.is_some() {
            // Proxy handlers return a boxed stream already connected to the
            // target; for TLS we need a TcpStream-shaped base only on the
            // direct path. Proxy+TLS is handled separately via boxed stream.
            anyhow::bail!("dial_tcp called with proxy set; use dial_tcp_boxed")
        }
        let addrs = self.endpoint.resolve_addrs().await?;
        let mut last_err = None;
        for addr in addrs {
            // Per-address budget: keep overall cold start reasonable when the
            // first (often broken v6) candidate hangs.
            let per = self.dial_timeout.min(Duration::from_secs(3));
            match tokio::time::timeout(
                per,
                honk_outbound::util::connect_marked_addr(
                    addr,
                    Some(honk_ebpf_common::DAE_BYPASS_MARK),
                    per,
                ),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    tracing::debug!("TCP dial to {addr} failed: {e}");
                    last_err = Some(anyhow::anyhow!("TCP dial to {addr}: {e}"));
                }
                Err(_) => {
                    tracing::debug!("TCP dial to {addr} timed out after {per:?}");
                    last_err = Some(anyhow::anyhow!("TCP dial to {addr} timed out"));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses to dial")))
    }

    /// Dial through the optional proxy, returning a boxed duplex stream to the
    /// upstream DNS server address.
    pub async fn dial_tcp_boxed(&self) -> anyhow::Result<Box<dyn crate::proxy::AsyncReadWrite>> {
        if let Some(proxy) = &self.proxy {
            let addr = self.endpoint.resolve_addr().await?;
            let ps = proxy
                .registry
                .dial(&proxy.node, addr, None, self.dial_timeout)
                .await
                .map_err(|e| anyhow::anyhow!("proxy dial for DNS upstream: {e}"))?;
            return Ok(ps.stream);
        }
        let stream = self.dial_tcp().await?;
        Ok(Box::new(stream))
    }
}

/// Max idle streams kept per DoT / plain-TCP pool.
const MAX_IDLE_STREAMS: usize = 4;

enum IdlePoolState {
    Open,
    Closed,
}

/// Uniform retry-once wrapper for all transports: on failure, run `reset`
/// (drop the cached session/connection) and retry the exchange once.
async fn exchange_with_retry<Once, Fut, Reset, ResetFut>(
    label: &'static str,
    once: Once,
    reset: Reset,
) -> anyhow::Result<Vec<u8>>
where
    Once: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Vec<u8>>>,
    Reset: FnOnce() -> ResetFut,
    ResetFut: std::future::Future<Output = ()>,
{
    match once().await {
        Ok(resp) => Ok(resp),
        Err(first) => {
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::TransportReset);
            tracing::debug!(
                transport = label,
                error_kind = "exchange_failed",
                "DNS transport reset before retry"
            );
            reset().await;
            once()
                .await
                .map_err(|e| anyhow::anyhow!("{label} failed after retry: {e} (first: {first})"))
        }
    }
}

/// Pop an idle stream or dial a fresh one, run one length-prefixed exchange,
/// and return the stream to the pool on success (DoT / plain-TCP shared shape).
async fn idle_pool_exchange<S, Dial, DialFut>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    dial: Dial,
    raw_query: &[u8],
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    Dial: FnOnce() -> DialFut,
    DialFut: std::future::Future<Output = anyhow::Result<S>>,
{
    let lifecycle = lifecycle.read().await;
    match *lifecycle {
        IdlePoolState::Open => {}
        IdlePoolState::Closed => anyhow::bail!("DNS transport pool is closed"),
    }
    let taken = idle.lock().pop();
    let mut stream = match taken {
        Some(s) => s,
        None => dial().await?,
    };
    let resp = framing::exchange_length_prefixed(&mut stream, raw_query, query_timeout).await?;
    let mut guard = idle.lock();
    if guard.len() < MAX_IDLE_STREAMS {
        guard.push(stream);
    }
    drop(lifecycle);
    Ok(resp)
}

async fn close_idle_pool<S>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    timeout: Duration,
) where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut lifecycle = lifecycle.write().await;
    match *lifecycle {
        IdlePoolState::Closed => return,
        IdlePoolState::Open => *lifecycle = IdlePoolState::Closed,
    }
    let streams = std::mem::take(&mut *idle.lock());
    for mut stream in streams {
        let _ = tokio::time::timeout(timeout, stream.shutdown()).await;
    }
}

/// Shared QUIC client config for DNS transports (15s keep-alive, cubic).
async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    honk_outbound::quic::client_config(
        &Default::default(),
        alpn,
        honk_outbound::quic::QuicClientOptions {
            keep_alive: Some(Duration::from_secs(15)),
            ..honk_outbound::quic::QuicClientOptions::with_congestion(Some("cubic"))
        },
    )
    .await
}

/// Lazily-created QUIC client endpoint reused across reconnects (DoQ/DoH3).
struct SharedQuicEndpoint(tokio::sync::Mutex<Option<quinn::Endpoint>>);

impl SharedQuicEndpoint {
    fn new() -> Self {
        Self(tokio::sync::Mutex::new(None))
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut guard = self.0.lock().await;
        if let Some(ep) = guard.as_ref() {
            return Ok(ep.clone());
        }
        let ep = honk_outbound::quic::client_endpoint(ipv6)
            .map_err(|e| anyhow::anyhow!("QUIC client endpoint: {e}"))?;
        *guard = Some(ep.clone());
        Ok(ep)
    }

    async fn close(&self) {
        let endpoint = self.0.lock().await.take();
        if let Some(endpoint) = endpoint {
            endpoint.close(0_u32.into(), b"shutdown");
            endpoint.wait_idle().await;
        }
    }
}

/// Connect `config` to `addr` through the shared endpoint, with a handshake
/// timeout. `label` prefixes error messages (`DoQ` / `DoH3 QUIC`).
async fn quic_connect(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    timeout: Duration,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let ep = endpoint.get(addr.is_ipv6()).await?;
    let connecting = ep
        .connect_with(config.clone(), addr, sni)
        .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
    tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| anyhow::anyhow!("{label} handshake timed out"))?
        .map_err(|e| anyhow::anyhow!("{label} handshake: {e}"))
}

/// `host[:port]` authority string (brackets bare IPv6, elides default 443).
fn authority(host: &str, port: u16) -> String {
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host_fmt
    } else {
        format!("{host_fmt}:{port}")
    }
}

/// Build the DoH/DoH3 POST request for a DNS message. `content_length` is
/// set only on the HTTP/2 path; H3 omits it.
fn build_doh_request(
    endpoint: &DnsEndpoint,
    content_length: Option<usize>,
    label: &str,
) -> anyhow::Result<http::Request<()>> {
    let path = if endpoint.path.is_empty() {
        "/dns-query"
    } else {
        endpoint.path.as_str()
    };
    let uri = format!(
        "https://{}{}",
        authority(&endpoint.host, endpoint.port),
        path
    );
    let mut builder = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message");
    if let Some(len) = content_length {
        builder = builder.header("content-length", len.to_string());
    }
    builder
        .body(())
        .map_err(|e| anyhow::anyhow!("{label} request build: {e}"))
}

/// Shared DoH/DoH3 response validation: 2xx status, minimum DNS header size,
/// then restore the original query ID.
fn finish_doh_response(
    label: &str,
    status: http::StatusCode,
    mut body: Vec<u8>,
    orig_id: u16,
) -> anyhow::Result<Vec<u8>> {
    if !status.is_success() {
        anyhow::bail!("{label} HTTP status {status}");
    }
    if body.len() < 12 {
        anyhow::bail!("{label} response too short ({} bytes)", body.len());
    }
    framing::restore_dns_id(&mut body, orig_id);
    Ok(body)
}

#[cfg(test)]
mod observability_tests {
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_exchange_records_reset_before_successful_retry() {
        let before = crate::stats::dns_snapshot();
        let calls = AtomicUsize::new(0);
        let resets = AtomicUsize::new(0);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer({
                let captured = Arc::clone(&captured);
                move || Capture(Arc::clone(&captured))
            })
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let response = super::exchange_with_retry(
            "test",
            || async {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("secret endpoint value")
                }
                Ok(vec![1, 2, 3])
            },
            || async {
                resets.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .expect("retry succeeds");

        assert_eq!(response, vec![1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        let log = String::from_utf8(captured.lock().expect("capture").clone()).expect("UTF-8 log");
        assert!(log.contains("error_kind=\"exchange_failed\""));
        assert!(log.contains("transport=\"test\""));
        assert!(!log.contains("secret endpoint value"));
        assert!(crate::stats::dns_snapshot().delta(before).transport_reset >= 1);
    }
}
