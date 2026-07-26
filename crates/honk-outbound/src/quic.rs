//! Shared QUIC client plumbing for QUIC-based proxy protocols.
//!
//! Used by the TUIC v5, Juicity, and Hysteria2 outbounds. It provides:
//!
//! - [`rustls_client_config`] — rustls client config built from the shared
//!   `tls.rs` helpers (webpki roots or no-verify) with a per-protocol ALPN.
//! - [`client_config`] — assembles a quinn [`ClientConfig`] (TLS + transport:
//!   congestion controller selection, datagram support, keep-alive).
//! - [`client_endpoint`] — a quinn [`Endpoint`] bound on an `SO_MARK`'ed UDP
//!   socket (`DAE_BYPASS_MARK`) so traffic to the proxy server bypasses the
//!   eBPF datapath instead of looping back into it.
//! - [`QuicClient`] — a per-server connection holder: at most one active QUIC
//!   connection, re-dialed on demand, with the protocol-specific post-connect
//!   setup (auth handshake, demux tasks) running inside the single-flight
//!   critical section.
//! - [`QuicBiStream`] — `AsyncRead + AsyncWrite` wrapper pairing a quinn
//!   [`SendStream`]/[`RecvStream`] so it can be boxed into a
//!   [`crate::proxy::ProxyStream`].

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use quinn::congestion;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::warn;

/// Map a congestion-control name (`cubic` / `new_reno` / `bbr`, as used by
/// sing-box and dae node configs) to a quinn controller factory.
///
/// Unknown names fall back to cubic with a warning (all three algorithms are
/// provided by quinn-proto itself).
pub fn congestion_factory(
    name: Option<&str>,
) -> Arc<dyn congestion::ControllerFactory + Send + Sync> {
    match name.unwrap_or("cubic") {
        "cubic" => Arc::new(congestion::CubicConfig::default()),
        "new_reno" => Arc::new(congestion::NewRenoConfig::default()),
        "bbr" => Arc::new(congestion::BbrConfig::default()),
        other => {
            warn!("unknown QUIC congestion control '{other}', falling back to cubic");
            Arc::new(congestion::CubicConfig::default())
        }
    }
}

/// Fixed-rate "brutal" sender (hysteria2 parity): paces at a constant rate
/// and ignores loss entirely. quinn's token-bucket pacer refills at
/// window/RTT, so reporting a window of `rate × RTT` yields the target
/// pacing rate — the same shape as apernet's brutal sender, whose congestion
/// window is `SendBPS × RTT`.
#[derive(Debug)]
pub struct BrutalConfig {
    /// Target send rate in bytes per second.
    bytes_per_second: u64,
}

impl BrutalConfig {
    /// Build a factory for a target rate in bits per second (hysteria2
    /// bandwidth configs are in bps; 1 Mbps = 1e6 bps).
    pub fn from_bps(bps: u64) -> Self {
        Self {
            bytes_per_second: bps / 8,
        }
    }
}

impl congestion::ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.bytes_per_second,
            // RFC 9002 initial RTT; refined by the first ACK.
            rtt: Duration::from_millis(333),
            mtu: current_mtu,
        })
    }
}

struct Brutal {
    /// Target send rate, bytes per second.
    rate: u64,
    /// Latest smoothed RTT estimate.
    rtt: Duration,
    mtu: u16,
}

impl Brutal {
    fn bdp(&self) -> u64 {
        let bdp = self.rate as u128 * self.rtt.as_micros() / 1_000_000;
        bdp as u64
    }
}

impl congestion::Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.rtt = rtt.get();
    }

    /// Brutal never slows down for loss or ECN — that is its entire point.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        self.bdp().max(self.initial_window())
    }

    fn metrics(&self) -> congestion::ControllerMetrics {
        // ControllerMetrics is #[non_exhaustive]: no struct literals outside
        // the crate, mutate a default value instead.
        let mut metrics = congestion::ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.rate * 8);
        metrics
    }

    fn clone_box(&self) -> Box<dyn congestion::Controller> {
        Box::new(Brutal {
            rate: self.rate,
            rtt: self.rtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        10 * u64::from(self.mtu)
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// Caller-tunable options for [`client_config`]. Everything defaults to the
/// quinn/cubic behavior; protocol handlers override only what they need.
#[derive(Clone, Default)]
pub struct QuicClientOptions {
    /// Congestion controller; `None` = cubic. Use [`congestion_factory`] for
    /// named algorithms or [`BrutalConfig`] for hysteria2's fixed-rate sender.
    pub congestion: Option<Arc<dyn congestion::ControllerFactory + Send + Sync>>,
    /// QUIC keep-alive interval (Juicity uses 5s per the daeuniverse
    /// reference client; TUIC relies on its own heartbeat datagrams instead).
    pub keep_alive: Option<Duration>,
    /// Initial per-stream receive window, bytes.
    pub stream_receive_window: Option<u64>,
    /// Initial connection-level receive window, bytes.
    pub conn_receive_window: Option<u64>,
    /// Disable QUIC path MTU discovery.
    pub disable_mtu_discovery: bool,
}

impl QuicClientOptions {
    /// Options with a named congestion controller (`cubic`/`new_reno`/`bbr`).
    pub fn with_congestion(name: Option<&str>) -> Self {
        Self {
            congestion: Some(congestion_factory(name)),
            ..Default::default()
        }
    }
}

/// Assemble a quinn [`ClientConfig`] for a proxy protocol.
///
/// - `alpn`: ALPN protocol list required by the protocol (TUIC: `tuic`,
///   Juicity/Hysteria2: `h3`).
/// - `options`: transport tuning, see [`QuicClientOptions`].
///
/// TLS is the BoringSSL backend in [`crate::quic_boring`] (Chrome fingerprint
/// when `tls_implementation = "utls"`, ECH when the node carries one —
/// static config, or DNS HTTPS-RR discovery when only `ech_enabled` is set,
/// pinSHA256 when `tls_pin_sha256` is set).
pub async fn client_config(
    node: &honk_config::node::Node,
    alpn: &[&[u8]],
    options: QuicClientOptions,
) -> anyhow::Result<ClientConfig> {
    let alpn_wire = alpn
        .iter()
        .flat_map(|p| std::iter::once(p.len() as u8).chain(p.iter().copied()))
        .collect::<Vec<u8>>();
    let ech = match crate::tls::load_ech_config_list(node)? {
        Some(list) => Some(Arc::new(list)),
        None if node.ech_enabled => {
            let name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
            crate::tls::discover_ech_config(&name).await.map(Arc::new)
        }
        None => None,
    };
    let crypto =
        crate::quic_boring::BoringQuicClientConfig::new(crate::quic_boring::BoringQuicOptions {
            alpn_wire,
            skip_cert_verify: node.skip_cert_verify,
            chrome: crate::tls::chrome_mode(),
            ech_config_list: ech,
            pin_sha256: node
                .tls_pin_sha256
                .as_deref()
                .and_then(crate::tls::parse_pin_sha256),
        })?;
    let mut cfg = ClientConfig::new(Arc::new(crypto));

    let mut transport = TransportConfig::default();
    transport
        .congestion_controller_factory(
            options
                .congestion
                .unwrap_or_else(|| congestion_factory(None)),
        )
        // Protocols like TUIC deliver inbound UDP packets on server-initiated
        // uni streams (one stream per packet) — allow a generous number
        // (sing-quic sets MaxIncomingUniStreams to 1<<60).
        .max_concurrent_uni_streams(VarInt::from_u32(4096));
    if let Some(w) = options.stream_receive_window {
        transport.stream_receive_window(VarInt::from_u64(w)?);
    }
    if let Some(w) = options.conn_receive_window {
        transport.receive_window(VarInt::from_u64(w)?);
    }
    if options.disable_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    if let Some(ka) = options.keep_alive {
        transport.keep_alive_interval(Some(ka));
    }
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}

/// Bind a non-blocking UDP socket with `SO_MARK` set so the local eBPF
/// datapath treats QUIC packets to the proxy server as control-plane traffic
/// and does not re-route them (same bypass as `util::udp_marked_bind`; QUIC
/// needs ownership of the raw socket, so it cannot reuse that helper).
///
/// Public so protocol handlers that wrap the socket themselves (Hysteria2's
/// salamander obfuscation) can reuse the same marking logic.
pub fn marked_udp_socket(ipv6: bool) -> io::Result<std::net::UdpSocket> {
    let domain = if ipv6 {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    crate::util::set_mark_best_effort(&socket, honk_ebpf_common::DAE_BYPASS_MARK)?;
    let bind_addr: SocketAddr = if ipv6 {
        "[::]:0".parse().expect("hardcoded IPv6 bind address")
    } else {
        "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
    };
    socket.bind(&bind_addr.into())?;
    Ok(socket.into())
}

/// Create a client-only quinn [`Endpoint`] on a marked UDP socket for the
/// given address family.
pub fn client_endpoint(ipv6: bool) -> io::Result<Endpoint> {
    let socket = marked_udp_socket(ipv6)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    Endpoint::new(EndpointConfig::default(), None, socket, runtime)
}

struct State<C> {
    /// Lazily created endpoint, tagged with its address family. Recreated when
    /// the family of the resolved server address changes.
    endpoint: Option<(bool, Endpoint)>,
    conn: Option<(Connection, Arc<C>)>,
}

/// Per-server QUIC connection holder.
///
/// Keeps at most one active QUIC connection to the server and re-dials on
/// demand (first use, connection loss, or explicit [`QuicClient::invalidate`]).
/// The generic `C` is the protocol-specific per-connection state (demux maps,
/// background task handles, ...), built by the `setup` closure inside the
/// single-flight critical section so concurrent dialers share exactly one
/// handshake.
pub struct QuicClient<C> {
    server_host: String,
    server_port: u16,
    server_name: String,
    config: ClientConfig,
    /// Optional custom endpoint constructor, called with the address family
    /// (`true` = IPv6) of the resolved server address. Hysteria2 uses this to
    /// run QUIC over a salamander-obfuscated socket; when unset the plain
    /// marked socket from [`client_endpoint`] is used.
    endpoint_factory: Option<Arc<dyn Fn(bool) -> io::Result<Endpoint> + Send + Sync>>,
    state: Mutex<State<C>>,
}

impl<C> QuicClient<C> {
    pub fn new(
        server_host: impl Into<String>,
        server_port: u16,
        server_name: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        Self {
            server_host: server_host.into(),
            server_port,
            server_name: server_name.into(),
            config,
            endpoint_factory: None,
            state: Mutex::new(State {
                endpoint: None,
                conn: None,
            }),
        }
    }

    /// Use a custom endpoint constructor instead of [`client_endpoint`] (see
    /// the field docs). The factory is called once per address family and the
    /// resulting endpoint is cached like the default one.
    pub fn with_endpoint_factory(
        mut self,
        factory: impl Fn(bool) -> io::Result<Endpoint> + Send + Sync + 'static,
    ) -> Self {
        self.endpoint_factory = Some(Arc::new(factory));
        self
    }

    /// Return the shared connection (plus its protocol state), dialing and
    /// running `setup` first when there is no live connection.
    ///
    /// Resolved server addresses are tried in order until one completes both
    /// the QUIC handshake and `setup`.
    pub async fn connection_with<F, Fut>(
        &self,
        connect_timeout: Duration,
        setup: F,
    ) -> anyhow::Result<(Connection, Arc<C>)>
    where
        F: FnOnce(Connection) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<C>>,
    {
        let mut state = self.state.lock().await;
        if let Some((conn, ctx)) = &state.conn
            && conn.close_reason().is_none()
        {
            return Ok((conn.clone(), Arc::clone(ctx)));
        }
        state.conn = None;

        let host = format!("{}:{}", self.server_host, self.server_port);
        let addrs: Vec<SocketAddr> = crate::bootstrap::resolve(&self.server_host)
            .await
            .with_context(|| format!("resolve {host}"))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.server_port))
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("resolve {host}: no addresses");
        }

        let mut last_err: Option<anyhow::Error> = None;
        let mut conn: Option<Connection> = None;
        'addrs: for server_addr in addrs {
            let ipv6 = server_addr.is_ipv6();
            let endpoint = match &state.endpoint {
                Some((family, ep)) if *family == ipv6 => ep.clone(),
                _ => {
                    let ep = match &self.endpoint_factory {
                        Some(factory) => factory(ipv6),
                        None => client_endpoint(ipv6),
                    }
                    .with_context(|| format!("create QUIC endpoint (ipv6={ipv6})"))?;
                    state.endpoint = Some((ipv6, ep.clone()));
                    ep
                }
            };
            // Retry the handshake a few times per address: lossy uplinks
            // (typical for cross-border QUIC) drop most Initials, and a
            // single attempt is what made nodes flap dead on such paths
            // (Go/quic-go clients succeed via retries).
            for attempt in 1..=3u8 {
                let connecting = match endpoint.connect_with(
                    self.config.clone(),
                    server_addr,
                    &self.server_name,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        last_err = Some(e.into());
                        continue 'addrs;
                    }
                };
                match tokio::time::timeout(connect_timeout, connecting).await {
                    Err(_) => {
                        last_err = Some(anyhow!(
                            "QUIC connect to {server_addr} timed out (attempt {attempt})"
                        ));
                    }
                    Ok(Err(e)) => {
                        last_err = Some(anyhow!(
                            "QUIC connect to {server_addr}: {e} (attempt {attempt})"
                        ));
                    }
                    Ok(Ok(established)) => {
                        conn = Some(established);
                        break 'addrs;
                    }
                }
            }
        }
        let conn = match conn {
            Some(conn) => conn,
            None => {
                return Err(last_err.unwrap_or_else(|| anyhow!("QUIC connect to {host} failed")));
            }
        };
        let ctx = setup(conn.clone()).await.inspect_err(|_| {
            conn.close(VarInt::from_u32(0), b"setup failed");
        })?;
        let ctx = Arc::new(ctx);
        state.conn = Some((conn.clone(), Arc::clone(&ctx)));
        Ok((conn, ctx))
    }

    /// Drop the cached connection if it is `conn`, forcing the next
    /// [`connection_with`](Self::connection_with) call to re-dial. Used when a
    /// stream operation fails on a half-dead connection.
    pub async fn invalidate(&self, conn: &Connection) {
        let mut state = self.state.lock().await;
        if let Some((cached, _)) = &state.conn
            && cached.stable_id() == conn.stable_id()
        {
            state.conn = None;
        }
    }
}

/// A QUIC bidirectional stream as a single `AsyncRead + AsyncWrite` object.
///
/// Dropping the send half finishes the stream (sends FIN), which is what the
/// relay's half-close semantics rely on. `on_drop` lets the owning protocol
/// track open-stream counts (for idle connection reaping) without wrapping
/// the stream again.
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
    on_drop: Option<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for QuicBiStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicBiStream")
            .field("send", &self.send)
            .field("recv", &self.recv)
            .finish_non_exhaustive()
    }
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            on_drop: None,
        }
    }

    /// Register a callback fired when this stream object is dropped.
    pub fn with_on_drop(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_drop = Some(Box::new(f));
        self
    }
}

impl Drop for QuicBiStream {
    fn drop(&mut self) {
        if let Some(f) = &self.on_drop {
            f();
        }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fully-qualified calls: quinn's inherent `poll_read`/`poll_write`
        // methods (different error types) would shadow the trait methods.
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! In-process QUIC test servers: self-signed certs plus endpoint builders
    //! shared by the TUIC and Juicity handler tests.

    use std::sync::Arc;

    use anyhow::anyhow;
    use quinn::{ServerConfig, TransportConfig};

    /// Build a quinn server config with a freshly generated self-signed
    /// certificate (valid for `localhost`) and the given ALPN list.
    ///
    /// When `datagrams` is false the server does not advertise QUIC datagram
    /// support, which exercises the UDP-over-stream fallback of clients.
    pub fn server_config(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_with_cert(alpn, datagrams).map(|(config, _)| config)
    }

    /// [`server_config`] that also returns the leaf certificate DER (for
    /// pinSHA256 tests).
    pub fn server_config_with_cert(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

        let provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
        let mut tls_config =
            tokio_rustls::rustls::ServerConfig::builder_with_provider(provider.into())
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow!("TLS protocol versions: {e}"))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                        signing_key.serialize_der().into(),
                    ),
                )
                .map_err(|e| anyhow!("TLS server config: {e}"))?;
        tls_config.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();

        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| anyhow!("rustls server config is not QUIC-compatible: {e}"))?;
        let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        if !datagrams {
            let mut transport = TransportConfig::default();
            transport.datagram_receive_buffer_size(None);
            config.transport_config(Arc::new(transport));
        }
        Ok((config, cert.der().to_vec()))
    }

    /// Start a QUIC server endpoint on a loopback ephemeral port.
    pub fn server_endpoint(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config(alpn, datagrams)?,
            "127.0.0.1:0".parse().expect("hardcoded bind address"),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr))
    }
}

#[cfg(test)]
mod brutal_tests {
    use super::*;
    use congestion::ControllerFactory;

    fn controller(rate_bps: u64) -> Box<dyn congestion::Controller> {
        Arc::new(BrutalConfig::from_bps(rate_bps)).build(Instant::now(), 1200)
    }

    #[test]
    fn window_is_rate_times_rtt() {
        let cc = controller(100_000_000); // 100 Mbps → 12.5 MB/s
        // Initial RTT guess 333ms: BDP = 12.5e6 × 0.333 ≈ 4.16 MB.
        let w = cc.window();
        assert!((4_000_000..4_400_000).contains(&w), "window {w}");
    }

    #[test]
    fn loss_never_shrinks_window() {
        let mut cc = controller(50_000_000);
        let before = cc.window();
        cc.on_congestion_event(Instant::now(), Instant::now(), true, 12000);
        cc.on_congestion_event(Instant::now(), Instant::now(), false, 0);
        assert_eq!(cc.window(), before);
    }
}

// ---------------------------------------------------------------------------
// QUIC liveness probing through a proxy's UDP tunnel
// ---------------------------------------------------------------------------

use crate::proxy::UdpProxySocket;

/// quinn [`AsyncUdpSocket`] that drives a proxied UDP tunnel
/// ([`UdpProxySocket`]): outbound datagrams go to the tunnel's relay address,
/// and inbound datagrams have their source normalized to the QUIC peer so
/// quinn's remote-address checks see a stable path (same trick as
/// hysteria2's port-hop normalization).
#[derive(Debug)]
struct UdpProxyQuinnSocket {
    proxy: Arc<UdpProxySocket>,
    remote: SocketAddr,
}

impl quinn::AsyncUdpSocket for UdpProxyQuinnSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        #[derive(Debug)]
        struct Poller(Arc<UdpProxySocket>);
        impl quinn::UdpPoller for Poller {
            fn poll_writable(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                self.0.socket.poll_send_ready(cx)
            }
        }
        Box::pin(Poller(self.proxy.clone()))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.proxy
            .socket
            .try_send_to(transmit.contents, self.proxy.relay_addr)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            let mut read_buf = tokio::io::ReadBuf::new(&mut buf[..]);
            match self.proxy.socket.poll_recv_from(cx, &mut read_buf) {
                std::task::Poll::Ready(Ok(_addr)) => {
                    let len = read_buf.filled().len();
                    *meta_slot = quinn::udp::RecvMeta {
                        addr: self.remote,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    count += 1;
                }
                std::task::Poll::Ready(Err(e)) => {
                    return if count == 0 {
                        std::task::Poll::Ready(Err(e))
                    } else {
                        std::task::Poll::Ready(Ok(count))
                    };
                }
                std::task::Poll::Pending => {
                    return if count == 0 {
                        std::task::Poll::Pending
                    } else {
                        std::task::Poll::Ready(Ok(count))
                    };
                }
            }
        }
        std::task::Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.proxy.socket.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

/// Establish a QUIC connection through a proxied UDP tunnel and time the
/// handshake.  This is the real QUIC liveness probe: unlike a bare
/// Version-Negotiation trigger (which many frontends ignore), it proves
/// TLS-in-QUIC reachability through the node's UDP path.  `config` comes from
/// [`client_config`] — pass a node with `skip_cert_verify` for pure liveness
/// probing.
pub async fn quic_handshake_probe(
    proxy: UdpProxySocket,
    target: SocketAddr,
    server_name: &str,
    config: &ClientConfig,
    timeout: Duration,
) -> anyhow::Result<Duration> {
    let socket = Arc::new(UdpProxyQuinnSocket {
        proxy: Arc::new(proxy),
        remote: target,
    });
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let endpoint =
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)?;

    let start = Instant::now();
    let connecting = endpoint
        .connect_with(config.clone(), target, server_name)
        .context("create QUIC connecting")?;
    let conn = tokio::time::timeout(timeout, connecting)
        .await
        .context("QUIC handshake timeout")??;
    let elapsed = start.elapsed();
    conn.close(quinn::VarInt::from_u32(0), b"probe");
    endpoint.close(quinn::VarInt::from_u32(0), b"probe");
    Ok(elapsed)
}
