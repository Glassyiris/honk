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
//! - Small pieces shared verbatim by the three protocol handlers:
//!   [`now_secs`], [`recv_read_exact`], the UDP fragment [`defrag`] module,
//!   [`cached_client`], [`exporter_auth`], [`spawn_conn_reaper`] and the
//!   [`dial_quic_stream`] retry skeleton.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use quinn::congestion;
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig,
    VarInt,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

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
    /// UDP payload size (NOT link MTU): applied as the send-side
    /// `initial_mtu` and the PMTUD upper bound; the endpoint's
    /// `max_udp_payload_size` (receive advertisement) is set separately by
    /// the protocol handler from the same node field.
    pub max_udp_payload_size: Option<u16>,
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
            // Tickets belong to a specific service, not a hostname:
            // address|port|SNI|ALPN — different protocols, different
            // servers behind one certificate, and reloaded configs never
            // cross-resume into each other.
            ticket_key: Some(format!(
                "{}|{}|{}|{}",
                node.host(),
                node.port,
                node.sni.clone().unwrap_or_else(|| node.host().to_string()),
                alpn.iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            )),
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
    if let Some(mtu) = options.max_udp_payload_size {
        // UDP payload size, not link MTU. Valid range per RFC 9000 (initial
        // packets must carry 1200) and quinn's cap; invalid values are
        // clamped rather than failing the first dial later.
        let mtu = mtu.clamp(1200, 65527);
        transport.initial_mtu(mtu);
        if !options.disable_mtu_discovery {
            let mut mtud = quinn::MtuDiscoveryConfig::default();
            mtud.upper_bound(mtu);
            transport.mtu_discovery_config(Some(mtud));
        }
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

/// Current unix time in seconds (0 on clock skew); used for the idle
/// accounting of shared connections.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `RecvStream::read_exact` with quinn's error mapped to
/// `io::ErrorKind::UnexpectedEof` (protocol framing helpers return
/// `io::Result`).
pub(crate) async fn recv_read_exact(recv: &mut RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}

/// UDP fragment reassembly shared by the TUIC and Hysteria2 session bridges
/// (sing `udpDefragger` parity).
pub(crate) mod defrag {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    /// Maximum pending fragmented packets kept for reassembly per session.
    const DEFRAG_MAX_PENDING: usize = 64;
    /// Maximum age of a pending fragmented packet before it is dropped.
    const DEFRAG_MAX_AGE: Duration = Duration::from_secs(10);

    /// Reassembly state for one fragmented packet.
    struct DefragBuffer {
        frags: Vec<Option<Vec<u8>>>,
        count: usize,
        updated: Instant,
    }

    /// Reassembles fragmented UDP packets, bounding memory by capping the
    /// number of pending packets and expiring stale ones.
    #[derive(Default)]
    pub(crate) struct Defragmenter {
        map: HashMap<u16, DefragBuffer>,
    }

    impl Defragmenter {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Feed one fragment; returns the reassembled payload when the last
        /// missing fragment arrives. Unfragmented packets (`frag_total <= 1`)
        /// pass through immediately; invalid or duplicate fragments are
        /// dropped (`None`).
        pub(crate) fn feed(
            &mut self,
            packet_id: u16,
            frag_id: u8,
            frag_total: u8,
            data: Vec<u8>,
        ) -> Option<Vec<u8>> {
            if frag_total <= 1 {
                return Some(data);
            }
            if frag_id >= frag_total {
                return None;
            }
            let map = &mut self.map;
            if map.len() >= DEFRAG_MAX_PENDING && !map.contains_key(&packet_id) {
                map.retain(|_, b| b.updated.elapsed() < DEFRAG_MAX_AGE);
                if map.len() >= DEFRAG_MAX_PENDING {
                    return None;
                }
            }
            let frag_total = frag_total as usize;
            let entry = map.entry(packet_id).or_insert_with(|| DefragBuffer {
                frags: (0..frag_total).map(|_| None).collect(),
                count: 0,
                updated: Instant::now(),
            });
            if entry.frags.len() != frag_total {
                entry.frags = (0..frag_total).map(|_| None).collect();
                entry.count = 0;
            }
            let frag_id = frag_id as usize;
            if entry.frags[frag_id].is_some() {
                return None;
            }
            entry.frags[frag_id] = Some(data);
            entry.count += 1;
            entry.updated = Instant::now();
            if entry.count != entry.frags.len() {
                return None;
            }
            let entry = map.remove(&packet_id).expect("entry just inserted");
            let mut data = Vec::new();
            for frag in entry.frags.into_iter().flatten() {
                data.extend_from_slice(&frag);
            }
            Some(data)
        }
    }
}

/// Bind a non-blocking UDP socket with `SO_MARK` set so the local eBPF
/// datapath treats QUIC packets to the proxy server as control-plane traffic
/// and does not re-route them (same bypass as `util::udp_marked_bind`; QUIC
/// needs ownership of the raw socket, so it cannot reuse that helper).
///
/// Public so protocol handlers that wrap the socket themselves (Hysteria2's
/// salamander obfuscation) can reuse the same marking logic.
pub fn marked_udp_socket(ipv6: bool) -> io::Result<std::net::UdpSocket> {
    let bind_addr: SocketAddr = if ipv6 {
        "[::]:0".parse().expect("hardcoded IPv6 bind address")
    } else {
        "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
    };
    crate::util::marked_udp_socket(bind_addr)
}

/// Create a client-only quinn [`Endpoint`] on a marked UDP socket for the
/// given address family.
///
/// The endpoint advertises `max_udp_payload_size = 1252` instead of quinn's
/// 1472: on PPPoE/tunneled last miles, larger downlink UDP datagrams are
/// silently black-holed (measured on a CN PPPoE line: ≤1260B echoes pass,
/// 1280B all lost), which kills every QUIC handshake whose ServerHello
/// flight exceeds the threshold. 1252 matches quic-go's default; going
/// lower (e.g. the RFC minimum 1200) shrinks the server's flight allowance
/// below its anti-amplification budget (3× the client Initial) and can
/// deadlock handshakes against large certificate chains.
pub fn client_endpoint(ipv6: bool) -> io::Result<Endpoint> {
    client_endpoint_with_mtu(ipv6, 1252)
}

/// [`client_endpoint`] with an explicit advertised `max_udp_payload_size`.
pub fn client_endpoint_with_mtu(ipv6: bool, max_udp_payload_size: u16) -> io::Result<Endpoint> {
    let socket = marked_udp_socket(ipv6)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
    let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
    static GSO: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let gso = *GSO.get_or_init(|| {
        std::env::var("HONK_QUIC_GSO")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    });
    let socket = Arc::new(NoGsoUdpSocket { io, inner, gso });
    Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(max_udp_payload_size)?,
        None,
        socket,
        runtime,
    )
}

/// EndpointConfig advertising `max_udp_payload_size` (see `client_endpoint`
/// for why 1252 is the safe default on PMTU-black-holed last miles).
pub(crate) fn endpoint_config_with_mtu(mtu: u16) -> io::Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config.max_udp_payload_size(mtu).map_err(io::Error::other)?;
    Ok(config)
}

/// quinn's stock tokio socket behavior (ECN, GRO, cmsgs) with **GSO
/// disabled** (`max_transmit_segments = 1`): every datagram goes out on its
/// own, dodging PPPoE uplinks that drop later segments of a GSO
/// super-packet. This is quinn's own `runtime/tokio.rs` socket with a
/// one-line change, so nothing else (ECN signaling, GRO receives, pktinfo)
/// diverges from the stock path.
///
/// `HONK_QUIC_GSO=1` opts back into kernel UDP GSO (a 10-20% single-flow
/// throughput win on non-PPPoE paths; keep it off where the uplink drops
/// GSO segments).
#[derive(Debug)]
struct NoGsoUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    gso: bool,
}

impl quinn::AsyncUdpSocket for NoGsoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(NoGsoUdpPoller {
            socket: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        if self.gso {
            self.inner.max_gso_segments()
        } else {
            1
        }
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

#[derive(Debug)]
struct NoGsoUdpPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for NoGsoUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
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
/// **Rotation overlaps by construction**: a flow owns its `(Connection,
/// Arc<C>)` pair, so when the holder detects the connection's close reason
/// and dials a fresh one, in-flight streams/datagram flows finish on the
/// old connection while new flows land on the new one — one Active plus
/// one draining, without a hard cut. The generic `C` is the
/// protocol-specific per-connection state (demux maps, background task
/// handles, ...), built by the `setup` closure inside the single-flight
/// critical section so concurrent dialers share exactly one handshake.
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
    /// Advertised `max_udp_payload_size` cap for the default endpoint (see
    /// [`client_endpoint`] for the safe 1252 default).
    mtu: u16,
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
            mtu: 1252,
            state: Mutex::new(State {
                endpoint: None,
                conn: None,
            }),
        }
    }

    /// Advertise a larger `max_udp_payload_size` on paths known to carry it
    /// (anything but PMTU-black-holed last miles — see [`client_endpoint`]).
    /// Larger datagrams directly lower the per-packet processing cost that
    /// caps single-connection QUIC throughput (~180k pps at 1252B).
    pub fn with_max_udp_payload_size(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
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
                        None => client_endpoint_with_mtu(ipv6, self.mtu),
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
    /// Whether this client already owns a live reusable QUIC connection.
    /// Warm-up uses this only to report whether it established a connection;
    /// the connection itself remains owned by the client cache.
    pub async fn has_live_connection(&self) -> bool {
        self.state
            .lock()
            .await
            .conn
            .as_ref()
            .is_some_and(|(conn, _)| conn.close_reason().is_none())
    }
}

/// A QUIC bidirectional stream as a single `AsyncRead + AsyncWrite` object.
///
/// Dropping the send half finishes the stream (sends FIN), which is what the
/// relay's half-close semantics rely on. The [`StreamDropGuard`] lets the
/// owning protocol track open-stream counts (for idle connection reaping)
/// without wrapping the stream again.
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
    guard: StreamDropGuard,
}

/// Fires the registered callback when dropped. Lives inside
/// [`QuicBiStream`]; users that split the stream into its raw quinn halves
/// ([`QuicBiStream::into_parts`]) keep the guard for the same lifetime
/// accounting.
pub(crate) struct StreamDropGuard(Option<Box<dyn Fn() + Send + Sync>>);

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
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
            guard: StreamDropGuard(None),
        }
    }

    /// Register a callback fired when this stream object is dropped.
    pub fn with_on_drop(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.guard.0 = Some(Box::new(f));
        self
    }

    /// Split into the raw quinn halves plus the drop guard (open-stream
    /// accounting) — for users that drive the halves separately, e.g. UDP
    /// session bridges.
    pub(crate) fn into_parts(self) -> (SendStream, RecvStream, StreamDropGuard) {
        (self.send, self.recv, self.guard)
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

// ---------------------------------------------------------------------------
// Shared skeletons for the TUIC / Juicity / Hysteria2 protocol handlers
// ---------------------------------------------------------------------------

/// Per-connection state shared by the QUIC proxy handlers: the activity
/// bookkeeping used by the dial retry skeleton and the idle reaper.
pub(crate) trait QuicConnState: Send + Sync + 'static {
    /// Record activity on the connection (resets the idle reaper).
    fn touch(&self);
    /// Counter of open streams/bridges on this connection.
    fn open_counter(&self) -> &Arc<AtomicUsize>;
}

/// Per-server protocol-client cache (TUIC/Juicity/Hysteria2 pool
/// parity): an owned map keyed by server + credential **fingerprint** —
/// one per handler instance, never process-global, and never holding a
/// cleartext password in the key.
pub(crate) struct ClientCache<C> {
    map: Arc<parking_lot::Mutex<HashMap<String, Arc<C>>>>,
}

impl<C> ClientCache<C> {
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }
}

impl<C> Default for ClientCache<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> Clone for ClientCache<C> {
    fn clone(&self) -> Self {
        Self {
            map: Arc::clone(&self.map),
        }
    }
}

impl<C> std::fmt::Debug for ClientCache<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCache")
            .field("entries", &self.map.lock().len())
            .finish()
    }
}

/// blake3 fingerprint (16 hex chars) for cache keys: credentials never
/// sit in keys in the clear.
pub(crate) fn key_fingerprint(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"|");
    }
    h.finalize().to_hex()[..16].to_string()
}

/// Look up a cached per-server protocol client, building and inserting it
/// when missing. The build runs outside the lock (it is async — ECH
/// discovery), so a concurrent task may have won the race; in that case the
/// existing entry is reused and the freshly built one dropped.
pub(crate) async fn cached_client<C, F, Fut>(
    cache: &ClientCache<C>,
    key: String,
    build: F,
) -> anyhow::Result<Arc<C>>
where
    C: Send + Sync + 'static,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Arc<C>>>,
{
    if let Some(client) = cache.map.lock().get(&key) {
        return Ok(Arc::clone(client));
    }
    let client = build().await?;
    // Another task may have won the race — reuse theirs.
    Ok(cache.map.lock().entry(key).or_insert(client).clone())
}

/// TUIC-style exporter authentication (sing `clientHandshake`,
/// `client.go:197-214`): one uni stream carrying
/// `[version, 0x00, uuid(16), token(32)]` where
/// `token = TLS ExportKeyingMaterial(label = uuid, context = password, 32)`.
/// Juicity reuses the same frame with version 0x00 and keeps the stream
/// open (`finish = false`); TUIC finishes it right after the write.
///
/// There is no positive auth acknowledgement: a server that rejects the
/// credentials closes the connection, so the call waits a brief `grace`
/// period for that to surface as a dial error here instead of a stream
/// failure on the first proxied connection. Returns the auth stream.
pub(crate) async fn exporter_auth(
    conn: &Connection,
    uuid: &[u8; 16],
    password: &str,
    version: u8,
    finish: bool,
    grace: Duration,
) -> anyhow::Result<SendStream> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("QUIC exporter auth: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(version);
    auth.push(0x00); // CMD_AUTHENTICATE
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("QUIC exporter auth: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("QUIC exporter auth: send authenticate")?;
    if finish {
        stream
            .finish()
            .context("QUIC exporter auth: finish authenticate stream")?;
    }
    tokio::select! {
        e = conn.closed() => Err(anyhow!("QUIC exporter auth: connection closed during authentication: {e}")),
        _ = tokio::time::sleep(grace) => Ok(stream),
    }
}

/// Per-tick callback for [`spawn_conn_reaper`] (TUIC's heartbeat datagram);
/// returning false ends the reaper loop.
type ReaperTick = Box<dyn Fn(&Connection) -> bool + Send + 'static>;

/// Spawn the idle-connection reaper shared by the QUIC protocol handlers:
/// every `interval`, close the connection when the owning protocol state was
/// dropped ("state dropped") or when it has had no open streams/bridges for
/// `idle_timeout` ("idle"). `on_tick` runs after the liveness checks (TUIC's
/// heartbeat datagram); returning false ends the loop.
pub(crate) fn spawn_conn_reaper(
    conn: Connection,
    open: Weak<AtomicUsize>,
    last_activity: Weak<AtomicU64>,
    interval: Duration,
    idle_timeout: Duration,
    on_tick: Option<ReaperTick>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if conn.close_reason().is_some() {
                break;
            }
            let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
                // Protocol state dropped: nothing can use this connection.
                conn.close(VarInt::from_u32(0), b"state dropped");
                break;
            };
            let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
            if open.load(Ordering::Relaxed) == 0 && idle > idle_timeout.as_secs() {
                conn.close(VarInt::from_u32(0), b"idle");
                break;
            }
            if let Some(on_tick) = &on_tick
                && !on_tick(&conn)
            {
                break;
            }
        }
    });
}

/// Shared TCP-over-QUIC dial skeleton (TUIC/Juicity/Hysteria2): get the
/// shared connection via `connect` (re-dialing when needed), run the
/// protocol's stream handshake (`make`), and retry once with a fresh
/// connection when the handshake fails on a half-dead cached connection and
/// `retryable` allows it (Hysteria2's server-side refusals are not
/// retryable). The returned stream decrements the connection's open counter
/// on drop.
pub(crate) async fn dial_quic_stream<S, Connect, Fut, Make, MakeFut>(
    client: &QuicClient<S>,
    connect: Connect,
    connect_timeout: Duration,
    make: Make,
    retryable: impl Fn(&anyhow::Error) -> bool,
    proto: &'static str,
) -> anyhow::Result<QuicBiStream>
where
    S: QuicConnState,
    Connect: Fn(Duration) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(Connection, Arc<S>)>>,
    Make: Fn(Connection) -> MakeFut,
    MakeFut: std::future::Future<Output = anyhow::Result<(SendStream, RecvStream)>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        let (conn, state) = connect(connect_timeout).await?;
        state.touch();
        match make(conn.clone()).await {
            Ok((send, recv)) => {
                let open = Arc::clone(state.open_counter());
                open.fetch_add(1, Ordering::Relaxed);
                let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                    open.fetch_sub(1, Ordering::Relaxed);
                });
                return Ok(stream);
            }
            Err(e) if retryable(&e) => {
                debug!("{proto}: stream open failed (attempt {attempt}): {e}");
                client.invalidate(&conn).await;
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop runs at least once"))
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
        server_config_impl(alpn, datagrams, false)
    }

    /// [`server_config`] restricted to TLS 1.3 ChaCha20-Poly1305, forcing the
    /// peer onto the ChaCha20 header-protection path.
    pub fn server_config_chacha20(alpn: &[&[u8]], datagrams: bool) -> anyhow::Result<ServerConfig> {
        server_config_impl(alpn, datagrams, true).map(|(config, _)| config)
    }

    fn server_config_impl(
        alpn: &[&[u8]],
        datagrams: bool,
        chacha20_only: bool,
    ) -> anyhow::Result<(ServerConfig, Vec<u8>)> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;

        let mut provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
        if chacha20_only {
            // ChaCha20 first so the handshake negotiates it; AES-128 stays
            // because quinn derives QUIC initial keys from it.
            provider.cipher_suites = vec![
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                tokio_rustls::rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
        }
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
        if chacha20_only {
            // rustls defaults to client order; honk's BoringSSL client offers
            // AES first, so the suite restriction alone is not enough.
            tls_config.ignore_client_order = true;
        }
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

    /// [`server_endpoint`] restricted to ChaCha20-Poly1305.
    pub fn server_endpoint_chacha20(
        alpn: &[&[u8]],
        datagrams: bool,
    ) -> anyhow::Result<(quinn::Endpoint, std::net::SocketAddr)> {
        let endpoint = quinn::Endpoint::server(
            server_config_chacha20(alpn, datagrams)?,
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
        Endpoint::new_with_abstract_socket(endpoint_config_with_mtu(1252)?, None, socket, runtime)?;

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
