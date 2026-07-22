//! AnyTLS proxy handler with sing-anytls session multiplexing.
//!
//! One TLS session carries any number of concurrent streams, each identified
//! by a stream id (`sid`) — sing-anytls `session/session.go` semantics:
//!
//! - a per-session **demux task** reads frames and dispatches them by `sid`
//!   (`PSH` → stream payload, `FIN` → stream EOF, heartbeats answered at
//!   session level);
//! - an atomic `sid` allocator hands out stream ids (starting at 1);
//! - the write half is shared behind a mutex (sing `connLock` parity);
//! - dialing on a healthy pooled session just opens a new `sid` (SYN + the
//!   first PSH carrying the target address) — no exclusive session borrow;
//! - a stream ends with FIN in either direction; the session itself is
//!   reclaimed by the pool janitor once it has no open streams and has been
//!   idle past `idle_session_timeout` (sing `idleCleanupExpTime` parity);
//! - `min_idle_session` keeps that many idle sessions pre-established.

use crate::tls::TlsConnector;
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, warn};

use super::{ProxyHandler, ProxyStream, UdpProxySocket};

/// sing uot v2 magic address (`protocol/anytls/outbound.go`,
/// `common/uot/protocol.go`): UDP-over-TCP streams are opened to this
/// pseudo-target inside the AnyTLS session.
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
/// Idle timeout for the UDP bridge task (matches the TUIC bridge).
const UDP_BRIDGE_IDLE_SECS: u64 = 90;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const FRAME_HEADER_LEN: usize = 7;

/// sing-anytls defaults (session/client.go): values below 5s clamp to 30s.
const DEFAULT_IDLE_CHECK_INTERVAL_SECS: u64 = 30;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// Buffer of the user-facing half of a stream (matches the old pool).
const STREAM_DUPLEX_BUFFER: usize = 65536;

/// Transport halves behind trait objects so tests can drive a session over
/// an in-memory duplex instead of a real TLS connection.
type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// AnyTLS proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct AnyTlsHandler;

/// Global session pool, shared across all AnyTlsHandler instances.
static SESSION_POOL: LazyLock<Arc<AnyTlsSessionPool>> =
    LazyLock::new(|| Arc::new(AnyTlsSessionPool::new()));

/// Node addresses that already have a running pool janitor.
static JANITORS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Monotonic session id for pool bookkeeping (sing `sessionCounter`).
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Inbound events delivered from the session demux to a stream task.
#[derive(Debug)]
enum StreamEvent {
    /// Server payload for this stream.
    Data(Vec<u8>),
    /// Server closed the stream (FIN, or SYNACK error report).
    Fin,
}

/// A multiplexed AnyTLS session: one TLS connection carrying any number of
/// concurrent streams (sing-anytls `Session`).
struct AnyTlsSession {
    /// Unique id within the pool (used for removal on close).
    seq: u64,
    /// Pool key (`host:port` of the AnyTLS server).
    addr: String,
    /// Shared frame writer (sing `connLock`): all streams serialize their
    /// frames through this mutex.
    writer: Arc<tokio::sync::Mutex<BoxedWriter>>,
    /// Open streams: sid → demux delivery channel.
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<StreamEvent>>>,
    /// Stream id allocator (sing `streamId`); first stream gets sid 1.
    next_sid: AtomicU32,
    /// Set once the TLS connection dies or an ALERT arrives; idempotent
    /// close via [`AnyTlsSession::close`].
    closed: AtomicBool,
    /// Number of currently open streams.
    active_streams: AtomicUsize,
    /// When the session last had zero open streams (janitor idle expiry).
    idle_since: Mutex<Instant>,
    /// Demux task handle, aborted on close.
    demux: Mutex<Option<tokio::task::AbortHandle>>,
    /// Owning pool (weak — the pool owns the session, not vice versa).
    pool: Weak<AnyTlsSessionPool>,
}

impl AnyTlsSession {
    /// Establish a session on a connected transport: write the auth blob
    /// and the settings frame (sid 0, sing `Session.Run` parity), spawn the
    /// demux task, and register the session in the pool.
    async fn establish(
        pool: &Arc<AnyTlsSessionPool>,
        addr: &str,
        transport_read: BoxedReader,
        mut transport_write: BoxedWriter,
        auth: &[u8],
        settings: &[u8],
    ) -> anyhow::Result<Arc<Self>> {
        transport_write.write_all(auth).await?;
        write_frame(&mut transport_write, CMD_SETTINGS, 0, settings).await?;
        transport_write.flush().await?;

        let session = Arc::new(Self {
            seq: SESSION_SEQ.fetch_add(1, Ordering::Relaxed),
            addr: addr.to_string(),
            writer: Arc::new(tokio::sync::Mutex::new(transport_write)),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            active_streams: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
            demux: Mutex::new(None),
            pool: Arc::downgrade(pool),
        });

        let demux_handle = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { session_demux(session, transport_read).await })
        };
        *session.demux.lock().unwrap() = Some(demux_handle.abort_handle());

        pool.insert(addr, Arc::clone(&session));
        debug!("AnyTLS session {} for {} established", session.seq, addr);
        Ok(session)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn active_streams(&self) -> usize {
        self.active_streams.load(Ordering::Relaxed)
    }

    /// How long the session has had zero open streams.
    fn idle_for(&self) -> Duration {
        self.idle_since.lock().unwrap().elapsed()
    }

    /// Restart the idle clock (janitor refresh within the min_idle budget,
    /// and the transition to zero open streams).
    fn touch_idle(&self) {
        *self.idle_since.lock().unwrap() = Instant::now();
    }

    /// Write a single frame through the shared writer.
    async fn write_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> anyhow::Result<()> {
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, cmd, sid, data).await?;
        w.flush().await?;
        Ok(())
    }

    /// Open a new stream on this session (sing `Session.OpenStream`):
    /// allocate a sid, send SYN + the first PSH carrying the target
    /// address, and return the user-facing half of the stream. Many
    /// streams may be open concurrently; no exclusive borrow is taken.
    async fn open_stream(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
    ) -> anyhow::Result<tokio::io::DuplexStream> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS session {} is closed", self.seq);
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        let (client_half, stream_half) = tokio::io::duplex(STREAM_DUPLEX_BUFFER);
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.lock().unwrap().insert(sid, tx);

        // SYN, then the first PSH carrying the target address — one writer
        // lock so the opening pair is never interleaved with other streams.
        let open_result: std::io::Result<()> = async {
            let mut w = self.writer.lock().await;
            write_frame(&mut *w, CMD_SYN, sid, &[]).await?;
            write_frame(&mut *w, CMD_PSH, sid, &target_addr).await?;
            w.flush().await
        }
        .await;
        if let Err(e) = open_result {
            self.streams.lock().unwrap().remove(&sid);
            // sing `writeControlFrame`: a write failure kills the session.
            self.close();
            return Err(anyhow::anyhow!(
                "AnyTLS session {} open sid={}: {}",
                self.seq,
                sid,
                e
            ));
        }

        self.active_streams.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(stream_task(Arc::clone(self), sid, stream_half, rx));
        debug!("AnyTLS session {} opened sid={}", self.seq, sid);
        Ok(client_half)
    }

    /// Unregister a stream, optionally notifying the server with FIN, and
    /// restart the idle clock when the last stream is gone. Called exactly
    /// once per stream task.
    async fn end_stream(&self, sid: u32, notify_fin: bool) {
        let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
        // No FIN back when the server already closed its side (dispatch_fin
        // leaves the entry registered; `notify_fin` distinguishes the
        // client-initiated close) or when the whole session is gone.
        if notify_fin && was_registered && !self.is_closed() {
            let _ = self.write_frame(CMD_FIN, sid, &[]).await;
        }
        if self.active_streams.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.touch_idle();
        }
        debug!("AnyTLS session {} sid={} stream ended", self.seq, sid);
    }

    /// Close the session: flag it, drop all stream dispatch channels (their
    /// tasks EOF the client side and exit), stop the demux, shut down the
    /// write half, and remove the session from the pool. Idempotent.
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.streams.lock().unwrap().clear();
        if let Some(handle) = self.demux.lock().unwrap().take() {
            handle.abort();
        }
        let writer = Arc::clone(&self.writer);
        tokio::spawn(async move {
            let _ = writer.lock().await.shutdown().await;
        });
        if let Some(pool) = self.pool.upgrade() {
            pool.remove(&self.addr, self.seq);
        }
        debug!("AnyTLS session {} for {} closed", self.seq, self.addr);
    }

    /// Deliver a server payload frame to its stream.
    fn dispatch_data(&self, sid: u32, data: Vec<u8>) {
        let tx = self.streams.lock().unwrap().get(&sid).cloned();
        match tx {
            Some(tx) => {
                if tx.send(StreamEvent::Data(data)).is_err() {
                    // Stream task died without unregistering; clean up.
                    self.streams.lock().unwrap().remove(&sid);
                }
            }
            None => {
                debug!(
                    "AnyTLS session {} PSH for unknown sid={} ({} bytes)",
                    self.seq,
                    sid,
                    data.len()
                );
            }
        }
    }

    /// Deliver a server FIN to its stream. The stream task unregisters
    /// itself when it processes the event.
    fn dispatch_fin(&self, sid: u32) {
        let tx = self.streams.lock().unwrap().get(&sid).cloned();
        if let Some(tx) = tx {
            let _ = tx.send(StreamEvent::Fin);
        }
    }
}

/// Session receive loop (sing `Session.recvLoop`): read frames and dispatch
/// by sid. Any read failure or server ALERT closes the whole session.
async fn session_demux(session: Arc<AnyTlsSession>, mut read: BoxedReader) {
    loop {
        let (cmd, sid, data) = match read_frame(&mut read).await {
            Ok(frame) => frame,
            Err(e) => {
                debug!("AnyTLS session {} demux read failed: {}", session.seq, e);
                break;
            }
        };
        match cmd {
            CMD_PSH => session.dispatch_data(sid, data),
            CMD_FIN => session.dispatch_fin(sid),
            CMD_SYNACK => {
                // sing: a SYNACK carrying data reports a dial error for the
                // stream (an empty SYNACK is a pure handshake ack — ignore).
                if !data.is_empty() {
                    debug!(
                        "AnyTLS session {} sid={} remote dial error: {}",
                        session.seq,
                        sid,
                        String::from_utf8_lossy(&data)
                    );
                    session.dispatch_fin(sid);
                }
            }
            CMD_HEART_REQUEST => {
                if session
                    .write_frame(CMD_HEART_RESPONSE, sid, &[])
                    .await
                    .is_err()
                {
                    break;
                }
            }
            CMD_ALERT => {
                warn!(
                    "AnyTLS session {} alert from server: {}",
                    session.seq,
                    String::from_utf8_lossy(&data)
                );
                break;
            }
            CMD_WASTE
            | CMD_SETTINGS
            | CMD_SERVER_SETTINGS
            | CMD_HEART_RESPONSE
            | CMD_UPDATE_PADDING_SCHEME
            | CMD_SYN => {
                // Session-level noise; ignored (sing parity).
            }
            other => {
                debug!(
                    "AnyTLS session {} ignoring unknown cmd {}",
                    session.seq, other
                );
            }
        }
    }
    session.close();
}

/// Per-stream task: pumps client payload into PSH frames and delivers
/// demuxed inbound events to the client. Client EOF closes the stream with
/// FIN (the session stays open for other streams); server FIN or session
/// teardown EOFs the client read side.
async fn stream_task(
    session: Arc<AnyTlsSession>,
    sid: u32,
    mut stream_half: tokio::io::DuplexStream,
    mut rx: mpsc::UnboundedReceiver<StreamEvent>,
) {
    let mut buf = vec![0u8; 65536];
    let mut notify_fin = false;
    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Some(StreamEvent::Data(data)) => {
                        if let Err(e) = stream_half.write_all(&data).await {
                            debug!("AnyTLS sid={} client write failed: {}", sid, e);
                            // The client is gone; tell the server to drop
                            // the stream.
                            notify_fin = true;
                            break;
                        }
                    }
                    Some(StreamEvent::Fin) | None => {
                        // Server closed the stream, or the session died and
                        // dropped the dispatch channels.
                        let _ = stream_half.shutdown().await;
                        break;
                    }
                }
            }
            n = stream_half.read(&mut buf) => {
                match n {
                    Ok(0) => {
                        // Client finished: close the stream, keep the session.
                        notify_fin = true;
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = session.write_frame(CMD_PSH, sid, &buf[..n]).await {
                            debug!("AnyTLS sid={} PSH write failed: {}", sid, e);
                            session.close();
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("AnyTLS sid={} client read failed: {}", sid, e);
                        notify_fin = true;
                        break;
                    }
                }
            }
        }
    }
    session.end_stream(sid, notify_fin).await;
}

/// Per-node pool of multiplexed AnyTLS sessions.
struct AnyTlsSessionPool {
    sessions: Mutex<HashMap<String, Vec<Arc<AnyTlsSession>>>>,
}

impl AnyTlsSessionPool {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, addr: &str, session: Arc<AnyTlsSession>) {
        self.sessions
            .lock()
            .unwrap()
            .entry(addr.to_string())
            .or_default()
            .push(session);
    }

    fn remove(&self, addr: &str, seq: u64) {
        let mut guard = self.sessions.lock().unwrap();
        if let Some(list) = guard.get_mut(addr) {
            list.retain(|s| s.seq != seq);
            if list.is_empty() {
                guard.remove(addr);
            }
        }
    }

    /// Pick a live session for `addr` — the one with the fewest open
    /// streams (spreads load and naturally skips closed-but-unreaped
    /// sessions). Returns `None` when no healthy session exists.
    fn acquire_session(&self, addr: &str) -> Option<Arc<AnyTlsSession>> {
        let guard = self.sessions.lock().unwrap();
        guard
            .get(addr)?
            .iter()
            .filter(|s| !s.is_closed())
            .min_by_key(|s| s.active_streams())
            .cloned()
    }

    /// Number of live sessions with no open streams (janitor min_idle
    /// bookkeeping).
    fn idle_count(&self, addr: &str) -> usize {
        let guard = self.sessions.lock().unwrap();
        guard
            .get(addr)
            .map(|list| {
                list.iter()
                    .filter(|s| !s.is_closed() && s.active_streams() == 0)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Number of sessions currently tracked for `addr` (tests).
    #[cfg(test)]
    fn session_count(&self, addr: &str) -> usize {
        let guard = self.sessions.lock().unwrap();
        guard.get(addr).map(|v| v.len()).unwrap_or(0)
    }

    /// Split `sessions` into (kept, to_close) per the janitor policy
    /// (sing-anytls `idleCleanupExpTime` parity, iterating newest first):
    /// closed sessions always go; sessions with no open streams idle for
    /// longer than `idle_timeout` go too, except the `min_idle` most
    /// recently used ones, whose idle clock is refreshed instead. Sessions
    /// with open streams are always kept and do not consume the `min_idle`
    /// budget (it applies to idle sessions only, as in sing).
    fn prune_sessions(
        sessions: &[Arc<AnyTlsSession>],
        min_idle: usize,
        idle_timeout: Duration,
    ) -> (Vec<Arc<AnyTlsSession>>, Vec<Arc<AnyTlsSession>>) {
        let mut kept = Vec::with_capacity(sessions.len());
        let mut to_close = Vec::new();
        let mut idle_kept = 0usize;
        // Vec order is creation order (oldest first); iterate newest first.
        for s in sessions.iter().rev() {
            if s.is_closed() {
                to_close.push(Arc::clone(s));
                continue;
            }
            let idle = s.active_streams() == 0;
            let expired = idle && s.idle_for() >= idle_timeout;
            if !idle {
                // Serving streams — never reaped by the idle janitor.
                kept.push(Arc::clone(s));
            } else if !expired || idle_kept < min_idle {
                if expired {
                    // Kept within the min_idle budget: refresh its clock.
                    s.touch_idle();
                }
                idle_kept += 1;
                kept.push(Arc::clone(s));
            } else {
                to_close.push(Arc::clone(s));
            }
        }
        kept.reverse();
        (kept, to_close)
    }

    /// Spawn a background janitor task that periodically prunes expired
    /// sessions and maintains `min_idle` sessions per node.
    ///
    /// The returned `JoinHandle` resolves when the janitor exits (only on
    /// `AnyTlsSessionPool` drop / cancellation).
    fn spawn_janitor(self: &Arc<Self>, node: Node) -> JoinHandle<()> {
        let pool = Arc::clone(self);
        let addr = format!("{}:{}", node.host(), node.port);
        let min_idle = node.anytls_min_idle_session.unwrap_or(0);
        let check_interval = Duration::from_secs(
            node.anytls_idle_session_check_interval
                .unwrap_or(DEFAULT_IDLE_CHECK_INTERVAL_SECS),
        );
        let idle_timeout = Duration::from_secs(
            node.anytls_idle_session_timeout
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        );

        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            // First tick fires immediately.
            interval.tick().await;

            loop {
                interval.tick().await;

                // Prune closed/expired sessions. Closing happens outside
                // the pool lock: `close()` re-enters it via `pool.remove`.
                let to_close = {
                    let mut guard = pool.sessions.lock().unwrap();
                    match guard.get_mut(&addr) {
                        Some(list) => {
                            let (kept, to_close) =
                                Self::prune_sessions(list, min_idle, idle_timeout);
                            *list = kept;
                            to_close
                        }
                        None => Vec::new(),
                    }
                };
                for session in to_close {
                    debug!(
                        "AnyTLS pool janitor: reaping session {} for {}",
                        session.seq, addr,
                    );
                    session.close();
                }

                let current = pool.idle_count(&addr);
                if current < min_idle {
                    let needed = min_idle - current;
                    debug!(
                        "AnyTLS pool janitor: replenishing {} sessions for {}",
                        needed, addr,
                    );
                    for _ in 0..needed {
                        match pre_establish_session(&node, &addr, Duration::from_secs(10)).await {
                            Ok(()) => {}
                            Err(e) => {
                                warn!(
                                    "AnyTLS pool janitor: failed to pre-establish session for {}: {}",
                                    addr, e,
                                );
                                break;
                            }
                        }
                    }
                }
            }
        })
    }
}

/// Pre-establish a fresh TLS + AnyTLS session and register it in the pool.
async fn pre_establish_session(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
) -> anyhow::Result<()> {
    let (read, write, auth, settings) =
        connect_transport(node, addr, connect_timeout, None).await?;
    AnyTlsSession::establish(&SESSION_POOL, addr, read, write, &auth, &settings).await?;
    Ok(())
}

/// Connect to the AnyTLS server (using `tcp` when the caller provides a
/// pre-connected stream) and wrap the connection in TLS. Returns boxed
/// transport halves plus the auth blob and settings payload needed for
/// session establishment.
async fn connect_transport(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
    tcp: Option<TcpStream>,
) -> anyhow::Result<(BoxedReader, BoxedWriter, Vec<u8>, Vec<u8>)> {
    let password = AnyTlsHandler::resolve_password(node);
    let auth_key = Sha256::digest(password.as_bytes());

    let tcp = match tcp {
        Some(tcp) => tcp,
        None => crate::util::connect_outbound(addr, connect_timeout).await?,
    };
    debug!("AnyTLS: TCP connected to {}", addr);

    let connector = AnyTlsHandler::build_tls_connector(node)?;
    let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
    let tls = connector.connect(&server_name, tcp).await?;
    debug!("AnyTLS: TLS handshake completed with {}", addr);
    let (read, write) = tokio::io::split(tls);

    let mut auth = Vec::with_capacity(34);
    auth.extend_from_slice(&auth_key);
    auth.extend_from_slice(&[0u8; 2]);

    let settings = AnyTlsHandler::settings_payload();
    Ok((Box::new(read), Box::new(write), auth, settings))
}

impl AnyTlsHandler {
    /// Create a new AnyTLS handler.
    pub fn new() -> Self {
        Self
    }

    /// Resolve the AnyTLS password: generic password first, then the
    /// AnyTLS-specific field.
    fn resolve_password(node: &Node) -> &str {
        node.password
            .as_deref()
            .or(node.anytls_password.as_deref())
            .unwrap_or("")
    }

    /// Build the TLS connector for the node.
    fn build_tls_connector(node: &Node) -> anyhow::Result<TlsConnector> {
        crate::tls::build_connector(node)
    }

    /// Encode the target address in SOCKS5-style format.
    fn encode_address(target: SocketAddr, target_domain: Option<&str>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(19);
        if let Some(domain) = target_domain {
            buf.push(0x03);
            buf.push(domain.len().min(u8::MAX as usize) as u8);
            buf.extend_from_slice(domain.as_bytes());
        } else {
            match target {
                SocketAddr::V4(v4) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buf.push(0x04);
                    buf.extend_from_slice(&v6.ip().octets());
                }
            }
        }
        buf.extend_from_slice(&target.port().to_be_bytes());
        buf
    }

    /// Build the client settings frame payload.
    fn settings_payload() -> Vec<u8> {
        let scheme = b"stop=0\n";
        let md5 = md5_hex(scheme);
        format!("v=2\nclient=dae\npadding-md5={}\n", md5).into_bytes()
    }
    /// Lazily start the pool janitor for this node (once per address).
    fn ensure_janitor(node: &Node) {
        let min_idle = node.anytls_min_idle_session.unwrap_or(0);
        if min_idle == 0 {
            return;
        }
        let addr = format!("{}:{}", node.host(), node.port);
        {
            let mut guard = JANITORS.lock().unwrap();
            if !guard.insert(addr.clone()) {
                return; // janitor already running for this address
            }
        }
        debug!(
            "AnyTLS pool: starting janitor for {} (min_idle={})",
            addr, min_idle
        );
        SESSION_POOL.spawn_janitor(node.clone());
    }

    /// Open a stream to `target_addr`, multiplexing onto a healthy pooled
    /// session when one exists.
    async fn open_pooled_stream(
        addr: &str,
        target_addr: &[u8],
    ) -> anyhow::Result<Option<tokio::io::DuplexStream>> {
        let Some(session) = SESSION_POOL.acquire_session(addr) else {
            return Ok(None);
        };
        match session.open_stream(target_addr.to_vec()).await {
            Ok(stream) => {
                debug!(
                    "AnyTLS: multiplexing on session {} for {} ({} open stream(s))",
                    session.seq,
                    addr,
                    session.active_streams(),
                );
                Ok(Some(stream))
            }
            Err(e) => {
                debug!(
                    "AnyTLS: pooled session for {} unusable ({}); dialing fresh",
                    addr, e
                );
                Ok(None)
            }
        }
    }
}

/// Bridge task for UoT: forwards payloads between the loopback UDP socket
/// and length-prefixed datagrams on the AnyTLS stream. Ends on error, EOF,
/// or after [`UDP_BRIDGE_IDLE_SECS`] without activity.
async fn uot_bridge(
    stream: tokio::io::DuplexStream,
    internal: tokio::net::UdpSocket,
    external_addr: SocketAddr,
) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader = tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 2];
            if rd.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            if rd.read_exact(&mut data).await.is_err() {
                break;
            }
            if tx.send(data).is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            result = internal.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if src != external_addr {
                            continue;
                        }
                        let len = (n as u16).to_be_bytes();
                        if wr.write_all(&len).await.is_err()
                            || wr.write_all(&buf[..n]).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if internal.send_to(&data, external_addr).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = time::sleep(Duration::from_secs(UDP_BRIDGE_IDLE_SECS)) => break,
        }
    }
    reader.abort();
}

#[async_trait]
impl ProxyHandler for AnyTlsHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::AnyTLS
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        let target_addr = Self::encode_address(target, target_domain);

        if let Some(stream) = Self::open_pooled_stream(&addr, &target_addr).await? {
            return Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(|s| s.to_string()),
            });
        }

        // Pool miss – make sure the janitor keeps the pool filled, then
        // establish a fresh session and open the stream on it.
        Self::ensure_janitor(node);

        debug!(
            "AnyTLS: connecting to {} for target {} (tls={} sni={:?} skip={})",
            addr, target, node.tls, node.sni, node.skip_cert_verify
        );
        let (read, write, auth, settings) =
            connect_transport(node, &addr, connect_timeout, None).await?;
        let session =
            AnyTlsSession::establish(&SESSION_POOL, &addr, read, write, &auth, &settings).await?;
        let stream = session.open_stream(target_addr).await?;

        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        let target_addr = Self::encode_address(target, target_domain);

        // Try the session pool first (ignoring the provided TCP since we
        // have a faster path via a pre-established session).
        if let Some(stream) = Self::open_pooled_stream(&addr, &target_addr).await? {
            drop(tcp);
            return Ok(ProxyStream {
                stream: Box::new(stream),
                target_addr: target,
                target_domain: target_domain.map(|s| s.to_string()),
            });
        }

        Self::ensure_janitor(node);

        let (read, write, auth, settings) =
            connect_transport(node, &addr, _connect_timeout, Some(tcp)).await?;
        let session =
            AnyTlsSession::establish(&SESSION_POOL, &addr, read, write, &auth, &settings).await?;
        let stream = session.open_stream(target_addr).await?;

        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        // sing-box enforces the network list: no UDP when the node is
        // tcp-only.
        if let Some(ref network) = node.network
            && !network
                .split(',')
                .any(|n| n.trim().eq_ignore_ascii_case("udp"))
        {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        let addr = format!("{}:{}", node.host(), node.port);
        // The stream target is the UoT magic address (SOCKS5 address form).
        let magic = Self::encode_address("0.0.0.0:0".parse().unwrap(), Some(UOT_MAGIC));
        let mut stream = if let Some(s) = Self::open_pooled_stream(&addr, &magic).await? {
            s
        } else {
            Self::ensure_janitor(node);
            let (read, write, auth, settings) =
                connect_transport(node, &addr, connect_timeout, None).await?;
            let session =
                AnyTlsSession::establish(&SESSION_POOL, &addr, read, write, &auth, &settings)
                    .await?;
            session.open_stream(magic).await?
        };

        // UoT request: isConnect=true + destination in SOCKS5 address form.
        // sing's uot.ReadRequest parses the destination with
        // M.SocksaddrSerializer (0x01/0x03/0x04), not the per-packet
        // AddrParser form (0x00/0x01/0x02) — the latter only appears on
        // isConnect=false packets, which we never send.
        let mut request = vec![1u8];
        request.extend(Self::encode_address(target, target_domain));
        tokio::time::timeout(connect_timeout, stream.write_all(&request)).await??;

        // Bridge a loopback UDP socket to length-prefixed datagrams on the
        // stream: the relay talks raw payloads to `relay_addr`, the bridge
        // frames them onto the AnyTLS stream.
        let external = crate::util::udp_loopback_bind().await?;
        let internal = crate::util::udp_loopback_bind().await?;
        let external_addr = external.local_addr()?;
        let relay_addr = internal.local_addr()?;
        tokio::spawn(uot_bridge(stream, internal, external_addr));

        Ok(UdpProxySocket {
            socket: Arc::new(external),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
            _control: None,
        })
    }

    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_) => true,
            Err(e) => {
                debug!("AnyTLS connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

/// Write a single AnyTLS frame.
async fn write_frame<W>(writer: &mut W, cmd: u8, sid: u32, data: &[u8]) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = cmd;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    if !data.is_empty() {
        writer.write_all(data).await?;
    }
    Ok(())
}

/// Read a single AnyTLS frame.
async fn read_frame<R>(reader: &mut R) -> std::io::Result<(u8, u32, Vec<u8>)>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; len];
    if len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok((cmd, sid, data))
}

/// Compute the lowercase hex MD5 digest of a byte slice.
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let hash = Md5::digest(data);
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_address_encoding_ipv4() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443));
        let encoded = AnyTlsHandler::encode_address(target, None);
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..5], &[93, 184, 216, 34]);
        assert_eq!(&encoded[5..7], &[0x01, 0xbb]);
    }

    #[test]
    fn test_address_encoding_domain() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80));
        let encoded = AnyTlsHandler::encode_address(target, Some("example.com"));
        assert_eq!(encoded[0], 0x03);
        assert_eq!(encoded[1], 11);
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(&encoded[13..15], &[0x00, 0x50]);
    }

    #[test]
    fn test_settings_payload_format() {
        let payload = String::from_utf8(AnyTlsHandler::settings_payload()).unwrap();
        assert!(payload.contains("v=2"));
        assert!(payload.contains("client=dae"));
        assert!(payload.contains("padding-md5="));
    }

    #[test]
    fn test_resolve_password_fallback() {
        let mut node = Node {
            name: "test".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        assert_eq!(AnyTlsHandler::resolve_password(&node), "");

        node.anytls_password = Some("anytls-secret".into());
        assert_eq!(AnyTlsHandler::resolve_password(&node), "anytls-secret");

        // Generic password wins when both are set.
        node.password = Some("generic-secret".into());
        assert_eq!(AnyTlsHandler::resolve_password(&node), "generic-secret");

        node.anytls_password = None;
        assert_eq!(AnyTlsHandler::resolve_password(&node), "generic-secret");
    }

    const TEST_AUTH: &[u8] = b"test-auth";
    const TEST_SETTINGS: &[u8] = b"test-settings";

    /// Establish a session over an in-memory duplex; returns the session
    /// and the server end of the transport.
    async fn establish_test_session(
        pool: &Arc<AnyTlsSessionPool>,
        addr: &str,
    ) -> (Arc<AnyTlsSession>, tokio::io::DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(client_end);
        let session = AnyTlsSession::establish(
            pool,
            addr,
            Box::new(read),
            Box::new(write),
            TEST_AUTH,
            TEST_SETTINGS,
        )
        .await
        .unwrap();
        (session, server_end)
    }

    /// Assert the session opened with the auth blob + settings frame.
    async fn expect_handshake(server: &mut tokio::io::DuplexStream) {
        let mut auth = vec![0u8; TEST_AUTH.len()];
        server.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, TEST_AUTH);
        let (cmd, sid, data) = read_frame(server).await.unwrap();
        assert_eq!(cmd, CMD_SETTINGS);
        assert_eq!(sid, 0);
        assert_eq!(data, TEST_SETTINGS);
    }

    /// A fake AnyTLS server: consumes each SYN and its address PSH (the
    /// address is forwarded to `addr_tx`), echoes payload PSHs back to the
    /// same sid, and answers FIN with FIN.
    fn spawn_echo_server(
        mut server: tokio::io::DuplexStream,
    ) -> mpsc::UnboundedReceiver<(u32, Vec<u8>)> {
        let (addr_tx, addr_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut pending_addr: HashSet<u32> = HashSet::new();
            let mut known: HashSet<u32> = HashSet::new();
            loop {
                let Ok((cmd, sid, data)) = read_frame(&mut server).await else {
                    break;
                };
                match cmd {
                    CMD_SYN => {
                        known.insert(sid);
                        pending_addr.insert(sid);
                    }
                    CMD_PSH if pending_addr.remove(&sid) => {
                        // First PSH after SYN: the target address.
                        addr_tx.send((sid, data)).unwrap();
                    }
                    CMD_PSH if known.contains(&sid) => {
                        write_frame(&mut server, CMD_PSH, sid, &data).await.unwrap();
                    }
                    CMD_FIN if known.contains(&sid) => {
                        known.remove(&sid);
                        write_frame(&mut server, CMD_FIN, sid, &[]).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
        addr_rx
    }

    #[tokio::test]
    async fn test_pool_acquire_empty() {
        let pool = AnyTlsSessionPool::new();
        assert!(pool.acquire_session("127.0.0.1:9999").is_none());
    }

    #[tokio::test]
    async fn test_establish_registers_and_acquires() {
        let pool = Arc::new(AnyTlsSessionPool::new());
        let addr = "127.0.0.1:1234";
        let (session, mut server) = establish_test_session(&pool, addr).await;
        expect_handshake(&mut server).await;

        assert_eq!(pool.session_count(addr), 1);
        let acquired = pool.acquire_session(addr).expect("session is live");
        assert_eq!(acquired.seq, session.seq);

        // Closing the session evicts it from the pool.
        session.close();
        assert!(pool.acquire_session(addr).is_none());
        assert_eq!(pool.session_count(addr), 0);
    }

    /// Write `payload` on `stream` and assert it echoes back intact.
    async fn echo(stream: &mut tokio::io::DuplexStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(buf, payload);
    }

    /// Three concurrent streams multiplexed on one session, echoing in
    /// parallel (sing-anytls semantics).
    #[tokio::test]
    async fn test_concurrent_streams_on_one_session() {
        let pool = Arc::new(AnyTlsSessionPool::new());
        let addr = "127.0.0.1:443";
        let (session, mut server) = establish_test_session(&pool, addr).await;
        expect_handshake(&mut server).await;
        let mut addr_rx = spawn_echo_server(server);

        // Open three streams concurrently on the same session.
        let target = |b: u8| vec![0x01, 127, 0, 0, b, 0x01, 0xbb];
        let (s1, s2, s3) = tokio::join!(
            session.open_stream(target(1)),
            session.open_stream(target(2)),
            session.open_stream(target(3)),
        );
        let (mut s1, mut s2, mut s3) = (s1.unwrap(), s2.unwrap(), s3.unwrap());
        assert_eq!(session.active_streams(), 3);

        // Each SYN was followed by its own address PSH.
        let mut addrs = Vec::new();
        for _ in 0..3 {
            let (sid, a) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
                .await
                .expect("address frame")
                .unwrap();
            addrs.push((sid, a));
        }
        addrs.sort_by_key(|(sid, _)| *sid);
        assert_eq!(addrs[0].1, target(1));
        assert_eq!(addrs[1].1, target(2));
        assert_eq!(addrs[2].1, target(3));

        // Distinct payloads echoed back on the right stream, in parallel.
        tokio::join!(
            echo(&mut s1, b"hello-one"),
            echo(&mut s2, b"hello-two-two"),
            echo(&mut s3, b"hello-three-three-three"),
        );

        // Closing all streams ends them (FIN handshake) and idles the
        // session without closing it.
        drop(s1);
        drop(s2);
        drop(s3);
        tokio::time::timeout(Duration::from_secs(2), async {
            while session.active_streams() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("streams drain");
        assert!(!session.is_closed());
        assert_eq!(pool.idle_count(addr), 1);

        // The same session serves another stream afterwards.
        let mut s4 = session.open_stream(target(4)).await.unwrap();
        let (sid, a) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .expect("address frame")
            .unwrap();
        assert_eq!(sid, 4);
        assert_eq!(a, target(4));
        echo(&mut s4, b"again").await;
    }

    /// A server-side FIN closes only that stream; sibling streams and the
    /// session itself are unaffected.
    #[tokio::test]
    async fn test_server_fin_closes_only_that_stream() {
        let pool = Arc::new(AnyTlsSessionPool::new());
        let addr = "127.0.0.1:1443";
        let (session, mut server) = establish_test_session(&pool, addr).await;
        expect_handshake(&mut server).await;

        let target = vec![0x01, 127, 0, 0, 1, 0x00, 0x50];
        let mut s1 = session.open_stream(target.clone()).await.unwrap();
        let mut s2 = session.open_stream(target.clone()).await.unwrap();

        // Server: consume both opening sequences, then FIN sid=1 only.
        for expected_sid in 1..=2u32 {
            let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
            assert_eq!((cmd, sid), (CMD_SYN, expected_sid));
            let (cmd, psid, _) = read_frame(&mut server).await.unwrap();
            assert_eq!((cmd, psid), (CMD_PSH, expected_sid));
        }
        write_frame(&mut server, CMD_FIN, 1, &[]).await.unwrap();

        // s1 sees EOF; s2 still echoes.
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), s1.read(&mut b))
            .await
            .expect("s1 EOF")
            .unwrap();
        assert_eq!(n, 0);

        s2.write_all(b"still-here").await.unwrap();
        // Server side: read the PSH and echo it back.
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, sid), (CMD_PSH, 2));
        assert_eq!(data, b"still-here");
        write_frame(&mut server, CMD_PSH, 2, &data).await.unwrap();
        let mut buf = vec![0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), s2.read_exact(&mut buf))
            .await
            .expect("s2 echo")
            .unwrap();
        assert_eq!(buf, b"still-here");

        assert!(!session.is_closed());
        assert_eq!(session.active_streams(), 1);
    }

    /// Janitor pruning: closed sessions go, idle-expired sessions go beyond
    /// the min_idle newest, active sessions are always kept.
    #[tokio::test]
    async fn test_prune_sessions_policy() {
        let pool = Arc::new(AnyTlsSessionPool::new());
        let addr = "127.0.0.1:2443";

        // Three idle sessions (creation order: s1 oldest … s3 newest),
        // one with an open stream, one already closed.
        let mut sessions = Vec::new();
        for _ in 0..3 {
            let (s, _server) = establish_test_session(&pool, addr).await;
            sessions.push(s);
        }
        let (active, _server) = establish_test_session(&pool, addr).await;
        // Give the "active" session a real open stream (SYN+PSH just lands
        // in the in-memory transport buffer — no server needed).
        let _open = active
            .open_stream(vec![0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        let (closed, server) = establish_test_session(&pool, addr).await;
        drop(server);
        closed.close();
        sessions.push(Arc::clone(&active));
        sessions.push(closed.clone());

        // idle_timeout = 0 → every idle session is expired. min_idle = 1.
        let (kept, to_close) =
            AnyTlsSessionPool::prune_sessions(&sessions, 1, Duration::from_secs(0));

        // Kept: the active session plus the single newest idle one.
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|s| s.seq == active.seq));
        assert!(!kept.iter().any(|s| s.seq == closed.seq));
        // Closed + two older idle sessions reaped.
        assert_eq!(to_close.len(), 3);
        assert!(to_close.iter().any(|s| s.seq == closed.seq));
        // The min_idle-kept session had its idle clock refreshed.
        let kept_idle = kept.iter().find(|s| s.seq != active.seq).unwrap();
        assert!(kept_idle.idle_for() < Duration::from_secs(5));

        // With min_idle = 0 everything idle is reaped; the active one stays.
        let (kept, to_close) =
            AnyTlsSessionPool::prune_sessions(&sessions, 0, Duration::from_secs(0));
        assert_eq!(kept.len(), 1);
        assert_eq!(to_close.len(), 4);
    }
}

#[cfg(test)]
mod uot_tests {
    use super::*;

    #[test]
    fn test_uot_request_uses_socks5_address_form() {
        // sing uot.ReadRequest parses the request destination with
        // M.SocksaddrSerializer (SOCKS5 ATYP), so the bytes a dial_udp
        // request carries after the isConnect byte must be SOCKS5 form.
        let v4 = AnyTlsHandler::encode_address("1.2.3.4:53".parse().unwrap(), None);
        assert_eq!(v4, vec![0x01, 1, 2, 3, 4, 0, 53]);
        let v6 = AnyTlsHandler::encode_address("[2606:4700:4700::1111]:853".parse().unwrap(), None);
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 1 + 16 + 2);
        let fqdn =
            AnyTlsHandler::encode_address("1.2.3.4:443".parse().unwrap(), Some("example.com"));
        assert_eq!(fqdn[0], 0x03);
        assert_eq!(fqdn[1], 11);
        assert_eq!(&fqdn[2..13], b"example.com");
        assert_eq!(&fqdn[13..], &[1, 187]);
    }

    /// The bridge frames loopback payloads as UoT datagrams and delivers
    /// inbound datagrams back to the loopback peer.
    #[tokio::test]
    async fn test_uot_bridge_roundtrip() {
        let (client_half, mut server_half) = tokio::io::duplex(65536);
        let external = crate::util::udp_loopback_bind().await.unwrap();
        let internal = crate::util::udp_loopback_bind().await.unwrap();
        let external_addr = external.local_addr().unwrap();
        let relay_addr = internal.local_addr().unwrap();
        tokio::spawn(uot_bridge(client_half, internal, external_addr));

        // Outbound: payload from the loopback peer becomes [len][payload].
        external.send_to(b"ping", relay_addr).await.unwrap();
        let mut head = [0u8; 2];
        server_half.read_exact(&mut head).await.unwrap();
        assert_eq!(u16::from_be_bytes(head), 4);
        let mut payload = vec![0u8; 4];
        server_half.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        // Inbound: [len][payload] from the stream is delivered to the peer.
        server_half.write_all(&[0, 4]).await.unwrap();
        server_half.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = external.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from, relay_addr);
    }
}
