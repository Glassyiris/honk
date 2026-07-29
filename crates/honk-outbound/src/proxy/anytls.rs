//! AnyTLS proxy handler with sing-anytls session multiplexing.
//!
//! One TLS session carries any number of concurrent streams, each identified
//! by a stream id (`sid`) — sing-anytls `session/session.go` semantics:
//!
//! - a per-session **demux task** reads frames and dispatches them by `sid`
//!   (`PSH` → stream payload, `FIN` → stream EOF, heartbeats answered at
//!   session level);
//! - an atomic `sid` allocator hands out stream ids (starting at 1);
//! - every frame goes out through the single ordered **writer task** (an
//!   ordered command queue — no cross-stream mutex, and a cancelled caller
//!   can never truncate a queued frame);
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
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::addr;
use super::{PacketTransport, ProxyHandler, ProxyStream, UdpProxySocket};
use crate::session::ManagedSession as _;

/// sing uot v2 magic address (`protocol/anytls/outbound.go`,
/// `common/uot/protocol.go`): UDP-over-TCP streams are opened to this
/// pseudo-target inside the AnyTLS session.
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

/// UoT v1 packet address types (sing uot v1 / non-connect form).
const UOT_V1_ATYP_V4: u8 = 0x00;
const UOT_V1_ATYP_V6: u8 = 0x01;
const UOT_V1_ATYP_DOMAIN: u8 = 0x02;
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
/// Per-stream demux queue depth (frames). A full queue applies bounded
/// backpressure to the session demux (see [`HOL_STALL_TIMEOUT`]) instead
/// of growing without bound.
const STREAM_QUEUE_CAP: usize = 64;

/// Transport halves behind trait objects so tests can drive a session over
/// an in-memory duplex instead of a real TLS connection.
type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// AnyTLS proxy handler. Stateless except for the runtime-registry
/// handle (installed by the control plane) and a fallback pool used when
/// no registry is installed (unit tests, standalone use).
#[derive(Debug, Default, Clone)]
pub struct AnyTlsHandler {
    runtime_registry: Arc<parking_lot::RwLock<Option<crate::runtime::SharedRuntimeRegistry>>>,
    fallback_pool: std::sync::OnceLock<Arc<AnyTlsPool>>,
}

impl AnyTlsHandler {
    /// The session pool for `node`: its runtime-registry pool when the
    /// control plane installed one, otherwise this handler's own.
    fn node_pool(&self, node: &Node) -> anyhow::Result<Arc<AnyTlsPool>> {
        if let Some(cell) = self.runtime_registry.read().as_ref() {
            let runtime = cell
                .read()
                .get(&node.id)
                .ok_or_else(|| anyhow::anyhow!("node '{}' not in runtime registry", node.name))?;
            return match &runtime.runtime {
                crate::runtime::ProtocolRuntime::AnyTls(rt) => Ok(Arc::clone(&rt.pool)),
                crate::runtime::ProtocolRuntime::None => Err(anyhow::anyhow!(
                    "node '{}' has no AnyTLS runtime",
                    node.name
                )),
            };
        }
        Ok(Arc::clone(self.fallback_pool.get_or_init(|| {
            Arc::new(crate::session::SessionPool::new(session_pool_config()))
        })))
    }
}

/// Key inside a node's own session pool. Pools are per-node (runtime
/// registry), so the key is a constant — the old `host:port|tls|sni|
/// pwhash|verify` fingerprint existed only to disambiguate the shared
/// static pool, and it also kept a password hash around for no reason.
pub(crate) const POOL_KEY: &str = "self";

/// Pool configuration for one AnyTLS node (least-loaded scheduling
/// without a stream cap (sing-anytls parity); the hard session cap still
/// applies). Shared by the runtime-registry pools and handler fallbacks.
pub(crate) fn session_pool_config() -> crate::session::SessionPoolConfig {
    crate::session::SessionPoolConfig {
        // v3.1 sizing: two sessions per node, 128 streams each (initial
        // values, tune by load test). The per-session semaphore is the
        // capacity truth; this cap only steers least-loaded scheduling.
        max_sessions: 2,
        max_streams_per_session: MAX_STREAMS_PER_SESSION,
        janitor_interval: Duration::from_secs(DEFAULT_IDLE_CHECK_INTERVAL_SECS),
        // Sessions rotate out after ~30 min (jittered ±10% per session,
        // so a batch of same-age sessions never reconnects in lockstep).
        max_session_age: Some(Duration::from_secs(30 * 60)),
        ..Default::default()
    }
}

/// Monotonic session id for pool bookkeeping (sing `sessionCounter`).
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Inbound events delivered from the session demux to a stream task.
#[derive(Debug)]
enum StreamEvent {
    /// Server payload for this stream.
    Data(Vec<u8>),
    /// Server closed the stream (clean FIN).
    Fin,
    /// Stream-level failure: server-reported open error (SYNACK with
    /// data) or a local HOL kill. Surfaces as a read error, not a clean
    /// EOF (a truncated TCP stream must never look like a clean close).
    Error(Arc<anyhow::Error>),
}

/// Per-stream demux delivery channel.
#[derive(Clone)]
enum StreamSink {
    /// TCP streams: bounded queue with bounded backpressure (payload
    /// must not be dropped; a consumer stalled past `HOL_STALL_TIMEOUT`
    /// gets only its own stream killed).
    Tcp(mpsc::Sender<StreamEvent>),
    /// UoT streams: drop-on-full (UDP semantics) — a slow consumer must
    /// never backpressure the session demux, or one hot UDP flow wedges
    /// every stream on the session (production h3 stall).
    Uot(mpsc::Sender<StreamEvent>),
}

impl StreamSink {
    /// Deliver a payload frame: demux-bounded for TCP, drop-on-full for UoT.
    /// Returns false when the receiver is gone (stream died unregistered).
    async fn send_data(&self, data: Vec<u8>) -> bool {
        match self {
            StreamSink::Tcp(tx) => tx.send(StreamEvent::Data(data)).await.is_ok(),
            StreamSink::Uot(tx) => match tx.try_send(StreamEvent::Data(data)) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            },
        }
    }

    /// Deliver a FIN (never dropped — close semantics matter).
    async fn send_fin(&self) {
        match self {
            StreamSink::Tcp(tx) => {
                let _ = tx.send(StreamEvent::Fin).await;
            }
            StreamSink::Uot(tx) => {
                let _ = tx.try_send(StreamEvent::Fin);
            }
        }
    }

    /// Deliver a stream-level failure (open error). Same delivery
    /// semantics as FIN: never dropped for TCP.
    async fn send_error(&self, err: anyhow::Error) {
        let event = StreamEvent::Error(Arc::new(err));
        match self {
            StreamSink::Tcp(tx) => {
                let _ = tx.send(event).await;
            }
            StreamSink::Uot(tx) => {
                let _ = tx.try_send(event);
            }
        }
    }
}

/// Ownership token for one registered stream id: the session's active
/// count moves exactly once in each direction through this token, and a
/// registration abandoned mid-handshake is cleaned up on Drop. Commit
/// boundaries: TCP streams commit when the SYN+PSH opening pair is
/// written; UoT streams commit only after the UoT request is fully
/// written and the transport is constructed.
struct StreamRegistration {
    session: Arc<AnyTlsSession>,
    sid: u32,
    /// A frame write is in progress: a partial frame may be on the wire.
    frame_started: bool,
    /// Lifecycle handed to the caller; Drop is then a no-op.
    committed: bool,
    /// Stream-slot capacity reserved for this registration. Moves to the
    /// stream on commit; released on an abandoned registration (the
    /// semaphore is the only capacity truth).
    permit: Option<crate::session::SessionPermit<AnyTlsSession>>,
}

impl StreamRegistration {
    /// Hand the lifecycle (and the capacity slot) to the caller's stream.
    fn commit(mut self) -> crate::session::SessionPermit<AnyTlsSession> {
        self.committed = true;
        self.permit.take().expect("registration owns a permit")
    }
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.session.streams.lock().unwrap().remove(&self.sid);
        if self.frame_started {
            // The opening frames are already queued (the writer queue
            // makes partial frames impossible): clean up the server's
            // side with a FIN instead of killing a healthy session.
            let _ = self
                .session
                .enqueue_control(CMD_FIN, self.sid, bytes::Bytes::new());
        }
        // `permit` drops here too: the slot is released exactly once.
    }
}

/// One ordered writer command. Data commands hold a queue permit until
/// popped (bounded → backpressure); control commands ride the reserved
/// headroom so SYN/FIN can never be starved by payload.
enum FrameCommand {
    Data {
        sid: u32,
        payload: bytes::Bytes,
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
    Control {
        cmd: u8,
        sid: u32,
        payload: bytes::Bytes,
    },
}

/// Session writer queue: every frame goes out in enqueue order through a
/// single task — no cross-stream mutex, and a cancelled caller can never
/// truncate a queued frame (only a physical write failure closes the
/// session). Data capacity is `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`;
/// control frames take the reserved headroom.
struct WriterQueue {
    queue: Mutex<std::collections::VecDeque<FrameCommand>>,
    notify: tokio::sync::Notify,
    data_permits: Arc<tokio::sync::Semaphore>,
}

/// Total writer-queue depth (data + control headroom).
const WRITER_QUEUE_CAP: usize = 1024;
/// Slots reserved for control frames (SYN/FIN/HEART) — data can never
/// fill the queue past `WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED`.
const WRITER_CONTROL_RESERVED: usize = 128;

impl WriterQueue {
    fn new() -> Self {
        Self {
            queue: Mutex::new(std::collections::VecDeque::new()),
            notify: tokio::sync::Notify::new(),
            data_permits: Arc::new(tokio::sync::Semaphore::new(
                WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED,
            )),
        }
    }

    /// Push commands atomically as one batch (the SYN+PSH opening pair is
    /// never interleaved with another stream's frame).
    fn push_batch(&self, cmds: impl IntoIterator<Item = FrameCommand>) {
        self.queue.lock().unwrap().extend(cmds);
        self.notify.notify_one();
    }

    async fn pop(&self) -> FrameCommand {
        loop {
            if let Some(cmd) = self.queue.lock().unwrap().pop_front() {
                return cmd;
            }
            self.notify.notified().await;
        }
    }

    fn clear(&self) {
        self.queue.lock().unwrap().clear();
    }
}

/// The single writer task for a session: drains the queue in order,
/// flushing per frame. A physical write failure kills the session (sing
/// `writeControlFrame` parity) — frames already queued are lost with it.
async fn session_writer(
    session: Arc<AnyTlsSession>,
    mut write: BoxedWriter,
    queue: Arc<WriterQueue>,
) {
    loop {
        let cmd = queue.pop().await;
        let (cmd_id, sid, payload) = match &cmd {
            FrameCommand::Data { sid, payload, .. } => (CMD_PSH, *sid, payload),
            FrameCommand::Control { cmd, sid, payload } => (*cmd, *sid, payload),
        };
        let failed = match write_frame(&mut write, cmd_id, sid, payload).await {
            Ok(()) => write.flush().await.is_err(),
            Err(_) => true,
        };
        if failed {
            debug!("AnyTLS session {} writer failed, closing", session.seq);
            session.fail(anyhow::anyhow!("writer task write failed"));
            break;
        }
        if session.is_closed() {
            break;
        }
    }
}

/// Session pool type for one AnyTLS node (runtime-registry owned).
pub(crate) type AnyTlsPool = crate::session::SessionPool<AnyTlsSession>;

/// Per-session stream capacity (v3.1): the semaphore is the single
/// capacity truth — 128 concurrent streams per session (initial value,
/// tune by load test).
pub(crate) const MAX_STREAMS_PER_SESSION: usize = 128;

/// A multiplexed AnyTLS session: one TLS connection carrying any number of
/// concurrent streams (sing-anytls `Session`).
pub(crate) struct AnyTlsSession {
    /// Unique id within the pool (used for removal on close).
    seq: u64,
    /// Pool key (`host:port` of the AnyTLS server).
    addr: String,
    /// Ordered writer queue: every frame goes out through the single
    /// writer task (no cross-stream mutex, uncancellable once queued).
    writer_q: Arc<WriterQueue>,
    /// Writer task handle, aborted on close.
    writer_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Open streams: sid → demux delivery channel.
    streams: Mutex<HashMap<u32, StreamSink>>,
    /// Stream id allocator (sing `streamId`); first stream gets sid 1.
    next_sid: AtomicU32,
    /// Set once the TLS connection dies or an ALERT arrives; idempotent
    /// close via [`AnyTlsSession::close`].
    closed: AtomicBool,
    /// Establishment time (max-age drains).
    created: Instant,
    /// Lifecycle: Active → Draining → Closed (a usize of
    /// [`crate::session::SessionState`] discriminants).
    session_state: AtomicUsize,
    /// First physical-failure reason (demux read error, writer failure):
    /// streams report it after draining queued data — a dead session is
    /// never a clean EOF.
    terminal_error: std::sync::OnceLock<Arc<anyhow::Error>>,
    /// Streams killed locally (HOL slow-consumer): their readers see a
    /// reset after the queued data drains, not a clean EOF.
    killed_streams: Mutex<HashSet<u32>>,
    /// Stream-slot capacity: the single capacity truth (replaces the old
    /// active_streams counter — a permit outlives the counter's races).
    stream_permits: Arc<tokio::sync::Semaphore>,
    /// Demux task handle, aborted on close.
    demux: Mutex<Option<tokio::task::AbortHandle>>,
}

impl AnyTlsSession {
    /// Establish a session on a connected transport: write the auth blob
    /// and the settings frame (sid 0, sing `Session.Run` parity) and spawn
    /// the demux task. Pool membership is the caller's business (the
    /// [`SessionPool`] offer/insert paths).
    async fn establish(
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
            writer_q: Arc::new(WriterQueue::new()),
            writer_task: Mutex::new(None),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            closed: AtomicBool::new(false),
            created: Instant::now(),
            session_state: AtomicUsize::new(crate::session::SessionState::Active as usize),
            terminal_error: std::sync::OnceLock::new(),
            killed_streams: Mutex::new(HashSet::new()),
            stream_permits: Arc::new(tokio::sync::Semaphore::new(MAX_STREAMS_PER_SESSION)),
            demux: Mutex::new(None),
        });

        let demux_handle = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { session_demux(session, transport_read).await })
        };
        *session.demux.lock().unwrap() = Some(demux_handle.abort_handle());
        let writer_handle = {
            let session = Arc::clone(&session);
            let queue = Arc::clone(&session.writer_q);
            tokio::spawn(async move { session_writer(session, transport_write, queue).await })
        };
        *session.writer_task.lock().unwrap() = Some(writer_handle.abort_handle());

        debug!("AnyTLS session {} for {} established", session.seq, addr);
        Ok(session)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Open streams on this session (capacity taken from the semaphore —
    /// the single truth; `MAX_STREAMS_PER_SESSION - available`).
    fn active_streams(&self) -> usize {
        MAX_STREAMS_PER_SESSION - self.stream_permits.available_permits()
    }

    /// Enqueue a control frame (SYN/FIN/HEART): ordered, reserved
    /// headroom, uncancellable once queued. Fails only when the session
    /// is already closed.
    fn enqueue_control(&self, cmd: u8, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        self.writer_q
            .push_batch([FrameCommand::Control { cmd, sid, payload }]);
        Ok(())
    }

    /// Enqueue a payload PSH for a stream: bounded by the writer-queue
    /// data permits, so a fast stream backpressures here instead of
    /// growing memory. Uncancellable once queued.
    async fn enqueue_data(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        let permit = Arc::clone(&self.writer_q.data_permits)
            .acquire_owned()
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "AnyTLS writer queue is closed",
                )
            })?;
        self.writer_q.push_batch([FrameCommand::Data {
            sid,
            payload,
            _permit: permit,
        }]);
        Ok(())
    }

    /// Enqueue a UoT datagram: drop-on-full (UDP semantics) — a hot UDP
    /// flow must never backpressure the session writer.
    fn enqueue_uot(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        let Ok(permit) = Arc::clone(&self.writer_q.data_permits).try_acquire_owned() else {
            return Ok(()); // saturated: drop the datagram
        };
        self.writer_q.push_batch([FrameCommand::Data {
            sid,
            payload,
            _permit: permit,
        }]);
        Ok(())
    }

    /// Register a sid and enqueue the SYN+PSH opening pair as one atomic
    /// batch (never interleaved with another stream's frame). The caller
    /// proves capacity with `permit` (from `try_reserve`); the returned
    /// guard owns both the registration and the slot until the caller
    /// commits; abandoning it removes the sid and cleans the server's
    /// side with a FIN (the writer queue makes partial frames
    /// impossible).
    async fn register_and_open(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        queue_cap: usize,
        sink: fn(mpsc::Sender<StreamEvent>) -> StreamSink,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, mpsc::Receiver<StreamEvent>, StreamRegistration)> {
        if self.is_closed() {
            anyhow::bail!("AnyTLS session {} is closed", self.seq);
        }
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel(queue_cap);
        self.streams.lock().unwrap().insert(sid, sink(tx));
        let mut guard = StreamRegistration {
            session: Arc::clone(self),
            sid,
            frame_started: true,
            committed: false,
            permit: Some(permit),
        };
        // The opening pair goes out as one atomic batch — never
        // interleaved with another stream's frame, never truncated (a
        // physical write failure closes the session in the writer task).
        if self.is_closed() {
            return Err(anyhow::anyhow!("AnyTLS session {} is closed", self.seq));
        }
        self.writer_q.push_batch([
            FrameCommand::Control {
                cmd: CMD_SYN,
                sid,
                payload: bytes::Bytes::new(),
            },
            FrameCommand::Control {
                cmd: CMD_PSH,
                sid,
                payload: bytes::Bytes::from(target_addr),
            },
        ]);
        guard.frame_started = false;
        Ok((sid, rx, guard))
    }

    /// Open a new stream on this session (sing `Session.OpenStream`):
    /// allocate a sid, send SYN + the first PSH carrying the target
    /// address, and return the user-facing half of the stream. Many
    /// streams may be open concurrently; no exclusive borrow is taken.
    async fn open_stream(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<tokio::io::DuplexStream> {
        let (sid, rx, guard) = self
            .register_and_open(target_addr, STREAM_QUEUE_CAP, StreamSink::Tcp, permit)
            .await?;
        let permit = guard.commit();
        let (client_half, stream_half) = tokio::io::duplex(STREAM_DUPLEX_BUFFER);
        tokio::spawn(stream_task(Arc::clone(self), sid, stream_half, rx, permit));
        debug!("AnyTLS session {} opened sid={}", self.seq, sid);
        Ok(client_half)
    }

    /// Open a UoT stream: same SYN+PSH opening as [`Self::open_stream`],
    /// but inbound datagrams go straight from the demux into a drop-on-full
    /// queue (no stream task, no duplex) and outbound frames are written
    /// directly to the session writer. A hot UDP flow therefore cannot
    /// backpressure the session demux — before this, one burst past the
    /// stream's buffers wedged the whole session (demux blocks on a full
    /// per-stream queue) and every flow on it died.
    ///
    /// The returned guard is **uncommitted**: the caller must drive the
    /// UoT request write and then [`StreamRegistration::commit`] —
    /// abandoning the stream in between cleans up the sid and releases
    /// the slot.
    async fn open_uot_stream(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<(u32, mpsc::Receiver<StreamEvent>, StreamRegistration)> {
        let (sid, rx, guard) = self
            .register_and_open(target_addr, UOT_DRAIN_QUEUE_CAP, StreamSink::Uot, permit)
            .await?;
        debug!("AnyTLS session {} opened uot sid={}", self.seq, sid);
        Ok((sid, rx, guard))
    }

    /// Write one PSH frame for a UoT stream (datagrams go directly on the
    /// session, no stream task in between).
    async fn write_uot_frame(&self, sid: u32, data: &[u8]) -> std::io::Result<()> {
        self.enqueue_uot(sid, bytes::Bytes::copy_from_slice(data))
    }

    /// Open a TCP stream with the direct data path (no stream task, no
    /// duplex): inbound frames arrive through the demux queue, outbound
    /// frames go through the ordered writer queue. Bounded backpressure
    /// on both ends (Tcp sink inbound, writer-queue permits outbound) —
    /// TCP payload must not be dropped, unlike UoT.
    async fn open_stream_direct(
        self: &Arc<Self>,
        target_addr: Vec<u8>,
        permit: crate::session::SessionPermit<Self>,
    ) -> anyhow::Result<AnyTlsStream> {
        let (sid, rx, guard) = self
            .register_and_open(target_addr, STREAM_QUEUE_CAP, StreamSink::Tcp, permit)
            .await?;
        let permit = guard.commit();
        debug!("AnyTLS session {} opened direct sid={}", self.seq, sid);
        Ok(AnyTlsStream::new(Arc::clone(self), sid, rx, permit))
    }

    /// Unregister a UoT stream (FIN to the server), mirroring
    /// [`Self::end_stream`]. Stream capacity is the permit's business
    /// (released when the transport drops it), never this map's.
    async fn end_uot_stream(&self, sid: u32) {
        let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
        if was_registered {
            let _ = self.enqueue_control(CMD_FIN, sid, bytes::Bytes::new());
        }
        debug!("AnyTLS session {} sid={} uot stream ended", self.seq, sid);
    }

    /// Unregister a stream, optionally notifying the server with FIN, and
    /// restart the idle clock when the last stream is gone. Called exactly
    /// once per stream task.
    async fn end_stream(&self, sid: u32, notify_fin: bool) {
        let was_registered = self.streams.lock().unwrap().remove(&sid).is_some();
        // No FIN back when the server already closed its side (dispatch_fin
        // leaves the entry registered; `notify_fin` distinguishes the
        // client-initiated close) or when the whole session is gone.
        if notify_fin && was_registered {
            let _ = self.enqueue_control(CMD_FIN, sid, bytes::Bytes::new());
        }
        debug!("AnyTLS session {} sid={} stream ended", self.seq, sid);
    }

    /// Record the first physical-failure reason and close: streams
    /// report the reason after draining queued data.
    fn fail(&self, reason: anyhow::Error) {
        let _ = self.terminal_error.set(Arc::new(reason));
        self.close();
    }

    /// Close the session: flag it, drop all stream dispatch channels (their
    /// tasks EOF the client side and exit), stop the demux, shut down the
    /// write half. Idempotent. Pool pruning happens on the next
    /// `SessionPool::offer`/janitor pass (closed sessions are retained
    /// never).
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.session_state.store(
            crate::session::SessionState::Closed as usize,
            Ordering::Release,
        );
        self.streams.lock().unwrap().clear();
        if let Some(handle) = self.demux.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.writer_task.lock().unwrap().take() {
            handle.abort();
        }
        self.writer_q.clear();
        debug!("AnyTLS session {} for {} closed", self.seq, self.addr);
    }

    /// Deliver a server payload frame to its stream. TCP sinks apply
    /// backpressure (their data must not be dropped); UoT sinks drop on a
    /// full queue (UDP semantics — the demux never blocks on them).
    /// Deliver a server payload frame to its stream. TCP sinks use
    /// try_send: a slow consumer must never stall the whole session's
    /// demux — the stream is killed (server told with a non-blocking
    /// FIN; the already-queued data still drains to the reader before
    /// the close) instead of blocking every other stream. UoT sinks
    /// drop on full (UDP semantics).
    async fn dispatch_data(&self, sid: u32, data: Vec<u8>) {
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => match tx.try_send(StreamEvent::Data(data)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        "AnyTLS session {} sid={} killed: slow consumer (HOL)",
                        self.seq, sid
                    );
                    // The reader sees a reset (not a clean EOF) after the
                    // already-queued data drains.
                    self.killed_streams.lock().unwrap().insert(sid);
                    self.streams.lock().unwrap().remove(&sid);
                    if self
                        .enqueue_control(CMD_FIN, sid, bytes::Bytes::new())
                        .is_err()
                    {
                        // The writer queue is gone too — the session is dead.
                        self.fail(anyhow::anyhow!("writer queue unavailable on HOL kill"));
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.streams.lock().unwrap().remove(&sid);
                }
            },
            Some(sink) => {
                if !sink.send_data(data).await {
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
    async fn dispatch_fin(&self, sid: u32) {
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        if let Some(sink) = sink {
            sink.send_fin().await;
        }
    }

    /// Deliver a stream-level failure (server-reported open error): the
    /// reader sees an error, not a clean EOF.
    async fn dispatch_error(&self, sid: u32, err: anyhow::Error) {
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        if let Some(sink) = sink {
            sink.send_error(err).await;
        }
    }
}

/// Session receive loop (sing `Session.recvLoop`): read frames and dispatch
/// by sid. Any read failure or server ALERT closes the whole session.
async fn session_demux(session: Arc<AnyTlsSession>, mut read: BoxedReader) {
    let mut fail_reason: Option<anyhow::Error> = None;
    loop {
        let (cmd, sid, data) = match read_frame(&mut read).await {
            Ok(frame) => frame,
            Err(e) => {
                debug!("AnyTLS session {} demux read failed: {}", session.seq, e);
                fail_reason = Some(anyhow::anyhow!("demux read failed: {e}"));
                break;
            }
        };
        match cmd {
            CMD_PSH => session.dispatch_data(sid, data).await,
            CMD_FIN => session.dispatch_fin(sid).await,
            CMD_SYNACK => {
                // sing: a SYNACK carrying data reports a dial error for the
                // stream (an empty SYNACK is a pure handshake ack — ignore).
                // The target refused — a typed stream error, not a clean
                // EOF (the session stays healthy).
                if !data.is_empty() {
                    debug!(
                        "AnyTLS session {} sid={} remote dial error: {}",
                        session.seq,
                        sid,
                        String::from_utf8_lossy(&data)
                    );
                    session
                        .dispatch_error(
                            sid,
                            anyhow::anyhow!("target refused: {}", String::from_utf8_lossy(&data)),
                        )
                        .await;
                }
            }
            CMD_HEART_REQUEST => {
                if session
                    .enqueue_control(CMD_HEART_RESPONSE, sid, bytes::Bytes::new())
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
    match fail_reason {
        Some(e) => session.fail(e),
        None => session.close(),
    }
}

/// Per-stream task: pumps client payload into PSH frames and delivers
/// demuxed inbound events to the client. Client EOF closes the stream with
/// FIN (the session stays open for other streams); server FIN or session
/// teardown EOFs the client read side.
async fn stream_task(
    session: Arc<AnyTlsSession>,
    sid: u32,
    mut stream_half: tokio::io::DuplexStream,
    mut rx: mpsc::Receiver<StreamEvent>,
    // The capacity slot for this stream; released when the task exits.
    _permit: crate::session::SessionPermit<AnyTlsSession>,
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
                    Some(StreamEvent::Fin) | Some(StreamEvent::Error(_)) | None => {
                        // Server closed the stream, a stream-level
                        // failure, or the session died and dropped the
                        // dispatch channels (the legacy duplex path
                        // cannot carry the error itself — EOF is the
                        // best it can signal).
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
                        if let Err(e) = session
                            .enqueue_data(sid, bytes::Bytes::copy_from_slice(&buf[..n]))
                            .await
                        {
                            debug!("AnyTLS sid={} PSH enqueue failed: {}", sid, e);
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

impl crate::session::ManagedSession for AnyTlsSession {
    // The inherent methods of the same names do the real work.
    fn active_streams(&self) -> usize {
        MAX_STREAMS_PER_SESSION - self.stream_permits.available_permits()
    }
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn close(&self) {
        AnyTlsSession::close(self)
    }
    fn state(&self) -> crate::session::SessionState {
        match self.session_state.load(Ordering::Acquire) {
            0 => crate::session::SessionState::Active,
            1 => crate::session::SessionState::Draining,
            _ => crate::session::SessionState::Closed,
        }
    }
    /// GOAWAY/max-age: stop taking new streams; the pool stops offering
    /// this session and existing streams run to the end.
    fn begin_drain(&self) {
        let _ = self.session_state.compare_exchange(
            crate::session::SessionState::Active as usize,
            crate::session::SessionState::Draining as usize,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    fn created_at(&self) -> Instant {
        self.created
    }
    /// Active → acquire → re-check Active: a session that began draining
    /// in between releases the slot immediately instead of taking one
    /// more stream it will never serve.
    fn try_reserve(self: &Arc<Self>) -> Option<crate::session::SessionPermit<Self>> {
        use crate::session::{SessionPermit, SessionState};
        if self.state() != SessionState::Active {
            return None;
        }
        let permit = Arc::clone(&self.stream_permits).try_acquire_owned().ok()?;
        if self.state() != SessionState::Active {
            drop(permit);
            return None;
        }
        Some(SessionPermit::new(Arc::clone(self), permit))
    }
}

/// Dial a fresh TLS + AnyTLS session (the `SessionPool::offer` dial
/// closure and the janitor's prewarm share this).
async fn dial_session(
    node: &Node,
    addr: &str,
    connect_timeout: Duration,
) -> anyhow::Result<Arc<AnyTlsSession>> {
    let (read, write, auth, settings) =
        connect_transport(node, addr, connect_timeout, None).await?;
    AnyTlsSession::establish(addr, read, write, &auth, &settings).await
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
        // `addr` is the pool key (host:port plus an auth/TLS fingerprint),
        // not a dial target — always dial the node's own address.
        None => {
            crate::util::connect_outbound(
                &format!("{}:{}", node.host(), node.port),
                connect_timeout,
            )
            .await?
        }
    };
    debug!("AnyTLS: TCP connected to {}", addr);

    let connector = AnyTlsHandler::build_tls_connector(node)?;
    let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
    let tls = connector.connect(&server_name, tcp).await?;
    debug!("AnyTLS: TLS handshake completed with {}", addr);
    let (read, write) = tokio::io::split(crate::tls::BatchRead::new(tls));

    let mut auth = Vec::with_capacity(34);
    auth.extend_from_slice(&auth_key);
    auth.extend_from_slice(&[0u8; 2]);

    let settings = AnyTlsHandler::settings_payload();
    Ok((Box::new(read), Box::new(write), auth, settings))
}

impl AnyTlsHandler {
    /// Create a new AnyTLS handler.
    pub fn new() -> Self {
        Self::default()
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

    /// Build the client settings frame payload.
    fn settings_payload() -> Vec<u8> {
        let scheme = b"stop=0\n";
        use md5::Digest as _;
        use std::fmt::Write as _;
        let md5 = md5::Md5::digest(scheme)
            .iter()
            .fold(String::with_capacity(32), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
        format!("v=2\nclient=dae\npadding-md5={}\n", md5).into_bytes()
    }
    /// Lazily start the pool janitor for this node (once per pool).
    fn ensure_janitor(node: &Node, pool: &Arc<AnyTlsPool>) {
        // Always run the janitor: it pre-establishes min_idle sessions
        // (default 1) and, just as importantly, reaps idle-expired ones —
        // skipping it entirely leaks idle sessions into the pool forever.
        // An explicit `min_idle_session=0` disables standby sessions only,
        // never pruning.
        let label = format!("{}:{}", node.host(), node.port);
        // Default 1 (not sing-box's 0): a single standby session per node
        // keeps every dial warm after the first — cold dials otherwise pay
        // TCP connect + TLS handshake (2 RTT) per burst.
        let min_idle = node.anytls_min_idle_session.unwrap_or(1);
        let idle_timeout = Duration::from_secs(
            node.anytls_idle_session_timeout
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        );
        let prewarm_node = node.clone();
        pool.ensure_janitor(POOL_KEY, min_idle, idle_timeout, move || {
            let node = prewarm_node.clone();
            let label = label.clone();
            async move { dial_session(&node, &label, Duration::from_secs(10)).await }
        });
    }

    /// Open a stream to `target_addr` on a pooled session, dialing one on
    /// demand (single-flight). One retry on a session that fails mid-open.
    async fn open_pooled_stream(
        &self,
        node: &Node,
        addr: &str,
        target_addr: &[u8],
        connect_timeout: Duration,
    ) -> anyhow::Result<AnyTlsStream> {
        let pool = self.node_pool(node)?;
        Self::ensure_janitor(node, &pool);
        // The dial future must be 'static (pool-owned dial task) and the
        // closure Clone (open_with retries once): own clones.
        let dial_node = node.clone();
        let dial_addr = addr.to_string();
        let target = target_addr.to_vec();
        pool.open_with(
            POOL_KEY,
            move || {
                let node = dial_node.clone();
                let addr = dial_addr.clone();
                async move { dial_session(&node, &addr, connect_timeout).await }
            },
            move |session, permit| {
                let target = target.clone();
                async move {
                    debug!(
                        "AnyTLS: multiplexing on session {} ({} open stream(s))",
                        session.seq,
                        session.active_streams(),
                    );
                    match session.open_stream_direct(target, permit).await {
                        Ok(stream) => Ok(stream),
                        // A write failure kills the session (sing parity):
                        // retry on a fresh one; everything else is refused.
                        Err(e) => Err(if session.is_closed() {
                            crate::session::OpenError::Session(e)
                        } else {
                            crate::session::OpenError::Refused(e)
                        }),
                    }
                }
            },
        )
        .await
    }
}

/// Direct-path AnyTLS stream: `AsyncRead`/`AsyncWrite` over a session
/// stream without the stream task and duplex the old path had (those cost
/// two task hops and two copies per byte — the SS codec review's
/// measurement, applied here).
pub(crate) struct AnyTlsStream {
    session: Arc<AnyTlsSession>,
    sid: u32,
    rx: mpsc::Receiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    /// Set when the Fin/disconnect event was consumed in the same poll
    /// that also delivered data: the data goes out now, the zero-byte
    /// EOF is owed to the next poll (a consumed Fin is otherwise lost
    /// and the relay hangs forever).
    read_eof: bool,
    /// A stream-level failure consumed after data was already delivered
    /// in the same poll: the error is owed to the next poll (data
    /// first, then the error — never silently merge them).
    read_err: Option<std::io::Error>,
    /// In-flight PSH/FIN write (owns the payload — cancelling the caller's
    /// write future can never lose data).
    write_fut:
        Option<std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>>,
    fin_sent: bool,
    /// Stream-slot capacity, held for the stream's whole life (released
    /// on Drop).
    _permit: crate::session::SessionPermit<AnyTlsSession>,
}

impl AnyTlsStream {
    fn new(
        session: Arc<AnyTlsSession>,
        sid: u32,
        rx: mpsc::Receiver<StreamEvent>,
        permit: crate::session::SessionPermit<AnyTlsSession>,
    ) -> Self {
        Self {
            session,
            sid,
            rx,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            read_err: None,
            write_fut: None,
            fin_sent: false,
            _permit: permit,
        }
    }

    /// Queue a PSH frame for up to `u16::MAX` payload bytes; the future
    /// owns the payload until flushed.
    fn queue_write(&mut self, data: Vec<u8>) {
        let session = Arc::clone(&self.session);
        let sid = self.sid;
        self.write_fut = Some(Box::pin(async move {
            session
                .enqueue_data(sid, bytes::Bytes::from(data))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }));
    }
}

impl std::fmt::Debug for AnyTlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsStream")
            .field("sid", &self.sid)
            .field("pending_read", &(self.read_buf.len() - self.read_pos))
            .finish()
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        let session = Arc::clone(&self.session);
        let sid = self.sid;
        let notify_fin = !self.fin_sent;
        tokio::spawn(async move { session.end_stream(sid, notify_fin).await });
    }
}

impl tokio::io::AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.read_eof {
            // The Fin/disconnect was already consumed; the zero-byte EOF
            // owed from that poll is delivered now (and stays delivered).
            return std::task::Poll::Ready(Ok(()));
        }
        if let Some(e) = this.read_err.take() {
            // The error owed from the data-first poll.
            this.read_eof = true;
            return std::task::Poll::Ready(Err(e));
        }
        // Drain as many queued frames as fit: servers that emit small
        // frames would otherwise cost one relay wakeup per frame.
        let mut got_any = this.read_pos < this.read_buf.len();
        loop {
            // Copy what the current frame buffer has.
            let n = (this.read_buf.len() - this.read_pos).min(out.remaining());
            if n > 0 {
                out.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
            }
            if out.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            // Frame consumed: fetch the next one (now, not next wakeup).
            this.read_buf.clear();
            this.read_pos = 0;
            let next = if got_any {
                // Already have data for the caller: never block for more.
                match this.rx.try_recv() {
                    Ok(ev) => std::task::Poll::Ready(Some(ev)),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => std::task::Poll::Pending,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        std::task::Poll::Ready(None)
                    }
                }
            } else {
                this.rx.poll_recv(cx)
            };
            match next {
                std::task::Poll::Ready(Some(StreamEvent::Data(data))) => {
                    this.read_buf = data;
                    got_any = true;
                }
                std::task::Poll::Ready(Some(StreamEvent::Error(e))) => {
                    let err =
                        std::io::Error::new(std::io::ErrorKind::ConnectionReset, e.to_string());
                    // Data already in `out` this poll would be discarded
                    // with an error: deliver the data, owe the error.
                    if got_any {
                        this.read_err = Some(err);
                        return std::task::Poll::Ready(Ok(()));
                    }
                    this.read_eof = true;
                    return std::task::Poll::Ready(Err(err));
                }
                std::task::Poll::Ready(Some(StreamEvent::Fin)) => {
                    // Consume the EOF event exactly once. If this poll
                    // already delivered data, the caller must see that
                    // data as a successful read; the EOF is owed to the
                    // next poll via `read_eof` (returning it now would
                    // either discard the data or lose the Fin).
                    this.read_eof = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(None) => {
                    // Channel disconnected: a session failure is an
                    // error (not a clean EOF); a locally HOL-killed
                    // stream is a reset; anything else is a clean end.
                    let pending: Option<std::io::Error> =
                        if let Some(e) = this.session.terminal_error.get() {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                e.to_string(),
                            ))
                        } else if this
                            .session
                            .killed_streams
                            .lock()
                            .unwrap()
                            .remove(&this.sid)
                        {
                            Some(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "stream killed: slow consumer (HOL)",
                            ))
                        } else {
                            None
                        };
                    if let Some(err) = pending {
                        if got_any {
                            this.read_err = Some(err);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.read_eof = true;
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => {
                    return if got_any {
                        std::task::Poll::Ready(Ok(()))
                    } else {
                        std::task::Poll::Pending
                    };
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Frames are u16-length-prefixed: take up to one full frame per
        // call (the caller retries with the remainder).
        let chunk = buf.len().min(u16::MAX as usize);
        if chunk == 0 {
            return std::task::Poll::Ready(Ok(0));
        }
        if self.write_fut.is_none() {
            self.queue_write(buf[..chunk].to_vec());
        }
        let this = self.as_mut().get_mut();
        let fut = this.write_fut.as_mut().expect("just queued");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(())) => {
                this.write_fut = None;
                std::task::Poll::Ready(Ok(chunk))
            }
            std::task::Poll::Ready(Err(e)) => {
                this.write_fut = None;
                std::task::Poll::Ready(Err(e))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(fut) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => self.write_fut = None,
                std::task::Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => {}
            other => return other,
        }
        if !self.fin_sent {
            self.fin_sent = true;
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            let fut: std::pin::Pin<
                Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>,
            > = Box::pin(async move {
                session
                    .enqueue_control(CMD_FIN, sid, bytes::Bytes::new())
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });
            self.write_fut = Some(fut);
        }
        self.poll_flush(cx)
    }
}

/// UoT response framing detected per stream. The sing-box spec's connect
/// mode is `u16be len + payload`, but some third-party servers answer
/// connect requests in the v1 packet layout (`atyp + addr + port +
/// u16be len + payload`) — detected on the first datagram by matching the
/// echoed destination, never by guessing from the length bytes (a v2
/// length high byte can look like a v1 atyp).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UotMode {
    V2Connect,
    V1Packet,
}

/// Buffered frame reader for the response direction of a UoT stream.
struct UotFrameReader<R> {
    rd: R,
    buf: Vec<u8>,
    mode: Option<UotMode>,
}

impl<R: tokio::io::AsyncRead + Unpin> UotFrameReader<R> {
    fn new(rd: R) -> Self {
        Self {
            rd,
            buf: Vec::with_capacity(4096),
            mode: None,
        }
    }

    /// Fill the buffer to `need` bytes. Returns Err on EOF.
    async fn fill(&mut self, need: usize) -> std::io::Result<()> {
        let mut chunk = [0u8; 4096];
        while self.buf.len() < need {
            let n = tokio::io::AsyncReadExt::read(&mut self.rd, &mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "UoT stream closed",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    }

    /// Bounded fill used only while the framing is still undetected: a tiny
    /// first datagram (a few bytes) must not deadlock the decision — after
    /// the grace period the spec framing (v2 connect) wins.
    async fn fill_grace(&mut self, need: usize) -> std::io::Result<()> {
        match tokio::time::timeout(Duration::from_millis(500), self.fill(need)).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "UoT mode detect grace expired",
            )),
        }
    }

    /// Read one datagram payload, detecting the framing on the first call.
    /// `target`/`target_domain` is the destination of the UoT connect
    /// request, which v1-format servers echo as the packet source.
    async fn next_datagram(
        &mut self,
        target: &SocketAddr,
        target_domain: Option<&str>,
    ) -> std::io::Result<Vec<u8>> {
        loop {
            match self.mode {
                Some(UotMode::V2Connect) => {
                    self.fill(2).await?;
                    let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                    self.fill(2 + len).await?;
                    return Ok(self.buf.drain(..2 + len).skip(2).collect());
                }
                Some(UotMode::V1Packet) => {
                    let (header, payload_len) = self.parse_v1_header().await?;
                    self.fill(header + payload_len).await?;
                    return Ok(self
                        .buf
                        .drain(..header + payload_len)
                        .skip(header)
                        .collect());
                }
                None => {
                    // Wait indefinitely for the first byte — a slow first
                    // reply (long proxied RTT) must not kill the flow; the
                    // caller owns the idle timeout. The grace below only
                    // bounds the disambiguation once bytes have started
                    // arriving.
                    self.fill(1).await?;
                    if self.buf[0] > UOT_V1_ATYP_DOMAIN {
                        self.mode = Some(UotMode::V2Connect);
                        continue;
                    }
                    match self.parse_v1_header_grace().await {
                        Ok((header, _)) => {
                            // A v1 server echoes the connect destination as the
                            // packet source; a mismatch means the bytes were really
                            // a v2 length prefix (e.g. 0x00..0x02) after all.
                            if self
                                .v1_header_matches(header, target, target_domain)
                                .await?
                            {
                                self.mode = Some(UotMode::V1Packet);
                            } else {
                                self.mode = Some(UotMode::V2Connect);
                            }
                        }
                        // Not enough bytes to decide within the grace
                        // period: fall back to the spec framing.
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            self.mode = Some(UotMode::V2Connect);
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Parse the v1 packet header length and payload length at `buf[0]`.
    async fn parse_v1_header(&mut self) -> std::io::Result<(usize, usize)> {
        self.parse_v1_header_inner(false).await
    }

    /// Grace-period variant used only while the framing is undetected.
    async fn parse_v1_header_grace(&mut self) -> std::io::Result<(usize, usize)> {
        self.parse_v1_header_inner(true).await
    }

    async fn parse_v1_header_inner(&mut self, grace: bool) -> std::io::Result<(usize, usize)> {
        const BAD: &str = "invalid UoT v1 packet header";
        macro_rules! fill {
            ($n:expr) => {
                if grace {
                    self.fill_grace($n).await?
                } else {
                    self.fill($n).await?
                }
            };
        }
        fill!(1);
        let atyp = self.buf[0];
        let addr_len = match atyp {
            UOT_V1_ATYP_V4 => 4,
            UOT_V1_ATYP_V6 => 16,
            UOT_V1_ATYP_DOMAIN => {
                fill!(2);
                1 + self.buf[1] as usize
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, BAD));
            }
        };
        let header = 1 + addr_len + 2 + 2;
        fill!(header);
        let len_at = 1 + addr_len + 2;
        let payload_len = u16::from_be_bytes([self.buf[len_at], self.buf[len_at + 1]]) as usize;
        Ok((header, payload_len))
    }

    /// Whether the v1 header currently in `buf` echoes the connect
    /// destination (source == the requested target).
    async fn v1_header_matches(
        &self,
        header: usize,
        target: &SocketAddr,
        target_domain: Option<&str>,
    ) -> std::io::Result<bool> {
        let atyp = self.buf[0];
        let addr_end = header - 4; // before port(2) + len(2)
        let port = u16::from_be_bytes([self.buf[addr_end], self.buf[addr_end + 1]]);
        if port != target.port() {
            return Ok(false);
        }
        let matched = match atyp {
            UOT_V1_ATYP_V4 => {
                let ip =
                    std::net::Ipv4Addr::new(self.buf[1], self.buf[2], self.buf[3], self.buf[4]);
                target.ip() == std::net::IpAddr::V4(ip)
            }
            UOT_V1_ATYP_V6 => {
                let ip: [u8; 16] = self.buf[1..17].try_into().unwrap_or([0; 16]);
                target.ip() == std::net::IpAddr::V6(ip.into())
            }
            _ => {
                let domain = String::from_utf8_lossy(&self.buf[2..addr_end]).to_string();
                Some(domain.as_str()) == target_domain
            }
        };
        Ok(matched)
    }
}

/// Bridge task for UoT: forwards payloads between the loopback UDP socket
/// and length-prefixed datagrams on the AnyTLS stream. Ends on error, EOF,
/// or after [`UDP_BRIDGE_IDLE_SECS`] without activity.
async fn uot_bridge(
    stream: tokio::io::DuplexStream,
    internal: tokio::net::UdpSocket,
    external_addr: SocketAddr,
    target: SocketAddr,
    target_domain: Option<String>,
) {
    let (rd, mut wr) = tokio::io::split(stream);
    // Bounded: UDP semantics — drop on a full queue, never queue unboundedly.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let reader = tokio::spawn(async move {
        let mut frames = UotFrameReader::new(rd);
        while let Ok(data) = frames
            .next_datagram(&target, target_domain.as_deref())
            .await
        {
            match tx.try_send(data) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(_)) => break,
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

    /// Multiplexed: the session pool already keeps warm connections; a
    /// pooled bare TCP would force a new session (TLS + auth) per flow,
    /// and sessions created over the pool cap leak (orphaned from the
    /// janitor, held forever by their demux task).
    fn pool_bare_tcp(&self, _node: &Node) -> bool {
        false
    }

    fn set_runtime_registry(&self, cell: crate::runtime::SharedRuntimeRegistry) {
        *self.runtime_registry.write() = Some(cell);
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let addr = format!("{}:{}", node.host(), node.port);
        let target_addr = addr::encode_address(target, target_domain);
        debug!(
            "AnyTLS: connecting to {} for target {} (tls={} sni={:?} skip={})",
            addr, target, node.tls, node.sni, node.skip_cert_verify
        );
        let stream = self
            .open_pooled_stream(node, &addr, &target_addr, connect_timeout)
            .await?;

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
        let target_addr = addr::encode_address(target, target_domain);

        let pool = self.node_pool(node)?;
        Self::ensure_janitor(node, &pool);
        let (read, write, auth, settings) =
            connect_transport(node, &addr, _connect_timeout, Some(tcp)).await?;
        let session = AnyTlsSession::establish(&addr, read, write, &auth, &settings).await?;
        pool.insert(POOL_KEY, &session);
        let permit = session
            .try_reserve()
            .ok_or_else(|| anyhow::anyhow!("fresh AnyTLS session has no stream capacity"))?;
        let stream = session.open_stream_direct(target_addr, permit).await?;

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
        let magic = addr::encode_address("0.0.0.0:0".parse().unwrap(), Some(UOT_MAGIC));
        let pool = self.node_pool(node)?;
        Self::ensure_janitor(node, &pool);
        // Legacy loopback path: needs a duplex stream for `uot_bridge`
        // (the production UDP path is `dial_udp_transport`).
        let mut stream = {
            let mut attempt = 0;
            loop {
                attempt += 1;
                let dial_node = node.clone();
                let dial_addr = addr.clone();
                let session = pool
                    .offer(POOL_KEY, move || async move {
                        dial_session(&dial_node, &dial_addr, connect_timeout).await
                    })
                    .await?;
                let Some(permit) = session.try_reserve() else {
                    pool.invalidate(POOL_KEY, &session);
                    if attempt >= 2 {
                        return Err(anyhow::anyhow!("AnyTLS session has no stream capacity"));
                    }
                    continue;
                };
                match session.open_stream(magic.clone(), permit).await {
                    Ok(s) => break s,
                    Err(e) => {
                        pool.invalidate(POOL_KEY, &session);
                        if attempt >= 2 {
                            return Err(e);
                        }
                    }
                }
            }
        };

        // UoT request: isConnect=true + destination in SOCKS5 address form.
        // sing's uot.ReadRequest parses the destination with
        // M.SocksaddrSerializer (0x01/0x03/0x04), not the per-packet
        // AddrParser form (0x00/0x01/0x02) — the latter only appears on
        // isConnect=false packets, which we never send.
        let mut request = vec![1u8];
        request.extend(addr::encode_address(target, target_domain));
        tokio::time::timeout(connect_timeout, stream.write_all(&request)).await??;

        // Bridge a loopback UDP socket to length-prefixed datagrams on the
        // stream: the relay talks raw payloads to `relay_addr`, the bridge
        // frames them onto the AnyTLS stream.
        let (external, internal, external_addr, relay_addr) =
            crate::util::udp_loopback_pair().await?;
        tokio::spawn(uot_bridge(
            stream,
            internal,
            external_addr,
            target,
            target_domain.map(str::to_string),
        ));

        Ok(UdpProxySocket {
            socket: Arc::new(external),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
            _control: None,
        })
    }

    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if let Some(ref network) = node.network
            && !network
                .split(',')
                .any(|n| n.trim().eq_ignore_ascii_case("udp"))
        {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        let addr = format!("{}:{}", node.host(), node.port);
        let magic = addr::encode_address("0.0.0.0:0".parse().unwrap(), Some(UOT_MAGIC));
        let pool = self.node_pool(node)?;
        Self::ensure_janitor(node, &pool);
        let mut attempt = 0;
        let (session, sid, rx, mut guard) = loop {
            attempt += 1;
            let dial_node = node.clone();
            let dial_addr = addr.clone();
            let session = pool
                .offer(POOL_KEY, move || async move {
                    dial_session(&dial_node, &dial_addr, connect_timeout).await
                })
                .await?;
            let Some(permit) = session.try_reserve() else {
                pool.invalidate(POOL_KEY, &session);
                if attempt >= 2 {
                    return Err(anyhow::anyhow!("AnyTLS session has no stream capacity"));
                }
                continue;
            };
            match session.open_uot_stream(magic.clone(), permit).await {
                Ok((sid, rx, guard)) => break (session, sid, rx, guard),
                Err(e) => {
                    pool.invalidate(POOL_KEY, &session);
                    if attempt >= 2 {
                        return Err(e);
                    }
                }
            }
        };

        // UoT request: isConnect=true + destination in SOCKS5 address form.
        // The registration commits only after the request is fully written
        // and the transport exists; a timeout/cancel/error in between
        // drops the guard (sid + count cleaned, session closed on a
        // possibly-partial frame).
        let mut request = vec![1u8];
        request.extend(addr::encode_address(target, target_domain));
        guard.frame_started = true;
        let request_written =
            tokio::time::timeout(connect_timeout, session.write_uot_frame(sid, &request)).await;
        match request_written {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(elapsed) => return Err(elapsed.into()),
        }
        guard.frame_started = false;
        let permit = guard.commit();

        Ok(Arc::new(AnyTlsUotTransport {
            session,
            sid,
            rx: tokio::sync::Mutex::new(rx),
            mode: tokio::sync::Mutex::new(None),
            target,
            target_domain: target_domain.map(str::to_string),
            _permit: permit,
        }))
    }
}

/// Framed UoT transport over a multiplexed AnyTLS stream. Inbound
/// datagrams come straight from the session demux (drop-on-full queue);
/// outbound frames are written directly to the session writer. No stream
/// task, no duplex, no drain task: the only buffer between the server and
/// the flow's reply handler is the demux queue, and it can never
/// backpressure the session.
struct AnyTlsUotTransport {
    session: Arc<AnyTlsSession>,
    sid: u32,
    rx: tokio::sync::Mutex<mpsc::Receiver<StreamEvent>>,
    /// Response framing, detected on the first datagram (v2 `len+payload`
    /// vs v1 `atyp+addr+port+len+payload` — see `UotFrameReader`).
    mode: tokio::sync::Mutex<Option<UotMode>>,
    target: SocketAddr,
    target_domain: Option<String>,
    /// Stream-slot capacity, held for the transport's life.
    _permit: crate::session::SessionPermit<AnyTlsSession>,
}

impl AnyTlsUotTransport {
    /// Strip the UoT per-datagram header, detecting the framing once.
    fn strip_uot_header<'a>(
        &self,
        mode: &mut Option<UotMode>,
        data: &'a [u8],
    ) -> std::io::Result<&'a [u8]> {
        const BAD: &str = "invalid UoT datagram";
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, BAD);
        match mode {
            Some(UotMode::V2Connect) => {
                if data.len() < 2 {
                    return Err(bad());
                }
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + len {
                    return Err(bad());
                }
                Ok(&data[2..2 + len])
            }
            Some(UotMode::V1Packet) => {
                let (header, payload_len) = parse_v1_header(data)?;
                if data.len() < header + payload_len {
                    return Err(bad());
                }
                Ok(&data[header..header + payload_len])
            }
            None => {
                // v1 servers echo the connect destination as the packet
                // source; anything else is the spec's v2 length prefix.
                let v1 = matches!(
                    parse_v1_header(data),
                    Ok((header, _))
                        if v1_header_matches(data, header, &self.target, self.target_domain.as_deref())
                );
                *mode = Some(if v1 {
                    UotMode::V1Packet
                } else {
                    UotMode::V2Connect
                });
                self.strip_uot_header(mode, data)
            }
        }
    }
}

/// v1 packet layout header (`atyp + addr + port + u16 len`) length and
/// payload length at the start of `data`.
fn parse_v1_header(data: &[u8]) -> std::io::Result<(usize, usize)> {
    const BAD: &str = "invalid UoT v1 packet header";
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, BAD);
    if data.is_empty() {
        return Err(bad());
    }
    let addr_len = match data[0] {
        UOT_V1_ATYP_V4 => 4,
        UOT_V1_ATYP_V6 => 16,
        UOT_V1_ATYP_DOMAIN => {
            if data.len() < 2 {
                return Err(bad());
            }
            1 + data[1] as usize
        }
        _ => return Err(bad()),
    };
    let header = 1 + addr_len + 2 + 2;
    if data.len() < header {
        return Err(bad());
    }
    let len_at = 1 + addr_len + 2;
    let payload_len = u16::from_be_bytes([data[len_at], data[len_at + 1]]) as usize;
    Ok((header, payload_len))
}

/// Whether the v1 header at the start of `data` echoes the connect
/// destination (source == the requested target).
fn v1_header_matches(
    data: &[u8],
    header: usize,
    target: &SocketAddr,
    target_domain: Option<&str>,
) -> bool {
    let addr_end = header - 4; // before port(2) + len(2)
    let port = u16::from_be_bytes([data[addr_end], data[addr_end + 1]]);
    if port != target.port() {
        return false;
    }
    match data[0] {
        UOT_V1_ATYP_V4 => {
            target.ip()
                == std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]))
        }
        UOT_V1_ATYP_V6 => {
            let ip: [u8; 16] = data[1..17].try_into().unwrap_or([0; 16]);
            target.ip() == std::net::IpAddr::V6(ip.into())
        }
        _ => {
            let domain = String::from_utf8_lossy(&data[2..addr_end]);
            Some(domain.as_ref()) == target_domain
        }
    }
}

/// Per-stream UoT demux queue depth. UDP semantics: drop on a full queue,
/// never queue unboundedly. Sized for QUIC bursts: the pre-P1.5 loopback
/// bridge had ~256KB of kernel socket buffer per leg; at ~1.2KB per
/// datagram, 1024 entries absorbs a ~10ms burst at 100k pps while the
/// reply handler drains.
const UOT_DRAIN_QUEUE_CAP: usize = 4096;

impl Drop for AnyTlsUotTransport {
    fn drop(&mut self) {
        let session = Arc::clone(&self.session);
        let sid = self.sid;
        tokio::spawn(async move { session.end_uot_stream(sid).await });
    }
}

impl std::fmt::Debug for AnyTlsUotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsUotTransport")
            .field("sid", &self.sid)
            .field("target", &self.target)
            .finish()
    }
}

#[async_trait]
impl PacketTransport for AnyTlsUotTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "uot datagram too large",
            ));
        }
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        self.session.write_uot_frame(self.sid, &frame).await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let event = self.rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "UoT stream closed")
        })?;
        match event {
            StreamEvent::Data(data) => {
                let payload = self
                    .strip_uot_header(&mut *self.mode.lock().await, &data)?
                    .to_vec();
                if payload.len() > buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "uot datagram exceeds buffer",
                    ));
                }
                buf[..payload.len()].copy_from_slice(&payload);
                Ok((payload.len(), self.target))
            }
            StreamEvent::Fin => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "UoT stream closed by server",
            )),
            StreamEvent::Error(e) => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                e.to_string(),
            )),
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
#[cfg(test)]
mod tests {
    use super::*;

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

    /// 2B: with a runtime registry installed, the handler dials through
    /// the node's registry-owned pool; without one, its own fallback.
    #[test]
    fn test_node_pool_prefers_registry() {
        let node = Node {
            name: "test".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        let handler = AnyTlsHandler::new();
        // No registry: fallback pool, shared across calls.
        let p1 = handler.node_pool(&node).unwrap();
        let p2 = handler.node_pool(&node).unwrap();
        assert!(Arc::ptr_eq(&p1, &p2));

        let registry = crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap()
            .into_shared();
        let handler2 = AnyTlsHandler::new();
        handler2.set_runtime_registry(registry.clone());
        let pool = handler2.node_pool(&node).unwrap();
        let registry_pool = match &registry.read().get(&node.id).unwrap().runtime {
            crate::runtime::ProtocolRuntime::AnyTls(rt) => Arc::clone(&rt.pool),
            crate::runtime::ProtocolRuntime::None => panic!("expected AnyTls runtime"),
        };
        assert!(Arc::ptr_eq(&pool, &registry_pool));
        assert!(
            handler2.fallback_pool.get().is_none(),
            "registry path must not touch the fallback"
        );

        // A node absent from the registry is an explicit error.
        let other = Node {
            name: "other".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        assert!(handler2.node_pool(&other).is_err());
    }

    const TEST_AUTH: &[u8] = b"test-auth";
    const TEST_SETTINGS: &[u8] = b"test-settings";

    /// Establish a session over an in-memory duplex; returns the session
    /// and the server end of the transport.
    async fn establish_test_session(addr: &str) -> (Arc<AnyTlsSession>, tokio::io::DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(client_end);
        let session = AnyTlsSession::establish(
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
    async fn test_pool_offer_reuses_and_invalidates() {
        let pool = crate::session::SessionPool::new(crate::session::SessionPoolConfig::default());
        let addr = "127.0.0.1:1234";
        let (session, mut server) = establish_test_session(addr).await;
        expect_handshake(&mut server).await;
        pool.insert(addr, &session);

        // A live pooled session is offered without dialing.
        let offered = pool
            .offer(addr, || async { anyhow::bail!("must not dial") })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&session, &offered));

        // Invalidation closes it; the next offer dials (fails here).
        pool.invalidate(addr, &session);
        assert!(session.is_closed());
        assert!(
            pool.offer(addr, || async { anyhow::bail!("no server") })
                .await
                .is_err()
        );
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

    /// Regression (113666e): Data+Fin enqueued before the first poll must
    /// deliver the data first and a zero-byte EOF next — the batched drain
    /// must not eat the Fin and hang the relay.
    #[tokio::test]
    async fn test_data_fin_same_batch_delivers_data_then_eof() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 7u32;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

        let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
        sink.send_data(b"hello".to_vec()).await;
        sink.send_fin().await;

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        // The consumed Fin must surface as EOF, not a permanent Pending.
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("EOF never delivered — Fin was eaten")
            .unwrap();
        assert_eq!(n, 0);
        // EOF is sticky.
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    /// Same-batch variant with multiple data frames before the Fin.
    #[tokio::test]
    async fn test_multi_data_fin_same_batch() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 9u32;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

        let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
        sink.send_data(b"aa".to_vec()).await;
        sink.send_data(b"bbb".to_vec()).await;
        sink.send_fin().await;

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"aabbb", "both frames batch into one read");
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    /// 0.5.2/v2: an uncommitted registration cleans the sid and releases
    /// the capacity slot on drop.
    #[tokio::test]
    async fn test_registration_guard_drop_cleans_uncommitted() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 11u32;
        let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        assert_eq!(session.active_streams(), 1);
        {
            let _guard = StreamRegistration {
                session: Arc::clone(&session),
                sid,
                frame_started: false,
                committed: false,
                permit: Some(permit),
            };
        }
        assert!(session.streams.lock().unwrap().get(&sid).is_none());
        assert_eq!(session.active_streams(), 0, "the slot is released");
        assert!(
            !session.is_closed(),
            "no frame was started: session must survive"
        );
    }

    /// v2 writer queue: an abandoned mid-open registration cleans up
    /// with a FIN (the queue makes partial frames impossible) — the
    /// session survives.
    #[tokio::test]
    async fn test_registration_guard_partial_frame_sends_fin() {
        let (session, mut server) = establish_test_session("127.0.0.1:443").await;
        let sid = 13u32;
        let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        {
            let _guard = StreamRegistration {
                session: Arc::clone(&session),
                sid,
                frame_started: true,
                committed: false,
                permit: Some(permit),
            };
        }
        assert!(
            !session.is_closed(),
            "no partial frames with the writer queue: session survives"
        );
        assert!(session.streams.lock().unwrap().get(&sid).is_none());
        // The FIN for the abandoned sid went out (after the handshake
        // blob + settings frame).
        expect_handshake(&mut server).await;
        let (cmd, got_sid, _) =
            tokio::time::timeout(Duration::from_secs(2), read_frame(&mut server))
                .await
                .expect("FIN frame")
                .unwrap();
        assert_eq!(cmd, CMD_FIN);
        assert_eq!(got_sid, sid);
    }

    /// v2: commit moves the capacity slot to the caller; end_stream only
    /// unregisters — the semaphore is the count.
    #[tokio::test]
    async fn test_registration_commit_moves_permit() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 17u32;
        let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let guard = StreamRegistration {
            session: Arc::clone(&session),
            sid,
            frame_started: false,
            committed: false,
            permit: Some(session.try_reserve().unwrap()),
        };
        let permit = guard.commit();
        assert_eq!(session.active_streams(), 1);
        session.end_stream(sid, false).await;
        assert_eq!(
            session.active_streams(),
            1,
            "end_stream only unregisters; the permit is the count"
        );
        drop(permit);
        assert_eq!(session.active_streams(), 0);
    }

    /// v2: a draining session takes no new permits, even after slots free.
    #[tokio::test]
    async fn test_try_reserve_rejects_draining() {
        use crate::session::{ManagedSession as _, SessionState};
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let permit = session.try_reserve().unwrap();
        session.begin_drain();
        assert!(session.try_reserve().is_none(), "draining takes no permits");
        drop(permit);
        assert!(
            session.try_reserve().is_none(),
            "still draining after slots free"
        );
        session.close();
        assert_eq!(session.state(), SessionState::Closed);
    }

    /// 3B-3: a SYNACK carrying a dial error surfaces as a stream error
    /// (not a clean EOF) and the session stays healthy.
    #[tokio::test]
    async fn test_synack_with_data_surfaces_open_error() {
        let (session, mut server) = establish_test_session("127.0.0.1:443").await;
        expect_handshake(&mut server).await;
        let permit = session.try_reserve().unwrap();
        let mut stream = session
            .open_stream_direct(vec![0x01, 1, 2, 3, 4, 0, 80], permit)
            .await
            .unwrap();
        let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
        assert_eq!(cmd, CMD_SYN);
        let (cmd, _, _) = read_frame(&mut server).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        write_frame(&mut server, CMD_SYNACK, sid, b"refused: banned")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("read settles")
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(err.to_string().contains("refused"));
        assert!(!session.is_closed(), "target refusal keeps the session");
    }

    /// 3B-2: a full TCP sink queue kills just that stream — the queued
    /// data still drains, then the reader sees a reset (never a clean
    /// EOF), and the session survives.
    #[tokio::test]
    async fn test_hol_slow_consumer_reset_after_queue_drains() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 21u32;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);
        let sink = session.streams.lock().unwrap().get(&sid).cloned().unwrap();
        for _ in 0..STREAM_QUEUE_CAP {
            sink.send_data(vec![1u8; 8]).await;
        }
        drop(sink); // the test's clone must not keep the channel alive
        // The next dispatch finds a full queue: HOL kill.
        session.dispatch_data(sid, vec![2u8; 8]).await;
        assert!(session.streams.lock().unwrap().get(&sid).is_none());
        let mut buf = vec![0u8; STREAM_QUEUE_CAP * 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert!(buf.iter().all(|&b| b == 1), "queued data drains first");
        let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0u8; 1]))
            .await
            .expect("read settles")
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(
            !session.is_closed(),
            "a killed stream must not kill the session"
        );
    }

    /// Ad-hoc bulk-transfer check for the writer-queue path (50MB echo).
    #[tokio::test]
    async fn test_bulk_50mb() {
        let addr = "127.0.0.1:443";
        let (session, mut server) = establish_test_session(addr).await;
        expect_handshake(&mut server).await;
        let mut addr_rx = spawn_echo_server(server);

        let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
        let permit = session.try_reserve().unwrap();
        let stream = session
            .open_stream_direct(target.clone(), permit)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .unwrap();

        let payload: Vec<u8> = (0..50_000_000u32).map(|i| (i % 251) as u8).collect();
        let t0 = std::time::Instant::now();
        let (mut rd, mut wr) = tokio::io::split(stream);
        // Writer and reader run concurrently (a sequential test deadlocks
        // by design: the echo can only flow while both move).
        let writer = {
            let payload = payload.clone();
            tokio::spawn(async move {
                for chunk in payload.chunks(65536) {
                    wr.write_all(chunk).await.unwrap();
                }
            })
        };
        let reader = tokio::spawn(async move {
            let mut received = vec![0u8; 50_000_000];
            rd.read_exact(&mut received).await.unwrap();
            received
        });
        let (w, r) = tokio::join!(writer, reader);
        w.unwrap();
        let received = r.unwrap();
        assert_eq!(received.len(), 50_000_000);
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(i, &b)| b == (i as u32 % 251) as u8)
        );
        eprintln!("50MB echoed in {:?}", t0.elapsed());
    }

    /// Direct-path stream: multi-frame bulk write echoes back intact, and a
    /// server FIN surfaces as read EOF.
    #[tokio::test]
    async fn test_direct_stream_roundtrip_and_fin() {
        let addr = "127.0.0.1:443";
        let (session, mut server) = establish_test_session(addr).await;
        expect_handshake(&mut server).await;
        let mut addr_rx = spawn_echo_server(server);

        let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
        let permit = session.try_reserve().unwrap();
        let mut stream = session
            .open_stream_direct(target.clone(), permit)
            .await
            .unwrap();

        // Server got SYN + the address PSH.
        let (got_sid, got_addr) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .expect("address frame")
            .unwrap();
        assert_eq!(got_sid, stream.sid);
        assert_eq!(got_addr, target);

        // ~150KB in three writes (spans multiple u16 frames).
        let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload[..70000]).await.unwrap();
        stream.write_all(&payload[70000..140000]).await.unwrap();
        stream.write_all(&payload[140000..]).await.unwrap();

        let mut received = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(received, payload);

        // Server FIN → EOF: our shutdown sent FIN; the echo server answers
        // FIN → read EOF.
        stream.shutdown().await.unwrap();
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut b))
            .await
            .expect("FIN read timed out")
            .unwrap();
        assert_eq!(n, 0);
    }

    /// Three concurrent streams multiplexed on one session, echoing in
    /// parallel (sing-anytls semantics).
    #[tokio::test]
    async fn test_concurrent_streams_on_one_session() {
        let addr = "127.0.0.1:443";
        let (session, mut server) = establish_test_session(addr).await;
        expect_handshake(&mut server).await;
        let mut addr_rx = spawn_echo_server(server);

        // Open three streams concurrently on the same session.
        let target = |b: u8| vec![0x01, 127, 0, 0, b, 0x01, 0xbb];
        let (s1, s2, s3) = tokio::join!(
            session.open_stream(target(1), session.try_reserve().unwrap()),
            session.open_stream(target(2), session.try_reserve().unwrap()),
            session.open_stream(target(3), session.try_reserve().unwrap()),
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

        // The same session serves another stream afterwards.
        let mut s4 = session
            .open_stream(target(4), session.try_reserve().unwrap())
            .await
            .unwrap();
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
        let addr = "127.0.0.1:1443";
        let (session, mut server) = establish_test_session(addr).await;
        expect_handshake(&mut server).await;

        let target = vec![0x01, 127, 0, 0, 1, 0x00, 0x50];
        let mut s1 = session
            .open_stream(target.clone(), session.try_reserve().unwrap())
            .await
            .unwrap();
        let mut s2 = session
            .open_stream(target.clone(), session.try_reserve().unwrap())
            .await
            .unwrap();

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
}

#[cfg(test)]
mod uot_tests {
    use super::*;

    #[test]
    fn test_uot_request_uses_socks5_address_form() {
        // sing uot.ReadRequest parses the request destination with
        // M.SocksaddrSerializer (SOCKS5 ATYP), so the bytes a dial_udp
        // request carries after the isConnect byte must be SOCKS5 form.
        let v4 = addr::encode_address("1.2.3.4:53".parse().unwrap(), None);
        assert_eq!(v4, vec![0x01, 1, 2, 3, 4, 0, 53]);
        let v6 = addr::encode_address("[2606:4700:4700::1111]:853".parse().unwrap(), None);
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 1 + 16 + 2);
        let fqdn = addr::encode_address("1.2.3.4:443".parse().unwrap(), Some("example.com"));
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
        let (external, internal, external_addr, relay_addr) =
            crate::util::udp_loopback_pair().await.unwrap();
        tokio::spawn(uot_bridge(
            client_half,
            internal,
            external_addr,
            "8.8.8.8:53".parse().unwrap(),
            None,
        ));

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

    /// Third-party servers (e.g. nexi) answer UoT connect requests in the
    /// v1 packet layout; the bridge must detect that framing by the echoed
    /// destination instead of eating the atyp byte as a length prefix.
    #[tokio::test]
    async fn test_uot_bridge_v1_packet_response() {
        let (client_half, mut server_half) = tokio::io::duplex(65536);
        let (external, internal, external_addr, _relay_addr) =
            crate::util::udp_loopback_pair().await.unwrap();
        tokio::spawn(uot_bridge(
            client_half,
            internal,
            external_addr,
            "8.8.8.8:53".parse().unwrap(),
            None,
        ));

        // v1 packet: atyp=v4, addr=8.8.8.8, port=53, len=4, "pong".
        server_half
            .write_all(&[0x00, 8, 8, 8, 8, 0x00, 53, 0x00, 4])
            .await
            .unwrap();
        server_half.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 16];
        let (n, _from) = external.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    /// A v2-format datagram whose length high byte is a valid v1 atyp must
    /// NOT be misdetected as v1 (destination mismatch falls back to v2).
    #[tokio::test]
    async fn test_uot_bridge_v2_with_atyp_like_prefix() {
        let (client_half, mut server_half) = tokio::io::duplex(65536);
        let (external, internal, external_addr, _relay_addr) =
            crate::util::udp_loopback_pair().await.unwrap();
        tokio::spawn(uot_bridge(
            client_half,
            internal,
            external_addr,
            "8.8.8.8:53".parse().unwrap(),
            None,
        ));

        // v2 connect datagram: len=4 (high byte 0x00 == atyp v4), "pong".
        server_half.write_all(&[0x00, 0x04]).await.unwrap();
        server_half.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 16];
        let (n, _from) = external.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
}

#[cfg(test)]
mod uot_transport_tests {
    use super::*;

    const TEST_AUTH: &[u8] = b"test-auth";
    const TEST_SETTINGS: &[u8] = b"test-settings";

    /// Open a UoT stream on an in-memory test session; returns the
    /// transport and the server end of the session transport.
    async fn uot_test_transport(
        target: SocketAddr,
    ) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
        let addr = "127.0.0.1:2443";
        let (client_end, mut server_end) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(client_end);
        let session = AnyTlsSession::establish(
            addr,
            Box::new(read),
            Box::new(write),
            TEST_AUTH,
            TEST_SETTINGS,
        )
        .await
        .unwrap();
        // Consume the auth blob + settings frame the server would read.
        let mut auth = vec![0u8; TEST_AUTH.len()];
        server_end.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, TEST_AUTH);
        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_SETTINGS);
        let permit = session.try_reserve().unwrap();
        let (sid, rx, guard) = session
            .open_uot_stream(vec![0x01, 0, 0, 0, 0, 0, 0], permit)
            .await
            .unwrap();
        let permit = guard.commit();
        // Consume the opening pair (SYN + address PSH).
        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_SYN);
        let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        (
            Arc::new(AnyTlsUotTransport {
                session,
                sid,
                rx: tokio::sync::Mutex::new(rx),
                mode: tokio::sync::Mutex::new(None),
                target,
                target_domain: None,
                _permit: permit,
            }),
            server_end,
        )
    }

    /// UoT v2 framing: send writes PSH(`u16 len + payload`) to the session;
    /// an inbound PSH datagram is delivered by recv.
    #[tokio::test]
    async fn uot_transport_frame_roundtrip() {
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (transport, mut server) = uot_test_transport(target).await;

        transport.send_packet(b"dns-packet").await.unwrap();
        // The datagram PSH follows the consumed opening pair.
        let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(data.len(), 2 + 10);
        assert_eq!(&data[2..], b"dns-packet");

        // server → client datagram frame
        let mut frame = Vec::new();
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.extend_from_slice(b"pong!");
        write_frame(&mut server, CMD_PSH, sid, &frame)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(src, target);
    }

    /// Backpressure guard: a flood of inbound datagrams with no recv call
    /// must be dropped at the demux queue, never block the session — the
    /// transport keeps working afterwards.
    #[tokio::test]
    async fn uot_transport_drops_when_consumer_stops() {
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let (transport, mut server) = uot_test_transport(target).await;
        let sid = transport.sid;

        // Flood far more datagrams than the demux queue holds.
        let mut frame = Vec::new();
        frame.extend_from_slice(&5u16.to_be_bytes());
        frame.extend_from_slice(b"flood");
        for _ in 0..(UOT_DRAIN_QUEUE_CAP * 4) {
            write_frame(&mut server, CMD_PSH, sid, &frame)
                .await
                .unwrap();
        }
        // The transport still works afterwards (overflow was dropped).
        transport.send_packet(b"ping").await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), transport.recv_packet(&mut buf))
            .await
            .expect("recv must not stall")
            .unwrap();
        assert_eq!(&buf[..n], b"flood");
    }
}
