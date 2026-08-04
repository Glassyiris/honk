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
//! - `min_idle_session` keeps that many idle sessions pre-established;
//! - cold URLTest uses a two-phase, cap-counted speculative checkout: loser
//!   cancellation owns and closes detached dials, while only the finalized
//!   winner commits into the captured runtime-generation pool.

use crate::tls::TlsConnector;
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::addr;
use super::{
    PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound, ProxyStream,
    TcpOutbound, UdpWarmStatus, WarmableOutbound,
};
use crate::session::{ManagedSession as _, SpeculativeCheckout};

/// sing uot v2 magic address (`protocol/anytls/outbound.go`,
/// `common/uot/protocol.go`): UDP-over-TCP streams are opened to this
/// pseudo-target inside the AnyTLS session.
const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";

/// UoT v1 packet address types (sing uot v1 / non-connect form).
const UOT_V1_ATYP_V4: u8 = 0x00;
const UOT_V1_ATYP_V6: u8 = 0x01;
const UOT_V1_ATYP_DOMAIN: u8 = 0x02;

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

/// Per-stream demux queue depth (frames). A full queue parks frames in
/// the session overflow instead of blocking the demux.
const STREAM_QUEUE_CAP: usize = 64;
/// Soft caps on parked overflow (data frames/payload, session-wide and
/// per stream). Tripping one never blocks the demux: the frame parks and
/// the stall watchdog reaps consumers that make no flush progress for
/// [`OVERFLOW_STALL_GRACE`]. Soft because a fast peer can burst past
/// them in the milliseconds before the reader task is first scheduled.
const SESSION_OVERFLOW_CAP: usize = 512;
const STREAM_OVERFLOW_BYTES_CAP: usize = 2 * 1024 * 1024;
const SESSION_OVERFLOW_BYTES_CAP: usize = 8 * 1024 * 1024;
/// Emergency session-wide hard caps. Tripping one reaps the most-stalled
/// parked stream on the spot when it is past the grace; while every
/// stalled stream is inside the grace the demux waits bounded
/// [`OVERFLOW_EMERGENCY_WAIT`] rounds for reader progress (woken by
/// flushes) — TCP-style backpressure, since at wire rate a healthy burst
/// fills any feasible buffer before the reader task is first scheduled,
/// so the only alternatives are blocking reads or killing the innocent.
const SESSION_OVERFLOW_HARD_CAP: usize = 768;
const SESSION_OVERFLOW_HARD_BYTES_CAP: usize = 12 * 1024 * 1024;
/// Terminal events (Fin/Error) parked per stream. They bypass the frame
/// quota — a full quota must not break stream termination — but are not
/// unbounded: the stream is already terminating, so extras are dropped.
const MAX_OVERFLOW_TERMINAL_EVENTS: usize = 2;
/// How long a parked stream may go without flush progress before the
/// watchdog judges it a stuck consumer and resets it. Parked bytes are
/// not a stall — only the absence of reader progress is.
const OVERFLOW_STALL_GRACE: Duration = Duration::from_secs(3);
/// One bounded wait round at an emergency hard cap with no stream past
/// the grace. Sized well above the 12–16ms reader-task startup delay
/// measured on a 9.4Gbps burst (a healthy reader's first flush wakes the
/// wait immediately), and far below the stall grace so a genuinely stuck
/// consumer is reaped the round it crosses the grace.
const OVERFLOW_EMERGENCY_WAIT: Duration = Duration::from_millis(100);
/// Overflow watchdog tick. The task is spawned by the first park,
/// retires when the overflow drains, and is aborted on session close.
const OVERFLOW_WATCHDOG_TICK: Duration = Duration::from_millis(250);
const MAX_STREAM_ERROR_SOURCE_BYTES: usize = 1024;

/// Transport halves behind trait objects so tests can drive a session over
/// an in-memory duplex instead of a real TLS connection.
type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// AnyTLS proxy handler. Stateless: the node's session pool lives in its
/// generation-owned runtime; node-based calls (tests, standalone probing)
/// get a throwaway pool per call.
#[derive(Debug, Default, Clone)]
pub struct AnyTlsHandler;

/// Key inside a node's own session pool: pools are per-node (runtime
/// registry), so the key is a constant.
pub(crate) const POOL_KEY: &str = "self";

/// Pool configuration for one AnyTLS node (least-loaded scheduling
/// without a stream cap (sing-anytls parity); the hard session cap still
/// applies). Shared by the generation-owned pools and throwaway pools.
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
    Data(Vec<u8>),
    Fin,
    Error(Arc<str>),
}

impl StreamEvent {
    fn payload_len(&self) -> usize {
        match self {
            Self::Data(data) => data.len(),
            Self::Fin | Self::Error(_) => 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OverflowUsage {
    frames: usize,
    bytes: usize,
}

#[derive(Default)]
struct StreamOverflow {
    events: VecDeque<StreamEvent>,
    /// Data frames only: terminal events bypass the frame quota.
    frames: usize,
    bytes: usize,
    terminal_events: usize,
    last_progress_at: Option<tokio::time::Instant>,
}

#[derive(Default)]
struct OverflowState {
    streams: HashMap<u32, StreamOverflow>,
    frames: usize,
    bytes: usize,
    flushing: HashSet<u32>,
    flush_requested: HashSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverflowLimit {
    SessionFrames,
    StreamBytes,
    SessionBytes,
    /// Watchdog reap: no flush progress for a full stall grace.
    StallGrace,
}

impl OverflowLimit {
    fn as_str(self) -> &'static str {
        match self {
            Self::SessionFrames => "session_frames",
            Self::StreamBytes => "stream_bytes",
            Self::SessionBytes => "session_bytes",
            Self::StallGrace => "stall_grace",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverflowVictim {
    sid: u32,
    limit: OverflowLimit,
    session: OverflowUsage,
    stream: OverflowUsage,
    stalled_for: Duration,
}

enum OverflowAction {
    Parked,
    /// A terminal event past the per-stream cap: the stream is already
    /// terminating, so dropping it is harmless.
    Dropped,
    /// Emergency-cap reap: the caller kills the victim outside the lock
    /// and retries with the returned event.
    Kill(OverflowVictim, StreamEvent),
    /// Hard cap with every stalled stream inside the grace: the caller
    /// waits up to the given bound for flush progress, then retries with
    /// the returned event.
    Wait(StreamEvent, Duration),
}

impl OverflowState {
    fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }
    fn has(&self, sid: u32) -> bool {
        self.streams.contains_key(&sid)
    }

    fn usage(&self) -> OverflowUsage {
        OverflowUsage {
            frames: self.frames,
            bytes: self.bytes,
        }
    }

    fn stream_usage(&self, sid: u32) -> OverflowUsage {
        self.streams
            .get(&sid)
            .map(|stream| OverflowUsage {
                frames: stream.frames,
                bytes: stream.bytes,
            })
            .unwrap_or_default()
    }

    /// Soft bounds, checked for data frames only (terminal events bypass
    /// the quota). Session-wide bounds first: a stream past its soft cap
    /// keeps parking until the watchdog's grace expires, so only this
    /// order keeps session memory capped while stall age accrues.
    fn limit_for(&self, sid: u32, event: &StreamEvent) -> Option<OverflowLimit> {
        let bytes = event.payload_len();
        if bytes != 0 && self.bytes.saturating_add(bytes) > SESSION_OVERFLOW_BYTES_CAP {
            return Some(OverflowLimit::SessionBytes);
        }
        if self.frames >= SESSION_OVERFLOW_CAP {
            return Some(OverflowLimit::SessionFrames);
        }
        if bytes != 0
            && self.stream_usage(sid).bytes.saturating_add(bytes) > STREAM_OVERFLOW_BYTES_CAP
        {
            return Some(OverflowLimit::StreamBytes);
        }
        None
    }

    /// Time since the reader last made flush progress on this stream (or
    /// since the first park, if it never has).
    fn stalled_for(&self, sid: u32) -> Duration {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
            .map(|progress| progress.elapsed())
            .unwrap_or_default()
    }

    fn last_progress_at(&self, sid: u32) -> Option<tokio::time::Instant> {
        self.streams
            .get(&sid)
            .and_then(|stream| stream.last_progress_at)
    }

    fn restore_last_progress_at(&mut self, sid: u32, progress: Option<tokio::time::Instant>) {
        if let (Some(stream), Some(progress)) = (self.streams.get_mut(&sid), progress) {
            stream.last_progress_at = Some(progress);
        }
    }

    /// A parked frame reached the stream queue: the consumer is alive.
    fn note_progress(&mut self, sid: u32) {
        if let Some(stream) = self.streams.get_mut(&sid) {
            stream.last_progress_at = Some(tokio::time::Instant::now());
        }
    }

    /// (data frames, payload bytes) — terminal events bypass the quota.
    fn event_weight(event: &StreamEvent) -> (usize, usize) {
        match event {
            StreamEvent::Data(data) => (1, data.len()),
            StreamEvent::Fin | StreamEvent::Error(_) => (0, 0),
        }
    }

    fn push_back(&mut self, sid: u32, event: StreamEvent) {
        let (frames, bytes) = Self::event_weight(&event);
        let stream = self.streams.entry(sid).or_default();
        stream
            .last_progress_at
            .get_or_insert_with(tokio::time::Instant::now);
        stream.events.push_back(event);
        stream.frames += frames;
        stream.bytes += bytes;
        stream.terminal_events += usize::from(frames == 0);
        self.frames += frames;
        self.bytes += bytes;
    }

    fn push_front(&mut self, sid: u32, event: StreamEvent) {
        let (frames, bytes) = Self::event_weight(&event);
        let stream = self.streams.entry(sid).or_default();
        stream
            .last_progress_at
            .get_or_insert_with(tokio::time::Instant::now);
        stream.events.push_front(event);
        stream.frames += frames;
        stream.bytes += bytes;
        stream.terminal_events += usize::from(frames == 0);
        self.frames += frames;
        self.bytes += bytes;
    }

    fn pop_front(&mut self, sid: u32) -> Option<StreamEvent> {
        let (event, empty) = {
            let stream = self.streams.get_mut(&sid)?;
            let event = stream.events.pop_front()?;
            let (frames, bytes) = Self::event_weight(&event);
            stream.frames -= frames;
            stream.bytes -= bytes;
            stream.terminal_events -= usize::from(frames == 0);
            self.frames -= frames;
            self.bytes -= bytes;
            (event, stream.events.is_empty())
        };
        if empty {
            self.streams.remove(&sid);
        }
        Some(event)
    }

    fn remove_stream(&mut self, sid: u32) -> OverflowUsage {
        let Some(stream) = self.streams.remove(&sid) else {
            return OverflowUsage::default();
        };
        self.frames -= stream.frames;
        self.bytes -= stream.bytes;
        OverflowUsage {
            frames: stream.frames,
            bytes: stream.bytes,
        }
    }

    fn clear(&mut self) -> OverflowUsage {
        let usage = self.usage();
        self.streams.clear();
        self.frames = 0;
        self.bytes = 0;
        usage
    }

    fn request_flush(&mut self, sid: u32) -> bool {
        if self.flushing.insert(sid) {
            true
        } else {
            self.flush_requested.insert(sid);
            false
        }
    }

    fn finish_flush(&mut self, sid: u32) -> bool {
        if self.flush_requested.remove(&sid) {
            true
        } else {
            self.flushing.remove(&sid);
            false
        }
    }

    fn cancel_flush(&mut self, sid: u32) {
        self.flushing.remove(&sid);
        self.flush_requested.remove(&sid);
    }

    /// The parked stream with the oldest flush progress (ties to the
    /// lowest sid): the prime stuck-consumer suspect at a session cap.
    fn most_stalled_stream(&self) -> Option<u32> {
        self.streams
            .iter()
            .filter_map(|(&sid, stream)| stream.last_progress_at.map(|at| (at, sid)))
            .min()
            .map(|(_, sid)| sid)
    }

    /// The most-stalled parked stream among those past
    /// [`OVERFLOW_STALL_GRACE`] without flush progress.
    fn most_stalled_past_grace(&self) -> Option<u32> {
        self.streams
            .iter()
            .filter_map(|(&sid, stream)| stream.last_progress_at.map(|at| (at, sid)))
            .filter(|(at, _)| at.elapsed() >= OVERFLOW_STALL_GRACE)
            .min()
            .map(|(_, sid)| sid)
    }

    /// Detach a parked stream's overflow and snapshot its usage for the
    /// kill log line.
    fn take_victim(&mut self, sid: u32, limit: OverflowLimit) -> OverflowVictim {
        let victim = OverflowVictim {
            sid,
            limit,
            session: self.usage(),
            stream: self.stream_usage(sid),
            stalled_for: self.stalled_for(sid),
        };
        self.remove_stream(sid);
        victim
    }

    /// Emergency session-wide bounds on parked data.
    fn hard_limit_for(&self, event: &StreamEvent) -> Option<OverflowLimit> {
        let bytes = event.payload_len();
        if self.bytes.saturating_add(bytes) > SESSION_OVERFLOW_HARD_BYTES_CAP {
            return Some(OverflowLimit::SessionBytes);
        }
        if self.frames >= SESSION_OVERFLOW_HARD_CAP {
            return Some(OverflowLimit::SessionFrames);
        }
        None
    }

    /// One wait round at a hard cap, clamped to the nearest grace expiry
    /// so a stream crossing the grace is reaped without a stale round.
    fn emergency_wait(&self) -> Duration {
        let remaining = self
            .most_stalled_stream()
            .map(|sid| OVERFLOW_STALL_GRACE.saturating_sub(self.stalled_for(sid)))
            .unwrap_or(OVERFLOW_EMERGENCY_WAIT);
        remaining.min(OVERFLOW_EMERGENCY_WAIT)
    }

    /// Admit an overflow-bound event, parking it inline or returning the
    /// verdict for the caller to execute outside the lock. Below the
    /// emergency hard caps every frame parks and the watchdog reaps
    /// consumers stalled past [`OVERFLOW_STALL_GRACE`]. At a hard cap a
    /// past-grace stream is reaped on the spot; with every stalled stream
    /// inside the grace the caller waits bounded
    /// [`OVERFLOW_EMERGENCY_WAIT`] rounds for flush progress (woken via
    /// the session overflow notify) — bounded TCP-style backpressure, and
    /// each elapsed round re-judges, so a stream is only ever reaped once
    /// its full grace has expired. Terminal events bypass the frame quota
    /// but are capped per stream: the stream is already terminating, so
    /// extras drop.
    fn admit(&mut self, sid: u32, event: StreamEvent) -> OverflowAction {
        if !matches!(event, StreamEvent::Data(_)) {
            let terminals = self
                .streams
                .get(&sid)
                .map(|stream| stream.terminal_events)
                .unwrap_or_default();
            if terminals >= MAX_OVERFLOW_TERMINAL_EVENTS {
                return OverflowAction::Dropped;
            }
            self.push_back(sid, event);
            return OverflowAction::Parked;
        }
        if self.limit_for(sid, &event).is_none() {
            self.push_back(sid, event);
            return OverflowAction::Parked;
        }
        let Some(hard) = self.hard_limit_for(&event) else {
            self.push_back(sid, event);
            return OverflowAction::Parked;
        };
        if let Some(victim_sid) = self.most_stalled_past_grace() {
            return OverflowAction::Kill(self.take_victim(victim_sid, hard), event);
        }
        OverflowAction::Wait(event, self.emergency_wait())
    }
}

/// Per-stream demux delivery channel.
#[derive(Clone)]
enum StreamSink {
    /// TCP streams: bounded queue plus the session overflow. Payload is
    /// retained in order; a stream parked at an overflow cap with no
    /// flush progress past [`OVERFLOW_STALL_GRACE`] gets only its own
    /// stream reset.
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

    /// Deliver a FIN. TCP waits for capacity; UoT uses best-effort
    /// delivery so a full datagram queue cannot backpressure the session.
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
    async fn send_error(&self, message: Arc<str>) {
        let event = StreamEvent::Error(message);
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
        self.session.discard_overflow(self.sid);
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

impl FrameCommand {
    /// Serialized size (header + payload).
    fn wire_len(&self) -> usize {
        let payload = match self {
            FrameCommand::Data { payload, .. } | FrameCommand::Control { payload, .. } => {
                payload.len()
            }
        };
        FRAME_HEADER_LEN + payload
    }

    /// Append the serialized frame to `buf`.
    fn encode_into(&self, buf: &mut bytes::BytesMut) {
        use bytes::BufMut as _;
        let (cmd, sid, payload) = match self {
            FrameCommand::Data { sid, payload, .. } => (CMD_PSH, *sid, payload),
            FrameCommand::Control { cmd, sid, payload } => (*cmd, *sid, payload),
        };
        buf.put_u8(cmd);
        buf.put_u32(sid);
        buf.put_u16(payload.len() as u16);
        buf.extend_from_slice(payload);
    }
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

    /// Move up to `max_frames` already-queued commands (staying under
    /// `max_bytes` of serialized payload) to the end of `out` without
    /// blocking. Only drains what is queued *now* — never waits, so it adds
    /// no latency to a live writer loop.
    fn drain_available(&self, out: &mut Vec<FrameCommand>, max_frames: usize, max_bytes: usize) {
        let mut q = self.queue.lock().unwrap();
        let mut bytes = 0usize;
        let mut taken = 0usize;
        while taken < max_frames {
            let Some(front) = q.front() else { break };
            let next = bytes + front.wire_len();
            if taken > 0 && next > max_bytes {
                break;
            }
            bytes = next;
            out.push(q.pop_front().expect("front checked"));
            taken += 1;
        }
    }

    fn clear(&self) {
        self.queue.lock().unwrap().clear();
    }
}

/// Batch caps for the writer's opportunistic gather: after the blocking
/// pop, at most this many extra queued frames (or this many serialized
/// bytes) ride the same `write_all` + single `flush`. Only what is already
/// queued is taken — batching never waits, so it adds no latency.
const WRITER_BATCH_MAX_FRAMES: usize = 64;
const WRITER_BATCH_MAX_BYTES: usize = 256 * 1024;

/// The single writer task for a session: drains the queue in order and
/// gather-writes whole batches per flush — one `write_all` of the
/// concatenated frames instead of a header/payload write pair plus flush
/// per frame (profiling showed flush-per-frame dominating CPU at line
/// rate). Order is preserved; framing is byte-level so batches are
/// transparent to the peer. A physical write failure kills the session
/// (sing `writeControlFrame` parity) — frames already queued are lost
/// with it.
async fn session_writer(
    session: Arc<AnyTlsSession>,
    mut write: BoxedWriter,
    queue: Arc<WriterQueue>,
) {
    let mut batch: Vec<FrameCommand> = Vec::with_capacity(WRITER_BATCH_MAX_FRAMES);
    let mut buf = bytes::BytesMut::with_capacity(64 * 1024);
    loop {
        batch.push(queue.pop().await);
        queue.drain_available(
            &mut batch,
            WRITER_BATCH_MAX_FRAMES - 1,
            WRITER_BATCH_MAX_BYTES,
        );
        buf.clear();
        for cmd in &batch {
            cmd.encode_into(&mut buf);
        }
        let failed = match write.write_all(&buf).await {
            Ok(()) => write.flush().await.is_err(),
            Err(_) => true,
        };
        // Dropping the batch here releases data permits only after the
        // bytes are actually written — backpressure spans the write.
        batch.clear();
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
    /// AnyTLS server address retained for diagnostics.
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
    /// Per-stream ordered overflow for full TCP queues, with exact session
    /// and stream frame/byte accounting.
    overflow: parking_lot::Mutex<OverflowState>,
    /// Wakes the demux waiting at an emergency hard cap when a flush
    /// actually frees overflow space (reader progress).
    overflow_notify: tokio::sync::Notify,
    /// Overflow stall watchdog (reaps parked streams with no flush
    /// progress past the grace): spawned by the first park, retires when
    /// the overflow drains, aborted on close. `None` while not running.
    watchdog: Mutex<Option<tokio::task::AbortHandle>>,
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
            overflow: parking_lot::Mutex::new(OverflowState::default()),
            overflow_notify: tokio::sync::Notify::new(),
            watchdog: Mutex::new(None),
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
        let permit = self.acquire_data_permit().await?;
        self.enqueue_data_with_permit(sid, payload, permit)
    }

    /// Acquire one writer-queue data permit (async).
    async fn acquire_data_permit(&self) -> std::io::Result<tokio::sync::OwnedSemaphorePermit> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
        Arc::clone(&self.writer_q.data_permits)
            .acquire_owned()
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "AnyTLS writer queue is closed",
                )
            })
    }

    /// Try to enqueue a data frame without waiting; returns the payload
    /// back when the writer queue is full (caller keeps it in its slot).
    fn try_enqueue_data(&self, sid: u32, payload: bytes::Bytes) -> Result<(), bytes::Bytes> {
        if self.is_closed() {
            return Err(payload);
        }
        let Ok(permit) = Arc::clone(&self.writer_q.data_permits).try_acquire_owned() else {
            return Err(payload);
        };
        self.writer_q.push_batch([FrameCommand::Data {
            sid,
            payload,
            _permit: permit,
        }]);
        Ok(())
    }

    /// Enqueue a data frame with an already-acquired permit.
    fn enqueue_data_with_permit(
        &self,
        sid: u32,
        payload: bytes::Bytes,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "AnyTLS session is closed",
            ));
        }
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

    /// Reliably enqueue the mandatory UoT setup request. Unlike application
    /// datagrams, setup waits for bounded writer capacity or fails; reporting
    /// success after dropping it would publish an unusable transport.
    async fn write_uot_setup_frame(&self, sid: u32, data: &[u8]) -> std::io::Result<()> {
        self.enqueue_data(sid, bytes::Bytes::copy_from_slice(data))
            .await
    }

    async fn write_uot_datagram(&self, sid: u32, payload: bytes::Bytes) -> std::io::Result<()> {
        self.enqueue_uot(sid, payload)
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
    fn end_uot_stream(&self, sid: u32) {
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
        // A dead stream's parked frames go with it.
        self.discard_overflow(sid);
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
        self.clear_overflow();
        if let Some(handle) = self.demux.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.writer_task.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.watchdog.lock().unwrap().take() {
            handle.abort();
        }
        self.writer_q.clear();
        debug!("AnyTLS session {} for {} closed", self.seq, self.addr);
    }

    /// Deliver a server payload frame to its stream. TCP sinks park a
    /// full per-stream queue into the session overflow (flushed later by
    /// the reader's progress — see [`Self::flush_overflow`]). Below the
    /// emergency hard caps parking never waits: every frame parks and the
    /// stall watchdog resets consumers with no flush progress past
    /// [`OVERFLOW_STALL_GRACE`] — parked bytes are not a stall (a fast
    /// peer bursts megabytes before the reader task is first scheduled),
    /// only missing flush progress past the grace kills. At a hard cap
    /// the demux waits bounded rounds for that progress (see
    /// [`Self::park_overflow`]). UoT sinks drop on full.
    async fn dispatch_data(self: &Arc<Self>, sid: u32, data: Vec<u8>) {
        // Ordering: if this sid already has parked frames, the new frame
        // goes behind them, never past them.
        if self.overflow_has(sid) {
            self.park_overflow(sid, StreamEvent::Data(data)).await;
            return;
        }
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => match tx.try_send(StreamEvent::Data(data)) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(ev)) => {
                    self.park_overflow(sid, ev).await;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.streams.lock().unwrap().remove(&sid);
                    self.discard_overflow(sid);
                }
            },
            Some(sink) => {
                if !sink.send_data(data).await {
                    // Stream task died without unregistering; clean up.
                    self.streams.lock().unwrap().remove(&sid);
                    self.discard_overflow(sid);
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

    fn overflow_sink_is_live(&self, sid: u32) -> bool {
        let live = matches!(
            self.streams.lock().unwrap().get(&sid),
            Some(StreamSink::Tcp(tx)) if !tx.is_closed()
        );
        if !live {
            self.streams.lock().unwrap().remove(&sid);
        }
        live
    }

    fn overflow_has(&self, sid: u32) -> bool {
        self.overflow.lock().has(sid)
    }

    fn discard_overflow(&self, sid: u32) -> OverflowUsage {
        self.overflow.lock().remove_stream(sid)
    }

    fn clear_overflow(&self) -> OverflowUsage {
        self.overflow.lock().clear()
    }

    fn kill_overflow_victim(&self, victim: OverflowVictim) {
        let stall_ms = u64::try_from(victim.stalled_for.as_millis()).unwrap_or(u64::MAX);
        let queue_capacity = match self.streams.lock().unwrap().get(&victim.sid) {
            Some(StreamSink::Tcp(tx)) => tx.capacity(),
            Some(StreamSink::Uot(_)) | None => 0,
        };
        warn!(
            session = self.seq,
            victim_sid = victim.sid,
            cap_reason = victim.limit.as_str(),
            after_stall_grace = victim.stalled_for >= OVERFLOW_STALL_GRACE,
            session_frames = victim.session.frames,
            session_bytes = victim.session.bytes,
            stream_frames = victim.stream.frames,
            stream_bytes = victim.stream.bytes,
            stall_ms,
            queue_capacity,
            "AnyTLS overflow killed stream"
        );
        self.killed_streams.lock().unwrap().insert(victim.sid);
        self.streams.lock().unwrap().remove(&victim.sid);
        if self
            .enqueue_control(CMD_FIN, victim.sid, bytes::Bytes::new())
            .is_err()
        {
            self.fail(anyhow::anyhow!("writer queue unavailable on overflow kill"));
        }
    }

    /// Park an event in the session overflow. Below the emergency hard
    /// caps parking always succeeds without waiting and the stall
    /// watchdog reaps consumers with no flush progress past
    /// [`OVERFLOW_STALL_GRACE`]. At a hard cap a past-grace stream is
    /// reaped on the spot; with every stalled stream inside the grace the
    /// demux waits bounded [`OVERFLOW_EMERGENCY_WAIT`] rounds for reader
    /// progress — the TCP-style backpressure that actually bounds parked
    /// memory at wire rate — and each elapsed round re-judges, so a
    /// stream is only ever reaped once its full grace has expired.
    async fn park_overflow(self: &Arc<Self>, sid: u32, mut event: StreamEvent) {
        loop {
            if !self.overflow_sink_is_live(sid) {
                self.discard_overflow(sid);
                return;
            }
            // Register before admitting so a flush landing between the
            // decision and the wait cannot be missed.
            let wait = self.overflow_notify.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();

            let action = self.overflow.lock().admit(sid, event);
            match action {
                OverflowAction::Parked => {
                    self.flush_overflow(sid);
                    if !self.overflow_sink_is_live(sid) {
                        self.discard_overflow(sid);
                    }
                    self.ensure_watchdog();
                    return;
                }
                OverflowAction::Dropped => return,
                OverflowAction::Kill(victim, returned) => {
                    let own = victim.sid == sid;
                    self.kill_overflow_victim(victim);
                    if own {
                        return;
                    }
                    event = returned;
                }
                OverflowAction::Wait(returned, wait_for) => {
                    event = returned;
                    let _ = tokio::time::timeout(wait_for, wait).await;
                }
            }
        }
    }

    /// Spawn the overflow stall watchdog unless it is already running.
    /// Lock order (overflow → watchdog) matches the watchdog's retire
    /// path, so a retiring watchdog and a new park can never both believe
    /// the other side is handling a non-empty overflow.
    fn ensure_watchdog(self: &Arc<Self>) {
        if self.overflow.lock().is_empty() {
            return;
        }
        let mut handle = self.watchdog.lock().unwrap();
        if handle.is_none() {
            let session = Arc::clone(self);
            *handle = Some(
                tokio::spawn(async move { session.run_overflow_watchdog().await }).abort_handle(),
            );
        }
    }

    /// Reap the most-stalled parked stream once it has made no flush
    /// progress for a full [`OVERFLOW_STALL_GRACE`] (one per tick);
    /// retire when the overflow drains — the next park respawns.
    async fn run_overflow_watchdog(self: &Arc<Self>) {
        let mut ticker = tokio::time::interval(OVERFLOW_WATCHDOG_TICK);
        loop {
            ticker.tick().await;
            if self.is_closed() {
                return;
            }
            let victim = {
                let mut overflow = self.overflow.lock();
                if overflow.is_empty() {
                    *self.watchdog.lock().unwrap() = None;
                    return;
                }
                overflow
                    .most_stalled_past_grace()
                    .map(|sid| overflow.take_victim(sid, OverflowLimit::StallGrace))
            };
            if let Some(victim) = victim {
                self.kill_overflow_victim(victim);
            }
        }
    }

    /// Move one sid's parked events into its queue without scanning
    /// siblings; wakes a demux waiting at a hard cap when space was
    /// actually freed.
    fn flush_overflow(&self, sid: u32) {
        if self.drain_overflow(sid) {
            self.overflow_notify.notify_waiters();
        }
    }

    /// Returns whether any parked event reached the stream queue.
    fn drain_overflow(&self, sid: u32) -> bool {
        {
            let mut overflow = self.overflow.lock();
            if !overflow.has(sid) || !overflow.request_flush(sid) {
                return false;
            }
        }

        let mut moved = false;
        loop {
            let tx = match self.streams.lock().unwrap().get(&sid).cloned() {
                Some(StreamSink::Tcp(tx)) => tx,
                _ => {
                    let mut overflow = self.overflow.lock();
                    overflow.remove_stream(sid);
                    overflow.cancel_flush(sid);
                    drop(overflow);
                    return moved;
                }
            };

            let mut overflow = self.overflow.lock();
            let last_progress_at = overflow.last_progress_at(sid);
            let Some(event) = overflow.pop_front(sid) else {
                if overflow.finish_flush(sid) {
                    drop(overflow);
                    continue;
                }
                drop(overflow);
                return moved;
            };
            match tx.try_send(event) {
                Ok(()) => {
                    overflow.note_progress(sid);
                    moved = true;
                }
                Err(mpsc::error::TrySendError::Full(event)) => {
                    overflow.push_front(sid, event);
                    overflow.restore_last_progress_at(sid, last_progress_at);
                    if overflow.finish_flush(sid) {
                        drop(overflow);
                        continue;
                    }
                    drop(overflow);
                    return moved;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    overflow.remove_stream(sid);
                    overflow.cancel_flush(sid);
                    drop(overflow);
                    self.streams.lock().unwrap().remove(&sid);
                    return moved;
                }
            }
        }
    }

    async fn dispatch_fin(self: &Arc<Self>, sid: u32) {
        if self.overflow_has(sid) {
            self.park_overflow(sid, StreamEvent::Fin).await;
            return;
        }
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => match tx.try_send(StreamEvent::Fin) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(event)) => {
                    self.park_overflow(sid, event).await;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.streams.lock().unwrap().remove(&sid);
                    self.discard_overflow(sid);
                }
            },
            Some(sink) => sink.send_fin().await,
            None => {}
        }
    }

    async fn dispatch_error(self: &Arc<Self>, sid: u32, message: Arc<str>) {
        if self.overflow_has(sid) {
            self.park_overflow(sid, StreamEvent::Error(message)).await;
            return;
        }
        let sink = self.streams.lock().unwrap().get(&sid).cloned();
        match sink {
            Some(StreamSink::Tcp(tx)) => {
                let event = StreamEvent::Error(message);
                match tx.try_send(event) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(event)) => {
                        self.park_overflow(sid, event).await;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.streams.lock().unwrap().remove(&sid);
                        self.discard_overflow(sid);
                    }
                }
            }
            Some(sink) => sink.send_error(message).await,
            None => {}
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
                if !data.is_empty() {
                    let shown = &data[..data.len().min(MAX_STREAM_ERROR_SOURCE_BYTES)];
                    let suffix = if shown.len() == data.len() {
                        ""
                    } else {
                        " [truncated]"
                    };
                    let message: Arc<str> = Arc::from(format!(
                        "target refused: {}{suffix}",
                        String::from_utf8_lossy(shown)
                    ));
                    debug!(
                        "AnyTLS session {} sid={} remote dial error: {}",
                        session.seq, sid, message
                    );
                    session.dispatch_error(sid, message).await;
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
    tls_connector: Option<Arc<TlsConnector>>,
) -> anyhow::Result<Arc<AnyTlsSession>> {
    let (read, write, auth, settings) =
        connect_transport(node, addr, connect_timeout, None, tls_connector).await?;
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
    tls_connector: Option<Arc<TlsConnector>>,
) -> anyhow::Result<(BoxedReader, BoxedWriter, Vec<u8>, Vec<u8>)> {
    let password = AnyTlsHandler::resolve_password(node);
    let auth_key = Sha256::digest(password.as_bytes());

    let tcp = match tcp {
        Some(tcp) => tcp,
        // `addr` is a log label, not a dial target — always dial the node's
        // own address.
        None => {
            crate::util::connect_outbound(
                &format!("{}:{}", node.host(), node.port),
                connect_timeout,
            )
            .await?
        }
    };
    debug!("AnyTLS: TCP connected to {}", addr);

    let connector = match tls_connector {
        Some(connector) => connector,
        None => Arc::new(AnyTlsHandler::build_tls_connector(node)?),
    };
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
    fn ensure_janitor(
        node: &Node,
        pool: &Arc<AnyTlsPool>,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
    ) {
        // Always run the janitor: it pre-establishes min_idle sessions
        // (default 1) and, just as importantly, reaps idle-expired ones —
        // skipping it entirely leaks idle sessions into the pool forever.
        // An explicit `min_idle_session=0` disables standby sessions only,
        // never pruning.
        // Default 1 (not sing-box's 0): a single standby session per node
        // keeps every dial warm after the first — cold dials otherwise pay
        // TCP connect + TLS handshake (2 RTT) per burst.
        let min_idle = node.anytls_min_idle_session.unwrap_or(1);
        let idle_timeout = Duration::from_secs(
            node.anytls_idle_session_timeout
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
        );
        let prewarm_node = node.clone();
        let label = format!("{}:{}", node.host(), node.port);
        pool.ensure_janitor(POOL_KEY, min_idle, idle_timeout, move || {
            let node = prewarm_node.clone();
            let label = label.clone();
            let runtime = runtime.clone();
            async move {
                let tls_connector = runtime
                    .as_ref()
                    .map(|runtime| runtime.anytls_tls_connector())
                    .transpose()?;
                dial_session(&node, &label, Duration::from_secs(10), tls_connector).await
            }
        });
    }

    /// Warm the explicit generation-owned AnyTLS pool. The generic dial seam
    /// keeps the production path small while letting unit tests use the
    /// in-memory AnyTLS session fixture instead of a network connection.
    async fn warm_pool_with<F, Fut>(
        runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
        dial: F,
    ) -> anyhow::Result<UdpWarmStatus>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send + 'static,
    {
        if runtime.node.protocol != NodeProtocol::AnyTLS {
            return Ok(UdpWarmStatus::NotApplicable);
        }
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                return Ok(UdpWarmStatus::NotApplicable);
            }
        };
        let already_ready = pool.has_usable_session(POOL_KEY);
        Self::ensure_janitor(&runtime.node, &pool, Some(Arc::clone(&runtime)));
        let _session = pool.offer(POOL_KEY, dial).await?;
        if !pool.has_usable_session(POOL_KEY) {
            anyhow::bail!("AnyTLS warm dial completed without a usable session");
        }
        Ok(if already_ready {
            UdpWarmStatus::AlreadyReady
        } else {
            UdpWarmStatus::Ready
        })
    }

    /// Open a stream on an explicitly captured generation-owned pool. One
    /// retry is allowed only when the selected session fails mid-open.
    async fn open_pooled_stream_for_pool(
        &self,
        node: &Node,
        pool: Arc<AnyTlsPool>,
        addr: &str,
        target_addr: &[u8],
        connect_timeout: Duration,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
    ) -> anyhow::Result<AnyTlsStream> {
        // A throwaway pool (no generation runtime) gets no janitor: the
        // janitor task pins its pool alive.
        if runtime.is_some() {
            Self::ensure_janitor(node, &pool, runtime.clone());
        }
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
                let runtime = runtime.clone();
                async move {
                    let tls_connector = runtime
                        .as_ref()
                        .map(|runtime| runtime.anytls_tls_connector())
                        .transpose()?;
                    dial_session(&node, &addr, connect_timeout, tls_connector).await
                }
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

    /// Keeps cancellation observable without opening a physical session.
    #[cfg(test)]
    async fn dial_udp_transport_speculative_with<F, Fut>(
        &self,
        node: &Node,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        dial: F,
    ) -> anyhow::Result<PreparedUdpTransport>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send,
    {
        Self::dial_udp_transport_speculative_for_pool_with(
            node,
            pool,
            target,
            target_domain,
            connect_timeout,
            None,
            dial,
        )
        .await
    }

    /// Prepare an AnyTLS UoT transport on an explicitly captured pool without
    /// publishing a detached session or starting the janitor. The injected
    /// dial seam keeps cancellation observable in tests.
    async fn dial_udp_transport_speculative_for_pool_with<F, Fut>(
        node: &Node,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
        dial: F,
    ) -> anyhow::Result<PreparedUdpTransport>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send,
    {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        let magic = addr::encode_address("0.0.0.0:0".parse().unwrap(), Some(UOT_MAGIC));
        let (session, permit, detached) = match pool.checkout_speculative(POOL_KEY).await? {
            SpeculativeCheckout::Shared { session, permit } => (session, permit, None),
            SpeculativeCheckout::Detached(mut reservation) => {
                // This future is owned by the speculative caller, not by the
                // pool. Aborting the caller drops both it and the reservation;
                // generation shutdown wins the same race explicitly.
                let session = tokio::select! {
                    result = dial() => result?,
                    _ = reservation.cancelled() => {
                        anyhow::bail!("AnyTLS speculative dial cancelled by pool shutdown")
                    }
                };
                reservation.attach(&session)?;
                let permit = session.try_reserve().ok_or_else(|| {
                    anyhow::anyhow!("fresh AnyTLS session has no stream capacity")
                })?;
                (session, permit, Some(reservation))
            }
        };

        let (sid, rx, mut guard) = session.open_uot_stream(magic, permit).await?;
        let mut request = vec![1u8];
        request.extend(addr::encode_address(target, target_domain));
        guard.frame_started = true;
        let request_written = tokio::time::timeout(
            connect_timeout,
            session.write_uot_setup_frame(sid, &request),
        )
        .await;
        match request_written {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(elapsed) => return Err(elapsed.into()),
        }
        guard.frame_started = false;
        let permit = guard.commit();
        let transport: Arc<dyn PacketTransport> = Arc::new(AnyTlsUotTransport {
            session,
            sid,
            rx: tokio::sync::Mutex::new(rx),
            mode: tokio::sync::Mutex::new(None),
            target,
            target_domain: target_domain.map(str::to_string),
            _permit: permit,
        });

        if let Some(reservation) = detached {
            let commit_node = node.clone();
            let commit_pool = Arc::clone(&pool);
            let commit_runtime = runtime.clone();
            return Ok(PreparedUdpTransport::new(transport, move || {
                reservation.commit()?;
                if commit_runtime.is_some() {
                    Self::ensure_janitor(&commit_node, &commit_pool, commit_runtime);
                }
                Ok(())
            }));
        }

        let commit_node = node.clone();
        Ok(PreparedUdpTransport::new(transport, move || {
            if runtime.is_some() {
                Self::ensure_janitor(&commit_node, &pool, runtime);
            }
            Ok(())
        }))
    }

    async fn dial_udp_transport_for_pool(
        &self,
        node: Arc<Node>,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if !crate::descriptor::network_allows_udp(&node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        let addr = format!("{}:{}", node.host(), node.port);
        let magic = addr::encode_address("0.0.0.0:0".parse().unwrap(), Some(UOT_MAGIC));
        if runtime.is_some() {
            Self::ensure_janitor(node.as_ref(), &pool, runtime.clone());
        }
        let dial_node = Arc::clone(&node);
        let dial_addr = addr.clone();
        let (session, sid, rx, mut guard) = pool
            .open_with(
                POOL_KEY,
                move || {
                    let node = Arc::clone(&dial_node);
                    let addr = dial_addr.clone();
                    let runtime = runtime.clone();
                    async move {
                        let tls_connector = runtime
                            .as_ref()
                            .map(|runtime| runtime.anytls_tls_connector())
                            .transpose()?;
                        dial_session(node.as_ref(), &addr, connect_timeout, tls_connector).await
                    }
                },
                move |session, permit| {
                    let magic = magic.clone();
                    async move {
                        match session.open_uot_stream(magic, permit).await {
                            Ok((sid, rx, guard)) => Ok((session, sid, rx, guard)),
                            Err(error) => Err(if session.is_closed() {
                                crate::session::OpenError::Session(error)
                            } else {
                                crate::session::OpenError::Refused(error)
                            }),
                        }
                    }
                },
            )
            .await?;

        let mut request = vec![1u8];
        request.extend(addr::encode_address(target, target_domain));
        guard.frame_started = true;
        let request_written = tokio::time::timeout(
            connect_timeout,
            session.write_uot_setup_frame(sid, &request),
        )
        .await;
        match request_written {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
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
    /// Outbound frame slot: the payload is owned by the stream until it
    /// is enqueued — cancelling the caller's write future can neither
    /// lose it nor enqueue it twice. `poll_write` only returns `Ok(n)`
    /// after exactly these `n` bytes were queued (never a number derived
    /// from a different call's buffer).
    out_slot: Option<(bytes::Bytes, usize)>,
    /// Waiter for a writer-queue data permit while `out_slot` is occupied.
    permit_fut: Option<
        std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<tokio::sync::OwnedSemaphorePermit>>
                    + Send,
            >,
        >,
    >,
    fin_sent: bool,
    /// Stream-slot capacity, held until either endpoint closes the stream.
    /// A server FIN releases it immediately even if callers retain the EOF
    /// stream object.
    _permit: Option<crate::session::SessionPermit<AnyTlsSession>>,
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
            out_slot: None,
            permit_fut: None,
            fin_sent: false,
            _permit: Some(permit),
        }
    }

    fn release_permit(&mut self) {
        self._permit.take();
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
            // Drain the session overflow FIRST: frames parked there must
            // enter the queue before we ask for more, or an emptied queue
            // costs a full task sleep/wake cycle per batch (measured:
            // single-stream throughput collapses to ~4 Mbps).
            this.session.flush_overflow(this.sid);
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
            // The reader's progress frees queue space: drain whatever the
            // session overflow parked for this stream (order-preserving).
            if matches!(next, std::task::Poll::Ready(Some(_))) {
                this.session.flush_overflow(this.sid);
            }
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
                    this.release_permit();
                    return std::task::Poll::Ready(Err(err));
                }
                std::task::Poll::Ready(Some(StreamEvent::Fin)) => {
                    // Consume the EOF event exactly once. If this poll
                    // already delivered data, the caller must see that
                    // data as a successful read; the EOF is owed to the
                    // next poll via `read_eof` (returning it now would
                    // either discard the data or lose the Fin).
                    this.read_eof = true;
                    this.release_permit();
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
                        this.release_permit();
                        return std::task::Poll::Ready(Err(err));
                    }
                    this.read_eof = true;
                    this.release_permit();
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
        let this = self.as_mut().get_mut();
        // Occupy the slot exactly once: a retry after Pending reuses the
        // stored payload, never re-queues it.
        if this.out_slot.is_none() {
            this.out_slot = Some((bytes::Bytes::copy_from_slice(&buf[..chunk]), chunk));
        }
        // Fast path: a writer-queue permit is available right now.
        if let Some((payload, n)) = this.out_slot.take() {
            match this.session.try_enqueue_data(this.sid, payload) {
                Ok(()) => return std::task::Poll::Ready(Ok(n)),
                Err(payload) => this.out_slot = Some((payload, n)),
            }
        }
        // Wait for a permit; the payload stays in the slot meanwhile.
        if this.permit_fut.is_none() {
            let session = Arc::clone(&this.session);
            this.permit_fut = Some(Box::pin(async move { session.acquire_data_permit().await }));
        }
        let fut = this.permit_fut.as_mut().expect("permit wait just queued");
        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(permit)) => {
                this.permit_fut = None;
                let (payload, n) = this.out_slot.take().expect("slot held while waiting");
                let r = this
                    .session
                    .enqueue_data_with_permit(this.sid, payload, permit);
                std::task::Poll::Ready(r.map(|()| n))
            }
            std::task::Poll::Ready(Err(e)) => {
                this.permit_fut = None;
                std::task::Poll::Ready(Err(e))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Some(fut) = this.permit_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(permit)) => {
                    this.permit_fut = None;
                    if let Some((payload, _)) = this.out_slot.take() {
                        this.session
                            .enqueue_data_with_permit(this.sid, payload, permit)?;
                    }
                }
                std::task::Poll::Ready(Err(e)) => {
                    this.permit_fut = None;
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
            self.session
                .enqueue_control(CMD_FIN, self.sid, bytes::Bytes::new())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        std::task::Poll::Ready(Ok(()))
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

#[async_trait]
impl WarmableOutbound for AnyTlsHandler {
    async fn warm_udp(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpWarmStatus> {
        let node = Arc::clone(&runtime.node);
        let addr = format!("{}:{}", node.host(), node.port);
        let dial_runtime = Arc::clone(&runtime);
        Self::warm_pool_with(runtime, connect_timeout, move || async move {
            let tls_connector = dial_runtime.anytls_tls_connector()?;
            dial_session(&node, &addr, connect_timeout, Some(tls_connector)).await
        })
        .await
    }
}

#[async_trait]
impl TcpOutbound for AnyTlsHandler {
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
            .open_pooled_stream_for_pool(
                node,
                Arc::new(crate::session::SessionPool::new(session_pool_config())),
                &addr,
                &target_addr,
                connect_timeout,
                None,
            )
            .await?;

        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                anyhow::bail!("AnyTLS node runtime does not own an AnyTLS pool")
            }
        };
        let node = Arc::clone(&runtime.node);
        let addr = format!("{}:{}", node.host(), node.port);
        let target_addr = addr::encode_address(target, target_domain);
        let stream = self
            .open_pooled_stream_for_pool(
                node.as_ref(),
                pool,
                &addr,
                &target_addr,
                connect_timeout,
                Some(runtime),
            )
            .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }
}

#[async_trait]
impl PacketOutbound for AnyTlsHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport_for_pool(
            Arc::new(node.clone()),
            Arc::new(crate::session::SessionPool::new(session_pool_config())),
            target,
            target_domain,
            connect_timeout,
            None,
        )
        .await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                anyhow::bail!("AnyTLS node runtime does not own an AnyTLS pool")
            }
        };
        let node = Arc::clone(&runtime.node);
        self.dial_udp_transport_for_pool(
            node,
            pool,
            target,
            target_domain,
            connect_timeout,
            Some(runtime),
        )
        .await
    }

    async fn dial_udp_transport_speculative(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let dial_node = node.clone();
        let dial_addr = format!("{}:{}", node.host(), node.port);
        Self::dial_udp_transport_speculative_for_pool_with(
            node,
            Arc::new(crate::session::SessionPool::new(session_pool_config())),
            target,
            target_domain,
            connect_timeout,
            None,
            move || async move {
                dial_session(&dial_node, &dial_addr, connect_timeout, None).await
            },
        )
        .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                anyhow::bail!("AnyTLS node runtime does not own an AnyTLS pool")
            }
        };
        let node = Arc::clone(&runtime.node);
        let dial_node = Arc::clone(&node);
        let dial_runtime = Arc::clone(&runtime);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        Self::dial_udp_transport_speculative_for_pool_with(
            node.as_ref(),
            pool,
            target,
            target_domain,
            connect_timeout,
            Some(runtime),
            move || async move {
                let tls_connector = dial_runtime.anytls_tls_connector()?;
                dial_session(
                    dial_node.as_ref(),
                    &dial_addr,
                    connect_timeout,
                    Some(tls_connector),
                )
                .await
            },
        )
        .await
    }
}

#[async_trait]
impl ProbeableOutbound for AnyTlsHandler {}

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
    /// vs v1 `atyp+addr+port+len+payload` — see `UotMode`).
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
/// never queue unboundedly. Sized for bursts: at ~1.2KB per datagram,
/// 4096 entries absorbs a ~40ms burst at 100k pps while the reply handler
/// drains.
const UOT_DRAIN_QUEUE_CAP: usize = 4096;

impl Drop for AnyTlsUotTransport {
    fn drop(&mut self) {
        self.session.end_uot_stream(self.sid);
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
        let mut frame = bytes::BytesMut::with_capacity(2 + data.len());
        use bytes::BufMut as _;
        frame.put_u16(data.len() as u16);
        frame.extend_from_slice(data);
        self.session
            .write_uot_datagram(self.sid, frame.freeze())
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let event = self.rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "UoT stream closed")
        })?;
        match event {
            StreamEvent::Data(data) => {
                let payload = self.strip_uot_header(&mut *self.mode.lock().await, &data)?;
                if payload.len() > buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "uot datagram exceeds buffer",
                    ));
                }
                buf[..payload.len()].copy_from_slice(payload);
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
    fn overflow_state_enforces_frame_and_byte_caps_independently() {
        let mut frames = OverflowState::default();
        for _ in 0..SESSION_OVERFLOW_CAP {
            frames.push_back(1, StreamEvent::Data(vec![1]));
        }
        assert_eq!(frames.usage().bytes, SESSION_OVERFLOW_CAP);
        assert_eq!(
            frames.limit_for(2, &StreamEvent::Data(vec![1])),
            Some(OverflowLimit::SessionFrames)
        );

        let mut stream_bytes = OverflowState::default();
        stream_bytes.push_back(1, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
        assert_eq!(
            stream_bytes.limit_for(1, &StreamEvent::Data(vec![1])),
            Some(OverflowLimit::StreamBytes)
        );

        let mut session_bytes = OverflowState::default();
        for sid in 1..=4 {
            session_bytes.push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
        }
        assert_eq!(session_bytes.usage().bytes, SESSION_OVERFLOW_BYTES_CAP);
        assert_eq!(
            session_bytes.limit_for(5, &StreamEvent::Data(vec![1])),
            Some(OverflowLimit::SessionBytes)
        );
        assert_eq!(session_bytes.limit_for(5, &StreamEvent::Fin), None);

        let mut competing_limits = OverflowState::default();
        competing_limits.push_back(9, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
        for _ in 1..SESSION_OVERFLOW_CAP {
            competing_limits.push_back(10, StreamEvent::Data(vec![2]));
        }
        assert_eq!(
            competing_limits.limit_for(9, &StreamEvent::Data(vec![1])),
            Some(OverflowLimit::SessionFrames)
        );

        let mut competing_session_limits = OverflowState::default();
        for sid in 1..=4 {
            competing_session_limits
                .push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
        }
        for _ in 4..SESSION_OVERFLOW_CAP {
            competing_session_limits.push_back(10, StreamEvent::Data(vec![3]));
        }
        assert_eq!(
            competing_session_limits.limit_for(11, &StreamEvent::Data(vec![1])),
            Some(OverflowLimit::SessionBytes)
        );

        // Terminal events bypass the frame/byte quota entirely.
        let mut errors = OverflowState::default();
        errors.push_back(1, StreamEvent::Error(Arc::from("remote error")));
        errors.push_back(1, StreamEvent::Fin);
        assert_eq!(errors.usage(), OverflowUsage::default());
        assert_eq!(errors.stream_usage(1).frames, 0);
    }

    #[test]
    fn overflow_terminal_events_cap_per_stream() {
        let mut overflow = OverflowState::default();
        for _ in 0..SESSION_OVERFLOW_CAP {
            overflow.push_back(1, StreamEvent::Data(vec![1]));
        }
        // A full frame quota does not break stream termination…
        assert!(matches!(
            overflow.admit(1, StreamEvent::Fin),
            OverflowAction::Parked
        ));
        assert!(matches!(
            overflow.admit(1, StreamEvent::Error(Arc::from("x"))),
            OverflowAction::Parked
        ));
        // …but parked terminal events are bounded per stream.
        assert!(matches!(
            overflow.admit(1, StreamEvent::Fin),
            OverflowAction::Dropped
        ));
        assert!(matches!(
            overflow.admit(2, StreamEvent::Fin),
            OverflowAction::Parked
        ));
        assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_CAP);
        assert_eq!(overflow.stream_usage(1).frames, SESSION_OVERFLOW_CAP);
    }

    #[test]
    fn overflow_state_accounting_tracks_every_queue_operation() {
        let mut overflow = OverflowState::default();
        overflow.push_back(1, StreamEvent::Data(vec![1, 2, 3]));
        overflow.push_back(1, StreamEvent::Fin);
        overflow.push_back(2, StreamEvent::Data(vec![0; 5]));
        assert_eq!(
            overflow.usage(),
            OverflowUsage {
                frames: 2,
                bytes: 8
            }
        );

        let event = overflow.pop_front(1).unwrap();
        assert_eq!(
            overflow.usage(),
            OverflowUsage {
                frames: 1,
                bytes: 5
            }
        );
        overflow.push_front(1, event);
        assert_eq!(
            overflow.usage(),
            OverflowUsage {
                frames: 2,
                bytes: 8
            }
        );

        // Stream 1 still holds the re-queued data frame plus the Fin;
        // the Fin carries no frame/byte weight.
        assert_eq!(
            overflow.remove_stream(1),
            OverflowUsage {
                frames: 1,
                bytes: 3
            }
        );
        assert_eq!(
            overflow.usage(),
            OverflowUsage {
                frames: 1,
                bytes: 5
            }
        );
        assert_eq!(
            overflow.clear(),
            OverflowUsage {
                frames: 1,
                bytes: 5
            }
        );
        assert_eq!(overflow.usage(), OverflowUsage::default());
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_full_requeue_preserves_stall_age() {
        let mut overflow = OverflowState::default();
        overflow.push_back(1, StreamEvent::Data(vec![1]));
        tokio::time::advance(Duration::from_secs(2)).await;

        let progress = overflow.last_progress_at(1);
        let event = overflow.pop_front(1).unwrap();
        overflow.push_front(1, event);
        overflow.restore_last_progress_at(1, progress);

        assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_flush_progress_resets_stall_age() {
        let mut overflow = OverflowState::default();
        overflow.push_back(1, StreamEvent::Data(vec![1]));
        tokio::time::advance(Duration::from_secs(2)).await;
        overflow.note_progress(1);
        tokio::time::advance(Duration::from_secs(2)).await;

        assert_eq!(overflow.stalled_for(1), Duration::from_secs(2));
    }

    /// Soft caps never kill, no matter how stale the stream: only the
    /// watchdog reaps on stall age, only the hard caps reap in admit.
    #[tokio::test(start_paused = true)]
    async fn overflow_admit_below_hard_caps_never_kills() {
        let mut overflow = OverflowState::default();
        overflow.push_back(1, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));
        tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
        assert!(matches!(
            overflow.admit(1, StreamEvent::Data(vec![1])),
            OverflowAction::Parked
        ));
        assert_eq!(
            overflow.stream_usage(1).bytes,
            STREAM_OVERFLOW_BYTES_CAP + 1
        );

        let mut session_soft = OverflowState::default();
        for _ in 0..SESSION_OVERFLOW_CAP {
            session_soft.push_back(1, StreamEvent::Data(vec![1]));
        }
        tokio::time::advance(OVERFLOW_STALL_GRACE * 4).await;
        assert!(matches!(
            session_soft.admit(2, StreamEvent::Data(vec![2])),
            OverflowAction::Parked
        ));
        assert_eq!(session_soft.usage().frames, SESSION_OVERFLOW_CAP + 1);
    }

    /// Hard cap with a past-grace stream: the admit reaps the
    /// most-stalled stream immediately and hands the event back; the
    /// retry parks on the freed space.
    #[tokio::test(start_paused = true)]
    async fn overflow_admit_hard_cap_reaps_past_grace_stream() {
        let mut overflow = OverflowState::default();
        for _ in 0..SESSION_OVERFLOW_HARD_CAP {
            overflow.push_back(1, StreamEvent::Data(vec![1; 8]));
        }
        tokio::time::advance(OVERFLOW_STALL_GRACE).await;

        let OverflowAction::Kill(victim, event) = overflow.admit(2, StreamEvent::Data(vec![9]))
        else {
            panic!("past-grace stream at the hard cap must be reaped")
        };
        assert_eq!(victim.sid, 1);
        assert_eq!(victim.limit, OverflowLimit::SessionFrames);
        assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
        assert!(!overflow.has(1));

        assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
        assert_eq!(overflow.usage().frames, 1);
    }

    /// Hard cap with every stream inside the grace: the admit asks the
    /// caller to wait a bounded round instead of killing or parking past
    /// the cap; once a stalled stream crosses the grace, the same admit
    /// reaps it.
    #[tokio::test(start_paused = true)]
    async fn overflow_admit_hard_cap_waits_inside_the_grace() {
        let mut overflow = OverflowState::default();
        for _ in 0..SESSION_OVERFLOW_HARD_CAP {
            overflow.push_back(1, StreamEvent::Data(vec![1; 8]));
        }
        let wait = match overflow.admit(2, StreamEvent::Data(vec![9])) {
            OverflowAction::Wait(_, wait) => wait,
            _ => panic!("hard cap inside the grace must wait, not kill"),
        };
        assert!(wait <= OVERFLOW_EMERGENCY_WAIT);
        assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
        assert!(overflow.has(1));

        tokio::time::advance(OVERFLOW_STALL_GRACE).await;
        let OverflowAction::Kill(victim, event) = overflow.admit(2, StreamEvent::Data(vec![9]))
        else {
            panic!("hard cap past the grace must reap")
        };
        assert_eq!(victim.sid, 1);
        assert!(victim.stalled_for >= OVERFLOW_STALL_GRACE);
        assert!(matches!(overflow.admit(2, event), OverflowAction::Parked));
    }

    /// The byte hard cap follows the same wait-then-reap path as the
    /// frame cap.
    #[tokio::test(start_paused = true)]
    async fn overflow_admit_hard_byte_cap_waits_inside_the_grace() {
        let mut overflow = OverflowState::default();
        overflow.push_back(
            1,
            StreamEvent::Data(vec![0; SESSION_OVERFLOW_HARD_BYTES_CAP]),
        );
        assert!(matches!(
            overflow.admit(2, StreamEvent::Data(vec![1])),
            OverflowAction::Wait(..)
        ));
        tokio::time::advance(OVERFLOW_STALL_GRACE).await;
        assert!(matches!(
            overflow.admit(2, StreamEvent::Data(vec![1])),
            OverflowAction::Kill(..)
        ));
        assert!(!overflow.has(1));
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

    #[tokio::test]
    async fn test_writer_batch_encoding_matches_sequential_frames() {
        let q = WriterQueue::new();
        let sem = Arc::new(tokio::sync::Semaphore::new(2));
        let p1 = sem.clone().acquire_owned().await.unwrap();
        let p2 = sem.clone().acquire_owned().await.unwrap();
        q.push_batch([
            FrameCommand::Control {
                cmd: CMD_SYN,
                sid: 1,
                payload: bytes::Bytes::from_static(b"addr"),
            },
            FrameCommand::Data {
                sid: 1,
                payload: bytes::Bytes::from_static(b"hello"),
                _permit: p1,
            },
            FrameCommand::Data {
                sid: 2,
                payload: bytes::Bytes::from_static(b"world"),
                _permit: p2,
            },
            FrameCommand::Control {
                cmd: CMD_FIN,
                sid: 2,
                payload: bytes::Bytes::new(),
            },
        ]);
        let mut batch = vec![q.pop().await];
        q.drain_available(
            &mut batch,
            WRITER_BATCH_MAX_FRAMES - 1,
            WRITER_BATCH_MAX_BYTES,
        );
        assert_eq!(batch.len(), 4);
        let mut buf = bytes::BytesMut::new();
        for cmd in &batch {
            cmd.encode_into(&mut buf);
        }

        let mut reference: Vec<u8> = Vec::new();
        write_frame(&mut reference, CMD_SYN, 1, b"addr")
            .await
            .unwrap();
        write_frame(&mut reference, CMD_PSH, 1, b"hello")
            .await
            .unwrap();
        write_frame(&mut reference, CMD_PSH, 2, b"world")
            .await
            .unwrap();
        write_frame(&mut reference, CMD_FIN, 2, b"").await.unwrap();
        assert_eq!(&buf[..], &reference[..]);
    }

    #[tokio::test]
    async fn test_writer_batch_caps() {
        let q = WriterQueue::new();
        let payload = bytes::Bytes::from(vec![7u8; 100]);
        for sid in 0..5u32 {
            q.push_batch([FrameCommand::Control {
                cmd: CMD_WASTE,
                sid,
                payload: payload.clone(),
            }]);
        }
        // Frame cap: only 2 of 5.
        let mut batch = Vec::new();
        q.drain_available(&mut batch, 2, usize::MAX);
        assert_eq!(batch.len(), 2);

        // Byte cap: wire_len is 107 per frame, cap 300 fits exactly 2 more
        // (always taking at least one for forward progress).
        let mut batch = Vec::new();
        q.drain_available(&mut batch, usize::MAX, 300);
        assert_eq!(batch.len(), 2);

        let mut batch = Vec::new();
        q.drain_available(&mut batch, usize::MAX, usize::MAX);
        assert_eq!(batch.len(), 1);
        assert!(q.queue.lock().unwrap().is_empty());
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

    #[tokio::test]
    async fn runtime_udp_pool_hit_does_not_build_connector() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "runtime-udp-hit".into(),
            protocol: NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("expected AnyTLS runtime")
            }
        };
        let (session, mut server) = establish_test_session("runtime-udp-hit").await;
        expect_handshake(&mut server).await;
        pool.insert(POOL_KEY, &session);
        assert!(!runtime.tls_connector_loaded());

        let handler = AnyTlsHandler::new();
        let transport = handler
            .dial_udp_transport_runtime(
                Arc::clone(&runtime),
                "127.0.0.1:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        assert!(!runtime.tls_connector_loaded());
        drop(transport);
        generation.shutdown().await;
    }

    #[tokio::test]
    async fn warm_resources_flip_with_pool_session() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-resources".into(),
            protocol: NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let generation =
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = generation.get(&node.id).unwrap();
        assert!(!runtime.has_warm_resources());

        let crate::runtime::ProtocolRuntime::AnyTls(anytls) = &runtime.runtime else {
            panic!("expected AnyTLS runtime")
        };
        let (session, mut server) = establish_test_session("warm-resources").await;
        expect_handshake(&mut server).await;
        anytls.pool.insert(POOL_KEY, &session);
        assert!(runtime.has_warm_resources());

        session.close();
        assert!(
            !runtime.has_warm_resources(),
            "a closed session no longer counts as warm"
        );
    }

    #[tokio::test]
    async fn runtime_dial_stays_on_captured_pool_after_registry_swap() {
        let old_node = Node {
            id: uuid::Uuid::new_v4(),
            name: "generation-node".into(),
            protocol: NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let old_generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&old_node))
                .unwrap(),
        );
        let old_runtime = old_generation.get(&old_node.id).unwrap();
        let old_pool = match &old_runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("expected AnyTLS runtime")
            }
        };
        let (session, mut server) = establish_test_session("captured-generation").await;
        expect_handshake(&mut server).await;
        let _addresses = spawn_echo_server(server);
        old_pool.insert(POOL_KEY, &session);

        let mut replacement_node = old_node.clone();
        replacement_node.address = "127.0.0.1:10".into();
        let replacement =
            crate::runtime::OutboundRuntimeRegistry::build(&[replacement_node]).unwrap();
        let replacement_pool = match &replacement.get(&old_node.id).unwrap().runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("expected AnyTLS runtime")
            }
        };
        let handler = AnyTlsHandler::new();

        let mut stream = handler
            .dial_runtime(
                old_runtime,
                "8.8.8.8:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
            )
            .await
            .unwrap()
            .stream;
        stream.write_all(b"old-generation").await.unwrap();
        let mut echoed = vec![0; b"old-generation".len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"old-generation");
        assert!(old_pool.has_usable_session(POOL_KEY));
        assert!(!replacement_pool.has_usable_session(POOL_KEY));
        session.close();
    }

    #[tokio::test(start_paused = true)]
    async fn runtime_retirement_drains_live_session_without_cutting_it() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "retiring-anytls".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        let generation =
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let pool = match &generation.get(&node.id).unwrap().runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("expected AnyTLS runtime")
            }
        };
        let (session, mut server) = establish_test_session("retiring-anytls").await;
        expect_handshake(&mut server).await;
        pool.insert(POOL_KEY, &session);
        let permit = session.try_reserve().expect("live stream permit");

        generation.begin_retirement();
        assert!(
            !session.is_closed(),
            "publication must not cut live streams"
        );
        generation.drain_session_pools();
        assert_eq!(session.state(), crate::session::SessionState::Draining);
        assert!(
            !session.is_closed(),
            "pool drain must preserve live streams"
        );

        drop(permit);
        tokio::time::advance(Duration::from_millis(20)).await;
        tokio::task::yield_now().await;
        assert!(session.is_closed(), "last stream release must finish drain");
    }

    #[tokio::test]
    async fn uot_setup_waits_for_writer_capacity_and_cancellation_does_not_enqueue() {
        let (session, mut server) = establish_test_session("uot-setup-capacity").await;
        expect_handshake(&mut server).await;
        let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
        let held = Arc::clone(&session.writer_q.data_permits)
            .acquire_many_owned(capacity)
            .await
            .unwrap();

        let setup = session.write_uot_setup_frame(7, b"setup");
        tokio::pin!(setup);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut setup)
                .await
                .is_err(),
            "mandatory UoT setup must wait rather than report a dropped frame"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), setup)
            .await
            .unwrap()
            .unwrap();
        let (cmd, sid, payload) =
            tokio::time::timeout(Duration::from_secs(1), read_frame(&mut server))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (cmd, sid, payload.as_slice()),
            (CMD_PSH, 7, b"setup".as_slice())
        );

        let held = Arc::clone(&session.writer_q.data_permits)
            .acquire_many_owned(capacity)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                session.write_uot_setup_frame(7, b"cancelled"),
            )
            .await
            .is_err()
        );
        drop(held);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), read_frame(&mut server))
                .await
                .is_err(),
            "cancelling before capacity is acquired must not enqueue setup"
        );
        session.close();
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

    /// poll_write cancel safety: a cancelled write neither loses the
    /// payload nor enqueues it twice; a retry reuses the stored slot.
    #[tokio::test]
    async fn test_poll_write_cancel_safety() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (session, mut server) = establish_test_session("127.0.0.1:443").await;
        expect_handshake(&mut server).await;
        let mut addr_rx = spawn_echo_server(server);
        let target = vec![0x01, 127, 0, 0, 1, 0x01, 0xbb];
        let permit = session.try_reserve().unwrap();
        let mut stream = session.open_stream_direct(target, permit).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .unwrap();

        // Exhaust the writer-queue data permits so the first write waits.
        let sem = Arc::clone(&session.writer_q.data_permits);
        let mut hog = Vec::new();
        while let Ok(p) = Arc::clone(&sem).try_acquire_owned() {
            hog.push(p);
        }
        assert!(!hog.is_empty());

        // The first write is cancelled mid-poll (timeout): no data out,
        // no leak.
        let one = b"payload-one".to_vec();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.write(&one))
                .await
                .is_err()
        );

        // Free one permit: the stored slot goes out exactly once.
        drop(hog.pop());
        tokio::time::timeout(Duration::from_secs(2), stream.write(&one))
            .await
            .unwrap()
            .unwrap();

        // A second buffer after the slot freed writes normally.
        let two = b"payload-two".to_vec();
        drop(hog);
        tokio::time::timeout(Duration::from_secs(2), stream.write(&two))
            .await
            .unwrap()
            .unwrap();

        // The echo contains each payload exactly once, in order.
        let mut echoed = vec![0u8; one.len() + two.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        let mut want = one.clone();
        want.extend_from_slice(&two);
        assert_eq!(echoed, want);
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
    async fn echo<S>(stream: &mut S, payload: &[u8]) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        stream.write_all(payload).await?;
        let mut buf = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
            .await
            .expect("echo timed out")?;
        assert_eq!(buf, payload);
        Ok(())
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

    #[tokio::test]
    async fn overflow_accounting_clears_on_lifecycle_exits() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;

        let (end_tx, _end_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(31, StreamSink::Tcp(end_tx));
        session
            .overflow
            .lock()
            .push_back(31, StreamEvent::Data(vec![1; 17]));
        session.end_stream(31, false).await;
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

        let (drop_tx, _drop_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(32, StreamSink::Tcp(drop_tx));
        let registration = StreamRegistration {
            session: Arc::clone(&session),
            sid: 32,
            frame_started: false,
            committed: false,
            permit: Some(session.try_reserve().unwrap()),
        };
        session
            .overflow
            .lock()
            .push_back(32, StreamEvent::Data(vec![2; 19]));
        drop(registration);
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

        let (closed_tx, closed_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(33, StreamSink::Tcp(closed_tx));
        session
            .overflow
            .lock()
            .push_back(33, StreamEvent::Data(vec![3; 23]));
        drop(closed_rx);
        session.dispatch_data(33, vec![4]).await;
        assert!(!session.streams.lock().unwrap().contains_key(&33));
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());

        let (close_tx, _close_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(34, StreamSink::Tcp(close_tx));
        session
            .overflow
            .lock()
            .push_back(34, StreamEvent::Data(vec![5; 29]));
        session.close();
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    }

    /// Below the hard caps parking never kills, however stale the stream:
    /// only the stall watchdog reaps it, strictly after a full grace
    /// without flush progress.
    #[tokio::test(start_paused = true)]
    async fn stream_byte_cap_reaps_via_watchdog_only_after_stall_grace() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 41;
        let (tx, _rx) = mpsc::channel(STREAM_QUEUE_CAP);
        for _ in 0..STREAM_QUEUE_CAP {
            tx.try_send(StreamEvent::Data(vec![0])).unwrap();
        }
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        session
            .overflow
            .lock()
            .push_back(sid, StreamEvent::Data(vec![0; STREAM_OVERFLOW_BYTES_CAP]));

        // At the cap but inside the grace window the frame still parks,
        // and the watchdog spawned by the park leaves the stream alone.
        session.park_overflow(sid, StreamEvent::Data(vec![1])).await;
        tokio::time::advance(OVERFLOW_STALL_GRACE - OVERFLOW_WATCHDOG_TICK).await;
        tokio::task::yield_now().await;
        assert!(session.streams.lock().unwrap().contains_key(&sid));
        assert!(!session.killed_streams.lock().unwrap().contains(&sid));
        assert_eq!(
            session.overflow.lock().stream_usage(sid).bytes,
            STREAM_OVERFLOW_BYTES_CAP + 1
        );

        // A reader that never consumes is reaped by the watchdog once the
        // grace expires.
        tokio::time::advance(OVERFLOW_WATCHDOG_TICK * 2).await;
        tokio::task::yield_now().await;
        assert!(!session.streams.lock().unwrap().contains_key(&sid));
        assert!(session.killed_streams.lock().unwrap().contains(&sid));
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
        assert!(!session.is_closed());
        session.close();
    }

    /// Fast-peer burst regression: a peer can park past the session byte
    /// soft cap in the milliseconds before the reader is first scheduled —
    /// parking never waits and never kills inside the grace, the late
    /// reader drains, and every byte arrives in order.
    #[tokio::test]
    async fn overflow_burst_within_grace_survives_and_delivers() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 42;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);

        const FRAME: usize = 32 * 1024;
        // Queue + stream soft cap + past the session byte soft cap (but
        // below the emergency hard cap).
        let frames = STREAM_QUEUE_CAP + SESSION_OVERFLOW_BYTES_CAP / FRAME + 8;
        let dispatcher = tokio::spawn({
            let session = Arc::clone(&session);
            async move {
                for i in 0..frames {
                    session
                        .dispatch_data(sid, vec![(i % 251) as u8; FRAME])
                        .await;
                }
            }
        });
        // The reader starts late: the burst has parked past the session
        // soft cap; parking neither waits nor kills inside the grace.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(session.streams.lock().unwrap().contains_key(&sid));
        assert!(!session.killed_streams.lock().unwrap().contains(&sid));

        let mut got = vec![0u8; frames * FRAME];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
            .await
            .expect("burst drains")
            .unwrap();
        dispatcher.await.unwrap();
        for (i, frame) in got.as_chunks::<FRAME>().0.iter().enumerate() {
            assert!(
                frame.iter().all(|&b| b == (i % 251) as u8),
                "frame {i} corrupted"
            );
        }
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
        assert!(session.streams.lock().unwrap().contains_key(&sid));
        session.close();
    }

    /// At the hard frame cap with stalled streams past the grace, parking
    /// reaps on the spot (never waits): the most-stalled parked stream —
    /// 51, oldest progress (ties to the lowest sid) — dies and the new
    /// frame parks on the freed space, then flushes into its empty
    /// channel.
    #[tokio::test(start_paused = true)]
    async fn session_hard_cap_kills_stream_that_outwaits_the_stall_grace() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (other_tx, _other_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (waiting_tx, _waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        {
            let mut streams = session.streams.lock().unwrap();
            streams.insert(51, StreamSink::Tcp(slow_tx));
            streams.insert(52, StreamSink::Tcp(other_tx));
            streams.insert(53, StreamSink::Tcp(waiting_tx));
        }
        {
            let mut overflow = session.overflow.lock();
            for _ in 0..400 {
                overflow.push_back(51, StreamEvent::Data(vec![1; 8]));
            }
            for _ in 0..368 {
                overflow.push_back(52, StreamEvent::Data(vec![2; 8]));
            }
            assert_eq!(overflow.usage().frames, SESSION_OVERFLOW_HARD_CAP);
        }
        tokio::time::advance(OVERFLOW_STALL_GRACE).await;

        session
            .park_overflow(53, StreamEvent::Data(vec![9, 8, 7]))
            .await;

        assert!(session.killed_streams.lock().unwrap().contains(&51));
        assert!(!session.streams.lock().unwrap().contains_key(&51));
        assert!(session.streams.lock().unwrap().contains_key(&52));
        assert!(session.streams.lock().unwrap().contains_key(&53));
        assert!(!session.overflow.lock().has(51));
        assert!(!session.overflow.lock().has(53));
        assert_eq!(
            session.overflow.lock().usage(),
            OverflowUsage {
                frames: 368,
                bytes: 368 * 8,
            }
        );

        // Terminal events bypass the frame quota; the post-park flush
        // moves a free channel's worth of events into the stream queue
        // (368 parked + 1 Fin − 64 delivered).
        session.park_overflow(52, StreamEvent::Fin).await;
        assert!(session.streams.lock().unwrap().contains_key(&52));
        assert_eq!(
            session.overflow.lock().usage().frames,
            368 - STREAM_QUEUE_CAP
        );
        assert!(!session.is_closed());
        session.close();
    }

    /// Hard cap with every stalled stream inside the grace: the demux
    /// waits bounded rounds instead of killing; reader progress on the
    /// stalled stream frees space, wakes the waiter, and the frame parks
    /// — nobody dies.
    #[tokio::test]
    async fn session_hard_cap_waits_for_progress_and_spares_everyone() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let slow_sid = 64;
        let waiting_sid = 65;
        let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (waiting_tx, mut waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        for _ in 0..STREAM_QUEUE_CAP {
            waiting_tx.try_send(StreamEvent::Data(vec![7])).unwrap();
        }
        {
            let mut streams = session.streams.lock().unwrap();
            streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
            streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
        }
        {
            let mut overflow = session.overflow.lock();
            for _ in 0..SESSION_OVERFLOW_HARD_CAP {
                overflow.push_back(slow_sid, StreamEvent::Data(vec![1; 8]));
            }
        }

        let parker = tokio::spawn({
            let session = Arc::clone(&session);
            async move {
                session
                    .park_overflow(waiting_sid, StreamEvent::Data(vec![9, 8, 7]))
                    .await;
            }
        });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            !session.overflow.lock().has(waiting_sid),
            "the frame waits at the hard cap inside the grace"
        );
        assert!(!parker.is_finished());
        assert!(session.killed_streams.lock().unwrap().is_empty());

        // Reader progress on the stalled stream frees overflow space and
        // wakes the parker, which parks its frame on the freed space.
        session.flush_overflow(slow_sid);
        tokio::time::timeout(Duration::from_secs(2), parker)
            .await
            .expect("parker wakes after the flush")
            .unwrap();
        assert_eq!(session.overflow.lock().stream_usage(waiting_sid).frames, 1);
        assert!(session.killed_streams.lock().unwrap().is_empty());

        // The parked frame flushes in order behind the queued ones.
        for _ in 0..STREAM_QUEUE_CAP {
            match waiting_rx.recv().await.unwrap() {
                StreamEvent::Data(data) => assert_eq!(data, vec![7]),
                StreamEvent::Fin | StreamEvent::Error(_) => {
                    panic!("waiting stream was terminated")
                }
            }
            session.flush_overflow(waiting_sid);
        }
        match waiting_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![9, 8, 7]),
            StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
        }
        assert!(!session.is_closed());
        session.close();
    }

    /// Hard cap with zero reader progress anywhere: the bounded wait
    /// rounds accrue until the most-stalled stream crosses the full
    /// grace — only then is it reaped (paused time walks the rounds).
    #[tokio::test(start_paused = true)]
    async fn session_hard_cap_kills_only_after_full_grace_of_waits() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (waiting_tx, _waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        {
            let mut streams = session.streams.lock().unwrap();
            streams.insert(71, StreamSink::Tcp(slow_tx));
            streams.insert(72, StreamSink::Tcp(waiting_tx));
        }
        {
            let mut overflow = session.overflow.lock();
            for _ in 0..SESSION_OVERFLOW_HARD_CAP {
                overflow.push_back(71, StreamEvent::Data(vec![1; 8]));
            }
        }

        session.park_overflow(72, StreamEvent::Data(vec![9])).await;

        assert!(session.killed_streams.lock().unwrap().contains(&71));
        assert!(!session.streams.lock().unwrap().contains_key(&71));
        assert!(!session.overflow.lock().has(71));
        assert!(!session.overflow.lock().has(72));
        assert!(!session.is_closed());
        session.close();
    }

    /// At the session soft cap parking is immediate — the demux never
    /// waits: a sibling with no parked frames dispatches normally, and
    /// reader progress flushes the parked frame into the freed slot.
    #[tokio::test]
    async fn session_soft_cap_parks_immediately_and_flushes_on_progress() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let slow_sid = 61;
        let fast_sid = 62;
        let waiting_sid = 63;
        let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (waiting_tx, mut waiting_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        for _ in 0..STREAM_QUEUE_CAP {
            waiting_tx.try_send(StreamEvent::Data(vec![7])).unwrap();
        }
        {
            let mut streams = session.streams.lock().unwrap();
            streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
            streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
            streams.insert(waiting_sid, StreamSink::Tcp(waiting_tx));
        }
        {
            let mut overflow = session.overflow.lock();
            for _ in 0..SESSION_OVERFLOW_CAP {
                overflow.push_back(slow_sid, StreamEvent::Data(vec![1; 8]));
            }
        }

        // The soft cap neither kills nor waits: the frame parks at once.
        session
            .park_overflow(waiting_sid, StreamEvent::Data(vec![9, 8, 7]))
            .await;
        assert!(
            !session
                .killed_streams
                .lock()
                .unwrap()
                .contains(&waiting_sid)
        );
        assert_eq!(session.overflow.lock().stream_usage(waiting_sid).frames, 1);

        // A sibling with no parked frames is not affected by the cap.
        session.dispatch_data(fast_sid, vec![7]).await;
        match fast_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![7]),
            StreamEvent::Fin | StreamEvent::Error(_) => panic!("fast sibling was terminated"),
        }

        // Reader progress frees a queue slot; the flush appends the
        // parked frame behind the still-queued ones (order-preserving).
        match waiting_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![7]),
            StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
        }
        session.flush_overflow(waiting_sid);
        for _ in 1..STREAM_QUEUE_CAP {
            match waiting_rx.recv().await.unwrap() {
                StreamEvent::Data(data) => assert_eq!(data, vec![7]),
                StreamEvent::Fin | StreamEvent::Error(_) => {
                    panic!("waiting stream was terminated")
                }
            }
        }
        match waiting_rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![9, 8, 7]),
            StreamEvent::Fin | StreamEvent::Error(_) => panic!("waiting stream was terminated"),
        }
        assert_eq!(session.overflow.lock().usage().frames, SESSION_OVERFLOW_CAP);
        assert!(!session.is_closed());
        session.close();
    }

    #[tokio::test]
    async fn overflow_transition_self_kicks_an_emptied_queue() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 70;
        let (tx, mut rx) = mpsc::channel(1);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));

        session
            .park_overflow(sid, StreamEvent::Data(vec![7, 8, 9]))
            .await;

        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
        match rx.recv().await.unwrap() {
            StreamEvent::Data(data) => assert_eq!(data, vec![7, 8, 9]),
            _ => panic!("overflow transition delivered a terminal event"),
        }
        session.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_overflow_flush_preserves_stream_order() {
        const EVENTS: usize = 256;
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 70;
        let (tx, mut rx) = mpsc::channel(1);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        for index in 0..EVENTS {
            session.overflow.lock().push_back(
                sid,
                StreamEvent::Data(u16::try_from(index).unwrap().to_be_bytes().to_vec()),
            );
        }

        let done = Arc::new(AtomicBool::new(false));
        let kickers: Vec<_> = (0..8)
            .map(|_| {
                let session = Arc::clone(&session);
                let done = Arc::clone(&done);
                tokio::spawn(async move {
                    while !done.load(Ordering::Acquire) {
                        session.flush_overflow(sid);
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();

        let mut observed = Vec::with_capacity(EVENTS);
        while observed.len() != EVENTS {
            session.flush_overflow(sid);
            let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("ordered overflow event timed out")
                .expect("ordered overflow channel closed");
            match event {
                StreamEvent::Data(data) => {
                    observed.push(u16::from_be_bytes(data.try_into().unwrap()) as usize);
                }
                StreamEvent::Fin | StreamEvent::Error(_) => {
                    panic!("unexpected terminal event")
                }
            }
        }
        done.store(true, Ordering::Release);
        for kicker in kickers {
            kicker.await.unwrap();
        }

        assert_eq!(observed, (0..EVENTS).collect::<Vec<_>>());
        let overflow = session.overflow.lock();
        assert_eq!(overflow.usage(), OverflowUsage::default());
        assert!(!overflow.flushing.contains(&sid));
        assert!(!overflow.flush_requested.contains(&sid));
        drop(overflow);
        session.close();
    }

    #[tokio::test]
    async fn overflow_preserves_data_before_fin() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 81;
        let (tx, rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        let permit = session.try_reserve().unwrap();
        let mut stream = AnyTlsStream::new(Arc::clone(&session), sid, rx, permit);
        for _ in 0..STREAM_QUEUE_CAP {
            session.dispatch_data(sid, vec![1]).await;
        }
        session.dispatch_data(sid, vec![9]).await;
        session.dispatch_fin(sid).await;

        let mut payload = vec![0; STREAM_QUEUE_CAP + 1];
        stream.read_exact(&mut payload).await.unwrap();
        assert!(payload[..STREAM_QUEUE_CAP].iter().all(|byte| *byte == 1));
        assert_eq!(payload[STREAM_QUEUE_CAP], 9);
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
    }

    /// 3B-2: a stalled stream is first parked in the session overflow
    /// (non-blocking); parking past the session soft cap still does not
    /// kill, but past the stall grace the watchdog reaps just that
    /// stream — queued data still drains, then the reader sees a reset
    /// (never a clean EOF), and the session survives.
    #[tokio::test(start_paused = true)]
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
        // A full queue alone does not kill: frames park in the overflow.
        session.dispatch_data(sid, vec![2u8; 8]).await;
        assert!(
            session.streams.lock().unwrap().get(&sid).is_some(),
            "overflow parking must not kill the stream"
        );
        // Parking past the session soft cap still does not kill…
        for _ in 0..SESSION_OVERFLOW_CAP {
            session.dispatch_data(sid, vec![2u8; 8]).await;
        }
        assert!(session.streams.lock().unwrap().get(&sid).is_some());
        // …but the watchdog reaps the stalled consumer past the grace.
        tokio::time::advance(OVERFLOW_STALL_GRACE + OVERFLOW_WATCHDOG_TICK).await;
        tokio::task::yield_now().await;
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

    /// 3B-3: a stalled stream never blocks the demux — a healthy stream on
    /// the same session keeps receiving while the stalled one parks in
    /// the session overflow, and the parked frames flush (in order) once
    /// the stalled reader progresses.
    #[tokio::test]
    async fn test_hol_stall_does_not_block_other_streams() {
        use tokio::io::AsyncReadExt as _;

        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let (slow_tx, slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        session
            .streams
            .lock()
            .unwrap()
            .insert(1, StreamSink::Tcp(slow_tx));
        session
            .streams
            .lock()
            .unwrap()
            .insert(2, StreamSink::Tcp(fast_tx));
        let permit = session.try_reserve().unwrap();
        let mut slow_stream = AnyTlsStream::new(Arc::clone(&session), 1, slow_rx, permit);

        // Stall stream 1 completely (queue full + overflow parking, never read).
        let parked = 64usize;
        for i in 0..STREAM_QUEUE_CAP + parked {
            session.dispatch_data(1, vec![(i % 251) as u8; 4]).await;
        }
        // Stream 2 still receives — the demux was never blocked.
        for i in 0..10u8 {
            session.dispatch_data(2, vec![i; 4]).await;
            let ev = tokio::time::timeout(Duration::from_secs(2), fast_rx.recv())
                .await
                .expect("stream 2 must not be blocked by stream 1")
                .expect("stream 2 channel open");
            match ev {
                StreamEvent::Data(d) => assert_eq!(d, vec![i; 4]),
                _ => panic!("stream 2 got non-data event"),
            }
        }

        // The slow reader progresses: queued + parked frames arrive in
        // order, exactly once each.
        let total = STREAM_QUEUE_CAP + parked;
        let mut got = vec![0u8; total * 4];
        tokio::time::timeout(Duration::from_secs(5), slow_stream.read_exact(&mut got))
            .await
            .expect("slow stream must drain")
            .unwrap();
        for (i, b) in got.as_chunks::<4>().0.iter().enumerate() {
            assert_eq!(b, &[(i % 251) as u8; 4], "frame {i} out of order");
        }
    }

    /// Regression: tripping the session overflow cap must never stall the
    /// demux. Driven through the real receive loop over the duplex: a slow
    /// stream parked to the session soft cap, one more frame for it, then
    /// a frame for a fast sibling — the sibling must receive within a
    /// bounded delay (the old demux waited ~500ms per cap trip here).
    #[tokio::test]
    async fn demux_overflow_cap_never_blocks_sibling_streams() {
        let (session, mut server) = establish_test_session("127.0.0.1:443").await;
        expect_handshake(&mut server).await;
        let slow_sid = 91;
        let fast_sid = 92;
        let (slow_tx, _slow_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        let (fast_tx, mut fast_rx) = mpsc::channel(STREAM_QUEUE_CAP);
        {
            let mut streams = session.streams.lock().unwrap();
            streams.insert(slow_sid, StreamSink::Tcp(slow_tx));
            streams.insert(fast_sid, StreamSink::Tcp(fast_tx));
        }

        // Fill the slow stream's queue, then park up to the session soft
        // cap — all through the real demux.
        for _ in 0..STREAM_QUEUE_CAP + SESSION_OVERFLOW_CAP {
            write_frame(&mut server, CMD_PSH, slow_sid, &[1u8; 8])
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while session.overflow.lock().usage().frames != SESSION_OVERFLOW_CAP {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("demux parks up to the session soft cap");

        // Trip the cap; the fast sibling's frame right behind it must not
        // wait, and the stalled stream survives inside its grace.
        write_frame(&mut server, CMD_PSH, slow_sid, &[2u8; 8])
            .await
            .unwrap();
        write_frame(&mut server, CMD_PSH, fast_sid, &[7u8; 4])
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_millis(100), fast_rx.recv())
            .await
            .expect("fast sibling must not wait behind the overflow cap")
            .expect("fast sibling channel open");
        match event {
            StreamEvent::Data(data) => assert_eq!(data, vec![7u8; 4]),
            StreamEvent::Fin | StreamEvent::Error(_) => panic!("fast sibling was terminated"),
        }
        assert!(session.streams.lock().unwrap().contains_key(&slow_sid));
        assert!(!session.killed_streams.lock().unwrap().contains(&slow_sid));
        session.close();
    }

    /// Flush progress pushes the reap deadline out: a stream that keeps
    /// draining is spared; once progress stops, the full grace applies.
    #[tokio::test(start_paused = true)]
    async fn overflow_watchdog_spares_streams_with_flush_progress() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 44;
        let (tx, mut rx) = mpsc::channel(STREAM_QUEUE_CAP);
        for _ in 0..STREAM_QUEUE_CAP {
            tx.try_send(StreamEvent::Data(vec![0])).unwrap();
        }
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        session
            .park_overflow(sid, StreamEvent::Data(vec![1; 8]))
            .await;
        session
            .park_overflow(sid, StreamEvent::Data(vec![2; 8]))
            .await;

        // Two seconds in the reader frees one slot: the flush moves a
        // parked frame and resets the stall clock.
        tokio::time::advance(Duration::from_secs(2)).await;
        match rx.recv().await {
            Some(StreamEvent::Data(_)) => {}
            _ => panic!("queued data must drain"),
        }
        session.flush_overflow(sid);
        assert_eq!(session.overflow.lock().stream_usage(sid).frames, 1);

        // Two more seconds: still inside the (reset) grace — alive.
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(session.streams.lock().unwrap().contains_key(&sid));
        assert!(!session.killed_streams.lock().unwrap().contains(&sid));

        // No further progress: the watchdog reaps after a full grace.
        tokio::time::advance(OVERFLOW_STALL_GRACE + OVERFLOW_WATCHDOG_TICK).await;
        tokio::task::yield_now().await;
        assert!(!session.streams.lock().unwrap().contains_key(&sid));
        assert!(session.killed_streams.lock().unwrap().contains(&sid));
        session.close();
    }

    /// The watchdog retires once the overflow drains; the next park
    /// respawns it.
    #[tokio::test(start_paused = true)]
    async fn overflow_watchdog_retires_when_the_overflow_drains() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let sid = 45;
        let (tx, mut rx) = mpsc::channel(STREAM_QUEUE_CAP);
        for _ in 0..STREAM_QUEUE_CAP {
            tx.try_send(StreamEvent::Data(vec![0])).unwrap();
        }
        session
            .streams
            .lock()
            .unwrap()
            .insert(sid, StreamSink::Tcp(tx));
        session
            .park_overflow(sid, StreamEvent::Data(vec![1; 8]))
            .await;
        assert!(session.watchdog.lock().unwrap().is_some());

        // Drain everything, then let a tick observe the empty overflow.
        while rx.try_recv().is_ok() {}
        session.flush_overflow(sid);
        while rx.try_recv().is_ok() {}
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
        tokio::time::advance(OVERFLOW_WATCHDOG_TICK * 2).await;
        tokio::task::yield_now().await;
        assert!(session.watchdog.lock().unwrap().is_none());
        session.close();
    }

    /// UoT sinks are drop-on-full: a flooded datagram queue parks nothing
    /// in the session overflow.
    #[tokio::test]
    async fn uot_sink_drop_on_full_never_parks_overflow() {
        let (session, _server) = establish_test_session("127.0.0.1:443").await;
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(StreamEvent::Data(vec![0])).unwrap();
        session
            .streams
            .lock()
            .unwrap()
            .insert(77, StreamSink::Uot(tx));
        session.dispatch_data(77, vec![1; 16]).await;
        session.dispatch_fin(77).await;
        assert_eq!(session.overflow.lock().usage(), OverflowUsage::default());
        assert!(session.watchdog.lock().unwrap().is_none());
        session.close();
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

        let target = |b: u8| vec![0x01, 127, 0, 0, b, 0x01, 0xbb];
        let (s1, s2, s3) = tokio::join!(
            session.open_stream_direct(target(1), session.try_reserve().unwrap()),
            session.open_stream_direct(target(2), session.try_reserve().unwrap()),
            session.open_stream_direct(target(3), session.try_reserve().unwrap()),
        );
        let (mut s1, mut s2, mut s3) = (s1.unwrap(), s2.unwrap(), s3.unwrap());
        assert_eq!(session.active_streams(), 3);

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

        tokio::try_join!(
            echo(&mut s1, b"one"),
            echo(&mut s2, b"two"),
            echo(&mut s3, b"three")
        )
        .unwrap();
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

        let mut s4 = session
            .open_stream_direct(target(4), session.try_reserve().unwrap())
            .await
            .unwrap();
        let (sid, a) = tokio::time::timeout(Duration::from_secs(2), addr_rx.recv())
            .await
            .expect("address frame")
            .unwrap();
        assert_eq!(sid, 4);
        assert_eq!(a, target(4));
        echo(&mut s4, b"again").await.unwrap();
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
            .open_stream_direct(target.clone(), session.try_reserve().unwrap())
            .await
            .unwrap();
        let mut s2 = session
            .open_stream_direct(target, session.try_reserve().unwrap())
            .await
            .unwrap();

        for expected_sid in 1..=2u32 {
            let (cmd, sid, _) = read_frame(&mut server).await.unwrap();
            assert_eq!((cmd, sid), (CMD_SYN, expected_sid));
            let (cmd, psid, _) = read_frame(&mut server).await.unwrap();
            assert_eq!((cmd, psid), (CMD_PSH, expected_sid));
        }
        write_frame(&mut server, CMD_FIN, 1, &[]).await.unwrap();

        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), s1.read(&mut b))
            .await
            .expect("s1 EOF")
            .unwrap();
        assert_eq!(n, 0);

        s2.write_all(b"still-here").await.unwrap();
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

    #[tokio::test]
    async fn warm_udp_uses_only_its_generation_owned_runtime_pool() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-anytls".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("AnyTLS node needs its own runtime")
            }
        };
        let (session, mut server) = establish_test_session("warm-anytls").await;
        expect_handshake(&mut server).await;

        let status = AnyTlsHandler::warm_pool_with(
            Arc::clone(&runtime),
            Duration::from_secs(1),
            move || async move { Ok(session) },
        )
        .await
        .unwrap();
        assert_eq!(status, UdpWarmStatus::Ready);
        assert!(pool.has_usable_session(POOL_KEY));

        let handler = AnyTlsHandler::new();
        assert_eq!(
            handler
                .warm_udp(Arc::clone(&runtime), Duration::from_secs(1))
                .await
                .unwrap(),
            UdpWarmStatus::AlreadyReady
        );
        drop(server);
    }

    #[tokio::test]
    async fn warm_udp_shutdown_cancels_a_notify_blocked_dial_and_keeps_pool_terminal() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "shutdown-warm-anytls".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        let runtime = generation.get(&node.id).unwrap();
        let pool = match &runtime.runtime {
            crate::runtime::ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.pool),
            crate::runtime::ProtocolRuntime::None | crate::runtime::ProtocolRuntime::Quic(_) => {
                panic!("AnyTLS node needs its own runtime")
            }
        };
        let dial_started = Arc::new(tokio::sync::Notify::new());
        let dial_blocked = Arc::new(tokio::sync::Notify::new());
        let warm = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            let dial_started = Arc::clone(&dial_started);
            let dial_blocked = Arc::clone(&dial_blocked);
            async move {
                AnyTlsHandler::warm_pool_with(runtime, Duration::from_secs(1), move || {
                    let dial_started = Arc::clone(&dial_started);
                    let dial_blocked = Arc::clone(&dial_blocked);
                    async move {
                        dial_started.notify_one();
                        dial_blocked.notified().await;
                        unreachable!("the blocked warm dial must be cancelled by shutdown")
                    }
                })
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(1), dial_started.notified())
            .await
            .expect("warm dial must start before its generation is shut down");
        generation.shutdown().await;
        let result = tokio::time::timeout(Duration::from_secs(1), warm)
            .await
            .expect("shutdown must unblock the warm future")
            .expect("warm task must not panic");
        assert!(result.is_err(), "terminal pool shutdown rejects the warm");
        assert!(
            !pool.has_usable_session(POOL_KEY),
            "a cancelled dial must not leave a usable session in the pool"
        );
        assert!(
            AnyTlsHandler::warm_pool_with(Arc::clone(&runtime), Duration::from_secs(1), || async {
                unreachable!("a terminal pool must reject before invoking a new dial")
            })
            .await
            .is_err(),
            "subsequent warm attempts must be rejected after generation shutdown"
        );
    }

    #[tokio::test]
    async fn speculative_shared_loser_unregisters_uot_sid_synchronously() {
        let handler = AnyTlsHandler::new();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "speculative-shared".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let pool: Arc<AnyTlsPool> =
            Arc::new(crate::session::SessionPool::new(session_pool_config()));
        let (session, _server) = establish_test_session("speculative-shared").await;
        pool.insert(POOL_KEY, &session);
        let prepared = handler
            .dial_udp_transport_speculative_with(
                &node,
                Arc::clone(&pool),
                "8.8.8.8:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
                || async { unreachable!("a shared checkout cannot dial") },
            )
            .await
            .unwrap();
        assert_eq!(session.streams.lock().unwrap().len(), 1);

        drop(prepared);

        assert!(
            session.streams.lock().unwrap().is_empty(),
            "loser Drop must synchronously unregister its UoT stream"
        );
        assert!(
            !session.is_closed(),
            "dropping a shared speculative transport must not retire its pooled session"
        );
    }

    #[tokio::test]
    async fn speculative_detached_winner_commits_into_captured_pool_once() {
        let handler = AnyTlsHandler::new();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "speculative-detached-commit".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let pool: Arc<AnyTlsPool> =
            Arc::new(crate::session::SessionPool::new(session_pool_config()));
        let (session, _server) = establish_test_session("speculative-detached-commit").await;
        let prepared = handler
            .dial_udp_transport_speculative_with(
                &node,
                Arc::clone(&pool),
                "8.8.8.8:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
                {
                    let session = Arc::clone(&session);
                    move || async move { Ok(session) }
                },
            )
            .await
            .unwrap();
        assert_eq!(pool.metrics().sessions, 0);
        assert_eq!(session.streams.lock().unwrap().len(), 1);

        let transport = prepared.commit().unwrap();
        assert_eq!(pool.metrics().sessions, 1);
        assert!(pool.has_usable_session(POOL_KEY));
        drop(transport);
        assert!(session.streams.lock().unwrap().is_empty());
        pool.shutdown();
    }

    #[tokio::test]
    async fn speculative_detached_commit_fails_closed_after_generation_shutdown() {
        let handler = AnyTlsHandler::new();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "speculative-detached-shutdown".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let pool: Arc<AnyTlsPool> =
            Arc::new(crate::session::SessionPool::new(session_pool_config()));
        let (session, _server) = establish_test_session("speculative-detached-shutdown").await;
        let prepared = handler
            .dial_udp_transport_speculative_with(
                &node,
                Arc::clone(&pool),
                "8.8.8.8:53".parse().unwrap(),
                None,
                Duration::from_secs(1),
                {
                    let session = Arc::clone(&session);
                    move || async move { Ok(session) }
                },
            )
            .await
            .unwrap();

        pool.shutdown();
        assert!(prepared.commit().is_err());
        assert!(session.is_closed());
        assert!(session.streams.lock().unwrap().is_empty());
        assert_eq!(pool.metrics().sessions, 0);
    }

    struct CancelledDial(Arc<AtomicBool>);

    impl Drop for CancelledDial {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn speculative_udp_abort_cancels_injected_dial_without_pooling() {
        let handler = Arc::new(AnyTlsHandler::new());
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "speculative-abort".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let pool: Arc<AnyTlsPool> =
            Arc::new(crate::session::SessionPool::new(session_pool_config()));
        let started = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let handler = Arc::clone(&handler);
            let node = node.clone();
            let pool = Arc::clone(&pool);
            let started = Arc::clone(&started);
            let cancelled = Arc::clone(&cancelled);
            async move {
                let _ = handler
                    .dial_udp_transport_speculative_with(
                        &node,
                        pool,
                        "8.8.8.8:53".parse().unwrap(),
                        None,
                        Duration::from_secs(1),
                        move || async move {
                            let _cancelled = CancelledDial(cancelled);
                            started.notify_one();
                            futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>()
                                .await
                        },
                    )
                    .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("the injected speculative dial must start");

        task.abort();
        let _ = task.await;
        assert!(
            cancelled.load(Ordering::Acquire),
            "aborting the speculative caller must drop the physical dial future"
        );
        assert_eq!(pool.metrics().sessions, 0);
        let first = pool.checkout_speculative(POOL_KEY).await.unwrap();
        let second = tokio::time::timeout(
            Duration::from_millis(100),
            pool.checkout_speculative(POOL_KEY),
        )
        .await
        .expect("cancelled speculative work must not leave a provisional slot")
        .unwrap();
        assert!(matches!(
            first,
            crate::session::SpeculativeCheckout::Detached(_)
        ));
        assert!(matches!(
            second,
            crate::session::SpeculativeCheckout::Detached(_)
        ));
    }

    #[tokio::test]
    async fn speculative_udp_generation_shutdown_cancels_injected_dial() {
        let handler = Arc::new(AnyTlsHandler::new());
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "speculative-shutdown".into(),
            protocol: NodeProtocol::AnyTLS,
            anytls_min_idle_session: Some(0),
            ..Default::default()
        };
        let pool: Arc<AnyTlsPool> =
            Arc::new(crate::session::SessionPool::new(session_pool_config()));
        let started = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn({
            let handler = Arc::clone(&handler);
            let node = node.clone();
            let pool = Arc::clone(&pool);
            let started = Arc::clone(&started);
            let cancelled = Arc::clone(&cancelled);
            async move {
                handler
                    .dial_udp_transport_speculative_with(
                        &node,
                        pool,
                        "8.8.8.8:53".parse().unwrap(),
                        None,
                        Duration::from_secs(1),
                        move || async move {
                            let _cancelled = CancelledDial(cancelled);
                            started.notify_one();
                            futures_util::future::pending::<anyhow::Result<Arc<AnyTlsSession>>>()
                                .await
                        },
                    )
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("the detached generation-owned dial must start");

        pool.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("pool shutdown must cancel the detached dial")
            .expect("speculative task must not panic");
        assert!(result.is_err());
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(pool.metrics().sessions, 0);
    }
}

#[cfg(test)]
mod uot_tests {
    use super::*;

    #[test]
    fn test_uot_request_uses_socks5_address_form() {
        // sing uot.ReadRequest parses the request destination with
        // M.SocksaddrSerializer (SOCKS5 ATYP), so the bytes a UoT connect
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
