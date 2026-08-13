//! UDP endpoint pool — NAT mapping and connection tracking for UDP relay.
//!
//! Each UDP "connection" (identified by client address + destination address)
//! gets a pooled endpoint that handles bidirectional forwarding and
//! NAT timeout management. Mirrors the Go `udp_endpoint_pool.go`.
//!
//! The pool is a [`DashMap`] so that per-packet lookups on the UDP fast path
//! only contend on a single shard instead of one global mutex.

use crate::stats::{ActiveConnectionGuard, OutboundTracker, StatsManager};
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tracing::debug;

#[doc(hidden)]
pub mod bench_support;

const DEFAULT_NAT_TIMEOUT: Duration = Duration::from_secs(30);
const JANITOR_INTERVAL: Duration = Duration::from_secs(5);
/// How long the endpoint driver waits for proxy data before giving up.
const REPLY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Hard cap on pooled endpoints. A unique-tuple UDP flood must not be able
/// to grow the pool (and with it sockets, reply tasks and memory) without
/// bound — at the cap new mappings are refused and the datagram is dropped,
/// which UDP tolerates by design.
pub(crate) const MAX_ENDPOINTS: usize = 8192;
/// At most 64 datagrams, including the initializer's first packet, may be
/// retained for one flow.
const FLOW_QUEUE_CAPACITY: usize = 64;
/// All retained payload bytes across UDP flows are bounded exactly by permits.
const GLOBAL_PAYLOAD_CAPACITY: usize = 8 * 1024 * 1024;
const TRANSPORT_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const TRAFFIC_ALIVE_REPORT_INTERVAL: Duration = Duration::from_millis(200);
const DRIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(6);
const DRIVER_ABORT_TIMEOUT: Duration = Duration::from_secs(1);
/// Includes the eagerly-created original-destination socket. Reaching the
/// bound fails the endpoint closed rather than replying from the wrong source.
const MAX_REPLY_SOCKETS_PER_ENDPOINT: usize = 8;
/// A pooled UDP endpoint representing one NAT mapping.
pub struct UdpEndpoint {
    /// The proxy-side framed UDP transport (upstream).
    pub proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
    /// The relay target address (upstream proxy).
    pub relay_addr: SocketAddr,
    /// NodeId of the proxy node this endpoint dials through — used to
    /// report UDP liveness when a reply actually arrives (see
    /// `receive_loop`) and to retire the endpoint on node death.
    node_id: uuid::Uuid,
    /// When this endpoint expires (monotonic nanos).
    expires_at: AtomicI64,
    /// Whether the endpoint has received at least one reply.
    has_reply: AtomicBool,
    /// Guard for the exactly-once first-reply metric.
    first_reply_recorded: AtomicBool,
    /// Bounds traffic-state lock acquisition to five times per second per endpoint.
    next_alive_report_at: AtomicI64,
    /// Creation time used for reply latency accounting.
    created_at: Instant,
    /// Reference count for active operations.
    ref_count: AtomicI64,
    /// Set when the endpoint is being destroyed.
    dead: AtomicBool,
    /// Serializes node-death retirement with the linearization point for an
    /// application send attempt. This lock is held only synchronously; no
    /// transport I/O occurs while it is held.
    send_gate: Mutex<()>,
    /// Ring buffer of peers we've sent packets to (for reply validation).
    pending_reply_peers: Mutex<[(SocketAddr, bool); 8]>,
    /// Next ring position to write.
    pending_reply_next: AtomicU64,
    /// Live byte counters shared with the clash-API tracker entry (plain
    /// atomics — the per-packet path must not take a lock).
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    /// Clash-API tracker connection id; set once at registration, taken at
    /// removal.  Not touched on the per-packet path.
    tracker_id: Mutex<Option<String>>,
}

impl UdpEndpoint {
    pub fn new(
        proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay_addr: SocketAddr,
        node_id: uuid::Uuid,
    ) -> Self {
        let now = monotonic_nanos();
        Self {
            proxy_socket,
            relay_addr,
            node_id,
            expires_at: AtomicI64::new(now + nanos_from_dur(DEFAULT_NAT_TIMEOUT)),
            has_reply: AtomicBool::new(false),
            first_reply_recorded: AtomicBool::new(false),
            next_alive_report_at: AtomicI64::new(0),
            created_at: Instant::now(),
            ref_count: AtomicI64::new(1),
            dead: AtomicBool::new(false),
            send_gate: Mutex::new(()),
            pending_reply_peers: Mutex::new(
                [(
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    false,
                ); 8],
            ),
            pending_reply_next: AtomicU64::new(0),
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            tracker_id: Mutex::new(None),
        }
    }

    /// Bind the clash-API tracker entry to this endpoint: the entry shares
    /// the endpoint's atomic counters, and `conn_id` is stored for removal.
    pub fn set_tracker(&self, conn_id: String) {
        *self.tracker_id.lock() = Some(conn_id);
    }

    /// Counter clones for the tracker entry.
    pub fn byte_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.upload.clone(), self.download.clone())
    }

    /// Count client→proxy bytes (lock-free).
    pub fn tracker_upload(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    /// Count proxy→client bytes (lock-free).
    pub fn tracker_download(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    /// Take the tracker connection id (on endpoint removal).
    pub fn take_tracker_id(&self) -> Option<String> {
        self.tracker_id.lock().take()
    }

    pub fn is_expired(&self) -> bool {
        monotonic_nanos() > self.expires_at.load(Ordering::Relaxed)
    }

    pub fn refresh(&self) {
        self.expires_at.store(
            monotonic_nanos() + nanos_from_dur(DEFAULT_NAT_TIMEOUT),
            Ordering::Relaxed,
        );
    }

    pub fn mark_reply(&self) {
        self.has_reply.store(true, Ordering::Relaxed);
        self.refresh();
    }

    fn take_first_reply_metric(&self) -> Option<Duration> {
        if self.first_reply_recorded.load(Ordering::Acquire) {
            return None;
        }
        (!self.first_reply_recorded.swap(true, Ordering::AcqRel)).then(|| self.created_at.elapsed())
    }

    fn take_alive_report_slot(&self) -> bool {
        let now = monotonic_nanos();
        if now < self.next_alive_report_at.load(Ordering::Relaxed) {
            return false;
        }
        self.next_alive_report_at.store(
            now + nanos_from_dur(TRAFFIC_ALIVE_REPORT_INTERVAL),
            Ordering::Relaxed,
        );
        true
    }

    pub fn has_reply(&self) -> bool {
        self.has_reply.load(Ordering::Relaxed)
    }

    pub fn release(&self) {
        self.ref_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn kill(&self) {
        // A node-death retirement ordered before `begin_send_attempt` must
        // prevent the transport call. Conversely, once an attempt has passed
        // that point it is ambiguous and may not be replayed.
        let _send_gate = self.send_gate.lock();
        self.dead.store(true, Ordering::Release);
    }

    fn begin_send_attempt(&self) -> io::Result<()> {
        let _send_gate = self.send_gate.lock();
        if self.dead.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "UDP endpoint was retired before transport send",
            ));
        }
        Ok(())
    }

    pub fn ref_count(&self) -> i64 {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Record a peer we've sent a packet to (for reply validation).
    ///
    /// Stores the peer address in a ring buffer. Transports without an
    /// explicit full-cone capability accept replies only from these peers.
    pub fn record_pending_reply_peer(&self, peer: SocketAddr) {
        let mut ring = self.pending_reply_peers.lock();
        let next = self.pending_reply_next.fetch_add(1, Ordering::Relaxed) as usize % 8;
        ring[next] = (peer, true);
    }

    /// Validate that a reply peer is expected for a fixed-peer transport.
    pub fn validate_reply_peer(&self, peer: SocketAddr) -> bool {
        self.pending_reply_peers
            .lock()
            .iter()
            .any(|(addr, valid)| *valid && *addr == peer)
    }
}

/// Key for the endpoint pool: (client address, destination address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    client_ip: [u8; 16],
    client_port: u16,
    dst_ip: [u8; 16],
    dst_port: u16,
}

impl EndpointKey {
    fn new(client: SocketAddr, dst: SocketAddr) -> Self {
        let mut cip = [0u8; 16];
        let mut dip = [0u8; 16];
        match client.ip() {
            std::net::IpAddr::V4(ip) => {
                cip[10] = 0xff;
                cip[11] = 0xff;
                cip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => cip.copy_from_slice(&ip.octets()),
        }
        match dst.ip() {
            std::net::IpAddr::V4(ip) => {
                dip[10] = 0xff;
                dip[11] = 0xff;
                dip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => dip.copy_from_slice(&ip.octets()),
        }
        Self {
            client_ip: cip,
            client_port: client.port(),
            dst_ip: dip,
            dst_port: dst.port(),
        }
    }

    /// Convert a stored 16-byte address back to `IpAddr`, unwrapping the
    /// v4-mapped form written by `new()`.
    fn ip_addr(bytes: &[u8; 16]) -> std::net::IpAddr {
        if bytes[0..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[12], bytes[13], bytes[14], bytes[15],
            ))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
        }
    }

    fn client_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.client_ip)
    }

    fn dst_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.dst_ip)
    }
}

/// Why a UDP pool entry went away.  The removal worker retires the flow's
/// conntrack entries only when userspace owned the datapath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RemovalReason {
    /// A userspace endpoint (or its uncommitted reservation) is gone; the
    /// flow's conntrack entries are retired with it.
    UserspaceEndpointRetired,
    #[cfg(any(feature = "ebpf", test))]
    /// The flow was handed to the kernel; its terminal conn_state must remain.
    KernelHandoff,
}

/// Message sent to the endpoint-removal sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EndpointRemoval {
    pub(crate) client: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) decision_token: u32,
    pub(crate) generation: u64,
    pub(crate) conn_id: Option<String>,
    pub(crate) reason: RemovalReason,
}

/// A synchronously-created anyfrom socket. The default factory calls the
/// daens-scoped production helper so eager and lazy sockets preserve the same
/// network-namespace and source-address invariants.
pub(super) trait UdpReplySocketFactory: Send + Sync + std::fmt::Debug {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket>;
}

#[derive(Debug)]
struct SystemUdpReplySocketFactory;

impl UdpReplySocketFactory for SystemUdpReplySocketFactory {
    fn create(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        super::new_udp_reply_socket(source)
    }
}
/// One retained packet owns all permits that account for it. Socket ingress
/// acquires them before copying; owned ingress transfers its allocation only
/// after the same bounded admission succeeds.
pub(super) struct QueuedDatagram {
    data: Bytes,
    _flow_permit: OwnedSemaphorePermit,
    _global_byte_permit: Option<OwnedSemaphorePermit>,
}

impl QueuedDatagram {
    pub(super) fn payload(&self) -> &[u8] {
        &self.data
    }
}

enum DatagramPayload<'a> {
    Borrowed(&'a [u8]),
    #[cfg(any(feature = "ebpf", test))]
    Owned(Bytes),
}

impl DatagramPayload<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(data) => data.len(),
            #[cfg(any(feature = "ebpf", test))]
            Self::Owned(data) => data.len(),
        }
    }

    fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(data) => Bytes::copy_from_slice(data),
            #[cfg(any(feature = "ebpf", test))]
            Self::Owned(data) => data,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketAdmissionError {
    FlowQueueFull,
    GlobalPayloadFull,
}
struct InitializingEndpoint {
    decision_token: u32,
    generation: u64,
    queue_tx: mpsc::Sender<QueuedDatagram>,
    queue_rx: Mutex<Option<mpsc::Receiver<QueuedDatagram>>>,
    flow_slots: Arc<Semaphore>,
    endpoint_permit: Mutex<Option<OwnedSemaphorePermit>>,
    /// A tracker registered after route selection but before the Ready
    /// transition. It must be removed if this initialization is cancelled.
    tracker_id: Mutex<Option<String>>,
    /// Finalized transport winner for this generation. Bound only after
    /// speculative preparation has drained, so a death callback can
    /// generation-safely retire the entry before `commit_ready` publishes Ready.
    selected_node: Mutex<Option<uuid::Uuid>>,
    cancelled: AtomicBool,
    cancel_notify: Notify,
}

impl InitializingEndpoint {
    fn take_receiver(&self) -> Option<mpsc::Receiver<QueuedDatagram>> {
        self.queue_rx.lock().take()
    }

    fn take_endpoint_permit(&self) -> Option<OwnedSemaphorePermit> {
        self.endpoint_permit.lock().take()
    }

    fn set_tracker_id(&self, tracker_id: String) -> bool {
        let mut current = self.tracker_id.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(tracker_id);
        true
    }

    fn take_tracker_id(&self) -> Option<String> {
        self.tracker_id.lock().take()
    }

    fn bind_selected_node(&self, node_id: uuid::Uuid) {
        *self.selected_node.lock() = Some(node_id);
    }

    fn clear_selected_node(&self) {
        *self.selected_node.lock() = None;
    }

    fn selected_node_is(&self, node_id: uuid::Uuid) -> bool {
        *self.selected_node.lock() == Some(node_id)
    }

    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::AcqRel) {
            self.cancel_notify.notify_waiters();
        }
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.cancel_notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

struct ReadyEndpoint {
    decision_token: u32,
    generation: u64,
    endpoint: Arc<UdpEndpoint>,
    queue_tx: mpsc::Sender<QueuedDatagram>,
    flow_slots: Arc<Semaphore>,
    _endpoint_permit: OwnedSemaphorePermit,
    _connection_guard: Option<ActiveConnectionGuard>,
    alive: AtomicBool,
}

enum EndpointEntry {
    Initializing(Arc<InitializingEndpoint>),
    Ready(Arc<ReadyEndpoint>),
    Retiring { generation: u64, token: u32 },
}

impl EndpointEntry {
    fn generation(&self) -> u64 {
        match self {
            Self::Initializing(entry) => entry.generation,
            Self::Ready(entry) => entry.generation,
            Self::Retiring { generation, .. } => *generation,
        }
    }

    fn decision_token(&self) -> u32 {
        match self {
            Self::Initializing(entry) => entry.decision_token,
            Self::Ready(entry) => entry.decision_token,
            Self::Retiring { token, .. } => *token,
        }
    }

    fn matches_identity(&self, generation: u64, token: u32) -> bool {
        self.generation() == generation && self.decision_token() == token
    }

    fn retire(&self) -> Option<String> {
        match self {
            Self::Initializing(entry) => entry.take_tracker_id(),
            Self::Ready(entry) => {
                entry.alive.store(false, Ordering::Release);
                entry.endpoint.kill();
                entry.endpoint.take_tracker_id()
            }
            Self::Retiring { .. } => None,
        }
    }
}

/// Result of the synchronous reservation performed by the UDP receive loop.
/// `Initializing` owns the first packet and the slow-path permit; all other
/// variants have released the permit before returning to the receive loop.
/// The lease stays inline to avoid another allocation on every new UDP flow.
#[allow(clippy::large_enum_variant)]
pub(super) enum EndpointReservation {
    Initializing(UdpInitLease),
    Enqueued,
    CapacityRejected,
    QueueFull,
    QueueClosed,
    #[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
    IdentityMismatch,
}

#[cfg(any(feature = "ebpf", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OwnedEnqueueError {
    IdentityMismatch,
    QueueFull,
    QueueClosed,
}

/// Owns an uncommitted Initializing incarnation. Dropping it transactionally
/// tombstones only this identity, closes followers, returns all permits, and
/// wakes reload waiters. It can never retire a newer entry for the key.
pub(super) struct UdpInitLease {
    pool: Arc<UdpEndpointPool>,
    key: EndpointKey,
    generation: u64,
    decision_token: u32,
    /// Cancellation epoch captured while publishing this Initializing entry.
    /// `commit_ready` compares it under the pool's shared epoch gate, so a
    /// cancellation that linearizes first can never publish Ready afterwards.
    epoch: u64,
    first: Option<QueuedDatagram>,
    _slow_permit: OwnedSemaphorePermit,
    cancellation: watch::Receiver<u64>,
    initializer: Arc<InitializingEndpoint>,
    _initializer_guard: UdpInitializerGuard,
    connection_guard: Option<ActiveConnectionGuard>,
    /// The DNS controller already examined this first datagram before the
    /// lease was created. A continuation must not invoke it a second time.
    dns_checked: bool,
    committed: bool,
}

impl UdpInitLease {
    pub(super) fn client_addr(&self) -> SocketAddr {
        SocketAddr::new(self.key.client_ip(), self.key.client_port)
    }

    pub(super) fn original_dst(&self) -> SocketAddr {
        SocketAddr::new(self.key.dst_ip(), self.key.dst_port)
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn decision_token(&self) -> u32 {
        self.decision_token
    }

    #[cfg(test)]
    pub(super) fn cancellation(&self) -> watch::Receiver<u64> {
        self.cancellation.clone()
    }

    pub(super) fn wait_cancellation(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut epoch = self.cancellation.clone();
        let initializer = Arc::clone(&self.initializer);
        async move {
            tokio::select! {
                _ = epoch.changed() => {}
                _ = initializer.cancelled() => {}
            }
        }
    }

    pub(super) fn set_connection_guard(&mut self, guard: ActiveConnectionGuard) {
        debug_assert!(self.connection_guard.is_none());
        self.connection_guard = Some(guard);
    }

    pub(super) fn mark_dns_checked(&mut self) {
        self.dns_checked = true;
    }

    pub(super) fn dns_checked(&self) -> bool {
        self.dns_checked
    }

    /// Associate a tracker created after route selection with this exact
    /// Initializing incarnation. If commit never happens, `Drop` transfers it
    /// to the removal sink; Ready cleanup continues to use `UdpEndpoint`.
    pub(super) fn set_tracker_id(&self, tracker_id: String) -> bool {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.set_tracker_id(tracker_id)
            }
            _ => false,
        }
    }

    /// Bind the finalized transport winner (NodeId) to this Initializing
    /// generation after speculative preparation drains and before endpoint
    /// setup. Returns false when a newer generation or death/cancel path
    /// retired this entry.
    pub(super) fn bind_selected_node(&self, node_id: uuid::Uuid) -> bool {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.bind_selected_node(node_id);
                true
            }
            _ => false,
        }
    }

    /// Clear the finalized winner's binding if it becomes ineligible before
    /// endpoint setup. This generation will retire; no later candidate rebinds.
    pub(super) fn clear_selected_node(&self) {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return;
        };
        if let EndpointEntry::Initializing(initializing) = entry.value()
            && initializing.generation == self.generation
            && initializing.decision_token == self.decision_token
        {
            initializing.clear_selected_node();
        }
    }

    /// True while this lease still owns the map's Initializing entry. Used as
    /// the post-bind / post-dial eligibility check so a death that won the
    /// race cannot proceed to dial or application send.
    pub(super) fn still_initializing(&self) -> bool {
        let Some(entry) = self.pool.endpoints.get(&self.key) else {
            return false;
        };
        matches!(
            entry.value(),
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token
        )
    }

    pub(super) fn take_queue_receiver(&self) -> Option<mpsc::Receiver<QueuedDatagram>> {
        let entry = self.pool.endpoints.get(&self.key)?;
        match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                initializing.take_receiver()
            }
            _ => None,
        }
    }

    pub(super) fn first_payload(&self) -> Bytes {
        self.first
            .as_ref()
            .expect("uncommitted UDP lease must retain its first datagram")
            .data
            .clone()
    }

    pub(super) fn take_first(&mut self) -> Option<QueuedDatagram> {
        self.first.take()
    }

    /// Replace the occupied Initializing entry in place. This is deliberately
    /// not an insert-after-lookup: a cancelled/old initializer cannot publish
    /// over a newer incarnation.
    pub(super) fn commit_ready(&mut self, endpoint: Arc<UdpEndpoint>) -> bool {
        // Keep the map-entry → epoch-gate order shared with reservation. The
        // cancellation path takes only the epoch gate, so it cannot form a
        // map/gate cycle and neither guard crosses an await.
        let mut occupied = match self.pool.endpoints.entry(self.key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => occupied,
            dashmap::mapref::entry::Entry::Vacant(_) => return false,
        };
        let _epoch_gate = self.pool.initialization_epoch.lock();
        if self.pool.terminal.load(Ordering::Acquire) || self.epoch != *_epoch_gate {
            return false;
        }
        let initializing = match occupied.get() {
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token =>
            {
                Arc::clone(initializing)
            }
            _ => return false,
        };
        let Some(endpoint_permit) = initializing.take_endpoint_permit() else {
            return false;
        };
        occupied.insert(EndpointEntry::Ready(Arc::new(ReadyEndpoint {
            generation: self.generation,
            decision_token: self.decision_token,
            endpoint,
            queue_tx: initializing.queue_tx.clone(),
            flow_slots: initializing.flow_slots.clone(),
            _endpoint_permit: endpoint_permit,
            _connection_guard: self.connection_guard.take(),
            alive: AtomicBool::new(true),
        })));
        self.committed = true;
        true
    }

    /// Retire a direct or blocked staged flow after its terminal conn_state is
    /// published. The exact tombstone prevents this tuple from being reused
    /// until the removal worker acknowledges the kernel handoff.
    #[cfg(any(feature = "ebpf", test))]
    pub(super) fn commit_kernel_handoff(&mut self) -> bool {
        let mut occupied = match self.pool.endpoints.entry(self.key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => occupied,
            dashmap::mapref::entry::Entry::Vacant(_) => return false,
        };
        let _epoch_gate = self.pool.initialization_epoch.lock();
        if self.pool.terminal.load(Ordering::Acquire) || self.epoch != *_epoch_gate {
            return false;
        }
        if !matches!(
            occupied.get(),
            EndpointEntry::Initializing(initializing)
                if initializing.generation == self.generation
                    && initializing.decision_token == self.decision_token
        ) {
            return false;
        }
        self.pool.active_retirements.fetch_add(1, Ordering::AcqRel);
        let entry = occupied.insert(EndpointEntry::Retiring {
            generation: self.generation,
            token: self.decision_token,
        });
        drop(occupied);
        let conn_id = entry.retire();
        drop(entry);
        drop(self.first.take());
        drop(self.connection_guard.take());
        self.pool.notify_removed(
            SocketAddr::new(self.key.client_ip(), self.key.client_port),
            SocketAddr::new(self.key.dst_ip(), self.key.dst_port),
            conn_id,
            RemovalReason::KernelHandoff,
            self.decision_token,
            self.generation,
        );
        self.committed = true;
        true
    }
}

impl Drop for UdpInitLease {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.first.take());
            drop(self.connection_guard.take());
            self.pool
                .retire_if_same(self.key, self.decision_token, self.generation);
        }
    }
}

struct UdpInitializerGuard {
    pool: Arc<UdpEndpointPool>,
}

#[cfg(test)]
#[derive(Debug)]
struct ReservationPublicationHook {
    published: Arc<std::sync::Barrier>,
    resume: Arc<std::sync::Barrier>,
}

impl UdpInitializerGuard {
    fn new(pool: Arc<UdpEndpointPool>) -> Self {
        pool.active_initializers.fetch_add(1, Ordering::AcqRel);
        Self { pool }
    }
}

impl Drop for UdpInitializerGuard {
    fn drop(&mut self) {
        if self.pool.active_initializers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.pool.initializers_empty.notify_waiters();
        }
    }
}

struct TaskRegistry {
    closed: bool,
    tasks: tokio::task::JoinSet<()>,
}

impl Default for TaskRegistry {
    fn default() -> Self {
        Self {
            closed: false,
            tasks: tokio::task::JoinSet::new(),
        }
    }
}

async fn drain_registered_tasks(tasks: &mut tokio::task::JoinSet<()>, label: &str) -> bool {
    let mut clean = true;
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            clean = false;
            debug!("UDP {} task join failed during shutdown: {}", label, error);
        }
    }
    clean
}

async fn join_registered_tasks(
    mut tasks: tokio::task::JoinSet<()>,
    label: &str,
    graceful_timeout: Duration,
    abort_first: bool,
) -> bool {
    if abort_first {
        tasks.abort_all();
    }
    match tokio::time::timeout(
        if abort_first {
            DRIVER_ABORT_TIMEOUT
        } else {
            graceful_timeout
        },
        drain_registered_tasks(&mut tasks, label),
    )
    .await
    {
        Ok(clean) => clean,
        Err(_) => {
            debug!(
                "Forcing cancellation of UDP {} tasks during shutdown",
                label
            );
            tasks.abort_all();
            tokio::time::timeout(
                DRIVER_ABORT_TIMEOUT,
                drain_registered_tasks(&mut tasks, label),
            )
            .await
            .unwrap_or_else(|_| {
                debug!("Timed out joining aborted UDP {} tasks", label);
                false
            })
        }
    }
}

/// Pool state is a single map entry per tuple: Initializing, Ready, or the
/// exact Retiring identity that fences reuse until cleanup is acknowledged.
pub struct UdpEndpointPool {
    endpoints: DashMap<EndpointKey, EndpointEntry>,
    endpoint_slots: Arc<Semaphore>,
    global_payload_bytes: Arc<Semaphore>,
    /// Monotonic per-reservation incarnation; used only for map ownership.
    next_generation: AtomicU64,
    /// Serializes initializer publication, cancellation bumps, and Ready
    /// commits. Reservations and commits take a map entry before this gate;
    /// cancellation takes only this gate. It is never held across await.
    initialization_epoch: Mutex<u64>,
    cancel_epoch: watch::Sender<u64>,
    active_initializers: AtomicUsize,
    initializers_empty: Notify,
    terminal: AtomicBool,
    slow_tasks: Mutex<TaskRegistry>,
    drivers: Mutex<TaskRegistry>,
    reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    /// Sink notified whenever an endpoint is removed; the control plane uses
    /// it to retire conntrack and tracker state exactly once.
    remove_sink: Mutex<Option<tokio::sync::mpsc::Sender<EndpointRemoval>>>,
    /// Bounded compensation for removals observed while the sink is full.
    removal_dirty: Mutex<HashSet<EndpointRemoval>>,
    active_retirements: AtomicUsize,
    retirements_empty: Notify,
    /// Test-only synchronous barrier at the historical publication point.
    /// It makes the cancellation linearization regression reproducible
    /// without introducing an await into reservation.
    #[cfg(test)]
    reservation_publication_hook: Mutex<Option<Arc<ReservationPublicationHook>>>,
}

impl UdpEndpointPool {
    /// Construct a max-capacity pool for tests and standalone callers.
    pub fn new() -> Self {
        Self::with_capacity_limit(MAX_ENDPOINTS)
    }

    /// Construct a pool with an explicit endpoint cap.
    pub fn with_capacity_limit(capacity_limit: usize) -> Self {
        Self::with_reply_socket_factory(
            capacity_limit.min(MAX_ENDPOINTS),
            Arc::new(SystemUdpReplySocketFactory),
        )
    }

    /// Dependency injection seam for synchronous anyfrom creation. The first
    /// socket is created before the driver starts; accepted alternate reply
    /// sources use the same factory lazily in the driver.
    pub(super) fn with_reply_socket_factory(
        capacity_limit: usize,
        reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    ) -> Self {
        let (cancel_epoch, _) = watch::channel(0u64);
        Self {
            endpoints: DashMap::new(),
            endpoint_slots: Arc::new(Semaphore::new(capacity_limit)),
            global_payload_bytes: Arc::new(Semaphore::new(GLOBAL_PAYLOAD_CAPACITY)),
            next_generation: AtomicU64::new(1),
            initialization_epoch: Mutex::new(0),
            cancel_epoch,
            active_initializers: AtomicUsize::new(0),
            initializers_empty: Notify::new(),
            terminal: AtomicBool::new(false),
            slow_tasks: Mutex::new(TaskRegistry::default()),
            drivers: Mutex::new(TaskRegistry::default()),
            reply_socket_factory,
            remove_sink: Mutex::new(None),
            removal_dirty: Mutex::new(HashSet::new()),
            active_retirements: AtomicUsize::new(0),
            retirements_empty: Notify::new(),
            #[cfg(test)]
            reservation_publication_hook: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn set_reservation_publication_hook(&self, hook: Option<Arc<ReservationPublicationHook>>) {
        *self.reservation_publication_hook.lock() = hook;
    }

    #[cfg(test)]
    fn pause_after_reservation_publication(&self) {
        let hook = self.reservation_publication_hook.lock().clone();
        if let Some(hook) = hook {
            hook.published.wait();
            hook.resume.wait();
        }
    }

    pub(super) fn create_reply_socket(&self, source: SocketAddr) -> io::Result<UdpSocket> {
        self.reply_socket_factory.create(source)
    }

    pub(crate) fn set_remove_sink(&self, tx: tokio::sync::mpsc::Sender<EndpointRemoval>) {
        *self.remove_sink.lock() = Some(tx);
        self.flush_removal_dirty();
    }

    pub(super) fn flush_removal_dirty(&self) {
        let Some(tx) = self.remove_sink.lock().clone() else {
            return;
        };
        let mut dirty = self.removal_dirty.lock();
        dirty.retain(|removal| match tx.try_send(removal.clone()) {
            Ok(()) => false,
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                true
            }
        });
    }

    async fn drain_removal_dirty(&self) {
        let Some(tx) = self.remove_sink.lock().clone() else {
            return;
        };
        let pending = std::mem::take(&mut *self.removal_dirty.lock());
        for removal in pending {
            if tx.send(removal).await.is_err() {
                break;
            }
        }
    }

    fn notify_removed(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        conn_id: Option<String>,
        reason: RemovalReason,
        decision_token: u32,
        generation: u64,
    ) {
        let removal = EndpointRemoval {
            client,
            dst,
            decision_token,
            generation,
            conn_id,
            reason,
        };
        #[cfg(test)]
        if self.remove_sink.lock().is_none() {
            self.complete_removal(client, dst, decision_token, generation);
            return;
        }
        let delivered = self
            .remove_sink
            .lock()
            .as_ref()
            .is_some_and(|tx| tx.try_send(removal.clone()).is_ok());
        if !delivered {
            self.removal_dirty.lock().insert(removal);
        }
        self.flush_removal_dirty();
    }

    fn packet_permits(
        &self,
        len: usize,
        flow_slots: &Arc<Semaphore>,
    ) -> Result<(OwnedSemaphorePermit, Option<OwnedSemaphorePermit>), PacketAdmissionError> {
        let flow_permit = flow_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| PacketAdmissionError::FlowQueueFull)?;
        let global_byte_permit = if len == 0 {
            None
        } else {
            let byte_count =
                u32::try_from(len).map_err(|_| PacketAdmissionError::GlobalPayloadFull)?;
            Some(
                self.global_payload_bytes
                    .clone()
                    .try_acquire_many_owned(byte_count)
                    .map_err(|_| PacketAdmissionError::GlobalPayloadFull)?,
            )
        };
        Ok((flow_permit, global_byte_permit))
    }

    fn make_packet(
        &self,
        data: DatagramPayload<'_>,
        flow_slots: &Arc<Semaphore>,
    ) -> Result<QueuedDatagram, PacketAdmissionError> {
        let (flow_permit, global_byte_permit) = self.packet_permits(data.len(), flow_slots)?;
        Ok(QueuedDatagram {
            data: data.into_bytes(),
            _flow_permit: flow_permit,
            _global_byte_permit: global_byte_permit,
        })
    }

    fn enqueue(
        &self,
        sender: &mpsc::Sender<QueuedDatagram>,
        flow_slots: &Arc<Semaphore>,
        data: DatagramPayload<'_>,
        stats: &StatsManager,
    ) -> EndpointReservation {
        if sender.is_closed() {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        let packet = match self.make_packet(data, flow_slots) {
            Ok(packet) => packet,
            Err(PacketAdmissionError::FlowQueueFull) => {
                stats.record_udp_flow_queue_full();
                return EndpointReservation::QueueFull;
            }
            Err(PacketAdmissionError::GlobalPayloadFull) => {
                stats.record_udp_global_payload_full();
                return EndpointReservation::QueueFull;
            }
        };
        match sender.try_send(packet) {
            Ok(()) => {
                stats.record_udp_queue_accepted();
                EndpointReservation::Enqueued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                stats.record_udp_flow_queue_full();
                EndpointReservation::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                stats.record_udp_queue_closed();
                EndpointReservation::QueueClosed
            }
        }
    }

    fn reserve_new(
        self: &Arc<Self>,
        vacant: dashmap::mapref::entry::VacantEntry<'_, EndpointKey, EndpointEntry>,
        data: DatagramPayload<'_>,
        decision_token: u32,
        slow_permit: OwnedSemaphorePermit,
        stats: &StatsManager,
    ) -> EndpointReservation {
        let endpoint_permit = match self.endpoint_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                stats.record_udp_capacity_rejection();
                return EndpointReservation::CapacityRejected;
            }
        };
        let flow_slots = Arc::new(Semaphore::new(FLOW_QUEUE_CAPACITY));
        let first = match self.make_packet(data, &flow_slots) {
            Ok(packet) => packet,
            Err(PacketAdmissionError::FlowQueueFull) => {
                stats.record_udp_flow_queue_full();
                return EndpointReservation::QueueFull;
            }
            Err(PacketAdmissionError::GlobalPayloadFull) => {
                stats.record_udp_global_payload_full();
                return EndpointReservation::QueueFull;
            }
        };
        let (queue_tx, queue_rx) = mpsc::channel(FLOW_QUEUE_CAPACITY);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let epoch_gate = self.initialization_epoch.lock();
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        let epoch = *epoch_gate;
        let cancellation = self.cancel_epoch.subscribe();
        let initializer_guard = UdpInitializerGuard::new(Arc::clone(self));
        let initializer = Arc::new(InitializingEndpoint {
            decision_token,
            generation,
            queue_tx,
            queue_rx: Mutex::new(Some(queue_rx)),
            flow_slots,
            endpoint_permit: Mutex::new(Some(endpoint_permit)),
            tracker_id: Mutex::new(None),
            selected_node: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            cancel_notify: Notify::new(),
        });
        let key = *vacant.key();
        vacant.insert(EndpointEntry::Initializing(Arc::clone(&initializer)));
        drop(epoch_gate);
        #[cfg(test)]
        self.pause_after_reservation_publication();
        EndpointReservation::Initializing(UdpInitLease {
            pool: Arc::clone(self),
            key,
            generation,
            decision_token,
            epoch,
            first: Some(first),
            _slow_permit: slow_permit,
            cancellation,
            initializer,
            _initializer_guard: initializer_guard,
            connection_guard: None,
            dns_checked: decision_token != 0,
            committed: false,
        })
    }
    /// Atomically reserve a cold tuple or synchronously enqueue onto its
    /// existing Initializing/Ready incarnation. No map or std-mutex guard is
    /// held across await because this entire operation is synchronous.
    pub(super) fn reserve_or_enqueue(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        slow_permit: OwnedSemaphorePermit,
        stats: &StatsManager,
    ) -> EndpointReservation {
        let key = EndpointKey::new(client, dst);
        loop {
            if self.terminal.load(Ordering::Acquire) {
                stats.record_udp_queue_closed();
                return EndpointReservation::QueueClosed;
            }
            match self.endpoints.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(occupied) => {
                    let (stale_token, stale_generation) = match occupied.get() {
                        EndpointEntry::Initializing(initializing) => {
                            match self.enqueue(
                                &initializing.queue_tx,
                                &initializing.flow_slots,
                                DatagramPayload::Borrowed(data),
                                stats,
                            ) {
                                EndpointReservation::QueueClosed => {
                                    (initializing.decision_token, initializing.generation)
                                }
                                other => return other,
                            }
                        }
                        EndpointEntry::Ready(ready)
                            if ready.alive.load(Ordering::Acquire)
                                && !ready.endpoint.dead.load(Ordering::Acquire) =>
                        {
                            match self.enqueue(
                                &ready.queue_tx,
                                &ready.flow_slots,
                                DatagramPayload::Borrowed(data),
                                stats,
                            ) {
                                EndpointReservation::QueueClosed => {
                                    (ready.decision_token, ready.generation)
                                }
                                other => return other,
                            }
                        }
                        EndpointEntry::Ready(ready) => (ready.decision_token, ready.generation),
                        EndpointEntry::Retiring { .. } => {
                            stats.record_udp_queue_closed();
                            return EndpointReservation::QueueClosed;
                        }
                    };
                    drop(occupied);
                    self.retire_if_same(key, stale_token, stale_generation);
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    return self.reserve_new(
                        vacant,
                        DatagramPayload::Borrowed(data),
                        0,
                        slow_permit,
                        stats,
                    );
                }
            }
        }
    }

    /// Admit a retained NFQUEUE allocation without duplicating its payload.
    /// A fresh call uses `None`; followers name the exact published generation.
    #[cfg(any(feature = "ebpf", test))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_owned_or_enqueue(
        self: &Arc<Self>,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        expected_generation: Option<u64>,
        slow_permit: OwnedSemaphorePermit,
        stats: &StatsManager,
    ) -> EndpointReservation {
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return EndpointReservation::QueueClosed;
        }
        if decision_token == 0 {
            return EndpointReservation::IdentityMismatch;
        }

        let key = EndpointKey::new(client, dst);
        match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let Some(generation) = expected_generation else {
                    return if matches!(occupied.get(), EndpointEntry::Retiring { .. }) {
                        EndpointReservation::QueueClosed
                    } else {
                        EndpointReservation::IdentityMismatch
                    };
                };
                if !occupied.get().matches_identity(generation, decision_token) {
                    return EndpointReservation::IdentityMismatch;
                }
                match occupied.get() {
                    EndpointEntry::Initializing(initializing) => self.enqueue(
                        &initializing.queue_tx,
                        &initializing.flow_slots,
                        DatagramPayload::Owned(data),
                        stats,
                    ),
                    EndpointEntry::Ready(ready)
                        if ready.alive.load(Ordering::Acquire)
                            && !ready.endpoint.dead.load(Ordering::Acquire) =>
                    {
                        self.enqueue(
                            &ready.queue_tx,
                            &ready.flow_slots,
                            DatagramPayload::Owned(data),
                            stats,
                        )
                    }
                    EndpointEntry::Ready(_) | EndpointEntry::Retiring { .. } => {
                        stats.record_udp_queue_closed();
                        EndpointReservation::QueueClosed
                    }
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if expected_generation.is_some() {
                    return EndpointReservation::IdentityMismatch;
                }
                self.reserve_new(
                    vacant,
                    DatagramPayload::Owned(data),
                    decision_token,
                    slow_permit,
                    stats,
                )
            }
        }
    }

    /// Reconstruct an expired terminal Proxy cell from the same-token live
    /// initializer or Ready entry and return its generation with the enqueue.
    #[cfg(any(feature = "ebpf", test))]
    pub(super) fn enqueue_owned_by_token(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: Bytes,
        decision_token: u32,
        stats: &StatsManager,
    ) -> Result<u64, OwnedEnqueueError> {
        if decision_token == 0 {
            return Err(OwnedEnqueueError::IdentityMismatch);
        }
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return Err(OwnedEnqueueError::QueueClosed);
        }
        let Some(entry) = self.endpoints.get(&EndpointKey::new(client, dst)) else {
            return Err(OwnedEnqueueError::IdentityMismatch);
        };
        let (generation, result) = match entry.value() {
            EndpointEntry::Initializing(initializing)
                if initializing.decision_token == decision_token =>
            {
                (
                    initializing.generation,
                    self.enqueue(
                        &initializing.queue_tx,
                        &initializing.flow_slots,
                        DatagramPayload::Owned(data),
                        stats,
                    ),
                )
            }
            EndpointEntry::Ready(ready)
                if ready.decision_token == decision_token
                    && ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                (
                    ready.generation,
                    self.enqueue(
                        &ready.queue_tx,
                        &ready.flow_slots,
                        DatagramPayload::Owned(data),
                        stats,
                    ),
                )
            }
            EndpointEntry::Retiring { token, .. } if *token == decision_token => {
                stats.record_udp_queue_closed();
                return Err(OwnedEnqueueError::QueueClosed);
            }
            _ => return Err(OwnedEnqueueError::IdentityMismatch),
        };
        match result {
            EndpointReservation::Enqueued => Ok(generation),
            EndpointReservation::QueueFull => Err(OwnedEnqueueError::QueueFull),
            EndpointReservation::QueueClosed => Err(OwnedEnqueueError::QueueClosed),
            EndpointReservation::Initializing(_)
            | EndpointReservation::CapacityRejected
            | EndpointReservation::IdentityMismatch => {
                unreachable!("enqueue-by-token returned an impossible reservation")
            }
        }
    }

    /// Receive-loop fast path: only a live Ready entry may be enqueued here.
    /// Initializing followers must take the slow admission path so they
    /// acquire the bounded slow permit before any payload copy/queue work.
    /// Closed entries are tombstoned by exact identity and reject the packet;
    /// the tuple remains fenced until the removal worker acknowledges cleanup.
    /// Terminal shutdown returns `QueueClosed` directly
    /// so the listener drops the datagram instead of attempting slow admission.
    pub(super) fn fast_path_enqueue(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        data: &[u8],
        stats: &StatsManager,
    ) -> Option<EndpointReservation> {
        if self.terminal.load(Ordering::Acquire) {
            stats.record_udp_queue_closed();
            return Some(EndpointReservation::QueueClosed);
        }
        let key = EndpointKey::new(client, dst);
        let entry = self.endpoints.get(&key)?;
        let (result, identity) = match entry.value() {
            EndpointEntry::Initializing(_) => return None,
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                (
                    self.enqueue(
                        &ready.queue_tx,
                        &ready.flow_slots,
                        DatagramPayload::Borrowed(data),
                        stats,
                    ),
                    (ready.decision_token, ready.generation),
                )
            }
            EndpointEntry::Ready(ready) => (
                EndpointReservation::QueueClosed,
                (ready.decision_token, ready.generation),
            ),
            EndpointEntry::Retiring { .. } => {
                stats.record_udp_queue_closed();
                return Some(EndpointReservation::QueueClosed);
            }
        };
        drop(entry);
        if matches!(result, EndpointReservation::QueueClosed) {
            self.retire_if_same(key, identity.0, identity.1);
        }
        Some(result)
    }

    #[cfg(test)]
    pub(super) fn get(&self, client: SocketAddr, dst: SocketAddr) -> Option<Arc<UdpEndpoint>> {
        let entry = self.endpoints.get(&EndpointKey::new(client, dst))?;
        match entry.value() {
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire) =>
            {
                Some(Arc::clone(&ready.endpoint))
            }
            _ => None,
        }
    }

    /// Begin exact retirement of the currently observed incarnation.
    pub fn remove(&self, client: SocketAddr, dst: SocketAddr) {
        let key = EndpointKey::new(client, dst);
        let identity = self.endpoints.get(&key).and_then(|entry| {
            (!matches!(entry.value(), EndpointEntry::Retiring { .. }))
                .then(|| (entry.value().decision_token(), entry.value().generation()))
        });
        if let Some((token, generation)) = identity {
            self.retire_if_same(key, token, generation);
        }
    }

    #[cfg(any(feature = "ebpf", test))]
    pub(super) fn retire_staged_identity(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        decision_token: u32,
        generation: u64,
    ) -> bool {
        decision_token != 0
            && self.retire_if_same(EndpointKey::new(client, dst), decision_token, generation)
    }

    /// Replace only the exact live incarnation with its removal tombstone.
    fn retire_if_same(&self, key: EndpointKey, token: u32, generation: u64) -> bool {
        let entry = match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied)
                if occupied.get().matches_identity(generation, token)
                    && !matches!(occupied.get(), EndpointEntry::Retiring { .. }) =>
            {
                if let EndpointEntry::Initializing(initializing) = occupied.get() {
                    initializing.cancel();
                }
                self.active_retirements.fetch_add(1, Ordering::AcqRel);
                occupied.insert(EndpointEntry::Retiring { generation, token })
            }
            _ => return false,
        };
        let conn_id = entry.retire();
        drop(entry);
        self.notify_removed(
            SocketAddr::new(key.client_ip(), key.client_port),
            SocketAddr::new(key.dst_ip(), key.dst_port),
            conn_id,
            RemovalReason::UserspaceEndpointRetired,
            token,
            generation,
        );
        true
    }

    /// Acknowledge backend/tracker cleanup and delete only its exact tombstone.
    pub(crate) fn complete_removal(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        decision_token: u32,
        generation: u64,
    ) -> bool {
        let key = EndpointKey::new(client, dst);
        let removed = match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(occupied)
                if matches!(
                    occupied.get(),
                    EndpointEntry::Retiring { generation: found, token }
                        if *found == generation && *token == decision_token
                ) =>
            {
                occupied.remove();
                true
            }
            _ => false,
        };
        if removed && self.active_retirements.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.retirements_empty.notify_waiters();
        }
        removed
    }

    /// Retire Ready and bound-Initializing mappings for a dead node.
    /// Only Initializing entries whose finalized winner is `node_id` are
    /// removed; an unbound reservation is still awaiting a winner. Removal is
    /// generation-safe.
    pub fn remove_by_node(&self, node_id: uuid::Uuid) {
        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready) if ready.endpoint.node_id == node_id => {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                EndpointEntry::Initializing(initializing)
                    if initializing.selected_node_is(node_id) =>
                {
                    Some((
                        *entry.key(),
                        initializing.decision_token,
                        initializing.generation,
                    ))
                }
                _ => None,
            })
            .collect();
        let removed = stale
            .into_iter()
            .filter(|(key, token, generation)| self.retire_if_same(*key, *token, *generation))
            .count();
        if removed != 0 {
            debug!(
                "Removed {} UDP endpoints bound to dead node {}",
                removed, node_id
            );
        }
    }

    /// The driver owns liveness and removes its mapping on reply timeout or
    /// I/O failure. Keep this janitor as a conservative backstop for entries
    /// whose reply task has already released its reference.
    pub fn janitor_cycle(&self) -> usize {
        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready)
                    if ready.endpoint.ref_count() <= 0 && ready.endpoint.is_expired() =>
                {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                _ => None,
            })
            .collect();
        let removed = stale
            .iter()
            .filter(|(key, token, generation)| self.retire_if_same(*key, *token, *generation))
            .count();
        if removed > 0 {
            debug!("UDP endpoint janitor removed {} expired endpoints", removed);
        }
        removed
    }

    pub fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JANITOR_INTERVAL).await;
                pool.janitor_cycle();
            }
        })
    }

    fn advance_initialization_epoch(&self, terminal: bool) {
        // This synchronous gate is the cancellation linearization point. It
        // is shared with reservation publication and commit_ready, and is
        // released before waiting for leases to drop.
        let next = {
            let mut epoch = self.initialization_epoch.lock();
            if terminal {
                self.terminal.store(true, Ordering::Release);
            }
            *epoch = epoch
                .checked_add(1)
                .expect("UDP initializer epoch overflow");
            self.cancel_epoch.send_replace(*epoch);
            *epoch
        };
        debug_assert_ne!(next, 0);
    }

    async fn wait_for_initializers(&self) -> bool {
        let wait = async {
            loop {
                if self.active_initializers.load(Ordering::Acquire) == 0 {
                    return;
                }
                let notified = self.initializers_empty.notified();
                if self.active_initializers.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .is_ok()
    }

    pub(super) async fn wait_for_retirements(&self) -> bool {
        let wait = async {
            loop {
                if self.active_retirements.load(Ordering::Acquire) == 0 {
                    return;
                }
                let notified = self.retirements_empty.notified();
                if self.active_retirements.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), wait)
            .await
            .is_ok()
    }

    pub(super) fn spawn_slow_path<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.slow_tasks.lock();
        while let Some(result) = tasks.tasks.try_join_next() {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                debug!("UDP slow-path task join failed: {}", error);
            }
        }
        if tasks.closed {
            return false;
        }
        drop(tasks.tasks.spawn(future));
        true
    }

    pub(super) async fn cancel_initializers_and_wait(&self) -> bool {
        self.advance_initialization_epoch(false);
        self.wait_for_initializers().await
    }

    /// Terminally close UDP admission, retire every mapping, and wait for all
    /// generation-owned slow-path tasks and endpoint drivers. The removal sink
    /// is closed only after task cleanup has completed so its consumer can
    /// drain before the control plane tears down generic background tasks.
    pub(super) async fn shutdown(&self) -> bool {
        self.advance_initialization_epoch(true);
        let slow_tasks = {
            let mut tasks = self.slow_tasks.lock();
            tasks.closed = true;
            std::mem::take(&mut tasks.tasks)
        };
        {
            let mut drivers = self.drivers.lock();
            drivers.closed = true;
        }

        let initializers_graceful = self.wait_for_initializers().await;
        let slow_tasks_clean = join_registered_tasks(
            slow_tasks,
            "slow-path",
            DRIVER_ABORT_TIMEOUT,
            !initializers_graceful,
        )
        .await;
        let initializers_clean =
            slow_tasks_clean && self.active_initializers.load(Ordering::Acquire) == 0;

        let stale: Vec<(EndpointKey, u32, u64)> = self
            .endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Initializing(initializing) => Some((
                    *entry.key(),
                    initializing.decision_token,
                    initializing.generation,
                )),
                EndpointEntry::Ready(ready) => {
                    Some((*entry.key(), ready.decision_token, ready.generation))
                }
                EndpointEntry::Retiring { .. } => None,
            })
            .collect();
        for (key, token, generation) in stale {
            self.retire_if_same(key, token, generation);
        }

        let driver_tasks = {
            let mut drivers = self.drivers.lock();
            std::mem::take(&mut drivers.tasks)
        };
        let drivers_clean = join_registered_tasks(
            driver_tasks,
            "endpoint driver",
            DRIVER_SHUTDOWN_TIMEOUT,
            false,
        )
        .await;

        self.drain_removal_dirty().await;
        let retirements_clean = self.wait_for_retirements().await;
        self.remove_sink.lock().take();
        initializers_clean && drivers_clean && retirements_clean
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    #[cfg(test)]
    fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn slow_task_count(&self) -> usize {
        self.slow_tasks.lock().tasks.len()
    }

    #[cfg(test)]
    fn driver_count(&self) -> usize {
        self.drivers.lock().tasks.len()
    }
}

impl Default for UdpEndpointPool {
    fn default() -> Self {
        Self::new()
    }
}

mod driver;

#[cfg(test)]
use driver::{UdpDriverContext, UdpDriverStart, run_endpoint_driver};
use driver::{monotonic_nanos, nanos_from_dur};

#[cfg(test)]
mod tests;
