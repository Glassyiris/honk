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
const DRIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(6);
const DRIVER_ABORT_TIMEOUT: Duration = Duration::from_secs(1);
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
        (!self.first_reply_recorded.swap(true, Ordering::AcqRel)).then(|| self.created_at.elapsed())
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
    /// Stores the peer address in a ring buffer. During the probing phase
    /// (before the first reply is received), only replies from recorded
    /// peers are accepted.
    pub fn record_pending_reply_peer(&self, peer: SocketAddr) {
        let mut ring = self.pending_reply_peers.lock();
        let next = self.pending_reply_next.fetch_add(1, Ordering::Relaxed) as usize % 8;
        ring[next] = (peer, true);
    }

    /// Validate that a reply peer is expected.
    ///
    /// Returns `true` if the reply should be accepted:
    /// - After `has_reply` is true: always accept (established state).
    /// - During probing: only accept if the peer was recorded via
    ///   `record_pending_reply_peer`.
    pub fn validate_reply_peer(&self, peer: SocketAddr) -> bool {
        if self.has_reply.load(Ordering::Relaxed) {
            return true;
        }
        let ring = self.pending_reply_peers.lock();
        for (addr, valid) in ring.iter() {
            if *valid && *addr == peer {
                return true;
            }
        }
        false
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
/// daens-scoped production helper; tests and embedders may inject a real
/// alternative without duplicating the endpoint state machine.
pub(super) trait UdpReplySocketFactory: Send + Sync + std::fmt::Debug {
    fn create(&self, original_dst: SocketAddr) -> io::Result<UdpSocket>;
}

#[derive(Debug)]
struct SystemUdpReplySocketFactory;

impl UdpReplySocketFactory for SystemUdpReplySocketFactory {
    fn create(&self, original_dst: SocketAddr) -> io::Result<UdpSocket> {
        super::new_udp_reply_socket(original_dst)
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
    Owned(Bytes),
}

impl DatagramPayload<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(data) => data.len(),
            Self::Owned(data) => data.len(),
        }
    }

    fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(data) => Bytes::copy_from_slice(data),
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
    /// Finalized Task 5 transport winner for this generation. Bound only after
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

    /// Production dependency injection seam for synchronous anyfrom creation.
    /// The factory is called before the driver starts and never from a
    /// transport-I/O await path.
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

    pub(super) fn create_reply_socket(&self, original_dst: SocketAddr) -> io::Result<UdpSocket> {
        self.reply_socket_factory.create(original_dst)
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

struct UdpDriverStart {
    first: QueuedDatagram,
    followers: Vec<QueuedDatagram>,
}

/// Channels that establish the driver barrier. The initializer creates the
/// anyfrom socket, spawns this driver, awaits `ready`, commits the map entry,
/// then transfers the retained initial flight and waits for `first_ack`.
pub(super) struct UdpDriverHandle {
    ready: Option<oneshot::Receiver<()>>,
    start: Option<oneshot::Sender<UdpDriverStart>>,
    first_ack: Option<oneshot::Receiver<io::Result<()>>>,
    /// Test-only cancellation handle; production ownership remains in the
    /// pool's driver registry until terminal shutdown joins every task.
    #[cfg(test)]
    task: Option<tokio::task::AbortHandle>,
}

/// Owns every terminal driver action. Its synchronous Drop runs after normal
/// completion, panic unwind, and Tokio task abort; token-and-generation-safe
/// retirement makes a stale driver harmless to a replacement mapping.
struct UdpDriverCleanupGuard {
    pool: Arc<UdpEndpointPool>,
    key: EndpointKey,
    generation: u64,
    decision_token: u32,
    endpoint: Arc<UdpEndpoint>,
}

impl UdpDriverCleanupGuard {
    fn new(
        pool: Arc<UdpEndpointPool>,
        key: EndpointKey,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
    ) -> Self {
        Self {
            pool,
            key,
            generation,
            decision_token,
            endpoint,
        }
    }
}

struct UdpDriverContext {
    endpoint: Arc<UdpEndpoint>,
    queue_rx: mpsc::Receiver<QueuedDatagram>,
    reply_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
}

impl Drop for UdpDriverCleanupGuard {
    fn drop(&mut self) {
        self.endpoint.release();
        self.pool
            .retire_if_same(self.key, self.decision_token, self.generation);
    }
}

impl UdpDriverHandle {
    pub(super) async fn wait_ready(&mut self) -> io::Result<()> {
        self.ready
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver ready already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before ready"))
    }

    #[cfg(test)]
    pub(super) fn start(&mut self, first: QueuedDatagram) -> io::Result<()> {
        self.start_with_followers(first, Vec::new())
    }

    pub(super) fn start_with_followers(
        &mut self,
        first: QueuedDatagram,
        followers: Vec<QueuedDatagram>,
    ) -> io::Result<()> {
        self.start
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver start already consumed"))?
            .send(UdpDriverStart { first, followers })
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))
    }

    pub(super) async fn wait_first_ack(&mut self) -> io::Result<()> {
        self.first_ack
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver first ack already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))?
    }

    #[cfg(test)]
    fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl UdpEndpointPool {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_driver(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        client_dst: SocketAddr,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
        queue_rx: mpsc::Receiver<QueuedDatagram>,
        reply_socket: Arc<UdpSocket>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        outbound_name: String,
    ) -> UdpDriverHandle {
        let key = EndpointKey::new(client_addr, client_dst);
        let outbound_tracker = stats.outbound_tracker(&outbound_name);
        let (ready_tx, ready) = oneshot::channel();
        let (start, start_rx) = oneshot::channel();
        let (first_ack_tx, first_ack) = oneshot::channel();
        let pool = Arc::clone(self);
        let mut drivers = self.drivers.lock();
        while let Some(result) = drivers.tasks.try_join_next() {
            if let Err(error) = result {
                debug!("UDP endpoint driver join failed: {}", error);
            }
        }
        if drivers.closed {
            drop(ready_tx);
            drop(start_rx);
            drop(first_ack_tx);
            return UdpDriverHandle {
                ready: Some(ready),
                start: Some(start),
                first_ack: Some(first_ack),
                #[cfg(test)]
                task: None,
            };
        }
        let task = drivers.tasks.spawn(async move {
            // Construct before every await so abort and panic take the same
            // cleanup path as an ordinary driver return.
            let _cleanup = UdpDriverCleanupGuard::new(
                Arc::clone(&pool),
                key,
                generation,
                decision_token,
                Arc::clone(&endpoint),
            );
            let _ = ready_tx.send(());
            let initial = match start_rx.await {
                Ok(initial) => initial,
                Err(_) => return,
            };
            let result = run_endpoint_driver(
                UdpDriverContext {
                    endpoint: Arc::clone(&endpoint),
                    queue_rx,
                    reply_socket,
                    client_addr,
                    client_dst,
                    alive_set,
                    stats,
                    outbound_tracker,
                },
                initial,
                first_ack_tx,
            )
            .await;
            if let Err(error) = result {
                debug!(
                    "UDP endpoint driver {} -> {} stopped: {}",
                    client_addr, client_dst, error
                );
            }
        });
        drop(drivers);
        #[cfg(not(test))]
        drop(task);
        UdpDriverHandle {
            ready: Some(ready),
            start: Some(start),
            first_ack: Some(first_ack),
            #[cfg(test)]
            task: Some(task),
        }
    }
}

async fn run_endpoint_driver(
    context: UdpDriverContext,
    initial: UdpDriverStart,
    first_ack: oneshot::Sender<io::Result<()>>,
) -> io::Result<()> {
    let UdpDriverContext {
        endpoint,
        queue_rx,
        reply_socket,
        client_addr,
        client_dst,
        alive_set,
        stats,
        outbound_tracker,
    } = context;
    // Sniffing may have consumed later QUIC Initial fragments from the queue.
    // Send that retained prefix before the untouched receiver queue so the
    // server sees the original flight in order without waiting for a PTO.
    let UdpDriverStart { first, followers } = initial;
    let mut initial_result = send_one(&endpoint, &stats, &outbound_tracker, first, true).await;
    if initial_result.is_ok() {
        for follower in followers {
            if let Err(error) =
                send_one(&endpoint, &stats, &outbound_tracker, follower, false).await
            {
                initial_result = Err(error);
                break;
            }
        }
    }
    match initial_result {
        Ok(()) => {
            let _ = first_ack.send(Ok(()));
        }
        Err(error) => {
            if !endpoint.dead.load(Ordering::Acquire) {
                let ipver = if client_dst.is_ipv4() {
                    honk_outbound::alive::IpVersion::V4
                } else {
                    honk_outbound::alive::IpVersion::V6
                };
                alive_set.report_unavailable_traffic(
                    endpoint.node_id,
                    honk_outbound::alive::ProbeDomain::DataUdp,
                    ipver,
                );
            }
            let _ = first_ack.send(Err(io::Error::new(error.kind(), error.to_string())));
            return Err(error);
        }
    }

    let sender = send_followers(
        Arc::clone(&endpoint),
        queue_rx,
        Arc::clone(&stats),
        outbound_tracker.clone(),
    );
    let receiver = receive_loop(
        Arc::clone(&endpoint),
        reply_socket,
        client_addr,
        client_dst,
        Arc::clone(&alive_set),
        stats,
        outbound_tracker,
    );
    tokio::pin!(sender);
    tokio::pin!(receiver);
    let result = tokio::select! {
        result = &mut sender => result,
        result = &mut receiver => result,
    };
    if result.is_err() && !endpoint.dead.load(Ordering::Acquire) {
        let ipver = if client_dst.is_ipv4() {
            honk_outbound::alive::IpVersion::V4
        } else {
            honk_outbound::alive::IpVersion::V6
        };
        alive_set.report_unavailable_traffic(
            endpoint.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            ipver,
        );
    }
    result
}

async fn send_followers(
    endpoint: Arc<UdpEndpoint>,
    mut queue_rx: mpsc::Receiver<QueuedDatagram>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    while let Some(packet) = queue_rx.recv().await {
        send_one(&endpoint, &stats, &outbound_tracker, packet, false).await?;
    }
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "UDP endpoint queue closed",
    ))
}

async fn send_one(
    endpoint: &UdpEndpoint,
    stats: &StatsManager,
    outbound_tracker: &OutboundTracker,
    packet: QueuedDatagram,
    first: bool,
) -> io::Result<()> {
    // This is the application-send linearization point. Node death that wins
    // before it prevents any transport call; death after it is ambiguous, so
    // this driver never retries the packet or starts later followers.
    endpoint.begin_send_attempt()?;
    let started = first.then(Instant::now);
    let sent = tokio::time::timeout(TRANSPORT_SEND_TIMEOUT, async {
        if first {
            endpoint
                .proxy_socket
                .send_packet_confirmed(&packet.data)
                .await
        } else {
            endpoint.proxy_socket.send_packet(&packet.data).await
        }
    })
    .await;
    let result = match sent {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP PacketTransport send timed out",
        )),
    };
    if let Some(started) = started {
        stats.record_udp_first_send_latency(started.elapsed());
    }
    match result {
        Ok(()) => {
            endpoint.refresh();
            endpoint.tracker_upload(packet.data.len() as u64);
            outbound_tracker.add_bytes(packet.data.len() as u64, 0);
            Ok(())
        }
        Err(error) => {
            if first {
                stats.record_udp_first_send_failure();
            }
            Err(error)
        }
    }
}

async fn receive_loop(
    endpoint: Arc<UdpEndpoint>,
    reply_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    let ipver = if client_dst.is_ipv4() {
        honk_outbound::alive::IpVersion::V4
    } else {
        honk_outbound::alive::IpVersion::V6
    };
    let mut buf = [0u8; 65536];
    loop {
        let received = tokio::time::timeout(
            REPLY_IDLE_TIMEOUT,
            endpoint.proxy_socket.recv_packet(&mut buf),
        )
        .await;
        let (n, source) = match received {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "UDP endpoint reply idle timeout",
                ));
            }
        };
        if source != endpoint.relay_addr && !endpoint.validate_reply_peer(source) {
            debug!(
                "UDP endpoint driver rejecting unexpected reply peer {}",
                source
            );
            continue;
        }
        reply_socket.send_to(&buf[..n], client_addr).await?;
        endpoint.mark_reply();
        if let Some(elapsed) = endpoint.take_first_reply_metric() {
            stats.record_udp_first_reply_latency(elapsed);
        }
        endpoint.tracker_download(n as u64);
        outbound_tracker.add_bytes(0, n as u64);
        alive_set.report_available_traffic(
            endpoint.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            ipver,
        );
    }
}

fn monotonic_nanos() -> i64 {
    // Use std Instant as monotonic clock (handles suspend correctly).
    // We only need relative comparisons, so offset from a fixed epoch is fine.
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

fn nanos_from_dur(d: Duration) -> i64 {
    d.as_nanos() as i64
}

#[cfg(test)]
mod tests {
    fn transport(
        sock: Arc<UdpSocket>,
        relay: SocketAddr,
    ) -> Arc<dyn honk_outbound::proxy::PacketTransport> {
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(sock, relay))
    }

    use super::*;

    async fn recv_and_ack(
        pool: &UdpEndpointPool,
        rx: &mut mpsc::Receiver<EndpointRemoval>,
    ) -> Option<EndpointRemoval> {
        let removal = rx.recv().await?;
        assert!(pool.complete_removal(
            removal.client,
            removal.dst,
            removal.decision_token,
            removal.generation,
        ));
        Some(removal)
    }

    fn try_recv_and_ack(
        pool: &UdpEndpointPool,
        rx: &mut mpsc::Receiver<EndpointRemoval>,
    ) -> Result<EndpointRemoval, mpsc::error::TryRecvError> {
        let removal = rx.try_recv()?;
        assert!(pool.complete_removal(
            removal.client,
            removal.dst,
            removal.decision_token,
            removal.generation,
        ));
        Ok(removal)
    }
    #[test]
    fn pool_constructors_use_max_or_explicit_capacity() {
        assert_eq!(
            UdpEndpointPool::new().endpoint_slots.available_permits(),
            MAX_ENDPOINTS
        );
        assert_eq!(
            UdpEndpointPool::with_capacity_limit(3)
                .endpoint_slots
                .available_permits(),
            3
        );
        assert_eq!(
            UdpEndpointPool::with_capacity_limit(usize::MAX)
                .endpoint_slots
                .available_permits(),
            MAX_ENDPOINTS
        );
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_endpoint_driver(
        endpoint: Arc<UdpEndpoint>,
        queue_rx: mpsc::Receiver<QueuedDatagram>,
        reply_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        client_dst: SocketAddr,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        outbound_name: String,
        first: QueuedDatagram,
        first_ack: oneshot::Sender<io::Result<()>>,
    ) -> io::Result<()> {
        let outbound_tracker = stats.outbound_tracker(&outbound_name);
        super::run_endpoint_driver(
            UdpDriverContext {
                endpoint,
                queue_rx,
                reply_socket,
                client_addr,
                client_dst,
                alive_set,
                stats,
                outbound_tracker,
            },
            UdpDriverStart {
                first,
                followers: Vec::new(),
            },
            first_ack,
        )
        .await
    }

    fn make_addr(ip: &str, port: u16) -> SocketAddr {
        format!("{}:{}", ip, port).parse().unwrap()
    }

    #[derive(Debug)]
    enum DriverSendAction {
        Ok,
        Error,
        Panic,
        Pending,
        WaitThenOk(Arc<tokio::sync::Notify>),
        WaitThenError(Arc<tokio::sync::Notify>),
    }

    #[derive(Debug)]
    enum DriverReceiveAction {
        Pending,
        Error,
        Packet { data: Vec<u8>, source: SocketAddr },
        WaitThenError(Arc<tokio::sync::Notify>),
    }

    #[derive(Debug)]
    struct ScriptedPacketTransport {
        relay: SocketAddr,
        actions: Mutex<std::collections::VecDeque<DriverSendAction>>,
        recv_actions: Mutex<std::collections::VecDeque<DriverReceiveAction>>,
        sent: Mutex<Vec<Vec<u8>>>,
        confirmed_sends: std::sync::atomic::AtomicUsize,
        send_progress: tokio::sync::Notify,
    }

    impl ScriptedPacketTransport {
        fn new(relay: SocketAddr, actions: impl IntoIterator<Item = DriverSendAction>) -> Self {
            Self {
                relay,
                actions: Mutex::new(actions.into_iter().collect()),
                recv_actions: Mutex::new(std::collections::VecDeque::new()),
                sent: Mutex::new(Vec::new()),
                confirmed_sends: std::sync::atomic::AtomicUsize::new(0),
                send_progress: tokio::sync::Notify::new(),
            }
        }

        fn with_receive_actions(
            relay: SocketAddr,
            send_actions: impl IntoIterator<Item = DriverSendAction>,
            recv_actions: impl IntoIterator<Item = DriverReceiveAction>,
        ) -> Self {
            Self {
                relay,
                actions: Mutex::new(send_actions.into_iter().collect()),
                recv_actions: Mutex::new(recv_actions.into_iter().collect()),
                sent: Mutex::new(Vec::new()),
                confirmed_sends: std::sync::atomic::AtomicUsize::new(0),
                send_progress: tokio::sync::Notify::new(),
            }
        }

        fn sent_packets(&self) -> Vec<Vec<u8>> {
            self.sent.lock().clone()
        }

        fn confirmed_send_count(&self) -> usize {
            self.confirmed_sends
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        async fn wait_for_send_count(&self, count: usize) {
            loop {
                if self.sent.lock().len() >= count {
                    return;
                }
                self.send_progress.notified().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl honk_outbound::proxy::PacketTransport for ScriptedPacketTransport {
        fn relay_addr(&self) -> SocketAddr {
            self.relay
        }

        async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
            self.sent.lock().push(data.to_vec());
            self.send_progress.notify_waiters();
            let action = self
                .actions
                .lock()
                .pop_front()
                .unwrap_or(DriverSendAction::Ok);
            match action {
                DriverSendAction::Ok => Ok(()),
                DriverSendAction::Error => Err(io::Error::other("scripted UDP send failure")),
                DriverSendAction::Panic => panic!("scripted UDP send panic"),
                DriverSendAction::Pending => std::future::pending::<io::Result<()>>().await,
                DriverSendAction::WaitThenOk(release) => {
                    release.notified().await;
                    Ok(())
                }
                DriverSendAction::WaitThenError(release) => {
                    release.notified().await;
                    Err(io::Error::other("released scripted UDP send failure"))
                }
            }
        }

        async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
            self.confirmed_sends
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.send_packet(data).await
        }

        async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let action = self
                .recv_actions
                .lock()
                .pop_front()
                .unwrap_or(DriverReceiveAction::Pending);
            match action {
                DriverReceiveAction::Pending => {
                    std::future::pending::<io::Result<(usize, SocketAddr)>>().await
                }
                DriverReceiveAction::Error => Err(io::Error::other("scripted UDP receive failure")),
                DriverReceiveAction::Packet { data, source } => {
                    buf[..data.len()].copy_from_slice(&data);
                    Ok((data.len(), source))
                }
                DriverReceiveAction::WaitThenError(release) => {
                    release.notified().await;
                    Err(io::Error::other("released scripted UDP receive failure"))
                }
            }
        }
    }

    fn reserve_driver_packets(
        pool: &Arc<UdpEndpointPool>,
        stats: &StatsManager,
        client: SocketAddr,
        dst: SocketAddr,
        first_data: &[u8],
        followers: &[&[u8]],
    ) -> (QueuedDatagram, mpsc::Receiver<QueuedDatagram>) {
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, first_data, first_permit, stats)
        {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("driver test must reserve a fresh lease"),
        };
        for follower in followers {
            let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            assert!(matches!(
                pool.reserve_or_enqueue(client, dst, follower, slow_permit, stats),
                EndpointReservation::Enqueued
            ));
        }
        let queue_rx = lease.take_queue_receiver().unwrap();
        let first = lease.take_first().unwrap();
        // The direct worker tests drive `run_endpoint_driver`; dropping the
        // uncommitted lease closes the producer while preserving queued FIFO
        // messages in the receiver.
        drop(lease);
        (first, queue_rx)
    }

    const TEST_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x7e57);
    const DEAD_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0xdead);
    const OTHER_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x07e4);
    const JANITOR_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x9a17);

    fn driver_test_endpoint(
        transport: Arc<ScriptedPacketTransport>,
        relay: SocketAddr,
    ) -> Arc<UdpEndpoint> {
        let transport: Arc<dyn honk_outbound::proxy::PacketTransport> = transport;
        Arc::new(UdpEndpoint::new(transport, relay, TEST_NODE_ID))
    }

    async fn test_reply_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    fn commit_ready(
        pool: &Arc<UdpEndpointPool>,
        client: SocketAddr,
        dst: SocketAddr,
        proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport>,
        relay: SocketAddr,
        node_id: uuid::Uuid,
    ) -> Arc<UdpEndpoint> {
        let stats = StatsManager::new();
        let slow_permit = Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("test slow permit");
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"test", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("expected a new initializer lease"),
        };
        let endpoint = Arc::new(UdpEndpoint::new(proxy_socket, relay, node_id));
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        endpoint
    }

    #[test]
    fn test_endpoint_key() {
        // Key is (client, dst) not (client, relay)
        let a = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
        let b = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
        let c = EndpointKey::new(make_addr("1.2.3.5", 80), make_addr("5.6.7.8", 443));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_endpoint_key_ipv6() {
        let a = EndpointKey::new(
            make_addr("[2001:db8::1]", 8080),
            make_addr("[2001:db8::2]", 9090),
        );
        let b = EndpointKey::new(
            make_addr("[2001:db8::1]", 8080),
            make_addr("[2001:db8::2]", 9090),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_pool_empty_operations() {
        let pool = UdpEndpointPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.janitor_cycle(), 0);
    }

    #[test]
    fn test_pool_get() {
        let pool = UdpEndpointPool::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        assert!(pool.get(client, dst).is_none());
    }

    #[test]
    fn udp_init_lease_reserves_one_initializing_incarnation_per_key() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let first = pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats);
        assert!(matches!(first, EndpointReservation::Initializing(_)));

        let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"follower", follower_permit, &stats),
            EndpointReservation::Enqueued
        ));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn udp_init_lease_old_generation_cannot_remove_replacement() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let first = match pool.reserve_or_enqueue(client, dst, b"old", first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("first reservation must initialize"),
        };
        let key = first.key;
        let old_generation = first.generation();
        let old_token = first.decision_token();
        drop(first);

        let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement = match pool.reserve_or_enqueue(
            client,
            dst,
            b"replacement",
            replacement_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("replacement reservation must initialize"),
        };
        pool.retire_if_same(key, old_token, old_generation);
        assert_eq!(pool.len(), 1, "old cleanup must not remove replacement");
        drop(replacement);
        assert!(pool.is_empty());
    }

    #[test]
    fn udp_owned_admission_transfers_allocations_and_preserves_identity() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 443);
        let slow_slots = Arc::new(Semaphore::new(1));
        let payload = Bytes::from(vec![0x41; 37]);
        let payload_ptr = payload.as_ptr();
        let slow_permit = slow_slots.clone().try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_owned_or_enqueue(
            client,
            dst,
            payload,
            41,
            None,
            slow_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("owned first payload must initialize"),
        };
        assert_eq!(lease.first_payload().as_ptr(), payload_ptr);
        assert_eq!(lease.decision_token(), 41);
        assert!(lease.dns_checked());
        assert_eq!(slow_slots.available_permits(), 0);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY - 37
        );

        let mut receiver = lease.take_queue_receiver().unwrap();
        let follower = Bytes::from(vec![0x42; 19]);
        let follower_ptr = follower.as_ptr();
        let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_owned_or_enqueue(
                client,
                dst,
                follower,
                41,
                Some(lease.generation()),
                follower_permit,
                &stats,
            ),
            EndpointReservation::Enqueued
        ));
        let queued = receiver.try_recv().unwrap();
        assert_eq!(queued.data.as_ptr(), follower_ptr);
        drop(queued);
        drop(lease.take_first());
        drop(lease);
        assert_eq!(slow_slots.available_permits(), 1);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
    }

    #[test]
    fn udp_retiring_tombstone_requires_exact_ack_before_tuple_reuse() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 443);
        let (removed_tx, mut removed_rx) = mpsc::channel(4);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"held"),
            77,
            None,
            slow_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("staged payload must initialize"),
        };
        let generation = lease.generation();
        assert!(pool.retire_staged_identity(client, dst, 77, generation));
        assert!(!lease.still_initializing());
        assert!(matches!(
            pool.reserve_or_enqueue(
                client,
                dst,
                b"too-early",
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                &stats,
            ),
            EndpointReservation::QueueClosed
        ));
        assert!(!pool.complete_removal(client, dst, 78, generation));
        assert!(!pool.complete_removal(client, dst, 77, generation + 1));
        let removal = removed_rx.try_recv().unwrap();
        assert_eq!(removal.decision_token, 77);
        assert_eq!(removal.generation, generation);
        assert!(pool.complete_removal(client, dst, 77, generation));

        let replacement = match pool.reserve_or_enqueue(
            client,
            dst,
            b"replacement",
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("acknowledged tombstone must allow replacement"),
        };
        assert_ne!(replacement.generation(), generation);
        assert!(!pool.complete_removal(client, dst, 77, generation));
        assert!(replacement.still_initializing());
        drop(replacement);
        let replacement_removal = removed_rx.try_recv().unwrap();
        assert!(pool.complete_removal(
            replacement_removal.client,
            replacement_removal.dst,
            replacement_removal.decision_token,
            replacement_removal.generation,
        ));
    }

    #[test]
    fn udp_kernel_handoff_preserves_terminal_identity_until_ack() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 443);
        let (removed_tx, mut removed_rx) = mpsc::channel(1);
        pool.set_remove_sink(removed_tx);
        let mut lease = match pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"held"),
            91,
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("staged payload must initialize"),
        };
        let generation = lease.generation();
        assert!(lease.commit_kernel_handoff());
        let removal = removed_rx.try_recv().unwrap();
        assert_eq!(removal.reason, RemovalReason::KernelHandoff);
        assert_eq!(removal.decision_token, 91);
        assert_eq!(removal.generation, generation);
        assert!(matches!(
            pool.reserve_owned_or_enqueue(
                client,
                dst,
                Bytes::from_static(b"late"),
                91,
                Some(generation),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                &stats,
            ),
            EndpointReservation::QueueClosed
        ));
        assert!(pool.complete_removal(client, dst, 91, generation));
    }

    #[tokio::test]
    async fn udp_exact_retirement_cancels_matching_initializer() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 443);
        let (removed_tx, mut removed_rx) = mpsc::channel(1);
        pool.set_remove_sink(removed_tx);
        let lease = match pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"held"),
            97,
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("staged payload must initialize"),
        };
        let generation = lease.generation();
        let cancellation = lease.wait_cancellation();

        assert!(pool.retire_staged_identity(client, dst, 97, generation));
        tokio::time::timeout(Duration::from_millis(100), cancellation)
            .await
            .expect("exact retirement must wake the initializer");
        let removal = removed_rx.try_recv().unwrap();
        assert!(pool.complete_removal(
            removal.client,
            removal.dst,
            removal.decision_token,
            removal.generation,
        ));
        drop(lease);
    }

    #[test]
    fn udp_live_reconstruction_enqueues_owned_payload_by_token() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 443);
        let relay = make_addr("192.168.1.1", 1080);
        let mut lease = match pool.reserve_owned_or_enqueue(
            client,
            dst,
            Bytes::from_static(b"first"),
            101,
            None,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("staged payload must initialize"),
        };
        let generation = lease.generation();
        let mut receiver = lease.take_queue_receiver().unwrap();
        let initializing_payload = Bytes::from(vec![0x44; 19]);
        let initializing_ptr = initializing_payload.as_ptr();
        assert!(matches!(
            pool.enqueue_owned_by_token(client, dst, initializing_payload, 101, &stats),
            Ok(found) if found == generation
        ));
        let queued = receiver.try_recv().unwrap();
        assert_eq!(queued.data.as_ptr(), initializing_ptr);
        drop(queued);
        let endpoint =
            driver_test_endpoint(Arc::new(ScriptedPacketTransport::new(relay, [])), relay);
        assert!(lease.commit_ready(endpoint));

        let payload = Bytes::from(vec![0x55; 23]);
        let payload_ptr = payload.as_ptr();
        assert!(matches!(
            pool.enqueue_owned_by_token(client, dst, payload, 101, &stats),
            Ok(found) if found == generation
        ));
        let queued = receiver.try_recv().unwrap();
        assert_eq!(queued.data.as_ptr(), payload_ptr);
        drop(queued);
        assert!(matches!(
            pool.reserve_owned_or_enqueue(
                client,
                dst,
                Bytes::from_static(b"stale"),
                101,
                Some(generation + 1),
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                &stats,
            ),
            EndpointReservation::IdentityMismatch
        ));
        pool.remove(client, dst);
    }

    #[test]
    fn udp_fast_path_queue_has_exact_flow_bound_and_drops_newest() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("first reservation must initialize"),
        };
        for _ in 0..FLOW_QUEUE_CAPACITY - 1 {
            let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            assert!(matches!(
                pool.reserve_or_enqueue(client, dst, b"follower", permit, &stats),
                EndpointReservation::Enqueued
            ));
        }
        let overflow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"newest", overflow_permit, &stats),
            EndpointReservation::QueueFull
        ));
        let snapshot = stats.udp_snapshot();
        assert_eq!(snapshot.queue_accepted, (FLOW_QUEUE_CAPACITY - 1) as u64);
        assert_eq!(snapshot.flow_queue_full, 1);
        drop(lease);
    }

    #[test]
    fn udp_fast_path_queue_has_exact_global_payload_bound() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let payload = vec![0x42; GLOBAL_PAYLOAD_CAPACITY];
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, &payload, first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("global-capacity packet must reserve"),
        };
        let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"x", follower_permit, &stats),
            EndpointReservation::QueueFull
        ));
        assert_eq!(stats.udp_snapshot().global_payload_full, 1);
        drop(lease);
    }

    #[test]
    fn udp_fast_path_queue_closed_entry_retires_and_allows_recreation() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("closed queue fixture must initialize"),
        };
        drop(lease.take_queue_receiver().unwrap());

        // Initializing is a fast-path miss; closed-queue retirement happens on
        // the slow reserve_or_enqueue path, which then creates a replacement.
        assert!(
            pool.fast_path_enqueue(client, dst, b"after-close", &stats)
                .is_none(),
            "Initializing (even closed) is never a direct fast-path hit"
        );
        let next_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement =
            match pool.reserve_or_enqueue(client, dst, b"replacement", next_permit, &stats) {
                EndpointReservation::Initializing(next) => next,
                _ => panic!("closed queue must allow recreation as Initializing"),
            };
        // The closed Initializing generation was retired; only the replacement remains.
        // The old lease identity cannot retire the newer generation.
        drop(lease);
        assert_eq!(pool.len(), 1);
        assert!(replacement.still_initializing());
        drop(replacement);
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn udp_init_lease_registers_cancellation_before_publishing() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let hook = Arc::new(ReservationPublicationHook {
            published: Arc::new(std::sync::Barrier::new(2)),
            resume: Arc::new(std::sync::Barrier::new(2)),
        });
        pool.set_reservation_publication_hook(Some(Arc::clone(&hook)));

        let (lease_tx, lease_rx) = std::sync::mpsc::sync_channel(1);
        let reserving_pool = Arc::clone(&pool);
        let reserving_stats = Arc::clone(&stats);
        let reserver = std::thread::spawn(move || {
            let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            let lease = match reserving_pool.reserve_or_enqueue(
                client,
                dst,
                b"first",
                slow_permit,
                &reserving_stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("publication fixture must reserve an initializer"),
            };
            lease_tx.send(lease).unwrap();
        });

        hook.published.wait();
        let mut cancellation_sent = pool.cancel_epoch.subscribe();
        let cancelling_pool = Arc::clone(&pool);
        let cancelling =
            tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
        cancellation_sent
            .changed()
            .await
            .expect("cancellation sender must remain live");
        let active_at_publication = pool.active_initializers.load(Ordering::Acquire);

        hook.resume.wait();
        let lease = tokio::task::spawn_blocking(move || lease_rx.recv().unwrap())
            .await
            .unwrap();
        let lease_cancellation = lease.cancellation();
        let cancellation_was_observed = lease_cancellation.has_changed().unwrap();
        drop(lease);
        assert!(cancelling.await.unwrap());
        reserver.join().unwrap();
        pool.set_reservation_publication_hook(None);

        assert_eq!(
            active_at_publication, 1,
            "a published initializer must already keep cancellation waiters active"
        );
        assert!(
            cancellation_was_observed,
            "the lease must observe cancellation sent while publication was paused"
        );
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn udp_init_lease_reload_cancellation_drops_slot_before_returning() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("first reservation must initialize"),
        };
        let mut cancellation = lease.cancellation();
        let cancelling_pool = Arc::clone(&pool);
        let cancelled =
            tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
        tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
            .await
            .expect("reload cancellation was not broadcast")
            .expect("reload cancellation sender closed");
        drop(lease);
        assert!(cancelled.await.unwrap());
        assert!(pool.is_empty());

        let next_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"next", next_permit, &stats),
            EndpointReservation::Initializing(_)
        ));
    }

    #[tokio::test]
    async fn udp_init_lease_cancellation_before_commit_fences_ready_publication() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("fence fixture must reserve an initializer"),
        };
        let mut cancellation = lease.cancellation();
        let cancelling_pool = Arc::clone(&pool);
        let cancelling =
            tokio::spawn(async move { cancelling_pool.cancel_initializers_and_wait().await });
        tokio::time::timeout(Duration::from_secs(1), cancellation.changed())
            .await
            .expect("test barrier must observe cancellation")
            .expect("cancellation sender must remain live");

        let relay = make_addr("192.168.1.1", 1080);
        let endpoint = Arc::new(UdpEndpoint::new(
            Arc::new(ScriptedPacketTransport::new(relay, []))
                as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            TEST_NODE_ID,
        ));
        assert!(
            !lease.commit_ready(endpoint),
            "cancellation that linearizes first must fence the old commit"
        );
        drop(lease);
        assert!(cancelling.await.unwrap());
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn udp_init_lease_commit_before_cancellation_keeps_ready_endpoint() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("fence fixture must reserve an initializer"),
        };
        let relay = make_addr("192.168.1.1", 1080);
        let endpoint = Arc::new(UdpEndpoint::new(
            Arc::new(ScriptedPacketTransport::new(relay, []))
                as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            TEST_NODE_ID,
        ));
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        drop(lease);

        assert!(pool.cancel_initializers_and_wait().await);
        assert!(
            Arc::ptr_eq(&pool.get(client, dst).unwrap(), &endpoint),
            "an ordinary reload only cancels Initializing work"
        );
        pool.remove(client, dst);
    }

    #[test]
    fn udp_init_lease_drop_notifies_registered_tracker_once() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let first_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, b"first", first_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("first reservation must initialize"),
        };
        assert!(lease.set_tracker_id("tracker-before-commit".to_owned()));

        drop(lease);

        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("tracker-before-commit".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_init_lease_abort_and_panic_release_generation_for_reuse() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);

        let (reserved_tx, reserved_rx) = oneshot::channel();
        let abort_pool = Arc::clone(&pool);
        let abort_stats = Arc::clone(&stats);
        let aborted = tokio::spawn(async move {
            let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            let lease = match abort_pool.reserve_or_enqueue(
                client,
                dst,
                b"abort",
                slow_permit,
                &abort_stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("abort test must initialize"),
            };
            let _lease = lease;
            reserved_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        reserved_rx.await.unwrap();
        aborted.abort();
        assert!(aborted.await.unwrap_err().is_cancelled());
        assert!(pool.is_empty(), "aborted initializer must drop its lease");

        let panic_pool = Arc::clone(&pool);
        let panic_stats = Arc::clone(&stats);
        let panicked = tokio::spawn(async move {
            let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            let _lease = match panic_pool.reserve_or_enqueue(
                client,
                dst,
                b"panic",
                slow_permit,
                &panic_stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("panic test must initialize"),
            };
            panic!("intentional initializer panic");
        });
        assert!(panicked.await.unwrap_err().is_panic());
        assert!(pool.is_empty(), "panicked initializer must drop its lease");

        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let next = pool.reserve_or_enqueue(client, dst, b"next", slow_permit, &stats);
        assert!(matches!(next, EndpointReservation::Initializing(_)));
    }

    #[tokio::test]
    async fn udp_ready_endpoint_survives_ordinary_reload_cancellation() {
        // Real driver: ready → commit → first/ack, leave receive pending,
        // production reload cancellation, then prove the mapping still
        // accepts and delivers traffic before deterministic cleanup.
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
            relay,
            [DriverSendAction::Ok, DriverSendAction::Ok],
            [DriverReceiveAction::Pending],
        ));
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("reload-ready fixture must initialize"),
        };
        let endpoint = Arc::new(UdpEndpoint::new(
            transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            TEST_NODE_ID,
        ));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        driver.wait_first_ack().await.unwrap();
        drop(lease);

        assert!(pool.cancel_initializers_and_wait().await);
        assert!(
            Arc::ptr_eq(&pool.get(client, dst).unwrap(), &endpoint),
            "ordinary reload cancels Initializing work only"
        );

        // Post-reload: steady packet must still enqueue and reach transport.
        let follower_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client, dst, b"after-reload", follower_permit, &stats),
            EndpointReservation::Enqueued
        ));
        transport.wait_for_send_count(2).await;
        assert_eq!(
            transport.sent_packets(),
            vec![b"first".to_vec(), b"after-reload".to_vec()]
        );

        pool.remove(client, dst);
        tokio::task::yield_now().await;
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn udp_endpoint_worker_sends_first_then_fifo_followers() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (first, queue_rx) =
            reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"second", b"third"]);
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [
                DriverSendAction::Ok,
                DriverSendAction::Ok,
                DriverSendAction::Ok,
            ],
        ));
        let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
        let (first_ack_tx, first_ack_rx) = oneshot::channel();
        let worker = tokio::spawn(run_endpoint_driver(
            endpoint,
            queue_rx,
            test_reply_socket().await,
            client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            first,
            first_ack_tx,
        ));

        first_ack_rx.await.unwrap().unwrap();
        transport.wait_for_send_count(3).await;
        assert_eq!(
            transport.sent_packets(),
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
        assert_eq!(transport.confirmed_send_count(), 1);
        assert_eq!(stats.udp_snapshot().first_send_latency.count, 1);
        worker.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn udp_endpoint_worker_times_out_first_send_after_five_seconds() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (first, queue_rx) = reserve_driver_packets(&pool, &stats, client, dst, b"first", &[]);
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::Pending],
        ));
        let endpoint = driver_test_endpoint(transport, relay);
        let (first_ack_tx, first_ack_rx) = oneshot::channel();
        let worker = tokio::spawn(run_endpoint_driver(
            endpoint,
            queue_rx,
            test_reply_socket().await,
            client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            first,
            first_ack_tx,
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(TRANSPORT_SEND_TIMEOUT).await;
        assert_eq!(
            first_ack_rx.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(stats.udp_snapshot().first_send_failures, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn udp_endpoint_worker_times_out_steady_send_after_five_seconds() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (first, queue_rx) =
            reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"steady"]);
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::Ok, DriverSendAction::Pending],
        ));
        let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
        let (first_ack_tx, first_ack_rx) = oneshot::channel();
        let worker = tokio::spawn(run_endpoint_driver(
            endpoint,
            queue_rx,
            test_reply_socket().await,
            client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            first,
            first_ack_tx,
        ));

        first_ack_rx.await.unwrap().unwrap();
        transport.wait_for_send_count(2).await;
        tokio::time::advance(TRANSPORT_SEND_TIMEOUT).await;
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(stats.udp_snapshot().first_send_failures, 0);
    }

    #[tokio::test]
    async fn udp_endpoint_worker_blocked_flow_does_not_block_another() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let relay = make_addr("192.168.1.1", 1080);
        let blocked_client = make_addr("10.0.0.1", 12345);
        let ready_client = make_addr("10.0.0.2", 12345);
        let dst = make_addr("8.8.8.8", 53);

        let (blocked_first, blocked_rx) =
            reserve_driver_packets(&pool, &stats, blocked_client, dst, b"blocked", &[]);
        let blocked_transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::Pending],
        ));
        let (blocked_ack_tx, _blocked_ack_rx) = oneshot::channel();
        let blocked_worker = tokio::spawn(run_endpoint_driver(
            driver_test_endpoint(Arc::clone(&blocked_transport), relay),
            blocked_rx,
            test_reply_socket().await,
            blocked_client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            blocked_first,
            blocked_ack_tx,
        ));
        blocked_transport.wait_for_send_count(1).await;

        let (ready_first, ready_rx) =
            reserve_driver_packets(&pool, &stats, ready_client, dst, b"other-flow", &[]);
        let ready_transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let (ready_ack_tx, ready_ack_rx) = oneshot::channel();
        let ready_worker = tokio::spawn(run_endpoint_driver(
            driver_test_endpoint(Arc::clone(&ready_transport), relay),
            ready_rx,
            test_reply_socket().await,
            ready_client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            stats,
            "test-node".to_owned(),
            ready_first,
            ready_ack_tx,
        ));

        tokio::time::timeout(Duration::from_secs(1), ready_ack_rx)
            .await
            .expect("blocked flow must not delay another endpoint driver")
            .unwrap()
            .unwrap();
        assert_eq!(ready_transport.sent_packets(), vec![b"other-flow".to_vec()]);
        blocked_worker.abort();
        ready_worker.abort();
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_stops_after_blocked_first_send() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (first, queue_rx) =
            reserve_driver_packets(&pool, &stats, client, dst, b"first", &[b"follower"]);
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [
                DriverSendAction::WaitThenOk(Arc::clone(&release)),
                DriverSendAction::Ok,
            ],
        ));
        let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
        let (first_ack_tx, first_ack_rx) = oneshot::channel();
        let worker = tokio::spawn(run_endpoint_driver(
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            first,
            first_ack_tx,
        ));
        transport.wait_for_send_count(1).await;
        endpoint.kill();
        release.notify_waiters();
        first_ack_rx.await.unwrap().unwrap();
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(transport.sent_packets(), vec![b"first".to_vec()]);
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_stops_after_blocked_steady_send() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (first, queue_rx) = reserve_driver_packets(
            &pool,
            &stats,
            client,
            dst,
            b"first",
            &[b"steady", b"follower"],
        );
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [
                DriverSendAction::Ok,
                DriverSendAction::WaitThenOk(Arc::clone(&release)),
                DriverSendAction::Ok,
            ],
        ));
        let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
        let (first_ack_tx, first_ack_rx) = oneshot::channel();
        let worker = tokio::spawn(run_endpoint_driver(
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            client,
            dst,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
            first,
            first_ack_tx,
        ));
        first_ack_rx.await.unwrap().unwrap();
        transport.wait_for_send_count(2).await;
        endpoint.kill();
        release.notify_waiters();
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            transport.sent_packets(),
            vec![b"first".to_vec(), b"steady".to_vec()]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn udp_endpoint_driver_reply_idle_timeout_cleans_up_once() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("idle fixture must initialize"),
        };
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.set_tracker("idle-tracker".to_owned());
        assert!(lease.set_tracker_id("idle-tracker".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::clone(&alive),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(endpoint));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        driver.wait_first_ack().await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(REPLY_IDLE_TIMEOUT).await;
        assert_eq!(
            recv_and_ack(&pool, &mut removed_rx).await,
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("idle-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert!(pool.is_empty());
        let history = alive.get_probe_history(
            TEST_NODE_ID,
            honk_outbound::alive::ProbeDomain::DataUdp,
            honk_outbound::alive::IpVersion::V4,
        );
        assert_eq!(history.len(), 1);
        assert!(!history[0].success);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_endpoint_pool_shutdown_joins_blocked_ready_driver() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let client = make_addr("10.0.0.9", 43000);
        let dst = make_addr("8.8.4.4", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("shutdown fixture must initialize"),
        };
        lease.set_connection_guard(stats.track_connection("shutdown-node"));
        let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
            relay,
            [DriverSendAction::Ok],
            [DriverReceiveAction::Pending],
        ));
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.set_tracker("shutdown-tracker".to_owned());
        assert!(lease.set_tracker_id("shutdown-tracker".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::clone(&alive),
            Arc::clone(&stats),
            "shutdown-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        driver.wait_first_ack().await.unwrap();
        assert_eq!(pool.driver_count(), 1);
        assert_eq!(stats.snapshot()["shutdown-node"].active_conns, 1);

        let ack_pool = Arc::clone(&pool);
        let removal_ack = tokio::spawn(async move {
            let removal = recv_and_ack(&ack_pool, &mut removed_rx).await;
            let closed = removed_rx.recv().await;
            (removal, closed)
        });
        assert!(pool.shutdown().await);
        let (removal, removal_channel_closed) = removal_ack.await.unwrap();

        assert!(pool.is_terminal());
        assert!(pool.is_empty());
        assert_eq!(pool.driver_count(), 0);
        assert!(endpoint.dead.load(Ordering::Acquire));
        assert_eq!(stats.snapshot()["shutdown-node"].active_conns, 0);
        assert!(
            alive
                .get_probe_history(
                    TEST_NODE_ID,
                    honk_outbound::alive::ProbeDomain::DataUdp,
                    honk_outbound::alive::IpVersion::V4,
                )
                .is_empty()
        );
        assert_eq!(
            removal,
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("shutdown-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert_eq!(removal_channel_closed, None);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
        assert!(matches!(
            pool.fast_path_enqueue(client, dst, b"late-fast", &stats),
            Some(EndpointReservation::QueueClosed)
        ));
        let rejected = pool.reserve_or_enqueue(
            client,
            dst,
            b"late",
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            &stats,
        );
        assert!(matches!(rejected, EndpointReservation::QueueClosed));
    }

    #[tokio::test(start_paused = true)]
    async fn udp_endpoint_pool_shutdown_aborts_stuck_initializer_task() {
        let pool = Arc::new(UdpEndpointPool::new());
        let endpoint_capacity = pool.endpoint_slots.available_permits();
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.10", 43001);
        let dst = make_addr("1.1.1.1", 53);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"held", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("stuck initializer fixture must initialize"),
        };
        lease.set_connection_guard(stats.track_connection("stuck-initializer"));
        assert!(lease.set_tracker_id("stuck-tracker".to_owned()));
        assert!(pool.spawn_slow_path(async move {
            std::future::pending::<()>().await;
            drop(lease);
        }));
        tokio::task::yield_now().await;
        assert_eq!(pool.slow_task_count(), 1);
        assert_eq!(stats.snapshot()["stuck-initializer"].active_conns, 1);

        let ack_pool = Arc::clone(&pool);
        let removal_ack = tokio::spawn(async move {
            let removal = recv_and_ack(&ack_pool, &mut removed_rx).await;
            let closed = removed_rx.recv().await;
            (removal, closed)
        });
        assert!(pool.shutdown().await);
        let (removal, removal_channel_closed) = removal_ack.await.unwrap();

        assert_eq!(pool.slow_task_count(), 0);
        assert!(!pool.spawn_slow_path(async {}));
        assert!(pool.is_empty());
        assert_eq!(stats.snapshot()["stuck-initializer"].active_conns, 0);
        assert_eq!(
            removal,
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("stuck-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert_eq!(removal_channel_closed, None);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
        assert_eq!(pool.endpoint_slots.available_permits(), endpoint_capacity);
    }

    #[tokio::test]
    async fn udp_endpoint_driver_receive_and_reply_errors_clean_up() {
        for (client, transport) in [
            (
                make_addr("10.0.0.1", 12345),
                Arc::new(ScriptedPacketTransport::with_receive_actions(
                    make_addr("192.168.1.1", 1080),
                    [DriverSendAction::Ok],
                    [DriverReceiveAction::Error],
                )),
            ),
            (
                make_addr("[::1]", 12345),
                Arc::new(ScriptedPacketTransport::with_receive_actions(
                    make_addr("192.168.1.1", 1080),
                    [DriverSendAction::Ok],
                    [DriverReceiveAction::Packet {
                        data: b"reply".to_vec(),
                        source: make_addr("192.168.1.1", 1080),
                    }],
                )),
            ),
        ] {
            let pool = Arc::new(UdpEndpointPool::new());
            let stats = Arc::new(StatsManager::new());
            let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
            let dst = make_addr("8.8.8.8", 53);
            let relay = make_addr("192.168.1.1", 1080);
            let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
            pool.set_remove_sink(removed_tx);
            let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            let mut lease =
                match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
                    EndpointReservation::Initializing(lease) => lease,
                    _ => panic!("receive-error fixture must initialize"),
                };
            let endpoint = driver_test_endpoint(transport, relay);
            endpoint.record_pending_reply_peer(relay);
            endpoint.set_tracker("receive-tracker".to_owned());
            assert!(lease.set_tracker_id("receive-tracker".to_owned()));
            let queue_rx = lease.take_queue_receiver().unwrap();
            let mut driver = pool.spawn_driver(
                client,
                dst,
                lease.generation(),
                lease.decision_token(),
                Arc::clone(&endpoint),
                queue_rx,
                test_reply_socket().await,
                Arc::clone(&alive),
                Arc::clone(&stats),
                "test-node".to_owned(),
            );
            driver.wait_ready().await.unwrap();
            assert!(lease.commit_ready(endpoint));
            driver.start(lease.take_first().unwrap()).unwrap();
            drop(lease);
            driver.wait_first_ack().await.unwrap();
            assert_eq!(
                recv_and_ack(&pool, &mut removed_rx).await,
                Some(EndpointRemoval {
                    client,
                    dst,
                    decision_token: 0,
                    generation: 1,
                    conn_id: Some("receive-tracker".to_owned()),
                    reason: RemovalReason::UserspaceEndpointRetired,
                })
            );
            assert!(pool.is_empty());
            let history = alive.get_probe_history(
                TEST_NODE_ID,
                honk_outbound::alive::ProbeDomain::DataUdp,
                honk_outbound::alive::IpVersion::V4,
            );
            assert_eq!(history.len(), 1);
            assert!(!history[0].success);
            assert!(matches!(
                removed_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
    }

    #[tokio::test]
    async fn udp_endpoint_receive_failure_cancels_blocked_steady_send_and_releases_permits() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let receive_failure = Arc::new(tokio::sync::Notify::new());
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("blocked-send fixture must initialize"),
        };
        for data in [b"steady".as_slice(), b"queued".as_slice()] {
            let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            assert!(matches!(
                pool.reserve_or_enqueue(client, dst, data, permit, &stats),
                EndpointReservation::Enqueued
            ));
        }
        let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
            relay,
            [DriverSendAction::Ok, DriverSendAction::Pending],
            [DriverReceiveAction::WaitThenError(Arc::clone(
                &receive_failure,
            ))],
        ));
        let endpoint = driver_test_endpoint(Arc::clone(&transport), relay);
        endpoint.set_tracker("blocked-receive-tracker".to_owned());
        assert!(lease.set_tracker_id("blocked-receive-tracker".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(endpoint));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        driver.wait_first_ack().await.unwrap();
        transport.wait_for_send_count(2).await;
        receive_failure.notify_waiters();
        assert_eq!(
            recv_and_ack(&pool, &mut removed_rx).await,
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("blocked-receive-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert!(pool.is_empty());
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_endpoint_worker_failure_removes_tracker_once() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("worker cleanup test must initialize"),
        };
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::Error],
        ));
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.set_tracker("worker-tracker".to_owned());
        assert!(lease.set_tracker_id("worker-tracker".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(endpoint));
        driver.start(lease.take_first().unwrap()).unwrap();
        assert!(driver.wait_first_ack().await.is_err());

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
                .await
                .unwrap(),
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("worker-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        tokio::task::yield_now().await;
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn udp_endpoint_driver_panic_releases_all_resources_exactly_once() {
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"panic", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("panic fixture must initialize"),
        };
        lease.set_connection_guard(stats.track_connection("driver-node"));
        assert!(lease.set_tracker_id("panic-tracker".to_owned()));
        let transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::Panic],
        ));
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.set_tracker("panic-tracker".to_owned());
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "driver-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);

        assert!(driver.wait_first_ack().await.is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
                .await
                .expect("panic cleanup must notify the removal sink"),
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("panic-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert!(pool.is_empty());
        assert_eq!(endpoint.ref_count(), 0, "endpoint.release must run once");
        assert_eq!(pool.endpoint_slots.available_permits(), 1);
        assert_eq!(
            pool.global_payload_bytes.available_permits(),
            GLOBAL_PAYLOAD_CAPACITY
        );
        assert_eq!(
            stats.snapshot().get("driver-node").unwrap().active_conns,
            0,
            "the Ready guard must be dropped by panic cleanup"
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_endpoint_driver_abort_releases_ready_mapping_and_allows_reuse() {
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"abort", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("abort fixture must initialize"),
        };
        lease.set_connection_guard(stats.track_connection("driver-node"));
        assert!(lease.set_tracker_id("abort-tracker".to_owned()));
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let endpoint = driver_test_endpoint(transport, relay);
        endpoint.set_tracker("abort-tracker".to_owned());
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "driver-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        driver.wait_first_ack().await.unwrap();
        drop(lease);

        driver.abort();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), recv_and_ack(&pool, &mut removed_rx))
                .await
                .expect("aborted driver must notify the removal sink"),
            Some(EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("abort-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            })
        );
        assert!(pool.is_empty());
        assert_eq!(endpoint.ref_count(), 0, "endpoint.release must run once");
        assert_eq!(pool.endpoint_slots.available_permits(), 1);
        assert_eq!(
            stats.snapshot().get("driver-node").unwrap().active_conns,
            0,
            "the Ready guard must be dropped by abort cleanup"
        );

        let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement = match pool.reserve_or_enqueue(
            client,
            dst,
            b"replacement",
            replacement_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("abort cleanup must release capacity for a new generation"),
        };
        assert!(replacement.still_initializing());
        assert_eq!(
            pool.len(),
            1,
            "old abort cleanup must not touch replacement"
        );
        drop(replacement);
    }

    #[tokio::test]
    async fn udp_endpoint_worker_old_generation_cannot_remove_replacement() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let release = Arc::new(tokio::sync::Notify::new());
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut old_lease = match pool.reserve_or_enqueue(client, dst, b"old", slow_permit, &stats)
        {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("old worker must initialize"),
        };
        let old_transport = Arc::new(ScriptedPacketTransport::new(
            relay,
            [DriverSendAction::WaitThenError(Arc::clone(&release))],
        ));
        let old_endpoint = driver_test_endpoint(old_transport.clone(), relay);
        old_endpoint.set_tracker("old-tracker".to_owned());
        assert!(old_lease.set_tracker_id("old-tracker".to_owned()));
        let old_queue_rx = old_lease.take_queue_receiver().unwrap();
        let mut old_driver = pool.spawn_driver(
            client,
            dst,
            old_lease.generation(),
            old_lease.decision_token(),
            Arc::clone(&old_endpoint),
            old_queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "test-node".to_owned(),
        );
        old_driver.wait_ready().await.unwrap();
        assert!(old_lease.commit_ready(old_endpoint));
        old_driver.start(old_lease.take_first().unwrap()).unwrap();
        old_transport.wait_for_send_count(1).await;

        pool.remove(client, dst);
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("old-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement =
            pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats);
        assert!(matches!(replacement, EndpointReservation::Initializing(_)));

        release.notify_waiters();
        assert!(old_driver.wait_first_ack().await.is_err());
        tokio::task::yield_now().await;
        assert_eq!(
            pool.len(),
            1,
            "old worker cleanup must not remove replacement"
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        drop(replacement);
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_before_dial_sends_nothing() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("death-before-dial fixture must initialize"),
        };
        let generation = lease.generation();
        assert!(lease.bind_selected_node(DEAD_NODE_ID));
        // Simulate death winning immediately after bind, before dial await.
        pool.remove_by_node(DEAD_NODE_ID);
        assert!(
            !lease.still_initializing(),
            "bound Initializing entry must be generation-safely removed"
        );
        // No tracker was attached yet, so sink sees None conn_id.
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: None,
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        assert!(pool.is_empty());

        let relay = make_addr("192.168.1.1", 1080);
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let endpoint = Arc::new(UdpEndpoint::new(
            transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            DEAD_NODE_ID,
        ));
        assert!(
            !lease.commit_ready(endpoint),
            "commit after death-before-dial must fail"
        );
        drop(lease);
        assert!(transport.sent_packets().is_empty());

        // A newer generation must not be deleted by the old lease Drop.
        let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement =
            match pool.reserve_or_enqueue(client, dst, b"next", replacement_permit, &stats) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("replacement must initialize"),
            };
        assert_ne!(replacement.generation(), generation);
        assert!(replacement.still_initializing());
        drop(replacement);
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_during_dial_sends_nothing() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("death-during-dial fixture must initialize"),
        };
        assert!(lease.bind_selected_node(DEAD_NODE_ID));
        assert!(lease.set_tracker_id("during-dial".to_owned()));
        // Death arrives while dial would be in flight.
        pool.remove_by_node(DEAD_NODE_ID);
        assert!(!lease.still_initializing());
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("during-dial".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );

        let relay = make_addr("192.168.1.1", 1080);
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let endpoint = Arc::new(UdpEndpoint::new(
            transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            DEAD_NODE_ID,
        ));
        // Even if dial "succeeded", commit and start must not send.
        assert!(lease.take_queue_receiver().is_none());
        assert!(!lease.commit_ready(endpoint));
        assert!(lease.take_first().is_some());
        drop(lease);
        assert!(transport.sent_packets().is_empty());
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_before_commit_sends_nothing() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("death-before-commit fixture must initialize"),
        };
        assert!(lease.bind_selected_node(DEAD_NODE_ID));
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let endpoint = Arc::new(UdpEndpoint::new(
            transport.clone() as Arc<dyn honk_outbound::proxy::PacketTransport>,
            relay,
            DEAD_NODE_ID,
        ));
        endpoint.set_tracker("before-commit".to_owned());
        assert!(lease.set_tracker_id("before-commit".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "dead-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();

        // Death wins after driver-ready, before commit_ready.
        pool.remove_by_node(DEAD_NODE_ID);
        assert!(!lease.still_initializing());
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("before-commit".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        assert!(pool.is_empty());
        assert!(
            !lease.commit_ready(endpoint),
            "commit after death-before-commit must fail"
        );
        // Dropping the driver handle closes `start` without delivering the
        // first packet; the task exits with send_count=0.
        drop(driver);
        drop(lease);
        assert!(transport.sent_packets().is_empty());
        tokio::task::yield_now().await;
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn udp_endpoint_node_death_before_driver_start_sends_nothing() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let relay = make_addr("192.168.1.1", 1080);
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let slow_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("node-death fixture must initialize"),
        };
        let transport = Arc::new(ScriptedPacketTransport::new(relay, [DriverSendAction::Ok]));
        let proxy_socket: Arc<dyn honk_outbound::proxy::PacketTransport> = transport.clone();
        let endpoint = Arc::new(UdpEndpoint::new(proxy_socket, relay, DEAD_NODE_ID));
        endpoint.set_tracker("dead-before-start".to_owned());
        assert!(lease.set_tracker_id("dead-before-start".to_owned()));
        let queue_rx = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            test_reply_socket().await,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "dead-node".to_owned(),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(endpoint));

        pool.remove_by_node(DEAD_NODE_ID);
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("dead-before-start".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        assert!(pool.is_empty(), "acknowledged node death must remove Ready");
        let replacement_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let replacement =
            pool.reserve_or_enqueue(client, dst, b"replacement", replacement_permit, &stats);
        assert!(matches!(replacement, EndpointReservation::Initializing(_)));

        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        assert!(
            driver.wait_first_ack().await.is_err(),
            "a start after node death must not reach PacketTransport"
        );
        assert!(transport.sent_packets().is_empty());
        tokio::task::yield_now().await;
        assert_eq!(
            pool.len(),
            1,
            "old driver cleanup must preserve replacement"
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        drop(replacement);
    }

    #[test]
    fn test_remove_by_node() {
        let pool = Arc::new(UdpEndpointPool::new());
        let stats = StatsManager::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let relay = make_addr("192.168.1.1", 1080);
        let dst = make_addr("8.8.8.8", 53);
        commit_ready(
            &pool,
            make_addr("10.0.0.1", 12345),
            dst,
            transport(proxy.clone(), relay),
            relay,
            DEAD_NODE_ID,
        );
        commit_ready(
            &pool,
            make_addr("10.0.0.2", 12345),
            dst,
            transport(proxy.clone(), relay),
            relay,
            OTHER_NODE_ID,
        );
        let init_permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let initializing = match pool.reserve_or_enqueue(
            make_addr("10.0.0.3", 12345),
            dst,
            b"init",
            init_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("unbound initializing fixture"),
        };
        // Unbound Initializing must not be attributed to the dead node yet.
        assert_eq!(pool.len(), 3);
        pool.remove_by_node(DEAD_NODE_ID);
        assert_eq!(pool.len(), 2);
        assert!(pool.get(make_addr("10.0.0.1", 12345), dst).is_none());
        assert!(pool.get(make_addr("10.0.0.2", 12345), dst).is_some());
        assert!(initializing.still_initializing());

        assert!(initializing.bind_selected_node(DEAD_NODE_ID));
        pool.remove_by_node(DEAD_NODE_ID);
        assert!(
            !initializing.still_initializing(),
            "bound Initializing must be removed generation-safely"
        );
        assert_eq!(pool.len(), 1);
        drop(initializing);
    }

    #[tokio::test]
    async fn udp_endpoint_node_and_janitor_cleanup_notify_tracker_once() {
        let pool = Arc::new(UdpEndpointPool::new());
        let (removed_tx, mut removed_rx) = tokio::sync::mpsc::channel(16);
        pool.set_remove_sink(removed_tx);
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = make_addr("192.168.1.1", 1080);
        let dst = make_addr("8.8.8.8", 53);
        let node_client = make_addr("10.0.0.1", 12345);
        let node_endpoint = commit_ready(
            &pool,
            node_client,
            dst,
            transport(proxy.clone(), relay),
            relay,
            DEAD_NODE_ID,
        );
        node_endpoint.set_tracker("node-tracker".to_owned());

        pool.remove_by_node(DEAD_NODE_ID);
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client: node_client,
                dst,
                decision_token: 0,
                generation: 1,
                conn_id: Some("node-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );

        let janitor_client = make_addr("10.0.0.2", 12345);
        let janitor_endpoint = commit_ready(
            &pool,
            janitor_client,
            dst,
            transport(proxy, relay),
            relay,
            JANITOR_NODE_ID,
        );
        janitor_endpoint.set_tracker("janitor-tracker".to_owned());
        janitor_endpoint.release();
        janitor_endpoint
            .expires_at
            .store(monotonic_nanos() - 1, Ordering::Relaxed);

        assert_eq!(pool.janitor_cycle(), 1);
        assert_eq!(
            try_recv_and_ack(&pool, &mut removed_rx).unwrap(),
            EndpointRemoval {
                client: janitor_client,
                dst,
                decision_token: 0,
                generation: 2,
                conn_id: Some("janitor-tracker".to_owned()),
                reason: RemovalReason::UserspaceEndpointRetired,
            }
        );
        assert!(matches!(
            removed_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}
