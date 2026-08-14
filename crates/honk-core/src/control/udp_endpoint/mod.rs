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

mod admission;
#[doc(hidden)]
pub mod bench_support;
#[cfg(feature = "ebpf")]
pub(in crate::control) use admission::OwnedEnqueueError;
#[cfg(test)]
use admission::ReservationPublicationHook;
use admission::{EndpointEntry, EndpointKey, FLOW_QUEUE_CAPACITY, GLOBAL_PAYLOAD_CAPACITY};
pub(in crate::control) use admission::{EndpointReservation, QueuedDatagram, UdpInitLease};

const DEFAULT_NAT_TIMEOUT: Duration = Duration::from_secs(30);
const JANITOR_INTERVAL: Duration = Duration::from_secs(5);
/// Hard cap on pooled endpoints. A unique-tuple UDP flood must not be able
/// to grow the pool (and with it sockets, reply tasks and memory) without
/// bound — at the cap new mappings are refused and the datagram is dropped,
/// which UDP tolerates by design.
pub(crate) const MAX_ENDPOINTS: usize = 8192;
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

use driver::{
    DRIVER_ABORT_TIMEOUT, DRIVER_SHUTDOWN_TIMEOUT, TRAFFIC_ALIVE_REPORT_INTERVAL, TaskRegistry,
    join_registered_tasks, monotonic_nanos, nanos_from_dur,
};
#[cfg(test)]
use driver::{
    REPLY_IDLE_TIMEOUT, TRANSPORT_SEND_TIMEOUT, UdpDriverContext, UdpDriverStart,
    run_endpoint_driver,
};

#[cfg(test)]
mod tests;
