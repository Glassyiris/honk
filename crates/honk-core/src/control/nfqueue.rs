//! Token-bound ownership of original UDP skbs held by NFQUEUE.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use honk_ebpf_common::{
    CLASSIFIED_MARK, OutboundIndex, ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED,
    TuplesKey, UdpDecisionState, extract_nfqueue_token, skb_mark_has_reserved_bits,
};
use honk_nfqueue::{QueuedPacket, VerdictGuard};
use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, mpsc, watch};

use super::connection::build_tuples_key;
use super::udp_endpoint::{EndpointReservation, OwnedEnqueueError, UdpEndpointPool, UdpInitLease};
use crate::ebpf::{EbpfBackend, UdpDecisionCommitResult, UdpDecisionTransition};
use crate::stats::StatsManager;

pub(super) const TERMINAL_GRACE: Duration = Duration::from_millis(500);
pub(super) const WATCHDOG_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const HARD_HOLD_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SCHEDULED_CLEANUPS: usize = honk_nfqueue::QUEUE_MAXLEN as usize;
const IPPROTO_UDP: u8 = 17;

const _: () = {
    assert!(honk_nfqueue::NFQUEUE_PENDING_MARK == honk_ebpf_common::NFQUEUE_PENDING_MARK);
    assert!(honk_nfqueue::NFQUEUE_SIGNATURE_MARK == honk_ebpf_common::NFQUEUE_SIGNATURE_MARK);
    assert!(honk_nfqueue::NFQUEUE_TOKEN_MASK == honk_ebpf_common::NFQUEUE_TOKEN_MASK);
};
#[derive(Debug, Clone, thiserror::Error)]
#[error("UDP NFQUEUE {operation} failed: {detail}")]
pub(super) struct PendingUdpFatal {
    operation: &'static str,
    detail: String,
}

impl PendingUdpFatal {
    fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum PendingUdpDecisionError {
    #[error("stale UDP NFQUEUE token or endpoint generation")]
    StaleIdentity,
    #[error("UDP direct rule mark uses a reserved datapath bit")]
    ReservedDirectMark,
    #[error("UDP direct activation is already armed")]
    ArmedInProgress,
    #[error(transparent)]
    Fatal(#[from] PendingUdpFatal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client: SocketAddr,
    destination: SocketAddr,
}

impl FlowKey {
    const fn new(client: SocketAddr, destination: SocketAddr) -> Self {
        Self {
            client,
            destination,
        }
    }

    fn tuples(self) -> TuplesKey {
        build_tuples_key(
            self.destination.ip(),
            self.destination.port(),
            self.client.ip(),
            self.client.port(),
            IPPROTO_UDP,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct PendingUdpIdentity {
    key: FlowKey,
    decision_token: u32,
    endpoint_generation: u64,
}

impl PendingUdpIdentity {
    fn new(key: FlowKey, decision_token: u32, endpoint_generation: u64) -> Self {
        Self {
            key,
            decision_token,
            endpoint_generation,
        }
    }

    pub(super) const fn client(self) -> SocketAddr {
        self.key.client
    }

    pub(super) const fn destination(self) -> SocketAddr {
        self.key.destination
    }

    fn tuples(self) -> TuplesKey {
        self.key.tuples()
    }
}

// The listener consumes this result immediately; keeping the sole lease inline
// avoids a second allocation on every staged UDP flow.
#[allow(clippy::large_enum_variant)]
pub(super) enum NfqueueIngest {
    Initialize {
        lease: UdpInitLease,
        identity: PendingUdpIdentity,
    },
    Queued,
    Dropped,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestVerdict {
    Accept { id: u64, mark: u32 },
    Drop { id: u64 },
}

enum StoredVerdictGuard {
    Kernel(VerdictGuard),
    #[cfg(test)]
    Test {
        id: u64,
        sink: Arc<Mutex<Vec<TestVerdict>>>,
    },
}

impl StoredVerdictGuard {
    fn accept(&mut self, mark: u32) -> Result<(), String> {
        match self {
            Self::Kernel(guard) => guard.accept(mark).map_err(|error| error.to_string()),
            #[cfg(test)]
            Self::Test { id, sink } => {
                sink.lock().push(TestVerdict::Accept { id: *id, mark });
                Ok(())
            }
        }
    }

    fn drop_packet(&mut self) -> Result<(), String> {
        match self {
            Self::Kernel(guard) => guard.drop_packet().map_err(|error| error.to_string()),
            #[cfg(test)]
            Self::Test { id, sink } => {
                sink.lock().push(TestVerdict::Drop { id: *id });
                Ok(())
            }
        }
    }
}

struct HeldVerdict {
    guard: StoredVerdictGuard,
    received_at: Instant,
}

impl HeldVerdict {
    fn kernel(guard: VerdictGuard, received_at: Instant) -> Self {
        Self {
            guard: StoredVerdictGuard::Kernel(guard),
            received_at,
        }
    }

    #[cfg(test)]
    fn test(id: u64, received_at: Instant, sink: Arc<Mutex<Vec<TestVerdict>>>) -> Self {
        Self {
            guard: StoredVerdictGuard::Test { id, sink },
            received_at,
        }
    }
}

enum CellState {
    Pending {
        started_at: Instant,
        armed: bool,
        cancelling: bool,
        verdicts: VecDeque<HeldVerdict>,
    },
    ActiveDirect {
        expires_at: Instant,
        final_mark: u32,
    },
    Proxy {
        expires_at: Instant,
    },
    Block {
        expires_at: Instant,
    },
    Dead {
        expires_at: Instant,
    },
}

impl CellState {
    fn terminal_expiry(&self) -> Option<Instant> {
        match self {
            Self::Pending { .. } => None,
            Self::ActiveDirect { expires_at, .. }
            | Self::Proxy { expires_at }
            | Self::Block { expires_at }
            | Self::Dead { expires_at } => Some(*expires_at),
        }
    }
}

struct FlowCell {
    identity: PendingUdpIdentity,
    state: Mutex<CellState>,
    changed: Notify,
}

impl FlowCell {
    fn pending(identity: PendingUdpIdentity, started_at: Instant, verdict: HeldVerdict) -> Self {
        let mut verdicts = VecDeque::with_capacity(1);
        verdicts.push_back(verdict);
        Self {
            identity,
            state: Mutex::new(CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            }),
            changed: Notify::new(),
        }
    }

    fn terminal(identity: PendingUdpIdentity, state: CellState) -> Self {
        Self {
            identity,
            state: Mutex::new(state),
            changed: Notify::new(),
        }
    }
}

fn terminal_cell_is_stale(cell: &FlowCell, decision_token: u32, now: Instant) -> bool {
    cell.state
        .lock()
        .terminal_expiry()
        .is_some_and(|expiry| expiry <= now || cell.identity.decision_token != decision_token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CleanupRequest {
    Flow(PendingUdpIdentity),
    Token { key: FlowKey, decision_token: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedState {
    Pending,
    ActiveDirect(u32),
    Proxy,
    Block,
    DirectArmed,
    Reject,
}

#[derive(Debug, Clone, Copy)]
enum DropOutcome {
    Proxy,
    Block,
    Cancel,
    Other,
}

#[derive(Debug)]
struct AdmissionState {
    open: bool,
    epoch: u64,
    in_flight: usize,
}

#[derive(Debug)]
struct AdmissionGate {
    state: Mutex<AdmissionState>,
    quiesced: Notify,
}

impl AdmissionGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(AdmissionState {
                open: false,
                epoch: 0,
                in_flight: 0,
            }),
            quiesced: Notify::new(),
        }
    }

    fn open(&self) {
        let mut state = self.state.lock();
        assert_eq!(
            state.in_flight, 0,
            "NFQUEUE admission reopened before quiescence"
        );
        state.open = true;
    }

    fn try_enter(&self) -> Option<AdmissionTicket<'_>> {
        let mut state = self.state.lock();
        if !state.open {
            return None;
        }
        state.in_flight = state
            .in_flight
            .checked_add(1)
            .expect("NFQUEUE admission counter overflow");
        Some(AdmissionTicket {
            gate: self,
            epoch: state.epoch,
        })
    }

    async fn close_and_wait(&self) {
        {
            let mut state = self.state.lock();
            if state.open {
                state.open = false;
                state.epoch = state
                    .epoch
                    .checked_add(1)
                    .expect("NFQUEUE admission epoch overflow");
            }
        }
        loop {
            let notified = self.quiesced.notified();
            if self.state.lock().in_flight == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct AdmissionTicket<'a> {
    gate: &'a AdmissionGate,
    epoch: u64,
}

impl Drop for AdmissionTicket<'_> {
    fn drop(&mut self) {
        let quiesced = {
            let mut state = self.gate.state.lock();
            debug_assert!(state.epoch == self.epoch || !state.open);
            state.in_flight = state
                .in_flight
                .checked_sub(1)
                .expect("NFQUEUE admission ticket underflow");
            state.in_flight == 0
        };
        if quiesced {
            self.gate.quiesced.notify_waiters();
        }
    }
}

pub(super) struct PendingUdpVerdicts {
    cells: DashMap<FlowKey, Arc<FlowCell>>,
    scheduled_cleanups: Mutex<HashSet<CleanupRequest>>,
    admission: AdmissionGate,
    empty: Notify,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    endpoints: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    fatal: mpsc::UnboundedSender<PendingUdpFatal>,
}

impl PendingUdpVerdicts {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        endpoints: Arc<UdpEndpointPool>,
        stats: Arc<StatsManager>,
    ) -> (Self, mpsc::UnboundedReceiver<PendingUdpFatal>) {
        let (fatal, receiver) = mpsc::unbounded_channel();
        (
            Self {
                cells: DashMap::new(),
                scheduled_cleanups: Mutex::new(HashSet::new()),
                admission: AdmissionGate::new(),
                empty: Notify::new(),
                ebpf,
                endpoints,
                stats,
                fatal,
            },
            receiver,
        )
    }

    pub(super) fn identity_for_lease(lease: &UdpInitLease) -> PendingUdpIdentity {
        PendingUdpIdentity::new(
            FlowKey::new(lease.client_addr(), lease.original_dst()),
            lease.decision_token(),
            lease.generation(),
        )
    }

    pub(super) fn open_admission(&self) {
        self.admission.open();
    }

    pub(super) fn is_empty(&self) -> bool {
        self.cells.is_empty() && self.scheduled_cleanups.lock().is_empty()
    }

    pub(super) async fn wait_empty(&self) {
        loop {
            if self.is_empty() {
                return;
            }
            let notified = self.empty.notified();
            if self.is_empty() {
                return;
            }
            notified.await;
        }
    }

    pub(super) async fn ingest_wait(
        &self,
        packet: QueuedPacket,
        guard: VerdictGuard,
        slow_permit: Option<OwnedSemaphorePermit>,
    ) -> NfqueueIngest {
        let backend = self.ebpf.read().await;
        self.ingest_with_backend(packet, guard, slow_permit, backend.as_ref())
    }

    fn ingest_with_backend(
        &self,
        packet: QueuedPacket,
        guard: VerdictGuard,
        slow_permit: Option<OwnedSemaphorePermit>,
        backend: &dyn EbpfBackend,
    ) -> NfqueueIngest {
        self.stats.record_udp_nfqueue_received();
        let received_at = packet.received_at;
        let held = HeldVerdict::kernel(guard, received_at);
        let Some(decision_token) = extract_nfqueue_token(packet.mark) else {
            self.drop_one(held, DropOutcome::Other);
            return NfqueueIngest::Dropped;
        };
        let key = FlowKey::new(packet.tuple.client, packet.tuple.destination);

        let Some(_admission) = self.admission.try_enter() else {
            self.schedule_cleanup_for_key(key, decision_token);
            self.drop_one(held, DropOutcome::Cancel);
            return NfqueueIngest::Dropped;
        };

        loop {
            let Some(entry) = self.cells.try_entry(key) else {
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
                drop(packet.payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            };
            match entry {
                dashmap::mapref::entry::Entry::Occupied(occupied) => {
                    let cell = Arc::clone(occupied.get());
                    let stale = terminal_cell_is_stale(&cell, decision_token, Instant::now());
                    if stale {
                        occupied.remove();
                        self.stats.decrement_udp_nfqueue_active_flows();
                        self.notify_empty_if_needed();
                        continue;
                    }
                    drop(occupied);
                    return self.ingest_existing(
                        cell,
                        decision_token,
                        packet.payload,
                        held,
                        slow_permit,
                    );
                }
                dashmap::mapref::entry::Entry::Vacant(vacant) => {
                    return self.ingest_vacant(
                        vacant,
                        decision_token,
                        packet.payload,
                        held,
                        slow_permit,
                        backend,
                    );
                }
            }
        }
    }

    fn ingest_existing(
        &self,
        cell: Arc<FlowCell>,
        decision_token: u32,
        payload: bytes::Bytes,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
    ) -> NfqueueIngest {
        if cell.identity.decision_token != decision_token {
            self.stats.record_udp_nfqueue_token_mismatch();
            self.schedule_cleanup(CleanupRequest::Token {
                key: cell.identity.key,
                decision_token,
            });
            self.drop_one(held, DropOutcome::Other);
            return NfqueueIngest::Dropped;
        }

        let mut state = cell.state.lock();
        match &mut *state {
            CellState::Pending {
                started_at,
                armed,
                cancelling,
                verdicts,
            } => {
                if *armed {
                    verdicts.push_back(held);
                    drop(state);
                    drop(payload);
                    drop(slow_permit);
                    cell.changed.notify_waiters();
                    return NfqueueIngest::Queued;
                }
                if *cancelling {
                    drop(state);
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                }
                if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                    *cancelling = true;
                    let mut stale = std::mem::take(verdicts);
                    drop(state);
                    self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                    stale.push_back(held);
                    self.drop_many(stale, DropOutcome::Cancel);
                    cell.changed.notify_waiters();
                    return NfqueueIngest::Dropped;
                }
                let Some(slow_permit) = slow_permit else {
                    drop(state);
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                };
                let result = self.endpoints.reserve_owned_or_enqueue(
                    cell.identity.client(),
                    cell.identity.destination(),
                    payload,
                    decision_token,
                    Some(cell.identity.endpoint_generation),
                    slow_permit,
                    &self.stats,
                );
                match result {
                    EndpointReservation::Enqueued => {
                        verdicts.push_back(held);
                        NfqueueIngest::Queued
                    }
                    EndpointReservation::Initializing(_) => {
                        unreachable!("an exact-generation follower cannot create an initializer")
                    }
                    EndpointReservation::IdentityMismatch => {
                        *cancelling = true;
                        drop(state);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        drop(state);
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            CellState::ActiveDirect { final_mark, .. } => {
                let final_mark = *final_mark;
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.accept_one(held, final_mark);
                NfqueueIngest::Queued
            }
            CellState::Proxy { .. } => {
                let Some(slow_permit) = slow_permit else {
                    drop(state);
                    drop(payload);
                    self.drop_one(held, DropOutcome::Other);
                    return NfqueueIngest::Dropped;
                };
                let result = self.endpoints.reserve_owned_or_enqueue(
                    cell.identity.client(),
                    cell.identity.destination(),
                    payload,
                    decision_token,
                    Some(cell.identity.endpoint_generation),
                    slow_permit,
                    &self.stats,
                );
                drop(state);
                match result {
                    EndpointReservation::Enqueued => {
                        self.drop_one(held, DropOutcome::Proxy);
                        NfqueueIngest::Queued
                    }
                    EndpointReservation::IdentityMismatch => {
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::Initializing(_) => {
                        unreachable!("an exact-generation proxy follower cannot initialize")
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            CellState::Block { .. } => {
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Block);
                NfqueueIngest::Queued
            }
            CellState::Dead { .. } => {
                drop(state);
                drop(payload);
                drop(slow_permit);
                self.drop_one(held, DropOutcome::Cancel);
                NfqueueIngest::Dropped
            }
        }
    }

    fn ingest_vacant(
        &self,
        vacant: dashmap::mapref::entry::VacantEntry<'_, FlowKey, Arc<FlowCell>>,
        decision_token: u32,
        payload: bytes::Bytes,
        held: HeldVerdict,
        slow_permit: Option<OwnedSemaphorePermit>,
        backend: &dyn EbpfBackend,
    ) -> NfqueueIngest {
        let key = *vacant.key();
        let retained = match backend.udp_conn_state_lookup(&key.tuples()) {
            Ok(Some(state)) if state.decision_token == decision_token => retained_state(&state),
            Ok(Some(_)) | Ok(None) => {
                drop(vacant);
                self.stats.record_udp_nfqueue_token_mismatch();
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            }
            Err(error) => {
                drop(vacant);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
                self.signal_fatal(PendingUdpFatal::new("state inspection", error.to_string()));
                self.drop_one(held, DropOutcome::Other);
                return NfqueueIngest::Dropped;
            }
        };

        match retained {
            RetainedState::Pending => {
                let Some(slow_permit) = slow_permit else {
                    self.insert_dead_vacant(vacant, key, decision_token);
                    self.schedule_cleanup(CleanupRequest::Token {
                        key,
                        decision_token,
                    });
                    self.drop_one(held, DropOutcome::Cancel);
                    return NfqueueIngest::Dropped;
                };
                match self.endpoints.reserve_owned_or_enqueue(
                    key.client,
                    key.destination,
                    payload,
                    decision_token,
                    None,
                    slow_permit,
                    &self.stats,
                ) {
                    EndpointReservation::Initializing(lease) => {
                        let identity = Self::identity_for_lease(&lease);
                        let cell = Arc::new(FlowCell::pending(identity, held.received_at, held));
                        vacant.insert(cell);
                        self.stats.increment_udp_nfqueue_active_flows();
                        NfqueueIngest::Initialize { lease, identity }
                    }
                    EndpointReservation::IdentityMismatch => {
                        self.insert_dead_vacant(vacant, key, decision_token);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::Enqueued => {
                        self.insert_dead_vacant(vacant, key, decision_token);
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    EndpointReservation::CapacityRejected
                    | EndpointReservation::QueueFull
                    | EndpointReservation::QueueClosed => {
                        self.insert_dead_vacant(vacant, key, decision_token);
                        self.schedule_cleanup(CleanupRequest::Token {
                            key,
                            decision_token,
                        });
                        self.drop_one(held, DropOutcome::Cancel);
                        NfqueueIngest::Dropped
                    }
                }
            }
            RetainedState::ActiveDirect(final_mark) => {
                drop(payload);
                drop(slow_permit);
                let identity = PendingUdpIdentity::new(key, decision_token, 0);
                vacant.insert(Arc::new(FlowCell::terminal(
                    identity,
                    CellState::ActiveDirect {
                        expires_at: Instant::now() + TERMINAL_GRACE,
                        final_mark,
                    },
                )));
                self.stats.increment_udp_nfqueue_active_flows();
                self.accept_one(held, final_mark);
                NfqueueIngest::Queued
            }
            RetainedState::Proxy => {
                drop(slow_permit);
                match self.endpoints.enqueue_owned_by_token(
                    key.client,
                    key.destination,
                    payload,
                    decision_token,
                    &self.stats,
                ) {
                    Ok(generation) => {
                        let identity = PendingUdpIdentity::new(key, decision_token, generation);
                        vacant.insert(Arc::new(FlowCell::terminal(
                            identity,
                            CellState::Proxy {
                                expires_at: Instant::now() + TERMINAL_GRACE,
                            },
                        )));
                        self.stats.increment_udp_nfqueue_active_flows();
                        self.drop_one(held, DropOutcome::Proxy);
                        NfqueueIngest::Queued
                    }
                    Err(OwnedEnqueueError::IdentityMismatch) => {
                        drop(vacant);
                        self.stats.record_udp_nfqueue_token_mismatch();
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                    Err(OwnedEnqueueError::QueueFull | OwnedEnqueueError::QueueClosed) => {
                        drop(vacant);
                        self.drop_one(held, DropOutcome::Other);
                        NfqueueIngest::Dropped
                    }
                }
            }
            RetainedState::Block => {
                drop(payload);
                drop(slow_permit);
                let identity = PendingUdpIdentity::new(key, decision_token, 0);
                vacant.insert(Arc::new(FlowCell::terminal(
                    identity,
                    CellState::Block {
                        expires_at: Instant::now() + TERMINAL_GRACE,
                    },
                )));
                self.stats.increment_udp_nfqueue_active_flows();
                self.drop_one(held, DropOutcome::Block);
                NfqueueIngest::Queued
            }
            RetainedState::DirectArmed => {
                drop(payload);
                drop(slow_permit);
                drop(vacant);
                self.signal_fatal(PendingUdpFatal::new(
                    "armed reconstruction",
                    "DirectArmed state has no live correlator",
                ));
                self.drop_one(held, DropOutcome::Other);
                NfqueueIngest::Dropped
            }
            RetainedState::Reject => {
                drop(payload);
                drop(slow_permit);
                drop(vacant);
                self.stats.record_udp_nfqueue_token_mismatch();
                self.drop_one(held, DropOutcome::Other);
                NfqueueIngest::Dropped
            }
        }
    }

    pub(super) async fn activate_direct(
        &self,
        identity: PendingUdpIdentity,
        lease: &mut UdpInitLease,
        direct_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if skb_mark_has_reserved_bits(direct_rule_mark) {
            return Err(PendingUdpDecisionError::ReservedDirectMark);
        }
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let final_mark = direct_rule_mark | CLASSIFIED_MARK;
        let cell = self.matching_cell(identity)?;

        {
            let mut backend = self.ebpf.write().await;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed, cancelling, ..
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if *armed {
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
            if *cancelling {
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ArmDirect(direct_rule_mark),
                )
                .map_err(|error| self.fatal_error("arm direct", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            *armed = true;
        }
        cell.changed.notify_waiters();

        loop {
            let batch = {
                let mut state = cell.state.lock();
                match &mut *state {
                    CellState::Pending {
                        armed: true,
                        verdicts,
                        ..
                    } => std::mem::take(verdicts),
                    _ => {
                        let fatal = PendingUdpFatal::new(
                            "direct verdict",
                            "armed correlator changed phase before activation",
                        );
                        self.signal_fatal(fatal.clone());
                        return Err(fatal.into());
                    }
                }
            };
            for verdict in batch {
                self.accept_one_fatal(verdict, final_mark)?;
            }

            let mut backend = self.ebpf.write().await;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                verdicts,
                ..
            } = &mut *state
            else {
                let fatal = PendingUdpFatal::new(
                    "activate direct",
                    "armed correlator changed phase before backend activation",
                );
                self.signal_fatal(fatal.clone());
                return Err(fatal.into());
            };
            if !verdicts.is_empty() {
                drop(state);
                drop(backend);
                continue;
            }
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ActivateDirect(direct_rule_mark),
                )
                .map_err(|error| self.fatal_error("activate direct", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                let fatal = PendingUdpFatal::new(
                    "activate direct",
                    format!("backend rejected armed transition: {result:?}"),
                );
                self.signal_fatal(fatal.clone());
                return Err(fatal.into());
            }
            *state = CellState::ActiveDirect {
                expires_at: Instant::now() + TERMINAL_GRACE,
                final_mark,
            };
            break;
        }
        cell.changed.notify_waiters();

        if !lease.commit_kernel_handoff() {
            let fatal = PendingUdpFatal::new(
                "direct endpoint handoff",
                "backend activated after endpoint identity was retired",
            );
            self.signal_fatal(fatal.clone());
            return Err(fatal.into());
        }
        Ok(())
    }

    pub(super) async fn activate_proxy(
        &self,
        identity: PendingUdpIdentity,
        lease: &UdpInitLease,
        final_outbound: u8,
        final_rule_mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        let verdicts = {
            let mut backend = self.ebpf.write().await;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: false,
                cancelling: false,
                verdicts,
                ..
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::ActivateProxy(final_outbound, final_rule_mark),
                )
                .map_err(|error| self.fatal_error("activate proxy", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Proxy {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        for verdict in verdicts {
            self.drop_one_fatal(verdict, DropOutcome::Proxy)?;
        }
        Ok(())
    }

    pub(super) async fn block(
        &self,
        identity: PendingUdpIdentity,
        lease: &mut UdpInitLease,
    ) -> Result<(), PendingUdpDecisionError> {
        if Self::identity_for_lease(lease) != identity {
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        let cell = self.matching_cell(identity)?;
        let verdicts = {
            let mut backend = self.ebpf.write().await;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: false,
                cancelling: false,
                verdicts,
                ..
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            let result = backend
                .commit_udp_decision(
                    &identity.tuples(),
                    identity.decision_token,
                    UdpDecisionTransition::Block,
                )
                .map_err(|error| self.fatal_error("block", error.to_string()))?;
            if result != UdpDecisionCommitResult::Applied {
                self.record_commit_mismatch(result);
                return Err(PendingUdpDecisionError::StaleIdentity);
            }
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Block {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        for verdict in verdicts {
            self.drop_one_fatal(verdict, DropOutcome::Block)?;
        }
        if !lease.commit_kernel_handoff() {
            let fatal = PendingUdpFatal::new(
                "block endpoint handoff",
                "backend blocked after endpoint identity was retired",
            );
            self.signal_fatal(fatal.clone());
            return Err(fatal.into());
        }
        Ok(())
    }

    pub(super) async fn cancel(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<(), PendingUdpDecisionError> {
        let cell = self.matching_cell(identity)?;
        {
            let state = cell.state.lock();
            match &*state {
                CellState::Pending { armed: true, .. } => {
                    drop(state);
                    self.fail_armed(&cell, identity);
                    return Err(PendingUdpDecisionError::ArmedInProgress);
                }
                CellState::Pending { .. } => {}
                _ => return Ok(()),
            }
        }

        let (verdicts, mismatch) = {
            let mut backend = self.ebpf.write().await;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: false,
                verdicts,
                ..
            } = &mut *state
            else {
                let armed = matches!(&*state, CellState::Pending { armed: true, .. });
                drop(state);
                drop(backend);
                if armed {
                    self.fail_armed(&cell, identity);
                    return Err(PendingUdpDecisionError::ArmedInProgress);
                }
                return Ok(());
            };
            let result = backend
                .abort_pending_udp_flow(&identity.tuples(), identity.decision_token)
                .map_err(|error| self.fatal_error("abort pending flow", error.to_string()))?;
            let mismatch = match result {
                UdpDecisionCommitResult::Applied
                | UdpDecisionCommitResult::Missing
                | UdpDecisionCommitResult::Superseded => None,
                UdpDecisionCommitResult::TokenMismatch => {
                    self.stats.record_udp_nfqueue_token_mismatch();
                    Some(UdpDecisionCommitResult::TokenMismatch)
                }
                UdpDecisionCommitResult::StateMismatch => {
                    Some(UdpDecisionCommitResult::StateMismatch)
                }
            };
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            (verdicts, mismatch)
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.client(),
            identity.destination(),
            identity.decision_token,
            identity.endpoint_generation,
        );
        match mismatch {
            Some(UdpDecisionCommitResult::TokenMismatch) => {
                Err(PendingUdpDecisionError::StaleIdentity)
            }
            Some(UdpDecisionCommitResult::StateMismatch) => {
                let fatal = PendingUdpFatal::new(
                    "abort pending flow",
                    "backend left Pending while retaining a non-pending token state",
                );
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
            None => Ok(()),
            Some(
                UdpDecisionCommitResult::Applied
                | UdpDecisionCommitResult::Missing
                | UdpDecisionCommitResult::Superseded,
            ) => unreachable!("successful abort results are not mismatches"),
        }
    }

    fn fail_armed(&self, cell: &Arc<FlowCell>, identity: PendingUdpIdentity) {
        let verdicts = {
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                verdicts,
                ..
            } = &mut *state
            else {
                return;
            };
            let verdicts = std::mem::take(verdicts);
            *state = CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            };
            verdicts
        };
        cell.changed.notify_waiters();
        self.drop_many(verdicts, DropOutcome::Cancel);
        self.endpoints.retire_staged_identity(
            identity.client(),
            identity.destination(),
            identity.decision_token,
            identity.endpoint_generation,
        );
        self.signal_fatal(PendingUdpFatal::new(
            "armed flow cancellation",
            "DirectArmed flow lost its initializer before activation",
        ));
    }

    pub(super) async fn cancel_all(&self) {
        self.admission.close_and_wait().await;
        loop {
            self.drain_scheduled_cleanups().await;
            let mut pending = Vec::new();
            let mut armed = Vec::new();
            let mut terminal = Vec::new();
            for entry in &self.cells {
                let cell = Arc::clone(entry.value());
                match &*cell.state.lock() {
                    CellState::Pending { armed: true, .. } => armed.push(Arc::clone(&cell)),
                    CellState::Pending { armed: false, .. } => pending.push(cell.identity),
                    _ => terminal.push((cell.identity.key, Arc::clone(&cell))),
                }
            }
            for identity in pending {
                let _ = self.cancel(identity).await;
            }
            for (key, cell) in terminal {
                self.remove_cell_now(key, &cell);
            }
            if armed.is_empty() {
                break;
            }
            for cell in armed {
                let notified = cell.changed.notified();
                if matches!(&*cell.state.lock(), CellState::Pending { armed: true, .. }) {
                    tokio::select! {
                        _ = notified => {}
                        _ = tokio::time::sleep(WATCHDOG_INTERVAL) => {
                            self.fail_armed(&cell, cell.identity);
                        }
                    }
                }
            }
        }
        self.drain_scheduled_cleanups().await;
        let leftovers: Vec<_> = self
            .cells
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect();
        for (key, cell) in leftovers {
            self.remove_cell_now(key, &cell);
        }
        self.notify_empty_if_needed();
    }

    pub(super) async fn run_watchdog(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => self.watchdog_tick().await,
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return;
                    }
                }
            }
        }
    }

    async fn watchdog_tick(&self) {
        self.drain_scheduled_cleanups().await;
        let now = Instant::now();
        let mut overdue = Vec::new();
        let mut expired = Vec::new();
        for entry in &self.cells {
            let cell = Arc::clone(entry.value());
            let state = cell.state.lock();
            match &*state {
                CellState::Pending {
                    started_at,
                    armed: false,
                    ..
                } if now.saturating_duration_since(*started_at) >= HARD_HOLD_TIMEOUT => {
                    overdue.push(cell.identity);
                }
                CellState::Pending { .. } => {}
                terminal
                    if terminal
                        .terminal_expiry()
                        .is_some_and(|expiry| expiry <= now) =>
                {
                    expired.push((*entry.key(), Arc::clone(&cell)));
                }
                _ => {}
            }
        }
        for identity in overdue {
            let _ = self.cancel(identity).await;
        }
        for (key, cell) in expired {
            self.remove_if_expired(key, &cell, now);
        }
        self.notify_empty_if_needed();
    }

    async fn drain_scheduled_cleanups(&self) {
        loop {
            let request = {
                let mut requests = self.scheduled_cleanups.lock();
                let request = requests.iter().next().copied();
                if let Some(request) = request {
                    requests.remove(&request);
                }
                request
            };
            let Some(request) = request else {
                self.notify_empty_if_needed();
                return;
            };
            match request {
                CleanupRequest::Flow(identity) => match self.cancel(identity).await {
                    Ok(()) | Err(PendingUdpDecisionError::StaleIdentity) => {}
                    Err(PendingUdpDecisionError::ArmedInProgress) => {
                        self.schedule_cleanup(request);
                        return;
                    }
                    Err(PendingUdpDecisionError::ReservedDirectMark) => unreachable!(),
                    Err(PendingUdpDecisionError::Fatal(_)) => {}
                },
                CleanupRequest::Token {
                    key,
                    decision_token,
                } => {
                    let result = {
                        let mut backend = self.ebpf.write().await;
                        backend.abort_pending_udp_flow(&key.tuples(), decision_token)
                    };
                    match result {
                        Ok(UdpDecisionCommitResult::Applied)
                        | Ok(UdpDecisionCommitResult::Missing) => {}
                        Ok(result) => self.record_commit_mismatch(result),
                        Err(error) => self.signal_fatal(PendingUdpFatal::new(
                            "scheduled abort",
                            error.to_string(),
                        )),
                    }
                }
            }
        }
    }

    fn matching_cell(
        &self,
        identity: PendingUdpIdentity,
    ) -> Result<Arc<FlowCell>, PendingUdpDecisionError> {
        let cell = self
            .cells
            .get(&identity.key)
            .map(|entry| Arc::clone(entry.value()))
            .ok_or(PendingUdpDecisionError::StaleIdentity)?;
        if cell.identity != identity {
            self.stats.record_udp_nfqueue_token_mismatch();
            return Err(PendingUdpDecisionError::StaleIdentity);
        }
        Ok(cell)
    }

    fn insert_dead_vacant(
        &self,
        vacant: dashmap::mapref::entry::VacantEntry<'_, FlowKey, Arc<FlowCell>>,
        key: FlowKey,
        decision_token: u32,
    ) {
        let identity = PendingUdpIdentity::new(key, decision_token, 0);
        vacant.insert(Arc::new(FlowCell::terminal(
            identity,
            CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            },
        )));
        self.stats.increment_udp_nfqueue_active_flows();
    }

    fn remove_if_expired(&self, key: FlowKey, cell: &Arc<FlowCell>, now: Instant) -> bool {
        let dashmap::mapref::entry::Entry::Occupied(occupied) = self.cells.entry(key) else {
            return false;
        };
        if !Arc::ptr_eq(occupied.get(), cell) {
            return false;
        }
        let state = cell.state.lock();
        if !state.terminal_expiry().is_some_and(|expiry| expiry <= now) {
            return false;
        }
        drop(state);
        occupied.remove();
        self.stats.decrement_udp_nfqueue_active_flows();
        self.notify_empty_if_needed();
        true
    }

    fn remove_cell_now(&self, key: FlowKey, cell: &Arc<FlowCell>) -> bool {
        let dashmap::mapref::entry::Entry::Occupied(occupied) = self.cells.entry(key) else {
            return false;
        };
        if !Arc::ptr_eq(occupied.get(), cell) {
            return false;
        }
        occupied.remove();
        self.stats.decrement_udp_nfqueue_active_flows();
        self.notify_empty_if_needed();
        true
    }

    fn schedule_cleanup_for_key(&self, key: FlowKey, decision_token: u32) {
        let Some(entry) = self.cells.try_entry(key) else {
            self.schedule_cleanup(CleanupRequest::Token {
                key,
                decision_token,
            });
            return;
        };
        match entry {
            dashmap::mapref::entry::Entry::Occupied(occupied)
                if occupied.get().identity.decision_token == decision_token =>
            {
                let cell = Arc::clone(occupied.get());
                drop(occupied);
                let Some(mut state) = cell.state.try_lock() else {
                    self.schedule_cleanup(CleanupRequest::Token {
                        key,
                        decision_token,
                    });
                    return;
                };
                let should_schedule = match &mut *state {
                    CellState::Pending { armed: true, .. } => false,
                    CellState::Pending { cancelling, .. } => {
                        *cancelling = true;
                        true
                    }
                    _ => true,
                };
                drop(state);
                if should_schedule {
                    self.schedule_cleanup(CleanupRequest::Flow(cell.identity));
                }
            }
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                drop(occupied);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                drop(vacant);
                self.schedule_cleanup(CleanupRequest::Token {
                    key,
                    decision_token,
                });
            }
        }
    }

    fn schedule_cleanup(&self, request: CleanupRequest) {
        let mut requests = self.scheduled_cleanups.lock();
        if requests.contains(&request) {
            return;
        }
        if requests.len() >= MAX_SCHEDULED_CLEANUPS {
            drop(requests);
            self.signal_fatal(PendingUdpFatal::new(
                "cleanup scheduling",
                "scheduled cleanup set reached NFQUEUE maxlen",
            ));
            return;
        }
        requests.insert(request);
    }

    fn accept_one(&self, verdict: HeldVerdict, mark: u32) {
        let _ = self.accept_one_fatal(verdict, mark);
    }

    fn accept_one_fatal(
        &self,
        mut verdict: HeldVerdict,
        mark: u32,
    ) -> Result<(), PendingUdpDecisionError> {
        match verdict.guard.accept(mark) {
            Ok(()) => {
                self.stats
                    .record_udp_nfqueue_direct_accepted(verdict.received_at.elapsed());
                Ok(())
            }
            Err(error) => {
                self.stats.record_udp_nfqueue_verdict_error();
                let fatal = PendingUdpFatal::new("NF_ACCEPT verdict", error);
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
        }
    }

    fn drop_one(&self, verdict: HeldVerdict, outcome: DropOutcome) {
        let _ = self.drop_one_fatal(verdict, outcome);
    }

    fn drop_one_fatal(
        &self,
        mut verdict: HeldVerdict,
        outcome: DropOutcome,
    ) -> Result<(), PendingUdpDecisionError> {
        match verdict.guard.drop_packet() {
            Ok(()) => {
                let elapsed = verdict.received_at.elapsed();
                match outcome {
                    DropOutcome::Proxy => {
                        self.stats.record_udp_nfqueue_proxy_copied();
                        self.stats.record_udp_nfqueue_proxy_dropped(elapsed);
                    }
                    DropOutcome::Block => self.stats.record_udp_nfqueue_block(elapsed),
                    DropOutcome::Cancel => self.stats.record_udp_nfqueue_cancel(elapsed),
                    DropOutcome::Other => self.stats.record_udp_nfqueue_drop(elapsed),
                }
                Ok(())
            }
            Err(error) => {
                self.stats.record_udp_nfqueue_verdict_error();
                let fatal = PendingUdpFatal::new("NF_DROP verdict", error);
                self.signal_fatal(fatal.clone());
                Err(fatal.into())
            }
        }
    }

    fn drop_many(&self, mut verdicts: VecDeque<HeldVerdict>, outcome: DropOutcome) {
        while let Some(verdict) = verdicts.pop_front() {
            if self.drop_one_fatal(verdict, outcome).is_err() {
                return;
            }
        }
    }

    fn record_commit_mismatch(&self, result: UdpDecisionCommitResult) {
        if matches!(result, UdpDecisionCommitResult::TokenMismatch) {
            self.stats.record_udp_nfqueue_token_mismatch();
        }
    }

    fn fatal_error(&self, operation: &'static str, detail: String) -> PendingUdpDecisionError {
        let fatal = PendingUdpFatal::new(operation, detail);
        self.signal_fatal(fatal.clone());
        fatal.into()
    }

    fn signal_fatal(&self, fatal: PendingUdpFatal) {
        let _ = self.fatal.send(fatal);
    }

    fn notify_empty_if_needed(&self) {
        if self.is_empty() {
            self.empty.notify_waiters();
        }
    }
}

fn retained_state(state: &honk_ebpf_common::ConnState) -> RetainedState {
    match state.state {
        value if value == UdpDecisionState::Pending as u8 => RetainedState::Pending,
        value if value == UdpDecisionState::DirectArmed as u8 => RetainedState::DirectArmed,
        value if value == UdpDecisionState::Proxy as u8 => RetainedState::Proxy,
        value if value == UdpDecisionState::Block as u8 => RetainedState::Block,
        value if value == UdpDecisionState::None as u8 => {
            let raw = unsafe { state.meta.raw };
            let outbound = raw as u8;
            let direct_rule_mark = (raw >> 8) as u32;
            if outbound == OutboundIndex::Direct as u8
                && raw & (ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD)
                    == ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD
                && !skb_mark_has_reserved_bits(direct_rule_mark)
            {
                RetainedState::ActiveDirect(direct_rule_mark | CLASSIFIED_MARK)
            } else {
                RetainedState::Reject
            }
        }
        _ => RetainedState::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::{ConnState, NFQUEUE_PENDING_MARK, RoutingMeta};

    fn identity(token: u32, generation: u64) -> PendingUdpIdentity {
        PendingUdpIdentity::new(
            FlowKey::new(
                "192.0.2.10:40000".parse().unwrap(),
                "198.51.100.20:443".parse().unwrap(),
            ),
            token,
            generation,
        )
    }

    fn retained(token: u32, state: UdpDecisionState, raw: u64) -> ConnState {
        ConnState {
            state: state as u8,
            decision_token: token,
            meta: RoutingMeta { raw },
            ..ConnState::default()
        }
    }

    #[test]
    fn retained_terminal_state_requires_exact_active_direct_encoding() {
        let direct_rule_mark = 0x0000_1200;
        let raw = OutboundIndex::Direct as u64
            | ((direct_rule_mark as u64) << 8)
            | ROUTING_META_FLAG_PUBLISHED
            | ROUTING_META_FLAG_OFFLOAD;
        assert_eq!(
            retained_state(&retained(9, UdpDecisionState::None, raw)),
            RetainedState::ActiveDirect(direct_rule_mark | CLASSIFIED_MARK)
        );
        assert_eq!(
            retained_state(&retained(
                9,
                UdpDecisionState::None,
                raw & !ROUTING_META_FLAG_OFFLOAD,
            )),
            RetainedState::Reject
        );
        assert_eq!(
            retained_state(&retained(
                9,
                UdpDecisionState::None,
                raw | ((NFQUEUE_PENDING_MARK as u64) << 8),
            )),
            RetainedState::Reject
        );
    }

    #[test]
    fn retained_staged_phases_are_not_guessed_from_routing_metadata() {
        assert_eq!(
            retained_state(&retained(7, UdpDecisionState::Pending, u64::MAX)),
            RetainedState::Pending
        );
        assert_eq!(
            retained_state(&retained(7, UdpDecisionState::DirectArmed, 0)),
            RetainedState::DirectArmed
        );
        assert_eq!(
            retained_state(&retained(7, UdpDecisionState::Proxy, 0)),
            RetainedState::Proxy
        );
        assert_eq!(
            retained_state(&retained(7, UdpDecisionState::Block, 0)),
            RetainedState::Block
        );
        assert_eq!(
            retained_state(&retained(7, UdpDecisionState::Preparing, 0)),
            RetainedState::Reject
        );
    }

    #[test]
    fn token_and_generation_both_identify_a_live_cell() {
        let exact = identity(11, 3);
        let cell = FlowCell::terminal(
            exact,
            CellState::Dead {
                expires_at: Instant::now() + TERMINAL_GRACE,
            },
        );
        assert_eq!(cell.identity, exact);
        assert_ne!(cell.identity, identity(12, 3));
        assert_ne!(cell.identity, identity(11, 4));
    }

    #[test]
    fn newer_token_supersedes_only_terminal_cell() {
        let now = Instant::now();
        let terminal = FlowCell::terminal(
            identity(11, 3),
            CellState::Dead {
                expires_at: now + TERMINAL_GRACE,
            },
        );
        assert!(!terminal_cell_is_stale(&terminal, 11, now));
        assert!(terminal_cell_is_stale(&terminal, 12, now));

        let expired = FlowCell::terminal(identity(11, 3), CellState::Dead { expires_at: now });
        assert!(terminal_cell_is_stale(&expired, 11, now));

        let pending = FlowCell {
            identity: identity(11, 3),
            state: Mutex::new(CellState::Pending {
                started_at: now,
                armed: false,
                cancelling: false,
                verdicts: VecDeque::new(),
            }),
            changed: Notify::new(),
        };
        assert!(!terminal_cell_is_stale(&pending, 12, now));
    }

    #[test]
    fn held_guards_preserve_fifo_without_retaining_payloads() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let received_at = Instant::now();
        let mut verdicts = VecDeque::new();
        verdicts.push_back(HeldVerdict::test(1, received_at, Arc::clone(&sink)));
        verdicts.push_back(HeldVerdict::test(2, received_at, Arc::clone(&sink)));
        verdicts.push_back(HeldVerdict::test(3, received_at, Arc::clone(&sink)));
        while let Some(mut verdict) = verdicts.pop_front() {
            verdict.guard.accept(CLASSIFIED_MARK).unwrap();
        }
        assert_eq!(
            *sink.lock(),
            vec![
                TestVerdict::Accept {
                    id: 1,
                    mark: CLASSIFIED_MARK,
                },
                TestVerdict::Accept {
                    id: 2,
                    mark: CLASSIFIED_MARK,
                },
                TestVerdict::Accept {
                    id: 3,
                    mark: CLASSIFIED_MARK,
                },
            ]
        );
    }

    #[tokio::test]
    async fn cancel_token_mismatch_drops_local_guards_and_marks_cell_dead() {
        let identity = identity(11, 3);
        let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
        backend
            .udp_conn_state_store(
                &identity.tuples(),
                &ConnState {
                    state: UdpDecisionState::Pending as u8,
                    decision_token: 12,
                    ..ConnState::default()
                },
            )
            .unwrap();
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(backend)));
        let endpoints = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let (pending, _fatal) = PendingUdpVerdicts::new(backend, endpoints, stats);
        let sink = Arc::new(Mutex::new(Vec::new()));
        let cell = Arc::new(FlowCell::pending(
            identity,
            Instant::now(),
            HeldVerdict::test(1, Instant::now(), Arc::clone(&sink)),
        ));
        pending.cells.insert(identity.key, Arc::clone(&cell));

        assert!(matches!(
            pending.cancel(identity).await,
            Err(PendingUdpDecisionError::StaleIdentity)
        ));
        assert!(matches!(&*cell.state.lock(), CellState::Dead { .. }));
        assert_eq!(*sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
    }

    struct DecisionFixture {
        pending: PendingUdpVerdicts,
        backend: Arc<RwLock<Box<dyn EbpfBackend>>>,
        lease: UdpInitLease,
        identity: PendingUdpIdentity,
        sink: Arc<Mutex<Vec<TestVerdict>>>,
        stats: Arc<StatsManager>,
        fatal: mpsc::UnboundedReceiver<PendingUdpFatal>,
    }

    fn pending_fixture(token: u32) -> DecisionFixture {
        let key = identity(token, 0).key;
        let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
        mock.seed_staged_udp_flow(
            &key.tuples(),
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: token,
                meta: RoutingMeta {
                    raw: ROUTING_META_FLAG_PUBLISHED,
                },
                ..ConnState::default()
            },
        );
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(mock)));
        let endpoints = Arc::new(UdpEndpointPool::new());
        let stats = Arc::new(StatsManager::new());
        let (pending, fatal) = PendingUdpVerdicts::new(
            Arc::clone(&backend),
            Arc::clone(&endpoints),
            Arc::clone(&stats),
        );
        pending.open_admission();
        let lease = match endpoints.reserve_owned_or_enqueue(
            key.client,
            key.destination,
            bytes::Bytes::from_static(b"first"),
            token,
            None,
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("pending fixture must initialize"),
        };
        let identity = PendingUdpVerdicts::identity_for_lease(&lease);
        let sink = Arc::new(Mutex::new(Vec::new()));
        pending.cells.insert(
            key,
            Arc::new(FlowCell::pending(
                identity,
                Instant::now(),
                HeldVerdict::test(1, Instant::now(), Arc::clone(&sink)),
            )),
        );
        stats.increment_udp_nfqueue_active_flows();
        DecisionFixture {
            pending,
            backend,
            lease,
            identity,
            sink,
            stats,
            fatal,
        }
    }

    #[test]
    fn armed_direct_follower_queues_without_slow_or_endpoint_admission() {
        let fixture = pending_fixture(20);
        let cell = Arc::clone(
            fixture
                .pending
                .cells
                .get(&fixture.identity.key)
                .unwrap()
                .value(),
        );
        {
            let mut state = cell.state.lock();
            let CellState::Pending { armed, .. } = &mut *state else {
                panic!("fixture cell must be pending");
            };
            *armed = true;
        }

        let result = fixture.pending.ingest_existing(
            Arc::clone(&cell),
            fixture.identity.decision_token,
            bytes::Bytes::from_static(b"discarded armed payload"),
            HeldVerdict::test(2, Instant::now(), Arc::clone(&fixture.sink)),
            None,
        );

        assert!(matches!(result, NfqueueIngest::Queued));
        assert!(fixture.sink.lock().is_empty());
        let state = cell.state.lock();
        let CellState::Pending { verdicts, .. } = &*state else {
            panic!("armed cell must remain pending until activation");
        };
        assert_eq!(verdicts.len(), 2);
    }

    #[tokio::test]
    async fn direct_arms_accepts_fifo_then_activates_without_copying_payload() {
        let mut fixture = pending_fixture(21);
        {
            let cell = fixture.pending.cells.get(&fixture.identity.key).unwrap();
            let mut state = cell.state.lock();
            let CellState::Pending { verdicts, .. } = &mut *state else {
                panic!("fixture cell must be pending");
            };
            verdicts.push_back(HeldVerdict::test(
                2,
                Instant::now(),
                Arc::clone(&fixture.sink),
            ));
        }

        fixture
            .pending
            .activate_direct(fixture.identity, &mut fixture.lease, 0x1200)
            .await
            .unwrap();

        assert_eq!(
            *fixture.sink.lock(),
            vec![
                TestVerdict::Accept {
                    id: 1,
                    mark: CLASSIFIED_MARK | 0x1200,
                },
                TestVerdict::Accept {
                    id: 2,
                    mark: CLASSIFIED_MARK | 0x1200,
                },
            ]
        );
        let state = fixture
            .backend
            .read()
            .await
            .udp_conn_state_lookup(&fixture.identity.tuples())
            .unwrap()
            .unwrap();
        let raw = unsafe { state.meta.raw };
        assert_eq!(state.state, UdpDecisionState::None as u8);
        assert_eq!(state.decision_token, fixture.identity.decision_token);
        assert_eq!(raw & 0xff, OutboundIndex::Direct as u64);
        assert_eq!(((raw >> 8) & u32::MAX as u64) as u32, 0x1200);
        assert_ne!(raw & ROUTING_META_FLAG_OFFLOAD, 0);
        assert_eq!(fixture.stats.udp_snapshot().nfqueue.direct_accepted, 2);
        assert!(matches!(
            fixture.fatal.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn proxy_commits_before_dropping_original_and_retains_copied_payload() {
        let mut fixture = pending_fixture(22);
        fixture
            .pending
            .activate_proxy(fixture.identity, &fixture.lease, 4, 0x3400)
            .await
            .unwrap();

        assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
        assert_eq!(
            fixture.lease.first_payload(),
            bytes::Bytes::from_static(b"first")
        );
        let state = fixture
            .backend
            .read()
            .await
            .udp_conn_state_lookup(&fixture.identity.tuples())
            .unwrap()
            .unwrap();
        let raw = unsafe { state.meta.raw };
        assert_eq!(state.state, UdpDecisionState::Proxy as u8);
        assert_eq!(state.decision_token, fixture.identity.decision_token);
        assert_eq!(raw & 0xff, 4);
        assert_eq!(((raw >> 8) & u32::MAX as u64) as u32, 0x3400);
        assert_eq!(raw & ROUTING_META_FLAG_OFFLOAD, 0);
        let snapshot = fixture.stats.udp_snapshot();
        assert_eq!(snapshot.nfqueue.proxy_copied, 1);
        assert_eq!(snapshot.nfqueue.proxy_dropped, 1);
        assert!(matches!(
            fixture.fatal.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn block_commits_then_drops_original_and_retires_initializer() {
        let mut fixture = pending_fixture(23);
        fixture
            .pending
            .block(fixture.identity, &mut fixture.lease)
            .await
            .unwrap();

        assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
        let state = fixture
            .backend
            .read()
            .await
            .udp_conn_state_lookup(&fixture.identity.tuples())
            .unwrap()
            .unwrap();
        let raw = unsafe { state.meta.raw };
        assert_eq!(state.state, UdpDecisionState::Block as u8);
        assert_eq!(state.decision_token, fixture.identity.decision_token);
        assert_eq!(raw & 0xff, OutboundIndex::Block as u64);
        assert_eq!(fixture.stats.udp_snapshot().nfqueue.block, 1);
        assert!(matches!(
            fixture.fatal.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn cancel_drops_original_and_removes_exact_pending_state() {
        let mut fixture = pending_fixture(24);
        let cancellation = fixture.lease.wait_cancellation();
        fixture.pending.cancel(fixture.identity).await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), cancellation)
            .await
            .expect("pending cancellation must wake the exact initializer");

        assert_eq!(*fixture.sink.lock(), vec![TestVerdict::Drop { id: 1 }]);
        assert!(
            fixture
                .backend
                .read()
                .await
                .udp_conn_state_lookup(&fixture.identity.tuples())
                .unwrap()
                .is_none()
        );
        assert_eq!(fixture.stats.udp_snapshot().nfqueue.cancel, 1);
        assert!(matches!(
            fixture.fatal.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn close_admission_waits_for_inflight_ingest_publication() {
        let gate = Arc::new(AdmissionGate::new());
        gate.open();
        let in_flight = gate.try_enter().unwrap();
        let closing_gate = Arc::clone(&gate);
        let close = tokio::spawn(async move {
            closing_gate.close_and_wait().await;
        });

        while gate.state.lock().open {
            tokio::task::yield_now().await;
        }
        assert!(!close.is_finished());
        drop(in_flight);
        tokio::time::timeout(Duration::from_secs(1), close)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.try_enter().is_none());
    }

    #[test]
    fn fixed_deadlines_match_the_held_packet_contract() {
        assert_eq!(TERMINAL_GRACE, Duration::from_millis(500));
        assert_eq!(WATCHDOG_INTERVAL, Duration::from_millis(100));
        assert_eq!(HARD_HOLD_TIMEOUT, Duration::from_secs(3));
    }
}
