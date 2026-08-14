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
use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, Semaphore, mpsc, watch};

use super::connection::build_tuples_key;
use super::udp_endpoint::{EndpointReservation, OwnedEnqueueError, UdpEndpointPool, UdpInitLease};
use crate::ebpf::{EbpfBackend, UdpDecisionCommitResult, UdpDecisionTransition};
use crate::stats::StatsManager;

mod cell;
mod ingest;
mod transition;
pub(super) use cell::PendingUdpIdentity;
#[cfg(test)]
use cell::TestVerdict;
use cell::{
    AdmissionGate, CellState, CleanupRequest, DropOutcome, FlowCell, FlowKey, HeldVerdict,
    RetainedState, terminal_cell_is_stale,
};
pub(super) const TERMINAL_GRACE: Duration = Duration::from_millis(500);
pub(super) const WATCHDOG_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const HARD_HOLD_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_SCHEDULED_CLEANUPS: usize = honk_nfqueue::QUEUE_MAXLEN as usize;
const MAX_CORRELATOR_FLOWS: usize = honk_nfqueue::QUEUE_MAXLEN as usize;
const MAX_HELD_VERDICTS_PER_FLOW: usize = 64;
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

pub(super) struct PendingUdpVerdicts {
    cells: DashMap<FlowKey, Arc<FlowCell>>,
    flow_slots: Arc<Semaphore>,
    scheduled_cleanups: Mutex<HashSet<CleanupRequest>>,
    cleanup_drainer: tokio::sync::Mutex<()>,
    admission: AdmissionGate,
    empty: Notify,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    endpoints: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    fatal: mpsc::Sender<PendingUdpFatal>,
}

impl PendingUdpVerdicts {
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        endpoints: Arc<UdpEndpointPool>,
        stats: Arc<StatsManager>,
    ) -> (Self, mpsc::Receiver<PendingUdpFatal>) {
        let (fatal, receiver) = mpsc::channel(1);
        (
            Self {
                cells: DashMap::new(),
                flow_slots: Arc::new(Semaphore::new(MAX_CORRELATOR_FLOWS)),
                scheduled_cleanups: Mutex::new(HashSet::new()),
                cleanup_drainer: tokio::sync::Mutex::new(()),
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

mod watchdog;

#[cfg(test)]
mod tests;
