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
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed,
                cancelling,
                ..
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
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

            let mut backend = self.armed_backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                armed: true,
                started_at,
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
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                self.fail_armed(&cell, identity);
                return Err(PendingUdpDecisionError::ArmedInProgress);
            }
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
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
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
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
                armed: false,
                cancelling: false,
                verdicts,
            } = &mut *state
            else {
                return Err(PendingUdpDecisionError::StaleIdentity);
            };
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
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
            let mut backend = self.backend_before_deadline(&cell, identity).await?;
            let mut state = cell.state.lock();
            let CellState::Pending {
                started_at,
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
            if started_at.elapsed() >= HARD_HOLD_TIMEOUT {
                drop(state);
                drop(backend);
                return Err(self.expire_unarmed_pending(&cell, identity));
            }
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
