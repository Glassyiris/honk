use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistCounters {
    pub queued: usize,
    pub pending: usize,
    pub dropped_full: u64,
    pub dropped_pending_full: u64,
    pub dropped_closed: u64,
    pub old_epoch_discarded: u64,
    pub written: u64,
    pub restored: u64,
    pub stale: u64,
    pub corrupt: u64,
    pub version_mismatch: u64,
    pub policy_mismatch: u64,
    pub db_errors: u64,
    pub write_attempts: u64,
}

#[derive(Default)]
pub(super) struct CounterSet {
    pub(super) queued: AtomicUsize,
    pub(super) pending: AtomicUsize,
    pub(super) dropped_full: AtomicU64,
    pub(super) dropped_pending_full: AtomicU64,
    pub(super) dropped_closed: AtomicU64,
    pub(super) old_epoch_discarded: AtomicU64,
    pub(super) written: AtomicU64,
    pub(super) restored: AtomicU64,
    pub(super) stale: AtomicU64,
    pub(super) corrupt: AtomicU64,
    pub(super) version_mismatch: AtomicU64,
    pub(super) policy_mismatch: AtomicU64,
    pub(super) db_errors: AtomicU64,
    pub(super) write_attempts: AtomicU64,
}

impl CounterSet {
    pub(super) fn snapshot(&self) -> PersistCounters {
        PersistCounters {
            queued: self.queued.load(Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
            dropped_full: self.dropped_full.load(Ordering::Relaxed),
            dropped_pending_full: self.dropped_pending_full.load(Ordering::Relaxed),
            dropped_closed: self.dropped_closed.load(Ordering::Relaxed),
            old_epoch_discarded: self.old_epoch_discarded.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            restored: self.restored.load(Ordering::Relaxed),
            stale: self.stale.load(Ordering::Relaxed),
            corrupt: self.corrupt.load(Ordering::Relaxed),
            version_mismatch: self.version_mismatch.load(Ordering::Relaxed),
            policy_mismatch: self.policy_mismatch.load(Ordering::Relaxed),
            db_errors: self.db_errors.load(Ordering::Relaxed),
            write_attempts: self.write_attempts.load(Ordering::Relaxed),
        }
    }
}
