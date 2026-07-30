use std::sync::atomic::{AtomicU64, Ordering};

use super::service::DnsCacheService;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheCounters {
    pub hits: u64,
    pub misses: u64,
    pub stale: u64,
}

#[derive(Default)]
pub(super) struct CacheCounterSet {
    pub(super) hits: AtomicU64,
    pub(super) misses: AtomicU64,
    pub(super) stale: AtomicU64,
}

impl CacheCounterSet {
    fn snapshot(&self) -> CacheCounters {
        CacheCounters {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stale: self.stale.load(Ordering::Relaxed),
        }
    }
}

impl DnsCacheService {
    pub fn counters(&self) -> CacheCounters {
        self.counters.snapshot()
    }
}
