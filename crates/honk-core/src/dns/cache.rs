//! DNS response cache with LRU eviction and TTL-based expiry.
//!
//! Provides a fixed-capacity, thread-safe DNS cache that stores
//! raw DNS response bytes keyed by domain:qtype. Entries are
//! evicted by LRU policy when the cache reaches capacity, and
//! expired entries are transparently skipped on lookup.

use std::sync::Arc;
use std::sync::{Mutex as StdMutex, MutexGuard};

use super::singleflight::Singleflight;

mod compatibility;
mod counters;
mod key;
mod maintenance;
mod service;
mod storage;
mod store;

pub use counters::CacheCounters;
pub(crate) use key::{CacheKey, KeyIdentity, OperationKind};
pub(crate) use service::PublicationEpoch;
pub(crate) use service::{CacheSlot, DnsCacheService};
pub use storage::{CachedEntry, NegativeCacheHit};

use storage::{CacheValue, NegativeEntry};

/// DNS response cache with LRU eviction and TTL-based expiry.
///
/// Internally uses [`lru::LruCache`] for bounded storage
/// with least-recently-used eviction. TTL checking is performed
/// at lookup time; expired entries are not returned by [`DnsCache::get`]
/// but remain available via [`DnsCache::get_stale`] for one hour
/// (serve-stale, RFC 8767) before being dropped.
///
/// Also maintains a negative cache for NXDOMAIN/SERVFAIL responses
/// to avoid repeated upstream queries for known-bad domains.
///
/// When a [`DnsCachePersister`](super::persist::DnsCachePersister) is
/// installed (`cache_file.store_dns`), every positive `put` is mirrored to
/// cache.db by a background writer; with no persister the insert path pays
/// a single branch.
pub struct DnsCache {
    service: Arc<DnsCacheService>,
}

impl DnsCache {
    pub(crate) fn service(&self) -> Arc<DnsCacheService> {
        Arc::clone(&self.service)
    }

    /// Install (or remove) the cache.db persistence sink. Wired by the
    /// control plane when `experimental.cache_file.store_dns` is enabled.
    pub fn set_persister(&mut self, persister: Option<super::persist::DnsCachePersister>) {
        *lock(&self.service.persister) = persister;
    }

    pub fn persistence(&self) -> Option<super::persist::DnsCachePersister> {
        self.service.persistence()
    }

    #[cfg(test)]
    pub(crate) fn singleflight(&self) -> Singleflight {
        self.service.singleflight()
    }

    pub fn counters(&self) -> CacheCounters {
        self.service.counters()
    }

    pub fn flight_counters(&self) -> super::singleflight::FlightCounters {
        self.service.flight_counters()
    }

    pub fn active_flights(&self) -> usize {
        self.service.active_flights()
    }
}

fn lock<T>(mutex: &StdMutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
