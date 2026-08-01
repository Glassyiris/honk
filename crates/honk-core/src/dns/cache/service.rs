use super::CacheKey;

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::counters::CacheCounterSet;
use super::{CacheValue, DnsCache, Singleflight, lock};

static ZERO_CAPACITY_WARNED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicationEpoch(pub(super) u64);

pub struct DnsCacheService {
    pub(super) shards: Vec<Mutex<lru::LruCache<CacheSlot, CacheValue>>>,
    pub(super) flights: Singleflight,
    pub(super) counters: CacheCounterSet,
    pub(super) persister: Mutex<Option<crate::dns::persist::DnsCachePersister>>,
    pub(super) refresh_tasks: Mutex<RefreshTasks>,
    pub(super) active_refresh_tasks: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CacheSlot {
    Exact(CacheKey),
    Legacy(String),
}

pub(super) struct RefreshTasks {
    pub(super) tasks: tokio::task::JoinSet<()>,
    pub(super) closed: bool,
    pub(super) publication_epoch: u64,
    pub(super) accepting_publications: bool,
}

impl DnsCache {
    /// Create a new DNS cache with the given maximum number of entries.
    ///
    /// Capacity is divided exactly across at most 16 shards. Eviction is LRU
    /// within a shard, so one hot shard cannot evict entries in another.
    pub fn new(max_size: usize) -> Self {
        let capacity = max_size.max(1);
        if max_size == 0
            && ZERO_CAPACITY_WARNED
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                requested = max_size,
                effective = capacity,
                "DNS cache capacity clamped"
            );
        }
        let shard_count = capacity.min(16);
        let quotient = capacity / shard_count;
        let remainder = capacity % shard_count;
        let shards = (0..shard_count)
            .map(|index| {
                let shard_capacity = quotient + usize::from(index < remainder);
                Mutex::new(lru::LruCache::new(
                    NonZeroUsize::new(shard_capacity)
                        .unwrap_or_else(|| unreachable!("shard capacity is positive")),
                ))
            })
            .collect();
        Self {
            service: Arc::new(DnsCacheService {
                shards,
                flights: Singleflight::default(),
                counters: CacheCounterSet::default(),
                persister: Mutex::new(None),
                refresh_tasks: Mutex::new(RefreshTasks {
                    tasks: tokio::task::JoinSet::new(),
                    closed: false,
                    publication_epoch: 0,
                    accepting_publications: true,
                }),
                active_refresh_tasks: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }
}

pub(crate) struct PublicationFlushGuard {
    service: Arc<DnsCacheService>,
    persistence: Option<crate::dns::persist::DnsCachePersister>,
}

impl PublicationFlushGuard {
    pub(crate) const fn persistence(&self) -> Option<&crate::dns::persist::DnsCachePersister> {
        self.persistence.as_ref()
    }
}

impl Drop for PublicationFlushGuard {
    fn drop(&mut self) {
        self.service.finish_flush();
    }
}

impl DnsCacheService {
    pub(crate) fn publication_epoch(&self) -> PublicationEpoch {
        PublicationEpoch(lock(&self.refresh_tasks).publication_epoch)
    }

    pub(crate) fn begin_flush(self: &Arc<Self>) -> PublicationFlushGuard {
        let mut registry = lock(&self.refresh_tasks);
        registry.publication_epoch = registry.publication_epoch.saturating_add(1);
        registry.accepting_publications = false;
        self.clear();
        PublicationFlushGuard {
            service: Arc::clone(self),
            persistence: lock(&self.persister).clone(),
        }
    }

    fn finish_flush(&self) {
        let mut registry = lock(&self.refresh_tasks);
        registry.publication_epoch = registry.publication_epoch.saturating_add(1);
        registry.accepting_publications = true;
    }

    pub(crate) fn singleflight(&self) -> super::Singleflight {
        self.flights.clone()
    }

    pub fn flight_counters(&self) -> crate::dns::singleflight::FlightCounters {
        self.flights.counters()
    }

    pub fn active_flights(&self) -> usize {
        self.flights.active_len()
    }

    pub(crate) fn spawn_refresh<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut registry = lock(&self.refresh_tasks);
        while registry.tasks.try_join_next().is_some() {}
        if registry.closed {
            return false;
        }
        self.active_refresh_tasks.fetch_add(1, Ordering::Relaxed);
        let active = Arc::clone(&self.active_refresh_tasks);
        registry.tasks.spawn(async move {
            let _guard = ActiveGuard(active);
            future.await;
        });
        true
    }

    pub fn refresh_task_count(&self) -> usize {
        self.active_refresh_tasks.load(Ordering::Relaxed)
    }

    pub async fn close_refresh_tasks(&self) {
        let mut tasks = {
            let mut registry = lock(&self.refresh_tasks);
            registry.closed = true;
            std::mem::replace(&mut registry.tasks, tokio::task::JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    pub(crate) fn persistence(&self) -> Option<crate::dns::persist::DnsCachePersister> {
        lock(&self.persister).clone()
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
