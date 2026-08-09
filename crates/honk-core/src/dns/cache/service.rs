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

const TARGET_WIRE_BYTES_PER_ENTRY: usize = 4 * 1024;
const MIN_WIRE_BYTES_PER_SHARD: usize = u16::MAX as usize;
const MAX_TOTAL_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub struct DnsCacheService {
    pub(super) shards: Vec<Mutex<CacheShard>>,
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

impl CacheSlot {
    fn wire_bytes(&self) -> usize {
        match self {
            Self::Exact(key) => {
                let scope_bytes = match key.scope() {
                    crate::dns::planner::RequestScope::Upstream(tag) => tag.as_str().len(),
                    crate::dns::planner::RequestScope::AsIs(_) => 0,
                };
                key.wire_identity().len().saturating_add(scope_bytes)
            }
            Self::Legacy(key) => key.len(),
        }
    }
}

pub(super) struct CacheShard {
    entries: lru::LruCache<CacheSlot, CacheValue>,
    wire_bytes: usize,
    wire_byte_capacity: usize,
}

impl CacheShard {
    fn new(entry_capacity: NonZeroUsize, wire_byte_capacity: usize) -> Self {
        Self {
            entries: lru::LruCache::new(entry_capacity),
            wire_bytes: 0,
            wire_byte_capacity,
        }
    }

    fn entry_wire_bytes(key: &CacheSlot, value: &CacheValue) -> usize {
        key.wire_bytes().saturating_add(value.response_bytes())
    }

    pub(super) fn put(&mut self, key: CacheSlot, value: CacheValue) -> bool {
        let retained_key = key.clone();
        self.wire_bytes = self
            .wire_bytes
            .saturating_add(Self::entry_wire_bytes(&key, &value));
        if let Some((removed_key, removed_value)) = self.entries.push(key, value) {
            self.wire_bytes = self
                .wire_bytes
                .saturating_sub(Self::entry_wire_bytes(&removed_key, &removed_value));
        }
        while self.wire_bytes > self.wire_byte_capacity {
            let Some((removed_key, removed_value)) = self.entries.pop_lru() else {
                self.wire_bytes = 0;
                break;
            };
            self.wire_bytes = self
                .wire_bytes
                .saturating_sub(Self::entry_wire_bytes(&removed_key, &removed_value));
        }
        self.entries.contains(&retained_key)
    }

    pub(super) fn pop(&mut self, key: &CacheSlot) -> Option<CacheValue> {
        let (removed_key, removed_value) = self.entries.pop_entry(key)?;
        self.wire_bytes = self
            .wire_bytes
            .saturating_sub(Self::entry_wire_bytes(&removed_key, &removed_value));
        Some(removed_value)
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.wire_bytes = 0;
    }

    pub(super) fn remove_positive(&mut self, key: &CacheSlot) {
        let mut removed_response_bytes = 0;
        let mut remove_slot = false;
        if let Some(value) = self.entries.get_mut(key) {
            if let Some(entry) = value.positive.take() {
                removed_response_bytes = entry.response.len();
            }
            remove_slot = value.negative.is_none();
        }
        self.wire_bytes = self.wire_bytes.saturating_sub(removed_response_bytes);
        if remove_slot && let Some((removed_key, removed_value)) = self.entries.pop_entry(key) {
            self.wire_bytes = self
                .wire_bytes
                .saturating_sub(Self::entry_wire_bytes(&removed_key, &removed_value));
        }
    }
}

impl std::ops::Deref for CacheShard {
    type Target = lru::LruCache<CacheSlot, CacheValue>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl std::ops::DerefMut for CacheShard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
    }
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
        let minimum_total = shard_count.saturating_mul(MIN_WIRE_BYTES_PER_SHARD);
        let wire_byte_capacity = capacity
            .saturating_mul(TARGET_WIRE_BYTES_PER_ENTRY)
            .clamp(minimum_total, MAX_TOTAL_WIRE_BYTES);
        let byte_quotient = wire_byte_capacity / shard_count;
        let byte_remainder = wire_byte_capacity % shard_count;
        let shards = (0..shard_count)
            .map(|index| {
                let shard_capacity = quotient + usize::from(index < remainder);
                let shard_byte_capacity = byte_quotient + usize::from(index < byte_remainder);
                Mutex::new(CacheShard::new(
                    NonZeroUsize::new(shard_capacity)
                        .unwrap_or_else(|| unreachable!("shard capacity is positive")),
                    shard_byte_capacity,
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
