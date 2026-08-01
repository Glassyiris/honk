use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{
    CacheKey, CacheSlot, CacheValue, CachedEntry, DnsCacheService, NegativeCacheHit,
    PublicationEpoch, lock,
};

impl DnsCacheService {
    pub fn get(&self, key: &str) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    pub(crate) fn get_exact(&self, key: &CacheKey) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Exact(key.clone()))
    }

    pub(crate) fn get_stale_exact(&self, key: &CacheKey) -> Option<CachedEntry> {
        self.get_stale_slot(&CacheSlot::Exact(key.clone()))
    }

    fn get_slot(&self, key: &CacheSlot) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let (result, remove) = match shard.get(key) {
            Some(CacheValue::Positive(entry)) if entry.is_stale_retention_exceeded() => {
                (None, true)
            }
            Some(CacheValue::Positive(entry)) if !entry.is_expired() => {
                (Some(entry.clone()), false)
            }
            Some(CacheValue::Positive(_) | CacheValue::Negative { .. }) | None => (None, false),
        };
        if remove {
            shard.pop(key);
        }
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
            tracing::debug!(result = "hit", "DNS cache lookup");
        } else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheMiss);
            tracing::debug!(result = "miss", "DNS cache lookup");
        }
        result
    }

    pub fn get_stale(&self, key: &str) -> Option<CachedEntry> {
        self.get_stale_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    fn get_stale_slot(&self, key: &CacheSlot) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let result = match shard.get(key) {
            Some(CacheValue::Positive(entry))
                if entry.is_expired() && !entry.is_stale_retention_exceeded() =>
            {
                Some(entry.clone())
            }
            Some(CacheValue::Positive(_) | CacheValue::Negative { .. }) | None => None,
        };
        if result.is_some() {
            self.counters.stale.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheStale);
            tracing::debug!(result = "stale", "DNS cache lookup");
        }
        result
    }

    pub fn put(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        self.put_restored(key, response, ttl);
    }

    pub(crate) fn put_exact(&self, key: CacheKey, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        let response = bytes::Bytes::from(response);
        if let Some(persister) = lock(&self.persister).clone() {
            persister.save(
                key.clone(),
                response.clone(),
                crate::dns::persist::unix_now() + u64::from(ttl),
            );
        }
        self.put_slot(CacheSlot::Exact(key), response, ttl);
    }

    pub(crate) fn put_exact_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let registry = lock(&self.refresh_tasks);
        if !registry.accepting_publications || registry.publication_epoch != epoch.0 {
            return;
        }
        self.put_exact(key, response, min_ttl);
    }

    pub(crate) fn put_restored(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        self.put_slot(CacheSlot::Legacy(key), response.into(), min_ttl);
    }

    pub(crate) fn put_restored_exact(&self, key: CacheKey, response: Vec<u8>, min_ttl: u32) {
        self.put_slot(CacheSlot::Exact(key), response.into(), min_ttl);
    }

    fn put_slot(&self, key: CacheSlot, response: bytes::Bytes, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        let entry = CachedEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            min_ttl,
        };
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(key, CacheValue::Positive(entry));
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_for_test(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now() - Duration::from_secs(1),
                min_ttl,
            }),
        );
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_exact_for_test(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Exact(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now() - Duration::from_secs(1),
                min_ttl,
            }),
        );
    }
    #[cfg(test)]
    pub(crate) fn insert_beyond_stale_retention_for_test(
        &self,
        key: String,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Positive(CachedEntry {
                response: response.into(),
                expires_at: Instant::now()
                    - super::storage::STALE_RETENTION
                    - Duration::from_secs(1),
                min_ttl,
            }),
        );
    }

    pub fn put_negative(&self, key: String, ttl: u32, rcode: u8) {
        let ttl = ttl.clamp(1, 300);
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Negative {
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
                rcode,
            },
        );
    }

    pub(crate) fn put_negative_if_current(
        &self,
        epoch: PublicationEpoch,
        key: String,
        ttl: u32,
        rcode: u8,
    ) {
        let registry = lock(&self.refresh_tasks);
        if !registry.accepting_publications || registry.publication_epoch != epoch.0 {
            return;
        }
        self.put_negative(key, ttl, rcode);
    }

    pub fn negative_rcode(&self, key: &str) -> Option<u8> {
        self.negative_hit(key).map(|hit| hit.rcode)
    }

    pub fn negative_hit(&self, key: &str) -> Option<NegativeCacheHit> {
        self.negative_hit_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    fn negative_hit_slot(&self, key: &CacheSlot) -> Option<NegativeCacheHit> {
        let index = self.shard_index(key);
        let now = Instant::now();
        let shard = lock(&self.shards[index]);
        let result = shard.peek(key).and_then(|value| match value {
            CacheValue::Negative { expires_at, rcode } => {
                expires_at.checked_duration_since(now).map(|remaining| {
                    let rounded_secs = remaining
                        .as_secs()
                        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
                    NegativeCacheHit {
                        rcode: *rcode,
                        remaining_ttl: Duration::from_secs(rounded_secs),
                    }
                })
            }
            CacheValue::Positive(_) => None,
        });
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
            tracing::debug!(result = "negative_hit", "DNS cache lookup");
        }
        result
    }
}
