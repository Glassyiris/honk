use std::hash::{Hash, Hasher};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{CacheValue, CachedEntry, DnsCacheService, NegativeCacheHit, lock};

impl DnsCacheService {
    pub fn get(&self, key: &str) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        if shard.peek(key).is_some_and(|value| {
            matches!(value, CacheValue::Positive(entry) if entry.is_stale_retention_exceeded())
        }) {
            shard.pop(key);
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let result = match shard.get(key) {
            Some(CacheValue::Positive(entry)) if !entry.is_expired() => Some(entry.clone()),
            Some(CacheValue::Positive(_) | CacheValue::Negative { .. }) | None => None,
        };
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    pub fn get_stale(&self, key: &str) -> Option<CachedEntry> {
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
        }
        result
    }

    pub fn put(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        if let Some(persister) = lock(&self.persister).clone()
            && let Some((name, qtype)) = key.rsplit_once(':')
            && let Ok(qtype) = qtype.parse::<u16>()
        {
            persister.save(crate::dns::persist::DnsPersistEntry {
                name: name.to_string(),
                qtype,
                response: response.clone(),
                expire_at_unix: crate::dns::persist::unix_now() + u64::from(ttl),
            });
        }
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
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Positive(CachedEntry {
                response,
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
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Positive(CachedEntry {
                response,
                expires_at: Instant::now() - super::STALE_RETENTION - Duration::from_secs(1),
                min_ttl,
            }),
        );
    }

    pub fn put_negative(&self, key: String, ttl: u32, rcode: u8) {
        let ttl = ttl.clamp(1, 300);
        let index = self.shard_index(&key);
        lock(&self.shards[index]).put(
            key,
            CacheValue::Negative {
                expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
                rcode,
            },
        );
    }

    pub fn negative_rcode(&self, key: &str) -> Option<u8> {
        self.negative_hit(key).map(|hit| hit.rcode)
    }

    pub fn negative_hit(&self, key: &str) -> Option<NegativeCacheHit> {
        let now = Instant::now();
        let index = self.shard_index(key);
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
        }
        result
    }

    pub fn clear_negative(&self, key: &str) {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        if matches!(shard.peek(key), Some(CacheValue::Negative { .. })) {
            shard.pop(key);
        }
    }

    pub fn purge_expired_negatives(&self) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut shard = lock(shard);
            let expired: Vec<String> = shard
                .iter()
                .filter_map(|(key, value)| match value {
                    CacheValue::Negative { expires_at, .. } if now >= *expires_at => {
                        Some(key.clone())
                    }
                    CacheValue::Positive(_) | CacheValue::Negative { .. } => None,
                })
                .collect();
            for key in expired {
                shard.pop(&key);
            }
        }
    }

    pub fn clear(&self) {
        for shard in &self.shards {
            lock(shard).clear();
        }
    }

    pub fn purge_expired(&self) {
        for shard in &self.shards {
            let mut shard = lock(shard);
            let expired: Vec<String> = shard
                .iter()
                .filter_map(|(key, value)| match value {
                    CacheValue::Positive(entry) if entry.is_expired() => Some(key.clone()),
                    CacheValue::Positive(_) | CacheValue::Negative { .. } => None,
                })
                .collect();
            for key in expired {
                shard.pop(&key);
            }
        }
        self.purge_expired_negatives();
    }

    pub fn remove(&self, key: &str) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        match lock(&self.shards[index]).pop(key) {
            Some(CacheValue::Positive(entry)) => Some(entry),
            Some(CacheValue::Negative { .. }) | None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| lock(shard).is_empty())
    }

    pub(super) fn shard_index(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        usize::try_from(hasher.finish() % u64::try_from(self.shards.len()).unwrap_or(1))
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(super) fn shard_capacities(&self) -> Vec<usize> {
        self.shards
            .iter()
            .map(|shard| lock(shard).cap().get())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn positive_entries_for_test(&self) -> Vec<CachedEntry> {
        self.shards
            .iter()
            .flat_map(|shard| {
                lock(shard)
                    .iter()
                    .filter_map(|(_, value)| match value {
                        CacheValue::Positive(entry) => Some(entry.clone()),
                        CacheValue::Negative { .. } => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
