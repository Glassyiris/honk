use std::time::Instant;

use super::{CacheSlot, CachedEntry, DnsCacheService, lock};

impl DnsCacheService {
    pub fn clear_negative(&self, key: &str) {
        let key = CacheSlot::Legacy(key.to_owned());
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        let remove_slot = shard.get_mut(&key).is_some_and(|value| {
            value.negative = None;
            value.positive.is_none()
        });
        if remove_slot {
            shard.pop(&key);
        }
    }

    pub fn purge_expired_negatives(&self) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut shard = lock(shard);
            let expired: Vec<CacheSlot> = shard
                .iter()
                .filter(|(_, value)| value.negative.is_some_and(|entry| now >= entry.expires_at))
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                let remove_slot = shard.get_mut(&key).is_some_and(|value| {
                    value.negative = None;
                    value.positive.is_none()
                });
                if remove_slot {
                    shard.pop(&key);
                }
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
            let expired: Vec<CacheSlot> = shard
                .iter()
                .filter(|(_, value)| value.positive.as_ref().is_some_and(CachedEntry::is_expired))
                .map(|(key, _)| key.clone())
                .collect();
            for key in expired {
                let remove_slot = shard.get_mut(&key).is_some_and(|value| {
                    value.positive = None;
                    value.negative.is_none()
                });
                if remove_slot {
                    shard.pop(&key);
                }
            }
        }
        self.purge_expired_negatives();
    }

    pub fn remove(&self, key: &str) -> Option<CachedEntry> {
        let key = CacheSlot::Legacy(key.to_owned());
        let index = self.shard_index(&key);
        lock(&self.shards[index])
            .pop(&key)
            .and_then(|value| value.positive)
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| lock(shard).is_empty())
    }

    pub(super) fn shard_index(&self, key: &CacheSlot) -> usize {
        let hash = match key {
            CacheSlot::Exact(key) => key.shard_hash(),
            CacheSlot::Legacy(key) => {
                let digest = super::key::stable_shard_digest(key);
                u64::from_be_bytes([
                    digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7],
                ])
            }
        };
        usize::try_from(hash % u64::try_from(self.shards.len()).unwrap_or(1)).unwrap_or_default()
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
                    .filter_map(|(_, value)| value.positive.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
