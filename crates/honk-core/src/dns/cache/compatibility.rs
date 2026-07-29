use super::{CachedEntry, DnsCache, NegativeCacheHit};

impl DnsCache {
    pub fn get(&mut self, key: &str) -> Option<CachedEntry> {
        self.service.get(key)
    }

    pub fn get_stale(&mut self, key: &str) -> Option<CachedEntry> {
        self.service.get_stale(key)
    }

    pub fn put(&mut self, key: String, response: Vec<u8>, min_ttl: u32) {
        self.service.put(key, response, min_ttl);
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_for_test(&mut self, key: String, response: Vec<u8>, ttl: u32) {
        self.service.insert_expired_for_test(key, response, ttl);
    }

    #[cfg(test)]
    pub(crate) fn insert_beyond_stale_retention_for_test(
        &mut self,
        key: String,
        response: Vec<u8>,
        ttl: u32,
    ) {
        self.service
            .insert_beyond_stale_retention_for_test(key, response, ttl);
    }

    pub fn put_negative(&mut self, key: String, ttl: u32, rcode: u8) {
        self.service.put_negative(key, ttl, rcode);
    }

    pub fn negative_rcode(&self, key: &str) -> Option<u8> {
        self.service.negative_rcode(key)
    }

    pub fn negative_hit(&self, key: &str) -> Option<NegativeCacheHit> {
        self.service.negative_hit(key)
    }

    pub fn clear_negative(&mut self, key: &str) {
        self.service.clear_negative(key);
    }

    pub fn purge_expired_negatives(&mut self) {
        self.service.purge_expired_negatives();
    }

    pub fn clear(&mut self) {
        self.service.clear();
    }

    pub fn purge_expired(&mut self) {
        self.service.purge_expired();
    }

    pub fn remove(&mut self, key: &str) -> Option<CachedEntry> {
        self.service.remove(key)
    }

    pub fn len(&self) -> usize {
        self.service.len()
    }

    pub fn is_empty(&self) -> bool {
        self.service.is_empty()
    }

    #[cfg(test)]
    pub(super) fn shard_index(&self, key: &str) -> usize {
        self.service.shard_index(key)
    }

    #[cfg(test)]
    pub(super) fn shard_capacities(&self) -> Vec<usize> {
        self.service.shard_capacities()
    }

    #[cfg(test)]
    pub(crate) fn positive_entries_for_test(&self) -> Vec<CachedEntry> {
        self.service.positive_entries_for_test()
    }
}
