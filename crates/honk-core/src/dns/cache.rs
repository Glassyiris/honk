//! DNS response cache with LRU eviction and TTL-based expiry.
//!
//! Provides a fixed-capacity, thread-safe DNS cache that stores
//! raw DNS response bytes keyed by domain:qtype. Entries are
//! evicted by LRU policy when the cache reaches capacity, and
//! expired entries are transparently skipped on lookup.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// A cached DNS response entry.
///
/// Contains the raw response bytes along with TTL metadata
/// used to determine expiry.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    /// Raw DNS response bytes (full wire-format message).
    pub response: Vec<u8>,
    /// Absolute wall-clock time after which this entry is stale.
    pub expires_at: Instant,
    /// Minimum TTL from the DNS record set, in seconds.
    pub min_ttl: u32,
}

impl CachedEntry {
    /// Returns `true` if the current time is past `expires_at`.
    #[inline]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining TTL in seconds (0 if expired).
    pub fn remaining_ttl_secs(&self) -> u64 {
        self.expires_at
            .checked_duration_since(Instant::now())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// DNS response cache with LRU eviction and TTL-based expiry.
///
/// Internally uses [`lru::LruCache`] for bounded storage
/// with least-recently-used eviction. TTL checking is performed
/// at lookup time; stale entries are not returned but may
/// persist until evicted by newer entries or explicit removal.
///
/// Also maintains a negative cache for NXDOMAIN/SERVFAIL responses
/// to avoid repeated upstream queries for known-bad domains.
///
/// When a [`DnsCachePersister`](super::persist::DnsCachePersister) is
/// installed (`cache_file.store_dns`), every positive `put` is mirrored to
/// cache.db by a background writer; with no persister the insert path pays
/// a single branch.
pub struct DnsCache {
    inner: lru::LruCache<String, CachedEntry>,
    /// Negative cache — maps cache key to expiry time for NXDOMAIN/SERVFAIL.
    negative: lru::LruCache<String, Instant>,
    /// Optional persistence sink for positive answers (store_dns).
    persister: Option<super::persist::DnsCachePersister>,
}

impl DnsCache {
    /// Create a new DNS cache with the given maximum number of entries.
    ///
    /// A `max_size` of 0 is silently clamped to 1.
    pub fn new(max_size: usize) -> Self {
        let cap = NonZeroUsize::new(max_size.max(1)).expect("max_size must be > 0");
        Self {
            inner: lru::LruCache::new(cap),
            negative: lru::LruCache::new(cap),
            persister: None,
        }
    }

    /// Install (or remove) the cache.db persistence sink. Wired by the
    /// control plane when `experimental.cache_file.store_dns` is enabled.
    pub fn set_persister(&mut self, persister: Option<super::persist::DnsCachePersister>) {
        self.persister = persister;
    }

    /// Look up a cached DNS response by key.
    ///
    /// Returns `None` if the key is not present **or** if the entry has
    /// expired. Hot keys are promoted in the LRU so repeated lookups keep
    /// popular domains resident under pressure.
    pub fn get(&mut self, key: &str) -> Option<&CachedEntry> {
        // Promote on hit; drop expired entries so capacity is freed promptly.
        if self.inner.peek(key).is_some_and(|e| e.is_expired()) {
            self.inner.pop(key);
            return None;
        }
        self.inner.get(key).filter(|entry| !entry.is_expired())
    }

    /// Store a DNS response in the cache.
    ///
    /// The entry will expire after `min_ttl` seconds. If the
    /// cache is full the least-recently-used entry is evicted.
    ///
    /// A `min_ttl` of 0 is clamped to 1 second to avoid
    /// immediate expiry.
    ///
    /// When a persister is installed the answer is also queued for
    /// asynchronous cache.db persistence (non-blocking).
    pub fn put(&mut self, key: String, response: Vec<u8>, min_ttl: u32) {
        let ttl = min_ttl.max(1);
        if let Some(ref persister) = self.persister {
            // The key is `{name}:{qtype}` (DNS names never contain ':').
            if let Some((name, qtype)) = key.rsplit_once(':')
                && let Ok(qtype) = qtype.parse::<u16>()
            {
                persister.save(super::persist::DnsPersistEntry {
                    name: name.to_string(),
                    qtype,
                    response: response.clone(),
                    expire_at_unix: super::persist::unix_now() + ttl as u64,
                });
            }
        }
        let entry = CachedEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            min_ttl,
        };
        self.inner.put(key, entry);
    }

    /// Store a negative cache entry (NXDOMAIN/SERVFAIL).
    ///
    /// The entry expires after `ttl` seconds (default: 60s for negative responses).
    pub fn put_negative(&mut self, key: String, ttl: u32) {
        let ttl = ttl.clamp(1, 300);
        self.negative
            .put(key, Instant::now() + Duration::from_secs(ttl as u64));
    }

    /// Check if a key is in the negative cache (known NXDOMAIN/SERVFAIL).
    pub fn is_negative(&self, key: &str) -> bool {
        self.negative
            .peek(key)
            .map(|expires| Instant::now() < *expires)
            .unwrap_or(false)
    }

    /// Remove a negative cache entry.
    pub fn clear_negative(&mut self, key: &str) {
        self.negative.pop(key);
    }

    /// Remove all expired negative cache entries.
    pub fn purge_expired_negatives(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .negative
            .iter()
            .filter(|(_, expires)| now >= **expires)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.negative.pop(&k);
        }
    }

    /// Remove all entries from both caches.
    pub fn clear(&mut self) {
        self.inner.clear();
        self.negative.clear();
    }

    /// Remove all entries that have expired (both positive and negative).
    pub fn purge_expired(&mut self) {
        // Positive cache
        let expired: Vec<String> = self
            .inner
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.inner.pop(&key);
        }
        // Negative cache
        self.purge_expired_negatives();
    }

    /// Remove an entry from the cache.
    ///
    /// Returns the removed [`CachedEntry`] if it was present and
    /// not already evicted.
    pub fn remove(&mut self, key: &str) -> Option<CachedEntry> {
        self.inner.pop(key)
    }

    /// Return the current number of entries (including stale ones).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    /// Build a small test DNS response for `example.com` A record.
    fn make_test_response(ip_octets: [u8; 4], ttl: u32) -> Vec<u8> {
        let ttl_bytes = ttl.to_be_bytes();
        // Pointer to qname at offset 12 (0xc0 0x0c)
        vec![
            // --- Header (12 bytes) ---
            0x00,
            0x01, // ID
            0x81,
            0x80, // Flags: standard response
            0x00,
            0x01, // QDCOUNT
            0x00,
            0x01, // ANCOUNT
            0x00,
            0x00, // NSCOUNT
            0x00,
            0x00, // ARCOUNT
            // --- Question: "example.com" A IN ---
            0x07,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            0x03,
            b'c',
            b'o',
            b'm',
            0x00, // terminator
            0x00,
            0x01, // QTYPE = A
            0x00,
            0x01, // QCLASS = IN
            // --- Answer ---
            0xc0,
            0x0c, // NAME (pointer to offset 12)
            0x00,
            0x01, // TYPE = A
            0x00,
            0x01, // CLASS = IN
            ttl_bytes[0],
            ttl_bytes[1],
            ttl_bytes[2],
            ttl_bytes[3], // TTL
            0x00,
            0x04, // RDLENGTH
            ip_octets[0],
            ip_octets[1],
            ip_octets[2],
            ip_octets[3], // RDATA
        ]
    }

    #[test]
    fn test_put_get() {
        let mut cache = DnsCache::new(10);
        let resp = make_test_response([93, 184, 216, 34], 300);
        cache.put("example.com:1".into(), resp.clone(), 300);

        let entry = cache.get("example.com:1").expect("entry should exist");
        assert_eq!(entry.response, resp);
        assert_eq!(entry.min_ttl, 300);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_expiry() {
        let mut cache = DnsCache::new(10);
        let resp = make_test_response([93, 184, 216, 34], 0);
        // min_ttl = 0, clamped to 1 second
        cache.put("example.com:1".into(), resp, 0);

        assert!(cache.get("example.com:1").is_some());

        thread::sleep(Duration::from_secs(2));
        assert!(
            cache.get("example.com:1").is_none(),
            "entry should have expired after 2 seconds"
        );
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = DnsCache::new(2);
        let r1 = make_test_response([1, 1, 1, 1], 300);
        let r2 = make_test_response([2, 2, 2, 2], 300);
        let r3 = make_test_response([3, 3, 3, 3], 300);

        cache.put("a.com:1".into(), r1.clone(), 300);
        cache.put("b.com:1".into(), r2.clone(), 300);

        assert!(cache.get("a.com:1").is_some());
        assert!(cache.get("b.com:1").is_some());

        cache.put("c.com:1".into(), r3.clone(), 300);

        assert!(
            cache.get("a.com:1").is_none(),
            "a.com should have been evicted"
        );
        assert!(cache.get("b.com:1").is_some());
        assert!(cache.get("c.com:1").is_some());
    }

    #[test]
    fn test_remove_entry() {
        let mut cache = DnsCache::new(10);
        let resp = make_test_response([8, 8, 8, 8], 300);
        cache.put("dns.google:1".into(), resp, 300);

        assert!(cache.get("dns.google:1").is_some());

        let removed = cache.remove("dns.google:1");
        assert!(removed.is_some());
        assert!(cache.get("dns.google:1").is_none());
    }

    #[test]
    fn test_clear() {
        let mut cache = DnsCache::new(10);
        cache.put("a.com:1".into(), make_test_response([1, 1, 1, 1], 300), 300);
        cache.put("b.com:1".into(), make_test_response([2, 2, 2, 2], 300), 300);
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_purge_expired() {
        let mut cache = DnsCache::new(10);
        cache.put(
            "stale.com:1".into(),
            make_test_response([1, 1, 1, 1], 0),
            0, // 1-second TTL after clamp
        );
        cache.put(
            "fresh.com:1".into(),
            make_test_response([2, 2, 2, 2], 3600),
            3600,
        );
        assert_eq!(cache.len(), 2);

        thread::sleep(Duration::from_secs(2));
        cache.purge_expired();

        assert_eq!(cache.len(), 1);
        assert!(cache.get("fresh.com:1").is_some());
        assert!(cache.get("stale.com:1").is_none());
    }

    #[test]
    fn test_zero_max_size_clamped() {
        let mut cache = DnsCache::new(0);
        let resp = make_test_response([8, 8, 8, 8], 300);
        cache.put("dns.com:1".into(), resp, 300);
        // Clamped to 1 — entry is present
        assert!(cache.get("dns.com:1").is_some());
    }

    #[test]
    fn test_remaining_ttl() {
        let entry = CachedEntry {
            response: vec![],
            expires_at: Instant::now() + Duration::from_secs(45),
            min_ttl: 45,
        };
        let remaining = entry.remaining_ttl_secs();
        // Should be approx 45 (allow 1-second tolerance)
        assert!(
            (44..=46).contains(&remaining),
            "expected ~45, got {}",
            remaining
        );
    }
}
