//! DNS response cache with LRU eviction and TTL-based expiry.
//!
//! Provides a fixed-capacity, thread-safe DNS cache that stores
//! raw DNS response bytes keyed by domain:qtype. Entries are
//! evicted by LRU policy when the cache reaches capacity, and
//! expired entries are transparently skipped on lookup.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

use super::planner::RequestScope;
use super::policy::PolicyId;
use super::query::{IngressProfile, QueryContext};
use super::singleflight::Singleflight;

mod compatibility;
mod service;
mod store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OperationKind {
    Resolve,
    Refresh,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheCounters {
    pub hits: u64,
    pub misses: u64,
    pub stale: u64,
}

#[derive(Default)]
struct CacheCounterSet {
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    wire_identity: Arc<[u8]>,
    ingress: IngressProfile,
    policy_id: Option<PolicyId>,
    scope: RequestScope,
    operation: OperationKind,
}

impl CacheKey {
    pub(crate) fn new(
        query: &QueryContext,
        policy_id: Option<PolicyId>,
        scope: RequestScope,
        operation: OperationKind,
    ) -> Self {
        Self {
            wire_identity: Arc::from(query.canonical_wire()),
            ingress: query.ingress(),
            policy_id,
            scope,
            operation,
        }
    }

    pub(crate) fn storage_key(&self) -> String {
        use std::fmt::Write;

        let mut key = String::with_capacity(self.wire_identity.len() * 2 + 128);
        for byte in self.wire_identity.iter() {
            let _ = write!(key, "{byte:02x}");
        }
        let _ = write!(
            key,
            "|{:?}|{}|{:?}|{:?}",
            self.ingress,
            self.policy_id
                .as_ref()
                .map(PolicyId::digest_hex)
                .unwrap_or_default(),
            self.scope,
            self.operation
        );
        key
    }

    pub(crate) const fn operation(&self) -> OperationKind {
        self.operation
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        wire_identity: Vec<u8>,
        ingress: IngressProfile,
        scope: RequestScope,
        operation: OperationKind,
    ) -> Self {
        Self {
            wire_identity: wire_identity.into(),
            ingress,
            policy_id: None,
            scope,
            operation,
        }
    }
}

/// Extra window past TTL expiry during which an entry stays in the cache
/// for serve-stale fallback (RFC 8767) instead of being dropped on the
/// first post-expiry lookup.
const STALE_RETENTION: Duration = Duration::from_secs(3600);
static ZERO_CAPACITY_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegativeCacheHit {
    pub rcode: u8,
    pub remaining_ttl: Duration,
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
    /// Returns `true` once the entry is too old even for serve-stale use
    /// (past `expires_at + STALE_RETENTION`).
    #[inline]
    pub fn is_stale_retention_exceeded(&self) -> bool {
        Instant::now() >= self.expires_at + STALE_RETENTION
    }
}

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

pub struct DnsCacheService {
    shards: Vec<StdMutex<lru::LruCache<String, CacheValue>>>,
    flights: Singleflight,
    counters: CacheCounterSet,
    persister: StdMutex<Option<super::persist::DnsCachePersister>>,
    refresh_tasks: StdMutex<RefreshTasks>,
    active_refresh_tasks: Arc<AtomicUsize>,
}

struct RefreshTasks {
    tasks: tokio::task::JoinSet<()>,
    closed: bool,
}

enum CacheValue {
    Positive(CachedEntry),
    Negative { expires_at: Instant, rcode: u8 },
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
                StdMutex::new(lru::LruCache::new(
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
                persister: StdMutex::new(None),
                refresh_tasks: StdMutex::new(RefreshTasks {
                    tasks: tokio::task::JoinSet::new(),
                    closed: false,
                }),
                active_refresh_tasks: Arc::new(AtomicUsize::new(0)),
            }),
        }
    }

    pub(crate) fn service(&self) -> Arc<DnsCacheService> {
        Arc::clone(&self.service)
    }

    /// Install (or remove) the cache.db persistence sink. Wired by the
    /// control plane when `experimental.cache_file.store_dns` is enabled.
    pub fn set_persister(&mut self, persister: Option<super::persist::DnsCachePersister>) {
        *lock(&self.service.persister) = persister;
    }

    #[cfg(test)]
    pub(crate) fn singleflight(&self) -> Singleflight {
        self.service.singleflight()
    }

    pub fn counters(&self) -> CacheCounters {
        CacheCounters {
            hits: self.service.counters.hits.load(Ordering::Relaxed),
            misses: self.service.counters.misses.load(Ordering::Relaxed),
            stale: self.service.counters.stale.load(Ordering::Relaxed),
        }
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
        let keys: Vec<String> = (0..100)
            .map(|index| format!("same-shard-{index}:1"))
            .filter(|key| cache.shard_index(key) == 0)
            .take(2)
            .collect();
        let first = keys.first().expect("first key").clone();
        let second = keys.get(1).expect("second key").clone();

        cache.put(first.clone(), r1, 300);
        cache.put(second.clone(), r2, 300);

        assert!(cache.get(&first).is_none());
        assert!(cache.get(&second).is_some());
    }

    #[test]
    fn shard_capacities_sum_exactly_and_clamp_count() {
        for capacity in 1..=33 {
            let cache = DnsCache::new(capacity);
            let capacities = cache.shard_capacities();
            assert_eq!(capacities.len(), capacity.min(16));
            assert_eq!(capacities.iter().sum::<usize>(), capacity);
            assert!(capacities.windows(2).all(|pair| pair[0] >= pair[1]));
            assert!(capacities.windows(2).all(|pair| pair[0] - pair[1] <= 1));
        }
    }

    #[test]
    fn exact_key_separates_wire_profile_policy_scope_and_operation() {
        // Given
        let base_wire = crate::dns::forwarder::build_dns_query("Example.com", 1);
        let base_query = QueryContext::parse(&base_wire).expect("base query");
        let scope = RequestScope::Upstream(
            crate::dns::planner::UpstreamTag::new("default").expect("scope"),
        );
        let base = CacheKey::new(&base_query, None, scope.clone(), OperationKind::Resolve);
        let mut variants = Vec::new();
        for mutate in [
            |wire: &mut Vec<u8>| wire[13] = b'e',
            |wire: &mut Vec<u8>| wire[2] ^= 0x10,
            |wire: &mut Vec<u8>| {
                let end = wire.len();
                wire[end - 1] = 3;
            },
        ] {
            let mut wire = base_wire.clone();
            mutate(&mut wire);
            variants.push(CacheKey::new(
                &QueryContext::parse(&wire).expect("wire variant"),
                None,
                scope.clone(),
                OperationKind::Resolve,
            ));
        }
        let mut edns_wire = base_wire.clone();
        edns_wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        edns_wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        variants.push(CacheKey::new(
            &QueryContext::parse(&edns_wire).expect("edns"),
            None,
            scope.clone(),
            OperationKind::Resolve,
        ));
        variants.push(CacheKey::new(
            &QueryContext::parse_with_profile(&base_wire, IngressProfile::Tcp).expect("profile"),
            None,
            scope.clone(),
            OperationKind::Resolve,
        ));
        variants.push(CacheKey::new(
            &base_query,
            Some(PolicyId::from_config(&Default::default()).expect("policy")),
            scope.clone(),
            OperationKind::Resolve,
        ));
        variants.push(CacheKey::new(
            &base_query,
            None,
            RequestScope::Upstream(
                crate::dns::planner::UpstreamTag::new("other").expect("other scope"),
            ),
            OperationKind::Resolve,
        ));
        variants.push(CacheKey::new(
            &base_query,
            None,
            scope,
            OperationKind::Refresh,
        ));

        // When / Then
        assert!(variants.iter().all(|variant| variant != &base));
        assert!(
            variants
                .iter()
                .all(|variant| variant.storage_key() != base.storage_key())
        );
    }

    #[test]
    fn cache_counters_are_exact_for_hit_miss_and_stale_paths() {
        // Given
        let mut cache = DnsCache::new(8);
        let response = make_test_response([192, 0, 2, 1], 60);

        // When
        assert!(cache.get("missing").is_none());
        cache.put("live".into(), response.clone(), 60);
        assert!(cache.get("live").is_some());
        cache.insert_expired_for_test("stale".into(), response, 60);
        assert!(cache.get("stale").is_none());
        assert!(cache.get_stale("stale").is_some());
        cache.put_negative("negative".into(), 60, 3);
        assert!(cache.negative_hit("negative").is_some());
        cache.insert_beyond_stale_retention_for_test(
            "retention-exceeded".into(),
            make_test_response([192, 0, 2, 2], 60),
            60,
        );
        assert!(cache.get("retention-exceeded").is_none());

        // Then
        assert_eq!(
            cache.counters(),
            CacheCounters {
                hits: 2,
                misses: 3,
                stale: 1,
            }
        );
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
    fn test_serve_stale_window() {
        let mut cache = DnsCache::new(10);
        let resp = make_test_response([93, 184, 216, 34], 0);
        // min_ttl = 0, clamped to 1 second
        cache.put("example.com:1".into(), resp.clone(), 0);
        thread::sleep(Duration::from_secs(2));

        // Expired: normal lookup misses, stale lookup still serves.
        assert!(cache.get("example.com:1").is_none());
        let stale = cache.get_stale("example.com:1").expect("stale entry");
        assert_eq!(stale.response, resp);
        assert!(stale.is_expired());
    }

    #[test]
    fn test_stale_retention_exceeded() {
        let entry = CachedEntry {
            response: vec![],
            expires_at: Instant::now() - Duration::from_secs(7200),
            min_ttl: 1,
        };
        assert!(entry.is_stale_retention_exceeded());
        let fresh = CachedEntry {
            response: vec![],
            expires_at: Instant::now() - Duration::from_secs(10),
            min_ttl: 1,
        };
        assert!(!fresh.is_stale_retention_exceeded());
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
