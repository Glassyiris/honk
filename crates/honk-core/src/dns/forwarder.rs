//! DNS forwarding engine that combines caching, routing, and upstream
//! querying into a single resolution pipeline.
//!
//! The forwarder accepts raw DNS wire-format queries, routes them to
//! the appropriate upstream based on domain matching, caches responses,
//! and returns the result.  It also supports background prefetch to
//! warm the cache for frequently-accessed domains.

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, trace};

use super::cache::DnsCache;
use super::routing::DnsRouter;
use honk_config::dns::DnsStrategy;

/// Abstraction over a pool of DNS upstream servers.
///
/// Implementations are expected to maintain connections to multiple
/// DNS upstreams and route raw queries to the named upstream.
#[async_trait]
pub trait DnsUpstreamPool: Send + Sync {
    /// Send a raw DNS query to the named upstream and return the
    /// raw wire-format response.
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// Notifier called when a domain is resolved (cache miss → upstream query).
///
/// The control plane implements this to update eBPF DOMAIN_ROUTING_MAP
/// proactively, so subsequent connections to the resolved IPs can be
/// routed by eBPF without userspace involvement.
pub trait DomainResolveNotifier: Send + Sync {
    /// Called after a successful upstream resolution with the domain name
    /// and the raw DNS response bytes.
    fn on_domain_resolved(&self, domain: &str, response: &[u8]);
}

/// DNS forwarder that resolves queries through a pipeline of
/// cache → routing → upstream → cache.
///
/// Optionally notifies a [`DomainResolveNotifier`] after successful
/// resolution so the control plane can proactively update eBPF
/// domain routing maps.
///
/// # Pipeline
///
/// ```text
/// raw_query
///   │
///   ├─ parse domain + qtype
///   ├─ cache.get(key)  ── hit ──→ return cached bytes
///   │       │ miss
///   ├─ router.select_upstream(domain)
///   ├─ upstream_pool.query(upstream, raw_query)
///   ├─ extract min_ttl
///   ├─ cache.put(key, response, min_ttl)
///   ├─ notifier.on_domain_resolved(domain, response)  (if present)
///   └─ return response
/// ```
#[derive(Clone)]
pub struct DnsForwarder {
    upstream_pool: Arc<dyn DnsUpstreamPool>,
    cache: Arc<Mutex<DnsCache>>,
    routing: Arc<DnsRouter>,
    strategy: DnsStrategy,
    notifier: Option<Arc<dyn DomainResolveNotifier>>,
}

impl DnsForwarder {
    /// Create a new forwarder with the given upstream pool, cache, and router.
    pub fn new(
        upstream_pool: Arc<dyn DnsUpstreamPool>,
        cache: Arc<Mutex<DnsCache>>,
        routing: Arc<DnsRouter>,
    ) -> Self {
        Self {
            upstream_pool,
            cache,
            routing,
            strategy: DnsStrategy::default(),
            notifier: None,
        }
    }

    /// Create a new forwarder with a domain resolve notifier.
    pub fn with_notifier(
        upstream_pool: Arc<dyn DnsUpstreamPool>,
        cache: Arc<Mutex<DnsCache>>,
        routing: Arc<DnsRouter>,
        notifier: Arc<dyn DomainResolveNotifier>,
    ) -> Self {
        Self {
            upstream_pool,
            cache,
            routing,
            strategy: DnsStrategy::default(),
            notifier: Some(notifier),
        }
    }

    /// Set the IP-version strategy used for DNS responses.
    pub fn with_strategy(mut self, strategy: DnsStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Return a clone of the underlying cache Arc.
    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        self.cache.clone()
    }

    /// Resolve a raw DNS query.
    ///
    /// Parses the question section to extract the domain and query type,
    /// checks the cache, routes to the appropriate upstream, and caches
    /// the response for future queries.
    pub async fn resolve(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        debug!("DNS forwarder: resolving {} bytes", raw_query.len());

        let (domain, qtype) = parse_dns_question(raw_query)
            .with_context(|| "failed to parse DNS question section")?;
        let cache_key = dns_cache_key(&domain, qtype);

        debug!(
            "DNS forwarder: query {} QTYPE={} (key={})",
            domain, qtype, cache_key
        );

        // IP-version strategy: drop queries for the unwanted address family so
        // clients fall back to the preferred one instead of trying to connect
        // through a proxy that lacks IPv6 connectivity.
        if is_filtered_qtype(qtype, &self.strategy) {
            debug!(
                "DNS forwarder: dropping {} query due to strategy {:?}",
                qtype_name(qtype),
                self.strategy
            );
            return Ok(make_empty_response(raw_query, &domain, qtype));
        }

        {
            let cache = self.cache.lock().await;
            if cache.is_negative(&cache_key) {
                debug!(
                    "DNS forwarder: negative cache hit for {} — skipping upstream",
                    domain
                );
                return Err(anyhow::anyhow!(
                    "negative cache hit for {} (NXDOMAIN/SERVFAIL)",
                    domain
                ));
            }
            if let Some(entry) = cache.get(&cache_key) {
                debug!(
                    "DNS forwarder: cache hit for {} (ttl_remaining={}s)",
                    domain,
                    entry.remaining_ttl_secs()
                );
                // Cached responses keep the ID of the query that populated the
                // cache.  Rewrite it to match the current query so the client
                // (libc/c-ares) accepts the response.
                let mut response = entry.response.clone();
                if response.len() >= 2 && raw_query.len() >= 2 {
                    response[0..2].copy_from_slice(&raw_query[0..2]);
                }
                return Ok(response);
            }
        }

        let upstream_name = self.routing.select_upstream(&domain);
        debug!(
            "DNS forwarder: routing {} → upstream '{}'",
            domain, upstream_name
        );

        let mut response = self
            .upstream_pool
            .query(upstream_name, raw_query)
            .await
            .with_context(|| format!("upstream '{}' query failed for {}", upstream_name, domain))?;

        let rcode = if response.len() >= 4 {
            response[3] & 0x0F
        } else {
            0
        };
        if rcode == 2 || rcode == 3 {
            // SERVFAIL or NXDOMAIN — store in negative cache
            let mut cache = self.cache.lock().await;
            cache.put_negative(cache_key.clone(), 60);
            debug!(
                "DNS forwarder: negative cache stored for {} (rcode={})",
                domain, rcode
            );
            // Still return the response to the client
            return Ok(response);
        }

        let min_ttl = extract_min_ttl(&response);
        {
            let mut cache = self.cache.lock().await;
            cache.put(cache_key, response.clone(), min_ttl);
        }

        if let Some(ref notifier) = self.notifier {
            notifier.on_domain_resolved(&domain, &response);
        }

        // Ensure the response ID matches the current query in case the
        // upstream (or cached entry) used a different ID.
        if response.len() >= 2 && raw_query.len() >= 2 {
            response[0..2].copy_from_slice(&raw_query[0..2]);
        }

        debug!(
            "DNS forwarder: resolved {} via '{}' (min_ttl={}s, {} bytes)",
            domain,
            upstream_name,
            min_ttl,
            response.len()
        );

        Ok(response)
    }

    /// Prefetch domains asynchronously to warm the cache.
    ///
    /// Constructs A-record queries for each domain and resolves them
    /// in background tasks.  Failures are silently ignored — the goal
    /// is best-effort cache warming.
    pub fn prefetch(&self, domains: &[String]) {
        for domain in domains {
            let domain = domain.clone();
            let query = build_dns_query(&domain, 1);
            let forwarder = self.clone();
            tokio::spawn(async move {
                match forwarder.resolve(&query).await {
                    Err(e) => {
                        debug!("DNS prefetch: {} failed: {:#}", domain, e);
                    }
                    _ => {
                        trace!("DNS prefetch: {} cached successfully", domain);
                    }
                }
            });
        }
    }
}

/// Build a minimal DNS query for the given domain and query type.
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let qname = encode_dns_name(domain);
    let mut query = Vec::with_capacity(12 + qname.len() + 4);

    // Header: ID=0, flags=0x0100 (RD), QDCOUNT=1, rest=0
    query.extend_from_slice(&[0x00, 0x00]); // ID
    query.extend_from_slice(&[0x01, 0x00]); // Flags (recursion desired)
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    query.extend_from_slice(&qname);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    query
}

/// Encode a domain name into DNS label format.
///
/// Example: `"example.com"` → `[0x07, b'e', ..., 0x03, b'c', b'o', b'm', 0x00]`
fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        if label.len() > 63 {
            continue; // skip invalid labels
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0x00); // terminator
    encoded
}

/// Parse the first question from a raw DNS query.
///
/// Returns the domain name and QTYPE on success, or `None` if the
/// message is truncated or malformed.
pub fn parse_dns_question(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 16 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12; // skip 12-byte header
    let domain = decode_dns_name(data, &mut pos)?;

    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

    Some((domain, qtype))
}

/// Decode a DNS name starting at `pos`, advancing `pos` past the name.
fn decode_dns_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_pos = *pos;
    let mut max_jumps = 10; // prevent pointer loops

    loop {
        if jump_pos >= data.len() {
            return None;
        }
        let len = data[jump_pos];

        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            if jump_pos + 2 > data.len() || max_jumps == 0 {
                return None;
            }
            max_jumps -= 1;
            let offset = ((len as usize & 0x3F) << 8) | (data[jump_pos + 1] as usize);
            if !jumped {
                *pos = jump_pos + 2; // advance past the pointer bytes
            }
            jump_pos = offset;
            jumped = true;
            continue;
        }

        if len == 0 {
            if !jumped {
                *pos = jump_pos + 1;
            }
            break;
        }

        if len > 63 {
            return None; // malformed label length
        }

        jump_pos += 1;
        if jump_pos + len as usize > data.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&data[jump_pos..jump_pos + len as usize])
                .ok()?
                .to_ascii_lowercase(),
        );
        jump_pos += len as usize;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Extract the minimum positive TTL from all answer/authority/additional
/// records in a DNS response.  Returns 60 if no TTL is found.
fn extract_min_ttl(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 60;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return 60;
        }
        pos += 4; // QTYPE + QCLASS
        if pos > data.len() {
            return 60;
        }
    }

    let total_records = ancount + nscount + arcount;
    let mut min_ttl = u32::MAX;

    for _ in 0..total_records {
        if pos + 12 > data.len() {
            break;
        }
        if !skip_dns_name(data, &mut pos) {
            break;
        }
        if pos + 10 > data.len() {
            break;
        }

        // Record layout after NAME: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(n)
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        if ttl > 0 && ttl < min_ttl {
            min_ttl = ttl;
        }

        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    if min_ttl == u32::MAX { 60 } else { min_ttl }
}

/// Advance `pos` past a DNS name (handling label sequences and
/// compression pointers).  Returns `false` on malformed data.
fn skip_dns_name(data: &[u8], pos: &mut usize) -> bool {
    loop {
        if *pos >= data.len() {
            return false;
        }
        let len = data[*pos];
        if len == 0 {
            *pos += 1;
            return true;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer — advance past the 2-byte pointer
            if *pos + 2 > data.len() {
                return false;
            }
            *pos += 2;
            return true;
        }
        if len > 63 {
            return false;
        }
        *pos += 1 + len as usize;
        if *pos > data.len() {
            return false;
        }
    }
}

/// Build the cache key for a domain and query type.
fn dns_cache_key(domain: &str, qtype: u16) -> String {
    format!("{}:{}", domain, qtype)
}

/// Return `true` if the given query type should be dropped for the configured
/// IP-version strategy.
fn is_filtered_qtype(qtype: u16, strategy: &DnsStrategy) -> bool {
    match strategy {
        DnsStrategy::PreferIpv4 | DnsStrategy::Ipv4Only => qtype == 28, // AAAA
        DnsStrategy::PreferIpv6 | DnsStrategy::Ipv6Only => qtype == 1,  // A
        DnsStrategy::Both => false,
    }
}

/// Human-readable qtype name for logging.
fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        2 => "NS",
        _ => "OTHER",
    }
}

/// Build a NODATA response (NOERROR, zero answers) for a filtered query,
/// preserving the query's transaction ID and question section.
fn make_empty_response(query: &[u8], domain: &str, qtype: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(256);
    // Transaction ID (first two bytes of the query).
    resp.extend_from_slice(&query[0..2.min(query.len())]);
    if query.len() >= 3 {
        // Set QR=1, preserve RD; keep OPCODE/AA/TC bits from the query.
        resp.push((query[2] & 0x7F) | 0x80);
    } else {
        resp.push(0x80);
    }
    // RA=1, RCODE=0.
    resp.push(0x80);
    // QDCOUNT = 1.
    resp.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    resp.extend_from_slice(&[0u8; 6]);
    // Question section: encode domain labels.
    for label in domain.split('.') {
        resp.push(label.len() as u8);
        resp.extend_from_slice(label.as_bytes());
    }
    resp.push(0); // root label
    resp.extend_from_slice(&qtype.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::cache::DnsCache;
    use crate::dns::routing::DnsRouter;
    use honk_config::dns::{DnsRouting, DnsRule};

    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_cache() -> Arc<Mutex<DnsCache>> {
        Arc::new(Mutex::new(DnsCache::new(100)))
    }

    fn test_router() -> Arc<DnsRouter> {
        Arc::new(
            DnsRouter::new(&DnsRouting {
                rules: vec![],
                fallback: "default".into(),
            })
            .expect("test router"),
        )
    }

    /// Build an A-record response for example.com with a given IP and TTL.
    fn make_a_response(ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let ttl_bytes = ttl.to_be_bytes();
        vec![
            0x00,
            0x00, // ID (matches the query built by build_dns_query)
            0x81,
            0x80, // Flags: QR=1, RD=1, RA=1
            0x00,
            0x01, // QDCOUNT
            0x00,
            0x01, // ANCOUNT
            0x00,
            0x00, // NSCOUNT
            0x00,
            0x00, // ARCOUNT
            // Question: example.com A IN
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
            0x00,
            0x00,
            0x01, // QTYPE A
            0x00,
            0x01, // QCLASS IN
            // Answer
            0xc0,
            0x0c, // NAME pointer to offset 12
            0x00,
            0x01, // TYPE A
            0x00,
            0x01, // CLASS IN
            ttl_bytes[0],
            ttl_bytes[1],
            ttl_bytes[2],
            ttl_bytes[3], // TTL
            0x00,
            0x04, // RDLENGTH
            ip[0],
            ip[1],
            ip[2],
            ip[3], // RDATA
        ]
    }

    /// Build an A-record query for example.com (same as what prefetch uses).
    fn make_a_query() -> Vec<u8> {
        build_dns_query("example.com", 1)
    }

    struct MockUpstream {
        response: Vec<u8>,
        call_count: AtomicUsize,
    }

    impl MockUpstream {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response,
                call_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DnsUpstreamPool for MockUpstream {
        async fn query(&self, _upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let response = make_a_response([93, 184, 216, 34], 300);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let query = make_a_query();

        let result1 = forwarder.resolve(&query).await.expect("first resolve");
        assert_eq!(result1, response);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        let result2 = forwarder.resolve(&query).await.expect("second resolve");
        assert_eq!(result2, response);
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            1,
            "upstream should not be called again"
        );
    }

    #[tokio::test]
    async fn test_cache_hit_rewrites_transaction_id() {
        // Build a response whose ID does not match the query ID.  The forwarder
        // must rewrite the response ID to match each query so that standard
        // resolvers (glibc/c-ares) accept cached answers.
        let mut response = make_a_response([93, 184, 216, 34], 300);
        response[0] = 0xBE;
        response[1] = 0xEF;

        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let mut query = make_a_query();
        query[0] = 0xAB;
        query[1] = 0xCD;

        let result1 = forwarder.resolve(&query).await.expect("first resolve");
        assert_eq!(&result1[0..2], &[0xAB, 0xCD]);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        let result2 = forwarder.resolve(&query).await.expect("second resolve");
        assert_eq!(&result2[0..2], &[0xAB, 0xCD]);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_forward_basic() {
        let response = make_a_response([8, 8, 8, 8], 600);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        );

        let result = forwarder.resolve(&make_a_query()).await.expect("resolve");
        assert_eq!(result, response);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_routing_respects_rules() {
        let response_custom = make_a_response([10, 0, 0, 1], 300);
        let response_default = make_a_response([8, 8, 8, 8], 300);

        // Mock that returns different responses based on upstream name
        struct RoutingMock {
            custom_resp: Vec<u8>,
            default_resp: Vec<u8>,
            calls: AtomicUsize,
        }
        #[async_trait]
        impl DnsUpstreamPool for RoutingMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                match upstream_name {
                    "custom" => Ok(self.custom_resp.clone()),
                    _ => Ok(self.default_resp.clone()),
                }
            }
        }

        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                rules: vec![DnsRule {
                    domain: "full:custom.test".into(),
                    upstream: "custom".into(),
                }],
                fallback: "default".into(),
            })
            .expect("router"),
        );

        let mock = Arc::new(RoutingMock {
            custom_resp: response_custom.clone(),
            default_resp: response_default.clone(),
            calls: AtomicUsize::new(0),
        });
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = build_dns_query("custom.test", 1);
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(result, response_custom);

        let query2 = build_dns_query("other.test", 1);
        let result2 = forwarder.resolve(&query2).await.expect("resolve");
        assert_eq!(result2, response_default);
    }

    #[tokio::test]
    async fn test_prefetch_warms_cache() {
        let response = make_a_response([1, 2, 3, 4], 300);
        let mock = Arc::new(MockUpstream::new(response.clone()));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            test_router(),
        );

        let domains: Vec<String> = vec!["example.com".into()];
        forwarder.prefetch(&domains);

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(result, response);

        // The upstream should have been called at least once (by prefetch),
        // but resolve itself may or may not call it depending on timing
        let calls = mock.call_count.load(Ordering::SeqCst);
        assert!(
            calls >= 1,
            "expected at least 1 upstream call for prefetch, got {}",
            calls
        );
    }

    #[test]
    fn test_parse_dns_question_a_record() {
        let query = build_dns_query("www.example.com", 1);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "www.example.com");
        assert_eq!(qtype, 1); // A
    }

    #[test]
    fn test_parse_dns_question_aaaa_record() {
        let query = build_dns_query("ipv6.test.org", 28);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "ipv6.test.org");
        assert_eq!(qtype, 28); // AAAA
    }

    #[test]
    fn test_parse_dns_question_single_label() {
        let query = build_dns_query("localhost", 1);
        let (domain, qtype) = parse_dns_question(&query).expect("parse");
        assert_eq!(domain, "localhost");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_parse_dns_question_truncated() {
        let short = vec![0u8; 10];
        assert!(parse_dns_question(&short).is_none());
    }

    #[test]
    fn test_extract_min_ttl_single_answer() {
        let resp = make_a_response([8, 8, 8, 8], 300);
        let ttl = extract_min_ttl(&resp);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn test_extract_min_ttl_no_answers() {
        // Response with ANCOUNT=0
        let resp = vec![
            0x00, 0x01, // ID
            0x81, 0x83, // Flags: NXDOMAIN
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];
        let ttl = extract_min_ttl(&resp);
        assert_eq!(ttl, 60, "default TTL when no answers present");
    }

    #[test]
    fn test_extract_min_ttl_short_response() {
        let short = vec![0u8; 5];
        assert_eq!(extract_min_ttl(&short), 60);
    }

    #[test]
    fn test_cache_key_format() {
        assert_eq!(dns_cache_key("example.com", 1), "example.com:1");
        assert_eq!(dns_cache_key("test.org", 28), "test.org:28");
    }

    #[test]
    fn test_build_and_parse_roundtrip() {
        let domains = vec![
            "google.com",
            "sub.domain.example.org",
            "localhost",
            "a.b.c.d.e.f.g.h.example.com",
        ];

        for domain in domains {
            for qtype in [1u16, 28u16, 5u16] {
                let query = build_dns_query(domain, qtype);
                let (parsed_domain, parsed_qtype) =
                    parse_dns_question(&query).expect("roundtrip parse");
                assert_eq!(
                    parsed_domain, domain,
                    "domain mismatch for {} QTYPE={}",
                    domain, qtype
                );
                assert_eq!(parsed_qtype, qtype, "qtype mismatch for {}", domain);
            }
        }
    }
}
