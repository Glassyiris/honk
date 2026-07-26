//! DNS forwarding engine that combines caching, routing, and upstream
//! querying into a single resolution pipeline.
//!
//! The forwarder accepts raw DNS wire-format queries, routes them to
//! the appropriate upstream based on domain matching, caches responses,
//! and returns the result.  It also supports background prefetch to
//! warm the cache for frequently-accessed domains.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use super::cache::DnsCache;
use super::routing::{DnsRequestDecision, DnsResponseDecision, DnsRouter};
use honk_config::dns::DnsStrategy;
use honk_ebpf_common::DAE_BYPASS_MARK;

/// dae response-routing re-query depth cap (`MaxDnsLookupDepth`).
const MAX_DNS_LOOKUP_DEPTH: usize = 3;

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
///   ├─ strategy filter (empty A/AAAA)
///   ├─ request routing (reject / asis / upstream)  — before cache (dae order)
///   ├─ cache.get(key)  ── hit ──→ return cached bytes
///   │       │ miss
///   ├─ upstream_pool.query / asis dial
///   ├─ response routing loop (accept / reject / requery, depth ≤ 3)
///   ├─ fixed_domain_ttl / optimistic_cache_ttl
///   ├─ cache.put
///   ├─ notifier.on_domain_resolved
///   └─ return response
/// ```
#[derive(Clone)]
pub struct DnsForwarder {
    upstream_pool: Arc<dyn DnsUpstreamPool>,
    cache: Arc<Mutex<DnsCache>>,
    routing: Arc<DnsRouter>,
    strategy: DnsStrategy,
    /// When false, skip positive/negative cache lookups and inserts
    /// (`dns.optimistic_cache` / `cache.enabled`).
    cache_enabled: bool,
    /// Fixed positive-cache TTL in seconds (`dns.optimistic_cache_ttl` /
    /// `cache.ttl`). Overrides answer-section min TTL when storing entries
    /// and when rewriting wire TTLs on the way into the cache. `0` falls
    /// back to the answer min TTL (default path uses 600).
    cache_ttl: u32,
    notifier: Option<Arc<dyn DomainResolveNotifier>>,
    /// Cache keys with an in-flight stale-while-revalidate background
    /// refresh; deduplicates refresh storms for hot expiring entries.
    refreshing: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
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
            cache_enabled: true,
            // 0 = keep answer min TTL until `with_cache_ttl` is applied from config.
            cache_ttl: 0,
            notifier: None,
            refreshing: Default::default(),
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
            cache_enabled: true,
            cache_ttl: 0,
            notifier: Some(notifier),
            refreshing: Default::default(),
        }
    }

    /// Set the IP-version strategy used for DNS responses.
    pub fn with_strategy(mut self, strategy: DnsStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Enable or disable the in-memory DNS cache (dae `optimistic_cache`).
    pub fn with_cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Set the fixed positive-cache TTL (dae `optimistic_cache_ttl`).
    ///
    /// When non-zero, this value **overrides** the minimum TTL from the
    /// upstream answer for both cache lifetime and wire-format TTL fields
    /// stored in the cache. `0` keeps answer min TTL behaviour.
    pub fn with_cache_ttl(mut self, ttl_secs: u32) -> Self {
        self.cache_ttl = ttl_secs;
        self
    }

    /// Return a clone of the underlying cache Arc.
    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        self.cache.clone()
    }

    /// Resolve a raw DNS query (no original destination for `asis`).
    pub async fn resolve(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_context(raw_query, None).await
    }

    /// Resolve a raw DNS query with optional original destination.
    ///
    /// `original_dst` is used when request routing selects `asis` (dial the
    /// intercepted packet's real DNS server). When `None`, `asis` falls back
    /// to the configured default upstream with a debug log.
    pub async fn resolve_with_context(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        self.resolve_inner(raw_query, original_dst, false).await
    }

    /// `bypass_cache_read` skips the cache/negative lookup — used by the
    /// stale-while-revalidate refresh so it always reaches the upstream
    /// (its result is still written back through the normal pipeline).
    async fn resolve_inner(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
        bypass_cache_read: bool,
    ) -> anyhow::Result<Vec<u8>> {
        debug!("DNS forwarder: resolving {} bytes", raw_query.len());

        let (domain, qtype) = parse_dns_question(raw_query)
            .with_context(|| "failed to parse DNS question section")?;
        let cache_key = dns_cache_key(&domain, qtype);

        debug!(
            "DNS forwarder: query {} QTYPE={} (key={})",
            domain, qtype, cache_key
        );

        // IP-version strategy: `*_only` modes answer the other family's
        // query with NODATA right here; prefer modes forward both families
        // and are enforced at response time (see `apply_prefer_strategy`).
        if is_filtered_qtype(qtype, &self.strategy) {
            debug!(
                "DNS forwarder: dropping {} query due to strategy {:?}",
                qtype_name(qtype),
                self.strategy
            );
            return Ok(make_empty_response(raw_query, &domain, qtype));
        }

        // Request routing runs *before* cache (dae order) so reject always wins
        // over a stale positive entry and asis is never short-circuited.
        let decision = self.routing.select_request(&domain, qtype);
        match &decision {
            DnsRequestDecision::Reject => {
                debug!("DNS forwarder: request reject for {}", domain);
                return Ok(make_empty_response(raw_query, &domain, qtype));
            }
            DnsRequestDecision::AsIs | DnsRequestDecision::Upstream(_) => {}
        }

        if self.cache_enabled && !bypass_cache_read {
            let mut cache = self.cache.lock().await;
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
                // Stale-while-revalidate: hot entries nearing expiry are
                // refreshed in the background (deduplicated) so the next
                // lookup never pays the upstream latency.
                let refresh_after = (entry.min_ttl as u64 / 10).max(1);
                if entry.remaining_ttl_secs() <= refresh_after {
                    self.maybe_spawn_refresh(cache_key.clone(), raw_query, original_dst);
                }
                let mut response = entry.response.clone();
                if response.len() >= 2 && raw_query.len() >= 2 {
                    response[0..2].copy_from_slice(&raw_query[0..2]);
                }
                // Drop the lock before the prefer check: it re-locks the cache
                // and may issue a sibling query.
                drop(cache);
                return self
                    .apply_prefer_strategy(raw_query, &domain, qtype, response, original_dst)
                    .await;
            }
        }

        let upstream_result: anyhow::Result<(Vec<u8>, String)> = match decision {
            DnsRequestDecision::AsIs => {
                let resp = self
                    .query_asis(raw_query, original_dst)
                    .await
                    .with_context(|| format!("asis query failed for {domain}"));
                resp.map(|r| (r, "asis".to_string()))
            }
            DnsRequestDecision::Upstream(name) => {
                debug!("DNS forwarder: routing {} → upstream '{}'", domain, name);
                let resp = self
                    .upstream_pool
                    .query(&name, raw_query)
                    .await
                    .with_context(|| format!("upstream '{name}' query failed for {domain}"));
                resp.map(|r| (r, name))
            }
            DnsRequestDecision::Reject => unreachable!("reject handled above"),
        };
        let (mut response, mut upstream_name) = match upstream_result {
            Ok(ok) => ok,
            Err(e) => {
                // RFC 8767 serve-stale: an upstream failure must not take
                // down resolution for names we still hold recently-expired
                // answers for.
                if let Some(stale) = self.try_serve_stale(&cache_key, raw_query, &domain).await {
                    return self
                        .apply_prefer_strategy(raw_query, &domain, qtype, stale, original_dst)
                        .await;
                }
                return Err(e);
            }
        };

        // Response routing: accept / reject / re-query (depth capped).
        for depth in 0..MAX_DNS_LOOKUP_DEPTH {
            let rcode = if response.len() >= 4 {
                response[3] & 0x0F
            } else {
                0
            };
            // Don't re-route hard failures — return them (and negative-cache).
            if rcode == 2 || rcode == 3 {
                // SERVFAIL: serve a stale positive entry if we have one —
                // the authoritative server failing must not shadow a name
                // we recently resolved (RFC 8767).
                if rcode == 2
                    && let Some(stale) = self.try_serve_stale(&cache_key, raw_query, &domain).await
                {
                    return self
                        .apply_prefer_strategy(raw_query, &domain, qtype, stale, original_dst)
                        .await;
                }
                if self.cache_enabled {
                    let neg_ttl = extract_soa_negative_ttl(&response, 60);
                    let mut cache = self.cache.lock().await;
                    cache.put_negative(cache_key.clone(), neg_ttl);
                    debug!(
                        "DNS forwarder: negative cache stored for {} (rcode={}, ttl={}s)",
                        domain, rcode, neg_ttl
                    );
                }
                if response.len() >= 2 && raw_query.len() >= 2 {
                    response[0..2].copy_from_slice(&raw_query[0..2]);
                }
                return Ok(response);
            }

            let ips = extract_answer_ips(&response);
            match self
                .routing
                .select_response(&domain, qtype, &ips, &upstream_name)
            {
                DnsResponseDecision::Accept => break,
                DnsResponseDecision::Reject => {
                    debug!(
                        "DNS forwarder: response reject for {} via {}",
                        domain, upstream_name
                    );
                    response = make_empty_response(raw_query, &domain, qtype);
                    break;
                }
                DnsResponseDecision::Requery(next) => {
                    if depth + 1 >= MAX_DNS_LOOKUP_DEPTH {
                        warn!(
                            "DNS forwarder: response re-query depth exceeded for {} (last={})",
                            domain, next
                        );
                        break;
                    }
                    if next == upstream_name {
                        debug!(
                            "DNS forwarder: response re-query to same upstream '{}' — accepting",
                            next
                        );
                        break;
                    }
                    debug!(
                        "DNS forwarder: response re-query {} → '{}' (depth={})",
                        domain,
                        next,
                        depth + 1
                    );
                    response = self
                        .upstream_pool
                        .query(&next, raw_query)
                        .await
                        .with_context(|| {
                            format!("response re-query upstream '{next}' failed for {domain}")
                        })?;
                    upstream_name = next;
                }
            }
        }

        // Cache TTL: fixed_domain_ttl wins when set; else optimistic_cache_ttl
        // override; else answer min TTL. fixed=0 means do not cache.
        let skip_cache = matches!(self.routing.fixed_ttl(&domain), Some(0));
        let answer_ttl = extract_min_ttl(&response);
        let cache_ttl = match self.routing.fixed_ttl(&domain) {
            Some(0) => 0,
            Some(fixed) => fixed,
            None => effective_cache_ttl(self.cache_ttl, answer_ttl),
        };

        if self.cache_enabled && !skip_cache && cache_ttl > 0 {
            rewrite_answer_ttls(&mut response, cache_ttl);
            let mut cache = self.cache.lock().await;
            cache.put(cache_key, response.clone(), cache_ttl);
        }

        if let Some(ref notifier) = self.notifier {
            notifier.on_domain_resolved(&domain, &response);
        }

        if response.len() >= 2 && raw_query.len() >= 2 {
            response[0..2].copy_from_slice(&raw_query[0..2]);
        }

        debug!(
            "DNS forwarder: resolved {} via '{}' (cache_ttl={}s answer_ttl={}s, {} bytes)",
            domain,
            upstream_name,
            cache_ttl,
            answer_ttl,
            response.len()
        );

        self.apply_prefer_strategy(raw_query, &domain, qtype, response, original_dst)
            .await
    }

    /// RFC 8767 serve-stale: fall back to a recently-expired cache entry
    /// when the upstream phase fails. TTLs are rewritten to
    /// [`SERVE_STALE_TTL_SECS`] so the client re-asks soon, and the txid is
    /// patched to the caller's query.
    async fn try_serve_stale(
        &self,
        cache_key: &str,
        raw_query: &[u8],
        domain: &str,
    ) -> Option<Vec<u8>> {
        if !self.cache_enabled {
            return None;
        }
        let mut cache = self.cache.lock().await;
        let entry = cache.get_stale(cache_key)?;
        let mut response = entry.response.clone();
        drop(cache);
        rewrite_answer_ttls(&mut response, SERVE_STALE_TTL_SECS);
        if response.len() >= 2 && raw_query.len() >= 2 {
            response[0..2].copy_from_slice(&raw_query[0..2]);
        }
        debug!(
            "DNS forwarder: serving stale cache for {} (upstream failure)",
            domain
        );
        Some(response)
    }

    /// Spawn a deduplicated background refresh for a hot entry nearing
    /// expiry (stale-while-revalidate). The refresh bypasses the cache read
    /// so it always reaches the upstream; the normal pipeline writes the
    /// fresh answer back.
    fn maybe_spawn_refresh(
        &self,
        cache_key: String,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) {
        {
            let mut set = self.refreshing.lock().unwrap();
            if !set.insert(cache_key.clone()) {
                return;
            }
        }
        let this = self.clone();
        let query = raw_query.to_vec();
        tokio::spawn(async move {
            let result = this.resolve_inner(&query, original_dst, true).await;
            if let Err(e) = result {
                debug!("DNS forwarder: background refresh failed: {e:#}");
            }
            this.refreshing.lock().unwrap().remove(&cache_key);
        });
    }

    /// Prefer-mode strategy (sing-box / dae `ipversion_prefer` semantics):
    /// when the preferred family has answers for the same name, suppress the
    /// non-preferred family's response with NODATA; otherwise return it
    /// unchanged. Only-modes are handled earlier at request time.
    async fn apply_prefer_strategy(
        &self,
        raw_query: &[u8],
        domain: &str,
        qtype: u16,
        response: Vec<u8>,
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        let preferred = match (&self.strategy, qtype) {
            (DnsStrategy::PreferIpv4, 28) => 1u16,
            (DnsStrategy::PreferIpv6, 1) => 28u16,
            _ => return Ok(response),
        };
        if self
            .preferred_family_has_answers(domain, preferred, original_dst)
            .await
        {
            debug!(
                "DNS forwarder: suppressing {} answer for {} — preferred {} answers exist",
                qtype_name(qtype),
                domain,
                qtype_name(preferred)
            );
            return Ok(make_empty_response(raw_query, domain, qtype));
        }
        Ok(response)
    }

    /// Whether the preferred address family has answers for `domain`, checking
    /// the cache first and issuing a sibling query through the normal pipeline
    /// on a miss (its result is cached by that pipeline). The sibling query
    /// uses the preferred qtype, so `apply_prefer_strategy` never recurses.
    async fn preferred_family_has_answers(
        &self,
        domain: &str,
        preferred_qtype: u16,
        original_dst: Option<SocketAddr>,
    ) -> bool {
        let sibling_key = dns_cache_key(domain, preferred_qtype);
        if self.cache_enabled {
            let mut cache = self.cache.lock().await;
            if cache.is_negative(&sibling_key) {
                return false;
            }
            if let Some(entry) = cache.get(&sibling_key) {
                return response_has_family_ips(&entry.response, preferred_qtype);
            }
        }
        let query = build_dns_query(domain, preferred_qtype);
        // Boxed: breaks the async recursion cycle through resolve_with_context
        // (the sibling uses the preferred qtype, so it never re-enters here).
        let sibling = Box::pin(self.resolve_with_context(&query, original_dst)).await;
        match sibling {
            Ok(resp) => response_has_family_ips(&resp, preferred_qtype),
            Err(e) => {
                debug!(
                    "DNS forwarder: preferred-family probe for {} failed: {}",
                    domain, e
                );
                false
            }
        }
    }

    /// Dial the original destination DNS server (dae `asis`).
    async fn query_asis(
        &self,
        raw_query: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<Vec<u8>> {
        let Some(dst) = original_dst else {
            debug!("DNS forwarder: asis without original_dst — falling back to default upstream");
            return self.upstream_pool.query("default", raw_query).await;
        };

        debug!("DNS forwarder: asis dial {}", dst);
        let domain = if dst.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock2 =
            socket2::Socket::new(domain, socket2::Type::DGRAM, None).context("asis socket")?;
        sock2.set_nonblocking(true).context("asis nonblocking")?;
        #[cfg(target_os = "linux")]
        {
            let _ = sock2.set_mark(DAE_BYPASS_MARK);
        }
        sock2
            .bind(
                &SocketAddr::new(
                    if dst.is_ipv4() {
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                    } else {
                        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                    },
                    0,
                )
                .into(),
            )
            .context("asis bind")?;
        let socket = tokio::net::UdpSocket::from_std(sock2.into()).context("asis from_std")?;
        socket.connect(dst).await.context("asis connect")?;

        let resp = tokio::time::timeout(Duration::from_secs(5), async {
            socket.send(raw_query).await?;
            let mut buf = vec![0u8; 4096];
            let n = socket.recv(&mut buf).await?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        })
        .await
        .context("asis recv timeout")?
        .context("asis recv")?;
        Ok(resp)
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

/// Resolve the TTL used for positive cache inserts.
///
/// `configured` is `dns.cache.ttl` / `optimistic_cache_ttl`. Non-zero values
/// win (fixed override); `0` keeps the answer-section minimum.
/// Extract A/AAAA answer IPs from a wire-format DNS response.
pub fn extract_answer_ips(data: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if data.len() < 12 {
        return ips;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return ips;
        }
        pos += 4;
        if pos > data.len() {
            return ips;
        }
    }
    for _ in 0..ancount {
        if !skip_dns_name(data, &mut pos) {
            break;
        }
        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > data.len() {
            break;
        }
        match rtype {
            1 if rdlength == 4 => {
                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                )));
            }
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += rdlength;
    }
    ips
}

fn effective_cache_ttl(configured: u32, answer_min_ttl: u32) -> u32 {
    if configured > 0 {
        configured
    } else {
        answer_min_ttl.max(1)
    }
}

/// TTL advertised on answers served from the serve-stale fallback: small
/// enough that clients retry soon and pick up the recovery.
const SERVE_STALE_TTL_SECS: u32 = 30;

/// RFC 2308 §5 negative-cache TTL: `min(SOA TTL, SOA MINIMUM)` from the
/// authority section, falling back to `default_ttl` when no SOA record is
/// present (or the message is malformed).
fn extract_soa_negative_ttl(data: &[u8], default_ttl: u32) -> u32 {
    if data.len() < 12 {
        return default_ttl;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        pos += 4;
        if pos > data.len() {
            return default_ttl;
        }
    }
    // Skip answers; scan authority records for SOA (TYPE 6).
    for i in 0..(ancount + nscount) {
        if !skip_dns_name(data, &mut pos) {
            return default_ttl;
        }
        if pos + 10 > data.len() {
            return default_ttl;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        if i >= ancount && rtype == 6 && rdlength >= 20 && pos + 10 + rdlength <= data.len() {
            // SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE,
            // MINIMUM — the last u32 of RDATA.
            let minimum = u32::from_be_bytes([
                data[pos + 10 + rdlength - 4],
                data[pos + 10 + rdlength - 3],
                data[pos + 10 + rdlength - 2],
                data[pos + 10 + rdlength - 1],
            ]);
            return ttl.min(minimum).max(1);
        }
        pos += 10 + rdlength;
    }
    default_ttl
}

/// Overwrite TTL fields on every answer/authority/additional RR with `ttl`.
///
/// Used so cached (and client-visible) records reflect `optimistic_cache_ttl`
/// rather than the upstream's original values. Malformed tails are left as-is.
fn rewrite_answer_ttls(data: &mut [u8], ttl: u32) {
    if data.len() < 12 {
        return;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        pos += 4;
        if pos > data.len() {
            return;
        }
    }

    let ttl_be = ttl.to_be_bytes();
    for _ in 0..(ancount + nscount + arcount) {
        if !skip_dns_name(data, &mut pos) {
            return;
        }
        if pos + 10 > data.len() {
            return;
        }
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA
        data[pos + 4] = ttl_be[0];
        data[pos + 5] = ttl_be[1];
        data[pos + 6] = ttl_be[2];
        data[pos + 7] = ttl_be[3];
        let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlength;
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

/// Return `true` if the given query type is hard-filtered at request time.
/// Only the `*_only` strategies filter here; prefer strategies forward both
/// families and suppress at response time instead.
fn is_filtered_qtype(qtype: u16, strategy: &DnsStrategy) -> bool {
    match strategy {
        DnsStrategy::Ipv4Only => qtype == 28, // AAAA
        DnsStrategy::Ipv6Only => qtype == 1,  // A
        DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Both => false,
    }
}

/// Whether a wire-format response contains at least one address record of
/// the given family (qtype 1 = A, 28 = AAAA).
fn response_has_family_ips(response: &[u8], qtype: u16) -> bool {
    extract_answer_ips(response).iter().any(|ip| match qtype {
        1 => ip.is_ipv4(),
        28 => ip.is_ipv6(),
        _ => false,
    })
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
                ..Default::default()
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

    /// Mock upstream that always fails (serve-stale tests).
    struct FailUpstream;

    #[async_trait]
    impl DnsUpstreamPool for FailUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("upstream down")
        }
    }

    /// Fill the cache with a 1-second-TTL answer, let it expire, then
    /// resolve through a failing upstream — the stale entry must be served
    /// (RFC 8767) with TTLs rewritten to SERVE_STALE_TTL_SECS.
    #[tokio::test]
    async fn test_serve_stale_on_upstream_failure() {
        let response = make_a_response([93, 184, 216, 34], 1);
        let cache = test_cache();
        let query = make_a_query();
        let fwd_ok = DnsForwarder::new(
            Arc::new(MockUpstream::new(response)),
            cache.clone(),
            test_router(),
        );
        fwd_ok.resolve(&query).await.expect("initial resolve");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let fwd_fail = DnsForwarder::new(Arc::new(FailUpstream), cache, test_router());
        let stale = fwd_fail.resolve(&query).await.expect("stale served");
        assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
        assert_eq!(extract_min_ttl(&stale), SERVE_STALE_TTL_SECS);
    }

    /// A SERVFAIL answer must not shadow a recently-expired positive entry.
    #[tokio::test]
    async fn test_serve_stale_on_servfail() {
        let mut servfail = make_a_response([93, 184, 216, 34], 1);
        servfail[3] = 0x82; // RCODE = SERVFAIL
        let cache = test_cache();
        let query = make_a_query();
        let fwd_ok = DnsForwarder::new(
            Arc::new(MockUpstream::new(make_a_response([93, 184, 216, 34], 1))),
            cache.clone(),
            test_router(),
        );
        fwd_ok.resolve(&query).await.expect("initial resolve");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

        let fwd_fail =
            DnsForwarder::new(Arc::new(MockUpstream::new(servfail)), cache, test_router());
        let stale = fwd_fail.resolve(&query).await.expect("stale served");
        assert!(stale.windows(4).any(|w| w == [93, 184, 216, 34]));
    }

    /// Hot entries nearing expiry trigger a deduplicated background refresh.
    #[tokio::test]
    async fn test_stale_while_revalidate_refresh() {
        let response = make_a_response([93, 184, 216, 34], 2);
        let mock = Arc::new(MockUpstream::new(response));
        let forwarder = DnsForwarder::new(mock.clone(), test_cache(), test_router());
        let query = make_a_query();

        forwarder.resolve(&query).await.expect("initial resolve");
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        // Wait until remaining TTL (2s) drops to the <=10% threshold.
        tokio::time::sleep(std::time::Duration::from_millis(1900)).await;
        // This lookup is a cache hit that should kick off a refresh.
        forwarder.resolve(&query).await.expect("cache hit");
        // The refresh happens in the background; poll briefly.
        let mut calls = 1;
        for _ in 0..20 {
            calls = mock.call_count.load(Ordering::SeqCst);
            if calls >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(calls, 2, "background refresh should re-query upstream");
    }

    /// RFC 2308 §5: negative TTL = min(SOA TTL, SOA MINIMUM).
    #[test]
    fn test_extract_soa_negative_ttl() {
        // NXDOMAIN with authority SOA (ttl=300, minimum=60).
        let mut resp = vec![
            0x00, 0x00, // ID
            0x81, 0x83, // QR + RCODE=NXDOMAIN
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x01, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        // Question: example.com A IN
        for label in ["example", "com"] {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Authority SOA: name ptr, type SOA, class IN, ttl 300, rdata
        // root mname/rname + serial/refresh/retry/expire + minimum 60.
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x06, 0x00, 0x01]);
        resp.extend_from_slice(&300u32.to_be_bytes());
        let mut rdata = vec![0x00, 0x00]; // MNAME, RNAME (root)
        for v in [1u32, 7200, 3600, 1209600, 60] {
            rdata.extend_from_slice(&v.to_be_bytes());
        }
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        assert_eq!(extract_soa_negative_ttl(&resp, 60), 60);
        // No authority section → default.
        let plain = make_a_response([1, 1, 1, 1], 300);
        assert_eq!(extract_soa_negative_ttl(&plain, 42), 42);
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
                ..Default::default()
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

    #[test]
    fn test_effective_cache_ttl_override() {
        assert_eq!(effective_cache_ttl(600, 30), 600);
        assert_eq!(effective_cache_ttl(0, 30), 30);
        assert_eq!(effective_cache_ttl(0, 0), 1);
    }

    #[test]
    fn test_rewrite_answer_ttls_overrides_wire() {
        let mut resp = make_a_response([1, 2, 3, 4], 30);
        assert_eq!(extract_min_ttl(&resp), 30);
        rewrite_answer_ttls(&mut resp, 600);
        assert_eq!(extract_min_ttl(&resp), 600);
    }

    #[tokio::test]
    async fn test_optimistic_cache_ttl_overrides_answer_ttl() {
        // Upstream answers with TTL=30; forwarder configured for 600.
        let upstream_resp = make_a_response([9, 9, 9, 9], 30);
        let mock = Arc::new(MockUpstream::new(upstream_resp));
        let cache = test_cache();
        let forwarder = DnsForwarder::new(
            mock as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            test_router(),
        )
        .with_cache_ttl(600);

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(
            extract_min_ttl(&result),
            600,
            "client-visible wire TTL overridden"
        );

        {
            let mut guard = cache.lock().await;
            let entry = guard.get("example.com:1").expect("cached");
            assert_eq!(entry.min_ttl, 600);
            assert_eq!(extract_min_ttl(&entry.response), 600);
            // Lifetime should be ~600s, not 30s.
            let remaining = entry.remaining_ttl_secs();
            assert!(
                (590..=600).contains(&remaining),
                "cache lifetime uses optimistic_cache_ttl, got {remaining}"
            );
        }
    }

    #[tokio::test]
    async fn test_request_reject_skips_upstream() {
        use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

        let mock = Arc::new(MockUpstream::new(make_a_response([1, 1, 1, 1], 60)));
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![65], // HTTPS
                        }],
                        action: DnsRequestAction::Reject,
                    }],
                    fallback: DnsRequestAction::Upstream("default".into()),
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = build_dns_query("example.com", 65);
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            0,
            "reject must not dial"
        );
        assert_eq!(
            u16::from_be_bytes([result[6], result[7]]),
            0,
            "empty ANCOUNT"
        );
    }

    #[tokio::test]
    async fn test_qtype_routes_to_named_upstream() {
        use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

        struct NameMock {
            last: std::sync::Mutex<String>,
            a_resp: Vec<u8>,
            aaaa_resp: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for NameMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                *self.last.lock().unwrap() = upstream_name.to_string();
                if upstream_name == "v6dns" {
                    Ok(self.aaaa_resp.clone())
                } else {
                    Ok(self.a_resp.clone())
                }
            }
        }

        let mock = Arc::new(NameMock {
            last: std::sync::Mutex::new(String::new()),
            a_resp: make_a_response([1, 2, 3, 4], 60),
            aaaa_resp: make_a_response([9, 9, 9, 9], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        }],
                        action: DnsRequestAction::Upstream("v6dns".into()),
                    }],
                    fallback: DnsRequestAction::Upstream("default".into()),
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        )
        .with_strategy(honk_config::dns::DnsStrategy::Both);

        let q_a = build_dns_query("example.com", 1);
        let _ = forwarder.resolve(&q_a).await.unwrap();
        assert_eq!(mock.last.lock().unwrap().as_str(), "default");

        let q_aaaa = build_dns_query("example.com", 28);
        let _ = forwarder.resolve(&q_aaaa).await.unwrap();
        assert_eq!(mock.last.lock().unwrap().as_str(), "v6dns");
    }

    #[tokio::test]
    async fn test_response_requery_switches_upstream() {
        use honk_config::dns::{
            DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
            DnsResponseRule,
        };

        struct SeqMock {
            calls: AtomicUsize,
            polluted: Vec<u8>,
            clean: Vec<u8>,
        }
        #[async_trait]
        impl DnsUpstreamPool for SeqMock {
            async fn query(
                &self,
                upstream_name: &str,
                _raw_query: &[u8],
            ) -> anyhow::Result<Vec<u8>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if upstream_name == "googledns" {
                    Ok(self.clean.clone())
                } else {
                    Ok(self.polluted.clone())
                }
            }
        }

        let mock = Arc::new(SeqMock {
            calls: AtomicUsize::new(0),
            polluted: make_a_response([10, 0, 0, 1], 60), // private → trigger requery
            clean: make_a_response([8, 8, 8, 8], 60),
        });
        let router = Arc::new(
            DnsRouter::new(&DnsRouting {
                request: DnsRequestRouting {
                    rules: vec![],
                    fallback: DnsRequestAction::Upstream("alidns".into()),
                },
                response: DnsResponseRouting {
                    rules: vec![DnsResponseRule {
                        conditions: vec![DnsCond::Ip {
                            not: false,
                            cidrs: vec!["10.0.0.0/8".into()],
                            geoip: vec![],
                        }],
                        action: DnsResponseAction::Upstream("googledns".into()),
                    }],
                    fallback: DnsResponseAction::Accept,
                },
                ..Default::default()
            })
            .unwrap(),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            router,
        );

        let query = make_a_query();
        let result = forwarder.resolve(&query).await.expect("resolve");
        assert_eq!(mock.calls.load(Ordering::SeqCst), 2, "polluted then clean");
        assert_eq!(&result[result.len() - 4..], &[8, 8, 8, 8]);
    }

    #[tokio::test]
    async fn test_fixed_domain_ttl_zero_skips_cache() {
        use std::collections::HashMap;

        let response = make_a_response([1, 2, 3, 4], 300);
        let mock = Arc::new(MockUpstream::new(response));
        let cache = test_cache();
        let mut ttl = HashMap::new();
        ttl.insert("example.com".to_string(), 0u32);
        let router = Arc::new(DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &ttl).unwrap());
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            cache.clone(),
            router,
        );

        let query = make_a_query();
        let _ = forwarder.resolve(&query).await.unwrap();
        assert!(
            cache.lock().await.get("example.com:1").is_none(),
            "fixed_domain_ttl=0 must not cache"
        );
        // Second resolve hits upstream again.
        let _ = forwarder.resolve(&query).await.unwrap();
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_extract_answer_ips_a_record() {
        let resp = make_a_response([1, 2, 3, 4], 60);
        let ips = extract_answer_ips(&resp);
        assert_eq!(ips, vec![IpAddr::from([1, 2, 3, 4])]);
    }

    /// Build an AAAA-record response for example.com with a given IPv6 and TTL.
    fn make_aaaa_response(ip: [u8; 16], ttl: u32) -> Vec<u8> {
        let ttl_bytes = ttl.to_be_bytes();
        let mut v = vec![
            0x00,
            0x00, // ID
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
            // Question: example.com AAAA IN
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
            0x1c, // QTYPE AAAA
            0x00,
            0x01, // QCLASS IN
            // Answer
            0xc0,
            0x0c, // NAME pointer to offset 12
            0x00,
            0x1c, // TYPE AAAA
            0x00,
            0x01, // CLASS IN
            ttl_bytes[0],
            ttl_bytes[1],
            ttl_bytes[2],
            ttl_bytes[3], // TTL
            0x00,
            0x10, // RDLENGTH 16
        ];
        v.extend_from_slice(&ip);
        v
    }

    fn nodata_response(domain: &str, qtype: u16) -> Vec<u8> {
        make_empty_response(&build_dns_query(domain, qtype), domain, qtype)
    }

    fn answer_count(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    /// Mock upstream answering per query qtype.
    struct QtypeMock {
        a: Vec<u8>,
        aaaa: Vec<u8>,
        call_count: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for QtypeMock {
        async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let (domain, qtype) = parse_dns_question(raw_query).expect("question");
            Ok(match qtype {
                1 => self.a.clone(),
                28 => self.aaaa.clone(),
                _ => make_empty_response(raw_query, &domain, qtype),
            })
        }
    }

    fn qtype_mock(a: Vec<u8>, aaaa: Vec<u8>) -> Arc<QtypeMock> {
        Arc::new(QtypeMock {
            a,
            aaaa,
            call_count: AtomicUsize::new(0),
        })
    }

    const TEST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    #[tokio::test]
    async fn test_only_strategy_filters_at_request_time() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::Ipv4Only);

        let resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(answer_count(&resp), 0, "AAAA must be answered NODATA");
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            0,
            "filtered query must never reach upstream"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv4_suppresses_aaaa_when_a_exists() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        // Prime the A cache with real answers.
        let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert!(answer_count(&a_resp) > 0);

        // AAAA is forwarded to upstream but suppressed at response time.
        let aaaa_resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(
            answer_count(&aaaa_resp),
            0,
            "AAAA must be suppressed when A answers exist"
        );
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            2,
            "A + AAAA; the prefer check must hit the cache, not upstream"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv4_returns_aaaa_when_no_a() {
        let mock = qtype_mock(
            nodata_response("example.com", 1),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        let resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(
            answer_count(&resp),
            1,
            "AAAA must be returned when no A answers exist"
        );
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            2,
            "AAAA + sibling A probe"
        );

        // Cache-hit path: AAAA and the sibling's NODATA are both cached.
        let resp2 = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert_eq!(answer_count(&resp2), 1);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_prefer_ipv4_never_probes_for_a_queries() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv4);

        let resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert_eq!(answer_count(&resp), 1);
        assert_eq!(
            mock.call_count.load(Ordering::SeqCst),
            1,
            "preferred qtype must not trigger a sibling probe"
        );
    }

    #[tokio::test]
    async fn test_prefer_ipv6_suppresses_a_when_aaaa_exists() {
        let mock = qtype_mock(
            make_a_response([10, 0, 0, 1], 300),
            make_aaaa_response(TEST_V6, 300),
        );
        let forwarder = DnsForwarder::new(
            mock.clone() as Arc<dyn DnsUpstreamPool>,
            test_cache(),
            test_router(),
        )
        .with_strategy(DnsStrategy::PreferIpv6);

        // Prime the AAAA cache.
        let aaaa_resp = forwarder
            .resolve(&build_dns_query("example.com", 28))
            .await
            .unwrap();
        assert!(answer_count(&aaaa_resp) > 0);

        let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
        assert_eq!(
            answer_count(&a_resp),
            0,
            "A must be suppressed when AAAA answers exist"
        );
    }
}
