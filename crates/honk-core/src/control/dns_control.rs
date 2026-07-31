//! DNS Controller — intercepts TPROXY DNS traffic and routes it through
//! the DNS forwarder, updating eBPF domain routing on resolution.
//!
//! ## Features
//!
//! - DNS query interception (UDP + TCP)
//! - Singleflight deduplication for concurrent identical queries
//! - Async BPF cache update channel (non-blocking)
//! - Periodic route refresh worker
//! - Concurrency limit with graceful SERVFAIL degradation
//!
//! Go ref: `dns_control.go` (2943L)

use crate::dns::forwarder::DnsForwarder;
use crate::dns::wire::extract_ips_from_dns_response;
use crate::ebpf::EbpfBackend;
use crate::routing::Router;
use dashmap::DashMap;
use honk_ebpf_common::DomainRouting;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::debug;

/// Max concurrent in-flight DNS queries. Sized like dae's (16384 @ ~4KB
/// each) but conservative: 2048 ≈ 8MB of in-flight state, comfortably
/// covering thousands of QPS before degradation. Over the limit the answer
/// is REFUSED, not SERVFAIL — SERVFAIL invites client retry storms, REFUSED
/// says "busy, back off".
const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 2048;

/// Interval for periodic DNS cache route refresh.
const ROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// TTL for domain→route cache entries (avoids repeated Router lookups).
const DOMAIN_ROUTE_CACHE_TTL: Duration = Duration::from_secs(300);
/// Maximum number of cached domain entries (defense against unbounded growth).
const DOMAIN_ROUTE_CACHE_MAX: usize = 10000;
/// Maximum number of learned domain→IP mappings retained across reloads.
const LEARNED_ROUTES_MAX: usize = 10000;

/// Lightweight TTL cache mapping domain → (rule_name, merged_bitmap).
/// Avoids O(n) Router::route_full() calls on every DNS response for the same domain.
///
/// Uses tokio::sync::RwLock instead of parking_lot::RwLock to prevent
/// thread starvation on the tokio runtime under high concurrent DNS load.
struct DomainRouteCache {
    entries: RwLock<HashMap<String, CachedDomainEntry>>,
}

struct CachedDomainEntry {
    rule_name: String,
    merged_bitmap: DomainRouting,
    generation: u64,
    expires_at: tokio::time::Instant,
}

impl DomainRouteCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Look up a domain. Returns None if not cached, expired, or stale generation.
    async fn get(&self, domain: &str) -> Option<(String, DomainRouting)> {
        use crate::control::routing_matcher::DOMAIN_BITMAPS_GENERATION;
        let current_gen = DOMAIN_BITMAPS_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        let entries = self.entries.read().await;
        entries.get(domain).and_then(|entry| {
            if entry.generation == current_gen && tokio::time::Instant::now() < entry.expires_at {
                Some((entry.rule_name.clone(), entry.merged_bitmap))
            } else {
                None
            }
        })
    }

    /// Store a domain → route mapping with TTL. Evicts expired entries if
    /// the cache exceeds DOMAIN_ROUTE_CACHE_MAX.
    async fn set(&self, domain: String, rule_name: String, bitmap: DomainRouting) {
        use crate::control::routing_matcher::DOMAIN_BITMAPS_GENERATION;
        let r#gen = DOMAIN_BITMAPS_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        let mut entries = self.entries.write().await;

        if entries.len() >= DOMAIN_ROUTE_CACHE_MAX {
            let now = tokio::time::Instant::now();
            entries.retain(|_, v| v.expires_at > now);
        }

        entries.insert(
            domain,
            CachedDomainEntry {
                rule_name,
                merged_bitmap: bitmap,
                generation: r#gen,
                expires_at: tokio::time::Instant::now() + DOMAIN_ROUTE_CACHE_TTL,
            },
        );
    }
}

/// DNS Controller — intercepts TPROXY DNS traffic and forwards it through
/// the DNS forwarding engine with proactive eBPF route updates.
pub struct DnsController {
    forwarder: Arc<RwLock<DnsForwarder>>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    router: Arc<RwLock<Router>>,
    /// Cache for domain→route lookups (avoids repeated Router scans).
    route_cache: DomainRouteCache,

    /// Learned domain → resolved IP sets, persisted across routing reloads.
    /// DOMAIN_ROUTING_MAP entries reference rule indices that change on
    /// every ruleset push; this mapping lets `rebuild_domain_routes`
    /// recompute the entries with the new bitmaps after a reload.
    learned_routes: DashMap<String, Vec<std::net::IpAddr>>,

    /// IPs currently present in DOMAIN_ROUTING_MAP via the DNS snoop path.
    /// Tracked so a rebuild can delete entries whose domain no longer
    /// matches any domain rule without touching unrelated map entries.
    pushed_ips: DashMap<std::net::IpAddr, ()>,

    /// In-flight query deduplication: (key → broadcast sender).
    /// When multiple clients query the same domain simultaneously,
    /// only one upstream request is made and the result is broadcast.
    in_flight: DashMap<String, broadcast::Sender<Vec<u8>>>,

    /// Semaphore limiting concurrent DNS queries.
    concurrency_limit: Semaphore,
}

impl DnsController {
    pub fn new(
        forwarder: Arc<DnsForwarder>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        router: Arc<RwLock<Router>>,
    ) -> Self {
        Self {
            forwarder: Arc::new(RwLock::new((*forwarder).clone())),
            ebpf,
            router,
            route_cache: DomainRouteCache::new(),
            learned_routes: DashMap::new(),
            pushed_ips: DashMap::new(),
            in_flight: DashMap::new(),
            concurrency_limit: Semaphore::new(DEFAULT_MAX_CONCURRENT_QUERIES),
        }
    }

    /// Resolve a domain (A + AAAA) through the *currently installed*
    /// forwarder — reload-safe, unlike holding a resolver from startup.
    /// Used by the health-check resolver hook.
    pub async fn resolve_domain(&self, domain: &str) -> Vec<std::net::IpAddr> {
        let mut out = Vec::new();
        for qtype in [1u16, 28] {
            let query = crate::dns::forwarder::build_dns_query(domain, qtype);
            let forwarder = self.forwarder.read().await;
            if let Ok(resp) = forwarder.resolve(&query).await {
                out.extend(crate::dns::forwarder::extract_answer_ips(&resp));
            }
        }
        out
    }

    /// Replace the DNS forwarder used by this controller (e.g. after config
    /// reload changed the upstream list or outbound routing).
    pub async fn set_forwarder(&self, forwarder: Arc<DnsForwarder>) {
        let mut guard = self.forwarder.write().await;
        *guard = (*forwarder).clone();
    }

    /// Return a clone of the DNS cache so it can be reused across reloads.
    pub async fn cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        // Access the cache through the currently installed forwarder.
        // DnsForwarder stores the cache as an Arc, so cloning it is cheap.
        let forwarder = self.forwarder.read().await;
        forwarder.cache()
    }

    /// Return a clone of the currently installed DNS forwarder (cheap: all
    /// fields are `Arc`s). Used by the clash API `/dns/query` endpoint so
    /// queries go through the same cache/routing/upstream pipeline as
    /// intercepted DNS traffic.
    pub async fn forwarder(&self) -> DnsForwarder {
        self.forwarder.read().await.clone()
    }

    /// Shared cell of the currently installed forwarder: callers holding
    /// this see reloads immediately (unlike a one-shot `forwarder()` clone).
    pub fn forwarder_cell(&self) -> Arc<RwLock<DnsForwarder>> {
        self.forwarder.clone()
    }

    /// Spawn the periodic route refresh worker.
    pub fn spawn_route_refresh_worker(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(ROUTE_REFRESH_INTERVAL);
            loop {
                tick.tick().await;
                this.refresh_all_routes().await;
            }
        })
    }

    /// Handle a UDP DNS query from TPROXY.
    pub async fn handle_udp_dns(
        &self,
        _udp_socket: &UdpSocket,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        if !is_dns_query(data) {
            return Ok(false);
        }

        // Hold the permit until the response is written — acquiring and
        // immediately dropping it would make the concurrency limit a no-op.
        let _permit = match self.concurrency_limit.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                debug!("DNS concurrency limit reached; sending REFUSED");
                let servfail = build_dns_refused(data);
                let _ =
                    super::send_udp_reply_from_orig_dst(&servfail, client_addr, original_dst).await;
                return Ok(true);
            }
        };

        debug!(
            "DNS controller (UDP): forwarding query from {}",
            client_addr
        );

        let response = self
            .resolve_with_singleflight(data, Some(original_dst))
            .await;
        let _ = super::send_udp_reply_from_orig_dst(&response, client_addr, original_dst).await;
        Ok(true)
    }

    /// Handle a TCP DNS-over-TCP connection from TPROXY.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }

        use tokio::io::AsyncReadExt;

        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(false);
        }
        let mut length = u16::from_be_bytes(len_buf) as usize;
        if !(12..=65535).contains(&length) {
            return Ok(false);
        }

        let mut dns_data = vec![0u8; length];
        if stream.read_exact(&mut dns_data).await.is_err() {
            return Ok(false);
        }

        if !is_dns_query(&dns_data) {
            return Ok(false);
        }

        debug!(
            "DNS controller (TCP): forwarding query from {}",
            client_addr
        );

        let response = if self.concurrency_limit.try_acquire().is_ok() {
            self.resolve_with_singleflight(&dns_data, Some(original_dst))
                .await
        } else {
            build_dns_refused(&dns_data)
        };
        write_tcp_dns_response(stream, &response).await?;

        loop {
            if stream.read_exact(&mut len_buf).await.is_err() {
                return Ok(true);
            }
            length = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&length) {
                return Ok(true);
            }

            dns_data.resize(length, 0);
            if stream.read_exact(&mut dns_data).await.is_err() {
                return Ok(true);
            }

            if !is_dns_query(&dns_data) {
                return Ok(true);
            }

            // Same as the UDP path: the permit must stay alive until the
            // response is written.
            let resp = match self.concurrency_limit.try_acquire() {
                Ok(_permit) => {
                    self.resolve_with_singleflight(&dns_data, Some(original_dst))
                        .await
                }
                Err(_) => build_dns_refused(&dns_data),
            };
            write_tcp_dns_response(stream, &resp).await?;
        }
    }

    /// Resolve a DNS query with singleflight deduplication.
    async fn resolve_with_singleflight(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> Vec<u8> {
        // Key covers the original destination too: `asis` queries to
        // different upstream servers must never share one flight.
        let cache_key = match crate::dns::forwarder::parse_dns_question(data) {
            Some((domain, qtype)) => {
                format!(
                    "{}:{}:{}",
                    domain,
                    qtype,
                    original_dst
                        .map(|a| a.ip())
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
                )
            }
            None => return self.resolve_and_notify(data, original_dst).await.0,
        };

        use dashmap::mapref::entry::Entry;
        let rx = match self.in_flight.entry(cache_key.clone()) {
            Entry::Occupied(e) => Some(e.get().subscribe()),
            Entry::Vacant(e) => {
                let (tx, _) = broadcast::channel(1);
                e.insert(tx.clone());
                None // leader
            }
        };

        if let Some(mut rx) = rx {
            match rx.recv().await {
                Ok(resp) => {
                    debug!("DNS singleflight: reused result for {}", cache_key);
                    // The shared response carries the leader's transaction
                    // ID; restore this query's own or clients will drop it.
                    return with_own_txid(resp, data);
                }
                Err(_) => {
                    // Leader dropped without answering (panic/cancel): clear
                    // the stale entry and retry as a fresh flight.
                    self.in_flight.remove(&cache_key);
                    return Box::pin(self.resolve_with_singleflight(data, original_dst)).await;
                }
            }
        }

        let (response, _) = self.resolve_and_notify(data, original_dst).await;
        if let Some((_, tx)) = self.in_flight.remove(&cache_key) {
            let _ = tx.send(response.clone());
        }
        response
    }

    /// Resolve a raw DNS query and notify BPF on success.
    async fn resolve_and_notify(
        &self,
        data: &[u8],
        original_dst: Option<SocketAddr>,
    ) -> (Vec<u8>, bool) {
        let forwarder = self.forwarder.read().await;
        match forwarder.resolve_with_context(data, original_dst).await {
            Ok(resp) => {
                self.notify_bpf_update(data, &resp).await;
                (resp, true)
            }
            Err(e) => {
                debug!("DNS controller forward failed: {}; sending SERVFAIL", e);
                (build_dns_servfail(data), true)
            }
        }
    }

    /// Push DOMAIN_ROUTING_MAP rule bitmaps for IPs resolved via DNS snoop.
    ///
    /// Only domain/geosite rules contribute entries. Domains that fall through
    /// to the routing default (e.g. `🍥 final`) intentionally produce no map
    /// entry — the real TCP/UDP connection re-evaluates with a full 5-tuple
    /// (port/geoip rules still apply then).
    async fn notify_bpf_update(&self, query: &[u8], response: &[u8]) {
        let domain = match crate::dns::forwarder::parse_dns_question(query) {
            Some((domain, _)) => domain,
            None => {
                debug!("DNS snoop: failed to parse question");
                return;
            }
        };

        let ips = extract_ips_from_dns_response(response);
        if ips.is_empty() {
            return;
        }

        // Persist the resolved address set so DOMAIN_ROUTING_MAP can be
        // rebuilt with fresh rule bitmaps after a routing reload (the eBPF
        // entries reference rule indices that change across reloads).
        if self.learned_routes.len() < LEARNED_ROUTES_MAX {
            self.learned_routes.insert(domain.clone(), ips.clone());
        }

        use crate::control::routing_matcher::DOMAIN_BITMAPS;
        use crate::ebpf::maps::cidr_to_lpm_key;
        use honk_ebpf_common::DomainRouting;

        let cached = self.route_cache.get(&domain).await;
        let (_rule_name, merged) = if let Some((rn, bm)) = cached {
            debug!("DNS snoop: cache hit for {} -> rule '{}'", domain, rn);
            (rn, bm)
        } else {
            // Cache miss: domain-only match (never logs as Connection 0.0.0.0:0).
            let rn = {
                let router = self.router.read().await;
                router
                    .route_domain(&domain)
                    .map(|m| m.rule_name.to_string())
                    .unwrap_or_default()
            };
            if rn.is_empty() {
                return;
            }
            debug!("DNS snoop: domain '{}' matched rule '{}'", domain, rn);
            let bitmaps: Vec<DomainRouting> = {
                let db = DOMAIN_BITMAPS.read();
                db.get(&rn).cloned().unwrap_or_default()
            };
            if bitmaps.is_empty() {
                return;
            }
            let mut merged = DomainRouting { bitmap: [0u32; 4] };
            for bm in &bitmaps {
                for i in 0..4 {
                    merged.bitmap[i] |= bm.bitmap[i];
                }
            }
            self.route_cache
                .set(domain.clone(), rn.clone(), merged)
                .await;
            (rn, merged)
        };

        let mut ebpf = self.ebpf.write().await;
        for ip in &ips {
            let prefix = match ip {
                std::net::IpAddr::V4(_) => format!("{}/32", ip),
                std::net::IpAddr::V6(_) => format!("{}/128", ip),
            };
            if let Ok(lpm_key) = cidr_to_lpm_key(&prefix) {
                match ebpf.add_domain_ip_bitmap(&lpm_key, &merged) {
                    Err(e) => {
                        debug!("DNS snoop: failed to push {} for {}: {}", ip, domain, e);
                    }
                    _ => {
                        debug!("DNS snoop: pushed {} for {} (rule bitmap)", ip, domain);
                        self.pushed_ips.insert(*ip, ());
                    }
                }
            }
        }
    }

    /// Rebuild DOMAIN_ROUTING_MAP from the learned domain→IP mappings using
    /// the current rule-index bitmaps.
    ///
    /// Called after every routing push (including reloads).  Entries pushed
    /// for a previous ruleset reference stale rule indices, so desired
    /// entries are overwritten wholesale and entries whose domain no longer
    /// matches any domain rule are deleted.  A concurrent DNS snoop update
    /// landing between the delete and the re-add loses at most one entry
    /// until the domain's next DNS response — the flow falls back to the
    /// userspace sniffing path, it is never dropped.
    pub async fn rebuild_domain_routes(&self) {
        use crate::control::routing_matcher::DOMAIN_BITMAPS;
        use crate::ebpf::maps::cidr_to_lpm_key;

        let learned: Vec<(String, Vec<std::net::IpAddr>)> = self
            .learned_routes
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        if learned.is_empty() {
            return;
        }

        // Compute the desired IP → bitmap state under the current ruleset,
        // OR-ing bitmaps when several domains resolve to the same IP.
        let mut desired: HashMap<std::net::IpAddr, DomainRouting> = HashMap::new();
        {
            let router = self.router.read().await;
            for (domain, ips) in &learned {
                let rule_name = router
                    .route_domain(domain)
                    .map(|m| m.rule_name.to_string())
                    .unwrap_or_default();
                if rule_name.is_empty() {
                    continue;
                }
                let bitmaps: Vec<DomainRouting> = {
                    let db = DOMAIN_BITMAPS.read();
                    db.get(&rule_name).cloned().unwrap_or_default()
                };
                if bitmaps.is_empty() {
                    continue;
                }
                for ip in ips {
                    let entry = desired.entry(*ip).or_default();
                    for bm in &bitmaps {
                        for (w, b) in entry.bitmap.iter_mut().zip(bm.bitmap.iter()) {
                            *w |= b;
                        }
                    }
                }
            }
        }

        let mut ebpf = self.ebpf.write().await;
        let mut rebuilt = 0usize;
        for (ip, bitmap) in &desired {
            let prefix = match ip {
                std::net::IpAddr::V4(_) => format!("{}/32", ip),
                std::net::IpAddr::V6(_) => format!("{}/128", ip),
            };
            match cidr_to_lpm_key(&prefix) {
                Ok(lpm_key) => match ebpf.set_domain_ip_bitmap(&lpm_key, bitmap) {
                    Err(e) => {
                        debug!("DNS rebuild: failed to set {}: {}", ip, e);
                    }
                    _ => {
                        rebuilt += 1;
                    }
                },
                Err(e) => debug!("DNS rebuild: invalid IP {}: {}", ip, e),
            }
        }

        let stale: Vec<std::net::IpAddr> = self
            .pushed_ips
            .iter()
            .map(|e| *e.key())
            .filter(|ip| !desired.contains_key(ip))
            .collect();
        let removed = stale.len();
        for ip in stale {
            let prefix = match ip {
                std::net::IpAddr::V4(_) => format!("{}/32", ip),
                std::net::IpAddr::V6(_) => format!("{}/128", ip),
            };
            if let Ok(lpm_key) = cidr_to_lpm_key(&prefix) {
                let _ = ebpf.remove_domain_ip_bitmap(&lpm_key);
            }
            self.pushed_ips.remove(&ip);
        }
        for ip in desired.keys() {
            self.pushed_ips.insert(*ip, ());
        }
        drop(ebpf);

        debug!(
            "DNS rebuild: {} domain route entries rebuilt, {} stale removed",
            rebuilt, removed
        );
    }

    /// Refresh all known DNS-to-BPF routes (periodic worker).
    async fn refresh_all_routes(&self) {
        debug!("DNS controller: refreshing BPF domain routes");
        // Stub: DnsForwarder handles TTL expiry; DOMAIN_ROUTING_MAP entries
        // are pushed on each successful resolve via notify_bpf_update and
        // rebuilt after routing reloads via rebuild_domain_routes.
    }
}

/// Delegate controller admission to the shared strict predicate used by UDP
/// provenance and both dispatch paths; forwarding behavior remains unchanged.
fn is_dns_query(data: &[u8]) -> bool {
    super::is_exact_dns_query(data)
}

fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 2)
}

/// REFUSED (rcode 5) for concurrency-limit degradation: tells the client to
/// back off instead of retrying into the storm (unlike SERVFAIL).
fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    build_dns_error_response(query, 5)
}

/// Minimal error response: the query with QR/RA set and the given rcode.
/// Counts are left as-is (a query has no answers anyway).
pub(crate) fn build_dns_error_response(query: &[u8], rcode: u8) -> Vec<u8> {
    if query.len() < 12 {
        return vec![0u8; 12];
    }
    let mut resp = query.to_vec();
    resp[2] = 0x81; // QR + RD
    resp[3] = 0x80 | (rcode & 0x0f); // RA + rcode
    resp
}

/// Rewrite the response's transaction ID to match this query — required
/// when a singleflight leader's response is shared with waiting clients.
fn with_own_txid(mut resp: Vec<u8>, query: &[u8]) -> Vec<u8> {
    if resp.len() >= 2 && query.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
    resp
}

async fn write_tcp_dns_response(stream: &mut TcpStream, response: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let resp_len = (response.len() as u16).to_be_bytes();
    stream.write_all(&resp_len).await?;
    stream.write_all(response).await?;
    Ok(())
}

/// Spawn DNS controller background workers.
/// Should be called after ControlPlane construction.
pub fn spawn_dns_workers(dns_controller: &Arc<DnsController>) -> tokio::task::JoinHandle<()> {
    dns_controller.spawn_route_refresh_worker()
}

#[cfg(test)]
mod singleflight_tests {
    use super::*;
    use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
    use crate::routing::Router;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SlowUpstream {
        calls: AtomicUsize,
        delay: Duration,
        response: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for SlowUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(self.response.clone())
        }
    }

    fn test_controller(
        response: Vec<u8>,
        delay: Duration,
    ) -> (Arc<DnsController>, Arc<SlowUpstream>) {
        let upstream = Arc::new(SlowUpstream {
            calls: AtomicUsize::new(0),
            delay,
            response,
        });
        let forwarder = Arc::new(DnsForwarder::new(
            upstream.clone(),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            Arc::new(
                crate::dns::routing::DnsRouter::new_from_dns_config(
                    &honk_config::dns::DnsConfig::default(),
                )
                .unwrap(),
            ),
        ));
        let controller = Arc::new(DnsController::new(
            forwarder,
            Arc::new(RwLock::new(Box::new(
                crate::ebpf::mock::MockEbpfBackend::new(),
            ))),
            Arc::new(RwLock::new(Router::new(&[], "direct").unwrap())),
        ));
        (controller, upstream)
    }

    fn query_with_txid(domain: &str, txid: u16) -> Vec<u8> {
        let mut q = crate::dns::forwarder::build_dns_query(domain, 1);
        q[0..2].copy_from_slice(&txid.to_be_bytes());
        q
    }

    fn response_with_txid(domain: &str, txid: u16) -> Vec<u8> {
        let mut resp = crate::dns::forwarder::build_dns_query(domain, 1);
        resp[0..2].copy_from_slice(&txid.to_be_bytes());
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp
    }

    #[test]
    fn dns_control_strict_query_predicate_rejects_unconsumed_or_forged_wire() {
        let query = crate::dns::forwarder::build_dns_query("example.com", 1);
        assert!(is_dns_query(&query));

        let mut forged_question_count = query.clone();
        forged_question_count[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(!is_dns_query(&forged_question_count));

        let mut trailing_junk = query.clone();
        trailing_junk.push(0xde);
        assert!(!is_dns_query(&trailing_junk));

        let mut truncated_rr = query;
        truncated_rr[6..8].copy_from_slice(&1u16.to_be_bytes());
        truncated_rr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01]);
        assert!(!is_dns_query(&truncated_rr));
    }

    /// Concurrent duplicate queries share one upstream flight, and each
    /// waiter gets the response with its OWN transaction id restored.
    #[tokio::test]
    async fn singleflight_dedups_and_restores_txid() {
        let (controller, upstream) = test_controller(
            response_with_txid("example.com", 0x1111),
            Duration::from_millis(100),
        );
        let q1 = query_with_txid("example.com", 0xaaaa);
        let q2 = query_with_txid("example.com", 0xbbbb);
        let (r1, r2) = tokio::join!(
            controller.resolve_with_singleflight(&q1, None),
            controller.resolve_with_singleflight(&q2, None),
        );
        assert_eq!(&r1[0..2], &q1[0..2], "waiter 1 keeps its own txid");
        assert_eq!(&r2[0..2], &q2[0..2], "waiter 2 keeps its own txid");
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            1,
            "deduped to one upstream query"
        );
    }
}
