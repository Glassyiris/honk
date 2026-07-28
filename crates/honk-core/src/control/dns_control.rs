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

/// Max concurrent DNS queries before SERVFAIL degradation.
const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 256;

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

        match self.concurrency_limit.try_acquire() {
            Ok(_permit) => {}
            Err(_) => {
                debug!("DNS concurrency limit reached; sending SERVFAIL");
                let servfail = build_dns_servfail(data);
                let _ =
                    super::send_udp_reply_from_orig_dst(&servfail, client_addr, original_dst).await;
                return Ok(true);
            }
        }

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
            build_dns_servfail(&dns_data)
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

            let resp = if self.concurrency_limit.try_acquire().is_ok() {
                self.resolve_with_singleflight(&dns_data, Some(original_dst))
                    .await
            } else {
                build_dns_servfail(&dns_data)
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
        let cache_key = match crate::dns::forwarder::parse_dns_question(data) {
            Some((domain, qtype)) => format!("{}:{}", domain, qtype),
            None => return self.resolve_and_notify(data, original_dst).await.0,
        };

        let maybe_rx = self.in_flight.get(&cache_key).map(|tx| tx.subscribe());

        if let Some(mut rx) = maybe_rx
            && let Ok(resp) = rx.recv().await
        {
            debug!("DNS singleflight: reused result for {}", cache_key);
            return resp;
        }
        // Sender dropped — fall through to execute the query ourselves.

        let (tx, _) = broadcast::channel(1);
        self.in_flight.insert(cache_key.clone(), tx.clone());

        let (response, _) = self.resolve_and_notify(data, original_dst).await;

        let _ = tx.send(response.clone());
        self.in_flight.remove(&cache_key);

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

fn is_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if data[2] & 0x80 != 0 {
        return false;
    }
    crate::dns::forwarder::parse_dns_question(data).is_some()
}

fn build_dns_servfail(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![0u8; 12];
    }
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x82;
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
