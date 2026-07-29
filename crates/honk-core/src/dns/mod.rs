//! DNS resolver, forwarder, cache, and routing.
//!
//! ## Modules
//!
//! - `routing` — DNS request routing (domain → upstream)
//! - `cache` — DNS response cache with LRU and TTL
//! - `endpoint` — upstream address / SNI / path parsing
//! - `transport` — pooled UDP/TCP/DoT/DoH/DoQ/DoH3 clients
//! - `upstream_pool` — per-upstream DNS query management
//! - `forwarder` — DNS forwarding engine (cache + upstream + routing)
//! - `persist` — optional cache.db persistence for DNS answers
//! - `wire` — shared wire-format parsing helpers
//!
//! ## `DnsResolver`
//!
//! Application-level domain → IP helper used by the control plane (SNI
//! reality checks, etc.). Always resolves through a [`DnsForwarder`] so
//! the same upstream stack (including encrypted DNS and `outbound:`) is
//! shared with intercepted client queries. There is no separate stub
//! resolver dependency.

pub mod cache;
pub mod endpoint;
pub mod engine;
pub mod forwarder;
pub mod outcome;
pub mod persist;
pub mod planner;
pub mod policy;
pub mod query;
pub mod response;
pub mod routing;
pub mod transport;
pub mod upstream_pool;
pub(crate) mod wire;

use honk_config::dns::DnsConfig;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

/// A resolved DNS result.
#[derive(Debug, Clone)]
pub struct ResolvedAddr {
    /// Resolved IPv4 addresses
    pub ipv4: Vec<IpAddr>,
    /// Resolved IPv6 addresses
    pub ipv6: Vec<IpAddr>,
    /// Minimum TTL from all records
    pub min_ttl: u32,
}

/// DNS resolver for honk-core.
///
/// Always backs onto a [`forwarder::DnsForwarder`] (built from config or
/// injected). A small process-local domain cache sits in front to avoid
/// re-issuing A+AAAA pairs for hot names.
pub struct DnsResolver {
    /// In-memory cache for fast domain lookups (application layer)
    cache: Arc<RwLock<lru::LruCache<String, (ResolvedAddr, std::time::Instant)>>>,
    /// Upstream wire-format forwarder (UDP/TCP/DoT/DoH/DoQ/DoH3)
    forwarder: Arc<crate::dns::forwarder::DnsForwarder>,
}

impl DnsResolver {
    /// Build a resolver with a private forwarder from `config.dns` upstreams.
    ///
    /// Used by tests and any caller that does not already own a shared
    /// forwarder. Production prefers [`Self::with_forwarder`] so intercepted
    /// DNS and internal lookups share one pool/cache.
    pub fn new(config: &DnsConfig) -> anyhow::Result<Self> {
        let forwarder = build_forwarder_from_config(config)?;
        Ok(Self {
            cache: new_app_cache(config.cache.max_size),
            forwarder,
        })
    }

    /// Create a resolver that reuses an existing shared DNS forwarder.
    pub fn with_forwarder(
        config: &DnsConfig,
        forwarder: Arc<crate::dns::forwarder::DnsForwarder>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cache: new_app_cache(config.cache.max_size),
            forwarder,
        })
    }

    /// Shared forwarder (for tests / diagnostics).
    pub fn forwarder(&self) -> Arc<crate::dns::forwarder::DnsForwarder> {
        self.forwarder.clone()
    }

    /// Resolve a domain name to IP addresses (A + AAAA via the forwarder).
    pub async fn resolve(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            anyhow::bail!("empty domain");
        }

        // Literal IP short-circuit — no upstream round-trip.
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(match ip {
                IpAddr::V4(_) => ResolvedAddr {
                    ipv4: vec![ip],
                    ipv6: vec![],
                    min_ttl: 3600,
                },
                IpAddr::V6(_) => ResolvedAddr {
                    ipv4: vec![],
                    ipv6: vec![ip],
                    min_ttl: 3600,
                },
            });
        }

        {
            let cache = self.cache.read().await;
            if let Some((addrs, timestamp)) = cache.peek(&domain) {
                let elapsed = timestamp.elapsed().as_secs();
                if elapsed < addrs.min_ttl as u64 {
                    debug!("DNS cache hit: {} → {:?}", domain, addrs.ipv4.first());
                    return Ok(addrs.clone());
                }
            }
        }

        debug!("DNS lookup: {}", domain);
        self.resolve_via_forwarder(&domain, &self.forwarder).await
    }

    /// Resolve a domain and return the first IPv4 address.
    pub async fn resolve_first_ipv4(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv4.first().copied())
    }

    /// Resolve a domain and return the first IPv6 address.
    pub async fn resolve_first_ipv6(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv6.first().copied())
    }

    /// Resolve a domain through the DNS forwarder (A then AAAA).
    async fn resolve_via_forwarder(
        &self,
        domain: &str,
        forwarder: &crate::dns::forwarder::DnsForwarder,
    ) -> anyhow::Result<ResolvedAddr> {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        let mut min_ttl = 60u32;

        // Query A record
        let a_query = crate::dns::forwarder::build_dns_query(domain, 1);
        match forwarder.resolve(&a_query).await {
            Ok(a_resp) => {
                if let Some((_, ttl, addrs)) = parse_a_aaaa_from_response(&a_resp) {
                    ipv4 = addrs
                        .into_iter()
                        .filter(|ip| matches!(ip, IpAddr::V4(_)))
                        .collect();
                    min_ttl = min_ttl.min(ttl);
                }
            }
            Err(e) => debug!("A lookup for {} failed: {e}", domain),
        }

        // Query AAAA record
        let aaaa_query = crate::dns::forwarder::build_dns_query(domain, 28);
        match forwarder.resolve(&aaaa_query).await {
            Ok(aaaa_resp) => {
                if let Some((_, ttl, addrs)) = parse_a_aaaa_from_response(&aaaa_resp) {
                    ipv6 = addrs
                        .into_iter()
                        .filter(|ip| matches!(ip, IpAddr::V6(_)))
                        .collect();
                    min_ttl = min_ttl.min(ttl);
                }
            }
            Err(e) => debug!("AAAA lookup for {} failed: {e}", domain),
        }

        // Last-resort: system resolver (bootstrap may also help node hostnames).
        if ipv4.is_empty() && ipv6.is_empty() {
            match honk_outbound::bootstrap::resolve(domain).await {
                Ok(ips) if !ips.is_empty() => {
                    for ip in ips {
                        match ip {
                            IpAddr::V4(_) => ipv4.push(ip),
                            IpAddr::V6(_) => ipv6.push(ip),
                        }
                    }
                    min_ttl = 60;
                }
                Ok(_) => anyhow::bail!("no A/AAAA records for {domain}"),
                Err(e) => anyhow::bail!("resolve {domain}: {e}"),
            }
        }

        let resolved = ResolvedAddr {
            ipv4,
            ipv6,
            min_ttl,
        };

        {
            let mut cache = self.cache.write().await;
            cache.put(
                domain.to_string(),
                (resolved.clone(), std::time::Instant::now()),
            );
        }

        debug!(
            "DNS resolved: {} → {:?} (TTL: {}s)",
            domain,
            resolved.ipv4.first(),
            resolved.min_ttl
        );

        Ok(resolved)
    }
}

fn new_app_cache(
    max_size: usize,
) -> Arc<RwLock<lru::LruCache<String, (ResolvedAddr, std::time::Instant)>>> {
    let cap = NonZeroUsize::new(max_size.max(1)).expect("max_size >= 1");
    Arc::new(RwLock::new(lru::LruCache::new(cap)))
}

/// Build a standalone forwarder from dns config (used by [`DnsResolver::new`]).
fn build_forwarder_from_config(
    config: &DnsConfig,
) -> anyhow::Result<Arc<crate::dns::forwarder::DnsForwarder>> {
    let dns_cache = Arc::new(Mutex::new(cache::DnsCache::new(config.cache.max_size)));
    let router = Arc::new(routing::DnsRouter::new_from_dns_config(config)?);
    let pool = Arc::new(upstream_pool::UpstreamPool::new(
        &config.upstream,
        router.clone(),
    )?);
    Ok(Arc::new(
        forwarder::DnsForwarder::new(pool, dns_cache, router)
            .with_strategy(config.strategy.clone())
            .with_cache_enabled(config.cache.enabled)
            .with_cache_ttl(config.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(config)?,
    ))
}

/// Parse A/AAAA records from a DNS response.
/// Returns (domain, min_ttl, ips) on success.
fn parse_a_aaaa_from_response(response: &[u8]) -> Option<(String, u32, Vec<IpAddr>)> {
    let pairs = wire::extract_ips_with_ttl(response);
    if pairs.is_empty() {
        return None;
    }
    let mut min_ttl = u32::MAX;
    let mut ips = Vec::with_capacity(pairs.len());
    for (ip, ttl) in pairs {
        if ttl > 0 {
            min_ttl = min_ttl.min(ttl);
        }
        ips.push(ip);
    }
    if min_ttl == u32::MAX {
        min_ttl = 60;
    }
    Some((String::new(), min_ttl, ips))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.upstream.len(), 1);
        assert_eq!(config.upstream[0].address, "223.5.5.5:53");
    }

    #[tokio::test]
    async fn test_resolver_creation() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config);
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_resolver_literal_ip() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config).unwrap();
        let r = resolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(r.ipv4.len(), 1);
        assert!(r.ipv6.is_empty());
    }

    #[tokio::test]
    async fn test_resolver_system_fallback_localhost() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config).unwrap();
        // May hit upstream or system fallback; must not panic.
        let _ = resolver.resolve("localhost").await;
    }
}
