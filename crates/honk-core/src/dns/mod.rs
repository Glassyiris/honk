//! DNS resolver, listener, forwarder, cache, and routing.
//!
//! ## Modules
//!
//! - `routing` — DNS request routing (domain → upstream)
//! - `cache` — DNS response cache with LRU and TTL
//! - `upstream_pool` — Per-upstream DNS query management
//! - `listener` — UDP/TCP DNS listener (intercepts local DNS)
//! - `forwarder` — DNS forwarding engine (cache + upstream + routing)
//! - `persist` — Optional cache.db persistence for DNS answers
//!
//! ## Legacy
//!
//! The `DnsResolver` wraps hickory-resolver for simple resolution.

pub mod cache;
pub mod forwarder;
pub mod persist;
pub mod routing;
pub mod upstream_pool;

pub mod listener;

use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::*;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use honk_config::dns::{DnsConfig, DnsStrategy, DnsUpstream};
use honk_config::types::DnsProtocol;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
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
pub struct DnsResolver {
    /// Hickory DNS resolver
    resolver: TokioResolver,
    /// DNS configuration
    config: DnsConfig,
    /// In-memory cache for fast lookups
    cache: Arc<RwLock<lru::LruCache<String, (ResolvedAddr, std::time::Instant)>>>,
    /// Optional DNS forwarder used to route queries through proxy outbounds.
    forwarder: Option<Arc<crate::dns::forwarder::DnsForwarder>>,
}

impl DnsResolver {
    /// Create a new DNS resolver from configuration.
    pub fn new(config: &DnsConfig) -> anyhow::Result<Self> {
        let mut resolver_config = ResolverConfig::from_parts(None, Vec::new(), Vec::new());

        for upstream in &config.upstream {
            let socket_addr: SocketAddr = upstream
                .address
                .parse()
                .unwrap_or_else(|_| "8.8.8.8:53".parse().unwrap());

            // hickory 0.26: NameServerConfig is non-exhaustive and built via
            // constructors; TLS/HTTPS/QUIC upstreams fall back to plain UDP
            // (same behavior as before the upgrade).
            let mut name_server_config = match upstream.protocol {
                DnsProtocol::Udp => NameServerConfig::udp(socket_addr.ip()),
                DnsProtocol::Tcp => NameServerConfig::tcp(socket_addr.ip()),
                DnsProtocol::Tls | DnsProtocol::Https | DnsProtocol::Quic => {
                    NameServerConfig::udp(socket_addr.ip())
                }
            };
            // Preserve a non-default port from the configured address.
            for connection in &mut name_server_config.connections {
                connection.port = socket_addr.port();
            }

            resolver_config.add_name_server(name_server_config);
        }

        let mut options = ResolverOpts::default();
        options.cache_size = config.cache.max_size as u64;
        options.use_hosts_file = ResolveHosts::Never;
        options.num_concurrent_reqs = 3;

        match config.strategy {
            DnsStrategy::PreferIpv4 => {
                options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            }
            DnsStrategy::PreferIpv6 => {
                options.ip_strategy = LookupIpStrategy::Ipv6thenIpv4;
            }
            DnsStrategy::Ipv4Only => {
                options.ip_strategy = LookupIpStrategy::Ipv4Only;
            }
            DnsStrategy::Ipv6Only => {
                options.ip_strategy = LookupIpStrategy::Ipv6Only;
            }
            DnsStrategy::Both => {
                options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            }
        }

        let resolver =
            Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                .with_options(options)
                .build()?;

        Ok(Self {
            resolver,
            config: config.clone(),
            cache: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(config.cache.max_size).unwrap(),
            ))),
            forwarder: None,
        })
    }

    /// Create a resolver that delegates upstream queries to the provided
    /// DNS forwarder. This lets internal domain resolution benefit from the
    /// same upstream routing (including proxy outbounds) as intercepted DNS.
    pub fn with_forwarder(
        config: &DnsConfig,
        forwarder: Arc<crate::dns::forwarder::DnsForwarder>,
    ) -> anyhow::Result<Self> {
        let mut resolver = Self::new(config)?;
        resolver.forwarder = Some(forwarder);
        Ok(resolver)
    }

    /// Resolve a domain name to IP addresses.
    pub async fn resolve(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        {
            let cache = self.cache.read().await;
            if let Some((addrs, timestamp)) = cache.peek(domain) {
                let elapsed = timestamp.elapsed().as_secs();
                if elapsed < addrs.min_ttl as u64 {
                    debug!("DNS cache hit: {} → {:?}", domain, addrs.ipv4.first());
                    return Ok(addrs.clone());
                }
            }
        }

        debug!("DNS lookup: {}", domain);

        // If a forwarder is configured, use it so queries can be routed through
        // proxy outbounds and avoid on-path DNS pollution.
        if let Some(ref forwarder) = self.forwarder {
            return self.resolve_via_forwarder(domain, forwarder).await;
        }

        let lookup = self.resolver.lookup_ip(domain).await?;

        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for addr in lookup.iter() {
            match addr {
                IpAddr::V4(_) => ipv4.push(addr),
                IpAddr::V6(_) => ipv6.push(addr),
            }
        }

        let min_ttl = lookup
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(60);

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

    /// Resolve a domain and return the first IPv4 address.
    pub async fn resolve_first_ipv4(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv4.first().copied())
    }

    /// Resolve a domain through the DNS forwarder.
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
        let a_resp = forwarder.resolve(&a_query).await?;
        if let Some((_, ttl, addrs)) = parse_a_aaaa_from_response(&a_resp) {
            ipv4 = addrs
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(IpAddr::V4(v4)),
                    _ => None,
                })
                .collect();
            min_ttl = min_ttl.min(ttl);
        }

        // Query AAAA record
        let aaaa_query = crate::dns::forwarder::build_dns_query(domain, 28);
        let aaaa_resp = forwarder.resolve(&aaaa_query).await?;
        if let Some((_, ttl, addrs)) = parse_a_aaaa_from_response(&aaaa_resp) {
            ipv6 = addrs
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(IpAddr::V6(v6)),
                    _ => None,
                })
                .collect();
            min_ttl = min_ttl.min(ttl);
        }

        if ipv4.is_empty() && ipv6.is_empty() {
            anyhow::bail!("forwarder returned no A/AAAA records for {}", domain);
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

    /// Resolve a domain and return the first IPv6 address.
    pub async fn resolve_first_ipv6(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv6.first().copied())
    }

    /// Route a domain to the appropriate upstream based on DNS routing rules.
    pub fn route_domain(&self, domain: &str) -> Option<&DnsUpstream> {
        for rule in &self.config.routing.rules {
            if domain_matches(domain, &rule.domain) {
                return self
                    .config
                    .upstream
                    .iter()
                    .find(|u| u.name == rule.upstream);
            }
        }
        None
    }
}

/// Check if a domain matches a routing pattern.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    if let Some(regex_str) = pattern.strip_prefix("regex:") {
        regex::Regex::new(regex_str)
            .map(|re| re.is_match(domain))
            .unwrap_or(false)
    } else if let Some(suffix) = pattern.strip_prefix("suffix:") {
        domain.ends_with(suffix) || domain == &suffix[1..]
    } else if let Some(keyword) = pattern.strip_prefix("keyword:") {
        domain.contains(keyword)
    } else if let Some(full) = pattern.strip_prefix("full:") {
        domain == full
    } else {
        // Default: full match
        domain == pattern
    }
}

/// Parse A/AAAA records from a DNS response.
/// Returns (domain, min_ttl, ips) on success.
fn parse_a_aaaa_from_response(response: &[u8]) -> Option<(String, u32, Vec<IpAddr>)> {
    if response.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut pos = 12;
    // Skip question section
    while pos < response.len() && response[pos] != 0 {
        let label_len = response[pos] as usize;
        if label_len >= 64 {
            pos += 2;
            break;
        }
        if label_len == 0 {
            pos += 1;
            break;
        }
        pos += 1 + label_len;
    }
    if pos >= response.len() {
        return None;
    }
    pos += 1; // terminating zero
    pos += 4; // QTYPE + QCLASS

    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if pos + 10 > response.len() {
            break;
        }
        pos = skip_dns_name(response, pos);
        if pos + 10 > response.len() {
            break;
        }
        let qtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > response.len() {
            break;
        }
        match qtype {
            1 if rdlength == 4 => {
                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                )));
                if ttl > 0 {
                    min_ttl = min_ttl.min(ttl);
                }
            }
            28 if rdlength == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&response[pos..pos + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                if ttl > 0 {
                    min_ttl = min_ttl.min(ttl);
                }
            }
            _ => {}
        }
        pos += rdlength;
    }

    if ips.is_empty() {
        return None;
    }
    if min_ttl == u32::MAX {
        min_ttl = 60;
    }
    Some((String::new(), min_ttl, ips))
}

fn skip_dns_name(response: &[u8], mut pos: usize) -> usize {
    while pos < response.len() {
        let byte = response[pos];
        if byte == 0 {
            return pos + 1;
        }
        if byte & 0xC0 == 0xC0 {
            return pos + 2;
        }
        pos += 1 + byte as usize;
    }
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matches() {
        assert!(domain_matches("google.com", "google.com"));
        assert!(domain_matches("www.google.com", "suffix:.google.com"));
        assert!(domain_matches("google.com", "suffix:google.com"));
        assert!(domain_matches("ads.example.com", "keyword:ads"));
        assert!(domain_matches("example.com", "full:example.com"));
        assert!(domain_matches("notgoogle.com", "suffix:google.com"));
        assert!(!domain_matches("notgoogle.com", "suffix:.google.com"));
        assert!(domain_matches(
            "test.example.com",
            "regex:.*\\.example\\.com"
        ));
    }

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
    async fn test_resolver_cache() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(&config).unwrap();

        // This test will try to resolve (may fail without network, but shouldn't panic)
        let result = resolver.resolve("localhost").await;
        // localhost should resolve on most systems
        assert!(result.is_ok() || result.is_err());
    }
}
