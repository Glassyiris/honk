use std::net::IpAddr;
use std::sync::Arc;

use honk_config::dns::DnsConfig;
use tokio::sync::Mutex;
use tracing::debug;

use super::cache::DnsCache;
use super::forwarder::{DnsForwarder, build_dns_query};
use super::routing::DnsRouter;
use super::service::DnsService;
use super::upstream_pool::UpstreamPool;

#[derive(Debug, Clone)]
pub struct ResolvedAddr {
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub min_ttl: u32,
}

pub struct DnsResolver {
    service: DnsService,
}

impl DnsResolver {
    pub fn new(config: &DnsConfig) -> anyhow::Result<Self> {
        let forwarder = build_forwarder_from_config(config)?;
        Ok(Self {
            service: DnsService::with_forwarder(forwarder),
        })
    }

    pub fn with_forwarder(
        _config: &DnsConfig,
        forwarder: Arc<DnsForwarder>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            service: DnsService::with_forwarder(forwarder),
        })
    }

    pub(crate) fn with_service(service: DnsService) -> Self {
        Self { service }
    }

    pub fn forwarder(&self) -> Arc<DnsForwarder> {
        self.service.forwarder()
    }

    pub async fn resolve(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            anyhow::bail!("empty domain");
        }
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

        debug!("DNS lookup: {}", domain);
        self.resolve_via_service(&domain).await
    }

    pub async fn resolve_first_ipv4(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv4.first().copied())
    }

    pub async fn resolve_first_ipv6(&self, domain: &str) -> anyhow::Result<Option<IpAddr>> {
        let result = self.resolve(domain).await?;
        Ok(result.ipv6.first().copied())
    }

    async fn resolve_via_service(&self, domain: &str) -> anyhow::Result<ResolvedAddr> {
        let queries = [build_dns_query(domain, 1), build_dns_query(domain, 28)];
        let mut responses = self
            .service
            .resolve_internal_queries(&queries)
            .await
            .into_iter();
        let (mut ipv4, a_ttl) = parsed_family(responses.next(), AddressFamily::Ipv4, domain);
        let (mut ipv6, aaaa_ttl) = parsed_family(responses.next(), AddressFamily::Ipv6, domain);
        let mut min_ttl = 60u32.min(a_ttl).min(aaaa_ttl);

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
                Err(error) => anyhow::bail!("resolve {domain}: {error}"),
            }
        }

        let resolved = ResolvedAddr {
            ipv4,
            ipv6,
            min_ttl,
        };
        debug!(
            "DNS resolved: {} → {:?} (TTL: {}s)",
            domain,
            resolved.ipv4.first(),
            resolved.min_ttl
        );
        Ok(resolved)
    }
}

#[derive(Clone, Copy)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "A",
            Self::Ipv6 => "AAAA",
        }
    }

    const fn accepts(self, ip: &IpAddr) -> bool {
        match self {
            Self::Ipv4 => ip.is_ipv4(),
            Self::Ipv6 => ip.is_ipv6(),
        }
    }
}

fn parsed_family(
    response: Option<anyhow::Result<Vec<u8>>>,
    family: AddressFamily,
    domain: &str,
) -> (Vec<IpAddr>, u32) {
    match response.unwrap_or_else(|| Err(anyhow::anyhow!("missing {} response", family.label()))) {
        Ok(response) => {
            let pairs = super::wire::extract_ips_with_ttl(&response);
            let ttl = pairs
                .iter()
                .filter_map(|(_, ttl)| (*ttl > 0).then_some(*ttl))
                .min()
                .unwrap_or(60);
            (
                pairs
                    .into_iter()
                    .map(|(ip, _)| ip)
                    .filter(|ip| family.accepts(ip))
                    .collect(),
                ttl,
            )
        }
        Err(error) => {
            debug!("{} lookup for {domain} failed: {error}", family.label());
            (Vec::new(), 60)
        }
    }
}

fn build_forwarder_from_config(config: &DnsConfig) -> anyhow::Result<Arc<DnsForwarder>> {
    let dns_cache = Arc::new(Mutex::new(DnsCache::new(config.cache.max_size)));
    let router = Arc::new(DnsRouter::new_from_dns_config(config)?);
    let pool = Arc::new(UpstreamPool::new(&config.upstream, Arc::clone(&router))?);
    Ok(Arc::new(
        DnsForwarder::new(pool, dns_cache, router)
            .with_strategy(config.strategy.clone())
            .with_cache_enabled(config.cache.enabled)
            .with_cache_ttl(config.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(config)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_config_default_has_one_upstream() {
        let config = DnsConfig::default();
        assert_eq!(config.upstream.len(), 1);
        assert_eq!(config.upstream[0].address, "223.5.5.5:53");
    }

    #[test]
    fn resolver_can_be_created_from_default_config() {
        assert!(DnsResolver::new(&DnsConfig::default()).is_ok());
    }

    #[tokio::test]
    async fn resolver_returns_literal_ipv4_without_upstream() {
        let resolver = DnsResolver::new(&DnsConfig::default()).expect("resolver");
        let resolved = resolver.resolve("127.0.0.1").await.expect("literal");
        assert_eq!(
            resolved.ipv4,
            vec!["127.0.0.1".parse::<IpAddr>().expect("IP")]
        );
        assert!(resolved.ipv6.is_empty());
    }
}
