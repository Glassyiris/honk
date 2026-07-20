use serde::{Deserialize, Serialize};

use crate::types::DnsProtocol;

/// DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers
    #[serde(default)]
    pub upstream: Vec<DnsUpstream>,
    /// Routing rules for DNS requests
    #[serde(default)]
    pub routing: DnsRouting,
    /// DNS request strategy
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// Cache settings
    #[serde(default)]
    pub cache: DnsCacheConfig,
    #[serde(default)]
    pub has_response_routing: bool,
}

/// A DNS upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsUpstream {
    /// Display name
    pub name: String,
    /// Server address (ip:port)
    pub address: String,
    /// DNS protocol
    #[serde(default)]
    pub protocol: DnsProtocol,
    /// TLS server name
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// Bootstrap DNS for resolving upstream
    #[serde(default)]
    pub bootstrap: Option<String>,
    /// Outbound node/group to route this upstream through (e.g. `proxy`).
    /// When set, DNS queries to this upstream are sent via the proxy instead
    /// of a direct connection, preventing UDP/TCP DNS hijacking/pollution.
    #[serde(default)]
    pub outbound: Option<String>,
    /// Tags for matching
    #[serde(default)]
    pub tags: Vec<String>,
}

/// DNS routing configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRouting {
    /// Rules for matching DNS requests to upstreams
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    /// Fallback upstream name
    #[serde(default = "default_fallback")]
    pub fallback: String,
}

fn default_fallback() -> String {
    "upstream".to_string()
}

/// A DNS routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRule {
    /// Domain pattern (regex or wildcard)
    pub domain: String,
    /// Upstream name to route to
    pub upstream: String,
}

/// DNS resolution strategy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Prefer IPv4
    #[default]
    PreferIpv4,
    /// Prefer IPv6
    PreferIpv6,
    /// IPv4 only
    Ipv4Only,
    /// IPv6 only
    Ipv6Only,
    /// Both IPv4 and IPv6
    Both,
}

/// DNS cache configuration.
///
/// NOTE: `Default` is implemented manually below (matching the serde field
/// defaults). A derived `Default` would produce `max_size: 0`, which makes
/// `DnsResolver::new` panic on `NonZeroUsize::new(0).unwrap()` whenever a
/// config omits the `[dns.cache]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    /// Enable DNS cache
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl: u64,
    /// Maximum cache entries
    #[serde(default = "default_cache_size")]
    pub max_size: usize,
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    600
}

fn default_cache_size() -> usize {
    10000
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            ttl: default_cache_ttl(),
            max_size: default_cache_size(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream: vec![DnsUpstream {
                name: "default".to_string(),
                address: "223.5.5.5:53".to_string(),
                protocol: DnsProtocol::Udp,
                tls_server_name: None,
                bootstrap: None,
                outbound: None,
                tags: vec![],
            }],
            routing: DnsRouting {
                rules: vec![],
                fallback: "default".to_string(),
            },
            strategy: DnsStrategy::PreferIpv4,
            cache: DnsCacheConfig {
                enabled: true,
                ttl: 600,
                max_size: 10000,
            },
            has_response_routing: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a `[dns]` section without `cache` must still get the
    /// documented defaults (max_size=10000). The derived `Default` used to
    /// produce max_size=0 and panicked `DnsResolver::new` at runtime.
    #[test]
    fn missing_cache_section_uses_nonzero_defaults() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}]}"#,
        )
        .unwrap();
        assert_eq!(cfg.cache.max_size, 10000);
        assert_eq!(cfg.cache.ttl, 600);
        assert!(cfg.cache.enabled);
    }
}
