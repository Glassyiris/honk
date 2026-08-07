use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::DnsProtocol;

/// DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub upstream: Vec<DnsUpstream>,
    #[serde(default)]
    pub routing: DnsRouting,
    /// DNS request strategy
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// Cache settings
    #[serde(default)]
    pub cache: DnsCacheConfig,
    /// Per-domain fixed TTL overrides. Key = domain, value = TTL seconds.
    /// A value of 0 means "never cache".
    #[serde(default)]
    pub fixed_domain_ttl: HashMap<String, u32>,
}

/// A DNS upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsUpstream {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub protocol: DnsProtocol,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// Outbound node/group to route this upstream through (e.g. `proxy`).
    ///
    /// dae syntax: `name: 'https://dns.google/dns-query' -> proxy`
    /// (legacy alias: `... outbound: proxy`). When set, queries go via the
    /// node/group instead of a direct connection.
    #[serde(default)]
    pub outbound: Option<String>,
}

/// DNS routing configuration.
///
/// Supports both the new request/response rules and the legacy flat
/// `rules` + `fallback` format. When `request.rules` is empty (e.g.
/// after serde from old JSON), `DnsRouter::new` converts legacy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRouting {
    /// New-style request routing rules.
    #[serde(default)]
    pub request: DnsRequestRouting,
    /// New-style response routing rules.
    #[serde(default)]
    pub response: DnsResponseRouting,
    /// LEGACY flat rules for old JSON/tests — converted in `DnsRouter::new`
    /// when `request.rules` is empty.
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    /// Legacy fallback upstream name.
    #[serde(default = "default_fallback")]
    pub fallback: String,
}

fn default_fallback() -> String {
    "upstream".to_string()
}

impl Default for DnsRouting {
    fn default() -> Self {
        Self {
            request: DnsRequestRouting::default(),
            response: DnsResponseRouting::default(),
            rules: vec![],
            fallback: default_fallback(),
        }
    }
}

/// A legacy DNS routing rule (domain → upstream).
///
/// Kept as a type alias for backward compatibility. New code should
/// use [`DnsRequestRouting`] instead.
pub type DnsRule = DnsLegacyRule;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLegacyRule {
    /// Domain pattern ("suffix:.cn" | "full:x" | "keyword:" | "regex:" | bare full)
    pub domain: String,
    /// Upstream name to route to
    pub upstream: String,
}

/// Request action: what to do with the DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestAction {
    /// Drop the query — return empty success answer.
    Reject,
    /// Bypass routing, send directly to the connection's original destination.
    AsIs,
    /// Send to the named upstream.
    Upstream(String),
}

impl DnsRequestAction {
    /// Parse from a config token.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "reject" => DnsRequestAction::Reject,
            "asis" => DnsRequestAction::AsIs,
            other => DnsRequestAction::Upstream(other.to_string()),
        }
    }
}

/// Response action: what to do with the DNS response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnsResponseAction {
    /// Accept the response as-is.
    #[default]
    Accept,
    /// Drop the response — return empty success answer (NODATA).
    Reject,
    /// Re-query the specified upstream.
    Upstream(String),
}

impl DnsResponseAction {
    /// Parse from a config token.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "accept" => DnsResponseAction::Accept,
            "reject" => DnsResponseAction::Reject,
            other => DnsResponseAction::Upstream(other.to_string()),
        }
    }
}

/// How to match a domain name.
#[derive(Debug, Clone)]
pub enum DnsDomainMatcher {
    /// Exact full-domain match.
    Full(String),
    /// Dot-boundary suffix match (e.g. `.cn` matches `baidu.cn` but not `notcn`).
    Suffix(String),
    /// Case-sensitive substring match.
    Keyword(String),
    /// Regex match against the domain.
    Regex(String),
    /// geosite code — expanded at router build time.
    Geosite(String),
}

/// One AND-ed condition. Matchers within the condition are OR-ed.
#[derive(Debug, Clone)]
pub enum DnsCond {
    /// Match the query name.
    Qname {
        /// Negate this condition.
        not: bool,
        /// Domain matchers (OR-ed within).
        matchers: Vec<DnsDomainMatcher>,
    },
    /// Match the query type.
    Qtype {
        /// Negate this condition.
        not: bool,
        /// QTYPE values (OR-ed within).
        types: Vec<u16>,
    },
    /// Response only: match the upstream that produced the answer.
    Upstream {
        /// Negate this condition.
        not: bool,
        /// Upstream names (OR-ed within).
        names: Vec<String>,
    },
    /// Response only: match answer IPs.
    Ip {
        /// Negate this condition.
        not: bool,
        /// CIDRs to match against.
        cidrs: Vec<String>,
        /// GeoIP codes to expand.
        geoip: Vec<String>,
    },
}

/// A single request routing rule.
///
/// All conditions are AND-ed; first matching rule wins.
#[derive(Debug, Clone)]
pub struct DnsRequestRule {
    /// Conditions that must all be true.
    pub conditions: Vec<DnsCond>,
    /// Action to take when all conditions match.
    pub action: DnsRequestAction,
}

/// A single response routing rule.
///
/// All conditions are AND-ed; first matching rule wins.
#[derive(Debug, Clone)]
pub struct DnsResponseRule {
    /// Conditions that must all be true.
    pub conditions: Vec<DnsCond>,
    /// Action to take when all conditions match.
    pub action: DnsResponseAction,
}

/// Request routing: rules + fallback action.
#[derive(Debug, Clone)]
pub struct DnsRequestRouting {
    /// Ordered list of rules.
    pub rules: Vec<DnsRequestRule>,
    /// Fallback action when no rule matches. Default: `Upstream("default")`.
    pub fallback: DnsRequestAction,
}

impl Default for DnsRequestRouting {
    fn default() -> Self {
        Self {
            rules: vec![],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        }
    }
}

/// Response routing: rules + fallback action.
#[derive(Debug, Clone)]
pub struct DnsResponseRouting {
    /// Ordered list of rules.
    pub rules: Vec<DnsResponseRule>,
    /// Fallback action when no rule matches. Default: `Accept`.
    pub fallback: DnsResponseAction,
}

impl Default for DnsResponseRouting {
    fn default() -> Self {
        Self {
            rules: vec![],
            fallback: DnsResponseAction::Accept,
        }
    }
}

// All the new routing types live outside the serde tree.  `DnsRouting` only
// serialises/deserialises the legacy fields; the new request/response blocks
// are populated by the parser, so the manual impls below accept-and-ignore
// any serialized form and deserialize back to the defaults.

impl Serialize for DnsRequestRouting {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Never serialised via JSON — the parser writes directly.
        s.serialize_unit()
    }
}
impl<'de> Deserialize<'de> for DnsRequestRouting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept anything and return default — populated by parser later.
        let _ = serde::de::IgnoredAny::deserialize(d)?;
        Ok(Self::default())
    }
}

impl Serialize for DnsResponseRouting {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_unit()
    }
}
impl<'de> Deserialize<'de> for DnsResponseRouting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let _ = serde::de::IgnoredAny::deserialize(d)?;
        Ok(Self::default())
    }
}

impl DnsRouting {
    /// Convert legacy rules into request rules.
    pub fn convert_legacy_rules(&self) -> DnsRequestRouting {
        let mut rules = Vec::with_capacity(self.rules.len());
        for legacy in &self.rules {
            let (matcher, _) = parse_legacy_pattern(&legacy.domain);
            rules.push(DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![matcher],
                }],
                action: DnsRequestAction::Upstream(legacy.upstream.clone()),
            });
        }
        DnsRequestRouting {
            rules,
            fallback: DnsRequestAction::Upstream(self.fallback.clone()),
        }
    }
}

/// Parse a legacy rule pattern into a DnsDomainMatcher.
fn parse_legacy_pattern(pattern: &str) -> (DnsDomainMatcher, String) {
    if let Some(suffix) = pattern.strip_prefix("suffix:") {
        (
            DnsDomainMatcher::Suffix(suffix.to_string()),
            pattern.to_string(),
        )
    } else if let Some(keyword) = pattern.strip_prefix("keyword:") {
        (
            DnsDomainMatcher::Keyword(keyword.to_string()),
            pattern.to_string(),
        )
    } else if let Some(full) = pattern.strip_prefix("full:") {
        (
            DnsDomainMatcher::Full(full.to_string()),
            pattern.to_string(),
        )
    } else if let Some(regex_str) = pattern.strip_prefix("regex:") {
        (
            DnsDomainMatcher::Regex(regex_str.to_string()),
            pattern.to_string(),
        )
    } else {
        (
            DnsDomainMatcher::Full(pattern.to_string()),
            pattern.to_string(),
        )
    }
}

/// Parse a QTYPE token (e.g. "a", "AAAA", "https", "65") into a `u16`.
///
/// Returns `None` for unrecognised names.
pub fn parse_qtype_token(s: &str) -> Option<u16> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u16>() {
        return Some(n);
    }

    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "AAAA" => Some(28),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "TXT" => Some(16),
        "NS" => Some(2),
        "PTR" => Some(12),
        "SOA" => Some(6),
        "SRV" => Some(33),
        "HTTPS" => Some(65),
        "SVCB" => Some(64),
        "ANY" | "*" => Some(255),
        _ => None,
    }
}

/// DNS resolution strategy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsStrategy {
    /// Prefer IPv4
    PreferIpv4,
    /// Prefer IPv6
    PreferIpv6,
    /// IPv4 only
    Ipv4Only,
    /// IPv6 only
    Ipv6Only,
    /// Both IPv4 and IPv6
    #[default]
    Both,
}

/// DNS cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    /// Enable DNS cache
    #[serde(default = "crate::types::default_true")]
    pub enabled: bool,
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl: u64,
    /// Maximum cache entries
    #[serde(default = "default_cache_size")]
    pub max_size: usize,
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
            enabled: crate::types::default_true(),
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
                outbound: None,
            }],
            routing: DnsRouting::default(),
            strategy: DnsStrategy::Both,
            cache: DnsCacheConfig {
                enabled: true,
                ttl: 600,
                max_size: 10000,
            },
            fixed_domain_ttl: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a `[dns]` section without `cache` must still get the
    /// documented defaults (max_size=10000). The derived `Default` used to
    /// produce max_size=0 which broke cache construction at runtime.
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

    #[test]
    fn test_default_dns_config_works() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.upstream.len(), 1);
        assert_eq!(cfg.routing.fallback, "upstream");
        assert!(cfg.routing.request.rules.is_empty());
        assert!(cfg.routing.response.rules.is_empty());
        assert!(matches!(cfg.strategy, DnsStrategy::Both));
    }

    #[test]
    fn missing_strategy_uses_both_for_serde_configs() {
        let cfg: DnsConfig = serde_json::from_str(
            r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}]}"#,
        )
        .unwrap();
        assert!(matches!(cfg.strategy, DnsStrategy::Both));
    }

    #[test]
    fn test_parse_qtype_token() {
        assert_eq!(parse_qtype_token("A"), Some(1));
        assert_eq!(parse_qtype_token("aaaa"), Some(28));
        assert_eq!(parse_qtype_token("HTTPS"), Some(65));
        assert_eq!(parse_qtype_token("svcb"), Some(64));
        assert_eq!(parse_qtype_token("65"), Some(65));
        assert_eq!(parse_qtype_token("999"), Some(999));
        assert_eq!(parse_qtype_token("unknown"), None);
    }

    #[test]
    fn test_dns_request_action_parse() {
        assert_eq!(DnsRequestAction::parse("reject"), DnsRequestAction::Reject);
        assert_eq!(DnsRequestAction::parse("asis"), DnsRequestAction::AsIs);
        assert_eq!(
            DnsRequestAction::parse("alidns"),
            DnsRequestAction::Upstream("alidns".to_string())
        );
    }

    #[test]
    fn test_dns_response_action_parse() {
        assert_eq!(
            DnsResponseAction::parse("accept"),
            DnsResponseAction::Accept
        );
        assert_eq!(
            DnsResponseAction::parse("reject"),
            DnsResponseAction::Reject
        );
        assert_eq!(
            DnsResponseAction::parse("alidns"),
            DnsResponseAction::Upstream("alidns".to_string())
        );
    }

    #[test]
    fn test_legacy_rules_serde_backcompat() {
        let json =
            r#"{"rules":[{"domain":"suffix:.cn","upstream":"alidns"}],"fallback":"default"}"#;
        let routing: DnsRouting = serde_json::from_str(json).unwrap();
        assert_eq!(routing.rules.len(), 1);
        assert_eq!(routing.rules[0].domain, "suffix:.cn");
        assert_eq!(routing.rules[0].upstream, "alidns");
        assert_eq!(routing.fallback, "default");
        // New request rules should be empty (legacy only)
        assert!(routing.request.rules.is_empty());
    }

    #[test]
    fn test_legacy_conversion() {
        let routing = DnsRouting {
            rules: vec![
                DnsLegacyRule {
                    domain: "suffix:.cn".into(),
                    upstream: "alidns".into(),
                },
                DnsLegacyRule {
                    domain: "full:google.com".into(),
                    upstream: "googledns".into(),
                },
            ],
            fallback: "default".into(),
            ..Default::default()
        };
        let converted = routing.convert_legacy_rules();
        assert_eq!(converted.rules.len(), 2);
        assert_eq!(
            converted.fallback,
            DnsRequestAction::Upstream("default".to_string())
        );
    }

    #[test]
    fn legacy_conversion_preserves_rule_order_and_matcher_kind() {
        let routing = DnsRouting {
            rules: vec![
                DnsLegacyRule {
                    domain: "suffix:.cn".into(),
                    upstream: "cn".into(),
                },
                DnsLegacyRule {
                    domain: "keyword:ads".into(),
                    upstream: "block".into(),
                },
                DnsLegacyRule {
                    domain: "full:example.com".into(),
                    upstream: "exact".into(),
                },
                DnsLegacyRule {
                    domain: "regex:^api\\\\.".into(),
                    upstream: "regex".into(),
                },
                DnsLegacyRule {
                    domain: "bare.example".into(),
                    upstream: "bare".into(),
                },
            ],
            ..Default::default()
        };

        let converted = routing.convert_legacy_rules();
        let actions = converted
            .rules
            .iter()
            .map(|rule| &rule.action)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                &DnsRequestAction::Upstream("cn".into()),
                &DnsRequestAction::Upstream("block".into()),
                &DnsRequestAction::Upstream("exact".into()),
                &DnsRequestAction::Upstream("regex".into()),
                &DnsRequestAction::Upstream("bare".into()),
            ]
        );

        fn matcher_kind(rule: &DnsRequestRule) -> &DnsDomainMatcher {
            match &rule.conditions[0] {
                DnsCond::Qname { matchers, .. } => &matchers[0],
                _ => panic!("legacy conversion must produce qname conditions"),
            }
        }
        assert!(matches!(
            matcher_kind(&converted.rules[0]),
            DnsDomainMatcher::Suffix(value) if value == ".cn"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[1]),
            DnsDomainMatcher::Keyword(value) if value == "ads"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[2]),
            DnsDomainMatcher::Full(value) if value == "example.com"
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[3]),
            DnsDomainMatcher::Regex(value) if value == "^api\\\\."
        ));
        assert!(matches!(
            matcher_kind(&converted.rules[4]),
            DnsDomainMatcher::Full(value) if value == "bare.example"
        ));
    }

    #[test]
    fn zero_cache_size_remains_accepted_for_runtime_clamping() {
        let cfg: DnsConfig =
            serde_json::from_str(r#"{"cache":{"enabled":true,"ttl":0,"max_size":0}}"#).unwrap();
        assert_eq!(cfg.cache.max_size, 0);
        assert_eq!(cfg.cache.ttl, 0);
    }

    #[test]
    fn test_fixed_domain_ttl_serde() {
        let json = r#"{"upstream":[{"name":"a","address":"223.5.5.5:53","protocol":"udp"}],"fixed_domain_ttl":{"a.test":0,"b.test":300}}"#;
        let cfg: DnsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.fixed_domain_ttl.get("a.test"), Some(&0u32));
        assert_eq!(cfg.fixed_domain_ttl.get("b.test"), Some(&300u32));
    }
}
