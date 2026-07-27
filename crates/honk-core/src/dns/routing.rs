//! DNS request/response routing.
//!
//! Routes DNS queries to the appropriate upstream based on
//! domain patterns, qtype, and (for responses) answer IPs.
//! Supports dae-shaped request/response rules with negation,
//! geosite/geoip expansion, and fixed per-domain TTL overrides.

use std::collections::HashMap;
use std::net::IpAddr;

use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsResponseAction,
    DnsResponseRouting, DnsRouting,
};

use crate::routing::BinaryLpmTrie;
use crate::routing::GeoAssets;
use crate::routing::GeositeMatcher;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

/// Output of request routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestDecision {
    Reject,
    AsIs,
    Upstream(String),
}

/// Output of response routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseDecision {
    Accept,
    Reject,
    Requery(String),
}

// ---------------------------------------------------------------------------
// Compiled matchers
// ---------------------------------------------------------------------------

/// Pre-compiled domain matcher.
enum CompiledDomainMatcher {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regex(regex::Regex),
    /// geosite — compiled into a GeositeMatcher at router build time.
    Geosite(GeositeMatcher),
}

impl CompiledDomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            // `domain` is already lowercased by the evaluator.
            CompiledDomainMatcher::Full(pattern) => domain == pattern.as_str(),
            CompiledDomainMatcher::Suffix(suffix) => {
                // Dot-boundary: host itself or any parent (`a.b.cn` matches `cn`).
                // `suffix` is stored without a leading dot.
                if domain == suffix.as_str() {
                    return true;
                }
                domain
                    .as_bytes()
                    .get(domain.len().saturating_sub(suffix.len() + 1))
                    .copied()
                    == Some(b'.')
                    && domain.ends_with(suffix.as_str())
            }
            CompiledDomainMatcher::Keyword(keyword) => domain.contains(keyword.as_str()),
            CompiledDomainMatcher::Regex(re) => re.is_match(domain),
            CompiledDomainMatcher::Geosite(m) => m.matches(domain),
        }
    }
}

/// Pre-compiled single condition.
enum CompiledCond {
    Qname {
        not: bool,
        matchers: Vec<CompiledDomainMatcher>,
    },
    Qtype {
        not: bool,
        types: Vec<u16>,
    },
    Upstream {
        not: bool,
        names: Vec<String>,
    },
    Ip {
        not: bool,
        /// Pre-built LPM trie for CIDR matching.
        trie: BinaryLpmTrie,
    },
}

// ---------------------------------------------------------------------------
// Compiled request rule
// ---------------------------------------------------------------------------

struct CompiledRequestRule {
    conditions: Vec<CompiledCond>,
    action: DnsRequestAction,
}

// ---------------------------------------------------------------------------
// Compiled response rule
// ---------------------------------------------------------------------------

struct CompiledResponseRule {
    conditions: Vec<CompiledCond>,
    action: DnsResponseAction,
}

// ---------------------------------------------------------------------------
// DNS Router
// ---------------------------------------------------------------------------

/// DNS router that selects upstreams based on domain, qtype, and response metadata.
pub struct DnsRouter {
    request_rules: Vec<CompiledRequestRule>,
    request_fallback: DnsRequestAction,
    response_rules: Vec<CompiledResponseRule>,
    response_fallback: DnsResponseAction,
    /// Per-domain fixed TTL. Some(0) = never cache; Some(n) = cache with TTL n.
    fixed_domain_ttl: HashMap<String, u32>,
    /// Total rule count (request + response).
    rule_count: usize,
}

impl DnsRouter {
    /// Build a router from the full DnsRouting config.
    ///
    /// Legacy `rules` are converted only when the new-style request ruleset
    /// is empty **and** legacy rules are present. An explicitly empty
    /// request block (with its own fallback) is left alone.
    pub fn new(config: &DnsRouting) -> anyhow::Result<Self> {
        Self::new_with_fixed_ttl(config, &HashMap::new())
    }

    /// Build a router from config + fixed_domain_ttl map.
    pub fn new_with_fixed_ttl(
        config: &DnsRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
    ) -> anyhow::Result<Self> {
        let request_routing = resolve_request_routing(config);
        Self::build(&request_routing, &config.response, fixed_domain_ttl)
    }

    /// Build from a top-level DnsConfig (convenience).
    pub fn new_from_dns_config(dns_config: &honk_config::dns::DnsConfig) -> anyhow::Result<Self> {
        Self::new_with_fixed_ttl(&dns_config.routing, &dns_config.fixed_domain_ttl)
    }

    // -- Internal builder --

    fn build(
        request: &DnsRequestRouting,
        response: &DnsResponseRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
    ) -> anyhow::Result<Self> {
        // Collect geosite + geoip codes from all rules
        let mut geosite_codes: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut geoip_codes: std::collections::HashSet<String> = std::collections::HashSet::new();

        for rule in &request.rules {
            collect_cond_codes(&rule.conditions, &mut geosite_codes, &mut geoip_codes);
        }
        for rule in &response.rules {
            collect_cond_codes(&rule.conditions, &mut geosite_codes, &mut geoip_codes);
        }

        let geo_assets = GeoAssets::load_codes(&geosite_codes, &geoip_codes);

        // Compile request rules
        let mut request_rules = Vec::with_capacity(request.rules.len());
        for rule in &request.rules {
            let compiled_conds = compile_conditions(&rule.conditions, &geo_assets)?;
            request_rules.push(CompiledRequestRule {
                conditions: compiled_conds,
                action: rule.action.clone(),
            });
        }

        // Compile response rules
        let mut response_rules = Vec::with_capacity(response.rules.len());
        for rule in &response.rules {
            let compiled_conds = compile_conditions(&rule.conditions, &geo_assets)?;
            response_rules.push(CompiledResponseRule {
                conditions: compiled_conds,
                action: rule.action.clone(),
            });
        }

        let rule_count = request_rules.len() + response_rules.len();

        Ok(Self {
            request_rules,
            request_fallback: request.fallback.clone(),
            response_rules,
            response_fallback: response.fallback.clone(),
            fixed_domain_ttl: fixed_domain_ttl.clone(),
            rule_count,
        })
    }

    // -----------------------------------------------------------------------
    // Request routing
    // -----------------------------------------------------------------------

    /// Select the action for a DNS request.
    pub fn select_request(&self, domain: &str, qtype: u16) -> DnsRequestDecision {
        let domain_lower = domain.to_lowercase();
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &domain_lower, qtype, &[], "") {
                debug!(
                    "DNS request route: {} QTYPE={} -> {:?}",
                    domain_lower, qtype, rule.action
                );
                return self.map_request_action(&rule.action);
            }
        }
        debug!(
            "DNS request route: {} QTYPE={} -> {:?} (fallback)",
            domain_lower, qtype, self.request_fallback
        );
        self.map_request_action(&self.request_fallback)
    }

    fn map_request_action(&self, action: &DnsRequestAction) -> DnsRequestDecision {
        match action {
            DnsRequestAction::Reject => DnsRequestDecision::Reject,
            DnsRequestAction::AsIs => DnsRequestDecision::AsIs,
            DnsRequestAction::Upstream(name) => DnsRequestDecision::Upstream(name.clone()),
        }
    }

    // -----------------------------------------------------------------------
    // Response routing
    // -----------------------------------------------------------------------

    /// Select the action for a DNS response.
    pub fn select_response(
        &self,
        domain: &str,
        qtype: u16,
        answer_ips: &[IpAddr],
        from_upstream: &str,
    ) -> DnsResponseDecision {
        let domain_lower = domain.to_lowercase();
        for rule in &self.response_rules {
            if eval_conditions(
                &rule.conditions,
                &domain_lower,
                qtype,
                answer_ips,
                from_upstream,
            ) {
                debug!(
                    "DNS response route: {} QTYPE={} upstream={} -> {:?}",
                    domain_lower, qtype, from_upstream, rule.action
                );
                return self.map_response_action(&rule.action);
            }
        }
        debug!(
            "DNS response route: {} QTYPE={} -> {:?} (fallback)",
            domain_lower, qtype, self.response_fallback
        );
        self.map_response_action(&self.response_fallback)
    }

    fn map_response_action(&self, action: &DnsResponseAction) -> DnsResponseDecision {
        match action {
            DnsResponseAction::Accept => DnsResponseDecision::Accept,
            DnsResponseAction::Reject => DnsResponseDecision::Reject,
            DnsResponseAction::Upstream(name) => DnsResponseDecision::Requery(name.clone()),
        }
    }

    // -----------------------------------------------------------------------
    // Fixed TTL
    // -----------------------------------------------------------------------

    /// Look up the fixed TTL for a domain. `Some(0)` disables caching.
    pub fn fixed_ttl(&self, domain: &str) -> Option<u32> {
        self.fixed_domain_ttl.get(domain).copied()
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Total number of compiled rules (request + response).
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Legacy API: domain-only lookup returning upstream name.
    ///
    /// Maps domain to request selection with QTYPE=A and returns:
    /// - The upstream name for `Upstream(name)` (borrowed from compiled rules)
    /// - `"reject"` for `Reject`
    /// - `"asis"` for `AsIs`
    pub fn select_upstream(&self, domain: &str) -> &str {
        let domain_lower = domain.to_lowercase();
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &domain_lower, 1, &[], "") {
                return match &rule.action {
                    DnsRequestAction::Upstream(name) => {
                        debug!("DNS route: {} -> {}", domain, name);
                        name.as_str()
                    }
                    DnsRequestAction::Reject => {
                        debug!("DNS route: {} -> reject", domain);
                        "reject"
                    }
                    DnsRequestAction::AsIs => {
                        debug!("DNS route: {} -> asis", domain);
                        "asis"
                    }
                };
            }
        }
        match &self.request_fallback {
            DnsRequestAction::Upstream(name) => {
                debug!("DNS route: {} -> {} (fallback)", domain, name);
                name.as_str()
            }
            DnsRequestAction::Reject => {
                debug!("DNS route: {} -> reject (fallback)", domain);
                "reject"
            }
            DnsRequestAction::AsIs => {
                debug!("DNS route: {} -> asis (fallback)", domain);
                "asis"
            }
        }
    }
}

/// Pick the effective request routing table from a config that may still
/// carry legacy flat rules.
fn resolve_request_routing(config: &DnsRouting) -> DnsRequestRouting {
    if !config.request.rules.is_empty() {
        return config.request.clone();
    }
    if !config.rules.is_empty() {
        return config.convert_legacy_rules();
    }
    // No rules of either shape. Keep the request block, but surface a
    // customized legacy `fallback:` string when the request fallback is
    // still the type default (`Upstream("default")`). The DnsRouting
    // Default uses legacy fallback `"upstream"` which we deliberately
    // ignore here so empty configs keep routing to `"default"`.
    let mut request = config.request.clone();
    let request_default_fb = matches!(
        &request.fallback,
        DnsRequestAction::Upstream(n) if n == "default"
    );
    if request_default_fb
        && !config.fallback.is_empty()
        && config.fallback != "upstream"
        && config.fallback != "default"
    {
        request.fallback = DnsRequestAction::Upstream(config.fallback.clone());
    }
    request
}

// ---------------------------------------------------------------------------
// Condition compilation helpers
// ---------------------------------------------------------------------------

fn collect_cond_codes(
    conds: &[DnsCond],
    geosite: &mut std::collections::HashSet<String>,
    geoip: &mut std::collections::HashSet<String>,
) {
    for cond in conds {
        match cond {
            DnsCond::Qname { matchers, .. } => {
                for m in matchers {
                    if let DnsDomainMatcher::Geosite(code) = m {
                        geosite.insert(code.to_lowercase());
                    }
                }
            }
            DnsCond::Ip {
                cidrs: _,
                geoip: codes,
                ..
            } => {
                for c in codes {
                    if c != "private" {
                        geoip.insert(c.to_lowercase());
                    }
                }
            }
            _ => {}
        }
    }
}

fn compile_conditions(
    conds: &[DnsCond],
    geo_assets: &GeoAssets,
) -> anyhow::Result<Vec<CompiledCond>> {
    let mut compiled = Vec::with_capacity(conds.len());
    for cond in conds {
        match cond {
            DnsCond::Qname { not, matchers } => {
                let mut compiled_matchers = Vec::with_capacity(matchers.len());
                for m in matchers {
                    compiled_matchers.push(compile_domain_matcher(m, geo_assets)?);
                }
                compiled.push(CompiledCond::Qname {
                    not: *not,
                    matchers: compiled_matchers,
                });
            }
            DnsCond::Qtype { not, types } => {
                compiled.push(CompiledCond::Qtype {
                    not: *not,
                    types: types.clone(),
                });
            }
            DnsCond::Upstream { not, names } => {
                compiled.push(CompiledCond::Upstream {
                    not: *not,
                    names: names.clone(),
                });
            }
            DnsCond::Ip {
                not,
                cidrs,
                geoip: geoip_codes,
            } => {
                let mut nets: Vec<ipnet::IpNet> =
                    cidrs.iter().filter_map(|c| c.parse().ok()).collect();
                nets.extend(geo_assets.geoip_nets(geoip_codes));
                let trie = BinaryLpmTrie::from_nets(&nets);
                compiled.push(CompiledCond::Ip { not: *not, trie });
            }
        }
    }
    Ok(compiled)
}

fn compile_domain_matcher(
    m: &DnsDomainMatcher,
    geo_assets: &GeoAssets,
) -> anyhow::Result<CompiledDomainMatcher> {
    Ok(match m {
        DnsDomainMatcher::Full(v) => CompiledDomainMatcher::Full(v.to_lowercase()),
        // Strip leading dots so `suffix:.cn` and `suffix:cn` are equivalent.
        DnsDomainMatcher::Suffix(v) => {
            CompiledDomainMatcher::Suffix(v.trim_start_matches('.').to_lowercase())
        }
        DnsDomainMatcher::Keyword(v) => CompiledDomainMatcher::Keyword(v.clone()),
        DnsDomainMatcher::Regex(pattern) => {
            let re = regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("Invalid DNS regex '{}': {}", pattern, e))?;
            CompiledDomainMatcher::Regex(re)
        }
        DnsDomainMatcher::Geosite(code) => {
            let geosite_domains = geo_assets.geosite_domains(std::slice::from_ref(code));
            if geosite_domains.is_empty() {
                warn!(
                    "geosite code '{}' expanded to 0 domains; matcher will never match",
                    code
                );
            }
            let matcher = GeositeMatcher::build(&geosite_domains);
            CompiledDomainMatcher::Geosite(matcher)
        }
    })
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

fn eval_conditions(
    conds: &[CompiledCond],
    domain: &str,
    qtype: u16,
    answer_ips: &[IpAddr],
    from_upstream: &str,
) -> bool {
    for cond in conds {
        let matches = match cond {
            CompiledCond::Qname { not, matchers } => {
                let hit = matchers.iter().any(|m| m.matches(domain));
                if *not { !hit } else { hit }
            }
            CompiledCond::Qtype { not, types } => {
                let hit = types.contains(&qtype);
                if *not { !hit } else { hit }
            }
            CompiledCond::Upstream { not, names } => {
                let hit = names.iter().any(|n| n == from_upstream);
                if *not { !hit } else { hit }
            }
            CompiledCond::Ip { not, trie } => {
                let hit = answer_ips.iter().any(|ip| trie.matches(ip));
                if *not { !hit } else { hit }
            }
        };
        if !matches {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::dns::{
        DnsCond, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsRequestRule, DnsRouting,
    };

    fn test_routing_from_request(request_routing: DnsRequestRouting) -> DnsRouter {
        let routing = DnsRouting {
            request: request_routing,
            ..Default::default()
        };
        DnsRouter::new(&routing).unwrap()
    }

    #[test]
    fn test_legacy_rules_converted() {
        let routing = DnsRouting {
            rules: vec![honk_config::dns::DnsLegacyRule {
                domain: "suffix:.cn".into(),
                upstream: "alidns".into(),
            }],
            fallback: "default".into(),
            ..Default::default()
        };
        let router = DnsRouter::new(&routing).unwrap();
        assert_eq!(router.rule_count(), 1);
        assert_eq!(router.select_upstream("baidu.cn"), "alidns");
        assert_eq!(router.select_upstream("google.com"), "default");
    }

    #[test]
    fn test_request_routing_qname_suffix() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Suffix("cn".to_string())],
                }],
                action: DnsRequestAction::Upstream("alidns".to_string()),
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("www.baidu.cn", 1),
            DnsRequestDecision::Upstream("alidns".to_string())
        );
        assert_eq!(
            router.select_request("google.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_qname_full() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Full("example.com".to_string())],
                }],
                action: DnsRequestAction::Upstream("custom".to_string()),
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("example.com", 1),
            DnsRequestDecision::Upstream("custom".to_string())
        );
        assert_eq!(
            router.select_request("sub.example.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_qname_keyword() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Keyword("ads".to_string())],
                }],
                action: DnsRequestAction::Reject,
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("ads.google.com", 1),
            DnsRequestDecision::Reject
        );
        assert_eq!(
            router.select_request("normal.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_qname_regex() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Regex(r"^.*\.example\.com$".to_string())],
                }],
                action: DnsRequestAction::Upstream("custom".to_string()),
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("sub.example.com", 1),
            DnsRequestDecision::Upstream("custom".to_string())
        );
        assert_eq!(
            router.select_request("other.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_qtype() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qtype {
                    not: false,
                    types: vec![65], // HTTPS
                }],
                action: DnsRequestAction::Reject,
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("test.com", 65),
            DnsRequestDecision::Reject
        );
        assert_eq!(
            router.select_request("test.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_and_qname_qtype() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![
                    DnsCond::Qname {
                        not: false,
                        matchers: vec![DnsDomainMatcher::Suffix("cn".to_string())],
                    },
                    DnsCond::Qtype {
                        not: false,
                        types: vec![1, 28],
                    },
                ],
                action: DnsRequestAction::Upstream("alidns".to_string()),
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        // Both conditions match
        assert_eq!(
            router.select_request("baidu.cn", 1),
            DnsRequestDecision::Upstream("alidns".to_string())
        );
        assert_eq!(
            router.select_request("baidu.cn", 28),
            DnsRequestDecision::Upstream("alidns".to_string())
        );
        // Qtype doesn't match
        assert_eq!(
            router.select_request("baidu.cn", 65),
            DnsRequestDecision::Upstream("default".to_string())
        );
        // Domain doesn't match
        assert_eq!(
            router.select_request("google.com", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_not_negation() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: true,
                    matchers: vec![DnsDomainMatcher::Suffix("cn".to_string())],
                }],
                action: DnsRequestAction::Upstream("googledns".to_string()),
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        // NOT cn → matches non-cn
        assert_eq!(
            router.select_request("google.com", 1),
            DnsRequestDecision::Upstream("googledns".to_string())
        );
        // cn domain matches the inner matcher but not true → rule doesn't match
        assert_eq!(
            router.select_request("baidu.cn", 1),
            DnsRequestDecision::Upstream("default".to_string())
        );
    }

    #[test]
    fn test_request_routing_reject() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Keyword("blocked".to_string())],
                }],
                action: DnsRequestAction::Reject,
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("blocked-site.com", 1),
            DnsRequestDecision::Reject
        );
    }

    #[test]
    fn test_request_routing_asis() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![DnsRequestRule {
                conditions: vec![DnsCond::Qname {
                    not: false,
                    matchers: vec![DnsDomainMatcher::Full("local.test".to_string())],
                }],
                action: DnsRequestAction::AsIs,
            }],
            fallback: DnsRequestAction::Upstream("default".to_string()),
        });
        assert_eq!(
            router.select_request("local.test", 1),
            DnsRequestDecision::AsIs
        );
    }

    #[test]
    fn test_empty_rules_fallback() {
        let router = test_routing_from_request(DnsRequestRouting {
            rules: vec![],
            fallback: DnsRequestAction::Upstream("fallback_upstream".to_string()),
        });
        assert_eq!(
            router.select_request("anything.com", 1),
            DnsRequestDecision::Upstream("fallback_upstream".to_string())
        );
    }

    #[test]
    fn test_response_upstream_match() {
        let routing = DnsRouting {
            response: DnsResponseRouting {
                rules: vec![honk_config::dns::DnsResponseRule {
                    conditions: vec![DnsCond::Upstream {
                        not: false,
                        names: vec!["googledns".to_string()],
                    }],
                    action: DnsResponseAction::Reject,
                }],
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        };
        let router = DnsRouter::new(&routing).unwrap();
        assert_eq!(
            router.select_response("test.com", 1, &[], "googledns"),
            DnsResponseDecision::Reject
        );
        assert_eq!(
            router.select_response("test.com", 1, &[], "other"),
            DnsResponseDecision::Accept
        );
    }

    #[test]
    fn test_response_ip_private_requery() {
        let routing = DnsRouting {
            response: DnsResponseRouting {
                rules: vec![honk_config::dns::DnsResponseRule {
                    conditions: vec![DnsCond::Ip {
                        not: false,
                        cidrs: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                        geoip: vec![],
                    }],
                    action: DnsResponseAction::Upstream("googledns".to_string()),
                }],
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        };
        let router = DnsRouter::new(&routing).unwrap();
        let private_ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(
            router.select_response("test.com", 1, &[private_ip], "any"),
            DnsResponseDecision::Requery("googledns".to_string())
        );
        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(
            router.select_response("test.com", 1, &[public_ip], "any"),
            DnsResponseDecision::Accept
        );
    }

    #[test]
    fn test_fixed_ttl_lookup() {
        let mut ttl_map = HashMap::new();
        ttl_map.insert("nocache.test".to_string(), 0);
        ttl_map.insert("custom.test".to_string(), 300);
        let routing = DnsRouting::default();
        let router = DnsRouter::new_with_fixed_ttl(&routing, &ttl_map).unwrap();
        assert_eq!(router.fixed_ttl("nocache.test"), Some(0));
        assert_eq!(router.fixed_ttl("custom.test"), Some(300));
        assert_eq!(router.fixed_ttl("normal.test"), None);
    }

    #[test]
    fn test_legacy_still_works() {
        // Replicate old test pattern
        let routing = DnsRouting {
            rules: vec![honk_config::dns::DnsLegacyRule {
                domain: "suffix:.cn".into(),
                upstream: "alidns".into(),
            }],
            fallback: "default".into(),
            ..Default::default()
        };
        let router = DnsRouter::new(&routing).unwrap();
        assert_eq!(router.select_upstream("www.baidu.cn"), "alidns");
        assert_eq!(router.select_upstream("google.com"), "default");
    }

    #[test]
    fn test_rule_count() {
        let routing = DnsRouting {
            rules: vec![honk_config::dns::DnsLegacyRule {
                domain: "suffix:.cn".into(),
                upstream: "alidns".into(),
            }],
            fallback: "default".into(),
            ..Default::default()
        };
        let router = DnsRouter::new(&routing).unwrap();
        assert_eq!(router.rule_count(), 1);
    }
}
