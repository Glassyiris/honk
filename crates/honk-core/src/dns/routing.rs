//! DNS request/response routing.
//!
//! Routes DNS queries to the appropriate upstream based on
//! domain patterns (suffix, keyword, regex, full match).

use honk_config::dns::DnsRouting;
#[cfg(test)]
use honk_config::dns::DnsRule;
use tracing::debug;

/// Compiled DNS routing rule.
#[derive(Debug, Clone)]
struct CompiledDnsRule {
    match_type: DnsMatchType,
    upstream: String,
}

#[derive(Debug, Clone)]
enum DnsMatchType {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regex(regex::Regex),
}

/// DNS router that selects upstreams based on domain matching.
pub struct DnsRouter {
    rules: Vec<CompiledDnsRule>,
    fallback: String,
}

impl DnsRouter {
    pub fn new(config: &DnsRouting) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for rule in &config.rules {
            let (match_type, _pattern) = parse_dns_rule(&rule.domain)?;
            rules.push(CompiledDnsRule {
                match_type,
                upstream: rule.upstream.clone(),
            });
        }
        Ok(Self {
            rules,
            fallback: config.fallback.clone(),
        })
    }

    pub fn select_upstream(&self, domain: &str) -> &str {
        for rule in &self.rules {
            if dns_domain_matches(domain, &rule.match_type) {
                debug!("DNS route: {} -> {}", domain, rule.upstream);
                return &rule.upstream;
            }
        }
        debug!("DNS route: {} -> {} (fallback)", domain, self.fallback);
        &self.fallback
    }

    pub fn fallback_upstream(&self) -> &str {
        &self.fallback
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn parse_dns_rule(pattern: &str) -> anyhow::Result<(DnsMatchType, String)> {
    if let Some(suffix) = pattern.strip_prefix("suffix:") {
        Ok((
            DnsMatchType::Suffix(suffix.to_string()),
            pattern.to_string(),
        ))
    } else if let Some(keyword) = pattern.strip_prefix("keyword:") {
        Ok((
            DnsMatchType::Keyword(keyword.to_string()),
            pattern.to_string(),
        ))
    } else if let Some(full) = pattern.strip_prefix("full:") {
        Ok((DnsMatchType::Full(full.to_string()), pattern.to_string()))
    } else if let Some(regex_str) = pattern.strip_prefix("regex:") {
        let re = regex::Regex::new(regex_str)
            .map_err(|e| anyhow::anyhow!("Invalid DNS regex '{}': {}", regex_str, e))?;
        Ok((DnsMatchType::Regex(re), pattern.to_string()))
    } else {
        Ok((DnsMatchType::Full(pattern.to_string()), pattern.to_string()))
    }
}

fn dns_domain_matches(domain: &str, match_type: &DnsMatchType) -> bool {
    match match_type {
        DnsMatchType::Full(pattern) => domain == pattern,
        DnsMatchType::Suffix(suffix) => domain.ends_with(suffix),
        DnsMatchType::Keyword(keyword) => domain.contains(keyword.as_str()),
        DnsMatchType::Regex(re) => re.is_match(domain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::dns::DnsRouting;

    fn test_routing(rules: Vec<DnsRule>, fallback: &str) -> DnsRouter {
        DnsRouter::new(&DnsRouting {
            rules,
            fallback: fallback.to_string(),
        })
        .unwrap()
    }

    #[test]
    fn test_suffix_routing() {
        let router = test_routing(
            vec![DnsRule {
                domain: "suffix:.cn".into(),
                upstream: "alidns".into(),
            }],
            "google",
        );
        assert_eq!(router.select_upstream("www.baidu.cn"), "alidns");
        assert_eq!(router.select_upstream("google.com"), "google");
    }

    #[test]
    fn test_keyword_routing() {
        let router = test_routing(
            vec![DnsRule {
                domain: "keyword:ads".into(),
                upstream: "block".into(),
            }],
            "default",
        );
        assert!(router.select_upstream("ads.google.com") == "block");
        assert_eq!(router.select_upstream("normal.com"), "default");
    }

    #[test]
    fn test_full_routing() {
        let router = test_routing(
            vec![DnsRule {
                domain: "full:example.com".into(),
                upstream: "custom".into(),
            }],
            "default",
        );
        assert_eq!(router.select_upstream("example.com"), "custom");
        assert_eq!(router.select_upstream("sub.example.com"), "default");
    }

    #[test]
    fn test_regex_routing() {
        let router = test_routing(
            vec![DnsRule {
                domain: "regex:.*\\.example\\.com".into(),
                upstream: "custom".into(),
            }],
            "default",
        );
        assert_eq!(router.select_upstream("sub.example.com"), "custom");
        assert_eq!(router.select_upstream("other.com"), "default");
    }

    #[test]
    fn test_empty_rules_fallback() {
        let router = test_routing(vec![], "fallback");
        assert_eq!(router.select_upstream("anything.com"), "fallback");
    }
}
