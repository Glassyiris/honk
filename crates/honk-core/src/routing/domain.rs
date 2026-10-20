//! Domain predicate matchers, geosite expansion matcher, and their build-local interner.

use super::bounded_any;
use honk_ebpf_common::ROUTING_FACT_CAPACITY;
use regex::Regex;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) enum GeositeDomain {
    Full(String),
    Domain(String),
    Keyword(String),
    Regex(Regex),
}

/// Fast matcher over a compiled geosite domain list.
///
/// Lookup semantics mirror the historical per-entry `match_geosite_domain`:
/// `Full` is a case-insensitive exact match, `Domain` matches the host itself
/// or any dot-boundary sub-domain (case-insensitive), `Keyword` is a
/// case-sensitive substring match, and `Regex` runs against the original
/// (non-lowercased) domain.
#[derive(Debug, Clone, Default)]
pub(crate) struct GeositeMatcher {
    /// Exact host names, stored lowercased.
    full: std::collections::HashSet<String>,
    /// Dot-boundary suffixes, stored lowercased.
    suffix: std::collections::HashSet<String>,
    /// Case-sensitive substring automaton for keywords.
    keyword_ac: Option<aho_corasick::AhoCorasick>,
    /// Full regular expressions (matched against the original domain).
    regex: Vec<Regex>,
}

impl GeositeMatcher {
    pub(crate) fn build(domains: &[GeositeDomain]) -> Self {
        let mut matcher = GeositeMatcher::default();
        let mut keywords: Vec<&str> = Vec::new();
        for d in domains {
            match d {
                GeositeDomain::Full(v) => {
                    matcher.full.insert(v.to_lowercase());
                }
                GeositeDomain::Domain(v) => {
                    matcher.suffix.insert(v.to_lowercase());
                }
                GeositeDomain::Keyword(v) => keywords.push(v.as_str()),
                GeositeDomain::Regex(re) => matcher.regex.push(re.clone()),
            }
        }
        if !keywords.is_empty() {
            matcher.keyword_ac = aho_corasick::AhoCorasick::new(&keywords).ok();
        }
        matcher
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        self.matches_bounded::<false>(domain, &lowercase(domain), None)
    }

    fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        lower: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        if self.full.contains(lower) {
            return true;
        }
        // Dot-boundary suffix walk: check the host itself, then each parent.
        if !self.suffix.is_empty() {
            let mut d = lower;
            loop {
                if self.suffix.contains(d) {
                    return true;
                }
                match d.find('.') {
                    Some(i) => d = &d[i + 1..],
                    None => break,
                }
            }
        }
        if let Some(ac) = &self.keyword_ac
            && ac.is_match(domain)
        {
            return true;
        }
        bounded_any::<BOUNDED, _>(&self.regex, deadline, |re| re.is_match(domain))
    }
}

pub(super) type DomainMatcherKey = Vec<(u8, String)>;

/// One `domain(...)` call. Every entry, including expanded geosite codes, is
/// an alternative: dae ORs the arguments of a single call.
#[derive(Debug, Clone)]
pub(super) struct DomainMatcher {
    patterns: Vec<Regex>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    /// One matcher per configured selector, matched as their union.
    pub(super) geosite: Vec<Arc<GeositeMatcher>>,
}

impl DomainMatcher {
    pub(super) fn new(
        domains: &[String],
        suffixes: &[String],
        keywords: &[String],
        regexes: &[String],
        geosite: &[GeositeDomain],
        matchers: Vec<Arc<GeositeMatcher>>,
    ) -> anyhow::Result<(DomainMatcherKey, Self)> {
        let mut patterns = Vec::with_capacity(regexes.len() + domains.len());
        for pattern in regexes {
            patterns.push(
                Regex::new(pattern)
                    .map_err(|error| anyhow::anyhow!("Invalid regex '{}': {}", pattern, error))?,
            );
        }
        for wildcard in domains {
            patterns.push(
                Regex::new(&glob_to_regex(wildcard)).map_err(|error| {
                    anyhow::anyhow!("Invalid pattern '{}': {}", wildcard, error)
                })?,
            );
        }
        let mut key = patterns
            .iter()
            .map(|pattern| (0, pattern.as_str().to_owned()))
            .chain(suffixes.iter().cloned().map(|value| (1, value)))
            .chain(keywords.iter().cloned().map(|value| (2, value)))
            .chain(geosite.iter().map(|domain| match domain {
                GeositeDomain::Full(value) => (3, value.to_lowercase()),
                GeositeDomain::Domain(value) => (4, value.to_lowercase()),
                GeositeDomain::Keyword(value) => (5, value.clone()),
                GeositeDomain::Regex(value) => (6, value.as_str().to_owned()),
            }))
            .collect::<Vec<_>>();
        key.sort();
        key.dedup();
        Ok((
            key,
            Self {
                patterns,
                suffixes: suffixes.to_vec(),
                keywords: keywords.to_vec(),
                geosite: matchers,
            },
        ))
    }

    pub(super) fn matches(&self, domain: &str) -> bool {
        self.matches_bounded::<false>(domain, None)
    }

    pub(super) fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        bounded_any::<BOUNDED, _>(&self.patterns, deadline, |pattern| pattern.is_match(domain))
            || bounded_any::<BOUNDED, _>(&self.suffixes, deadline, |suffix| {
                domain.ends_with(suffix)
            })
            || bounded_any::<BOUNDED, _>(&self.keywords, deadline, |keyword| {
                domain.contains(keyword)
            })
            || (!self.geosite.is_empty() && {
                let lower = lowercase(domain);
                bounded_any::<BOUNDED, _>(&self.geosite, deadline, |matcher| {
                    matcher.matches_bounded::<BOUNDED>(domain, &lower, deadline)
                })
            })
    }
}

/// Geosite sets are stored lowercased; query names almost always already are.
pub(super) fn lowercase(domain: &str) -> std::borrow::Cow<'_, str> {
    if domain
        .bytes()
        .any(|b| b.is_ascii_uppercase() || !b.is_ascii())
    {
        std::borrow::Cow::Owned(domain.to_lowercase())
    } else {
        std::borrow::Cow::Borrowed(domain)
    }
}

/// Keys copy each matcher's whole expansion and are read only by interning and
/// the policy fingerprint, so the built router keeps just `matchers`.
#[derive(Debug, Default)]
pub(super) struct DomainRegistry {
    pub(super) keys: Vec<DomainMatcherKey>,
    pub(super) matchers: Vec<DomainMatcher>,
}

impl DomainRegistry {
    pub(super) fn intern(
        &mut self,
        (key, matcher): (DomainMatcherKey, DomainMatcher),
    ) -> anyhow::Result<u32> {
        if let Some(id) = self.keys.iter().position(|candidate| *candidate == key) {
            return Ok(id as u32);
        }
        anyhow::ensure!(
            self.matchers.len() < ROUTING_FACT_CAPACITY,
            "routing policy has more than {ROUTING_FACT_CAPACITY} domain predicates"
        );
        let id = self.matchers.len() as u32;
        self.keys.push(key);
        self.matchers.push(matcher);
        Ok(id)
    }
}

pub(super) fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    re
}
