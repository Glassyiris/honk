use std::net::IpAddr;

use crate::routing::{BinaryLpmTrie, GeositeMatcher};

#[derive(Clone)]
pub(super) enum CompiledDomainMatcher {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regex(regex::Regex),
    Geosite(GeositeMatcher),
}

impl CompiledDomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(pattern) => domain == pattern,
            Self::Suffix(suffix) => {
                domain == suffix
                    || domain
                        .as_bytes()
                        .get(domain.len().saturating_sub(suffix.len() + 1))
                        .copied()
                        == Some(b'.')
                        && domain.ends_with(suffix)
            }
            Self::Keyword(keyword) => domain.contains(keyword),
            Self::Regex(regex) => regex.is_match(domain),
            Self::Geosite(matcher) => matcher.matches(domain),
        }
    }
}

#[derive(Clone)]
pub(super) enum CompiledCond {
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
        trie: BinaryLpmTrie,
    },
}

pub(super) struct Evaluation<'a> {
    domain: &'a str,
    qtype: u16,
    answer_ips: &'a [IpAddr],
    from_upstream: &'a str,
}

pub(super) struct ResponseContext<'a> {
    pub(super) answer_ips: &'a [IpAddr],
    pub(super) from_upstream: &'a str,
}

impl<'a> Evaluation<'a> {
    pub(super) fn request(domain: &'a str, qtype: u16) -> Self {
        Self {
            domain,
            qtype,
            answer_ips: &[],
            from_upstream: "",
        }
    }

    pub(super) fn response(domain: &'a str, qtype: u16, context: ResponseContext<'a>) -> Self {
        Self {
            domain,
            qtype,
            answer_ips: context.answer_ips,
            from_upstream: context.from_upstream,
        }
    }
}

pub(super) fn eval_conditions(conditions: &[CompiledCond], value: &Evaluation<'_>) -> bool {
    conditions.iter().all(|condition| {
        let (matched, negated) = match condition {
            CompiledCond::Qname { not, matchers } => (
                matchers.iter().any(|matcher| matcher.matches(value.domain)),
                *not,
            ),
            CompiledCond::Qtype { not, types } => (types.contains(&value.qtype), *not),
            CompiledCond::Upstream { not, names } => {
                (names.iter().any(|name| name == value.from_upstream), *not)
            }
            CompiledCond::Ip { not, trie } => {
                (value.answer_ips.iter().any(|ip| trie.matches(ip)), *not)
            }
        };
        matched != negated
    })
}
