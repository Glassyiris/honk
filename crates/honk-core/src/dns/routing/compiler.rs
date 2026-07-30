use std::collections::HashSet;

use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsRequestAction, DnsRequestRouting, DnsResponseAction,
    DnsResponseRouting,
};
use tracing::warn;

use super::matcher::{CompiledCond, CompiledDomainMatcher};
use crate::routing::{BinaryLpmTrie, GeoAssets, GeositeMatcher};

#[derive(Clone)]
pub(super) struct CompiledRequestRule {
    pub(super) conditions: Vec<CompiledCond>,
    pub(super) action: DnsRequestAction,
}

#[derive(Clone)]
pub(super) struct CompiledResponseRule {
    pub(super) conditions: Vec<CompiledCond>,
    pub(super) action: DnsResponseAction,
}

pub(super) struct CompiledRouting {
    pub(super) request_rules: Vec<CompiledRequestRule>,
    pub(super) response_rules: Vec<CompiledResponseRule>,
}

pub(super) fn compile(
    request: &DnsRequestRouting,
    response: &DnsResponseRouting,
) -> anyhow::Result<CompiledRouting> {
    let mut geosite_codes = HashSet::new();
    let mut geoip_codes = HashSet::new();
    for conditions in request
        .rules
        .iter()
        .map(|rule| rule.conditions.as_slice())
        .chain(response.rules.iter().map(|rule| rule.conditions.as_slice()))
    {
        collect_cond_codes(conditions, &mut geosite_codes, &mut geoip_codes);
    }
    let assets = GeoAssets::load_codes(&geosite_codes, &geoip_codes);
    let request_rules = request
        .rules
        .iter()
        .map(|rule| {
            Ok(CompiledRequestRule {
                conditions: compile_conditions(&rule.conditions, &assets)?,
                action: rule.action.clone(),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let response_rules = response
        .rules
        .iter()
        .map(|rule| {
            Ok(CompiledResponseRule {
                conditions: compile_conditions(&rule.conditions, &assets)?,
                action: rule.action.clone(),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(CompiledRouting {
        request_rules,
        response_rules,
    })
}

fn collect_cond_codes(
    conditions: &[DnsCond],
    geosite: &mut HashSet<String>,
    geoip: &mut HashSet<String>,
) {
    for condition in conditions {
        match condition {
            DnsCond::Qname { matchers, .. } => {
                for matcher in matchers {
                    if let DnsDomainMatcher::Geosite(code) = matcher {
                        geosite.insert(code.to_lowercase());
                    }
                }
            }
            DnsCond::Ip { geoip: codes, .. } => {
                geoip.extend(
                    codes
                        .iter()
                        .filter(|code| code.as_str() != "private")
                        .map(|code| code.to_lowercase()),
                );
            }
            DnsCond::Qtype { .. } | DnsCond::Upstream { .. } => {}
        }
    }
}

fn compile_conditions(
    conditions: &[DnsCond],
    assets: &GeoAssets,
) -> anyhow::Result<Vec<CompiledCond>> {
    conditions
        .iter()
        .map(|condition| match condition {
            DnsCond::Qname { not, matchers } => Ok(CompiledCond::Qname {
                not: *not,
                matchers: matchers
                    .iter()
                    .map(|matcher| compile_domain_matcher(matcher, assets))
                    .collect::<anyhow::Result<_>>()?,
            }),
            DnsCond::Qtype { not, types } => Ok(CompiledCond::Qtype {
                not: *not,
                types: types.clone(),
            }),
            DnsCond::Upstream { not, names } => Ok(CompiledCond::Upstream {
                not: *not,
                names: names.clone(),
            }),
            DnsCond::Ip { not, cidrs, geoip } => {
                let mut nets: Vec<ipnet::IpNet> =
                    cidrs.iter().filter_map(|cidr| cidr.parse().ok()).collect();
                nets.extend(assets.geoip_nets(geoip));
                Ok(CompiledCond::Ip {
                    not: *not,
                    trie: BinaryLpmTrie::from_nets(&nets),
                })
            }
        })
        .collect()
}

fn compile_domain_matcher(
    matcher: &DnsDomainMatcher,
    assets: &GeoAssets,
) -> anyhow::Result<CompiledDomainMatcher> {
    Ok(match matcher {
        DnsDomainMatcher::Full(value) => CompiledDomainMatcher::Full(value.to_lowercase()),
        DnsDomainMatcher::Suffix(value) => {
            CompiledDomainMatcher::Suffix(value.trim_start_matches('.').to_lowercase())
        }
        DnsDomainMatcher::Keyword(value) => CompiledDomainMatcher::Keyword(value.clone()),
        DnsDomainMatcher::Regex(pattern) => CompiledDomainMatcher::Regex(
            regex::Regex::new(pattern)
                .map_err(|error| anyhow::anyhow!("Invalid DNS regex '{}': {}", pattern, error))?,
        ),
        DnsDomainMatcher::Geosite(code) => {
            let domains = assets.geosite_domains(std::slice::from_ref(code));
            if domains.is_empty() {
                warn!(
                    "geosite code '{}' expanded to 0 domains; matcher will never match",
                    code
                );
            }
            CompiledDomainMatcher::Geosite(GeositeMatcher::build(&domains))
        }
    })
}
