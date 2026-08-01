//! DNS request/response routing.
//!
//! Routes DNS queries by domain, qtype, response IPs, and upstream metadata.

mod compiler;
mod config;
mod matcher;

#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use honk_config::dns::{DnsRequestAction, DnsResponseAction, DnsResponseRouting, DnsRouting};
use tracing::debug;

use self::compiler::{CompiledRequestRule, CompiledResponseRule, compile};
use self::config::{request_upstream, resolve_request_routing, response_upstream};
use self::matcher::{Evaluation, ResponseContext, eval_conditions};

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

/// DNS router that selects upstreams based on domain, qtype, and response metadata.
#[derive(Clone)]
pub struct DnsRouter {
    request_rules: Vec<CompiledRequestRule>,
    request_fallback: DnsRequestAction,
    response_rules: Vec<CompiledResponseRule>,
    response_fallback: DnsResponseAction,
    fixed_domain_ttl: HashMap<String, u32>,
    rule_count: usize,
}

impl DnsRouter {
    pub fn new(config: &DnsRouting) -> anyhow::Result<Self> {
        Self::new_with_fixed_ttl(config, &HashMap::new())
    }

    pub fn new_with_fixed_ttl(
        config: &DnsRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
    ) -> anyhow::Result<Self> {
        let request = resolve_request_routing(config);
        Self::build(&request, &config.response, fixed_domain_ttl)
    }

    pub fn new_from_dns_config(dns_config: &honk_config::dns::DnsConfig) -> anyhow::Result<Self> {
        Self::new_with_fixed_ttl(&dns_config.routing, &dns_config.fixed_domain_ttl)
    }

    fn build(
        request: &honk_config::dns::DnsRequestRouting,
        response: &DnsResponseRouting,
        fixed_domain_ttl: &HashMap<String, u32>,
    ) -> anyhow::Result<Self> {
        let compiled = compile(request, response)?;
        Ok(Self {
            rule_count: compiled.request_rules.len() + compiled.response_rules.len(),
            request_rules: compiled.request_rules,
            request_fallback: request.fallback.clone(),
            response_rules: compiled.response_rules,
            response_fallback: response.fallback.clone(),
            fixed_domain_ttl: fixed_domain_ttl.clone(),
        })
    }

    /// Select a request route for a domain that has already been normalized to
    /// ASCII lowercase by the DNS query parser.
    pub(crate) fn select_request_normalized(&self, domain: &str, qtype: u16) -> DnsRequestDecision {
        let evaluation = Evaluation::request(domain, qtype);
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                debug!(
                    "DNS request route: {} QTYPE={} -> {:?}",
                    domain, qtype, rule.action
                );
                return map_request_action(&rule.action);
            }
        }
        debug!(
            "DNS request route: {} QTYPE={} -> {:?} (fallback)",
            domain, qtype, self.request_fallback
        );
        map_request_action(&self.request_fallback)
    }

    pub fn select_request(&self, domain: &str, qtype: u16) -> DnsRequestDecision {
        self.select_request_normalized(&domain.to_ascii_lowercase(), qtype)
    }

    /// Select a response route for a domain that has already been normalized
    /// to ASCII lowercase by the DNS query parser.
    pub(crate) fn select_response_normalized(
        &self,
        domain: &str,
        qtype: u16,
        answer_ips: &[IpAddr],
        from_upstream: &str,
    ) -> DnsResponseDecision {
        let evaluation = Evaluation::response(
            domain,
            qtype,
            ResponseContext {
                answer_ips,
                from_upstream,
            },
        );
        for rule in &self.response_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                debug!(
                    "DNS response route: {} QTYPE={} upstream={} -> {:?}",
                    domain, qtype, from_upstream, rule.action
                );
                return map_response_action(&rule.action);
            }
        }
        debug!(
            "DNS response route: {} QTYPE={} -> {:?} (fallback)",
            domain, qtype, self.response_fallback
        );
        map_response_action(&self.response_fallback)
    }

    pub fn select_response(
        &self,
        domain: &str,
        qtype: u16,
        answer_ips: &[IpAddr],
        from_upstream: &str,
    ) -> DnsResponseDecision {
        self.select_response_normalized(
            &domain.to_ascii_lowercase(),
            qtype,
            answer_ips,
            from_upstream,
        )
    }

    pub fn fixed_ttl(&self, domain: &str) -> Option<u32> {
        self.fixed_domain_ttl.get(domain).copied()
    }

    pub(crate) fn upstream_names(&self) -> BTreeSet<String> {
        let request = self
            .request_rules
            .iter()
            .filter_map(|rule| request_upstream(&rule.action))
            .chain(request_upstream(&self.request_fallback));
        let response = self
            .response_rules
            .iter()
            .filter_map(|rule| response_upstream(&rule.action))
            .chain(response_upstream(&self.response_fallback));
        request
            .chain(response)
            .chain(std::iter::once("default"))
            .map(str::to_owned)
            .collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub(crate) fn select_upstream_normalized(&self, domain: &str) -> &str {
        let evaluation = Evaluation::request(domain, 1);
        for rule in &self.request_rules {
            if eval_conditions(&rule.conditions, &evaluation) {
                return request_action_name(domain, &rule.action, false);
            }
        }
        request_action_name(domain, &self.request_fallback, true)
    }

    pub fn select_upstream(&self, domain: &str) -> &str {
        self.select_upstream_normalized(&domain.to_ascii_lowercase())
    }
}

fn map_request_action(action: &DnsRequestAction) -> DnsRequestDecision {
    match action {
        DnsRequestAction::Reject => DnsRequestDecision::Reject,
        DnsRequestAction::AsIs => DnsRequestDecision::AsIs,
        DnsRequestAction::Upstream(name) => DnsRequestDecision::Upstream(name.clone()),
    }
}

fn map_response_action(action: &DnsResponseAction) -> DnsResponseDecision {
    match action {
        DnsResponseAction::Accept => DnsResponseDecision::Accept,
        DnsResponseAction::Reject => DnsResponseDecision::Reject,
        DnsResponseAction::Upstream(name) => DnsResponseDecision::Requery(name.clone()),
    }
}

fn request_action_name<'a>(domain: &str, action: &'a DnsRequestAction, fallback: bool) -> &'a str {
    let suffix = if fallback { " (fallback)" } else { "" };
    match action {
        DnsRequestAction::Upstream(name) => {
            debug!("DNS route: {} -> {}{}", domain, name, suffix);
            name
        }
        DnsRequestAction::Reject => {
            debug!("DNS route: {} -> reject{}", domain, suffix);
            "reject"
        }
        DnsRequestAction::AsIs => {
            debug!("DNS route: {} -> asis{}", domain, suffix);
            "asis"
        }
    }
}
