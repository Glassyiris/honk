//! Inspection and bounded source-time capture of the accepted compiled routing policy.

use std::{fmt::Write, time::Instant};

use super::{
    CompiledCondition, CompiledPredicate, ConnectionInfo, DomainRouting, PredicateInput,
    RouteMatch, Router,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatchResult {
    Matched,
    NotMatched,
    Indeterminate,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatedRule {
    pub(crate) result: MatchResult,
    pub(crate) conditions: Vec<MatchResult>,
}

pub(crate) struct Evaluation<'a> {
    pub(crate) outbound: Option<&'a str>,
    pub(crate) rules: Vec<EvaluatedRule>,
}

#[derive(Clone, Debug)]
pub(crate) struct ObservedRoute<'a> {
    pub(crate) matched: Option<RouteMatch<'a>>,
    pub(crate) rules: Vec<EvaluatedRule>,
    pub(crate) truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TraceError {
    Steps,
    Deadline,
}

impl Router {
    pub(crate) fn route_full_observed(
        &self,
        conn: &ConnectionInfo,
        bitmap: Option<&DomainRouting>,
        max_steps: usize,
    ) -> ObservedRoute<'_> {
        // Reserve only evidence slots, never evaluate predicates here. Budget exhaustion
        // omits a suffix but cannot short-circuit the production decision below.
        let mut remaining = max_steps;
        let mut rules = Vec::with_capacity(max_steps.min(self.routes.len().saturating_add(1)));
        let mut truncated = false;
        for route in self.routes.iter() {
            if remaining == 0 {
                truncated = true;
                break;
            }
            remaining -= 1;
            let count = route.conditions.len().min(remaining);
            rules.push(EvaluatedRule {
                result: MatchResult::Skipped,
                conditions: vec![MatchResult::Skipped; count],
            });
            remaining -= count;
            if count < route.conditions.len() {
                truncated = true;
                break;
            }
        }
        if !truncated {
            if remaining == 0 {
                truncated = true;
            } else {
                rules.push(EvaluatedRule {
                    result: MatchResult::Skipped,
                    conditions: Vec::new(),
                });
            }
        }

        let matched = self.route_full_with_observer(conn, bitmap, |rule, condition, matched| {
            let Some(evaluated) = rules.get_mut(rule) else {
                return;
            };
            let result = if matched {
                MatchResult::Matched
            } else {
                MatchResult::NotMatched
            };
            if let Some(condition) = condition {
                if let Some(recorded) = evaluated.conditions.get_mut(condition) {
                    *recorded = result;
                }
            } else {
                evaluated.result = result;
            }
        });
        if matched.is_none()
            && let Some(fallback) = rules.get_mut(self.routes.len())
        {
            fallback.result = MatchResult::Matched;
        }
        ObservedRoute {
            matched,
            rules,
            truncated,
        }
    }

    pub(crate) fn condition_display(
        &self,
        compiled: &CompiledCondition,
        configured: &honk_config::routing::RoutingCondition,
    ) -> String {
        macro_rules! field {
            ($name:ident) => {
                if compiled.not {
                    configured.not.$name.as_slice()
                } else {
                    configured.$name.as_slice()
                }
            };
        }
        // Select by the compiled predicate, not source order: domain/geosite split,
        // while explicit destination IPs and geoip alternatives share one predicate.
        let (kind, fields): (&str, &[(&str, &[String])]) = match &compiled.predicate {
            CompiledPredicate::Domain(id) => match &self.domain_matchers[*id as usize] {
                super::DomainMatcher::Ordinary { .. } => (
                    "domain",
                    &[
                        ("full: ", field!(domain)),
                        ("suffix: ", field!(domain_suffix)),
                        ("keyword: ", field!(domain_keyword)),
                        ("regex: ", field!(domain_regex)),
                    ],
                ),
                super::DomainMatcher::Geosite { .. } => {
                    ("domain", &[("geosite: ", field!(geosite))])
                }
            },
            CompiledPredicate::DestinationIp(_) => {
                ("dip", &[("", field!(ip)), ("geoip: ", field!(geo_ip))])
            }
            CompiledPredicate::SourceIp(_) => ("sip", &[("", field!(source_ip))]),
            CompiledPredicate::DestinationPort(_) => ("dport", &[("", field!(port))]),
            CompiledPredicate::SourcePort(_) => ("sport", &[("", field!(source_port))]),
            CompiledPredicate::Protocol(_) => ("l4proto", &[("", field!(protocol))]),
            CompiledPredicate::IpVersion(_) => ("ipversion", &[("", field!(ip_version))]),
            CompiledPredicate::Dscp(_) => ("dscp", &[("", field!(dscp))]),
            CompiledPredicate::ProcessName(_) => ("pname", &[("", field!(process_name))]),
            CompiledPredicate::Mac(_) => ("mac", &[("", field!(mac))]),
        };
        let mut display = String::new();
        if compiled.not {
            display.push('!');
        }
        display.push_str(kind);
        display.push('(');
        let mut separator = "";
        for (prefix, values) in fields {
            for value in *values {
                write!(display, "{separator}{prefix}{value:?}").unwrap();
                separator = ", ";
            }
        }
        display.push(')');
        display
    }

    pub(crate) fn simulate(
        &self,
        input: PredicateInput<'_>,
        max_steps: usize,
        deadline: Instant,
    ) -> Result<Evaluation<'_>, TraceError> {
        // Charge skipped evidence too: the response must never hide a suffix of the policy.
        let mut remaining = max_steps.checked_sub(1).ok_or(TraceError::Steps)?;
        for route in self.routes.iter() {
            check_deadline(deadline)?;
            remaining = remaining
                .checked_sub(1)
                .and_then(|n| n.checked_sub(route.conditions.len()))
                .ok_or(TraceError::Steps)?;
        }
        let mut rules = Vec::with_capacity(self.routes.len() + 1);
        let mut stopped = false;
        let mut candidate = None;
        let mut disagreement = false;
        for route in self.routes.iter() {
            check_deadline(deadline)?;
            let mut result = if stopped {
                MatchResult::Skipped
            } else if route.conditions.is_empty() {
                MatchResult::NotMatched
            } else {
                MatchResult::Matched
            };
            let mut conditions = Vec::with_capacity(route.conditions.len());
            for condition in &route.conditions {
                check_deadline(deadline)?;
                let next = if matches!(result, MatchResult::NotMatched | MatchResult::Skipped) {
                    MatchResult::Skipped
                } else {
                    match self.evaluate_predicate::<true>(
                        &condition.predicate,
                        input,
                        None,
                        Some(deadline),
                    ) {
                        Some(value) if value != condition.not => MatchResult::Matched,
                        Some(_) => MatchResult::NotMatched,
                        None => MatchResult::Indeterminate,
                    }
                };
                check_deadline(deadline)?;
                conditions.push(next);
                match next {
                    MatchResult::NotMatched => result = MatchResult::NotMatched,
                    MatchResult::Indeterminate => result = MatchResult::Indeterminate,
                    MatchResult::Matched | MatchResult::Skipped => {}
                }
            }
            if matches!(result, MatchResult::Matched | MatchResult::Indeterminate) {
                add_candidate(&mut candidate, &mut disagreement, &route.outbound);
            }
            stopped |= result == MatchResult::Matched;
            rules.push(EvaluatedRule { result, conditions });
        }
        if !stopped {
            add_candidate(&mut candidate, &mut disagreement, self.default_outbound());
        }
        rules.push(EvaluatedRule {
            result: if stopped {
                MatchResult::Skipped
            } else {
                MatchResult::Matched
            },
            conditions: Vec::new(),
        });
        check_deadline(deadline)?;
        Ok(Evaluation {
            outbound: if disagreement { None } else { candidate },
            rules,
        })
    }
}

fn add_candidate<'a>(candidate: &mut Option<&'a str>, disagreement: &mut bool, next: &'a str) {
    if let Some(previous) = candidate {
        *disagreement |= *previous != next;
    } else {
        *candidate = Some(next);
    }
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<(), TraceError> {
    if Instant::now() >= deadline {
        Err(TraceError::Deadline)
    } else {
        Ok(())
    }
}

pub(crate) fn missing_input(predicate: &CompiledPredicate) -> &'static str {
    match predicate {
        CompiledPredicate::Domain(_) => "domain",
        CompiledPredicate::DestinationIp(_) | CompiledPredicate::IpVersion(_) => "dst_ip",
        CompiledPredicate::SourceIp(_) => "src_ip",
        CompiledPredicate::DestinationPort(_) => "dst_port",
        CompiledPredicate::SourcePort(_) => "src_port",
        CompiledPredicate::Protocol(_) => "network",
        CompiledPredicate::Dscp(_) => "dscp",
        CompiledPredicate::ProcessName(_) => "pname",
        CompiledPredicate::Mac(_) => "src_mac",
    }
}

pub(crate) fn condition_expression(condition: &CompiledCondition) -> String {
    let kind = match condition.predicate {
        CompiledPredicate::Domain(_) => "domain",
        CompiledPredicate::DestinationIp(_) => "dip",
        CompiledPredicate::SourceIp(_) => "sip",
        CompiledPredicate::DestinationPort(_) => "dport",
        CompiledPredicate::SourcePort(_) => "sport",
        CompiledPredicate::Protocol(_) => "l4proto",
        CompiledPredicate::IpVersion(_) => "ipversion",
        CompiledPredicate::Dscp(_) => "dscp",
        CompiledPredicate::ProcessName(_) => "pname",
        CompiledPredicate::Mac(_) => "mac",
    };
    format!("{}{kind}(<redacted>)", if condition.not { "!" } else { "" })
}

pub(crate) fn rule_expression(conditions: &[CompiledCondition]) -> String {
    if conditions.is_empty() {
        return "empty rule (never matches)".into();
    }
    // A dictionary row is a safe display, not an unbounded reproduction of configuration.
    if conditions.len() > 64 {
        return format!(
            "AND({} compiled conditions; values redacted)",
            conditions.len()
        );
    }
    conditions
        .iter()
        .map(condition_expression)
        .collect::<Vec<_>>()
        .join(" && ")
}
