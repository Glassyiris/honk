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
                write!(display, "{separator}{prefix}{value}").unwrap();
                separator = ", ";
            }
        }
        display.push(')');
        display
    }

    pub(crate) fn configured_rule_expression(
        &self,
        conditions: &[CompiledCondition],
        configured: &honk_config::routing::RoutingCondition,
    ) -> String {
        if conditions.is_empty() {
            return rule_expression(conditions);
        }
        conditions
            .iter()
            .map(|condition| self.condition_display(condition, configured))
            .collect::<Vec<_>>()
            .join(" && ")
    }

    pub(crate) fn condition_expression(&self, condition: &CompiledCondition) -> String {
        let CompiledPredicate::Domain(id) = condition.predicate else {
            return condition_expression(condition)
                .expect("non-domain predicate retains its values");
        };
        let matcher = &self.domain_matchers[id as usize];
        let mut expression = format!("{}domain(", if condition.not { "!" } else { "" });
        for (index, (kind, value)) in matcher.key().alternatives.iter().enumerate() {
            let kind = match (matcher, kind) {
                (super::DomainMatcher::Ordinary { .. }, 0) | (_, 3) => "regex",
                (_, 0) => "full",
                (_, 1) => "suffix",
                _ => "keyword",
            };
            write!(
                expression,
                "{}{kind}: {value}",
                if index == 0 { "" } else { ", " }
            )
            .unwrap();
            if expression.len() > 512 {
                return bounded_expression(expression);
            }
        }
        expression.push(')');
        expression
    }

    pub(crate) fn rule_expression(&self, conditions: &[CompiledCondition]) -> String {
        join_expressions(
            conditions
                .iter()
                .map(|condition| self.condition_expression(condition)),
        )
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

pub(crate) fn condition_expression(condition: &CompiledCondition) -> Option<String> {
    let ip_display = |net: &ipnet::IpNet| {
        if net.prefix_len() == if net.addr().is_ipv4() { 32 } else { 128 } {
            net.addr().to_string()
        } else {
            net.to_string()
        }
    };
    let (kind, values) = match &condition.predicate {
        CompiledPredicate::Domain(_) => return None,
        CompiledPredicate::DestinationIp(matcher) => (
            "dip",
            matcher
                .nets()
                .iter()
                .map(ip_display)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::SourceIp(matcher) => (
            "sip",
            matcher
                .nets()
                .iter()
                .map(ip_display)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::DestinationPort(ports) | CompiledPredicate::SourcePort(ports) => (
            if matches!(condition.predicate, CompiledPredicate::DestinationPort(_)) {
                "dport"
            } else {
                "sport"
            },
            ports
                .iter()
                .map(|port| {
                    if port.start == port.end {
                        port.start.to_string()
                    } else {
                        format!("{}-{}", port.start, port.end)
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::Protocol(mask) => (
            "l4proto",
            [(1, "tcp"), (2, "udp")]
                .into_iter()
                .filter_map(|(bit, name)| (mask & bit != 0).then_some(name))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::IpVersion(mask) => (
            "ipversion",
            [(1, "4"), (2, "6")]
                .into_iter()
                .filter_map(|(bit, name)| (mask & bit != 0).then_some(name))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::Dscp(values) => (
            "dscp",
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CompiledPredicate::ProcessName(values) => ("pname", values.join(", ")),
        CompiledPredicate::Mac(values) => (
            "mac",
            values
                .iter()
                .map(|mac| {
                    mac.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(":")
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
    };
    Some(bounded_expression(format!(
        "{}{kind}({values})",
        if condition.not { "!" } else { "" }
    )))
}

fn bounded_expression(mut expression: String) -> String {
    if expression.len() > 512 {
        let mut end = 512;
        while !expression.is_char_boundary(end) {
            end -= 1;
        }
        expression.truncate(end);
        expression.push('…');
    }
    expression
}

fn join_expressions(expressions: impl Iterator<Item = String>) -> String {
    let mut joined = String::new();
    for expression in expressions {
        if !joined.is_empty() {
            joined.push_str(" && ");
        }
        joined.push_str(&expression);
        if joined.len() > 512 {
            return bounded_expression(joined);
        }
    }
    if joined.is_empty() {
        "empty rule (never matches)".into()
    } else {
        joined
    }
}

pub(crate) fn rule_expression(conditions: &[CompiledCondition]) -> String {
    conditions
        .iter()
        .map(condition_expression)
        .collect::<Option<Vec<_>>>()
        .map(|expressions| join_expressions(expressions.into_iter()))
        .unwrap_or_default()
}
