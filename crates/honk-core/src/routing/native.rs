//! Side-effect-free inspection of the accepted compiled routing policy.

use std::time::Instant;

use super::{CompiledCondition, CompiledPredicate, PredicateInput, Router};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatchResult {
    Matched,
    NotMatched,
    Indeterminate,
    Skipped,
}

pub(crate) struct EvaluatedRule {
    pub(crate) result: MatchResult,
    pub(crate) conditions: Vec<MatchResult>,
}

pub(crate) struct Evaluation<'a> {
    pub(crate) outbound: Option<&'a str>,
    pub(crate) rules: Vec<EvaluatedRule>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TraceError {
    Steps,
    Deadline,
}

impl Router {
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
