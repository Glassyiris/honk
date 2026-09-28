//! Read-only DNS routing rules of the running generation.

use std::time::{Duration, Instant};

use axum::{
    Json,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsRequestAction, DnsResponseAction, DnsRouting,
};
use serde::Serialize;
use serde_json::{Value, json};

use super::super::{
    ApiError, ErrorCode, NativeState, catalog::snapshot_unavailable, error, parse_query,
    routing::RuleSource, types::RequestId,
};

/// Bounds each list, including its fallback.
const MAX_RULES: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn capability() -> Value {
    json!({"available":true,"max_rules":MAX_RULES})
}

/// Mirrors `/rules` ids with the list name in front of the ordinal:
/// `{instance}:{generation}:dns_request:rule:{index}` or `…:dns_request:fallback`.
fn rule_id(instance: &str, generation: u64, list: &str, index: Option<usize>) -> String {
    match index {
        Some(index) => format!("{instance}:{generation}:{list}:rule:{index}"),
        None => format!("{instance}:{generation}:{list}:fallback"),
    }
}

#[derive(Debug, Serialize)]
struct DnsRule {
    rule_id: String,
    index: usize,
    expression: String,
    action: &'static str,
    upstream: Option<String>,
    source: Option<RuleSource>,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct DnsRuleList {
    generation_id: String,
    request: Vec<DnsRule>,
    response: Vec<DnsRule>,
}

/// A wire `action` and its `upstream`.
type Action = (&'static str, Option<String>);

/// One list's parsed rules, with their conditions, and its fallback.
struct Parsed<'c> {
    response: bool,
    rules: Vec<(&'c [DnsCond], Action)>,
    fallback: Action,
}

pub(in crate::native_api) async fn serve(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    parse_query(uri, &[], id)?;
    let result = snapshot(state, Instant::now() + TIMEOUT, id).await?;
    Ok(Json(super::super::config::administrative_projection(
        state,
        json!(result),
    )?)
    .into_response())
}

pub(super) async fn snapshot(
    state: &NativeState,
    deadline: Instant,
    id: &RequestId,
) -> Result<DnsRuleList, ApiError> {
    tokio::time::timeout_at(deadline.into(), async {
        // Reload publishes the config, its generation and the accepted
        // sources under the config write lock, so this read pins all three.
        let config = state.config.read().await;
        let generation = state.diagnostics.read().generation;
        list(state, &config.dns.routing, generation, id)
    })
    .await
    .map_err(|_| snapshot_unavailable(id))?
}

fn list(
    state: &NativeState,
    routing: &DnsRouting,
    generation: u64,
    id: &RequestId,
) -> Result<DnsRuleList, ApiError> {
    let request = routing.effective_request();
    let lists = [
        Parsed {
            response: false,
            rules: request
                .rules
                .iter()
                .map(|rule| (rule.conditions.as_slice(), request_action(&rule.action)))
                .collect(),
            fallback: request_action(&request.fallback),
        },
        Parsed {
            response: true,
            rules: routing
                .response
                .rules
                .iter()
                .map(|rule| (rule.conditions.as_slice(), response_action(&rule.action)))
                .collect(),
            fallback: response_action(&routing.response.fallback),
        },
    ];
    if lists.iter().any(|list| list.rules.len() >= MAX_RULES) {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::TemporarilyUnavailable,
            "A DNS rule list exceeds resources.dns_rules.max_rules",
            id,
        )
        .with_retry_after(1));
    }
    let [request, response] = lists.map(|list| entries(state, generation, list));
    Ok(DnsRuleList {
        generation_id: format!("{}:{generation}", state.instance_id),
        request,
        response,
    })
}

fn entries(state: &NativeState, generation: u64, list: Parsed<'_>) -> Vec<DnsRule> {
    let name = if list.response {
        "dns_response"
    } else {
        "dns_request"
    };
    let located = |index| {
        state
            .observation
            .configuration
            .dns_rule_source(list.response, index)
            .map(super::super::routing::located)
    };
    let count = list.rules.len();
    let entry = |index: Option<usize>, (action, upstream): Action| {
        let (source, expression) = located(index).unzip();
        DnsRule {
            rule_id: rule_id(&state.instance_id, generation, name, index),
            index: index.unwrap_or(count),
            expression: expression.unwrap_or_default(),
            action,
            upstream,
            source,
            kind: if index.is_some() { "rule" } else { "fallback" },
        }
    };
    let mut rules = Vec::with_capacity(count + 1);
    for (index, (conditions, action)) in list.rules.into_iter().enumerate() {
        let mut rule = entry(Some(index), action);
        if rule.expression.is_empty() {
            rule.expression = format!("{} -> {}", display(conditions), target(&rule));
        }
        rules.push(rule);
    }
    let mut fallback = entry(None, list.fallback);
    if fallback.expression.is_empty() {
        fallback.expression = format!("fallback: {}", target(&fallback));
    }
    rules.push(fallback);
    rules
}

fn request_action(action: &DnsRequestAction) -> Action {
    match action {
        DnsRequestAction::Upstream(name) => ("upstream", Some(name.clone())),
        DnsRequestAction::AsIs => ("asis", None),
        DnsRequestAction::Reject => ("reject", None),
    }
}

fn response_action(action: &DnsResponseAction) -> Action {
    match action {
        DnsResponseAction::Upstream(name) => ("requery", Some(name.clone())),
        DnsResponseAction::Accept => ("accept", None),
        DnsResponseAction::Reject => ("reject", None),
    }
}

/// The configuration spelling of an action: the upstream name, or the keyword.
fn target(rule: &DnsRule) -> &str {
    rule.upstream.as_deref().unwrap_or(rule.action)
}

/// A readable form of parsed conditions, used only when the accepted sources
/// cannot place the rule, so there is no source text to show.
fn display(conditions: &[DnsCond]) -> String {
    let render = |name: &str, not: bool, args: Vec<String>| {
        format!("{}{name}({})", if not { "!" } else { "" }, args.join(", "))
    };
    conditions
        .iter()
        .map(|condition| match condition {
            DnsCond::Qname { not, matchers } => render(
                "qname",
                *not,
                matchers
                    .iter()
                    .map(|matcher| match matcher {
                        DnsDomainMatcher::Full(value) => format!("full: {value}"),
                        DnsDomainMatcher::Suffix(value) => format!("suffix: {value}"),
                        DnsDomainMatcher::Keyword(value) => format!("keyword: {value}"),
                        DnsDomainMatcher::Regex(value) => format!("regex: {value}"),
                        DnsDomainMatcher::Geosite(value) => format!("geosite: {value}"),
                    })
                    .collect(),
            ),
            DnsCond::Qtype { not, types } => {
                render("qtype", *not, types.iter().map(u16::to_string).collect())
            }
            DnsCond::Sip { not, cidrs } => render("sip", *not, cidrs.clone()),
            DnsCond::Upstream { not, names } => render("upstream", *not, names.clone()),
            DnsCond::Ip { not, cidrs, geoip } => render(
                "ip",
                *not,
                cidrs
                    .iter()
                    .cloned()
                    .chain(geoip.iter().map(|code| format!("geoip: {code}")))
                    .collect(),
            ),
        })
        .collect::<Vec<_>>()
        .join(" && ")
}
