use std::time::Duration;

use tracing::debug;

use super::{ExecutionContext, cache};
use crate::dns::engine::ResponseDirective;
use crate::dns::forwarder::{
    DnsForwardError, ResolveMode, SERVE_STALE_TTL_SECS, make_empty_response, traversal_strings,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{ResponseTraversal, UpstreamTag};
use crate::dns::singleflight::FlightLeader;

pub(super) async fn run_as_leader(
    leader: FlightLeader,
    context: &ExecutionContext<'_>,
) -> Result<DnsOutcome, DnsForwardError> {
    let outcome = run(context).await?;
    Ok(super::flight::publish_outcome(leader, outcome))
}

pub(super) async fn run(context: &ExecutionContext<'_>) -> Result<DnsOutcome, DnsForwardError> {
    let upstream_result = context
        .forwarder
        .exchange(&context.request_scope, context.raw_query)
        .await;
    let (mut response, mut upstream_name) = match upstream_result {
        Ok(response) => (response, context.logical_upstream.clone()),
        Err(source) => {
            if context.reuse_eligible
                && let Some(stale) = stale_outcome(
                    context,
                    &context.logical_upstream,
                    vec![context.logical_upstream.as_str().to_owned()],
                )
                .await?
            {
                return Ok(stale);
            }
            return Err(DnsForwardError::Exchange {
                upstream: context.logical_upstream.as_str().to_owned(),
                source,
            });
        }
    };

    let mut traversal = ResponseTraversal::start(context.logical_upstream.clone());
    let (status, class) = loop {
        match context.engine.analyze(
            context.prepared,
            traversal,
            response,
            matches!(context.mode, ResolveMode::Strict),
        )? {
            ResponseDirective::Accept {
                response: analyzed,
                traversal: accepted,
            } => {
                response = analyzed.wire;
                traversal = accepted;
                if context.reuse_eligible
                    && analyzed.class == ResponseClass::Servfail
                    && let Some(stale) =
                        stale_outcome(context, &upstream_name, traversal_strings(&traversal))
                            .await?
                {
                    return Ok(stale);
                }
                break (OutcomeStatus::Accepted, analyzed.class);
            }
            ResponseDirective::Reject {
                response: analyzed,
                traversal: rejected,
            } => {
                response = make_empty_response(
                    context.raw_query,
                    context.prepared.domain(),
                    context.prepared.qtype(),
                );
                traversal = rejected;
                break (OutcomeStatus::Rejected, analyzed.class);
            }
            ResponseDirective::Requery {
                upstream,
                traversal: next,
            } => {
                response = context
                    .forwarder
                    .upstream_pool
                    .query(upstream.as_str(), context.raw_query)
                    .await
                    .map_err(|source| DnsForwardError::Exchange {
                        upstream: upstream.as_str().to_owned(),
                        source,
                    })?;
                upstream_name = upstream;
                traversal = next;
            }
        }
    };

    let exact_cache_key = context.cache_key.clone();
    let expiry = cache::store(context, &exact_cache_key, &mut response, class).await;
    if let Some(notifier) = &context.forwarder.notifier {
        notifier.on_domain_resolved(context.prepared.domain(), &response);
    }
    debug!(
        ttl = expiry.ttl().as_secs(),
        bytes = response.len(),
        "DNS forwarder: resolved query"
    );
    let response = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.domain(),
            context.prepared.qtype(),
            response,
            context.original_dst,
            context.prepared.query().ingress(),
        )
        .await?;
    context.forwarder.outcome_from_wire(
        context.engine,
        context.prepared,
        response,
        status,
        Provenance::Upstream,
        expiry,
        Some(context.logical_upstream.as_str().to_owned()),
        Some(upstream_name.as_str().to_owned()),
        traversal_strings(&traversal),
        context.mode,
    )
}

async fn stale_outcome(
    context: &ExecutionContext<'_>,
    final_upstream: &UpstreamTag,
    history: Vec<String>,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    let Some(stale) = context
        .forwarder
        .try_serve_stale(
            &context.cache_key,
            context.raw_query,
            context.prepared.domain(),
        )
        .await
    else {
        return Ok(None);
    };
    let stale = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.domain(),
            context.prepared.qtype(),
            stale,
            context.original_dst,
            context.prepared.query().ingress(),
        )
        .await?;
    context
        .forwarder
        .outcome_from_wire(
            context.engine,
            context.prepared,
            stale,
            OutcomeStatus::Accepted,
            Provenance::Stale,
            EffectiveExpiry::cacheable(Duration::from_secs(u64::from(SERVE_STALE_TTL_SECS))),
            Some(context.logical_upstream.as_str().to_owned()),
            Some(final_upstream.as_str().to_owned()),
            history,
            context.mode,
        )
        .map(Some)
}
