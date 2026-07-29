use std::net::SocketAddr;
use std::time::Duration;

use tracing::debug;

use super::{DnsEngine, ResponseDirective};
use crate::dns::forwarder::{
    DnsForwardError, DnsForwarder, ResolveMode, SERVE_STALE_TTL_SECS, dns_cache_key,
    is_filtered_qtype, make_empty_response, qtype_name, traversal_strings,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{RequestPlan, ResponseTraversal};

mod cache;
mod plan;

use plan::{rejected_outcome, request_exchange};

pub(crate) async fn resolve(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    bypass_cache_read: bool,
    mode: ResolveMode,
) -> Result<DnsOutcome, DnsForwardError> {
    debug!("DNS forwarder: resolving {} bytes", raw_query.len());
    let engine = DnsEngine::from_router(&forwarder.routing, forwarder.policy_id.clone())?;
    let prepared = match mode {
        ResolveMode::Strict => engine.prepare(raw_query, original_dst)?,
        ResolveMode::Compatibility => engine.prepare_compatibility(raw_query, original_dst)?,
    };
    let domain = prepared.domain();
    let qtype = prepared.qtype();
    let cache_key = dns_cache_key(domain, qtype);
    let reuse_eligible = prepared.is_cacheable() && prepared.is_coalescable();

    debug!(
        domain,
        qtype, cache_key, reuse_eligible, "DNS forwarder: planned query"
    );

    if is_filtered_qtype(qtype, &forwarder.strategy) {
        debug!(
            qtype = qtype_name(qtype),
            strategy = ?forwarder.strategy,
            "DNS forwarder: dropping query due to strategy"
        );
        return rejected_outcome(
            forwarder,
            &engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }

    match prepared.plan() {
        RequestPlan::Reject => {
            debug!(domain, "DNS forwarder: request rejected");
            return rejected_outcome(
                forwarder,
                &engine,
                &prepared,
                raw_query,
                mode,
                OutcomeStatus::Rejected,
            );
        }
        RequestPlan::Exchange(_) => {}
    }

    if reuse_eligible
        && let Some(outcome) = cache::lookup(
            forwarder,
            &engine,
            &prepared,
            raw_query,
            original_dst,
            &cache_key,
            bypass_cache_read,
            mode,
        )
        .await?
    {
        return Ok(outcome);
    }

    let (logical_upstream, request_scope) = request_exchange(&prepared)?;
    let upstream_result = forwarder.exchange(request_scope, raw_query).await;
    let (mut response, mut upstream_name) = match upstream_result {
        Ok(response) => (response, logical_upstream.clone()),
        Err(source) => {
            if reuse_eligible
                && let Some(stale) = forwarder
                    .try_serve_stale(&cache_key, raw_query, domain)
                    .await
            {
                let stale = forwarder
                    .apply_prefer_strategy(raw_query, domain, qtype, stale, original_dst)
                    .await?;
                return forwarder.outcome_from_wire(
                    &engine,
                    &prepared,
                    stale,
                    OutcomeStatus::Accepted,
                    Provenance::Stale,
                    EffectiveExpiry::cacheable(Duration::from_secs(u64::from(
                        SERVE_STALE_TTL_SECS,
                    ))),
                    Some(logical_upstream.as_str().to_owned()),
                    Some(logical_upstream.as_str().to_owned()),
                    vec![logical_upstream.as_str().to_owned()],
                    mode,
                );
            }
            return Err(DnsForwardError::Exchange {
                upstream: logical_upstream.as_str().to_owned(),
                source,
            });
        }
    };

    let mut traversal = ResponseTraversal::start(logical_upstream.clone());
    let (status, class) = loop {
        match engine.analyze(
            &prepared,
            traversal,
            response,
            matches!(mode, ResolveMode::Strict),
        )? {
            ResponseDirective::Accept {
                response: analyzed,
                traversal: accepted,
            } => {
                response = analyzed.wire;
                traversal = accepted;
                if reuse_eligible
                    && analyzed.class == ResponseClass::Servfail
                    && let Some(stale) = forwarder
                        .try_serve_stale(&cache_key, raw_query, domain)
                        .await
                {
                    let stale = forwarder
                        .apply_prefer_strategy(raw_query, domain, qtype, stale, original_dst)
                        .await?;
                    return forwarder.outcome_from_wire(
                        &engine,
                        &prepared,
                        stale,
                        OutcomeStatus::Accepted,
                        Provenance::Stale,
                        EffectiveExpiry::cacheable(Duration::from_secs(u64::from(
                            SERVE_STALE_TTL_SECS,
                        ))),
                        Some(logical_upstream.as_str().to_owned()),
                        Some(upstream_name.as_str().to_owned()),
                        traversal_strings(&traversal),
                        mode,
                    );
                }
                break (OutcomeStatus::Accepted, analyzed.class);
            }
            ResponseDirective::Reject {
                response: analyzed,
                traversal: rejected,
            } => {
                response = make_empty_response(raw_query, domain, qtype);
                traversal = rejected;
                break (OutcomeStatus::Rejected, analyzed.class);
            }
            ResponseDirective::Requery {
                upstream,
                traversal: next,
            } => {
                response = forwarder
                    .upstream_pool
                    .query(upstream.as_str(), raw_query)
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

    let expiry = cache::store(
        forwarder,
        &prepared,
        &cache_key,
        &mut response,
        class,
        reuse_eligible,
    )
    .await;
    if let Some(notifier) = &forwarder.notifier {
        notifier.on_domain_resolved(domain, &response);
    }
    debug!(
        domain,
        upstream = upstream_name.as_str(),
        ttl = expiry.ttl().as_secs(),
        bytes = response.len(),
        "DNS forwarder: resolved query"
    );

    let response = forwarder
        .apply_prefer_strategy(raw_query, domain, qtype, response, original_dst)
        .await?;
    forwarder.outcome_from_wire(
        &engine,
        &prepared,
        response,
        status,
        Provenance::Upstream,
        expiry,
        Some(logical_upstream.as_str().to_owned()),
        Some(upstream_name.as_str().to_owned()),
        traversal_strings(&traversal),
        mode,
    )
}
