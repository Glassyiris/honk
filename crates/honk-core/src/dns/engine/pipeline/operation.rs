use std::net::SocketAddr;
use std::time::Duration;

use tracing::debug;

use super::cache;
use crate::dns::cache::{CacheKey, OperationKind};
use crate::dns::engine::{DnsEngine, PreparedQuery, ResponseDirective};
use crate::dns::forwarder::{
    DnsForwardError, DnsForwarder, ResolveMode, SERVE_STALE_TTL_SECS, make_empty_response,
    traversal_strings,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::{RequestScope, ResponseTraversal, UpstreamTag};

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &PreparedQuery,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    cache_key: &str,
    logical_upstream: UpstreamTag,
    request_scope: RequestScope,
    reuse_eligible: bool,
    mode: ResolveMode,
) -> Result<DnsOutcome, DnsForwardError> {
    let upstream_result = forwarder.exchange(&request_scope, raw_query).await;
    let (mut response, mut upstream_name) = match upstream_result {
        Ok(response) => (response, logical_upstream.clone()),
        Err(source) => {
            if reuse_eligible
                && let Some(stale) = stale_outcome(
                    forwarder,
                    engine,
                    prepared,
                    raw_query,
                    original_dst,
                    cache_key,
                    &logical_upstream,
                    &logical_upstream,
                    vec![logical_upstream.as_str().to_owned()],
                    mode,
                )
                .await?
            {
                return Ok(stale);
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
            prepared,
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
                    && let Some(stale) = stale_outcome(
                        forwarder,
                        engine,
                        prepared,
                        raw_query,
                        original_dst,
                        cache_key,
                        &logical_upstream,
                        &upstream_name,
                        traversal_strings(&traversal),
                        mode,
                    )
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
                response = make_empty_response(raw_query, prepared.domain(), prepared.qtype());
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

    let exact_cache_key = CacheKey::new(
        prepared.query(),
        engine.policy_id().cloned(),
        request_scope,
        OperationKind::Resolve,
    );
    let expiry = cache::store(
        forwarder,
        prepared,
        &exact_cache_key,
        &mut response,
        class,
        reuse_eligible,
    )
    .await;
    if let Some(notifier) = &forwarder.notifier {
        notifier.on_domain_resolved(prepared.domain(), &response);
    }
    debug!(
        domain = prepared.domain(),
        upstream = upstream_name.as_str(),
        ttl = expiry.ttl().as_secs(),
        bytes = response.len(),
        "DNS forwarder: resolved query"
    );
    let response = forwarder
        .apply_prefer_strategy(
            raw_query,
            prepared.domain(),
            prepared.qtype(),
            response,
            original_dst,
        )
        .await?;
    forwarder.outcome_from_wire(
        engine,
        prepared,
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

#[allow(clippy::too_many_arguments)]
async fn stale_outcome(
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &PreparedQuery,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    cache_key: &str,
    logical_upstream: &UpstreamTag,
    final_upstream: &UpstreamTag,
    history: Vec<String>,
    mode: ResolveMode,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    let Some(stale) = forwarder
        .try_serve_stale(cache_key, raw_query, prepared.domain())
        .await
    else {
        return Ok(None);
    };
    let stale = forwarder
        .apply_prefer_strategy(
            raw_query,
            prepared.domain(),
            prepared.qtype(),
            stale,
            original_dst,
        )
        .await?;
    forwarder
        .outcome_from_wire(
            engine,
            prepared,
            stale,
            OutcomeStatus::Accepted,
            Provenance::Stale,
            EffectiveExpiry::cacheable(Duration::from_secs(u64::from(SERVE_STALE_TTL_SECS))),
            Some(logical_upstream.as_str().to_owned()),
            Some(final_upstream.as_str().to_owned()),
            history,
            mode,
        )
        .map(Some)
}
