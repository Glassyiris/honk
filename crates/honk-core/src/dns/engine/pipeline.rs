use std::net::SocketAddr;

use tracing::debug;

use super::DnsEngine;
use crate::dns::cache::{CacheKey, OperationKind};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode, is_filtered_qtype};
use crate::dns::outcome::{DnsOutcome, OutcomeStatus};
use crate::dns::planner::RequestPlan;
use crate::dns::singleflight::{FlightLeader, FlightRole};

mod cache;
mod flight;
mod operation;
mod plan;

use plan::{rejected_outcome, request_exchange};

pub(crate) async fn resolve(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    bypass_cache_read: bool,
    mode: ResolveMode,
) -> Result<DnsOutcome, DnsForwardError> {
    resolve_with_owner(
        forwarder,
        raw_query,
        original_dst,
        bypass_cache_read,
        mode,
        None,
    )
    .await
}

pub(crate) async fn resolve_with_owner(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    bypass_cache_read: bool,
    mode: ResolveMode,
    refresh_owner: Option<FlightLeader>,
) -> Result<DnsOutcome, DnsForwardError> {
    debug!("DNS forwarder: resolving {} bytes", raw_query.len());
    let engine = DnsEngine::from_router(&forwarder.routing, forwarder.policy_id.clone())?;
    let prepared = match mode {
        ResolveMode::Strict => engine.prepare(raw_query, original_dst)?,
        ResolveMode::Compatibility => engine.prepare_compatibility(raw_query, original_dst)?,
    };
    let qtype = prepared.qtype();
    let reuse_eligible = prepared.is_cacheable() && prepared.is_coalescable();

    if is_filtered_qtype(qtype, &forwarder.strategy) {
        return rejected_outcome(
            forwarder,
            &engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }
    if matches!(prepared.plan(), RequestPlan::Reject) {
        return rejected_outcome(
            forwarder,
            &engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }

    let (logical_upstream, request_scope) = request_exchange(&prepared)?;
    let resolve_key = CacheKey::new(
        prepared.query(),
        engine.policy_id().cloned(),
        request_scope.clone(),
        OperationKind::Resolve,
    );
    let cache_key = resolve_key.storage_key();
    let refresh_key = CacheKey::new(
        prepared.query(),
        engine.policy_id().cloned(),
        request_scope.clone(),
        OperationKind::Refresh,
    );
    if reuse_eligible
        && let Some(outcome) = cache::lookup(
            forwarder,
            &engine,
            &prepared,
            raw_query,
            original_dst,
            &cache_key,
            &refresh_key,
            bypass_cache_read,
            true,
            mode,
        )
        .await?
    {
        return Ok(outcome);
    }

    if let Some(owner) = refresh_owner {
        return run_as_leader(
            owner,
            forwarder,
            &engine,
            &prepared,
            raw_query,
            original_dst,
            &cache_key,
            logical_upstream,
            request_scope.clone(),
            reuse_eligible,
            mode,
        )
        .await;
    }

    let operation = if bypass_cache_read {
        OperationKind::Refresh
    } else {
        OperationKind::Resolve
    };
    let flight_key = CacheKey::new(
        prepared.query(),
        engine.policy_id().cloned(),
        request_scope.clone(),
        operation,
    );
    let flights = forwarder.cache_service().await.singleflight();
    loop {
        match flights.acquire(flight_key.clone()) {
            FlightRole::Bypass => {
                return operation::run(
                    forwarder,
                    &engine,
                    &prepared,
                    raw_query,
                    original_dst,
                    &cache_key,
                    logical_upstream,
                    request_scope.clone(),
                    reuse_eligible,
                    mode,
                )
                .await;
            }
            FlightRole::Ready(template) => {
                return flight::waiter_outcome(
                    forwarder,
                    &engine,
                    &prepared,
                    raw_query,
                    original_dst,
                    &cache_key,
                    &refresh_key,
                    bypass_cache_read,
                    mode,
                    template,
                )
                .await;
            }
            FlightRole::Waiter(waiter) => match waiter.receive().await {
                Some(template) => {
                    return flight::waiter_outcome(
                        forwarder,
                        &engine,
                        &prepared,
                        raw_query,
                        original_dst,
                        &cache_key,
                        &refresh_key,
                        bypass_cache_read,
                        mode,
                        template,
                    )
                    .await;
                }
                None => continue,
            },
            FlightRole::Leader(leader) => {
                if !bypass_cache_read
                    && let Some(outcome) = cache::lookup(
                        forwarder,
                        &engine,
                        &prepared,
                        raw_query,
                        original_dst,
                        &cache_key,
                        &refresh_key,
                        false,
                        true,
                        mode,
                    )
                    .await?
                {
                    return Ok(flight::publish_outcome(leader, outcome));
                }
                return run_as_leader(
                    leader,
                    forwarder,
                    &engine,
                    &prepared,
                    raw_query,
                    original_dst,
                    &cache_key,
                    logical_upstream,
                    request_scope.clone(),
                    reuse_eligible,
                    mode,
                )
                .await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_as_leader(
    leader: FlightLeader,
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &super::PreparedQuery,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    cache_key: &str,
    logical_upstream: crate::dns::planner::UpstreamTag,
    request_scope: crate::dns::planner::RequestScope,
    reuse_eligible: bool,
    mode: ResolveMode,
) -> Result<DnsOutcome, DnsForwardError> {
    let outcome = operation::run(
        forwarder,
        engine,
        prepared,
        raw_query,
        original_dst,
        cache_key,
        logical_upstream,
        request_scope,
        reuse_eligible,
        mode,
    )
    .await?;
    Ok(flight::publish_outcome(leader, outcome))
}
