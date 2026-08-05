use std::net::SocketAddr;

use tracing::debug;

use super::{DnsEngine, PreparedQuery};
use crate::dns::cache::{CacheKey, OperationKind, PublicationEpoch};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode, is_filtered_qtype};
use crate::dns::outcome::{DnsOutcome, OutcomeStatus};
use crate::dns::planner::{RequestPlan, RequestScope, UpstreamTag};
use crate::dns::query::IngressProfile;
use crate::dns::singleflight::{FlightLeader, FlightRole};

mod cache;
mod flight;
mod operation;
mod plan;

use plan::{rejected_outcome, request_exchange};

pub(crate) struct ResolveExecution {
    refresh_owner: Option<FlightLeader>,
    publication_epoch: PublicationEpoch,
}

pub(super) struct ExecutionContext<'a> {
    pub(super) forwarder: &'a DnsForwarder,
    pub(super) engine: &'a DnsEngine,
    pub(super) prepared: &'a PreparedQuery,
    pub(super) raw_query: &'a [u8],
    pub(super) original_dst: Option<SocketAddr>,
    pub(super) cache_key: CacheKey,
    pub(super) refresh_key: CacheKey,
    pub(super) logical_upstream: UpstreamTag,
    pub(super) request_scope: RequestScope,
    pub(super) reuse_eligible: bool,
    pub(super) bypass_cache_read: bool,
    pub(super) mode: ResolveMode,
    pub(super) publication_epoch: PublicationEpoch,
}

impl ResolveExecution {
    pub(crate) const fn foreground(publication_epoch: PublicationEpoch) -> Self {
        Self {
            refresh_owner: None,
            publication_epoch,
        }
    }

    pub(crate) const fn refresh(owner: FlightLeader, publication_epoch: PublicationEpoch) -> Self {
        Self {
            refresh_owner: Some(owner),
            publication_epoch,
        }
    }
}

pub(crate) async fn resolve(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    ingress: IngressProfile,
    bypass_cache_read: bool,
    mode: ResolveMode,
    publication_epoch: PublicationEpoch,
) -> Result<DnsOutcome, DnsForwardError> {
    resolve_with_owner(
        forwarder,
        raw_query,
        original_dst,
        ingress,
        bypass_cache_read,
        mode,
        ResolveExecution::foreground(publication_epoch),
    )
    .await
}

pub(crate) async fn resolve_with_owner(
    forwarder: &DnsForwarder,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    ingress: IngressProfile,
    bypass_cache_read: bool,
    mode: ResolveMode,
    execution: ResolveExecution,
) -> Result<DnsOutcome, DnsForwardError> {
    let ResolveExecution {
        refresh_owner,
        publication_epoch,
    } = execution;
    debug!("DNS forwarder: resolving {} bytes", raw_query.len());
    let engine = forwarder.engine().await?;
    let prepared = match mode {
        ResolveMode::Strict => engine.prepare(raw_query, original_dst, ingress)?,
        ResolveMode::Compatibility => {
            engine.prepare_compatibility(raw_query, original_dst, ingress)?
        }
    };
    let qtype = prepared.qtype();
    let reuse_eligible = prepared.is_cacheable() && prepared.is_coalescable();

    if is_filtered_qtype(qtype, &forwarder.strategy) {
        return rejected_outcome(
            forwarder,
            engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }
    if matches!(prepared.plan(), RequestPlan::Reject) {
        return rejected_outcome(
            forwarder,
            engine,
            &prepared,
            raw_query,
            mode,
            OutcomeStatus::Rejected,
        );
    }

    let (logical_upstream, request_scope) = request_exchange(&prepared)?;
    let resolve_key = prepared.cache_key(request_scope.clone(), OperationKind::Resolve);
    let refresh_key = resolve_key.with_operation(OperationKind::Refresh);
    let context = ExecutionContext {
        forwarder,
        engine,
        prepared: &prepared,
        raw_query,
        original_dst,
        cache_key: resolve_key,
        refresh_key,
        logical_upstream,
        request_scope: request_scope.clone(),
        reuse_eligible,
        bypass_cache_read,
        mode,
        publication_epoch,
    };
    if reuse_eligible && let Some(outcome) = cache::lookup(&context, true).await? {
        return Ok(outcome);
    }

    if !reuse_eligible {
        return operation::run(&context).await;
    }

    if let Some(owner) = refresh_owner {
        return operation::run_as_leader(owner, &context).await;
    }

    let operation = if bypass_cache_read {
        OperationKind::Refresh
    } else {
        OperationKind::Resolve
    };
    let flight_key = context.cache_key.with_operation(operation);
    let flights = forwarder.cache_service().await.singleflight();
    loop {
        match flights.acquire(flight_key.clone()) {
            FlightRole::Rejected => return Err(DnsForwardError::Overloaded),
            FlightRole::Ready(template) => {
                return flight::waiter_outcome(&context, template).await;
            }
            FlightRole::Waiter(waiter) => match waiter.receive().await {
                Some(template) => {
                    return flight::waiter_outcome(&context, template).await;
                }
                None => continue,
            },
            FlightRole::Leader(leader) => {
                if !bypass_cache_read && let Some(outcome) = cache::lookup(&context, true).await? {
                    return Ok(flight::publish_outcome(leader, outcome));
                }
                return operation::run_as_leader(leader, &context).await;
            }
        }
    }
}
