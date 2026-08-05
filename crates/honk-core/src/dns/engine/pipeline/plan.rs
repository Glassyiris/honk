use super::super::{DnsEngine, EngineError, PreparedQuery};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode, make_empty_response};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance};
use crate::dns::planner::{RequestPlan, RequestScope, UpstreamTag};

pub(super) fn request_exchange(
    prepared: &PreparedQuery,
) -> Result<(UpstreamTag, &RequestScope), DnsForwardError> {
    match prepared.plan() {
        RequestPlan::Exchange(scope @ RequestScope::AsIs(_)) => {
            Ok((UpstreamTag::new("asis").map_err(EngineError::from)?, scope))
        }
        RequestPlan::Exchange(scope @ RequestScope::Upstream(upstream)) => {
            Ok((upstream.clone(), scope))
        }
        RequestPlan::Reject => Err(DnsForwardError::RejectedPlanEscaped),
    }
}

pub(super) fn rejected_outcome(
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &PreparedQuery,
    raw_query: &[u8],
    mode: ResolveMode,
    status: OutcomeStatus,
) -> Result<DnsOutcome, DnsForwardError> {
    forwarder.outcome_from_wire(
        engine,
        prepared,
        make_empty_response(raw_query, prepared.domain(), prepared.qtype()),
        None,
        status,
        Provenance::Fresh,
        EffectiveExpiry::do_not_cache(),
        None,
        None,
        Vec::new(),
        mode,
    )
}
