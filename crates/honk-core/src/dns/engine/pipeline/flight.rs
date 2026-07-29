use std::net::SocketAddr;
use std::sync::Arc;

use super::cache;
use crate::dns::cache::CacheKey;
use crate::dns::engine::{DnsEngine, PreparedQuery};
use crate::dns::forwarder::{DnsForwardError, DnsForwarder, ResolveMode};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance};
use crate::dns::response::ResponseTemplate;
use crate::dns::singleflight::FlightLeader;

pub(super) fn publish_outcome(mut leader: FlightLeader, outcome: DnsOutcome) -> DnsOutcome {
    if let Some(template) = outcome.template() {
        leader.publish(Arc::new(template.clone()));
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn waiter_outcome(
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &PreparedQuery,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    cache_key: &str,
    refresh_key: &CacheKey,
    bypass_cache_read: bool,
    mode: ResolveMode,
    template: Arc<ResponseTemplate>,
) -> Result<DnsOutcome, DnsForwardError> {
    if !bypass_cache_read
        && let Some(outcome) = cache::lookup(
            forwarder,
            engine,
            prepared,
            raw_query,
            original_dst,
            cache_key,
            refresh_key,
            false,
            false,
            mode,
        )
        .await?
    {
        return Ok(outcome);
    }
    let response = template.render(prepared.query())?;
    forwarder.outcome_from_wire(
        engine,
        prepared,
        response,
        OutcomeStatus::Accepted,
        Provenance::Upstream,
        EffectiveExpiry::do_not_cache(),
        None,
        None,
        Vec::new(),
        mode,
    )
}
