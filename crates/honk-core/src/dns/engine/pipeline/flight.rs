use std::sync::Arc;

use super::{ExecutionContext, cache};
use crate::dns::forwarder::DnsForwardError;
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance};
use crate::dns::response::ResponseTemplate;
use crate::dns::singleflight::FlightLeader;

pub(super) fn publish_outcome(mut leader: FlightLeader, outcome: DnsOutcome) -> DnsOutcome {
    if let Some(template) = outcome.template() {
        leader.publish(Arc::new(template.clone()));
    }
    outcome
}

pub(super) async fn waiter_outcome(
    context: &ExecutionContext<'_>,
    template: Arc<ResponseTemplate>,
) -> Result<DnsOutcome, DnsForwardError> {
    if !context.bypass_cache_read
        && let Some(outcome) = cache::lookup(context, false).await?
    {
        return Ok(outcome);
    }
    let response = template.render(context.prepared.query())?;
    context.forwarder.outcome_from_wire(
        context.engine,
        context.prepared,
        response,
        OutcomeStatus::Accepted,
        Provenance::Upstream,
        EffectiveExpiry::do_not_cache(),
        None,
        None,
        Vec::new(),
        context.mode,
    )
}
