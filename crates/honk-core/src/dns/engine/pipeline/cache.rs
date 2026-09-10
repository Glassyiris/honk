use tracing::debug;

use super::super::effective_expiry;
use super::ExecutionContext;
use crate::dns::cache::{CacheKey, ExactLookup, OperationKind};
use crate::dns::forwarder::{
    DnsForwardError, ResolveMode, extract_min_ttl, extract_min_ttl_including_zero,
    extract_soa_negative_ttl, rewrite_answer_ttls,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};

pub(super) async fn lookup(
    context: &ExecutionContext<'_>,
    allow_refresh: bool,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    if !context.forwarder.cache_enabled || context.bypass_cache_read {
        return Ok(None);
    }
    let cache = context.forwarder.cache_service().await;
    let (entry, revision) = match cache.lookup_exact(
        &context.cache_key,
        matches!(context.mode, ResolveMode::Strict),
    ) {
        ExactLookup::Negative(hit) => {
            let response =
                crate::dns::response::build_dns_error_response(context.raw_query, hit.rcode);
            let response = context
                .forwarder
                .apply_prefer_strategy(
                    context.raw_query,
                    context.prepared.query(),
                    context.prepared.qtype(),
                    response.into(),
                    context.metadata,
                    context.mode,
                )
                .await?;
            return context
                .forwarder
                .outcome_from_wire(
                    context.engine,
                    context.prepared,
                    response,
                    None,
                    OutcomeStatus::Accepted,
                    Provenance::Cache,
                    EffectiveExpiry::cacheable(hit.remaining_ttl),
                    None,
                    None,
                    Vec::new(),
                    context.mode,
                )
                .map(Some);
        }
        ExactLookup::Positive { entry, revision } => (entry, revision),
        ExactLookup::Miss => return Ok(None),
    };
    let remaining = entry.remaining_ttl_secs();
    debug!(remaining, "DNS forwarder: positive cache hit");
    let refresh_after = (entry.min_ttl as u64 / 10).max(1);
    if allow_refresh && remaining <= refresh_after {
        let refresh_key = context.cache_key.with_operation(OperationKind::Refresh);
        context.forwarder.maybe_spawn_refresh(
            context.raw_query,
            context.metadata,
            context.mode,
            refresh_key,
            context.publication_epoch,
            revision,
        );
    }
    let response = entry.response;
    let response = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.query(),
            context.prepared.qtype(),
            response,
            context.metadata,
            context.mode,
        )
        .await?;
    context
        .forwarder
        .outcome_from_wire(
            context.engine,
            context.prepared,
            response,
            None,
            OutcomeStatus::Accepted,
            Provenance::Cache,
            EffectiveExpiry::cacheable(std::time::Duration::from_secs(remaining)),
            None,
            None,
            Vec::new(),
            context.mode,
        )
        .map(Some)
}

pub(super) async fn store(
    context: &ExecutionContext<'_>,
    cache_key: &CacheKey,
    response: &mut [u8],
    rejected_wire: Option<&[u8]>,
    class: ResponseClass,
) -> EffectiveExpiry {
    let lifetime_wire = rejected_wire.unwrap_or(response);
    if !context.reuse_eligible {
        return EffectiveExpiry::do_not_cache();
    }
    let fixed_ttl = context
        .forwarder
        .routing
        .fixed_ttl(context.prepared.domain());
    if fixed_ttl == Some(0) {
        return EffectiveExpiry::do_not_cache();
    }
    if matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail) {
        let soa_ttl = extract_soa_negative_ttl(lifetime_wire);
        let negative_ttl = if class == ResponseClass::Nxdomain {
            let Some(ttl) = soa_ttl.filter(|ttl| *ttl > 0) else {
                if context.forwarder.cache_enabled {
                    context
                        .forwarder
                        .cache_service()
                        .await
                        .supersede_exact_if_current(
                            context.publication_epoch,
                            cache_key.clone(),
                            context.refreshing,
                        );
                }
                return EffectiveExpiry::do_not_cache();
            };
            ttl.min(300)
        } else {
            soa_ttl.unwrap_or(60).clamp(1, 300)
        };
        if context.forwarder.cache_enabled {
            let rcode = response.get(3).copied().unwrap_or_default() & 0x0f;
            context
                .forwarder
                .cache_service()
                .await
                .put_negative_if_current(
                    context.publication_epoch,
                    cache_key.clone(),
                    negative_ttl,
                    rcode,
                    context.refreshing,
                );
        }
        return EffectiveExpiry::cacheable(std::time::Duration::from_secs(u64::from(negative_ttl)));
    }

    let rcode = response.get(3).copied().unwrap_or_default() & 0x0f;
    let expiry = if class == ResponseClass::Nodata && rcode == 0 {
        let ttl = fixed_ttl.unwrap_or_else(|| {
            extract_soa_negative_ttl(lifetime_wire)
                .unwrap_or(0)
                .min(300)
        });
        if ttl == 0 {
            EffectiveExpiry::do_not_cache()
        } else {
            EffectiveExpiry::cacheable(std::time::Duration::from_secs(u64::from(ttl)))
        }
    } else {
        let answer_ttl = if class == ResponseClass::Positive && rcode == 0 {
            extract_min_ttl_including_zero(lifetime_wire)
        } else {
            extract_min_ttl(lifetime_wire)
        };
        effective_expiry(fixed_ttl, context.forwarder.cache_ttl, answer_ttl)
    };
    if !expiry.is_cacheable() {
        if context.forwarder.cache_enabled {
            context
                .forwarder
                .cache_service()
                .await
                .supersede_exact_if_current(
                    context.publication_epoch,
                    cache_key.clone(),
                    context.refreshing,
                );
        }
        return expiry;
    }
    if context.forwarder.cache_enabled {
        let cache_ttl = expiry.ttl().as_secs().min(u64::from(u32::MAX)) as u32;
        rewrite_answer_ttls(response, cache_ttl);
        context
            .forwarder
            .cache_service()
            .await
            .put_exact_if_current(
                context.publication_epoch,
                cache_key.clone(),
                response.to_owned(),
                cache_ttl,
                context.refreshing,
            );
    }
    expiry
}
