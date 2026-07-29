use std::net::SocketAddr;

use tracing::debug;

use super::super::{DnsEngine, PreparedQuery, effective_expiry};
use crate::dns::forwarder::{
    DnsForwardError, DnsForwarder, ResolveMode, extract_min_ttl, extract_soa_negative_ttl,
    rewrite_answer_ttls,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};

#[allow(clippy::too_many_arguments)]
pub(super) async fn lookup(
    forwarder: &DnsForwarder,
    engine: &DnsEngine,
    prepared: &PreparedQuery,
    raw_query: &[u8],
    original_dst: Option<SocketAddr>,
    cache_key: &str,
    bypass_cache_read: bool,
    mode: ResolveMode,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    if !forwarder.cache_enabled || bypass_cache_read {
        return Ok(None);
    }
    let mut cache = forwarder.cache.lock().await;
    if let Some(hit) = cache.negative_hit(cache_key) {
        debug!(
            domain = prepared.domain(),
            rcode = hit.rcode,
            "DNS forwarder: negative cache hit"
        );
        let response = crate::control::dns_control::build_dns_error_response(raw_query, hit.rcode);
        drop(cache);
        return forwarder
            .outcome_from_wire(
                engine,
                prepared,
                response,
                OutcomeStatus::Accepted,
                Provenance::Cache,
                EffectiveExpiry::cacheable(hit.remaining_ttl),
                None,
                None,
                Vec::new(),
                mode,
            )
            .map(Some);
    }
    let Some(entry) = cache.get(cache_key) else {
        return Ok(None);
    };
    let remaining = entry.remaining_ttl_secs();
    debug!(
        domain = prepared.domain(),
        remaining, "DNS forwarder: positive cache hit"
    );
    let refresh_after = (entry.min_ttl as u64 / 10).max(1);
    if remaining <= refresh_after {
        forwarder.maybe_spawn_refresh(cache_key.to_owned(), raw_query, original_dst);
    }
    let response = entry.response.clone();
    drop(cache);
    let response = forwarder
        .apply_prefer_strategy(
            raw_query,
            prepared.domain(),
            prepared.qtype(),
            response,
            original_dst,
        )
        .await?;
    forwarder
        .outcome_from_wire(
            engine,
            prepared,
            response,
            OutcomeStatus::Accepted,
            Provenance::Cache,
            EffectiveExpiry::cacheable(std::time::Duration::from_secs(remaining)),
            None,
            None,
            Vec::new(),
            mode,
        )
        .map(Some)
}

pub(super) async fn store(
    forwarder: &DnsForwarder,
    prepared: &PreparedQuery,
    cache_key: &str,
    response: &mut [u8],
    class: ResponseClass,
    reuse_eligible: bool,
) -> EffectiveExpiry {
    if !reuse_eligible {
        return EffectiveExpiry::do_not_cache();
    }
    if matches!(class, ResponseClass::Nxdomain | ResponseClass::Servfail) {
        let negative_ttl = extract_soa_negative_ttl(response, 60).clamp(1, 300);
        if forwarder.cache_enabled {
            let rcode = response.get(3).copied().unwrap_or_default() & 0x0f;
            forwarder
                .cache
                .lock()
                .await
                .put_negative(cache_key.to_owned(), negative_ttl, rcode);
        }
        return EffectiveExpiry::cacheable(std::time::Duration::from_secs(u64::from(negative_ttl)));
    }

    let answer_ttl = extract_min_ttl(response);
    let expiry = effective_expiry(
        forwarder.routing.fixed_ttl(prepared.domain()),
        forwarder.cache_ttl,
        answer_ttl,
    );
    if forwarder.cache_enabled && expiry.is_cacheable() {
        let cache_ttl = expiry.ttl().as_secs().min(u64::from(u32::MAX)) as u32;
        rewrite_answer_ttls(response, cache_ttl);
        forwarder
            .cache
            .lock()
            .await
            .put(cache_key.to_owned(), response.to_owned(), cache_ttl);
    }
    expiry
}
