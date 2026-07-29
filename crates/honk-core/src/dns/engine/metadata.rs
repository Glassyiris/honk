use std::time::Duration;

use crate::dns::outcome::{EffectiveExpiry, ResponseClass};

pub(crate) fn classify_response(wire: &[u8]) -> ResponseClass {
    let rcode = wire.get(3).copied().unwrap_or_default() & 0x0f;
    match rcode {
        2 => ResponseClass::Servfail,
        3 => ResponseClass::Nxdomain,
        _ if wire.get(6..8) == Some(&[0, 0]) => ResponseClass::Nodata,
        _ => ResponseClass::Positive,
    }
}

pub(crate) fn effective_expiry(
    fixed_ttl: Option<u32>,
    configured_ttl: u32,
    answer_ttl: u32,
) -> EffectiveExpiry {
    match fixed_ttl {
        Some(0) => EffectiveExpiry::do_not_cache(),
        Some(ttl) => EffectiveExpiry::cacheable(Duration::from_secs(u64::from(ttl))),
        None if configured_ttl > 0 => {
            EffectiveExpiry::cacheable(Duration::from_secs(u64::from(configured_ttl)))
        }
        None => EffectiveExpiry::cacheable(Duration::from_secs(u64::from(answer_ttl.max(1)))),
    }
}
