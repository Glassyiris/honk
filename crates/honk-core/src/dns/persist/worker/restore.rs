use std::sync::atomic::Ordering;

use super::super::codec::{self, DecodeError};
use super::super::{CounterSet, unix_now};
use crate::cachedb::CacheDb;
use crate::dns::cache::DnsCacheService;
use crate::dns::policy::PolicyId;

pub(super) fn restore(
    db: &CacheDb,
    cache: &DnsCacheService,
    policy: Option<&PolicyId>,
    counters: &CounterSet,
) -> usize {
    let rows = match db.load_dns_v2() {
        Ok(rows) => rows,
        Err(error) => {
            counters.db_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%error, "DNS persistence restore query failed");
            return 0;
        }
    };
    let now = unix_now();
    let mut restored = 0usize;
    for (suffix, bytes) in rows {
        match codec::decode(&suffix, &bytes, policy) {
            Ok(entry) if entry.expire_at_unix <= now => {
                counters.stale.fetch_add(1, Ordering::Relaxed);
            }
            Ok(entry) => {
                let remaining = entry.expire_at_unix.saturating_sub(now);
                let Ok(ttl) = u32::try_from(remaining) else {
                    counters.corrupt.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                cache.put_restored_exact(entry.key, entry.response, ttl);
                restored = restored.saturating_add(1);
                counters.restored.fetch_add(1, Ordering::Relaxed);
            }
            Err(DecodeError::Version(_)) => {
                counters.version_mismatch.fetch_add(1, Ordering::Relaxed);
            }
            Err(DecodeError::PolicyMismatch) => {
                counters.policy_mismatch.fetch_add(1, Ordering::Relaxed);
            }
            Err(DecodeError::Collision | DecodeError::Corrupt) => {
                counters.corrupt.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    restored
}
