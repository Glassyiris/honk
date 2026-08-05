use bytes::Bytes;

use std::time::{Duration, Instant};

pub(super) const STALE_RETENTION: Duration = Duration::from_secs(3600);

/// A cached DNS response entry.
///
/// Contains the raw response bytes along with TTL metadata
/// used to determine expiry.
#[derive(Debug, Clone)]
pub struct CachedEntry {
    /// Raw DNS response bytes (full wire-format message).
    pub response: Bytes,
    /// Absolute wall-clock time after which this entry is stale.
    pub expires_at: Instant,
    /// Minimum TTL from the DNS record set, in seconds.
    pub min_ttl: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegativeCacheHit {
    pub rcode: u8,
    pub remaining_ttl: Duration,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct NegativeEntry {
    pub expires_at: Instant,
    pub rcode: u8,
}

pub(super) struct CacheValue {
    pub positive: Option<CachedEntry>,
    pub negative: Option<NegativeEntry>,
}

impl CacheValue {
    pub(super) fn positive(entry: CachedEntry) -> Self {
        Self {
            positive: Some(entry),
            negative: None,
        }
    }

    pub(super) fn negative(entry: NegativeEntry) -> Self {
        Self {
            positive: None,
            negative: Some(entry),
        }
    }
}

impl CachedEntry {
    /// Returns `true` if the current time is past `expires_at`.
    #[inline]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining TTL in seconds (0 if expired).
    pub fn remaining_ttl_secs(&self) -> u64 {
        self.expires_at
            .checked_duration_since(Instant::now())
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    /// Returns `true` once the entry is too old even for serve-stale use
    /// (past `expires_at + STALE_RETENTION`).
    #[inline]
    pub fn is_stale_retention_exceeded(&self) -> bool {
        Instant::now() >= self.expires_at + STALE_RETENTION
    }
}
