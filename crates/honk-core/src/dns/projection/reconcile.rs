use std::time::Duration;

use tokio::time::Instant;

use super::state::{Batch, DesiredState, PendingRemove, PendingSet, RetryDeadline, RetryMetadata};

const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(5);
pub(super) const MAX_BATCH_ENTRIES: usize = 256;

impl DesiredState {
    pub(super) fn batch(&mut self, now: Instant) -> Batch {
        let mut sets = Vec::new();
        let mut removes = Vec::new();
        let candidates = self
            .dirty_ips
            .iter()
            .copied()
            .filter(|ip| {
                self.retries
                    .get(ip)
                    .is_none_or(|retry| retry.next_at <= now)
            })
            .take(MAX_BATCH_ENTRIES)
            .collect::<Vec<_>>();
        for ip in candidates {
            match self.desired.get(&ip) {
                Some(desired)
                    if self
                        .applied
                        .get(&ip)
                        .is_none_or(|applied| applied.bitmap != desired.bitmap) =>
                {
                    sets.push(PendingSet {
                        ip,
                        bitmap: *desired,
                        revision: self.revisions.get(&ip).copied().unwrap_or_default(),
                    });
                }
                None if self.applied.contains_key(&ip) => {
                    removes.push(PendingRemove {
                        ip,
                        revision: self.revisions.get(&ip).copied().unwrap_or_default(),
                    });
                }
                Some(_) | None => {
                    self.dirty_ips.remove(&ip);
                    self.retries.remove(&ip);
                }
            }
            if sets.len() + removes.len() >= MAX_BATCH_ENTRIES {
                break;
            }
        }
        Batch {
            generation: self.snapshot.generation(),
            sets,
            removes,
        }
    }

    pub(super) fn commit_success(
        &mut self,
        generation: u64,
        sets: &[PendingSet],
        removes: &[PendingRemove],
    ) -> bool {
        if generation != self.snapshot.generation() {
            for set in sets {
                self.applied.insert(set.ip, set.bitmap);
            }
            for remove in removes {
                self.applied.remove(&remove.ip);
            }
            self.rebuild_all();
            return false;
        }
        let mut current = true;
        for set in sets {
            self.applied.insert(set.ip, set.bitmap);
            if self.revisions.get(&set.ip) == Some(&set.revision)
                && self
                    .desired
                    .get(&set.ip)
                    .is_some_and(|desired| desired.bitmap == set.bitmap.bitmap)
            {
                self.dirty_ips.remove(&set.ip);
                self.retries.remove(&set.ip);
            } else {
                self.dirty_ips.insert(set.ip);
                self.retries.remove(&set.ip);
                current = false;
            }
        }
        for remove in removes {
            self.applied.remove(&remove.ip);
            if self.revisions.get(&remove.ip) == Some(&remove.revision)
                && !self.desired.contains_key(&remove.ip)
            {
                self.dirty_ips.remove(&remove.ip);
                self.retries.remove(&remove.ip);
            } else {
                self.dirty_ips.insert(remove.ip);
                self.retries.remove(&remove.ip);
                current = false;
            }
        }
        if self.dirty_ips.is_empty() {
            self.dirty_domains.clear();
        }
        current
    }

    pub(super) fn record_failure(&mut self, ip: std::net::IpAddr, now: Instant) {
        let attempts = self
            .retries
            .get(&ip)
            .map_or(1, |retry| retry.attempts.saturating_add(1));
        let factor = 1u32 << u32::from(attempts.saturating_sub(1).min(6));
        let next_at = now + RETRY_MIN.saturating_mul(factor).min(RETRY_MAX);
        self.retries.insert(ip, RetryMetadata { attempts, next_at });
        self.retry_deadlines.push(std::cmp::Reverse(RetryDeadline {
            at: next_at,
            ip,
            attempts,
        }));
        self.dirty_ips.insert(ip);
    }

    pub(super) fn next_deadline(&mut self) -> Option<Instant> {
        while let Some(std::cmp::Reverse(deadline)) = self.retry_deadlines.peek() {
            if self.retries.get(&deadline.ip).is_some_and(|retry| {
                retry.attempts == deadline.attempts && retry.next_at == deadline.at
            }) {
                break;
            }
            self.retry_deadlines.pop();
        }
        self.expiry_deadlines
            .peek()
            .map(|entry| entry.0.at)
            .into_iter()
            .chain(self.retry_deadlines.peek().map(|entry| entry.0.at))
            .min()
    }
}
