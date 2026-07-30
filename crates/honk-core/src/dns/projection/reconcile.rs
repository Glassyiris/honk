use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::state::{Batch, DesiredState, PendingRemove, PendingSet, RetryMetadata};

const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(5);

impl DesiredState {
    pub(super) fn batch(&mut self, now: Instant) -> Batch {
        let ready = |ip: &IpAddr| {
            self.retries
                .get(ip)
                .is_none_or(|retry| retry.next_at <= now)
        };
        let mut sets = Vec::new();
        let mut removes = Vec::new();
        let dirty = self.dirty_ips.iter().copied().collect::<Vec<_>>();
        for ip in dirty.iter().filter(|ip| ready(ip)) {
            match self.desired.get(ip) {
                Some(desired)
                    if self
                        .applied
                        .get(ip)
                        .is_none_or(|applied| applied.bitmap != desired.bitmap) =>
                {
                    sets.push(PendingSet {
                        ip: *ip,
                        bitmap: *desired,
                        revision: self.revisions.get(ip).copied().unwrap_or_default(),
                    });
                }
                None if self.applied.contains_key(ip) => removes.push(PendingRemove {
                    ip: *ip,
                    revision: self.revisions.get(ip).copied().unwrap_or_default(),
                }),
                Some(_) | None => {}
            }
        }
        for ip in dirty {
            if !sets.iter().any(|set| set.ip == ip)
                && !removes.iter().any(|remove| remove.ip == ip)
                && !self.retries.contains_key(&ip)
            {
                self.dirty_ips.remove(&ip);
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

    pub(super) fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        let attempts = self
            .retries
            .get(&ip)
            .map_or(1, |retry| retry.attempts.saturating_add(1));
        let factor = 1u32 << u32::from(attempts.saturating_sub(1).min(6));
        let delay = RETRY_MIN.saturating_mul(factor).min(RETRY_MAX);
        self.retries.insert(
            ip,
            RetryMetadata {
                attempts,
                next_at: now + delay,
            },
        );
        self.dirty_ips.insert(ip);
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.owners
            .values()
            .map(|owner| owner.expires_at)
            .chain(self.retries.values().map(|retry| retry.next_at))
            .min()
    }
}
