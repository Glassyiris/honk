use honk_ebpf_common::DomainRouting;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::Instant;

use super::{ProjectionFreshness, ProjectionObservation, RoutingProjectionSnapshot, or_bitmap};

#[derive(Debug)]
pub(super) struct DomainOwner {
    pub(super) ips: BTreeSet<IpAddr>,
    pub(super) expires_at: Instant,
    pub(super) sequence: u64,
    pub(super) _freshness: ProjectionFreshness,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RetryMetadata {
    pub(super) attempts: u8,
    pub(super) next_at: Instant,
}

#[derive(Debug)]
pub(super) struct Batch {
    pub(super) generation: u64,
    pub(super) sets: Vec<PendingSet>,
    pub(super) removes: Vec<PendingRemove>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingSet {
    pub(super) ip: IpAddr,
    pub(super) bitmap: DomainRouting,
    pub(super) revision: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingRemove {
    pub(super) ip: IpAddr,
    pub(super) revision: u64,
}

pub(super) struct DesiredState {
    pub(super) capacity: usize,
    pub(super) sequence: u64,
    pub(super) snapshot: Arc<RoutingProjectionSnapshot>,
    pub(super) owners: BTreeMap<String, DomainOwner>,
    pub(super) reverse: BTreeMap<IpAddr, BTreeSet<String>>,
    pub(super) desired: BTreeMap<IpAddr, DomainRouting>,
    pub(super) revisions: BTreeMap<IpAddr, u64>,
    pub(super) applied: BTreeMap<IpAddr, DomainRouting>,
    pub(super) dirty_ips: BTreeSet<IpAddr>,
    pub(super) dirty_domains: BTreeSet<String>,
    pub(super) retries: BTreeMap<IpAddr, RetryMetadata>,
}

impl DesiredState {
    pub(super) fn new(snapshot: Arc<RoutingProjectionSnapshot>, capacity: usize) -> Self {
        Self {
            capacity,
            sequence: 0,
            snapshot,
            owners: BTreeMap::new(),
            reverse: BTreeMap::new(),
            desired: BTreeMap::new(),
            revisions: BTreeMap::new(),
            applied: BTreeMap::new(),
            dirty_ips: BTreeSet::new(),
            dirty_domains: BTreeSet::new(),
            retries: BTreeMap::new(),
        }
    }

    pub(super) fn update_snapshot(&mut self, snapshot: Arc<RoutingProjectionSnapshot>) -> bool {
        if snapshot.generation() <= self.snapshot.generation() {
            return snapshot.generation() == self.snapshot.generation();
        }
        self.snapshot = snapshot;
        self.dirty_domains.extend(self.owners.keys().cloned());
        self.rebuild_all();
        true
    }

    pub(super) fn observe(&mut self, observation: ProjectionObservation<'_>, now: Instant) -> u64 {
        self.expire(now);
        match observation {
            ProjectionObservation::Positive {
                domain,
                ips,
                advertised_ttl,
                freshness,
            } => self.replace(domain, ips, now + advertised_ttl, freshness),
            ProjectionObservation::Clear { domain } => {
                self.remove_owner(domain);
                0
            }
            ProjectionObservation::Retain { domain } => {
                self.dirty_domains.remove(domain);
                0
            }
        }
    }

    fn replace(
        &mut self,
        domain: &str,
        ips: &[IpAddr],
        expires_at: Instant,
        freshness: ProjectionFreshness,
    ) -> u64 {
        self.remove_owner(domain);
        self.sequence = self.sequence.wrapping_add(1);
        let ips = ips.iter().copied().collect::<BTreeSet<_>>();
        for ip in &ips {
            self.reverse
                .entry(*ip)
                .or_default()
                .insert(domain.to_owned());
        }
        self.owners.insert(
            domain.to_owned(),
            DomainOwner {
                ips: ips.clone(),
                expires_at,
                sequence: self.sequence,
                _freshness: freshness,
            },
        );
        self.dirty_domains.insert(domain.to_owned());
        self.recompute_ips(ips);
        if self.owners.len() <= self.capacity {
            return 0;
        }
        let evicted = self
            .owners
            .iter()
            .min_by_key(|(domain, owner)| (owner.sequence, domain.as_str()))
            .map(|(domain, _)| domain.clone());
        if let Some(evicted) = evicted {
            self.remove_owner(&evicted);
            1
        } else {
            0
        }
    }

    fn remove_owner(&mut self, domain: &str) {
        let Some(owner) = self.owners.remove(domain) else {
            return;
        };
        self.dirty_domains.insert(domain.to_owned());
        for ip in &owner.ips {
            if let Some(domains) = self.reverse.get_mut(ip) {
                domains.remove(domain);
                if domains.is_empty() {
                    self.reverse.remove(ip);
                }
            }
        }
        self.recompute_ips(owner.ips);
    }

    fn recompute_ips(&mut self, ips: impl IntoIterator<Item = IpAddr>) {
        for ip in ips {
            let revision = self.revisions.entry(ip).or_default();
            *revision = revision.wrapping_add(1);
            let mut aggregate = DomainRouting::default();
            if let Some(domains) = self.reverse.get(&ip) {
                for domain in domains {
                    if let Some(bitmap) = self.snapshot.bitmap_for(domain) {
                        or_bitmap(&mut aggregate, &bitmap);
                    }
                }
            }
            if aggregate.bitmap == [0; 4] {
                self.desired.remove(&ip);
            } else {
                self.desired.insert(ip, aggregate);
            }
            self.dirty_ips.insert(ip);
        }
    }

    pub(super) fn rebuild_all(&mut self) {
        let ips = self
            .reverse
            .keys()
            .chain(self.applied.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        self.desired.clear();
        self.recompute_ips(ips);
    }

    pub(super) fn expire(&mut self, now: Instant) {
        let expired = self
            .owners
            .iter()
            .filter(|(_, owner)| owner.expires_at <= now)
            .map(|(domain, _)| domain.clone())
            .collect::<Vec<_>>();
        for domain in expired {
            self.remove_owner(&domain);
        }
    }

    #[cfg(test)]
    pub(super) fn owner_domains(&self) -> Vec<String> {
        self.owners.keys().cloned().collect()
    }
}
