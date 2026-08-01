use honk_ebpf_common::DomainRouting;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct DeadlineEntry {
    pub(super) at: Instant,
    pub(super) domain: String,
    pub(super) sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RetryDeadline {
    pub(super) at: Instant,
    pub(super) ip: IpAddr,
    pub(super) attempts: u8,
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
    pub(super) expiry_deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    pub(super) eviction_order: BinaryHeap<Reverse<(u64, String)>>,
    pub(super) retry_deadlines: BinaryHeap<Reverse<RetryDeadline>>,
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
            expiry_deadlines: BinaryHeap::new(),
            eviction_order: BinaryHeap::new(),
            retry_deadlines: BinaryHeap::new(),
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
        self.expiry_deadlines.push(Reverse(DeadlineEntry {
            at: expires_at,
            domain: domain.to_owned(),
            sequence: self.sequence,
        }));
        self.eviction_order
            .push(Reverse((self.sequence, domain.to_owned())));
        self.dirty_domains.insert(domain.to_owned());
        self.recompute_ips(ips);
        if self.owners.len() <= self.capacity {
            return 0;
        }
        let evicted = loop {
            let Some(Reverse((sequence, domain))) = self.eviction_order.pop() else {
                break None;
            };
            if self
                .owners
                .get(&domain)
                .is_some_and(|owner| owner.sequence == sequence)
            {
                break Some(domain);
            }
        };
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
        while let Some(Reverse(deadline)) = self.expiry_deadlines.peek() {
            if deadline.at > now {
                break;
            }
            let deadline = self
                .expiry_deadlines
                .pop()
                .expect("expiry heap entry disappeared")
                .0;
            if self
                .owners
                .get(&deadline.domain)
                .is_some_and(|owner| owner.sequence == deadline.sequence && owner.expires_at <= now)
            {
                self.remove_owner(&deadline.domain);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn owner_domains(&self) -> Vec<String> {
        self.owners.keys().cloned().collect()
    }
}
