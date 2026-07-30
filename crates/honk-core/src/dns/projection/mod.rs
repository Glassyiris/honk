use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use honk_ebpf_common::DomainRouting;

use crate::ebpf::EbpfBackend;
use crate::routing::Router;

mod reconcile;
mod state;
mod worker;

use state::DesiredState;

const DEFAULT_DOMAIN_CAPACITY: usize = 10_000;

#[derive(Debug, Clone)]
pub(crate) struct RoutingProjectionSnapshot {
    generation: u64,
    matcher: Arc<Router>,
    bitmaps: Arc<HashMap<String, Vec<DomainRouting>>>,
}

impl RoutingProjectionSnapshot {
    pub(crate) fn new(
        generation: u64,
        matcher: Arc<Router>,
        bitmaps: HashMap<String, Vec<DomainRouting>>,
    ) -> Self {
        Self {
            generation,
            matcher,
            bitmaps: Arc::new(bitmaps),
        }
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn bitmap_for(&self, domain: &str) -> Option<DomainRouting> {
        let rule_name = self.matcher.route_domain(domain)?.rule_name;
        let mut aggregate = DomainRouting::default();
        let bitmaps = self.bitmaps.get(rule_name)?;
        for bitmap in bitmaps {
            or_bitmap(&mut aggregate, bitmap);
        }
        (aggregate.bitmap != [0; 4]).then_some(aggregate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionFreshness {
    Fresh,
    Stale,
}

#[derive(Debug)]
pub(crate) enum ProjectionObservation<'a> {
    Positive {
        domain: &'a str,
        ips: &'a [IpAddr],
        advertised_ttl: Duration,
        freshness: ProjectionFreshness,
    },
    Clear {
        domain: &'a str,
    },
    Retain {
        domain: &'a str,
    },
}

#[derive(Debug, Default)]
pub(crate) struct ProjectionCounters {
    write_failures: AtomicU64,
    map_full: AtomicU64,
    wake_coalesced: AtomicU64,
    evictions: AtomicU64,
    generation_rebuilds: AtomicU64,
}

impl ProjectionCounters {
    #[allow(dead_code)]
    pub(crate) fn snapshot(&self) -> ProjectionCounterSnapshot {
        ProjectionCounterSnapshot {
            write_failures: self.write_failures.load(Ordering::Relaxed),
            map_full: self.map_full.load(Ordering::Relaxed),
            wake_coalesced: self.wake_coalesced.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            generation_rebuilds: self.generation_rebuilds.load(Ordering::Relaxed),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectionCounterSnapshot {
    pub(crate) write_failures: u64,
    pub(crate) map_full: u64,
    pub(crate) wake_coalesced: u64,
    pub(crate) evictions: u64,
    pub(crate) generation_rebuilds: u64,
}

pub(crate) struct RoutingProjection {
    state: parking_lot::Mutex<DesiredState>,
    wake: tokio::sync::mpsc::Sender<()>,
    counters: Arc<ProjectionCounters>,
}

impl RoutingProjection {
    pub(crate) fn spawn(
        ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>,
        snapshot: Arc<RoutingProjectionSnapshot>,
    ) -> Arc<Self> {
        let (wake, receiver) = tokio::sync::mpsc::channel(1);
        let counters = Arc::new(ProjectionCounters::default());
        let projection = Arc::new(Self {
            state: parking_lot::Mutex::new(DesiredState::new(snapshot, DEFAULT_DOMAIN_CAPACITY)),
            wake,
            counters: Arc::clone(&counters),
        });
        tokio::spawn(worker::run(
            Arc::downgrade(&projection),
            receiver,
            ebpf,
            counters,
        ));
        projection
    }

    pub(crate) fn update_snapshot(&self, snapshot: Arc<RoutingProjectionSnapshot>) {
        self.mutate(|state| {
            state.update_snapshot(snapshot);
            0
        });
    }

    pub(crate) fn submit(
        &self,
        snapshot: Arc<RoutingProjectionSnapshot>,
        observation: ProjectionObservation<'_>,
    ) {
        self.mutate(|state| {
            if state.update_snapshot(snapshot) {
                state.observe(observation, tokio::time::Instant::now())
            } else {
                0
            }
        });
    }

    #[allow(dead_code)]
    pub(crate) fn counters(&self) -> ProjectionCounterSnapshot {
        self.counters.snapshot()
    }

    fn mutate(&self, operation: impl FnOnce(&mut DesiredState) -> u64) {
        let counter_delta = operation(&mut self.state.lock());
        self.counters
            .evictions
            .fetch_add(counter_delta, Ordering::Relaxed);
        if self.wake.try_send(()).is_err() {
            self.counters.wake_coalesced.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn or_bitmap(target: &mut DomainRouting, source: &DomainRouting) {
    for (target, source) in target.bitmap.iter_mut().zip(source.bitmap) {
        *target |= source;
    }
}

#[cfg(test)]
mod tests;
