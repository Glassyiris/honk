use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_ebpf_common::DomainRouting;

use super::state::DesiredState;
use super::worker;
use super::{
    ProjectionFreshness, ProjectionObservation, RoutingProjection, RoutingProjectionSnapshot,
};
use crate::ebpf::maps;
use crate::ebpf::mock::MockEbpfBackend;
use crate::ebpf::{EbpfBackend, ProjectionMapOperation};
use crate::routing::Router;

type SharedBackend = Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>;
type TestProjection = (
    RoutingProjection,
    tokio::sync::mpsc::Receiver<()>,
    SharedBackend,
);

fn bitmap(bit: u32) -> DomainRouting {
    DomainRouting {
        bitmap: [bit, 0, 0, 0],
    }
}

fn snapshot(generation: u64, a: u32, b: u32) -> Arc<RoutingProjectionSnapshot> {
    let routes = vec![
        RoutingRule {
            name: "a".to_owned(),
            condition: RoutingCondition {
                domain: vec!["a.test".to_owned()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".to_owned()),
            priority: 1,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "b".to_owned(),
            condition: RoutingCondition {
                domain: vec!["b.test".to_owned()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".to_owned()),
            priority: 2,
            must: false,
            mark: 0,
        },
    ];
    Arc::new(RoutingProjectionSnapshot::new(
        generation,
        Arc::new(Router::new(&routes, "direct").expect("test router")),
        HashMap::from([
            ("a".to_owned(), vec![bitmap(a)]),
            ("b".to_owned(), vec![bitmap(b)]),
        ]),
    ))
}

fn positive<'a>(domain: &'a str, ips: &'a [IpAddr], ttl: Duration) -> ProjectionObservation<'a> {
    ProjectionObservation::Positive {
        domain,
        ips,
        advertised_ttl: ttl,
        freshness: ProjectionFreshness::Fresh,
    }
}

#[tokio::test(start_paused = true)]
async fn shared_ip_clear_and_expiry_recompute_owner_or() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(positive("a.test", &[ip], Duration::from_secs(1)), now);
    state.observe(positive("b.test", &[ip], Duration::from_secs(5)), now);
    let batch = state.batch(now);
    assert_eq!(batch.sets[0].bitmap.bitmap, [3, 0, 0, 0]);
    assert!(state.commit_success(batch.generation, &batch.sets, &batch.removes));

    state.observe(ProjectionObservation::Clear { domain: "a.test" }, now);
    assert_eq!(state.batch(now).sets[0].bitmap.bitmap, [2, 0, 0, 0]);
    tokio::time::advance(Duration::from_secs(5)).await;
    state.expire(tokio::time::Instant::now());
    assert_eq!(state.batch(tokio::time::Instant::now()).removes[0].ip, ip);
}

#[tokio::test(start_paused = true)]
async fn stale_uses_only_advertised_ttl_and_retain_keeps_owner() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    state.observe(
        ProjectionObservation::Retain { domain: "a.test" },
        now + Duration::from_secs(1),
    );
    state.observe(
        ProjectionObservation::Positive {
            domain: "a.test",
            ips: &[ip],
            advertised_ttl: Duration::from_secs(2),
            freshness: ProjectionFreshness::Stale,
        },
        now + Duration::from_secs(1),
    );
    state.expire(now + Duration::from_secs(2));
    assert!(state.batch(now + Duration::from_secs(2)).sets.len() == 1);
    state.expire(now + Duration::from_secs(3));
    assert_eq!(state.owner_domains(), Vec::<String>::new());
}

#[tokio::test(start_paused = true)]
async fn generation_race_forces_full_recompute() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    let stale = state.batch(now);
    state.update_snapshot(snapshot(2, 4, 8));
    assert!(!state.commit_success(stale.generation, &stale.sets, &stale.removes));
    let rebuilt = state.batch(now);
    assert_eq!(rebuilt.generation, 2);
    assert_eq!(rebuilt.sets[0].bitmap.bitmap, [4, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn same_generation_update_after_batch_snapshot_stays_dirty() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 30));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    let stale = state.batch(now);

    state.observe(positive("b.test", &[ip], Duration::from_secs(30)), now);

    assert!(!state.commit_success(stale.generation, &stale.sets, &stale.removes));
    let repaired = state.batch(now);
    assert_eq!(repaired.sets[0].bitmap.bitmap, [3, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn stale_runtime_observation_cannot_downgrade_generation() {
    let now = tokio::time::Instant::now();
    let old = snapshot(1, 1, 2);
    let current = snapshot(2, 4, 8);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
    let mut state = DesiredState::new(Arc::clone(&old), 10_000);
    assert!(state.update_snapshot(Arc::clone(&current)));
    if state.update_snapshot(old) {
        state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    }
    assert!(state.owner_domains().is_empty());
    state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    let batch = state.batch(now);
    assert_eq!(batch.generation, 2);
    assert_eq!(batch.sets[0].bitmap.bitmap, [4, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn stale_runtime_submission_records_generation_fence_event() {
    let before = crate::stats::dns_snapshot();
    let (projection, _receiver, _ebpf) = projection_for_test(snapshot(2, 4, 8));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));

    projection.submit(
        snapshot(1, 1, 2),
        positive("a.test", &[ip], Duration::from_secs(30)),
    );

    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .projection_stale_generation
            >= 1
    );
}

#[tokio::test(start_paused = true)]
async fn deterministic_capacity_evicts_oldest_domain() {
    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 2);
    for (domain, octet) in [("a.test", 1), ("b.test", 2), ("a.test", 3)] {
        state.observe(
            positive(
                domain,
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet))],
                Duration::from_secs(30),
            ),
            now,
        );
    }
    assert_eq!(
        state.owner_domains(),
        vec!["a.test".to_owned(), "b.test".to_owned()]
    );
    state.observe(
        positive(
            "c.test",
            &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))],
            Duration::from_secs(30),
        ),
        now,
    );
    assert_eq!(
        state.owner_domains(),
        vec!["a.test".to_owned(), "c.test".to_owned()]
    );
}

#[tokio::test(start_paused = true)]
async fn ten_thousand_and_first_domain_evicts_exact_oldest_owner() {
    let now = tokio::time::Instant::now();
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    for index in 0..=10_000u32 {
        let domain = format!("d{index:05}.test");
        let ip = IpAddr::V4(Ipv4Addr::from(index));
        state.observe(positive(&domain, &[ip], Duration::from_secs(30)), now);
    }
    let domains = state.owner_domains();
    assert_eq!(domains.len(), 10_000);
    assert!(!domains.iter().any(|domain| domain == "d00000.test"));
    assert!(domains.iter().any(|domain| domain == "d10000.test"));
}

fn projection_for_test(snapshot: Arc<RoutingProjectionSnapshot>) -> TestProjection {
    let (wake, receiver) = tokio::sync::mpsc::channel(1);
    let counters = Arc::new(super::ProjectionCounters::default());
    (
        RoutingProjection {
            state: parking_lot::Mutex::new(DesiredState::new(snapshot, 10_000)),
            wake: parking_lot::Mutex::new(Some(wake)),
            counters,
            worker: parking_lot::Mutex::new(None),
            lifecycle: {
                let lifecycle = super::ProjectionLifecycle::running();
                lifecycle.finish();
                lifecycle
            },
        },
        receiver,
        Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new()))),
    )
}

mod worker_tests;
