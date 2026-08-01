use std::sync::Arc;

use super::*;
use crate::dns::cache::OperationKind;
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::query::{IngressProfile, QueryContext};
use crate::dns::response::ResponseTemplate;

fn key(index: u16) -> CacheKey {
    let mut wire = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    wire.extend_from_slice(&index.to_be_bytes());
    CacheKey::for_test(
        wire,
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
        OperationKind::Resolve,
    )
}

fn template() -> Arc<ResponseTemplate> {
    let query = QueryContext::parse(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1])
        .expect("query");
    let mut response = query.canonical_wire().to_vec();
    response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
    Arc::new(ResponseTemplate::validate(&query, &response).expect("template"))
}

#[tokio::test]
async fn waiter_receives_leader_template_when_completed() {
    // Given
    let flights = Singleflight::default();
    let FlightRole::Leader(mut leader) = flights.acquire(key(1)) else {
        panic!("leader");
    };
    let FlightRole::Waiter(waiter) = flights.acquire(key(1)) else {
        panic!("waiter");
    };

    // When
    leader.publish(template());
    let received = waiter.receive().await;

    // Then
    assert!(received.is_some());
    assert_eq!(flights.active_len(), 1);
    assert_eq!(flights.counters().leaders, 1);
    assert_eq!(flights.counters().waiters, 1);
    drop(leader);
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test]
async fn waiter_retries_when_leader_is_cancelled() {
    // Given
    let before = crate::stats::dns_snapshot();
    let flights = Singleflight::default();
    let FlightRole::Leader(leader) = flights.acquire(key(2)) else {
        panic!("leader");
    };
    let FlightRole::Waiter(waiter) = flights.acquire(key(2)) else {
        panic!("waiter");
    };

    // When
    drop(leader);
    let received = waiter.receive().await;

    // Then
    assert!(received.is_none());
    assert_eq!(flights.active_len(), 0);
    assert_eq!(flights.counters().aborts, 1);
    assert_eq!(flights.counters().retries, 1);
    assert!(matches!(flights.acquire(key(2)), FlightRole::Leader(_)));
    let delta = crate::stats::dns_snapshot().delta(before);
    assert!(delta.singleflight_cancel >= 1);
    assert!(delta.singleflight_retry >= 1);
}

#[test]
fn active_flight_limit_rejects_the_2049th_key() {
    let before = crate::stats::dns_snapshot();
    let flights = Singleflight::default();
    let leaders: Vec<_> = (0..MAX_ACTIVE_FLIGHTS)
        .map(
            |index| match flights.acquire(key(u16::try_from(index).expect("index"))) {
                FlightRole::Leader(leader) => leader,
                _ => panic!("leader"),
            },
        )
        .collect();

    assert_eq!(flights.active_len(), 2048);
    assert!(matches!(flights.acquire(key(2048)), FlightRole::Rejected));
    assert_eq!(flights.active_len(), 2048);
    assert_eq!(flights.counters().rejections, 1);
    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .singleflight_rejected
            >= 1
    );
    drop(leaders);
}

#[test]
fn waiter_limit_rejects_the_257th_follower_without_opening_an_exchange() {
    let before = crate::stats::dns_snapshot();
    let flights = Singleflight::default();
    let FlightRole::Leader(_leader) = flights.acquire(key(3)) else {
        panic!("leader");
    };
    let waiters: Vec<_> = (0..MAX_WAITERS_PER_FLIGHT)
        .map(|_| match flights.acquire(key(3)) {
            FlightRole::Waiter(waiter) => waiter,
            _ => panic!("waiter"),
        })
        .collect();

    assert_eq!(flights.counters().waiters, 256);
    assert!(matches!(flights.acquire(key(3)), FlightRole::Rejected));
    let counters = flights.counters();
    assert_eq!(counters.rejections, 1);
    assert_eq!(counters.amplification_avoided, 256);
    assert!(
        crate::stats::dns_snapshot()
            .delta(before)
            .singleflight_rejected
            >= 1
    );
    drop(waiters);
}
