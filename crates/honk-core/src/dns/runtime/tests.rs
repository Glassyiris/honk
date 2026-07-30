use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::Config;

use super::{
    DnsRuntime, DnsRuntimeParts, DnsServiceProvider, MAX_RETIRED_RUNTIMES,
    RoutingProjectionSnapshot, RuntimeGeneration, RuntimeState, RuntimeTransport,
};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::policy::PolicyId;
use crate::dns::routing::DnsRouter;
use crate::group::GroupManager;
use crate::routing::Router;
use tokio::sync::{Mutex, Notify};

struct UnusedPool;

#[async_trait]
impl DnsUpstreamPool for UnusedPool {
    async fn query(&self, _upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("test upstream is unused")
    }
}

#[derive(Default)]
struct ObservedTransport {
    closes: AtomicUsize,
    closed: Notify,
}

#[async_trait]
impl RuntimeTransport for ObservedTransport {
    async fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.closed.notify_waiters();
    }
}

fn runtime(generation: u64, route_count: usize) -> (Arc<DnsRuntime>, Arc<ObservedTransport>) {
    let config = Config::default();
    let dns_router =
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid default DNS config"));
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::new(UnusedPool),
        Arc::clone(&cache),
        dns_router,
    ));
    let transport = Arc::new(ObservedTransport::default());
    let runtime = DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(generation),
        forwarder,
        router: Arc::new(
            Router::new(&config.routing.rules, &config.routing.default_outbound)
                .expect("valid default router"),
        ),
        group_manager: Arc::new(GroupManager::new(&config.groups, &config.nodes)),
        policy_id: PolicyId::from_config(&config.dns).expect("valid policy"),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            route_count,
            Default::default(),
        )),
        cache: Arc::clone(&cache),
        persistence: super::ProcessPersistenceHandle::new(Arc::clone(&cache)),
        transport: transport.clone(),
    });
    (runtime, transport)
}

#[tokio::test]
async fn old_dns_request_keeps_generation_snapshots_after_publication() {
    // Given: a request has leased the old runtime generation.
    let (old, old_transport) = runtime(1, 11);
    let provider = DnsServiceProvider::new(Arc::clone(&old));
    let old_lease = provider.acquire();
    let old_router = Arc::clone(old_lease.runtime().router());
    let old_groups = Arc::clone(old_lease.runtime().group_manager());
    let old_policy = old_lease.runtime().policy_id().clone();
    let (new, _) = runtime(2, 22);

    // When: the new coherent runtime is published.
    provider.publish(new);
    let new_lease = provider.acquire();

    // Then: each lease sees only its own generation's snapshot.
    assert_eq!(old_lease.runtime().generation(), RuntimeGeneration::new(1));
    assert_eq!(old_lease.runtime().routing_projection().route_count(), 11);
    assert!(Arc::ptr_eq(old_lease.runtime().router(), &old_router));
    assert!(Arc::ptr_eq(
        old_lease.runtime().group_manager(),
        &old_groups
    ));
    assert_eq!(old_lease.runtime().policy_id(), &old_policy);
    assert_eq!(new_lease.runtime().generation(), RuntimeGeneration::new(2));
    assert_eq!(new_lease.runtime().routing_projection().route_count(), 22);
    assert!(!Arc::ptr_eq(new_lease.runtime().router(), &old_router));
    assert!(!Arc::ptr_eq(
        new_lease.runtime().group_manager(),
        &old_groups
    ));
    assert_eq!(old_transport.closes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn publication_does_not_wait_for_old_lease_and_drop_awaits_close() {
    // Given: the old generation has an in-flight lease.
    let (old, transport) = runtime(1, 1);
    let provider = DnsServiceProvider::new(old);
    let lease = provider.acquire();
    let (new, _) = runtime(2, 2);

    // When: publication occurs while the old request remains stalled.
    provider.publish(new);

    // Then: new acquisition is immediate and old transport stays open.
    assert_eq!(provider.acquire().runtime().generation().get(), 2);
    assert_eq!(transport.closes.load(Ordering::SeqCst), 0);
    drop(lease);
    tokio::time::timeout(Duration::from_secs(1), transport.closed.notified())
        .await
        .expect("old transport closed after the lease completed");
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn retirement_deadline_closes_a_stalled_generation() {
    // Given: a retired generation still has a lease.
    let (old, transport) = runtime(1, 1);
    let provider = DnsServiceProvider::new(old);
    let _lease = provider.acquire();
    let (new, _) = runtime(2, 2);
    provider.publish(new);
    tokio::task::yield_now().await;

    // When: virtual time reaches the retirement deadline.
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;

    // Then: the old generation is forcibly closed without wall-clock sleep.
    assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fifth_retirement_cancels_oldest_and_retains_four() {
    // Given: the oldest runtime is kept alive by a lease.
    let (oldest, oldest_transport) = runtime(0, 0);
    let provider = DnsServiceProvider::new(oldest);
    let oldest_lease = provider.acquire();

    // When: five replacement generations are published.
    for generation in 1..=5 {
        let (replacement, _) = runtime(generation, generation as usize);
        provider.publish(replacement);
    }

    // Then: only four retired runtimes remain and the oldest is closed.
    assert_eq!(provider.retired_count(), MAX_RETIRED_RUNTIMES);
    tokio::time::timeout(Duration::from_secs(1), oldest_transport.closed.notified())
        .await
        .expect("oldest generation closed at retirement cap");
    assert_eq!(oldest_lease.runtime().state(), RuntimeState::Closed);
}

#[tokio::test]
async fn explicit_shutdown_awaits_each_generation_transport_once() {
    // Given: one retired runtime and one current runtime.
    let (old, old_transport) = runtime(1, 1);
    let provider = DnsServiceProvider::new(old);
    let (current, current_transport) = runtime(2, 2);
    provider.publish(current);

    // When: process shutdown explicitly joins the runtime supervisors.
    provider.shutdown().await;

    // Then: every generation-owned transport is closed exactly once.
    assert_eq!(old_transport.closes.load(Ordering::SeqCst), 1);
    assert_eq!(current_transport.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completed_retirement_supervisors_are_reaped_during_publication() {
    let (initial, _) = runtime(0, 0);
    let provider = DnsServiceProvider::new(initial);

    for generation in 1..=64 {
        provider.publish(runtime(generation, generation as usize).0);
        tokio::task::yield_now().await;
    }

    assert!(provider.retired_count() <= MAX_RETIRED_RUNTIMES);
    assert!(
        provider.supervisor_count() <= 1,
        "completed supervisor records must not accumulate"
    );
}
