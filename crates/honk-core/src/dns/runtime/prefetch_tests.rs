use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use honk_config::Config;
use tokio::sync::{Mutex, Notify};

use super::{
    DnsRuntime, DnsRuntimeParts, ProcessPersistenceHandle, RoutingProjectionSnapshot,
    RuntimeGeneration, RuntimeTransport,
};
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::policy::PolicyId;
use crate::dns::routing::DnsRouter;
use crate::group::GroupManager;
use crate::routing::Router;

struct DropSignal<'a>(&'a BlockingTransport);

impl Drop for DropSignal<'_> {
    fn drop(&mut self) {
        let order = self.0.next_order.fetch_add(1, Ordering::AcqRel) + 1;
        self.0.query_drop_order.store(order, Ordering::Release);
        self.0.dropped.notify_waiters();
    }
}

#[derive(Default)]
struct BlockingTransport {
    entered: Notify,
    dropped: Notify,
    next_order: AtomicUsize,
    query_drop_order: AtomicUsize,
    close_order: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for BlockingTransport {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        let _drop_signal = DropSignal(self);
        self.entered.notify_one();
        std::future::pending().await
    }
}

#[async_trait]
impl RuntimeTransport for BlockingTransport {
    async fn close(&self) {
        let order = self.next_order.fetch_add(1, Ordering::AcqRel) + 1;
        self.close_order.store(order, Ordering::Release);
    }
}

fn runtime(transport: Arc<BlockingTransport>) -> Arc<DnsRuntime> {
    let mut config = Config::default();
    config.dns.routing.fallback = "default".to_owned();
    let cache = Arc::new(Mutex::new(DnsCache::new(32)));
    let router = Arc::new(
        Router::new(&config.routing.rules, &config.routing.default_outbound).expect("valid router"),
    );
    let forwarder = Arc::new(DnsForwarder::new(
        Arc::clone(&transport) as Arc<dyn DnsUpstreamPool>,
        Arc::clone(&cache),
        Arc::new(DnsRouter::new_from_dns_config(&config.dns).expect("valid DNS router")),
    ));
    DnsRuntime::new(DnsRuntimeParts {
        generation: RuntimeGeneration::new(1),
        forwarder,
        router: Arc::clone(&router),
        group_manager: Arc::new(GroupManager::new(&config.groups, &config.nodes)),
        policy_id: PolicyId::from_config(&config.dns).expect("valid policy"),
        routing_projection: Arc::new(RoutingProjectionSnapshot::new(
            1,
            router,
            Default::default(),
        )),
        cache: Arc::clone(&cache),
        persistence: ProcessPersistenceHandle::new(cache),
        transport: transport.clone(),
    })
}

#[tokio::test]
async fn retirement_joins_blocked_prefetch_before_transport_close() {
    let transport = Arc::new(BlockingTransport::default());
    let runtime = runtime(Arc::clone(&transport));
    runtime
        .forwarder()
        .prefetch(&["blocked.example".to_owned()]);
    transport.entered.notified().await;

    Arc::clone(&runtime).retire(Duration::ZERO).await;

    assert_eq!(transport.query_drop_order.load(Ordering::Acquire), 1);
    assert_eq!(transport.close_order.load(Ordering::Acquire), 2);
}
