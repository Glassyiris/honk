//! Per-upstream DNS query management with connection reuse.

mod entries;
mod query;
mod routing;
mod transports;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use honk_config::dns::DnsUpstream;
use honk_config::node::{Group, Node};
use honk_outbound::group::{GroupManager, SharedGroupManager};
use tokio::sync::RwLock as AsyncRwLock;

use self::entries::{PoolState, UpstreamEntry, build_entries};
use crate::dns::routing::DnsRouter;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportLifecycleStats {
    pub init_count: usize,
    pub close_count: usize,
    pub tasks: usize,
}

pub struct UpstreamPool {
    entries: HashMap<String, UpstreamEntry>,
    proxy_registry: Option<Arc<ProxyRegistry>>,
    nodes: Vec<Node>,
    groups: Vec<Group>,
    group_manager: parking_lot::RwLock<Option<SharedGroupManager>>,
    group_manager_snapshot: parking_lot::RwLock<Option<Arc<GroupManager>>>,
    traffic_router: parking_lot::RwLock<Option<Arc<AsyncRwLock<Router>>>>,
    traffic_router_snapshot: parking_lot::RwLock<Option<Arc<Router>>>,
    dns_query_timeout: Duration,
    dns_dial_timeout: Duration,
    active_transport_tasks: Arc<AtomicUsize>,
    shutdown: tokio::sync::RwLock<PoolState>,
}

impl UpstreamPool {
    pub fn new(upstreams: &[DnsUpstream], router: Arc<DnsRouter>) -> anyhow::Result<Self> {
        Self::new_with_proxy(upstreams, router, None, Vec::new(), Vec::new())
    }

    pub fn new_with_proxy(
        upstreams: &[DnsUpstream],
        router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
    ) -> anyhow::Result<Self> {
        Self::new_with_proxy_and_bootstrap(
            upstreams,
            router,
            proxy_registry,
            nodes,
            groups,
            honk_outbound::bootstrap::global(),
        )
    }

    pub(crate) fn new_with_proxy_and_bootstrap(
        upstreams: &[DnsUpstream],
        _router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
        bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            entries: build_entries(upstreams, bootstrap_resolver)?,
            proxy_registry,
            nodes,
            groups,
            group_manager: parking_lot::RwLock::new(None),
            group_manager_snapshot: parking_lot::RwLock::new(None),
            traffic_router: parking_lot::RwLock::new(None),
            traffic_router_snapshot: parking_lot::RwLock::new(None),
            dns_query_timeout: Duration::from_secs(3),
            dns_dial_timeout: Duration::from_secs(10),
            active_transport_tasks: Arc::new(AtomicUsize::new(0)),
            shutdown: tokio::sync::RwLock::new(PoolState::Open),
        })
    }

    pub fn with_timeouts(
        mut self,
        dns_query_timeout: Duration,
        dns_dial_timeout: Duration,
    ) -> Self {
        self.dns_query_timeout = dns_query_timeout;
        self.dns_dial_timeout = dns_dial_timeout;
        self
    }

    pub fn set_group_manager(&self, group_manager: Option<SharedGroupManager>) {
        *self.group_manager.write() = group_manager;
    }

    pub fn with_group_manager(self, group_manager: SharedGroupManager) -> Self {
        *self.group_manager.write() = Some(group_manager);
        self
    }

    pub fn set_group_manager_snapshot(&self, group_manager: Arc<GroupManager>) {
        *self.group_manager_snapshot.write() = Some(group_manager);
    }

    pub fn with_group_manager_snapshot(self, group_manager: Arc<GroupManager>) -> Self {
        self.set_group_manager_snapshot(group_manager);
        self
    }

    pub fn set_traffic_router(&self, router: Option<Arc<AsyncRwLock<Router>>>) {
        *self.traffic_router.write() = router;
    }

    pub fn with_traffic_router(self, router: Arc<AsyncRwLock<Router>>) -> Self {
        *self.traffic_router.write() = Some(router);
        self
    }

    pub fn set_traffic_router_snapshot(&self, router: Arc<Router>) {
        *self.traffic_router_snapshot.write() = Some(router);
    }

    pub fn with_traffic_router_snapshot(self, router: Arc<Router>) -> Self {
        self.set_traffic_router_snapshot(router);
        self
    }

    pub fn upstream_count(&self) -> usize {
        self.entries.len()
    }
}
