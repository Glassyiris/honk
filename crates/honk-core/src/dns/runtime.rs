use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;

use super::cache::DnsCache;
use super::forwarder::DnsForwarder;
use super::policy::PolicyId;
use super::upstream_pool::UpstreamPool;
use crate::group::GroupManager;
use crate::routing::Router;

pub(crate) const RETIREMENT_DEADLINE: Duration = Duration::from_secs(30);
pub(crate) const MAX_RETIRED_RUNTIMES: usize = 4;
static NEXT_PERSISTENCE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

mod provider;
pub(crate) use provider::DnsServiceProvider;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RuntimeGeneration(u64);

impl RuntimeGeneration {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RuntimeState {
    Active,
    Draining,
    Closing,
    Closed,
}

impl RuntimeState {
    const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Draining,
            2 => Self::Closing,
            _ => Self::Closed,
        }
    }
}

pub(crate) use super::projection::RoutingProjectionSnapshot;

#[async_trait]
pub(crate) trait RuntimeTransport: Send + Sync {
    async fn close(&self);
}

#[async_trait]
impl RuntimeTransport for UpstreamPool {
    async fn close(&self) {
        UpstreamPool::close(self).await;
    }
}

pub(crate) struct ProcessPersistenceHandle {
    #[allow(dead_code)]
    identity: u64,
    _cache: Arc<tokio::sync::Mutex<DnsCache>>,
}

impl ProcessPersistenceHandle {
    pub(crate) fn new(cache: Arc<tokio::sync::Mutex<DnsCache>>) -> Arc<Self> {
        Arc::new(Self {
            identity: NEXT_PERSISTENCE_ID.fetch_add(1, Ordering::Relaxed),
            _cache: cache,
        })
    }

    #[cfg(test)]
    pub(crate) const fn identity(&self) -> u64 {
        self.identity
    }
}

pub(crate) struct DnsRuntimeParts {
    pub(crate) generation: RuntimeGeneration,
    pub(crate) forwarder: Arc<DnsForwarder>,
    #[allow(dead_code)]
    pub(crate) router: Arc<Router>,
    #[allow(dead_code)]
    pub(crate) group_manager: Arc<GroupManager>,
    #[allow(dead_code)]
    pub(crate) policy_id: PolicyId,
    pub(crate) routing_projection: Arc<RoutingProjectionSnapshot>,
    pub(crate) cache: Arc<tokio::sync::Mutex<DnsCache>>,
    pub(crate) persistence: Arc<ProcessPersistenceHandle>,
    pub(crate) transport: Arc<dyn RuntimeTransport>,
}

pub(crate) struct DnsRuntime {
    parts: DnsRuntimeParts,
    state: AtomicU8,
    leases: AtomicUsize,
    lease_released: Notify,
    cancellation_requested: AtomicBool,
    cancellation: Notify,
    closed: Notify,
}

impl DnsRuntime {
    pub(crate) fn new(parts: DnsRuntimeParts) -> Arc<Self> {
        Arc::new(Self {
            parts,
            state: AtomicU8::new(RuntimeState::Active as u8),
            leases: AtomicUsize::new(0),
            lease_released: Notify::new(),
            cancellation_requested: AtomicBool::new(false),
            cancellation: Notify::new(),
            closed: Notify::new(),
        })
    }

    pub(crate) const fn generation(&self) -> RuntimeGeneration {
        self.parts.generation
    }

    pub(crate) fn state(&self) -> RuntimeState {
        RuntimeState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub(crate) fn lease_count(&self) -> usize {
        self.leases.load(Ordering::Acquire)
    }

    #[allow(dead_code)]
    pub(crate) fn router(&self) -> &Arc<Router> {
        &self.parts.router
    }

    pub(crate) fn forwarder(&self) -> &Arc<DnsForwarder> {
        &self.parts.forwarder
    }

    #[cfg(test)]
    pub(crate) fn group_manager(&self) -> &Arc<GroupManager> {
        &self.parts.group_manager
    }

    #[cfg(test)]
    pub(crate) fn policy_id(&self) -> &PolicyId {
        &self.parts.policy_id
    }

    pub(crate) fn routing_projection(&self) -> &Arc<RoutingProjectionSnapshot> {
        &self.parts.routing_projection
    }

    pub(crate) fn cache(&self) -> &Arc<tokio::sync::Mutex<DnsCache>> {
        &self.parts.cache
    }

    pub(crate) fn persistence(&self) -> &Arc<ProcessPersistenceHandle> {
        &self.parts.persistence
    }

    fn acquire(runtime: &Arc<Self>) -> RuntimeLease {
        runtime.leases.fetch_add(1, Ordering::AcqRel);
        RuntimeLease {
            runtime: Arc::clone(runtime),
        }
    }

    fn start_draining(&self) {
        let _ = self.state.compare_exchange(
            RuntimeState::Active as u8,
            RuntimeState::Draining as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn request_cancellation(&self) {
        self.cancellation_requested.store(true, Ordering::Release);
        self.cancellation.notify_waiters();
    }

    async fn retire(self: Arc<Self>, deadline: Duration) {
        self.start_draining();
        let cancellation = self.cancellation.notified();
        tokio::pin!(cancellation);
        if self.lease_count() != 0 && !self.cancellation_requested.load(Ordering::Acquire) {
            tokio::select! {
                () = Self::wait_for_zero_leases(&self) => {}
                () = tokio::time::sleep(deadline) => {}
                () = &mut cancellation => {}
            }
        }
        if self
            .state
            .compare_exchange(
                RuntimeState::Draining as u8,
                RuntimeState::Closing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.wait_closed().await;
            return;
        }
        self.parts.transport.close().await;
        self.state
            .store(RuntimeState::Closed as u8, Ordering::Release);
        self.closed.notify_waiters();
    }

    async fn wait_for_zero_leases(&self) {
        loop {
            let released = self.lease_released.notified();
            if self.lease_count() == 0 {
                return;
            }
            released.await;
        }
    }

    pub(crate) async fn wait_closed(&self) {
        loop {
            let closed = self.closed.notified();
            if self.state() == RuntimeState::Closed {
                return;
            }
            closed.await;
        }
    }
}

pub(crate) struct RuntimeLease {
    runtime: Arc<DnsRuntime>,
}

impl RuntimeLease {
    pub(crate) fn runtime(&self) -> &DnsRuntime {
        &self.runtime
    }
}

impl Drop for RuntimeLease {
    fn drop(&mut self) {
        if self.runtime.leases.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.runtime.lease_released.notify_waiters();
        }
    }
}
