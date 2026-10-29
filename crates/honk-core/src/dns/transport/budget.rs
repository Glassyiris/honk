use std::sync::{Arc, LazyLock, Weak};

use crate::dns::upstream_pool::DnsIdleResources;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const DEFAULT_DNS_SOCKET_LIMIT: usize = 256;
pub(crate) const MAX_EXTRA_UDP_SOCKETS: usize = 16;

static DEFAULT_BUDGET: LazyLock<DnsSocketBudget> =
    LazyLock::new(|| DnsSocketBudget::new(DEFAULT_DNS_SOCKET_LIMIT));
static EXTRA_UDP_SOCKETS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_EXTRA_UDP_SOCKETS)));

#[derive(Debug, Default)]
struct PressureState {
    owners: parking_lot::Mutex<Vec<Weak<DnsIdleResources>>>,
    waiters: parking_lot::Mutex<usize>,
}

struct PressureWaiter<'a>(&'a parking_lot::Mutex<usize>);

impl<'a> PressureWaiter<'a> {
    fn new(waiters: &'a parking_lot::Mutex<usize>) -> Self {
        // Registration precedes the first scan; release hooks take this same
        // mutex after dropping their resource Arcs, so neither handoff is lost.
        *waiters.lock() += 1;
        Self(waiters)
    }
}

impl Drop for PressureWaiter<'_> {
    fn drop(&mut self) {
        *self.0.lock() -= 1;
    }
}

/// Shared DNS physical-socket credits and conservative proxy-stream admission.
#[derive(Clone, Debug)]
pub struct DnsSocketBudget {
    sockets: Arc<Semaphore>,
    proxy_streams: Arc<Semaphore>,
    pressure: Arc<PressureState>,
    limit: usize,
}

impl Default for DnsSocketBudget {
    fn default() -> Self {
        DEFAULT_BUDGET.clone()
    }
}

pub(crate) struct IdlePressureRelease<'a>(pub(crate) &'a DnsSocketBudget);

impl Drop for IdlePressureRelease<'_> {
    fn drop(&mut self) {
        self.0.reclaim_idle_if_waiting();
    }
}

impl DnsSocketBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            sockets: Arc::new(Semaphore::new(limit)),
            proxy_streams: Arc::new(Semaphore::new(limit)),
            pressure: Arc::default(),
            limit,
        }
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    pub(crate) async fn acquire_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        self.acquire_socket_credits_until(1, deadline).await
    }

    pub(crate) async fn acquire_bootstrap_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if self.limit < 2 {
            return Err(
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS bootstrap requires two socket credits"),
            );
        }
        self.acquire_socket_credits_until(2, deadline).await
    }

    async fn acquire_socket_credits_until(
        &self,
        count: u32,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.sockets).try_acquire_many_owned(count) {
            return Ok(permit);
        }
        let _waiting = PressureWaiter::new(&self.pressure.waiters);
        self.reclaim_idle_resources();
        tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.sockets).acquire_many_owned(count),
        )
        .await
        .map_err(|_| {
            anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                .context("DNS socket admission timed out")
        })?
        .map_err(|_| {
            anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                .context("DNS socket admission is closed")
        })
    }

    pub(crate) async fn acquire_proxy_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<OwnedSemaphorePermit> {
        if let Ok(permit) = Arc::clone(&self.proxy_streams).try_acquire_owned() {
            return Ok(permit);
        }
        let _waiting = PressureWaiter::new(&self.pressure.waiters);
        self.reclaim_idle_resources();
        tokio::time::timeout_at(deadline, Arc::clone(&self.proxy_streams).acquire_owned())
            .await
            .map_err(|_| {
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS proxy stream admission timed out")
            })?
            .map_err(|_| {
                anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                    .context("DNS proxy stream admission is closed")
            })
    }

    pub(crate) fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sockets).try_acquire_owned().ok()
    }

    pub(crate) fn try_extra_udp(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&EXTRA_UDP_SOCKETS).try_acquire_owned().ok()
    }

    pub(crate) fn shares_admission(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.sockets, &other.sockets)
            && Arc::ptr_eq(&self.proxy_streams, &other.proxy_streams)
    }

    pub(crate) fn register_idle_owner(&self, owner: &Arc<DnsIdleResources>) {
        let owner = Arc::downgrade(owner);
        let mut registered = self.pressure.owners.lock();
        registered.retain(|owner| owner.strong_count() != 0);
        if !registered
            .iter()
            .any(|current| Weak::ptr_eq(current, &owner))
        {
            registered.push(owner);
        }
    }

    pub(crate) fn unregister_idle_owner(&self, owner: &Arc<DnsIdleResources>) {
        let owner = Arc::downgrade(owner);
        self.pressure
            .owners
            .lock()
            .retain(|current| current.strong_count() != 0 && !Weak::ptr_eq(current, &owner));
    }

    pub(crate) fn reclaim_idle_if_waiting(&self) {
        let waiting = *self.pressure.waiters.lock() != 0;
        if waiting {
            self.reclaim_idle_resources();
        }
    }

    fn reclaim_idle_resources(&self) {
        let owners = {
            let mut owners = Vec::new();
            self.pressure.owners.lock().retain(|owner| {
                if let Some(owner) = owner.upgrade() {
                    owners.push(owner);
                    true
                } else {
                    false
                }
            });
            owners
        };
        for owner in owners {
            owner.reclaim_idle();
        }
    }

    #[cfg(test)]
    pub(crate) fn available_sockets(&self) -> usize {
        self.sockets.available_permits()
    }

    #[cfg(test)]
    pub(crate) fn available_proxy_streams(&self) -> usize {
        self.proxy_streams.available_permits()
    }
}
