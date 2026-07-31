use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use crate::dns::cache::DnsCache;
use crate::dns::upstream_pool::UpstreamPool;

static NEXT_PERSISTENCE_ID: AtomicU64 = AtomicU64::new(1);

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
