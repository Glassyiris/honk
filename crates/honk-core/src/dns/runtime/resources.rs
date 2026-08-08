use async_trait::async_trait;

use crate::dns::upstream_pool::UpstreamPool;

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
