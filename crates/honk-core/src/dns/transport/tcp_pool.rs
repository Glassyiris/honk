//! Idle pool for plain DNS-over-TCP (RFC 7766).

use std::sync::Arc;

use parking_lot::Mutex;

use super::{DialContext, exchange_with_retry, idle_pool_exchange};

/// Direct or proxied pooled TCP stream.
type PooledStream = Box<dyn crate::proxy::AsyncReadWrite>;

/// Idle-pool plain-TCP DNS client for one upstream.
pub struct TcpPool {
    dial: DialContext,
    idle: Mutex<Vec<PooledStream>>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Arc::new(Self {
            dial,
            idle: Mutex::new(Vec::new()),
        })
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry("TCP DNS", || self.exchange_once(raw_query), || async {}).await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.idle,
            || self.dial_new(),
            raw_query,
            self.dial.query_timeout,
        )
        .await
    }

    async fn dial_new(&self) -> anyhow::Result<PooledStream> {
        if self.dial.proxy.is_some() {
            self.dial.dial_tcp_boxed().await
        } else {
            Ok(Box::new(self.dial.dial_tcp().await?))
        }
    }
}
