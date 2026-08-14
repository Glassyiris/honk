//! Idle pool for plain DNS-over-TCP (RFC 7766).

use std::sync::Arc;

use super::{DialContext, IdlePoolState, close_idle_pool, exchange_with_retry, idle_pool_exchange};
use parking_lot::Mutex;

/// Direct or proxied pooled TCP stream.
type PooledStream = Box<dyn crate::proxy::AsyncReadWrite>;

/// Idle-pool plain-TCP DNS client for one upstream.
pub struct TcpPool {
    dial: DialContext,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<PooledStream>>,
}

impl TcpPool {
    pub fn new(dial: DialContext) -> Arc<Self> {
        Arc::new(Self {
            dial,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        })
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        #[cfg(feature = "honk-policy")] feedback: Option<&honk_outbound::group::HonkFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        #[cfg(feature = "honk-policy")]
        return exchange_with_retry(
            "TCP DNS",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            || async {},
            feedback,
        )
        .await;
        #[cfg(not(feature = "honk-policy"))]
        exchange_with_retry(
            "TCP DNS",
            raw_query,
            || self.exchange_once(raw_query),
            || async {},
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        #[cfg(feature = "honk-policy")] reporter: Option<&honk_outbound::group::HonkReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_new(),
            raw_query,
            self.dial.query_timeout,
            #[cfg(feature = "honk-policy")]
            reporter,
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

    pub(crate) async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}
