//! DNS over TLS (RFC 7858) with an idle connection pool.

use std::sync::Arc;

use super::{DialContext, IdlePoolState, close_idle_pool, exchange_with_retry, idle_pool_exchange};
use honk_outbound::tls::{TlsConnector, TlsStream};
use parking_lot::Mutex;

/// TLS stream over either a direct or proxied base connection.
type PooledStream = TlsStream<Box<dyn crate::proxy::AsyncReadWrite>>;

/// Idle-pool DoT client for one upstream.
pub struct DotPool {
    dial: DialContext,
    connector: TlsConnector,
    lifecycle: tokio::sync::RwLock<IdlePoolState>,
    idle: Mutex<Vec<PooledStream>>,
}

impl DotPool {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x03dot")?;
        Ok(Arc::new(Self {
            dial,
            connector,
            lifecycle: tokio::sync::RwLock::new(IdlePoolState::Open),
            idle: Mutex::new(Vec::new()),
        }))
    }

    pub async fn exchange(
        self: &Arc<Self>,
        raw_query: &[u8],
        feedback: Option<&honk_outbound::group::ScoreFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoT",
            raw_query,
            |reporter| async move { self.exchange_once(raw_query, reporter.as_ref()).await },
            || async {},
            feedback,
        )
        .await
    }

    async fn exchange_once(
        &self,
        raw_query: &[u8],
        reporter: Option<&honk_outbound::group::ScoreReporter>,
    ) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.lifecycle,
            &self.idle,
            || self.dial_tls(),
            raw_query,
            self.dial.query_timeout,
            reporter,
        )
        .await
    }

    async fn dial_tls(&self) -> anyhow::Result<PooledStream> {
        let server_name = self.dial.endpoint.sni.clone();
        let via_proxy = self.dial.proxy.is_some();
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_boxed_until(deadline).await?;
        tokio::time::timeout_at(deadline, self.connector.connect(&server_name, tcp))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "DoT dial and TLS handshake timed out after {:?}",
                    self.dial.dial_timeout
                )
            })?
            .map_err(|error| {
                let route = if via_proxy { " (via proxy)" } else { "" };
                anyhow::anyhow!("DoT TLS handshake{route}: {error}")
            })
    }

    pub(crate) async fn close(&self) {
        close_idle_pool(&self.lifecycle, &self.idle, self.dial.query_timeout).await;
    }
}
