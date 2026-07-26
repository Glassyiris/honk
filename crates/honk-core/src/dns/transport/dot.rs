//! DNS over TLS (RFC 7858) with an idle connection pool.

use std::sync::Arc;

use parking_lot::Mutex;

use super::{DialContext, exchange_with_retry, idle_pool_exchange};
use honk_outbound::tls::{TlsConnector, TlsStream};

/// TLS stream over either a direct or proxied base connection.
type PooledStream = TlsStream<Box<dyn crate::proxy::AsyncReadWrite>>;

/// Idle-pool DoT client for one upstream.
pub struct DotPool {
    dial: DialContext,
    connector: TlsConnector,
    idle: Mutex<Vec<PooledStream>>,
}

impl DotPool {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x03dot")?;
        Ok(Arc::new(Self {
            dial,
            connector,
            idle: Mutex::new(Vec::new()),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry("DoT", || self.exchange_once(raw_query), || async {}).await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        idle_pool_exchange(
            &self.idle,
            || self.dial_tls(),
            raw_query,
            self.dial.query_timeout,
        )
        .await
    }

    async fn dial_tls(&self) -> anyhow::Result<PooledStream> {
        let server_name = self.dial.endpoint.sni.clone();

        if self.dial.proxy.is_some() {
            let tcp = self.dial.dial_tcp_boxed().await?;
            self.connector
                .connect(&server_name, tcp)
                .await
                .map_err(|e| anyhow::anyhow!("DoT TLS handshake (via proxy): {e}"))
        } else {
            let tcp: Box<dyn crate::proxy::AsyncReadWrite> = Box::new(self.dial.dial_tcp().await?);
            self.connector
                .connect(&server_name, tcp)
                .await
                .map_err(|e| anyhow::anyhow!("DoT TLS handshake: {e}"))
        }
    }
}
