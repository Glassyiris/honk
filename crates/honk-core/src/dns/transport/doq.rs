//! DNS over QUIC (RFC 9250).
//!
//! One long-lived QUIC connection (ALPN `doq`); each query opens a
//! bidirectional stream, writes a length-prefixed message with ID=0,
//! finishes the send side, and reads the length-prefixed response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection};
use tokio::sync::Mutex;

use crate::dns::endpoint::DnsEndpoint;

use super::framing::{
    force_dns_id_zero, read_length_prefixed, restore_dns_id, write_length_prefixed,
};
use super::{SharedQuicEndpoint, dns_quic_config, exchange_with_retry, quic_connect};

/// DoQ client for one upstream.
pub struct DoqClient {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    conn: Mutex<Option<Connection>>,
}

impl DoqClient {
    pub async fn new(endpoint: DnsEndpoint, query_timeout: Duration) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"doq"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            conn: Mutex::new(None),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoQ",
            || self.exchange_once(raw_query),
            || async {
                self.conn.lock().await.take();
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("DoQ open_bi: {e}"))?;

        let mut wire = raw_query.to_vec();
        let orig_id = force_dns_id_zero(&mut wire);
        write_length_prefixed(&mut send, &wire).await?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;

        let mut resp = read_length_prefixed(&mut recv, self.query_timeout).await?;
        restore_dns_id(&mut resp, orig_id);
        Ok(resp)
    }

    async fn get_conn(&self) -> anyhow::Result<Connection> {
        {
            let conn = self.conn.lock().await;
            if let Some(c) = conn.clone()
                && c.close_reason().is_none()
            {
                return Ok(c);
            }
        }
        self.dial().await
    }

    async fn dial(&self) -> anyhow::Result<Connection> {
        let addr: SocketAddr = self.endpoint.resolve_addr().await?;
        let conn = quic_connect(
            &self.quic_ep,
            &self.quic_config,
            addr,
            &self.endpoint.sni,
            self.query_timeout,
            "DoQ",
        )
        .await?;
        *self.conn.lock().await = Some(conn.clone());
        Ok(conn)
    }
}
