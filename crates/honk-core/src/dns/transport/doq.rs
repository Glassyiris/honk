//! DNS over QUIC (RFC 9250).
//!
//! One long-lived QUIC connection (ALPN `doq`); each query opens a
//! bidirectional stream, writes a length-prefixed message with ID=0,
//! finishes the send side, and reads the length-prefixed response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::Mutex;
use tracing::debug;

use crate::dns::endpoint::DnsEndpoint;

use super::framing::{force_dns_id_zero, restore_dns_id};

/// DoQ client for one upstream.
pub struct DoqClient {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    quic_config: ClientConfig,
    state: Mutex<DoqState>,
}

struct DoqState {
    ep: Option<Endpoint>,
    conn: Option<Connection>,
}

impl DoqClient {
    pub fn new(endpoint: DnsEndpoint, query_timeout: Duration) -> anyhow::Result<Arc<Self>> {
        let quic_config = honk_outbound::quic::client_config(
            &Default::default(),
            &[b"doq"],
            Some("cubic"),
            Some(Duration::from_secs(15)),
        )?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            quic_config,
            state: Mutex::new(DoqState {
                ep: None,
                conn: None,
            }),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.exchange_once(raw_query).await {
            Ok(r) => Ok(r),
            Err(first) => {
                debug!("DoQ exchange failed ({first}); invalidating conn and retrying");
                self.invalidate().await;
                self.exchange_once(raw_query)
                    .await
                    .map_err(|e| anyhow::anyhow!("DoQ failed after retry: {e} (first: {first})"))
            }
        }
    }

    async fn invalidate(&self) {
        self.state.lock().await.conn = None;
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let conn = self.get_conn().await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("DoQ open_bi: {e}"))?;

        let mut wire = raw_query.to_vec();
        let orig_id = force_dns_id_zero(&mut wire);
        write_lp(&mut send, &wire).await?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("DoQ finish send: {e}"))?;

        let mut resp = read_lp(&mut recv, self.query_timeout).await?;
        restore_dns_id(&mut resp, orig_id);
        Ok(resp)
    }

    async fn get_conn(&self) -> anyhow::Result<Connection> {
        {
            let st = self.state.lock().await;
            if let Some(c) = st.conn.clone()
                && c.close_reason().is_none()
            {
                return Ok(c);
            }
        }
        self.dial().await
    }

    async fn dial(&self) -> anyhow::Result<Connection> {
        let addr: SocketAddr = self.endpoint.resolve_addr().await?;
        let ipv6 = addr.is_ipv6();

        let ep = {
            let mut st = self.state.lock().await;
            if st.ep.is_none() {
                let ep = honk_outbound::quic::client_endpoint(ipv6)
                    .map_err(|e| anyhow::anyhow!("DoQ endpoint: {e}"))?;
                st.ep = Some(ep);
            }
            st.ep.as_ref().expect("endpoint just inserted").clone()
        };

        let connecting = ep
            .connect_with(self.quic_config.clone(), addr, &self.endpoint.sni)
            .map_err(|e| anyhow::anyhow!("DoQ connect_with: {e}"))?;
        let conn = tokio::time::timeout(self.query_timeout, connecting)
            .await
            .map_err(|_| anyhow::anyhow!("DoQ handshake timed out"))?
            .map_err(|e| anyhow::anyhow!("DoQ handshake: {e}"))?;
        self.state.lock().await.conn = Some(conn.clone());
        Ok(conn)
    }
}

async fn write_lp(send: &mut SendStream, msg: &[u8]) -> anyhow::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| anyhow::anyhow!("DoQ message too large"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| anyhow::anyhow!("DoQ write len: {e}"))?;
    send.write_all(msg)
        .await
        .map_err(|e| anyhow::anyhow!("DoQ write body: {e}"))?;
    Ok(())
}

async fn read_lp(recv: &mut RecvStream, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, recv.read_exact(&mut len_buf))
        .await
        .map_err(|_| anyhow::anyhow!("DoQ read len timed out"))?
        .map_err(|e| anyhow::anyhow!("DoQ read len: {e}"))?;
    let n = u16::from_be_bytes(len_buf) as usize;
    if n == 0 || n > 65535 {
        anyhow::bail!("invalid DoQ response length {n}");
    }
    let mut buf = vec![0u8; n];
    tokio::time::timeout(timeout, recv.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("DoQ read body timed out"))?
        .map_err(|e| anyhow::anyhow!("DoQ read body: {e}"))?;
    Ok(buf)
}
