//! DNS over HTTP/3 (DoH3).
//!
//! One long-lived QUIC connection with ALPN `h3`, carrying POST requests of
//! `application/dns-message` to the configured path (default `/dns-query`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::ClientConfig;
use tokio::sync::Mutex;
use tracing::debug;

use crate::dns::endpoint::DnsEndpoint;

use super::framing::force_dns_id_zero;
use super::{
    SharedQuicEndpoint, build_doh_request, dns_quic_config, exchange_with_retry,
    finish_doh_response, quic_connect,
};

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

/// DoH3 client for one upstream.
pub struct Doh3Client {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    /// Open H3 request sender; `None` forces redial.
    sender: Mutex<Option<H3Sender>>,
}

impl Doh3Client {
    pub async fn new(endpoint: DnsEndpoint, query_timeout: Duration) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"h3"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            sender: Mutex::new(None),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH3",
            || self.exchange_once(raw_query),
            || async {
                self.sender.lock().await.take();
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender().await?;

        let mut wire = raw_query.to_vec();
        let orig_id = force_dns_id_zero(&mut wire);

        let req = build_doh_request(&self.endpoint, None, "DoH3")?;

        let mut stream = sender
            .send_request(req)
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 send_request: {e}"))?;

        stream
            .send_data(Bytes::from(wire))
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 send_data: {e}"))?;
        stream
            .finish()
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 finish: {e}"))?;

        let response = tokio::time::timeout(self.query_timeout, stream.recv_response())
            .await
            .map_err(|_| anyhow::anyhow!("DoH3 response timed out"))?
            .map_err(|e| anyhow::anyhow!("DoH3 recv_response: {e}"))?;

        let status = response.status();
        let mut buf = Vec::with_capacity(512);
        loop {
            let chunk = tokio::time::timeout(self.query_timeout, stream.recv_data())
                .await
                .map_err(|_| anyhow::anyhow!("DoH3 body timed out"))?
                .map_err(|e| anyhow::anyhow!("DoH3 recv_data: {e}"))?;
            match chunk {
                Some(mut b) => {
                    while b.has_remaining() {
                        let chunk = b.chunk();
                        buf.extend_from_slice(chunk);
                        let len = chunk.len();
                        b.advance(len);
                    }
                }
                None => break,
            }
        }

        finish_doh_response("DoH3", status, buf, orig_id)
    }

    async fn get_sender(&self) -> anyhow::Result<H3Sender> {
        {
            let sender = self.sender.lock().await;
            if let Some(s) = sender.clone() {
                return Ok(s);
            }
        }

        let addr: SocketAddr = self.endpoint.resolve_addr().await?;
        let conn = quic_connect(
            &self.quic_ep,
            &self.quic_config,
            addr,
            &self.endpoint.sni,
            self.query_timeout,
            "DoH3 QUIC",
        )
        .await?;

        let quinn_conn = H3QuinnConnection::new(conn);
        let (mut driver, sender) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 h3::client::new: {e}"))?;

        // poll_close resolves with ConnectionError (not Result) when the
        // connection ends — drive it on a background task for the session life.
        tokio::spawn(async move {
            let err = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("DoH3 driver closed: {err}");
        });

        *self.sender.lock().await = Some(sender.clone());
        Ok(sender)
    }
}
