//! DNS over HTTP/3 (DoH3).
//!
//! One long-lived QUIC connection with ALPN `h3`, carrying POST requests of
//! `application/dns-message` to the configured path (default `/dns-query`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3_quinn::Connection as H3QuinnConnection;
use quinn::ClientConfig;
use tokio::sync::Mutex;
use tracing::debug;

use crate::dns::endpoint::DnsEndpoint;

use super::framing::force_dns_id_zero;
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::{
    DnsMessageBody, SharedQuicEndpoint, build_doh_request, dns_quic_config, doh_content_length,
    exchange_with_retry, finish_doh_response, quic_connect,
};

type H3Sender = SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Session {
    sender: Mutex<Option<H3Sender>>,
    connection: quinn::Connection,
    driver: OwnedTask,
}

/// DoH3 client for one upstream.
pub struct Doh3Client {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    quic_config: ClientConfig,
    quic_ep: SharedQuicEndpoint,
    session: LifecycleSlot<H3Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl Doh3Client {
    pub async fn new(endpoint: DnsEndpoint, query_timeout: Duration) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(endpoint, query_timeout, Arc::new(AtomicUsize::new(0))).await
    }

    pub(crate) async fn new_tracked(
        endpoint: DnsEndpoint,
        query_timeout: Duration,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let quic_config = dns_quic_config(&[b"h3"]).await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            quic_config,
            quic_ep: SharedQuicEndpoint::new(),
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH3",
            || self.exchange_once(raw_query),
            || async {
                self.close_session().await;
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
        let content_length = doh_content_length("DoH3", response.headers())?;
        let mut buf = DnsMessageBody::new("DoH3", content_length)?;
        loop {
            let chunk = tokio::time::timeout(self.query_timeout, stream.recv_data())
                .await
                .map_err(|_| anyhow::anyhow!("DoH3 body timed out"))?
                .map_err(|e| anyhow::anyhow!("DoH3 recv_data: {e}"))?;
            match chunk {
                Some(mut b) => {
                    while b.has_remaining() {
                        let chunk = b.chunk();
                        let len = chunk.len();
                        buf.push(chunk)?;
                        b.advance(len);
                    }
                }
                None => break,
            }
        }

        finish_doh_response("DoH3", status, buf.into_bytes(), orig_id)
    }

    async fn get_sender(&self) -> anyhow::Result<H3Sender> {
        let session = self.session.acquire(|| self.handshake()).await?;
        session
            .sender
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DoH3 session is closing"))
    }

    async fn handshake(&self) -> anyhow::Result<H3Session> {
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

        let quinn_conn = H3QuinnConnection::new(conn.clone());
        let (mut driver, sender) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| anyhow::anyhow!("DoH3 h3::client::new: {e}"))?;

        let driver = OwnedTask::spawn(
            async move {
                let error = futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
                debug!(
                    error = %error,
                    transport = "doh3",
                    "dns transport driver stopped"
                );
            },
            Arc::clone(&self.active_tasks),
        );
        Ok(H3Session {
            sender: Mutex::new(Some(sender)),
            connection: conn,
            driver,
        })
    }

    async fn close_session(&self) {
        let timeout = self.query_timeout;
        self.session
            .close(|session| async move {
                session.sender.lock().await.take();
                session.connection.close(0_u32.into(), b"shutdown");
                session.driver.shutdown(timeout).await;
            })
            .await;
    }

    pub(crate) async fn close(&self) {
        self.close_session().await;
        self.quic_ep.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DnsMessageBody, DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE};

    #[test]
    fn h3_body_rejects_hostile_multichunk_response_before_append() {
        // Given
        let mut body = DnsMessageBody::new("DoH3", None).expect("body");
        body.push(&vec![0; 40_000]).expect("first chunk");

        // When
        let error = body
            .push(&vec![0; 30_000])
            .expect_err("oversized second chunk");

        // Then
        assert_eq!(body.len(), 40_000);
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }

    #[test]
    fn h3_body_accepts_exact_protocol_boundary() {
        // Given
        let mut body =
            DnsMessageBody::new("DoH3", Some(MAX_DNS_MESSAGE_SIZE)).expect("bounded body");

        // When
        body.push(&vec![0; MAX_DNS_MESSAGE_SIZE])
            .expect("exact boundary");

        // Then
        assert_eq!(body.len(), MAX_DNS_MESSAGE_SIZE);
    }
}
