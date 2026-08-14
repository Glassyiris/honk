//! DNS over HTTPS (RFC 8484) over HTTP/2.
//!
//! One long-lived H2 session per upstream multiplexes concurrent POSTs of
//! `application/dns-message`. On session death the next query redials once.
//! Query ID is forced to 0 on the wire (cache-friendly) and restored for the
//! intercepted client.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use bytes::Bytes;
use h2::client::{SendRequest, handshake};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use super::framing::force_dns_id_zero;
use super::lifecycle::LifecycleSlot;
use super::owned_task::OwnedTask;
use super::{
    DialContext, DnsMessageBody, build_doh_request, doh_content_length, exchange_with_retry,
    finish_doh_response,
};
use honk_outbound::tls::TlsConnector;

pub(super) const DOH_ALPN_WIRE: &[u8] = b"\x02h2";

type H2Sender = SendRequest<Bytes>;

struct H2Session {
    sender: Mutex<Option<H2Sender>>,
    driver: OwnedTask,
}

/// Shared DoH (HTTP/2) client for one upstream.
pub struct DohClient {
    dial: DialContext,
    connector: TlsConnector,
    session: LifecycleSlot<H2Session>,
    active_tasks: Arc<AtomicUsize>,
}

impl DohClient {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        Self::new_tracked(dial, Arc::new(AtomicUsize::new(0)))
    }

    pub(crate) fn new_tracked(
        dial: DialContext,
        active_tasks: Arc<AtomicUsize>,
    ) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, DOH_ALPN_WIRE)?;
        Ok(Arc::new(Self {
            dial,
            connector,
            session: LifecycleSlot::new(),
            active_tasks,
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        exchange_with_retry(
            "DoH",
            || self.exchange_once(raw_query),
            || async {
                self.close_session().await;
            },
        )
        .await
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender().await?;

        tokio::time::timeout(self.dial.query_timeout, async {
            let mut wire = raw_query.to_vec();
            let orig_id = force_dns_id_zero(&mut wire);

            let req = build_doh_request(&self.dial.endpoint, Some(wire.len()), "DoH")?;

            let (response_fut, mut send_stream) = sender
                .send_request(req, false)
                .map_err(|e| anyhow::anyhow!("DoH send_request: {e}"))?;

            send_stream
                .send_data(Bytes::from(wire), true)
                .map_err(|e| anyhow::anyhow!("DoH send_data: {e}"))?;

            let response = response_fut
                .await
                .map_err(|e| anyhow::anyhow!("DoH response error: {e}"))?;

            let status = response.status();
            let content_length = doh_content_length("DoH", response.headers())?;
            let mut body = response.into_body();
            let mut buf = DnsMessageBody::new("DoH", content_length)?;
            while let Some(chunk) = body.data().await {
                let chunk = chunk.map_err(|e| anyhow::anyhow!("DoH body read: {e}"))?;
                let n = chunk.len();
                buf.push(&chunk)?;
                let _ = body.flow_control().release_capacity(n);
            }

            finish_doh_response("DoH", status, buf.into_bytes(), orig_id)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("DoH exchange timed out after {:?}", self.dial.query_timeout)
        })?
    }

    async fn get_sender(&self) -> anyhow::Result<H2Sender> {
        let session = self.session.acquire(|| self.handshake()).await?;
        session
            .sender
            .lock()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("DoH session is closing"))
    }

    async fn handshake(&self) -> anyhow::Result<H2Session> {
        let server_name = self.dial.endpoint.sni.clone();
        let via_proxy = self.dial.proxy.is_some();
        let deadline = tokio::time::Instant::now() + self.dial.dial_timeout;
        let tcp = self.dial.dial_tcp_boxed_until(deadline).await?;
        tokio::time::timeout_at(deadline, async {
            let tls = self
                .connector
                .connect(&server_name, tcp)
                .await
                .map_err(|error| {
                    let route = if via_proxy { " (via proxy)" } else { "" };
                    anyhow::anyhow!("DoH TLS handshake{route}: {error}")
                })?;
            spawn_h2(tls, Arc::clone(&self.active_tasks)).await
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "DoH TCP, TLS, and HTTP/2 setup timed out after {:?}",
                self.dial.dial_timeout
            )
        })?
    }

    async fn close_session(&self) {
        let timeout = self.dial.query_timeout;
        self.session
            .close(|session| async move {
                session.sender.lock().take();
                session.driver.shutdown(timeout).await;
            })
            .await;
    }

    pub(crate) async fn close(&self) {
        self.close_session().await;
    }
}

async fn spawn_h2<S>(tls: S, active_tasks: Arc<AtomicUsize>) -> anyhow::Result<H2Session>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = handshake(tls)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/2 handshake: {e}"))?;
    let driver = OwnedTask::spawn(
        async move {
            if let Err(error) = conn.await {
                debug!(
                    error = %error,
                    transport = "doh",
                    "dns transport driver stopped"
                );
            }
        },
        active_tasks,
    );
    Ok(H2Session {
        sender: Mutex::new(Some(sender)),
        driver,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        DnsMessageBody, DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE, doh_content_length,
    };

    #[test]
    fn h2_body_rejects_hostile_multichunk_response_before_append() {
        // Given
        let mut body = DnsMessageBody::new("DoH", None).expect("body");
        body.push(&vec![0; 32_768]).expect("first chunk");

        // When
        let error = body
            .push(&vec![0; 32_768])
            .expect_err("oversized second chunk");

        // Then
        assert_eq!(body.len(), 32_768);
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }

    #[test]
    fn h2_body_accepts_exact_protocol_boundary() {
        // Given
        let mut body =
            DnsMessageBody::new("DoH", Some(MAX_DNS_MESSAGE_SIZE)).expect("bounded body");

        // When
        body.push(&vec![0; MAX_DNS_MESSAGE_SIZE])
            .expect("exact boundary");

        // Then
        assert_eq!(body.len(), MAX_DNS_MESSAGE_SIZE);
    }

    #[test]
    fn h2_body_rejects_oversized_content_length_before_allocation() {
        // Given
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("65536"),
        );

        // When
        let error = doh_content_length("DoH", &headers).expect_err("oversized content length");

        // Then
        assert!(error.downcast_ref::<DnsMessageTooLarge>().is_some());
    }
}
