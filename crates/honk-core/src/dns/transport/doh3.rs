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
use http::{Method, Request};
use quinn::{ClientConfig, Endpoint};
use tokio::sync::Mutex;
use tracing::debug;

use crate::dns::endpoint::DnsEndpoint;

use super::framing::{force_dns_id_zero, restore_dns_id};

/// DoH3 client for one upstream.
pub struct Doh3Client {
    endpoint: DnsEndpoint,
    query_timeout: Duration,
    quic_config: ClientConfig,
    state: Mutex<Doh3State>,
}

struct Doh3State {
    ep: Option<Endpoint>,
    /// Open H3 request sender; `None` forces redial.
    sender: Option<SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

impl Doh3Client {
    pub async fn new(endpoint: DnsEndpoint, query_timeout: Duration) -> anyhow::Result<Arc<Self>> {
        let quic_config = honk_outbound::quic::client_config(
            &Default::default(),
            &[b"h3"],
            honk_outbound::quic::QuicClientOptions {
                keep_alive: Some(Duration::from_secs(15)),
                ..honk_outbound::quic::QuicClientOptions::with_congestion(Some("cubic"))
            },
        )
        .await?;
        Ok(Arc::new(Self {
            endpoint,
            query_timeout,
            quic_config,
            state: Mutex::new(Doh3State {
                ep: None,
                sender: None,
            }),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.exchange_once(raw_query).await {
            Ok(r) => Ok(r),
            Err(first) => {
                debug!("DoH3 exchange failed ({first}); resetting and retrying");
                self.state.lock().await.sender = None;
                self.exchange_once(raw_query)
                    .await
                    .map_err(|e| anyhow::anyhow!("DoH3 failed after retry: {e} (first: {first})"))
            }
        }
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender().await?;

        let mut wire = raw_query.to_vec();
        let orig_id = force_dns_id_zero(&mut wire);

        let path = if self.endpoint.path.is_empty() {
            "/dns-query"
        } else {
            self.endpoint.path.as_str()
        };
        let authority = authority(&self.endpoint.host, self.endpoint.port);
        let uri = format!("https://{authority}{path}");

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| anyhow::anyhow!("DoH3 request build: {e}"))?;

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

        if !status.is_success() {
            anyhow::bail!("DoH3 HTTP status {status}");
        }
        if buf.len() < 12 {
            anyhow::bail!("DoH3 response too short ({} bytes)", buf.len());
        }
        restore_dns_id(&mut buf, orig_id);
        Ok(buf)
    }

    async fn get_sender(&self) -> anyhow::Result<SendRequest<h3_quinn::OpenStreams, Bytes>> {
        {
            let st = self.state.lock().await;
            if let Some(s) = st.sender.clone() {
                return Ok(s);
            }
        }

        let addr: SocketAddr = self.endpoint.resolve_addr().await?;
        let ipv6 = addr.is_ipv6();

        let ep = {
            let mut st = self.state.lock().await;
            if st.ep.is_none() {
                let ep = honk_outbound::quic::client_endpoint(ipv6)
                    .map_err(|e| anyhow::anyhow!("DoH3 endpoint: {e}"))?;
                st.ep = Some(ep);
            }
            st.ep.as_ref().expect("endpoint just inserted").clone()
        };

        let connecting = ep
            .connect_with(self.quic_config.clone(), addr, &self.endpoint.sni)
            .map_err(|e| anyhow::anyhow!("DoH3 connect_with: {e}"))?;

        let conn = tokio::time::timeout(self.query_timeout, connecting)
            .await
            .map_err(|_| anyhow::anyhow!("DoH3 QUIC handshake timed out"))?
            .map_err(|e| anyhow::anyhow!("DoH3 QUIC handshake: {e}"))?;

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

        self.state.lock().await.sender = Some(sender.clone());
        Ok(sender)
    }
}

fn authority(host: &str, port: u16) -> String {
    let host_fmt = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host_fmt
    } else {
        format!("{host_fmt}:{port}")
    }
}
