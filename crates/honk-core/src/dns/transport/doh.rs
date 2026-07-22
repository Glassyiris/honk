//! DNS over HTTPS (RFC 8484) over HTTP/2.
//!
//! One long-lived H2 session per upstream multiplexes concurrent POSTs of
//! `application/dns-message`. On session death the next query redials once.
//! Query ID is forced to 0 on the wire (cache-friendly) and restored for the
//! intercepted client.

use std::sync::Arc;

use bytes::Bytes;
use h2::client::{SendRequest, handshake};
use http::Request;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use super::DialContext;
use super::framing::{force_dns_id_zero, restore_dns_id};
use honk_outbound::tls::TlsConnector;

type H2Sender = SendRequest<Bytes>;

/// Shared DoH (HTTP/2) client for one upstream.
pub struct DohClient {
    dial: DialContext,
    connector: TlsConnector,
    /// `None` means "need (re)handshake".
    session: Mutex<Option<H2Sender>>,
}

impl DohClient {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let connector = honk_outbound::tls::build_dns_connector(false, b"\x02h2\x08http/1.1")?;
        Ok(Arc::new(Self {
            dial,
            connector,
            session: Mutex::new(None),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.exchange_once(raw_query, false).await {
            Ok(r) => Ok(r),
            Err(first) => {
                debug!("DoH exchange failed ({first}); resetting session and retrying");
                *self.session.lock() = None;
                self.exchange_once(raw_query, true)
                    .await
                    .map_err(|e| anyhow::anyhow!("DoH failed after retry: {e} (first: {first})"))
            }
        }
    }

    async fn exchange_once(&self, raw_query: &[u8], force_new: bool) -> anyhow::Result<Vec<u8>> {
        let mut sender = self.get_sender(force_new).await?;

        let mut wire = raw_query.to_vec();
        let orig_id = force_dns_id_zero(&mut wire);

        let path = if self.dial.endpoint.path.is_empty() {
            "/dns-query"
        } else {
            self.dial.endpoint.path.as_str()
        };
        let authority = authority(&self.dial.endpoint.host, self.dial.endpoint.port);
        let uri = format!("https://{authority}{path}");

        let req = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .header("content-length", wire.len().to_string())
            .body(())
            .map_err(|e| anyhow::anyhow!("DoH request build: {e}"))?;

        let (response_fut, mut send_stream) = sender
            .send_request(req, false)
            .map_err(|e| anyhow::anyhow!("DoH send_request: {e}"))?;

        send_stream
            .send_data(Bytes::from(wire), true)
            .map_err(|e| anyhow::anyhow!("DoH send_data: {e}"))?;

        let response = tokio::time::timeout(self.dial.query_timeout, response_fut)
            .await
            .map_err(|_| anyhow::anyhow!("DoH response timed out"))?
            .map_err(|e| anyhow::anyhow!("DoH response error: {e}"))?;

        let status = response.status();
        let mut body = response.into_body();
        let mut buf = Vec::with_capacity(512);
        loop {
            let next = tokio::time::timeout(self.dial.query_timeout, body.data())
                .await
                .map_err(|_| anyhow::anyhow!("DoH body timed out"))?;
            match next {
                Some(chunk) => {
                    let chunk = chunk.map_err(|e| anyhow::anyhow!("DoH body read: {e}"))?;
                    let n = chunk.len();
                    buf.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(n);
                }
                None => break,
            }
        }

        if !status.is_success() {
            anyhow::bail!("DoH HTTP status {status}");
        }
        if buf.len() < 12 {
            anyhow::bail!("DoH response too short ({} bytes)", buf.len());
        }
        restore_dns_id(&mut buf, orig_id);
        Ok(buf)
    }

    async fn get_sender(&self, force_new: bool) -> anyhow::Result<H2Sender> {
        if !force_new && let Some(s) = self.session.lock().clone() {
            return Ok(s);
        }
        let sender = self.handshake().await?;
        *self.session.lock() = Some(sender.clone());
        Ok(sender)
    }

    async fn handshake(&self) -> anyhow::Result<H2Sender> {
        let server_name = self.dial.endpoint.sni.clone();

        if self.dial.proxy.is_some() {
            let tcp = self.dial.dial_tcp_boxed().await?;
            let tls = self
                .connector
                .connect(&server_name, tcp)
                .await
                .map_err(|e| anyhow::anyhow!("DoH TLS handshake (proxy): {e}"))?;
            return spawn_h2(tls).await;
        }
        let tcp = self.dial.dial_tcp().await?;
        let tls = self
            .connector
            .connect(&server_name, tcp)
            .await
            .map_err(|e| anyhow::anyhow!("DoH TLS handshake: {e}"))?;
        spawn_h2(tls).await
    }
}

async fn spawn_h2<S>(tls: S) -> anyhow::Result<H2Sender>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = handshake(tls)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/2 handshake: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("DoH H2 connection closed: {e}");
        }
    });
    Ok(sender)
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
