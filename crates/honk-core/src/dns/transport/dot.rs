//! DNS over TLS (RFC 7858) with an idle connection pool.

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::debug;

use super::framing::exchange_length_prefixed;
use super::DialContext;

const MAX_POOL_SIZE: usize = 4;

enum DotStream {
    Direct(TlsStream<tokio::net::TcpStream>),
    Proxied(TlsStream<Box<dyn crate::proxy::AsyncReadWrite>>),
}

impl AsyncRead for DotStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            DotStream::Direct(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            DotStream::Proxied(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DotStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            DotStream::Direct(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            DotStream::Proxied(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            DotStream::Direct(s) => std::pin::Pin::new(s).poll_flush(cx),
            DotStream::Proxied(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            DotStream::Direct(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            DotStream::Proxied(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Idle-pool DoT client for one upstream.
pub struct DotPool {
    dial: DialContext,
    connector: TlsConnector,
    idle: Mutex<Vec<DotStream>>,
}

impl DotPool {
    pub fn new(dial: DialContext) -> anyhow::Result<Arc<Self>> {
        let mut cfg = honk_outbound::tls::standard_config()?;
        cfg.alpn_protocols = vec![b"dot".to_vec()];
        Ok(Arc::new(Self {
            dial,
            connector: TlsConnector::from(Arc::new(cfg)),
            idle: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
        }))
    }

    pub async fn exchange(self: &Arc<Self>, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.exchange_once(raw_query).await {
            Ok(resp) => Ok(resp),
            Err(first) => {
                debug!("DoT exchange failed ({first}); redialing once");
                self.exchange_once(raw_query).await.map_err(|e| {
                    anyhow::anyhow!("DoT query failed after retry: {e} (first: {first})")
                })
            }
        }
    }

    async fn exchange_once(&self, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut stream = {
            let taken = self.idle.lock().pop();
            match taken {
                Some(s) => s,
                None => self.dial_tls().await?,
            }
        };
        match exchange_length_prefixed(&mut stream, raw_query, self.dial.query_timeout).await {
            Ok(resp) => {
                let mut idle = self.idle.lock();
                if idle.len() < MAX_POOL_SIZE {
                    idle.push(stream);
                }
                Ok(resp)
            }
            Err(e) => Err(e),
        }
    }

    async fn dial_tls(&self) -> anyhow::Result<DotStream> {
        let server_name = ServerName::try_from(self.dial.endpoint.sni.clone())
            .map_err(|e| anyhow::anyhow!("invalid DoT SNI '{}': {e}", self.dial.endpoint.sni))?;

        if self.dial.proxy.is_some() {
            let tcp = self.dial.dial_tcp_boxed().await?;
            let tls = self
                .connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| anyhow::anyhow!("DoT TLS handshake (via proxy): {e}"))?;
            Ok(DotStream::Proxied(tls))
        } else {
            let tcp = self.dial.dial_tcp().await?;
            let tls = self
                .connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| anyhow::anyhow!("DoT TLS handshake: {e}"))?;
            Ok(DotStream::Direct(tls))
        }
    }
}
