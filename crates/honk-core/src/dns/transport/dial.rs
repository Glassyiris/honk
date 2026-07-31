use std::sync::Arc;
use std::time::Duration;

use super::super::endpoint::DnsEndpoint;
use crate::proxy::ProxyRegistry;
use honk_config::node::Node;

/// Shared dial context for transports that may go direct or via a proxy node.
#[derive(Clone)]
pub struct DialContext {
    pub endpoint: DnsEndpoint,
    pub query_timeout: Duration,
    pub dial_timeout: Duration,
    /// When set, TCP/TLS is established through this proxy to `endpoint`.
    pub proxy: Option<ProxyDial>,
}

#[derive(Clone)]
pub struct ProxyDial {
    pub registry: Arc<ProxyRegistry>,
    pub node: Node,
}

impl DialContext {
    /// Dial a plain TCP stream to the upstream (marked, or via proxy).
    ///
    /// Tries every bootstrap-resolved address (IPv4 preferred) so a single
    /// unreachable AAAA does not fail the whole DoH/DoT dial.
    pub async fn dial_tcp(&self) -> anyhow::Result<tokio::net::TcpStream> {
        if self.proxy.is_some() {
            // Proxy handlers return a boxed stream already connected to the
            // target; for TLS we need a TcpStream-shaped base only on the
            // direct path. Proxy+TLS is handled separately via boxed stream.
            anyhow::bail!("dial_tcp called with proxy set; use dial_tcp_boxed")
        }
        let addrs = self.endpoint.resolve_addrs().await?;
        let mut last_err = None;
        for addr in addrs {
            // Per-address budget: keep overall cold start reasonable when the
            // first (often broken v6) candidate hangs.
            let per = self.dial_timeout.min(Duration::from_secs(3));
            match tokio::time::timeout(
                per,
                honk_outbound::util::connect_marked_addr(
                    addr,
                    Some(honk_ebpf_common::DAE_BYPASS_MARK),
                    per,
                ),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    tracing::debug!("TCP dial to {addr} failed: {e}");
                    last_err = Some(anyhow::anyhow!("TCP dial to {addr}: {e}"));
                }
                Err(_) => {
                    tracing::debug!("TCP dial to {addr} timed out after {per:?}");
                    last_err = Some(anyhow::anyhow!("TCP dial to {addr} timed out"));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no addresses to dial")))
    }

    /// Dial through the optional proxy, returning a boxed duplex stream to the
    /// upstream DNS server address.
    pub async fn dial_tcp_boxed(&self) -> anyhow::Result<Box<dyn crate::proxy::AsyncReadWrite>> {
        if let Some(proxy) = &self.proxy {
            let addr = self.endpoint.resolve_addr().await?;
            let ps = proxy
                .registry
                .dial(&proxy.node, addr, None, self.dial_timeout)
                .await
                .map_err(|e| anyhow::anyhow!("proxy dial for DNS upstream: {e}"))?;
            return Ok(ps.stream);
        }
        let stream = self.dial_tcp().await?;
        Ok(Box::new(stream))
    }
}
