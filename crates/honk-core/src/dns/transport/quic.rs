use std::time::Duration;

/// Shared QUIC client config for DNS transports (15s keep-alive, cubic).
pub(super) async fn dns_quic_config(alpn: &[&[u8]]) -> anyhow::Result<quinn::ClientConfig> {
    honk_outbound::quic::client_config(
        &Default::default(),
        alpn,
        honk_outbound::quic::QuicClientOptions {
            keep_alive: Some(Duration::from_secs(15)),
            ..honk_outbound::quic::QuicClientOptions::with_congestion(Some("cubic"))
        },
    )
    .await
}

/// Lazily-created QUIC client endpoint reused across reconnects (DoQ/DoH3).
pub(super) struct SharedQuicEndpoint(tokio::sync::Mutex<Option<quinn::Endpoint>>);

impl SharedQuicEndpoint {
    pub(super) fn new() -> Self {
        Self(tokio::sync::Mutex::new(None))
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut guard = self.0.lock().await;
        if let Some(ep) = guard.as_ref() {
            return Ok(ep.clone());
        }
        let ep = honk_outbound::quic::client_endpoint(ipv6)
            .map_err(|e| anyhow::anyhow!("QUIC client endpoint: {e}"))?;
        *guard = Some(ep.clone());
        Ok(ep)
    }

    pub(super) async fn close(&self) {
        let endpoint = self.0.lock().await.take();
        if let Some(endpoint) = endpoint {
            endpoint.close(0_u32.into(), b"shutdown");
            endpoint.wait_idle().await;
        }
    }
}

/// Connect `config` to `addr` through the shared endpoint, with a handshake
/// timeout. `label` prefixes error messages (`DoQ` / `DoH3 QUIC`).
pub(super) async fn quic_connect(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    addr: std::net::SocketAddr,
    sni: &str,
    timeout: Duration,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let ep = endpoint.get(addr.is_ipv6()).await?;
    let connecting = ep
        .connect_with(config.clone(), addr, sni)
        .map_err(|e| anyhow::anyhow!("{label} connect_with: {e}"))?;
    tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| anyhow::anyhow!("{label} handshake timed out"))?
        .map_err(|e| anyhow::anyhow!("{label} handshake: {e}"))
}
