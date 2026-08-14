use crate::dns::endpoint::DnsEndpoint;
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

/// Lazily-created per-family QUIC client endpoints reused across reconnects.
pub(super) struct SharedQuicEndpoint(tokio::sync::Mutex<[Option<quinn::Endpoint>; 2]>);

impl SharedQuicEndpoint {
    pub(super) fn new() -> Self {
        Self(tokio::sync::Mutex::new([None, None]))
    }

    async fn get(&self, ipv6: bool) -> anyhow::Result<quinn::Endpoint> {
        let mut endpoints = self.0.lock().await;
        let endpoint = &mut endpoints[if ipv6 { 1 } else { 0 }];
        if let Some(endpoint) = endpoint.as_ref() {
            return Ok(endpoint.clone());
        }
        let created = honk_outbound::quic::client_endpoint(ipv6)
            .map_err(|e| anyhow::anyhow!("QUIC client endpoint: {e}"))?;
        *endpoint = Some(created.clone());
        Ok(created)
    }

    pub(super) async fn close(&self, timeout: Duration) {
        let endpoints = {
            let mut endpoints = self.0.lock().await;
            [endpoints[0].take(), endpoints[1].take()]
        };
        for endpoint in endpoints.into_iter().flatten() {
            endpoint.close(0_u32.into(), b"shutdown");
            let _ = tokio::time::timeout(timeout, endpoint.wait_idle()).await;
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

pub(super) async fn quic_connect_endpoint(
    endpoint: &SharedQuicEndpoint,
    config: &quinn::ClientConfig,
    target: &DnsEndpoint,
    timeout: Duration,
    label: &str,
) -> anyhow::Result<quinn::Connection> {
    let per_address = timeout.min(Duration::from_secs(3));
    let mut last_error = None;
    for address in target.resolve_addrs().await? {
        match quic_connect(endpoint, config, address, &target.sni, per_address, label).await {
            Ok(connection) => return Ok(connection),
            Err(error) => {
                tracing::debug!(
                    %address,
                    transport = label,
                    error_kind = "handshake_failed",
                    "DNS QUIC dial failed; trying next address"
                );
                last_error = Some(anyhow::anyhow!("{label} dial to {address}: {error}"));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("{label} resolved to no addresses")))
}
