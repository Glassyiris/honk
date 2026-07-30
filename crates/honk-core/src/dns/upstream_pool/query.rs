use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use honk_config::types::DnsProtocol;
use honk_ebpf_common::DAE_BYPASS_MARK;
use tracing::debug;

use super::UpstreamPool;
use super::entries::{PoolState, UpstreamEntry};
use crate::dns::forwarder::DnsUpstreamPool;
use crate::dns::transport::TcpPool;

impl UpstreamPool {
    async fn query_udp(
        address: SocketAddr,
        raw_query: &[u8],
        query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let domain = if address.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        honk_outbound::util::set_mark_best_effort(&socket, DAE_BYPASS_MARK)?;
        let unspecified = if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        socket.bind(&SocketAddr::new(unspecified, 0).into())?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())?;
        socket.connect(address).await?;

        let first_budget = (query_timeout / 3).max(Duration::from_millis(200));
        match Self::udp_roundtrip(&socket, address, raw_query, first_budget).await {
            Ok(response) => Ok(response),
            Err(error) => {
                debug!("UDP DNS query to {address} first attempt: {error}; retrying");
                Self::udp_roundtrip(&socket, address, raw_query, query_timeout).await
            }
        }
    }

    async fn udp_roundtrip(
        socket: &tokio::net::UdpSocket,
        address: SocketAddr,
        raw_query: &[u8],
        budget: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(budget, async {
            socket.send(raw_query).await?;
            let mut response = vec![0_u8; 4096];
            loop {
                let length = socket.recv(&mut response).await?;
                if length >= 2 && raw_query.len() >= 2 && response[..2] == raw_query[..2] {
                    response.truncate(length);
                    return Ok::<_, std::io::Error>(response);
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("UDP DNS query to {address} timed out after {budget:?}"))?
        .map_err(Into::into)
    }

    pub(super) async fn resolve_udp_addr(entry: &UpstreamEntry) -> anyhow::Result<SocketAddr> {
        if let Ok(address) = entry.address.parse::<SocketAddr>() {
            return Ok(address);
        }
        entry.endpoint.resolve_addr().await
    }

    async fn query_datagram(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        proxy_node: Option<&honk_config::node::Node>,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(node) = proxy_node {
            let pool = TcpPool::new(self.dial_context(entry, Some(node)));
            let response = pool.exchange(raw_query).await?;
            debug!(
                "DNS upstream '{}' (udp via proxy {}) returned {} bytes",
                upstream_name,
                node.name,
                response.len()
            );
            return Ok(response);
        }

        let address = Self::resolve_udp_addr(entry).await?;
        let response = Self::query_udp(address, raw_query, self.dns_query_timeout).await?;
        if response.len() >= 4 && response[2] & 0x02 != 0 {
            debug!(
                "DNS upstream '{}' UDP answer has TC set — retrying over TCP",
                upstream_name
            );
            return TcpPool::new(self.dial_context(entry, None))
                .exchange(raw_query)
                .await;
        }
        debug!(
            "DNS upstream '{}' (udp {}) returned {} bytes",
            upstream_name,
            address,
            response.len()
        );
        Ok(response)
    }
}

#[async_trait::async_trait]
impl DnsUpstreamPool for UpstreamPool {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        debug!(
            "UpstreamPool::query called for '{}' ({} bytes)",
            upstream_name,
            raw_query.len()
        );
        let entry = self
            .entries
            .get(upstream_name)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream: {upstream_name}"))?;
        let proxy_node = self
            .resolve_dial_leaf(entry)
            .await
            .map_err(|error| anyhow::anyhow!("DNS upstream '{upstream_name}': {error}"))?;
        match *self.shutdown.read().await {
            PoolState::Open => {}
            PoolState::Closing | PoolState::Closed => {
                anyhow::bail!("DNS upstream pool is closed")
            }
        }
        debug!(
            "DNS upstream '{}' dial leaf={:?} (forced={})",
            upstream_name,
            proxy_node.as_ref().map(|node| node.name.as_str()),
            entry.outbound.is_some()
        );

        if entry.protocol == DnsProtocol::Udp {
            return self
                .query_datagram(upstream_name, entry, proxy_node.as_ref(), raw_query)
                .await;
        }
        if matches!(entry.protocol, DnsProtocol::Quic | DnsProtocol::H3) && proxy_node.is_some() {
            anyhow::bail!(
                "DNS upstream '{}' protocol {:?} does not support outbound proxy yet",
                upstream_name,
                entry.protocol
            );
        }
        let response = self
            .get_transport(entry, proxy_node.as_ref())
            .await?
            .exchange(raw_query)
            .await?;
        debug!(
            "DNS upstream '{}' ({:?} {} via {:?}) returned {} bytes",
            upstream_name,
            entry.protocol,
            entry.endpoint.host,
            proxy_node
                .as_ref()
                .map(|node| node.name.as_str())
                .unwrap_or("direct"),
            response.len()
        );
        Ok(response)
    }
}
