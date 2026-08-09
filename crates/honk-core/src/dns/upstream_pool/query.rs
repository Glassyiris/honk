use std::net::SocketAddr;
use std::sync::Arc;

use honk_config::types::DnsProtocol;
use tracing::debug;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::dns::forwarder::DnsUpstreamPool;

impl UpstreamPool {
    async fn query_udp(&self, entry: &UpstreamEntry, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let pool = if let Some(pool) = entry.udp.lock().as_ref() {
            Arc::clone(pool)
        } else {
            let address = Self::resolve_udp_addr(entry).await?;
            let candidate = crate::dns::transport::UdpPool::new_tracked(
                address,
                self.dns_query_timeout,
                Arc::clone(&self.active_transport_tasks),
            )
            .await?;
            let (pool, unused) = {
                let mut slot = entry.udp.lock();
                if let Some(pool) = slot.as_ref() {
                    (Arc::clone(pool), Some(candidate))
                } else {
                    *slot = Some(Arc::clone(&candidate));
                    (candidate, None)
                }
            };
            if let Some(unused) = unused {
                unused.close().await;
            }
            pool
        };
        match pool.exchange(raw_query).await {
            Ok(response) => Ok(response),
            Err(error) => {
                debug!("UDP DNS query first attempt: {error}; retrying");
                pool.exchange(raw_query).await
            }
        }
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
            let response = self
                .get_transport(entry, Some(node))
                .await?
                .exchange(raw_query)
                .await?;
            debug!(
                "DNS upstream '{}' (udp via proxy {}) returned {} bytes",
                upstream_name,
                node.name,
                response.len()
            );
            return Ok(response);
        }

        let response = self.query_udp(entry, raw_query).await?;
        if response.len() >= 4 && response[2] & 0x02 != 0 {
            debug!(
                "DNS upstream '{}' UDP answer has TC set — retrying over TCP",
                upstream_name
            );
            return self
                .get_transport(entry, None)
                .await?
                .exchange(raw_query)
                .await;
        }
        debug!(
            "DNS upstream '{}' (udp) returned {} bytes",
            upstream_name,
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
        let _admission = self
            .admission
            .admit()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream pool is closed"))?;
        #[cfg(test)]
        self.pause_after_admission_for_test().await;
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
