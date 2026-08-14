use std::net::SocketAddr;
use std::sync::Arc;

use honk_config::types::DnsProtocol;
use tracing::debug;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::dns::forwarder::DnsUpstreamPool;
fn udp_attempt_addresses(
    addresses: &[SocketAddr],
    current: Option<SocketAddr>,
) -> Option<[SocketAddr; 2]> {
    let first = current
        .filter(|address| addresses.contains(address))
        .or_else(|| addresses.first().copied())?;
    let retry = addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4() != first.is_ipv4())
        .or_else(|| addresses.iter().copied().find(|address| *address != first))
        .unwrap_or(first);
    Some([first, retry])
}

impl UpstreamPool {
    async fn udp_pool(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
    ) -> anyhow::Result<Arc<crate::dns::transport::UdpPool>> {
        let family = if address.is_ipv6() { 1 } else { 0 };
        if let Some((cached_address, pool)) = entry.udp.lock().pools[family].as_ref()
            && *cached_address == address
        {
            return Ok(Arc::clone(pool));
        }
        let candidate = crate::dns::transport::UdpPool::new_tracked(
            address,
            self.dns_query_timeout,
            Arc::clone(&self.active_transport_tasks),
        )
        .await?;
        let (pool, unused, replaced) = {
            let mut state = entry.udp.lock();
            if let Some((cached_address, pool)) = state.pools[family].as_ref()
                && *cached_address == address
            {
                (Arc::clone(pool), Some(candidate), None)
            } else {
                if state
                    .current
                    .is_some_and(|current| current.is_ipv6() == address.is_ipv6())
                {
                    state.current = None;
                }
                let replaced = state.pools[family]
                    .replace((address, Arc::clone(&candidate)))
                    .map(|(_, pool)| pool);
                (candidate, None, replaced)
            }
        };
        for discarded in [unused, replaced].into_iter().flatten() {
            discarded.close().await;
        }
        Ok(pool)
    }

    async fn query_udp(&self, entry: &UpstreamEntry, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let addresses = Self::resolve_udp_addrs(entry).await?;
        let current = entry.udp.lock().current;
        let [first, retry] = udp_attempt_addresses(&addresses, current)
            .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
        let first_result = match self.udp_pool(entry, first).await {
            Ok(pool) => pool.exchange(raw_query).await,
            Err(error) => Err(error),
        };
        match first_result {
            Ok(response) => {
                entry.udp.lock().current = Some(first);
                Ok(response)
            }
            Err(first_error) => {
                debug!(
                    address = %first,
                    retry_address = %retry,
                    error_kind = "exchange_failed",
                    "UDP DNS query candidate failed; retrying"
                );
                let retry_result = match self.udp_pool(entry, retry).await {
                    Ok(pool) => pool.exchange(raw_query).await,
                    Err(error) => Err(error),
                };
                match retry_result {
                    Ok(response) => {
                        entry.udp.lock().current = Some(retry);
                        Ok(response)
                    }
                    Err(error) => Err(anyhow::anyhow!(
                        "UDP DNS failed via {retry}: {error} (first {first}: {first_error})"
                    )),
                }
            }
        }
    }

    pub(super) async fn resolve_udp_addrs(
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        if let Ok(address) = entry.address.parse::<SocketAddr>() {
            return Ok(vec![address]);
        }
        entry.endpoint.resolve_addrs().await
    }

    pub(super) async fn resolve_udp_addr(entry: &UpstreamEntry) -> anyhow::Result<SocketAddr> {
        Self::resolve_udp_addrs(entry)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_retry_uses_other_family_before_same_family() {
        let ipv6_first = [
            "[2001:db8::1]:53".parse().unwrap(),
            "[2001:db8::2]:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
        ];

        assert_eq!(
            udp_attempt_addresses(&ipv6_first, None).unwrap(),
            [ipv6_first[0], ipv6_first[2]]
        );
        assert_eq!(
            udp_attempt_addresses(&ipv6_first, Some(ipv6_first[2])).unwrap(),
            [ipv6_first[2], ipv6_first[0]]
        );
    }
}
