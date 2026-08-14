use std::net::SocketAddr;
use std::sync::Arc;

use honk_config::types::DnsProtocol;
use tracing::debug;

use super::UpstreamPool;
use super::admission::AdmissionPermit;
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
    pub(super) async fn udp_pool(
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
        let (pool, unused) = {
            let mut state = entry.udp.lock();
            if let Some((cached_address, pool)) = state.pools[family].as_ref()
                && *cached_address == address
            {
                (Arc::clone(pool), Some(candidate))
            } else {
                if state
                    .current
                    .is_some_and(|current| current.is_ipv6() == address.is_ipv6())
                {
                    state.current = None;
                }
                let _ = state.pools[family].replace((address, Arc::clone(&candidate)));
                (candidate, None)
            }
        };
        if let Some(unused) = unused {
            unused.close().await;
        }
        Ok(pool)
    }

    async fn admit_query(&self) -> anyhow::Result<AdmissionPermit<'_>> {
        let admission = self
            .admission
            .admit()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream pool is closed"))?;
        #[cfg(test)]
        self.pause_after_admission_for_test().await;
        Ok(admission)
    }

    async fn exchange_direct_udp<'a>(
        &'a self,
        entry: &UpstreamEntry,
        address: SocketAddr,
        raw_query: &[u8],
    ) -> anyhow::Result<(Vec<u8>, AdmissionPermit<'a>)> {
        let admission = self.admit_query().await?;
        let response = self
            .udp_pool(entry, address)
            .await?
            .exchange(raw_query)
            .await?;
        entry.udp.lock().mark_current(address);
        Ok((response, admission))
    }

    pub(super) async fn resolve_udp_addrs(
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        entry.endpoint.resolve_addrs().await
    }

    pub(super) async fn resolve_udp_addr(entry: &UpstreamEntry) -> anyhow::Result<SocketAddr> {
        Self::resolve_udp_addrs(entry)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))
    }

    async fn query_udp_via_proxy(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        node: &honk_config::node::Node,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let _admission = self.admit_query().await?;
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
        Ok(response)
    }

    async fn finish_direct_udp_query(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        raw_query: &[u8],
        response: Vec<u8>,
        _admission: AdmissionPermit<'_>,
    ) -> anyhow::Result<Vec<u8>> {
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

    async fn query_datagram(
        &self,
        upstream_name: &str,
        entry: &UpstreamEntry,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let forced_route = entry.outbound.is_some();
        if forced_route {
            let proxy_node = self.resolve_dial_leaf(entry).await?;
            debug!(
                "DNS upstream '{}' dial leaf={:?} (forced=true)",
                upstream_name,
                proxy_node.as_ref().map(|node| node.name.as_str())
            );
            if let Some(node) = proxy_node.as_ref() {
                return self
                    .query_udp_via_proxy(upstream_name, entry, node, raw_query)
                    .await;
            }
        }

        let current = { entry.udp.lock().current_pool() };
        let failed = if let Some((address, pool)) = current {
            if !forced_route
                && let Some(node) = self.resolve_dial_leaf_for_address(entry, address).await?
            {
                return self
                    .query_udp_via_proxy(upstream_name, entry, &node, raw_query)
                    .await;
            }
            let admission = self.admit_query().await?;
            match pool.exchange(raw_query).await {
                Ok(response) => {
                    entry.udp.lock().mark_current(address);
                    return self
                        .finish_direct_udp_query(
                            upstream_name,
                            entry,
                            raw_query,
                            response,
                            admission,
                        )
                        .await;
                }
                Err(error) => {
                    drop(admission);
                    Some((address, error))
                }
            }
        } else {
            None
        };

        let addresses = Self::resolve_udp_addrs(entry).await?;
        let (first, first_error, retry) = if let Some((failed_address, first_error)) = failed {
            let [first, retry] = udp_attempt_addresses(&addresses, Some(failed_address))
                .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
            let retry = if first == failed_address {
                retry
            } else {
                first
            };
            (failed_address, first_error, retry)
        } else {
            let [first, retry] = udp_attempt_addresses(&addresses, None)
                .ok_or_else(|| anyhow::anyhow!("DNS upstream resolved to no addresses"))?;
            if !forced_route
                && let Some(node) = self.resolve_dial_leaf_for_address(entry, first).await?
            {
                return self
                    .query_udp_via_proxy(upstream_name, entry, &node, raw_query)
                    .await;
            }
            match self.exchange_direct_udp(entry, first, raw_query).await {
                Ok((response, admission)) => {
                    return self
                        .finish_direct_udp_query(
                            upstream_name,
                            entry,
                            raw_query,
                            response,
                            admission,
                        )
                        .await;
                }
                Err(first_error) => (first, first_error, retry),
            }
        };

        debug!(
            address = %first,
            retry_address = %retry,
            error_kind = "exchange_failed",
            "UDP DNS query candidate failed; retrying"
        );
        if !forced_route
            && retry != first
            && let Some(node) = self.resolve_dial_leaf_for_address(entry, retry).await?
        {
            return self
                .query_udp_via_proxy(upstream_name, entry, &node, raw_query)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "UDP DNS failed via {retry}: {error} (first {first}: {first_error})"
                    )
                });
        }
        match self.exchange_direct_udp(entry, retry, raw_query).await {
            Ok((response, admission)) => {
                self.finish_direct_udp_query(upstream_name, entry, raw_query, response, admission)
                    .await
            }
            Err(error) => Err(anyhow::anyhow!(
                "UDP DNS failed via {retry}: {error} (first {first}: {first_error})"
            )),
        }
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
        if entry.protocol == DnsProtocol::Udp {
            return self.query_datagram(upstream_name, entry, raw_query).await;
        }
        let proxy_node = self
            .resolve_dial_leaf(entry)
            .await
            .map_err(|error| anyhow::anyhow!("DNS upstream '{upstream_name}': {error}"))?;
        let _admission = self.admit_query().await?;
        debug!(
            "DNS upstream '{}' dial leaf={:?} (forced={})",
            upstream_name,
            proxy_node.as_ref().map(|node| node.name.as_str()),
            entry.outbound.is_some()
        );
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
