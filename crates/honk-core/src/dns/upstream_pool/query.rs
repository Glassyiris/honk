use std::net::SocketAddr;
use std::sync::Arc;

use honk_config::types::DnsProtocol;
#[cfg(feature = "honk-policy")]
use honk_outbound::group::{HonkFeedback, HonkOutcome, HonkReporter};
use tracing::debug;

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use super::routing::DnsDialRoute;
use crate::dns::forwarder::DnsUpstreamPool;
#[cfg(feature = "honk-policy")]
use crate::dns::query::QueryContext;
#[cfg(feature = "honk-policy")]
use crate::dns::response::ResponseTemplate;

impl UpstreamPool {
    #[cfg(feature = "honk-policy")]
    async fn udp_attempt(
        pool: &crate::dns::transport::UdpPool,
        raw_query: &[u8],
        feedback: Option<&HonkFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        let reporter = feedback.map(HonkFeedback::start);
        let result = pool.exchange(raw_query, reporter.as_ref()).await;
        Self::finish_reporter(reporter.as_ref(), raw_query, &result);
        result
    }

    #[cfg(not(feature = "honk-policy"))]
    async fn udp_attempt(
        pool: &crate::dns::transport::UdpPool,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        pool.exchange(raw_query).await
    }

    #[cfg(feature = "honk-policy")]
    fn finish_reporter(
        reporter: Option<&HonkReporter>,
        raw_query: &[u8],
        result: &anyhow::Result<Vec<u8>>,
    ) {
        let Some(reporter) = reporter else {
            return;
        };
        match result {
            Ok(response) => {
                let valid = QueryContext::parse(raw_query).is_ok_and(|query| {
                    ResponseTemplate::check(&query, response).is_ok()
                        && response.get(2).is_none_or(|flags| flags & 0x02 == 0)
                });
                if valid {
                    reporter.first_response();
                    reporter.rx(response.len() as u64);
                    reporter.finish(HonkOutcome::Success);
                } else {
                    reporter.finish(HonkOutcome::Other);
                }
            }
            Err(error) => reporter.finish(HonkOutcome::from_error(error)),
        }
    }

    async fn query_udp(
        &self,
        entry: &UpstreamEntry,
        address: SocketAddr,
        raw_query: &[u8],
        #[cfg(feature = "honk-policy")] feedback: Option<&HonkFeedback>,
    ) -> anyhow::Result<Vec<u8>> {
        let pool = if let Some(pool) = entry.udp.lock().get(&address) {
            Arc::clone(pool)
        } else {
            let candidate = crate::dns::transport::UdpPool::new_tracked(
                address,
                self.dns_query_timeout,
                Arc::clone(&self.active_transport_tasks),
            )
            .await?;
            let (pool, unused) = {
                let mut pools = entry.udp.lock();
                if let Some(pool) = pools.get(&address) {
                    (Arc::clone(pool), Some(candidate))
                } else {
                    pools.insert(address, Arc::clone(&candidate));
                    (candidate, None)
                }
            };
            if let Some(unused) = unused {
                unused.close().await;
            }
            pool
        };
        match Self::udp_attempt(
            &pool,
            raw_query,
            #[cfg(feature = "honk-policy")]
            feedback,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(error) => {
                debug!("UDP DNS query first attempt: {error}; retrying");
                Self::udp_attempt(
                    &pool,
                    raw_query,
                    #[cfg(feature = "honk-policy")]
                    feedback,
                )
                .await
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
        route: &DnsDialRoute,
        raw_query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(node) = route.node.as_ref() {
            let response = self
                .get_transport(entry, Some(node), route.target)
                .await?
                .exchange(
                    raw_query,
                    #[cfg(feature = "honk-policy")]
                    route.feedback.as_ref(),
                )
                .await?;
            if response.len() >= 4 && response[2] & 0x02 != 0 {
                #[cfg(feature = "honk-policy")]
                let tcp_feedback = self.tcp_feedback_for_route(entry, route);
                debug!(
                    "DNS upstream '{}' proxied UDP answer has TC set — retrying over proxied TCP",
                    upstream_name
                );
                return self
                    .get_transport(entry, Some(node), route.target)
                    .await?
                    .exchange(
                        raw_query,
                        #[cfg(feature = "honk-policy")]
                        tcp_feedback.as_ref(),
                    )
                    .await;
            }
            debug!(
                "DNS upstream '{}' (udp via proxy {}) returned {} bytes",
                upstream_name,
                node.name,
                response.len()
            );
            return Ok(response);
        }

        let response = self
            .query_udp(
                entry,
                route.target,
                raw_query,
                #[cfg(feature = "honk-policy")]
                route.feedback.as_ref(),
            )
            .await?;
        if response.len() >= 4 && response[2] & 0x02 != 0 {
            debug!(
                "DNS upstream '{}' UDP answer has TC set — retrying over TCP",
                upstream_name
            );
            return self
                .get_transport(entry, None, route.target)
                .await?
                .exchange(
                    raw_query,
                    #[cfg(feature = "honk-policy")]
                    None,
                )
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
        let route = self
            .resolve_dial_route(entry)
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
            route.node.as_ref().map(|node| node.name.as_str()),
            entry.outbound.is_some()
        );

        if entry.protocol == DnsProtocol::Udp {
            return self
                .query_datagram(upstream_name, entry, &route, raw_query)
                .await;
        }
        if matches!(entry.protocol, DnsProtocol::Quic | DnsProtocol::H3) && route.node.is_some() {
            anyhow::bail!(
                "DNS upstream '{}' protocol {:?} does not support outbound proxy yet",
                upstream_name,
                entry.protocol
            );
        }
        let response = self
            .get_transport(entry, route.node.as_ref(), route.target)
            .await?
            .exchange(
                raw_query,
                #[cfg(feature = "honk-policy")]
                route.feedback.as_ref(),
            )
            .await?;
        debug!(
            "DNS upstream '{}' ({:?} {} via {:?}) returned {} bytes",
            upstream_name,
            entry.protocol,
            entry.endpoint.host,
            route
                .node
                .as_ref()
                .map(|node| node.name.as_str())
                .unwrap_or("direct"),
            response.len()
        );
        Ok(response)
    }
}
