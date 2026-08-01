use std::collections::HashMap;
use std::sync::Arc;

use honk_config::dns::DnsUpstream;

use super::transports::{PooledTransport, TransportKey};
use crate::dns::endpoint::DnsEndpoint;
use crate::dns::transport::{LifecycleSlot, UdpPool};

pub(super) struct UpstreamEntry {
    pub(super) protocol: honk_config::types::DnsProtocol,
    pub(super) endpoint: DnsEndpoint,
    pub(super) address: String,
    pub(super) outbound: Option<String>,
    pub(super) transports:
        parking_lot::Mutex<HashMap<TransportKey, Arc<LifecycleSlot<PooledTransport>>>>,
    pub(super) udp: parking_lot::Mutex<Option<Arc<UdpPool>>>,
}

pub(super) fn build_entries(
    upstreams: &[DnsUpstream],
    bootstrap_resolver: Option<honk_outbound::bootstrap::BootstrapResolver>,
) -> anyhow::Result<HashMap<String, UpstreamEntry>> {
    let mut entries = HashMap::new();
    for upstream in upstreams {
        let endpoint = DnsEndpoint::parse_with_resolver(
            &upstream.address,
            upstream.protocol,
            upstream.tls_server_name.as_deref(),
            bootstrap_resolver,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "invalid upstream '{}' address '{}': {error}",
                upstream.name,
                upstream.address
            )
        })?;
        entries.insert(
            upstream.name.clone(),
            UpstreamEntry {
                protocol: upstream.protocol,
                endpoint,
                address: upstream.address.clone(),
                outbound: upstream.outbound.clone(),
                transports: parking_lot::Mutex::new(HashMap::new()),
                udp: parking_lot::Mutex::new(None),
            },
        );
    }
    Ok(entries)
}
