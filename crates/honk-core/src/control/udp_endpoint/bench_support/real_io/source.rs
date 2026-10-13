//! VLESS XUDP source constructor: one carrier per client, one endpoint and
//! driver per destination, exactly the production `prepare_source` ->
//! `new_source_scored` -> driver sequence.

use super::IoHarness;
use crate::control::udp_endpoint::{SourcePath, UdpEndpoint};
use honk_config::node::{Node, OutboundConfig, VlessConfig, VlessUdpEncoding, VlessUdpPath};
use honk_outbound::alive::IpVersion;
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub(super) struct SourceRuntime {
    node: Node,
    generation: Arc<OutboundRuntimeRegistry>,
    runtime: Arc<NodeRuntime>,
}

impl SourceRuntime {
    fn new(server: SocketAddr) -> io::Result<Self> {
        let mut node = Node {
            name: "udp-io-bench-vless".into(),
            address: server.to_string(),
            host: server.ip().to_string(),
            port: server.port(),
            outbound: OutboundConfig::Vless(VlessConfig {
                uuid: Some("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3".into()),
                udp_encoding: VlessUdpEncoding::Xudp,
                ..Default::default()
            }),
            ..Default::default()
        };
        node.id = node.derive_id();
        let generation = Arc::new(
            OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                std::slice::from_ref(&node),
                8,
                8,
                8,
                false,
                None,
            )
            .map_err(io::Error::other)?
            .0,
        );
        let runtime = generation
            .get(&node.id)
            .ok_or_else(|| io::Error::other("node runtime missing"))?;
        Ok(Self {
            node,
            generation,
            runtime,
        })
    }
}

impl IoHarness {
    /// Adds one destination to the client's shared VLESS XUDP source against
    /// the wire peer at `server`. The first call creates the carrier; later
    /// calls (same `server`) attach to it. The first datagram is echoed and
    /// drained before returning.
    pub async fn install_vless_xudp_source(
        &mut self,
        destination: usize,
        server: SocketAddr,
    ) -> io::Result<()> {
        if self.source.is_none() {
            self.source = Some(SourceRuntime::new(server)?);
        }
        let source = self.source.as_ref().expect("source runtime just created");
        let target = self.targets[destination];
        let lease = self.reserve(target, source.node.id)?;
        let attachment = self
            .pool
            .prepare_source(
                Arc::clone(&source.generation),
                Arc::clone(&source.runtime),
                self.client_addr,
                SourcePath::Vless(VlessUdpPath::Xudp),
                None,
                target,
                None,
                Duration::from_secs(2),
                Arc::clone(&self.alive),
                Arc::clone(&self.stats),
                IpVersion::V4,
                false,
            )
            .await
            .map_err(io::Error::other)?
            .commit(&self.pool)
            .await
            .map_err(io::Error::other)?;
        let reply = Arc::new(self.pool.create_reply_socket(target)?);
        let endpoint = Arc::new(UdpEndpoint::new_source_scored(
            attachment,
            target,
            None,
            reply,
            self.stats
                .outbound_tracker("udp-io-bench", crate::stats::OutboundKind::Node),
            source.node.id,
            IpVersion::V4,
            None,
        ));
        let reply = Arc::clone(endpoint.source_reply_socket());
        self.start(lease, endpoint, target, reply).await
    }
}
