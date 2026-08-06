//! Registry-based outbound dispatch: a static protocol descriptor plus
//! per-capability trait objects (`TcpOutbound`, `PacketOutbound`,
//! `WarmableOutbound`, `ProbeableOutbound`).

pub(crate) mod addr;
pub mod anytls;
pub mod block;
pub mod direct;
pub mod hysteria2;
pub mod juicity;
pub mod shadowsocks;
pub(crate) mod shadowsocks_2022;
pub mod socks5;
pub(crate) mod ss_stream;
pub(crate) mod transport;
pub mod trojan;
pub mod tuic;
#[cfg(feature = "rprx")]
pub mod vless;
#[cfg(feature = "rprx")]
pub mod vmess;

use anytls::AnyTlsHandler;
use async_trait::async_trait;
use block::BlockHandler;
use direct::DirectHandler;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use hysteria2::Hysteria2Handler;
use juicity::JuicityHandler;
use shadowsocks::ShadowsocksHandler;
use socks5::Socks5Handler;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use trojan::TrojanHandler;
use tuic::TuicHandler;
#[cfg(feature = "rprx")]
use vless::VLessHandler;
#[cfg(feature = "rprx")]
use vmess::VmessHandler;

/// Trait object-compatible combination of async I/O traits used for proxy streams.
///
/// This allows a `ProxyStream` to hold either a plain `TcpStream` or a
/// TLS-wrapped stream (e.g. `tokio_boring::SslStream<TcpStream>`)
/// without exposing the concrete type to downstream relay code.
///
/// The `as_any`/`into_any` accessors let the relay layer downcast back to a
/// concrete `TcpStream` so direct (unwrapped) connections can use the
/// zero-copy `splice(2)` datapath.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin + Debug {
    /// Borrow this stream as `Any` for type checks.
    fn as_any(&self) -> &dyn std::any::Any;
    /// Consume this boxed stream as `Any` for owned downcasts.
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

impl<T> AsyncReadWrite for T
where
    T: AsyncRead + AsyncWrite + Send + Unpin + Debug + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[derive(Debug)]
pub struct ProxyStream {
    /// Boxed so it can hold either a plain TCP or TLS-wrapped stream.
    pub stream: Box<dyn AsyncReadWrite>,
    pub target_addr: SocketAddr,
    /// Domain-based routing support.
    pub target_domain: Option<String>,
}

impl ProxyStream {
    /// If the dialled stream is a plain `TcpStream` (direct/bypass
    /// connections), return it as an owned socket so the relay can use the
    /// zero-copy `splice(2)` path. Returns `self` unchanged for wrapped
    /// (TLS/protocol) streams.
    pub fn into_tcp_stream(self) -> Result<tokio::net::TcpStream, Self> {
        // NOTE: `(*stream).as_any()` dispatches through the trait
        // object's vtable. `self.stream.as_any()` would instead resolve to
        // the blanket `impl<T> AsyncReadWrite for T` with T = `Box<dyn
        // AsyncReadWrite>` (tokio implements AsyncRead/AsyncWrite for
        // Box<T>, so the Box itself satisfies the blanket bound), and the
        // returned `Any` would wrap the Box — every downcast would fail.
        if !(*self.stream).as_any().is::<tokio::net::TcpStream>() {
            return Err(self);
        }
        let Self { stream, .. } = self;
        match stream.into_any().downcast::<tokio::net::TcpStream>() {
            Ok(stream) => Ok(*stream),
            // The type was checked immediately above.
            Err(_) => unreachable!("AsyncReadWrite type changed between checks"),
        }
    }

    /// Raw file descriptor of the underlying TCP socket, if reachable.
    ///
    /// Used by the connection pool's `MSG_PEEK` liveness probe for pooled
    /// ready streams. Returns `None` when no socket is directly reachable
    /// (e.g. a WebSocket duplex bridge); callers must treat `None` as
    /// "cannot probe" and decide conservatively.
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        // Vtable dispatch required — see into_tcp_stream.
        let any = (*self.stream).as_any();
        if let Some(tcp) = any.downcast_ref::<tokio::net::TcpStream>() {
            return Some(tcp.as_raw_fd());
        }
        if let Some(tls) = any.downcast_ref::<tokio_boring::SslStream<tokio::net::TcpStream>>() {
            return Some(tls.get_ref().as_raw_fd());
        }
        None
    }
}

/// Framed UDP packet transport — the production UDP contract. Native UDP
/// protocols wrap a real `UdpSocket`; tunnel protocols implement their
/// framing directly on the tunnel instead of bouncing datagrams through a
/// loopback socket pair (extra FD + bridge task + 1–2 copies per packet).
#[async_trait]
pub trait PacketTransport: Send + Sync + Debug {
    /// The relay target a flow reports as its destination.
    fn relay_addr(&self) -> SocketAddr;
    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()>;
    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

/// A prepared UDP transport that is usable only after its final side effects
/// have been committed. Dropping it without [`Self::commit`] abandons the
/// preparation; protocol-specific resources then clean themselves up via
/// normal RAII. Commit failure drops the transport and returns no value.
pub struct PreparedUdpTransport {
    transport: Option<Arc<dyn PacketTransport>>,
    commit: Option<Box<dyn FnOnce() -> anyhow::Result<()> + Send>>,
}

impl std::fmt::Debug for PreparedUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUdpTransport")
            .field("prepared", &self.transport.is_some())
            .finish_non_exhaustive()
    }
}

impl PreparedUdpTransport {
    pub fn new<F>(transport: Arc<dyn PacketTransport>, commit: F) -> Self
    where
        F: FnOnce() -> anyhow::Result<()> + Send + 'static,
    {
        Self {
            transport: Some(transport),
            commit: Some(Box::new(commit)),
        }
    }

    /// Wrap an already-authoritative ordinary transport. This deliberately
    /// preserves `dial_udp_transport` semantics for protocols with no
    /// speculative ownership to promote.
    pub fn ready(transport: Arc<dyn PacketTransport>) -> Self {
        Self::new(transport, || Ok(()))
    }

    /// Consume the preparation, run its one-shot promotion, then expose the
    /// transport. A failed promotion is fail-closed: the transport is dropped
    /// and cannot be sent on by a caller.
    pub fn commit(mut self) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let transport = self
            .transport
            .take()
            .ok_or_else(|| anyhow::anyhow!("UDP transport preparation already consumed"))?;
        let commit = self
            .commit
            .take()
            .ok_or_else(|| anyhow::anyhow!("UDP transport commit already consumed"))?;
        if let Err(error) = commit() {
            drop(transport);
            return Err(error);
        }
        Ok(transport)
    }
}

/// Adapter presenting a raw `UdpSocket` (e.g. the direct handler's
/// bypass-marked socket) as a [`PacketTransport`].
#[derive(Debug)]
pub struct UdpSocketTransport {
    socket: Arc<tokio::net::UdpSocket>,
    relay_addr: SocketAddr,
}

impl UdpSocketTransport {
    pub fn new(socket: Arc<tokio::net::UdpSocket>, relay_addr: SocketAddr) -> Self {
        Self { socket, relay_addr }
    }
}

#[async_trait]
impl PacketTransport for UdpSocketTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }
    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(data, self.relay_addr).await?;
        Ok(())
    }
    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

/// Outcome of an additive UDP session warm-up request. A status is not a
/// protocol capability claim: only handlers that own a reusable UDP-capable
/// session return `Ready` or `AlreadyReady`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpWarmStatus {
    Ready,
    AlreadyReady,
    NotApplicable,
}

/// TCP flow dialing. Every protocol implements this.
#[async_trait]
pub trait TcpOutbound: Send + Sync {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

    /// The provided `tcp` stream is already connected to the proxy
    /// server. Handlers that support connection pooling override this to
    /// skip `TcpStream::connect()`; the default ignores `tcp` and delegates
    /// to [`Self::dial`].
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let _ = tcp;
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through an explicitly captured runtime generation. Stateless
    /// handlers delegate to [`Self::dial`]; session-owning handlers override
    /// this to avoid consulting the mutable current-generation registry.
    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        self.dial(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }
}

/// Framed UDP transports — only protocols with UDP capability (see
/// [`crate::descriptor::ProtocolDescriptor::capabilities`]).
#[async_trait]
pub trait PacketOutbound: Send + Sync {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>>;

    /// Open a framed UDP transport using an explicitly captured runtime
    /// generation. Session-owning handlers override this so an authoritative
    /// flow reuses the same warmed generation-local client.
    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        self.dial_udp_transport(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    /// Prepare a UDP transport for a Cold URLTest candidate. Protocols that
    /// do not need speculative ownership can use their ordinary transport;
    /// session protocols override this to defer pool publication until the
    /// caller has selected and committed a winner.
    async fn dial_udp_transport_speculative(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
            .map(PreparedUdpTransport::ready)
    }

    /// Generation-pinned speculative preparation. The default delegates to
    /// the node-based method; session-owning handlers override this so every
    /// provisional resource stays attached to the captured runtime generation.
    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        self.dial_udp_transport_speculative(
            runtime.node.as_ref(),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }
}

/// Warming of generation-owned reusable UDP session resources. Transport
/// support alone does not imply a warmable session; only session-owning
/// protocols (AnyTLS, the QUIC tunnels) implement this.
#[async_trait]
pub trait WarmableOutbound: Send + Sync {
    async fn warm_udp(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpWarmStatus>;
}

/// Raw server reachability checks.
#[async_trait]
pub trait ProbeableOutbound: Send + Sync {
    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_stream) => true,
            Err(e) => {
                tracing::debug!(
                    "{} connectivity test failed for {}: {}",
                    node.protocol.as_str(),
                    node.name,
                    e
                );
                false
            }
        }
    }
}

/// One registered protocol: its descriptor plus the capability objects it
/// implements. A `None` slot means the protocol lacks that capability;
/// dispatches into it are refused.
pub struct ProtocolEntry {
    pub descriptor: &'static crate::descriptor::ProtocolDescriptor,
    pub tcp: Arc<dyn TcpOutbound>,
    pub packet: Option<Arc<dyn PacketOutbound>>,
    pub warmable: Option<Arc<dyn WarmableOutbound>>,
    pub probeable: Option<Arc<dyn ProbeableOutbound>>,
    /// Declared reason a packet slot may exist despite the descriptor
    /// reporting `udp: false` for a default node (Block: the slot answers
    /// blocked UDP flows with the routing refusal). `None` enforces
    /// slot/table parity in [`Self::validate_consistency`].
    packet_udp_exemption: Option<&'static str>,
}

impl ProtocolEntry {
    pub fn new<T: TcpOutbound + 'static>(protocol: NodeProtocol, handler: Arc<T>) -> Self {
        Self {
            descriptor: crate::descriptor::descriptor(protocol),
            tcp: handler,
            packet: None,
            warmable: None,
            probeable: None,
            packet_udp_exemption: None,
        }
    }

    pub fn with_packet<T: PacketOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.packet = Some(handler);
        self
    }

    pub fn with_packet_udp_exemption(mut self, reason: &'static str) -> Self {
        self.packet_udp_exemption = Some(reason);
        self
    }

    pub fn with_warmable<T: WarmableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.warmable = Some(handler);
        self
    }

    pub fn with_probeable<T: ProbeableOutbound + 'static>(mut self, handler: Arc<T>) -> Self {
        self.probeable = Some(handler);
        self
    }

    /// Cross-check the capability slots against the descriptor table. The
    /// table drives selection and warm-candidate decisions; a slot that
    /// disagrees with it silently misroutes work, so registry assembly
    /// panics on inconsistency rather than starting up half-truthful.
    fn validate_consistency(&self) {
        let protocol = self.descriptor.protocol;
        let default_node = Node {
            protocol,
            ..Default::default()
        };
        let udp_capable = (self.descriptor.capabilities)(&default_node).udp;
        if self.packet.is_some() != udp_capable && self.packet_udp_exemption.is_none() {
            panic!(
                "protocol {}: packet slot (present={}) disagrees with descriptor udp={}; \
                 declare with_packet_udp_exemption if intentional",
                protocol.as_str(),
                self.packet.is_some(),
                udp_capable
            );
        }
        if self.warmable.is_some() != self.descriptor.has_generation_runtime() {
            panic!(
                "protocol {}: warmable slot (present={}) disagrees with generation runtime {:?}",
                protocol.as_str(),
                self.warmable.is_some(),
                self.descriptor.generation_runtime
            );
        }
    }
}

pub struct ProxyRegistry {
    entries: Vec<ProtocolEntry>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();

        let socks5 = Arc::new(Socks5Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Socks5, socks5.clone())
                .with_packet(socks5.clone())
                .with_probeable(socks5),
        );
        let direct = Arc::new(DirectHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Direct, direct.clone())
                .with_packet(direct.clone())
                .with_probeable(direct),
        );
        let block = Arc::new(BlockHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Block, block.clone())
                .with_packet(block.clone())
                // Blocked UDP flows get the routing refusal from the handler;
                // the node itself is never UDP-selectable.
                .with_packet_udp_exemption("block answers with the routing refusal")
                .with_probeable(block),
        );
        let trojan = Arc::new(TrojanHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Trojan, trojan.clone())
                .with_packet(trojan.clone())
                .with_probeable(trojan),
        );
        let hysteria2 = Arc::new(Hysteria2Handler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Hysteria2, hysteria2.clone())
                .with_packet(hysteria2.clone())
                .with_warmable(hysteria2.clone())
                .with_probeable(hysteria2),
        );
        let shadowsocks = Arc::new(ShadowsocksHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::SS, shadowsocks.clone())
                .with_packet(shadowsocks.clone())
                .with_probeable(shadowsocks),
        );
        #[cfg(feature = "rprx")]
        {
            let vless = Arc::new(VLessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VLess, vless.clone()).with_probeable(vless),
            );
            let vmess = Arc::new(VmessHandler::new());
            registry.register(
                ProtocolEntry::new(NodeProtocol::VMess, vmess.clone()).with_probeable(vmess),
            );
        }
        let anytls = Arc::new(AnyTlsHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::AnyTLS, anytls.clone())
                .with_packet(anytls.clone())
                .with_warmable(anytls.clone())
                .with_probeable(anytls),
        );
        let tuic = Arc::new(TuicHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Tuic, tuic.clone())
                .with_packet(tuic.clone())
                .with_warmable(tuic.clone())
                .with_probeable(tuic),
        );
        let juicity = Arc::new(JuicityHandler::new());
        registry.register(
            ProtocolEntry::new(NodeProtocol::Juicity, juicity.clone())
                .with_packet(juicity.clone())
                .with_warmable(juicity.clone())
                .with_probeable(juicity),
        );
        for entry in &registry.entries {
            entry.validate_consistency();
        }
        Ok(registry)
    }

    pub fn register(&mut self, entry: ProtocolEntry) {
        self.entries.push(entry);
    }

    pub fn find(&self, protocol: NodeProtocol) -> Option<&ProtocolEntry> {
        self.entries
            .iter()
            .find(|entry| entry.descriptor.protocol == protocol)
    }

    pub async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let entry = self
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;

        tracing::debug!(
            "Dialing {}:{} via {} ({})",
            target,
            node.protocol.as_str(),
            node.name,
            node.host()
        );

        entry
            .tcp
            .dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through a generation-pinned node runtime. The generation's
    /// terminal flag is checked before and after the dial so a reload or
    /// shutdown racing the handshake fails closed instead of publishing a
    /// stream into a retired generation.
    pub async fn dial_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let entry = self.find(runtime.node.protocol).ok_or_else(|| {
            anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
        })?;
        let stream = entry
            .tcp
            .dial_runtime(runtime, target, target_domain, connect_timeout)
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during dial");
        }
        Ok(stream)
    }

    /// Warm a node using the explicitly supplied runtime generation. This
    /// deliberately never reads the mutable shared runtime-registry cell:
    /// reload-owned work must stay attached to its original generation.
    pub async fn warm_udp(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpWarmStatus> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let entry = self.find(runtime.node.protocol).ok_or_else(|| {
            anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
        })?;
        let Some(warmable) = entry.warmable.as_ref() else {
            return Ok(UdpWarmStatus::NotApplicable);
        };
        let status = warmable.warm_udp(runtime, connect_timeout).await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during warm-up");
        }
        Ok(status)
    }

    /// Framed UDP transport for a flow, dispatching to the node's packet
    /// capability (see [`PacketOutbound::dial_udp_transport`]).
    pub async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let entry = self
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!("UDP not supported for protocol {}", node.protocol.as_str())
        })?;
        packet
            .dial_udp_transport(node, target, target_domain, connect_timeout)
            .await
    }

    /// Generation-pinned framed UDP transport for an authoritative flow.
    /// This complements speculative preparation: both paths must retain the
    /// runtime captured when the flow was admitted, not re-resolve a handler
    /// cache after reload.
    pub async fn dial_udp_transport_runtime(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let (runtime, packet) = self.packet_runtime(&generation, node_id)?;
        let transport = packet
            .dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP dial");
        }
        Ok(transport)
    }

    /// Speculatively prepare a framed UDP transport for a Cold URLTest
    /// candidate. Ordinary dial behavior remains available through
    /// [`Self::dial_udp_transport`] for authoritative paths.
    pub async fn dial_udp_transport_speculative(
        &self,
        generation: Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let (runtime, packet) = self.packet_runtime(&generation, node_id)?;
        let prepared = packet
            .dial_udp_transport_speculative_runtime(runtime, target, target_domain, connect_timeout)
            .await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP preparation");
        }
        Ok(prepared)
    }

    fn packet_runtime(
        &self,
        generation: &Arc<crate::runtime::OutboundRuntimeRegistry>,
        node_id: uuid::Uuid,
    ) -> anyhow::Result<(Arc<crate::runtime::NodeRuntime>, &Arc<dyn PacketOutbound>)> {
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let entry = self.find(runtime.node.protocol).ok_or_else(|| {
            anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
        })?;
        let packet = entry.packet.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "UDP not supported for protocol {}",
                runtime.node.protocol.as_str()
            )
        })?;
        Ok((runtime, packet))
    }

    pub fn handler_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_default_handlers() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        assert!(registry.handler_count() >= 4);
        assert!(registry.find(NodeProtocol::Socks5).is_some());
        assert!(registry.find(NodeProtocol::Direct).is_some());
        assert!(registry.find(NodeProtocol::Block).is_some());
        assert!(registry.find(NodeProtocol::Trojan).is_some());
        assert!(registry.find(NodeProtocol::SS).is_some());
        assert!(registry.find(NodeProtocol::AnyTLS).is_some());
        assert!(registry.find(NodeProtocol::Hysteria2).is_some());
        #[cfg(feature = "rprx")]
        assert!(registry.find(NodeProtocol::VMess).is_some());
        assert!(registry.find(NodeProtocol::Tuic).is_some());
        assert!(registry.find(NodeProtocol::Juicity).is_some());
    }

    /// Without the `rprx` feature a parsed VLESS/VMess node must hit the
    /// ordinary no-handler refusal, never a panic.
    #[cfg(not(feature = "rprx"))]
    #[tokio::test]
    async fn rprx_off_refuses_vless_vmess_without_handler() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        for protocol in [NodeProtocol::VLess, NodeProtocol::VMess] {
            assert!(registry.find(protocol).is_none());
            let node = Node {
                protocol,
                ..Default::default()
            };
            let err = registry
                .dial(
                    &node,
                    "93.184.216.34:443".parse().unwrap(),
                    None,
                    Duration::from_secs(1),
                )
                .await
                .expect_err("no handler registered without rprx");
            assert!(err.to_string().contains("No handler for protocol"));
        }
    }

    #[test]
    #[should_panic(expected = "packet slot")]
    fn consistency_rejects_undeclared_packet_without_udp_capability() {
        let block = Arc::new(BlockHandler::new());
        ProtocolEntry::new(NodeProtocol::VMess, block.clone())
            .with_packet(block)
            .validate_consistency();
    }

    #[test]
    #[should_panic(expected = "warmable slot")]
    fn consistency_rejects_warmable_without_generation_runtime() {
        let socks5 = Arc::new(Socks5Handler::new());
        let anytls = Arc::new(AnyTlsHandler::new());
        ProtocolEntry::new(NodeProtocol::Socks5, socks5.clone())
            .with_packet(socks5)
            .with_warmable(anytls)
            .validate_consistency();
    }

    /// The built-in block node carries NodeProtocol::Block; the registry must
    /// dispatch it to BlockHandler (regression: block rules silently dialed
    /// direct when block shared direct's protocol marker).
    #[tokio::test]
    async fn test_block_node_dispatches_to_block_handler() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "block".into(),
            protocol: NodeProtocol::Block,
            ..Default::default()
        };
        let target: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let err = registry
            .dial(&node, target, None, Duration::from_secs(1))
            .await
            .expect_err("block node must not dial");
        assert!(err.to_string().contains("blocked"));
        let err = registry
            .dial_udp_transport(&node, target, None, Duration::from_secs(1))
            .await
            .expect_err("block node must not dial UDP");
        assert!(err.to_string().contains("blocked"));
    }

    /// Regression test for the `Box<dyn AsyncReadWrite>` method-resolution
    /// trap: `as_any`/`into_any` must see the inner stream, not the Box.
    #[tokio::test]
    async fn test_into_tcp_stream_plain_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ps = ProxyStream {
            stream: Box::new(tcp),
            target_addr: addr,
            target_domain: None,
        };
        assert!(
            ps.into_tcp_stream().is_ok(),
            "plain TcpStream must downcast"
        );
    }

    #[tokio::test]
    async fn test_raw_fd_plain_tcp() {
        use std::os::unix::io::AsRawFd;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let expected = tcp.as_raw_fd();
        let ps = ProxyStream {
            stream: Box::new(tcp),
            target_addr: addr,
            target_domain: None,
        };
        assert_eq!(ps.raw_fd(), Some(expected));
    }

    #[tokio::test]
    async fn test_raw_fd_none_for_non_tcp() {
        // A stream without a reachable socket (duplex bridge, as used by
        // the WebSocket transport) must report "cannot probe".
        let (client, _server) = tokio::io::duplex(64);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ps = ProxyStream {
            stream: Box::new(client),
            target_addr: addr,
            target_domain: None,
        };
        assert_eq!(ps.raw_fd(), None);
    }

    #[tokio::test]
    async fn warm_udp_is_not_applicable_for_handlers_without_reusable_sessions() {
        let mut nodes = Vec::new();
        for (name, protocol) in [
            ("direct", NodeProtocol::Direct),
            ("socks", NodeProtocol::Socks5),
            ("ss", NodeProtocol::SS),
            ("trojan", NodeProtocol::Trojan),
        ] {
            nodes.push(Node {
                id: uuid::Uuid::new_v4(),
                name: name.into(),
                protocol,
                ..Default::default()
            });
        }
        let generation = Arc::new(crate::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
        let registry = ProxyRegistry::default_resolver().unwrap();

        for node in &nodes {
            assert_eq!(
                registry
                    .warm_udp(Arc::clone(&generation), node.id, Duration::from_secs(1))
                    .await
                    .unwrap(),
                UdpWarmStatus::NotApplicable,
                "{} must not masquerade as a warmable UDP session",
                node.name
            );
        }
    }

    #[tokio::test]
    async fn warm_udp_rejects_a_shutdown_generation_before_dispatch() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "old-anytls".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown().await;

        assert!(
            ProxyRegistry::default_resolver()
                .unwrap()
                .warm_udp(generation, node.id, Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn speculative_udp_rejects_a_shutdown_generation_before_dispatch() {
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "direct".into(),
            protocol: NodeProtocol::Direct,
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown().await;

        assert!(
            ProxyRegistry::default_resolver()
                .unwrap()
                .dial_udp_transport_speculative(
                    generation,
                    node.id,
                    "127.0.0.1:53".parse().unwrap(),
                    None,
                    Duration::from_secs(1),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn prepared_udp_transport_defers_transport_exposure_until_commit() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_addr = socket.local_addr().unwrap();
        let transport: Arc<dyn PacketTransport> =
            Arc::new(UdpSocketTransport::new(Arc::clone(&socket), relay_addr));
        let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let prepared = PreparedUdpTransport::new(Arc::clone(&transport), {
            let commits = Arc::clone(&commits);
            move || {
                commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
        });
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);

        let committed = prepared.commit().unwrap();

        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(&transport, &committed));
    }
}
