//! Registry-based proxy handler dispatch.

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
pub mod vless;
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
use vless::VLessHandler;
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

#[derive(Debug)]
pub struct UdpProxySocket {
    pub socket: Arc<tokio::net::UdpSocket>,
    pub relay_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub target_domain: Option<String>,
    /// TCP control connection (must be kept alive for SOCKS5 UDP ASSOCIATE).
    pub _control: Option<tokio::net::TcpStream>,
}

/// Framed UDP packet transport — the long-term replacement for per-flow
/// loopback bridges. Native UDP protocols wrap a real `UdpSocket`; tunnel
/// protocols implement their framing directly on the tunnel instead of
/// bouncing datagrams through a loopback socket pair (extra FD + bridge
/// task + 1–2 copies per packet).
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

/// Adapter presenting any `UdpSocket` — a direct target, a socks5
/// server-assigned relay, or a legacy loopback bridge — as a
/// [`PacketTransport`]. Lets tunnel protocols migrate to framed transports
/// incrementally instead of one flag-day rewrite.
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

#[async_trait]
pub trait ProxyHandler: Send + Sync {
    fn protocol(&self) -> NodeProtocol;

    /// Warm this generation's node-owned UDP session resources. The default
    /// is intentionally honest: transport support does not imply that a
    /// protocol has a reusable warm session.
    async fn warm_udp(
        &self,
        _runtime: Arc<crate::runtime::NodeRuntime>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<UdpWarmStatus> {
        Ok(UdpWarmStatus::NotApplicable)
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

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

    /// Default implementation returns an error indicating UDP is not supported.
    async fn dial_udp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        Err(anyhow::anyhow!("UDP not supported for this protocol"))
    }

    /// Framed UDP transport for a flow. The default wraps `dial_udp`'s socket
    /// (direct target, socks5 relay, or a legacy loopback bridge) in
    /// [`UdpSocketTransport`]; tunnel protocols override it with a real
    /// framed transport (no loopback).
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let proxy = self
            .dial_udp(node, target, target_domain, connect_timeout)
            .await?;
        Ok(Arc::new(UdpSocketTransport::new(
            proxy.socket,
            proxy.relay_addr,
        )))
    }
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

    /// Raw TCP reachability check against the node server. Handlers share
    /// this default; `direct`/`block` keep their own overrides.
    async fn test_connectivity(&self, node: &Node) -> bool {
        let addr = format!("{}:{}", node.host(), node.port);
        match crate::util::connect_outbound(&addr, std::time::Duration::from_secs(3)).await {
            Ok(_stream) => true,
            Err(e) => {
                tracing::debug!(
                    "{} connectivity test failed for {}: {}",
                    self.protocol().as_str(),
                    node.name,
                    e
                );
                false
            }
        }
    }

    /// The provided `tcp` stream is already connected to the proxy
    /// server.  Handlers that support connection pooling should
    /// override this to skip `TcpStream::connect()`.  The default
    /// implementation ignores `tcp` and delegates to [`dial`].
    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: tokio::net::TcpStream,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let _ = tcp; // default: ignore pooled connection
        self.dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Whether a fully-completed `dial()` for `node` yields a stream that
    /// may be pooled and later reused *directly* as the data channel,
    /// skipping both the TCP connect and the protocol handshake.
    ///
    /// Only handlers whose post-handshake stream is an unframed,
    /// target-bound byte channel (SOCKS5 after CONNECT, Trojan after the
    /// request header) should return `true`. The default is `false`:
    /// those handlers keep bare-TCP pooling via [`dial_with_tcp`].
    fn pool_ready_streams(&self, node: &Node) -> bool {
        let _ = node;
        false
    }

    /// Whether bare-TCP pool hits are useful for this node. Multiplexed
    /// protocols (AnyTLS) keep their own warm session pools; a pooled bare
    /// TCP forces a brand-new mux session per flow — worse than reusing the
    /// session pool, and sessions created over the pool cap leak. Return
    /// `false` for those; the dial then always goes through the session
    /// pool. The default is `true` (single-connection protocols where
    /// skipping the TCP handshake helps).
    fn pool_bare_tcp(&self, node: &Node) -> bool {
        let _ = node;
        true
    }

    /// Install the per-node runtime registry (session-layer ownership).
    /// Handlers with pooled sessions (AnyTLS) resolve their node's pool
    /// through it; the default is a no-op for stateless
    /// handlers. The shared cell swaps its contents on reload, so this is
    /// installed once at startup.
    fn set_runtime_registry(&self, cell: crate::runtime::SharedRuntimeRegistry) {
        let _ = cell;
    }
}

pub struct ProxyRegistry {
    handlers: Vec<Box<dyn ProxyHandler>>,
}

impl ProxyRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Hand the per-node runtime registry to every handler (see
    /// [`ProxyHandler::set_runtime_registry`]).
    pub fn install_runtime_registry(&self, cell: crate::runtime::SharedRuntimeRegistry) {
        for handler in &self.handlers {
            handler.set_runtime_registry(cell.clone());
        }
    }

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();
        registry.register(Box::new(Socks5Handler::new()));
        registry.register(Box::new(DirectHandler::new()));
        registry.register(Box::new(BlockHandler::new()));
        registry.register(Box::new(TrojanHandler::new()));
        registry.register(Box::new(Hysteria2Handler::new()));
        registry.register(Box::new(ShadowsocksHandler::new()));
        registry.register(Box::new(VLessHandler::new()));
        registry.register(Box::new(VmessHandler::new()));
        registry.register(Box::new(AnyTlsHandler::new()));
        registry.register(Box::new(TuicHandler::new()));
        registry.register(Box::new(JuicityHandler::new()));
        Ok(registry)
    }

    pub fn register(&mut self, handler: Box<dyn ProxyHandler>) {
        self.handlers.push(handler);
    }

    pub fn find(&self, protocol: NodeProtocol) -> Option<&dyn ProxyHandler> {
        self.handlers
            .iter()
            .find(|h| h.protocol() == protocol)
            .map(|h| h.as_ref())
    }

    pub async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        // The built-in direct/block nodes share NodeProtocol::HTTP, and
        // find() returns the first protocol match (DirectHandler) — dispatch
        // block by name so routed block traffic is actually rejected.
        if node.name == "block" {
            return BlockHandler::new()
                .dial(node, target, target_domain, connect_timeout)
                .await;
        }
        let handler = self
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;

        tracing::debug!(
            "Dialing {}:{} via {} ({})",
            target,
            node.protocol.as_str(),
            node.name,
            node.host()
        );

        handler
            .dial(node, target, target_domain, connect_timeout)
            .await
    }

    /// Dial through a generation-pinned node runtime. DNS runtime leases use
    /// this path so a reload cannot redirect an old snapshot into a new pool.
    pub async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        if runtime.node.name == "block" {
            return BlockHandler::new()
                .dial_runtime(runtime, target, target_domain, connect_timeout)
                .await;
        }
        let handler = self.find(runtime.node.protocol).ok_or_else(|| {
            anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
        })?;
        handler
            .dial_runtime(runtime, target, target_domain, connect_timeout)
            .await
    }

    pub async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        // See dial(): the block built-in must not fall through to
        // DirectHandler via the shared NodeProtocol::HTTP marker.
        if node.name == "block" {
            return BlockHandler::new()
                .dial_udp(node, target, target_domain, connect_timeout)
                .await;
        }
        let handler = self
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;

        tracing::debug!(
            "Dialing UDP {}:{} via {} ({})",
            target,
            node.protocol.as_str(),
            node.name,
            node.host()
        );

        handler
            .dial_udp(node, target, target_domain, connect_timeout)
            .await
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
        let handler = self.find(runtime.node.protocol).ok_or_else(|| {
            anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
        })?;
        let status = handler.warm_udp(runtime, connect_timeout).await?;
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during warm-up");
        }
        Ok(status)
    }

    /// Framed UDP transport for a flow, dispatching to the node's handler
    /// (see [`ProxyHandler::dial_udp_transport`]).
    pub async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        if node.name == "block" {
            return BlockHandler::new()
                .dial_udp_transport(node, target, target_domain, connect_timeout)
                .await;
        }
        let handler = self
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;
        handler
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
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let transport = if runtime.node.name == "block" {
            BlockHandler::new()
                .dial_udp_transport_runtime(
                    Arc::clone(&runtime),
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await?
        } else {
            let handler = self.find(runtime.node.protocol).ok_or_else(|| {
                anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
            })?;
            handler
                .dial_udp_transport_runtime(runtime, target, target_domain, connect_timeout)
                .await?
        };
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
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation is shut down");
        }
        let runtime = generation
            .get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("node {node_id} is not in runtime generation"))?;
        let prepared = if runtime.node.name == "block" {
            BlockHandler::new()
                .dial_udp_transport_speculative_runtime(
                    Arc::clone(&runtime),
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await?
        } else {
            let handler = self.find(runtime.node.protocol).ok_or_else(|| {
                anyhow::anyhow!("No handler for protocol {:?}", runtime.node.protocol)
            })?;
            handler
                .dial_udp_transport_speculative_runtime(
                    runtime,
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await?
        };
        if generation.is_shutdown() {
            anyhow::bail!("outbound runtime generation shut down during UDP preparation");
        }
        Ok(prepared)
    }

    pub async fn test_node(&self, node: &Node) -> bool {
        match self.find(node.protocol) {
            Some(handler) => handler.test_connectivity(node).await,
            None => false,
        }
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.len()
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
        assert!(registry.find(NodeProtocol::HTTP).is_some()); // HTTP uses DirectHandler
        assert!(registry.find(NodeProtocol::Trojan).is_some());
        assert!(registry.find(NodeProtocol::SS).is_some());
        assert!(registry.find(NodeProtocol::AnyTLS).is_some());
        assert!(registry.find(NodeProtocol::Hysteria2).is_some());
        assert!(registry.find(NodeProtocol::VMess).is_some());
        assert!(registry.find(NodeProtocol::Tuic).is_some());
        assert!(registry.find(NodeProtocol::Juicity).is_some());
    }

    /// The built-in direct/block nodes both carry NodeProtocol::HTTP; the
    /// registry must dispatch "block" by name to BlockHandler instead of
    /// falling through to DirectHandler (regression: block rules silently
    /// dialed direct).
    #[tokio::test]
    async fn test_block_node_dispatches_to_block_handler() {
        let registry = ProxyRegistry::default_resolver().unwrap();
        let node = Node {
            name: "block".into(),
            protocol: NodeProtocol::HTTP,
            ..Default::default()
        };
        let target: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let err = registry
            .dial(&node, target, None, Duration::from_secs(1))
            .await
            .expect_err("block node must not dial");
        assert!(err.to_string().contains("blocked"));
        let err = registry
            .dial_udp(&node, target, None, Duration::from_secs(1))
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
            ("direct", NodeProtocol::HTTP),
            ("socks", NodeProtocol::Socks5),
            ("ss", NodeProtocol::SS),
            ("trojan", NodeProtocol::Trojan),
        ] {
            nodes.push(Node {
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
            name: "old-anytls".into(),
            protocol: NodeProtocol::AnyTLS,
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown();

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
            name: "direct".into(),
            protocol: NodeProtocol::HTTP,
            ..Default::default()
        };
        let generation = Arc::new(
            crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap(),
        );
        generation.shutdown();

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
