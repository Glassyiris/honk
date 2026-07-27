//! Registry-based proxy handler dispatch.

pub(crate) mod addr;
pub mod anytls;
pub mod block;
pub mod direct;
pub mod hysteria2;
pub mod juicity;
pub(crate) mod mux;
pub mod shadowsocks;
pub(crate) mod shadowsocks_2022;
pub mod socks5;
pub mod ssr;
pub(crate) mod transport;
pub mod trojan;
pub mod trojan_go;
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
use ssr::ShadowsocksRHandler;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use trojan::TrojanHandler;
use trojan_go::TrojanGoHandler;
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

#[async_trait]
pub trait ProxyHandler: Send + Sync {
    fn protocol(&self) -> NodeProtocol;

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream>;

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

    pub fn default_resolver() -> anyhow::Result<Self> {
        let mut registry = Self::new();
        registry.register(Box::new(Socks5Handler::new()));
        registry.register(Box::new(DirectHandler::new()));
        registry.register(Box::new(BlockHandler::new()));
        registry.register(Box::new(TrojanHandler::new()));
        registry.register(Box::new(TrojanGoHandler::new()));
        registry.register(Box::new(Hysteria2Handler::new()));
        registry.register(Box::new(ShadowsocksHandler::new()));
        registry.register(Box::new(ShadowsocksRHandler::new()));
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
}
