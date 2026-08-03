//! Static per-protocol facts — capabilities, pooling behavior, generation
//! runtime ownership, and share-link schemes — converged into one table.
//! These used to be spread across `OutboundCapabilities::for_node`, handler
//! `pool_ready_streams`/`pool_bare_tcp` overrides, and the runtime-registry
//! build match.

use honk_config::node::Node;
use honk_config::types::NodeProtocol;

use crate::runtime::{GenerationRuntime, OutboundCapabilities};

/// The static facts of one outbound protocol. Function-typed fields cover
/// per-node conditions (trojan pools ready streams only on the plain TCP
/// transport).
pub struct ProtocolDescriptor {
    pub protocol: NodeProtocol,
    pub capabilities: OutboundCapabilities,
    pub pool_ready_streams: fn(&Node) -> bool,
    pub pool_bare_tcp: fn(&Node) -> bool,
    pub generation_runtime: GenerationRuntime,
    pub share_link_schemes: &'static [&'static str],
}

impl ProtocolDescriptor {
    pub fn has_generation_runtime(&self) -> bool {
        self.generation_runtime != GenerationRuntime::None
    }
}

const fn capabilities(udp: bool, multiplexed: bool) -> OutboundCapabilities {
    OutboundCapabilities {
        tcp: true,
        udp,
        multiplexed,
    }
}

fn never(_: &Node) -> bool {
    false
}

fn always(_: &Node) -> bool {
    true
}

/// Poolable only on the plain TCP transport: `dial()` completes the TLS
/// handshake (if enabled) and writes the one-shot request header; Trojan
/// defines no server handshake reply, so the stream is then a target-bound
/// data channel. WebSocket/gRPC transports add a bridge task / HTTP/2
/// framing state whose idle liveness cannot be probed at the fd level, so
/// they stay on bare-TCP pooling.
fn trojan_pool_ready_streams(node: &Node) -> bool {
    matches!(node.transport.as_str(), "" | "tcp")
}

static DESCRIPTORS: &[ProtocolDescriptor] = &[
    ProtocolDescriptor {
        protocol: NodeProtocol::SS,
        capabilities: capabilities(true, false),
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["ss"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Trojan,
        capabilities: capabilities(true, false),
        pool_ready_streams: trojan_pool_ready_streams,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["trojan"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VMess,
        capabilities: capabilities(false, false),
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["vmess"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VLess,
        capabilities: capabilities(false, false),
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["vless"],
    },
    // After the greeting (+ optional RFC 1929 auth) and a successful CONNECT
    // reply, the connection is a pure data channel bound to the requested
    // target — the server sends nothing of its own first, so a fully-dialed
    // stream is safe to pool and reuse directly.
    ProtocolDescriptor {
        protocol: NodeProtocol::Socks5,
        capabilities: capabilities(true, false),
        pool_ready_streams: always,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["socks5", "socks4", "socks4a"],
    },
    // QUIC-based (hy2/tuic/juicity): a pooled bare TCP is unusable — their
    // `dial_with_tcp` fails — so preconnect warmup must not deposit one (it
    // would poison the first flow).
    ProtocolDescriptor {
        protocol: NodeProtocol::Hysteria2,
        capabilities: capabilities(true, false),
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["hysteria2", "hysteria"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Tuic,
        capabilities: capabilities(true, false),
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["tuic"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Juicity,
        capabilities: capabilities(true, false),
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["juicity"],
    },
    // Multiplexed: the session pool already keeps warm connections; a pooled
    // bare TCP would force a new session (TLS + auth) per flow, and sessions
    // created over the pool cap leak (orphaned from the janitor, held forever
    // by their demux task).
    ProtocolDescriptor {
        protocol: NodeProtocol::AnyTLS,
        capabilities: capabilities(true, true),
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::AnyTls,
        share_link_schemes: &["anytls"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Direct,
        capabilities: capabilities(true, false),
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Block,
        capabilities: capabilities(false, false),
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
];

pub fn descriptor(protocol: NodeProtocol) -> &'static ProtocolDescriptor {
    DESCRIPTORS
        .iter()
        .find(|d| d.protocol == protocol)
        .expect("every NodeProtocol has a descriptor")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_has_a_descriptor() {
        for protocol in [
            NodeProtocol::SS,
            NodeProtocol::Trojan,
            NodeProtocol::VMess,
            NodeProtocol::VLess,
            NodeProtocol::Socks5,
            NodeProtocol::Hysteria2,
            NodeProtocol::Tuic,
            NodeProtocol::Juicity,
            NodeProtocol::AnyTLS,
            NodeProtocol::Direct,
            NodeProtocol::Block,
        ] {
            assert_eq!(descriptor(protocol).protocol, protocol);
        }
    }

    #[test]
    fn generation_runtime_matches_protocol_family() {
        assert!(descriptor(NodeProtocol::AnyTLS).has_generation_runtime());
        assert!(descriptor(NodeProtocol::Tuic).has_generation_runtime());
        assert!(descriptor(NodeProtocol::Juicity).has_generation_runtime());
        assert!(descriptor(NodeProtocol::Hysteria2).has_generation_runtime());
        assert!(!descriptor(NodeProtocol::Trojan).has_generation_runtime());
        assert!(!descriptor(NodeProtocol::Direct).has_generation_runtime());
    }
}
