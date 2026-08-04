//! Per-protocol facts — capabilities, pooling behavior, generation runtime
//! ownership, and share-link schemes — converged into one table.
//! These used to be spread across `OutboundCapabilities::for_node`, handler
//! `pool_ready_streams`/`pool_bare_tcp` overrides, and the runtime-registry
//! build match.

use honk_config::node::Node;
use honk_config::types::NodeProtocol;

use crate::runtime::{GenerationRuntime, OutboundCapabilities};

/// The per-protocol facts. Function-typed fields cover per-node conditions
/// (trojan pools ready streams only on the plain TCP transport; trojan and
/// anytls carry UDP only when `node.network` allows it).
pub struct ProtocolDescriptor {
    pub protocol: NodeProtocol,
    pub capabilities: fn(&Node) -> OutboundCapabilities,
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

/// The dial-time network gate, shared by the capability table and the
/// trojan/anytls UDP dial paths: no `network` restriction means UDP is
/// allowed; otherwise the list must contain "udp".
pub(crate) fn network_allows_udp(node: &Node) -> bool {
    node.network.as_deref().is_none_or(|network| {
        network
            .split(',')
            .any(|entry| entry.trim().eq_ignore_ascii_case("udp"))
    })
}

fn caps_tcp_udp(_: &Node) -> OutboundCapabilities {
    capabilities(true, false)
}

fn caps_tcp_only(_: &Node) -> OutboundCapabilities {
    capabilities(false, false)
}

fn caps_trojan(node: &Node) -> OutboundCapabilities {
    capabilities(network_allows_udp(node), false)
}

fn caps_anytls(node: &Node) -> OutboundCapabilities {
    capabilities(network_allows_udp(node), true)
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
        capabilities: caps_tcp_udp,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["ss"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Trojan,
        capabilities: caps_trojan,
        pool_ready_streams: trojan_pool_ready_streams,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["trojan"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VMess,
        capabilities: caps_tcp_only,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &["vmess"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::VLess,
        capabilities: caps_tcp_only,
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
        capabilities: caps_tcp_udp,
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
        capabilities: caps_tcp_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["hysteria2", "hysteria"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Tuic,
        capabilities: caps_tcp_udp,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::Quic,
        share_link_schemes: &["tuic"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Juicity,
        capabilities: caps_tcp_udp,
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
        capabilities: caps_anytls,
        pool_ready_streams: never,
        pool_bare_tcp: never,
        generation_runtime: GenerationRuntime::AnyTls,
        share_link_schemes: &["anytls"],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Direct,
        capabilities: caps_tcp_udp,
        pool_ready_streams: never,
        pool_bare_tcp: always,
        generation_runtime: GenerationRuntime::None,
        share_link_schemes: &[],
    },
    ProtocolDescriptor {
        protocol: NodeProtocol::Block,
        capabilities: caps_tcp_only,
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

    #[test]
    fn udp_capability_follows_the_network_gate() {
        let base = Node {
            protocol: NodeProtocol::Trojan,
            ..Default::default()
        };
        let trojan = descriptor(NodeProtocol::Trojan).capabilities;
        assert!(trojan(&base).udp, "no network restriction allows UDP");
        let ws_only = Node {
            network: Some("ws".to_string()),
            ..base.clone()
        };
        assert!(!trojan(&ws_only).udp);
        let mixed = Node {
            network: Some("tcp, udp".to_string()),
            ..base.clone()
        };
        assert!(trojan(&mixed).udp);

        let anytls = descriptor(NodeProtocol::AnyTLS).capabilities;
        let ws_only = Node {
            protocol: NodeProtocol::AnyTLS,
            network: Some("ws".to_string()),
            ..Default::default()
        };
        let caps = anytls(&ws_only);
        assert!(caps.multiplexed && !caps.udp);

        let ss = descriptor(NodeProtocol::SS).capabilities;
        let restricted = Node {
            protocol: NodeProtocol::SS,
            network: Some("tcp".to_string()),
            ..Default::default()
        };
        assert!(ss(&restricted).udp, "SS UDP is not network-gated");
    }
}
