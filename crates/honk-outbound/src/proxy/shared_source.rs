//! Preparation dispatch for protocols whose one association carries every
//! destination of a client source (the core `Shared` source transport).
//!
//! Hysteria2, TUIC and VLESS XUDP/Mux.Cool keep their concrete source
//! preparations: their hot send path is not boxed. VLESS is not in [`SHARED`]
//! because only its explicit UoT v2 and H2MUX paths are served here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::types::NodeProtocol;

use super::anytls::AnyTlsHandler;
use super::juicity::JuicityHandler;
use super::shadowsocks::ShadowsocksHandler;
use super::{MultiTargetTransport, PacketRejection, PreparedUdpTransport};
use crate::runtime::NodeRuntime;

/// Protocols served by [`prepare_shared_source`].
const SHARED: &[NodeProtocol] = &[
    NodeProtocol::SS,
    NodeProtocol::Socks5,
    NodeProtocol::Juicity,
    NodeProtocol::Trojan,
    NodeProtocol::AnyTLS,
];

pub fn uses_shared_source(protocol: NodeProtocol) -> bool {
    SHARED.contains(&protocol)
}

/// Build one association for the client source scope. `speculative`
/// preparations must not publish carrier state until committed.
pub async fn prepare_shared_source(
    runtime: Arc<NodeRuntime>,
    target: SocketAddr,
    target_domain: Option<&str>,
    connect_timeout: Duration,
    speculative: bool,
) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
    match runtime.node.protocol() {
        // These own only a socket or a stream whose preparation already defers
        // publication to commit, so speculative needs no separate path.
        NodeProtocol::SS => {
            ShadowsocksHandler::prepare_udp_source(
                &runtime.node,
                target,
                target_domain,
                connect_timeout,
            )
            .await
        }
        NodeProtocol::Socks5 => {
            super::socks5::Socks5Handler::new()
                .prepare_udp_source(
                    runtime.node.as_ref(),
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await
        }
        NodeProtocol::Trojan => {
            super::trojan::TrojanHandler::prepare_udp_source(
                &runtime,
                target,
                target_domain,
                connect_timeout,
            )
            .await
        }
        NodeProtocol::Juicity => {
            JuicityHandler::new()
                .prepare_udp_source(runtime, target, target_domain, connect_timeout, speculative)
                .await
        }
        NodeProtocol::AnyTLS => {
            AnyTlsHandler::prepare_udp_source(
                runtime,
                target,
                target_domain,
                connect_timeout,
                speculative,
            )
            .await
        }
        #[cfg(feature = "rprx")]
        NodeProtocol::VLess => {
            super::vless::VLessHandler::prepare_shared_udp(
                runtime,
                target,
                target_domain,
                connect_timeout,
            )
            .await
        }
        _ => Err(PacketRejection::Policy.into()),
    }
}
