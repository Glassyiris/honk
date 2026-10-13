//! Preparation dispatch for protocols whose one association carries every
//! destination of a client source (the core `Shared` source transport).
//!
//! Hysteria2, TUIC and VLESS keep their concrete source preparations: their
//! hot send path is not boxed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::types::NodeProtocol;

use super::shadowsocks::ShadowsocksHandler;
use super::{MultiTargetTransport, PacketRejection, PreparedUdpTransport};
use crate::runtime::NodeRuntime;

/// Protocols served by [`prepare_shared_source`].
const SHARED: &[NodeProtocol] = &[NodeProtocol::SS, NodeProtocol::Socks5];

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
    // SS and SOCKS5 own only a socket (and SOCKS5 a control stream): nothing is
    // published at commit, so speculative preparation needs no separate path.
    let _ = speculative;
    match runtime.node.protocol() {
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
        _ => Err(PacketRejection::Policy.into()),
    }
}
