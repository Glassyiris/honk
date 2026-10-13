//! Preparation dispatch for protocols whose one association carries every
//! destination of a client source (the core `Shared` source transport).
//!
//! Hysteria2, TUIC and VLESS keep their concrete source preparations: their
//! hot send path is not boxed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::types::NodeProtocol;

use super::{MultiTargetTransport, PacketRejection, PreparedUdpTransport};
use crate::runtime::NodeRuntime;

/// Protocols served by [`prepare_shared_source`].
const SHARED: &[NodeProtocol] = &[NodeProtocol::Socks5];

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
    // SOCKS5 owns only a control stream and a socket, so there is no state to
    // publish at commit and speculative needs no separate path.
    let _ = speculative;
    match runtime.node.protocol() {
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
