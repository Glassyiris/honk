//! The outbound a control-plane download leaves through, chosen and dialed
//! the way user traffic is: the external UI archive and geodata updates.
//!
//! A configured detour forces the node or group it names. Otherwise the
//! target follows the routing rules: `direct` and `block` are returned for the
//! caller to handle, and any other result is a node to dial through its tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use honk_config::Config;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::{
    ScoreAttempt, ScoreContinuation, ScoreSelectionContext, ScoreTarget, SelectionNetwork,
    SharedGroupManager,
};
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry, TcpOutbound};
use honk_outbound::runtime::{
    EphemeralRuntimeGuard, NodeRuntime, OutboundRuntimeRegistry, SharedRuntimeRegistry,
};
use tokio::sync::RwLock;
use tracing::info;

use crate::routing::{ConnectionInfo, Router};

/// What a download needs to be routed like user traffic.
#[derive(Clone, Copy)]
pub(crate) struct Outbounds<'a> {
    pub(crate) router: &'a RwLock<Router>,
    pub(crate) config: &'a RwLock<std::sync::Arc<Config>>,
    pub(crate) group_manager: &'a SharedGroupManager,
    pub(crate) proxy_registry: &'a ProxyRegistry,
    pub(crate) runtime_registry: &'a SharedRuntimeRegistry,
}

/// Where the download goes.
pub(crate) enum Route {
    Direct {
        feedback: Option<ScoreAttempt>,
    },
    Block,
    Proxy {
        node: Box<Node>,
        feedback: Option<ScoreAttempt>,
    },
}

/// A route, and the group the detour or the routing rules chose, if any.
pub(crate) struct Decision {
    pub(crate) route: Route,
    pub(crate) group: Option<String>,
}

pub(crate) fn parse_host_ip(host: &str) -> Option<IpAddr> {
    host.parse()
        .ok()
        .or_else(|| host.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

impl Outbounds<'_> {
    /// Runs `host:port` through `detour`, or through the routing rules when it
    /// is `None`: `Router::route_with_must` for the outbound name, then the
    /// authoritative group/leaf resolution for the node to dial. `setting`
    /// names the detour's setting in the log, and `purpose` the download in errors.
    pub(crate) async fn decide(
        &self,
        detour: Option<&str>,
        setting: &str,
        purpose: &str,
        (host, port): (&str, u16),
        original: Option<&ScoreContinuation>,
    ) -> anyhow::Result<Decision> {
        let host_ip = parse_host_ip(host);
        let resolved_ip = if let Some(ip) = host_ip {
            Some(ip)
        } else {
            honk_outbound::bootstrap::resolve(host)
                .await
                .ok()
                .and_then(|addresses| addresses.into_iter().next())
        };
        let (dst_ip, domain) = match host_ip {
            Some(ip) => (
                ip,
                (!host.parse::<IpAddr>().is_ok()).then(|| host.to_string()),
            ),
            None => (
                resolved_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                Some(host.to_string()),
            ),
        };
        let info = ConnectionInfo {
            domain: domain.clone(),
            dst_ip,
            dst_port: port,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        };
        let (outbound, rule) = match detour {
            None => {
                let router = self.router.read().await;
                let (action, matched) = router.route_action(&info);
                let rule = matched.map(|m| format!("{}:{}", m.rule_type, m.rule_payload));
                (action.outbound.clone(), rule)
            }
            Some(detour) => (detour.to_owned(), Some(setting.to_owned())),
        };
        let target_ipver = if matches!(dst_ip, IpAddr::V6(_)) {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let score_ipver = resolved_ip.map(|ip| {
            if ip.is_ipv6() {
                IpVersion::V6
            } else {
                IpVersion::V4
            }
        });
        let (node, feedback, group) = {
            let config = self.config.read().await;
            let group_manager = self.group_manager.read().clone();
            // Generic route resolution defaults unknown outputs to direct; an
            // explicitly configured detour must not bypass that operator error.
            if detour.is_some()
                && config.builtin_node(&outbound).is_none()
                && !config.nodes.iter().any(|node| node.name == outbound)
                && !config.groups.iter().any(|group| group.name == outbound)
            {
                anyhow::bail!("{purpose}: detour outbound '{outbound}' not found");
            }
            let group = config
                .groups
                .iter()
                .any(|group| group.name == outbound)
                .then(|| outbound.clone());
            if group.is_some() {
                let context = ScoreSelectionContext {
                    network: SelectionNetwork::Tcp,
                    probe_domain: ProbeDomain::Tcp,
                    target_family: score_ipver,
                    health_family: score_ipver.unwrap_or(target_ipver),
                    target: Some(if domain.is_some() {
                        ScoreTarget::domain(host, port)
                    } else {
                        SocketAddr::new(dst_ip, port).into()
                    }),
                };
                let plan = group_manager
                    .selection_plan_for_target_with_health_fallback(&outbound, &context, original);
                match plan.entries.into_iter().next() {
                    Some(entry) => (Some(entry.node.clone()), entry.feedback, group),
                    None => (None, None, group),
                }
            } else {
                let nodes = crate::control::reload::resolve_outbound_nodes(
                    &config,
                    &group_manager,
                    &outbound,
                    ProbeDomain::Tcp,
                    target_ipver,
                );
                (nodes.into_iter().next(), None, None)
            }
        };
        let Some(node) = node else {
            anyhow::bail!("{purpose}: outbound '{outbound}' has no available node");
        };
        let route = match node.protocol() {
            NodeProtocol::Direct => Route::Direct { feedback },
            NodeProtocol::Block => Route::Block,
            _ => Route::Proxy {
                node: Box::new(node),
                feedback,
            },
        };
        info!(
            outbound = %outbound,
            rule = rule.as_deref().unwrap_or("fallback"),
            via = match &route {
                Route::Direct { .. } => "direct",
                Route::Block => "block",
                Route::Proxy { node, .. } => node.name.as_str(),
            },
            "{purpose} routed"
        );
        Ok(Decision { route, group })
    }

    /// Prepares a tunnel through `node` to `host:port`. Tunnel handlers dial
    /// by domain, so the node's egress resolves it and local DNS poisoning
    /// does not matter; the address is only a fallback for handlers that need one.
    pub(crate) async fn tunnel(
        &self,
        node: &Node,
        (host, port): (&str, u16),
    ) -> anyhow::Result<Tunnel> {
        let protocol = node.protocol();
        let entry = self
            .proxy_registry
            .find(protocol)
            .ok_or_else(|| anyhow::anyhow!("no handler for protocol {protocol:?}"))?;
        let connect_timeout =
            Duration::from_millis(self.config.read().await.global.connect_timeout_ms);
        let (domain, addr) = match parse_host_ip(host) {
            Some(ip) => (None, SocketAddr::new(ip, port)),
            None => (
                Some(host.to_owned()),
                SocketAddr::from(([0, 0, 0, 0], port)),
            ),
        };
        let generation = self.runtime_registry.read().clone();
        let (runtime, guard) = honk_outbound::urltest::try_probe_runtime(
            &generation,
            node,
            honk_outbound::proxy::WarmRequirement::Session,
        )?;
        Ok(Tunnel {
            generation,
            runtime,
            guard,
            tcp: std::sync::Arc::clone(&entry.tcp),
            connect_timeout,
            addr,
            domain,
        })
    }
}

/// A node's tunnel to one target. The disposable runtime it may own lives
/// until [`Tunnel::close`], after the stream is done.
pub(crate) struct Tunnel {
    generation: std::sync::Arc<OutboundRuntimeRegistry>,
    runtime: std::sync::Arc<NodeRuntime>,
    guard: Option<EphemeralRuntimeGuard>,
    tcp: std::sync::Arc<dyn TcpOutbound>,
    connect_timeout: Duration,
    addr: SocketAddr,
    domain: Option<String>,
}

impl Tunnel {
    pub(crate) async fn dial(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let proxy = self
            .generation
            .scope_dials(self.tcp.dial_runtime(
                std::sync::Arc::clone(&self.runtime),
                self.addr,
                self.domain.as_deref(),
                self.connect_timeout,
            ))
            .await?;
        Ok(proxy.stream)
    }

    pub(crate) async fn close(mut self) -> anyhow::Result<()> {
        if let Some(guard) = self.guard.as_mut() {
            guard.close().await?;
        }
        Ok(())
    }
}
