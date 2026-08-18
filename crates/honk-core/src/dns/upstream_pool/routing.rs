use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use honk_config::node::Node;
use honk_config::types::DnsProtocol;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::GroupManager;
#[cfg(feature = "honk-policy")]
use honk_outbound::group::{HonkFeedback, HonkSelectionContext, HonkTarget, SelectionNetwork};
use tracing::{debug, warn};

use super::UpstreamPool;
use super::entries::UpstreamEntry;
use crate::routing::ConnectionInfo;

pub(super) struct DnsDialRoute {
    pub(super) target: SocketAddr,
    pub(super) node: Option<Node>,
    #[cfg(feature = "honk-policy")]
    pub(super) feedback: Option<HonkFeedback>,
}

#[cfg(feature = "honk-policy")]
pub(super) fn target_context(entry: &UpstreamEntry, target: SocketAddr) -> HonkSelectionContext {
    let (network, probe_domain) = match entry.protocol {
        DnsProtocol::Udp | DnsProtocol::Quic | DnsProtocol::H3 => {
            (SelectionNetwork::Udp, ProbeDomain::DnsUdp)
        }
        DnsProtocol::Tcp | DnsProtocol::Tls | DnsProtocol::Https => {
            (SelectionNetwork::Tcp, ProbeDomain::Tcp)
        }
    };
    let family = if target.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };
    HonkSelectionContext {
        network,
        probe_domain,
        target_family: Some(family),
        health_family: family,
        target: Some(if entry.endpoint.host.parse::<IpAddr>().is_ok() {
            HonkTarget::from(target)
        } else {
            HonkTarget::domain(&entry.endpoint.host, target.port())
        }),
    }
}
#[cfg(feature = "honk-policy")]
pub(super) fn tcp_target_context(
    entry: &UpstreamEntry,
    target: SocketAddr,
) -> HonkSelectionContext {
    let mut context = target_context(entry, target);
    context.network = SelectionNetwork::Tcp;
    context.probe_domain = ProbeDomain::Tcp;
    context
}

#[cfg(any(test, not(feature = "honk-policy")))]
fn select_group_leaf(group_manager: &GroupManager, outbound: &str) -> Option<Node> {
    group_manager.get_group_policy(outbound)?;
    let mut picked =
        group_manager.select_nodes_in_order_for_domain(outbound, ProbeDomain::Tcp, IpVersion::V4);
    if picked.is_empty() {
        picked = group_manager.select_nodes_in_order_for_domain(
            outbound,
            ProbeDomain::Tcp,
            IpVersion::V6,
        );
    }
    picked.into_iter().next().cloned()
}

#[cfg(feature = "honk-policy")]
fn select_group_leaf_for_target(
    group_manager: &GroupManager,
    outbound: &str,
    entry: &UpstreamEntry,
    target: SocketAddr,
) -> Option<(Node, Option<HonkFeedback>)> {
    group_manager.get_group_policy(outbound)?;
    group_manager
        .selection_plan_for_target_with_health_fallback(outbound, &target_context(entry, target))
        .entries
        .into_iter()
        .next()
        .map(|selected| (selected.node.clone(), selected.feedback))
}

impl UpstreamPool {
    #[cfg(any(test, not(feature = "honk-policy")))]
    pub(super) fn resolve_outbound_leaf(&self, outbound: &str) -> Option<Node> {
        if outbound.eq_ignore_ascii_case("direct") || outbound.eq_ignore_ascii_case("block") {
            return None;
        }

        if let Some(group_manager) = self.group_manager_snapshot.read().as_ref() {
            if let Some(node) = select_group_leaf(group_manager, outbound) {
                return Some(node);
            }
            if group_manager.get_group_policy(outbound).is_some() {
                return None;
            }
        } else {
            let cell = self.group_manager.read();
            if let Some(cell) = cell.as_ref() {
                let group_manager = cell.read();
                if group_manager.get_group_policy(outbound).is_some() {
                    if let Some(node) = select_group_leaf(&group_manager, outbound) {
                        return Some(node);
                    }
                    warn!(
                        "DNS outbound group '{}' has no available node (GroupManager)",
                        outbound
                    );
                    return None;
                }
            }
        }

        if let Some(node) = self.nodes.iter().find(|node| node.name == outbound) {
            return Some(node.clone());
        }

        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|group| group.name == outbound)
        {
            for node_id in &group.nodes {
                if let Some(node) = self.nodes.iter().find(|node| &node.id == node_id) {
                    return Some(node.clone());
                }
            }
        }

        warn!("DNS outbound '{}' resolved to no node", outbound);
        None
    }

    #[cfg(feature = "honk-policy")]
    fn resolve_outbound_for_target(
        &self,
        outbound: &str,
        entry: &UpstreamEntry,
        target: SocketAddr,
    ) -> (Option<Node>, Option<HonkFeedback>) {
        if outbound.eq_ignore_ascii_case("direct") || outbound.eq_ignore_ascii_case("block") {
            return (None, None);
        }

        if let Some(group_manager) = self.group_manager_snapshot.read().as_ref() {
            if let Some((node, feedback)) =
                select_group_leaf_for_target(group_manager, outbound, entry, target)
            {
                return (Some(node), feedback);
            }
            if group_manager.get_group_policy(outbound).is_some() {
                return (None, None);
            }
        } else if let Some(cell) = self.group_manager.read().as_ref() {
            let group_manager = cell.read();
            if group_manager.get_group_policy(outbound).is_some() {
                if let Some((node, feedback)) =
                    select_group_leaf_for_target(&group_manager, outbound, entry, target)
                {
                    return (Some(node), feedback);
                }
                warn!(
                    "DNS outbound group '{}' has no available node (GroupManager)",
                    outbound
                );
                return (None, None);
            }
        }

        if let Some(node) = self.nodes.iter().find(|node| node.name == outbound) {
            return (Some(node.clone()), None);
        }
        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|group| group.name == outbound)
            && let Some(node) = group
                .nodes
                .iter()
                .find_map(|id| self.nodes.iter().find(|node| node.id == *id))
        {
            return (Some(node.clone()), None);
        }
        warn!("DNS outbound '{}' resolved to no node", outbound);
        (None, None)
    }
    #[cfg(feature = "honk-policy")]
    pub(super) fn tcp_feedback_for_route(
        &self,
        entry: &UpstreamEntry,
        route: &DnsDialRoute,
    ) -> Option<HonkFeedback> {
        route
            .feedback
            .clone()
            .map(|feedback| feedback.with_context(tcp_target_context(entry, route.target)))
    }
    #[cfg(test)]
    pub(super) async fn resolve_dial_route(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<DnsDialRoute> {
        let target = Self::resolve_udp_addr(entry).await?;
        self.resolve_dial_route_for_address(entry, target).await
    }

    pub(super) async fn resolve_dial_route_for_address(
        &self,
        entry: &UpstreamEntry,
        target: SocketAddr,
    ) -> anyhow::Result<DnsDialRoute> {
        if let Some(tag) = entry.outbound.as_deref() {
            #[cfg(feature = "honk-policy")]
            let (node, feedback) = self.resolve_outbound_for_target(tag, entry, target);
            #[cfg(not(feature = "honk-policy"))]
            let node = self.resolve_outbound_leaf(tag);
            if node.is_none()
                && !tag.eq_ignore_ascii_case("direct")
                && !tag.eq_ignore_ascii_case("block")
            {
                anyhow::bail!("DNS upstream outbound '{tag}' has no available node");
            }
            debug!(
                "DNS dial leaf (forced -> {}): {:?}",
                tag,
                node.as_ref().map(|node| node.name.as_str())
            );
            return Ok(DnsDialRoute {
                target,
                node,
                #[cfg(feature = "honk-policy")]
                feedback,
            });
        }

        let host_is_ip = entry.endpoint.host.parse::<IpAddr>().is_ok();
        let protocol = match entry.protocol {
            DnsProtocol::Udp => "udp",
            DnsProtocol::Tcp
            | DnsProtocol::Tls
            | DnsProtocol::Https
            | DnsProtocol::Quic
            | DnsProtocol::H3 => "tcp",
        };
        let connection = ConnectionInfo {
            domain: (!host_is_ip).then(|| entry.endpoint.host.clone()),
            dst_ip: target.ip(),
            dst_port: target.port(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol,
            process_name: None,
            mac: None,
            dscp: None,
        };
        let outbound_name = if let Some(router) = self.traffic_router_snapshot.read().as_ref() {
            router.route(&connection).to_string()
        } else {
            let router_cell = self.traffic_router.read().clone();
            let Some(router) = router_cell else {
                debug!("DNS dial leaf (no traffic router): direct");
                return Ok(DnsDialRoute {
                    target,
                    node: None,
                    #[cfg(feature = "honk-policy")]
                    feedback: None,
                });
            };
            router.read().await.route(&connection).to_string()
        };
        debug!(
            "DNS dial route: {} {}:{} (host={}) l4={} → outbound '{}'",
            entry.endpoint.host,
            target.ip(),
            target.port(),
            entry.endpoint.host,
            protocol,
            outbound_name
        );
        if outbound_name.eq_ignore_ascii_case("direct")
            || outbound_name.eq_ignore_ascii_case("block")
        {
            return Ok(DnsDialRoute {
                target,
                node: None,
                #[cfg(feature = "honk-policy")]
                feedback: None,
            });
        }
        #[cfg(feature = "honk-policy")]
        let (node, feedback) = self.resolve_outbound_for_target(&outbound_name, entry, target);
        #[cfg(not(feature = "honk-policy"))]
        let node = self.resolve_outbound_leaf(&outbound_name);
        if node.is_none() {
            anyhow::bail!(
                "DNS dial route selected outbound '{outbound_name}' but no leaf node is available"
            );
        }
        debug!(
            "DNS dial leaf (routed via {}): {:?}",
            outbound_name,
            node.as_ref().map(|node| node.name.as_str())
        );
        Ok(DnsDialRoute {
            target,
            node,
            #[cfg(feature = "honk-policy")]
            feedback,
        })
    }

    #[cfg(test)]
    pub(super) async fn resolve_dial_leaf(
        &self,
        entry: &UpstreamEntry,
    ) -> anyhow::Result<Option<Node>> {
        Ok(self.resolve_dial_route(entry).await?.node)
    }
}
