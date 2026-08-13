use super::*;

/// Pick the nodes the startup preconnect warm-up dials: each group's current
/// selection (selector pick / urltest winner, peek semantics) first, then
/// config order to fill the remaining budget. Eligibility is
/// descriptor-driven — multiplexed (AnyTLS) and QUIC nodes can never consume
/// a pooled bare TCP — and the built-in direct/block markers have no server
/// to dial. `count == 0` disables the warm-up; the
/// [`honk_config::config::PRECONNECT_NODE_COUNT_AUTO`] sentinel caps at
/// `min(nodes, 8)`.
pub(crate) fn preconnect_candidates(
    config: &Config,
    group_manager: &GroupManager,
    count: usize,
) -> Vec<Node> {
    if count == 0 {
        return Vec::new();
    }
    let limit = if count == honk_config::config::PRECONNECT_NODE_COUNT_AUTO {
        config.nodes.len().min(8)
    } else {
        count
    };
    fn eligible(node: &Node) -> bool {
        !matches!(node.protocol, NodeProtocol::Direct | NodeProtocol::Block)
            && (honk_outbound::descriptor::descriptor(node.protocol).pool_bare_tcp)(node)
    }
    let mut seen = std::collections::HashSet::new();
    let mut selected: Vec<Node> = Vec::new();
    let push = |node: &Node,
                seen: &mut std::collections::HashSet<uuid::Uuid>,
                selected: &mut Vec<Node>| {
        if selected.len() < limit && eligible(node) && seen.insert(node.id) {
            selected.push(node.clone());
        }
    };
    for group in &config.groups {
        if let Some(node) = group_manager
            .peek_selection_plan_for_domain(&group.name, ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .first()
        {
            push(node, &mut seen, &mut selected);
        }
    }
    for node in &config.nodes {
        push(node, &mut seen, &mut selected);
    }
    selected
}
