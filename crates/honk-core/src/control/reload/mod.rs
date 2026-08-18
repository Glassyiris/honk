use super::*;
mod connectivity;
mod policy;
mod subscription;
mod transaction;
mod warm;

pub(in crate::control) use policy::restart_required_changes;

#[cfg(test)]
pub(in crate::control) use warm::{
    SelectorWarmResources, run_udp_warm_dispatches, selector_warm_candidates, udp_warm_candidates,
    warm_selector_candidate,
};

pub(in crate::control) use subscription::config_with_subscription_nodes;

pub(in crate::control) use connectivity::{
    build_outbound_id_map, group_check_url_registrations, group_connectivity_snapshot,
    group_datapath_alive, install_interrupt_callback, install_selector_warm_callback,
    open_group_connectivity, publish_group_connectivity, sync_health_check_nodes,
    urltest_group_registrations,
};

#[cfg(any(not(feature = "honk-policy"), feature = "clash-api"))]
pub(crate) fn resolve_outbound_nodes(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> Vec<Node> {
    if let Some(node) = config.builtin_node(outbound_name) {
        return vec![node];
    }
    if let Some(node) = config.nodes.iter().find(|n| n.name == outbound_name) {
        return vec![node.clone()];
    }
    for group in &config.groups {
        if group.name == outbound_name {
            let mut nodes =
                group_manager.select_nodes_in_order_for_domain(&group.name, domain, ipver);
            // Fallback: IPv6 targets may still be forwarded through nodes that
            // are only reachable over IPv4 (common for proxy servers with only
            // an A record). Try IPv4 alive candidates before giving up.
            if nodes.is_empty() && ipver == IpVersion::V6 {
                nodes = group_manager.select_nodes_in_order_for_domain(
                    &group.name,
                    domain,
                    IpVersion::V4,
                );
                if !nodes.is_empty() {
                    warn!(
                        "resolve_outbound_nodes: group '{}' has no IPv6 alive node; falling back to IPv4 alive candidates",
                        group.name
                    );
                }
            }
            if nodes.is_empty() {
                warn!(
                    "resolve_outbound_nodes: group '{}' has no available node (ipver={:?})",
                    group.name, ipver
                );
                // When all nodes in a group are dead and `final` is configured,
                // recursively resolve the fallback outbound.
                if let Some(final_name) = group_manager.get_final_outbound(&group.name) {
                    info!(
                        "Group '{}' has no alive nodes, falling back to final outbound '{}'",
                        group.name, final_name
                    );
                    return resolve_outbound_nodes(
                        config,
                        group_manager,
                        &final_name,
                        domain,
                        ipver,
                    );
                }
            }
            return nodes.into_iter().cloned().collect();
        }
    }
    warn!(
        "Outbound '{}' not found, falling back to direct",
        outbound_name
    );
    vec![Config::builtin_direct_node()]
}

#[cfg(feature = "honk-policy")]
#[derive(Debug, Clone)]
pub(super) struct ResolvedHonkPlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) health_family: IpVersion,
    pub(super) feedback: Vec<Option<honk_outbound::group::HonkFeedback>>,
    pub(super) selection_chains: Vec<Vec<String>>,
}

#[cfg(feature = "honk-policy")]
fn own_honk_plan(plan: honk_outbound::group::HonkSelectionPlan<'_>) -> ResolvedHonkPlan {
    let mut nodes = Vec::with_capacity(plan.entries.len());
    let mut feedback = Vec::with_capacity(plan.entries.len());
    let mut selection_chains = Vec::with_capacity(plan.entries.len());
    for entry in plan.entries {
        nodes.push(entry.node.clone());
        feedback.push(entry.feedback);
        selection_chains.push(entry.selection_chain);
    }
    ResolvedHonkPlan {
        mode: plan.mode,
        nodes,
        health_family: plan.health_family,
        feedback,
        selection_chains,
    }
}

#[cfg(feature = "honk-policy")]
pub(super) fn resolve_urltest_retry_plan_for_target(
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::HonkSelectionContext,
) -> ResolvedHonkPlan {
    own_honk_plan(group_manager.urltest_retry_plan_for_target(outbound_name, context))
}

#[cfg(feature = "honk-policy")]
pub(super) fn resolve_outbound_plan_for_target(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::HonkSelectionContext,
) -> ResolvedHonkPlan {
    resolve_outbound_plan_for_target_inner(
        config,
        group_manager,
        outbound_name,
        context,
        0,
        &mut Vec::new(),
    )
}

#[cfg(feature = "honk-policy")]
fn resolve_outbound_plan_for_target_inner(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::HonkSelectionContext,
    depth: usize,
    visited: &mut Vec<String>,
) -> ResolvedHonkPlan {
    if let Some(node) = config.builtin_node(outbound_name) {
        return ResolvedHonkPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![node],
            health_family: context.health_family,
            feedback: vec![None],
            selection_chains: vec![vec![outbound_name.to_owned()]],
        };
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == outbound_name) {
        let health_family = if group_manager.is_node_selectable_for_domain(
            node.id,
            context.probe_domain,
            context.health_family,
        ) {
            Some(context.health_family)
        } else if context.health_family == IpVersion::V6
            && group_manager.is_node_selectable_for_domain(
                node.id,
                context.probe_domain,
                IpVersion::V4,
            )
        {
            Some(IpVersion::V4)
        } else {
            None
        };
        return ResolvedHonkPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: health_family.map(|_| node.clone()).into_iter().collect(),
            health_family: health_family.unwrap_or(context.health_family),
            feedback: health_family.map(|_| None).into_iter().collect(),
            selection_chains: health_family
                .map(|_| vec![node.name.clone()])
                .into_iter()
                .collect(),
        };
    }
    let Some(group) = config
        .groups
        .iter()
        .find(|group| group.name == outbound_name)
    else {
        return ResolvedHonkPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![Config::builtin_direct_node()],
            health_family: context.health_family,
            feedback: vec![None],
            selection_chains: vec![vec![Config::BUILTIN_DIRECT_NODE.to_owned()]],
        };
    };
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH
        || visited.iter().any(|name| name == outbound_name)
    {
        return ResolvedHonkPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: Vec::new(),
            health_family: context.health_family,
            feedback: Vec::new(),
            selection_chains: Vec::new(),
        };
    }
    let plan = group_manager.selection_plan_for_target_with_health_fallback(outbound_name, context);
    if !plan.entries.is_empty() {
        return own_honk_plan(plan);
    }
    let Some(final_name) = group.final_outbound.as_deref() else {
        return ResolvedHonkPlan {
            mode: plan.mode,
            nodes: Vec::new(),
            health_family: plan.health_family,
            feedback: Vec::new(),
            selection_chains: Vec::new(),
        };
    };
    visited.push(outbound_name.to_owned());
    let mut terminal = resolve_outbound_plan_for_target_inner(
        config,
        group_manager,
        final_name,
        context,
        depth + 1,
        visited,
    );
    visited.pop();
    for chain in &mut terminal.selection_chains {
        chain.insert(0, outbound_name.to_owned());
    }
    for (index, node) in terminal.nodes.iter().enumerate() {
        let outer = group_manager.feedback_for_group_node(outbound_name, node.id, context.clone());
        terminal.feedback[index] = match (outer, terminal.feedback[index].take()) {
            (Some(outer), Some(inner)) => {
                Some(inner.prepend_attribution(outer.attributions()[0].group.clone(), node.id))
            }
            (Some(outer), None) => Some(outer),
            (None, inner) => inner,
        };
    }
    terminal
}

/// Concrete UDP candidates plus the provenance and IP family selected by
/// the final outbound resolution. This companion does not change the legacy
/// TCP/DNS `resolve_outbound_nodes` API.
#[derive(Debug, Clone)]
pub(super) struct ResolvedUdpPlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) ipver: IpVersion,
    #[cfg(feature = "honk-policy")]
    pub(super) feedback: Vec<Option<honk_outbound::group::HonkFeedback>>,
    #[cfg(feature = "honk-policy")]
    pub(super) selection_chains: Vec<Vec<String>>,
}

/// Resolve UDP candidates without inferring policy from candidate count.
///
/// A group plan supplies the authoritative/cold provenance directly. Empty
/// groups may follow `final_outbound`, in which case the terminal outbound's
/// mode and resolved IP version replace the outer plan. Recursive final
/// chains are bounded and cycle-safe; a missing final target retains the
/// historical direct fallback, while a cycle/depth breach fails closed.
#[cfg(any(test, not(feature = "honk-policy")))]
pub(super) fn resolve_udp_outbound_plan(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    ipver: IpVersion,
) -> ResolvedUdpPlan {
    resolve_udp_outbound_plan_inner(
        config,
        group_manager,
        outbound_name,
        ipver,
        0,
        &mut Vec::new(),
    )
}

#[cfg(feature = "honk-policy")]
pub(super) fn resolve_udp_outbound_plan_for_target(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    context: &honk_outbound::group::HonkSelectionContext,
) -> ResolvedUdpPlan {
    let plan = resolve_outbound_plan_for_target(config, group_manager, outbound_name, context);
    ResolvedUdpPlan {
        mode: plan.mode,
        nodes: plan.nodes,
        ipver: plan.health_family,
        feedback: plan.feedback,
        selection_chains: plan.selection_chains,
    }
}

#[cfg(any(test, not(feature = "honk-policy")))]
fn resolve_udp_outbound_plan_inner(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    ipver: IpVersion,
    depth: usize,
    visited: &mut Vec<String>,
) -> ResolvedUdpPlan {
    if let Some(node) = config.builtin_node(outbound_name) {
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![node],
            ipver,
            #[cfg(feature = "honk-policy")]
            feedback: Vec::new(),
            #[cfg(feature = "honk-policy")]
            selection_chains: Vec::new(),
        };
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == outbound_name) {
        let mut selected_ipver = ipver;
        let nodes = if group_manager.is_node_selectable_for_domain(
            node.id,
            ProbeDomain::DataUdp,
            selected_ipver,
        ) {
            vec![node.clone()]
        } else if ipver == IpVersion::V6
            && group_manager.is_node_selectable_for_domain(
                node.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            )
        {
            selected_ipver = IpVersion::V4;
            vec![node.clone()]
        } else {
            vec![]
        };
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes,
            ipver: selected_ipver,
            #[cfg(feature = "honk-policy")]
            feedback: Vec::new(),
            #[cfg(feature = "honk-policy")]
            selection_chains: Vec::new(),
        };
    }
    let Some(group) = config
        .groups
        .iter()
        .find(|group| group.name == outbound_name)
    else {
        warn!(
            "UDP outbound '{}' not found, falling back to direct",
            outbound_name
        );
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![Config::builtin_direct_node()],
            ipver,
            #[cfg(feature = "honk-policy")]
            feedback: Vec::new(),
            #[cfg(feature = "honk-policy")]
            selection_chains: Vec::new(),
        };
    };
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH
        || visited.iter().any(|name| name == outbound_name)
    {
        warn!(
            "UDP final outbound resolution for '{}' stopped at recursive cycle/depth",
            outbound_name
        );
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![],
            ipver,
            #[cfg(feature = "honk-policy")]
            feedback: Vec::new(),
            #[cfg(feature = "honk-policy")]
            selection_chains: Vec::new(),
        };
    }

    visited.push(outbound_name.to_owned());
    let mut selected_ipver = ipver;
    let mut plan =
        group_manager.selection_plan_for_domain(&group.name, ProbeDomain::DataUdp, selected_ipver);
    // Proxy servers frequently have only an A record. Preserve that concrete
    // fallback family for traffic health feedback rather than reporting the
    // original IPv6 destination family.
    if plan.nodes.is_empty() && ipver == IpVersion::V6 {
        plan = group_manager.selection_plan_for_domain(
            &group.name,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        if !plan.nodes.is_empty() {
            selected_ipver = IpVersion::V4;
            warn!(
                "UDP group '{}' has no IPv6 alive node; falling back to IPv4 alive candidates",
                group.name
            );
        }
    }
    if !plan.nodes.is_empty() {
        visited.pop();
        return ResolvedUdpPlan {
            mode: plan.mode,
            nodes: plan.nodes.into_iter().cloned().collect(),
            ipver: selected_ipver,
            #[cfg(feature = "honk-policy")]
            feedback: Vec::new(),
            #[cfg(feature = "honk-policy")]
            selection_chains: Vec::new(),
        };
    }

    if let Some(final_name) = group_manager.get_final_outbound(&group.name) {
        info!(
            "UDP group '{}' has no available node; falling back to final outbound '{}'",
            group.name, final_name
        );
        let terminal = resolve_udp_outbound_plan_inner(
            config,
            group_manager,
            &final_name,
            ipver,
            depth + 1,
            visited,
        );
        visited.pop();
        return terminal;
    }
    visited.pop();
    ResolvedUdpPlan {
        mode: plan.mode,
        nodes: vec![],
        ipver: selected_ipver,
        #[cfg(feature = "honk-policy")]
        feedback: Vec::new(),
        #[cfg(feature = "honk-policy")]
        selection_chains: Vec::new(),
    }
}
