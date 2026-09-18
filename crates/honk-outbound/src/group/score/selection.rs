use crate::group::GroupMember;

use super::*;

impl super::GroupManager {
    /// Shared scorer handle for fallible reload construction.
    pub fn score_state(&self) -> Arc<ScorePolicyState> {
        Arc::clone(&self.score_state)
    }

    /// Publish committed group/leaf membership and prune only removed pairs.
    /// Extant non-Score groups remain valid for reporters started before a
    /// policy change; new selection creates feedback only for Score groups.
    pub fn publish_score_membership(&self) {
        let groups = self.groups.keys().cloned().collect::<Vec<_>>();
        let membership = self.groups.values().flat_map(|group| {
            self.reachable_leaf_nodes_in_group(&group.name)
                .into_iter()
                .map(move |node| (group.name.clone(), node.id))
        });
        self.score_state
            .publish_generation(Arc::clone(&self.score_authority), groups, membership);
    }

    /// Aggregate scorer feedback for concrete work scheduled by leaf ID.
    /// Every Score group that recursively contains the leaf is attributed
    /// once, regardless of how many nested paths reach it.
    pub fn feedback_for_node(
        &self,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        let attributions: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|group| self.group_reaches_node(&group.name, node_id))
            .map(|group| ScoreAttribution {
                group: group.name.clone(),
                node_id,
            })
            .collect();
        (!attributions.is_empty() && self.score_state.is_current_authority(&self.score_authority))
            .then(|| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    attributions,
                )
            })
    }

    /// Feedback for work explicitly attributed to one Score group.
    /// Selected leaves should use their plan-carried feedback.
    pub fn feedback_for_group_node(
        &self,
        group_name: &str,
        node_id: Uuid,
        context: ScoreSelectionContext,
    ) -> Option<ScoreFeedback> {
        self.groups
            .get(group_name)
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
            .filter(|_| self.score_state.is_current_authority(&self.score_authority))
            .map(|group| {
                ScoreFeedback::new(
                    Arc::clone(&self.score_state),
                    Arc::clone(&self.score_authority),
                    context,
                    vec![ScoreAttribution {
                        group: group.name.clone(),
                        node_id,
                    }],
                )
            })
    }

    /// Target-aware selection with IPv6-target/IPv4-proxy health fallback.
    /// The target family remains unchanged in feedback keys; only the
    /// candidate health filter retries with IPv4.
    pub fn selection_plan_for_target_with_health_fallback(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        let plan = self.selection_plan_for_target_with_effects(
            group_name,
            context,
            super::SelectionEffects::ApplyWithHealthFallback,
        );
        if !plan.entries.is_empty() || context.health_family != IpVersion::V6 {
            return plan;
        }
        let mut fallback = context.clone();
        fallback.health_family = IpVersion::V4;
        self.selection_plan_for_target(group_name, &fallback)
    }
    /// Return the latency-ordered URLTest alternatives for one target without
    /// changing selection state. Each entry keeps the same Honk attribution
    /// and selection chain as an ordinary target-aware plan.
    pub fn urltest_retry_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        if group.policy != honk_config::group::GroupPolicy::URLTest {
            return super::ScoreSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        }
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        );
        let candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let mut seen = std::collections::HashSet::new();
        let candidates = self
            .order_by_latency(
                candidates,
                context.network,
                context.health_family,
                group.check_url.as_deref(),
            )
            .into_iter()
            .filter(|candidate| seen.insert(candidate.node.id))
            .take(3)
            .map(|mut candidate| {
                candidate.selection_chain.insert(0, group.name.as_str());
                candidate
            })
            .collect();
        self.score_selection_plan(candidates, super::SelectionPlanMode::Authoritative, context)
    }

    fn score_selection_plan<'a>(
        &'a self,
        candidates: Vec<super::Candidate<'a>>,
        mode: super::SelectionPlanMode,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'a> {
        super::ScoreSelectionPlan {
            mode,
            health_family: context.health_family,
            entries: candidates
                .into_iter()
                .map(|candidate| {
                    let attributions: Vec<_> = candidate
                        .attribution
                        .into_iter()
                        .map(|group| ScoreAttribution {
                            group: group.to_string(),
                            node_id: candidate.node.id,
                        })
                        .collect();
                    let selection_chain = candidate
                        .selection_chain
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let feedback = (!attributions.is_empty())
                        .then(|| {
                            ScoreFeedback::new(
                                Arc::clone(&self.score_state),
                                Arc::clone(&self.score_authority),
                                context.clone(),
                                attributions,
                            )
                        })
                        .filter(|_| self.score_state.is_current_authority(&self.score_authority));
                    super::ScoreSelectionEntry {
                        node: candidate.node,
                        feedback,
                        selection_chain,
                    }
                })
                .collect(),
        }
    }

    /// Target-aware, candidate-safe plan with attribution captured during
    /// recursive selection rather than recovered from the selected NodeId.
    pub fn selection_plan_for_target(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
    ) -> super::ScoreSelectionPlan<'_> {
        self.selection_plan_for_target_with_effects(
            group_name,
            context,
            super::SelectionEffects::Apply,
        )
    }

    fn selection_plan_for_target_with_effects(
        &self,
        group_name: &str,
        context: &ScoreSelectionContext,
        effects: super::SelectionEffects,
    ) -> super::ScoreSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return self.score_selection_plan(
                Vec::new(),
                super::SelectionPlanMode::Authoritative,
                context,
            );
        };
        if effects.applies() {
            self.mark_used(group_name);
        }
        let (mode, candidates) =
            self.selection_candidates_for_target(group, context, &mut Vec::new(), 0, effects, true);
        self.score_selection_plan(candidates, mode, context)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::group) fn selection_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        cold_urltest: bool,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>) {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return (super::SelectionPlanMode::Authoritative, Vec::new());
        }
        let (mut mode, mut candidates) = self.normal_candidates_for_target(
            group,
            context,
            visited,
            depth,
            effects,
            cold_urltest,
        );
        if candidates.is_empty()
            && let Some(member) = self.final_member(group)
        {
            // A business IPv6 target may use an IPv4 proxy. Defer this final
            // until the outer health-family retry has tried that ordinary path.
            if effects.health_fallback() && context.health_family == IpVersion::V6 {
                let mut ipv4 = context.clone();
                ipv4.health_family = IpVersion::V4;
                if !self
                    .normal_candidates_for_target(
                        group,
                        &ipv4,
                        visited,
                        depth,
                        effects.peek(),
                        cold_urltest,
                    )
                    .1
                    .is_empty()
                {
                    return (mode, candidates);
                }
            }
            match member {
                GroupMember::Node(node) => {
                    if matches!(
                        node.protocol(),
                        honk_config::types::NodeProtocol::Direct
                            | honk_config::types::NodeProtocol::Block
                    ) || self.is_node_selectable_for_domain(
                        node.id,
                        context.probe_domain,
                        context.health_family,
                    ) {
                        mode = super::SelectionPlanMode::Authoritative;
                        candidates.push(super::Candidate {
                            via: None,
                            node,
                            attribution: Vec::new(),
                            selection_chain: vec![node.name.as_str()],
                        });
                    }
                }
                GroupMember::Group(final_group) => {
                    if effects.applies() {
                        self.mark_used(&final_group.name);
                    }
                    visited.push(group.name.as_str());
                    (mode, candidates) = self.selection_candidates_for_target(
                        final_group,
                        context,
                        visited,
                        depth + 1,
                        effects,
                        cold_urltest,
                    );
                    visited.pop();
                    for candidate in &mut candidates {
                        candidate.via = Some(final_group);
                    }
                }
            }
        }
        for candidate in &mut candidates {
            if group.policy == honk_config::group::GroupPolicy::Score {
                candidate.attribution.insert(0, group.name.as_str());
            }
            candidate.selection_chain.insert(0, group.name.as_str());
        }
        (mode, candidates)
    }

    #[allow(clippy::too_many_arguments)]
    fn normal_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
        cold_urltest: bool,
    ) -> (super::SelectionPlanMode, Vec<super::Candidate<'a>>) {
        let selected_member = self.selector_member(group, context.network);
        let mut candidates =
            self.flatten_candidates_for_target(group, context, visited, depth, effects);
        let before_filter = (effects.applies()
            && group.policy == honk_config::group::GroupPolicy::Score
            && self.score_state.is_current_authority(&self.score_authority))
        .then(|| super::unique_candidate_ids(&candidates))
        .flatten();
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        if let Some(before_filter) = before_filter {
            self.score_state.record_dead_filtered(
                &self.score_authority,
                SelectionReasonKey::new(&group.name, context.network),
                super::removed_unique_candidate_count(before_filter, &candidates),
            );
        }
        if candidates.is_empty() {
            let candidate =
                self.last_resort_candidate_for_target(group, context, visited, depth, effects);
            let mode = if candidate.is_none()
                && cold_urltest
                && group.policy == honk_config::group::GroupPolicy::URLTest
            {
                super::SelectionPlanMode::ColdUrlTest
            } else {
                super::SelectionPlanMode::Authoritative
            };
            return (mode, candidate.into_iter().collect());
        }
        if cold_urltest
            && group.policy == honk_config::group::GroupPolicy::URLTest
            && !candidates.iter().any(|candidate| {
                self.node_latency(
                    candidate.node,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                    candidate.tag(),
                ) != Duration::MAX
            })
        {
            return (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
            );
        }
        let candidate = match group.policy {
            honk_config::group::GroupPolicy::Selector => selected_member
                .and_then(|member| Self::pick_selector(&candidates, member))
                .and_then(|picked| {
                    self.commit_selector_pick_for_target(
                        group, picked, context, visited, depth, effects,
                    )
                }),
            honk_config::group::GroupPolicy::URLTest => Some(self.pick_urltest(
                &candidates,
                group,
                context.network,
                context.health_family,
                effects,
            )),
            honk_config::group::GroupPolicy::LoadBalance => {
                Some(self.pick_load_balance(&candidates, group, context.network, effects))
            }
            honk_config::group::GroupPolicy::Fallback => {
                Some(self.pick_fallback(&candidates, group, context.network, effects))
            }
            honk_config::group::GroupPolicy::Score => {
                Some(self.pick_score(&candidates, group, context, effects))
            }
        };
        (
            super::SelectionPlanMode::Authoritative,
            candidate.into_iter().collect(),
        )
    }

    fn last_resort_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let selected_member = if group.policy == honk_config::group::GroupPolicy::Selector {
            Some(self.selector_member(group, context.network)?)
        } else {
            None
        };
        let node = self.last_resort_tcp_leaf(group, context.probe_domain, effects)?;
        if group.nodes.contains(&node.id)
            && selected_member.is_none_or(
                |member| matches!(member, GroupMember::Node(selected) if selected.id == node.id),
            )
        {
            return Some(super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            });
        }

        visited.push(group.name.as_str());
        let candidate = group.groups.iter().find_map(|tag| {
            if selected_member.is_some_and(
                |member| !matches!(member, GroupMember::Group(selected) if selected.name == *tag),
            ) {
                return None;
            }
            let subgroup = self.groups.get(tag)?;
            self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
                .filter(|candidate| candidate.node.id == node.id)
                .map(|mut candidate| {
                    candidate.via = Some(subgroup);
                    candidate
                })
        });
        visited.pop();
        candidate
    }

    pub(in crate::group) fn pick_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        self.selection_candidates_for_target(group, context, visited, depth, effects, false)
            .1
            .into_iter()
            .next()
    }

    /// Commit only the serving Selector subgroup; refusal cannot restore its stale peek.
    pub(in crate::group) fn commit_selector_pick_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        picked: super::Candidate<'a>,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        if !effects.applies() {
            return Some(picked);
        }
        let Some(sub) = picked.via else {
            return Some(picked);
        };
        self.mark_used(&sub.name);
        visited.push(group.name.as_str());
        let committed = self.pick_candidate_for_target(sub, context, visited, depth + 1, effects);
        visited.pop();
        let mut committed = committed?;
        committed.via = picked.via;
        Some(committed)
    }

    pub(in crate::group) fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &ScoreSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Vec<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        // Only the serving Selector member may advance nested policy state.
        let sub_effects =
            if group.policy == honk_config::group::GroupPolicy::Selector && effects.applies() {
                effects.peek()
            } else {
                effects
            };
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| super::Candidate {
                via: None,
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            })
            .collect();
        for tag in &group.groups {
            let Some(subgroup) = self.groups.get(tag.as_str()) else {
                continue;
            };
            if sub_effects.applies() {
                self.mark_used(tag);
            }
            if let Some(mut candidate) =
                self.pick_candidate_for_target(subgroup, context, visited, depth + 1, sub_effects)
            {
                candidate.via = Some(subgroup);
                candidates.push(candidate);
            }
        }
        visited.pop();
        candidates
    }

    /// Aggregate winner used by display/control surfaces.
    pub fn get_score_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let context = ScoreSelectionContext::aggregate(
            network,
            match network {
                SelectionNetwork::Tcp => ProbeDomain::Tcp,
                SelectionNetwork::Udp => ProbeDomain::DataUdp,
            },
            IpVersion::V4,
        );
        let mut visited = Vec::new();
        self.pick_candidate_for_target(
            group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        )
        .map(|candidate| candidate.tag().to_owned())
    }
}

#[test]
fn selector_commit_does_not_restore_a_stale_sibling() {
    use crate::alive::AliveDialerSet;
    use honk_config::group::{Group, GroupPolicy};
    use honk_config::node::Node;

    let nodes: Vec<_> = ["a", "b", "outside"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| Node {
            id: Uuid::from_u128(index as u128 + 1),
            name: name.into(),
            ..Default::default()
        })
        .collect();
    let groups = [
        Group {
            name: "child".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![nodes[0].id, nodes[1].id],
            ..Default::default()
        },
        Group {
            name: "parent".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![nodes[2].id],
            groups: vec!["child".into()],
            ..Default::default()
        },
    ];
    let mut results = Vec::new();
    for target_aware in [false, true] {
        for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp] {
            let alive = Arc::new(AliveDialerSet::new());
            for domain in [ProbeDomain::Tcp, ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                alive.report_unavailable_forced(nodes[1].id, domain, IpVersion::V4);
            }
            let manager = GroupManager::with_alive_set(&groups, &nodes, Some(alive));
            manager
                .set_selector_choice("parent", "child", crate::group::SelectorNetworks::Both)
                .unwrap();
            manager
                .set_selector_choice("child", "a", crate::group::SelectorNetworks::Both)
                .unwrap();
            let parent = &manager.groups["parent"];
            let selected_member = manager
                .selector_member(parent, SelectionNetwork::from_probe_domain(domain))
                .unwrap();
            let context = ScoreSelectionContext {
                target: Some(ScoreTarget::domain("commit.example", 443)),
                ..ScoreSelectionContext::aggregate(
                    SelectionNetwork::from_probe_domain(domain),
                    domain,
                    IpVersion::V4,
                )
            };
            let mut visited = Vec::new();
            let candidates = if target_aware {
                manager.flatten_candidates_for_target(
                    parent,
                    &context,
                    &mut visited,
                    0,
                    SelectionEffects::Apply,
                )
            } else {
                manager.flatten_candidates(
                    parent,
                    context.probe_domain,
                    context.health_family,
                    &mut visited,
                    0,
                    SelectionEffects::Apply,
                )
            };

            // A failed serving commit must not resurrect the child's old leaf.
            manager
                .set_selector_choice("child", "b", crate::group::SelectorNetworks::Both)
                .unwrap();
            let picked = GroupManager::pick_selector(&candidates, selected_member).unwrap();
            let committed = manager.commit_selector_pick_for_target(
                parent,
                picked,
                &context,
                &mut visited,
                0,
                SelectionEffects::Apply,
            );
            results.push(committed.map(|candidate| candidate.node.id));
        }
    }
    assert_eq!(
        results, [None; 4],
        "ordinary and target-aware commits must refuse"
    );
}
