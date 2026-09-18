use super::*;

#[test]
fn split_selector_drives_routes_peeks_score_finals_and_warmth() {
    let a = make_node(nid("network-a"), "a");
    let b = make_node(nid("network-b"), "b");
    let child = make_group("child", GroupPolicy::Selector, vec![a.id, b.id]);
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["child"]);
    let score = make_subgroup("score", GroupPolicy::Score, &["child"]);
    let mut final_group = make_group("final", GroupPolicy::Fallback, Vec::new());
    final_group.final_outbound = Some("child".into());
    let alive = Arc::new(AliveDialerSet::new());
    let manager = GroupManager::with_alive_set(
        &[child, parent, score, final_group],
        &[a.clone(), b.clone()],
        Some(alive.clone()),
    );
    assert_eq!(
        manager.set_selector_choice("child", "b", SelectorNetworks::Tcp),
        Ok(1)
    );

    for (network, domain, expected) in [
        (SelectionNetwork::Tcp, ProbeDomain::Tcp, b.id),
        (SelectionNetwork::Udp, ProbeDomain::DataUdp, a.id),
    ] {
        for group in ["child", "parent", "score", "final"] {
            let context = ScoreSelectionContext::aggregate(network, domain, IpVersion::V4);
            assert_eq!(
                manager
                    .select_node_for_domain(group, domain, IpVersion::V4)
                    .map(|node| node.id),
                Some(expected)
            );
            assert_eq!(
                manager
                    .peek_selection_plan_for_domain(group, domain, IpVersion::V4)
                    .nodes
                    .iter()
                    .map(|node| node.id)
                    .collect::<Vec<_>>(),
                [expected]
            );
            let plan = manager.selection_plan_for_target(group, &context);
            assert_eq!(
                plan.entries
                    .iter()
                    .map(|entry| entry.node.id)
                    .collect::<Vec<_>>(),
                [expected]
            );
            assert_eq!(
                plan.entries[0].selection_chain.last().unwrap(),
                if expected == a.id { "a" } else { "b" }
            );
        }
        assert_eq!(
            manager
                .selector_warm_node("parent", network)
                .map(|node| node.id),
            Some(expected)
        );
        assert_eq!(
            manager.selection_chain_for_network("parent", network),
            ["parent", "child", if expected == a.id { "a" } else { "b" }]
        );
        #[cfg(feature = "native-api")]
        assert_eq!(
            manager
                .native_selection("parent", network)
                .and_then(|selection| selection.leaf)
                .map(|node| node.id),
            Some(expected)
        );
    }

    alive.report_unavailable_forced(b.id, ProbeDomain::Tcp, IpVersion::V4);
    for group in ["child", "parent", "score", "final"] {
        assert!(
            manager
                .select_node_for_domain(group, ProbeDomain::Tcp, IpVersion::V4)
                .is_none()
        );
        assert!(
            manager
                .peek_selection_plan_for_domain(group, ProbeDomain::Tcp, IpVersion::V4)
                .nodes
                .is_empty()
        );
        assert_eq!(
            manager
                .select_node_for_domain(group, ProbeDomain::DataUdp, IpVersion::V4)
                .map(|node| node.id),
            Some(a.id)
        );
    }
    assert_eq!(
        manager
            .selector_warm_node("parent", SelectionNetwork::Tcp)
            .map(|node| node.id),
        Some(b.id)
    );
    assert_eq!(
        manager.selector_choices("child").unwrap(),
        SelectorChoices {
            tcp: Some(SelectorMember::Node(b.id)),
            udp: Some(SelectorMember::Node(a.id)),
            revision: 1,
        }
    );
}

#[test]
fn udp_choice_cannot_open_tcp_empty_path_or_replace_sole_dead_leaf() {
    let leaf = make_node(nid("split-sole"), "leaf");
    let empty = make_group("empty", GroupPolicy::Selector, Vec::new());
    let mut selector = make_subgroup("selector", GroupPolicy::Selector, &["empty"]);
    selector.nodes.push(leaf.id);
    selector.default = Some("empty".into());
    let parent = make_subgroup("parent", GroupPolicy::Selector, &["selector"]);
    let alive = Arc::new(AliveDialerSet::new());
    alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
    let manager = GroupManager::with_alive_set(
        &[empty, selector, parent],
        std::slice::from_ref(&leaf),
        Some(alive),
    );
    manager
        .set_selector_choice("selector", "leaf", SelectorNetworks::Udp)
        .unwrap();
    assert!(manager.select_node("parent").is_none());
    assert!(
        manager
            .peek_selection_plan_for_domain("parent", ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .is_empty()
    );
    manager
        .set_selector_choice("selector", "leaf", SelectorNetworks::Tcp)
        .unwrap();
    assert_eq!(
        manager.select_node("parent").map(|node| node.id),
        Some(leaf.id)
    );
    assert!(
        manager
            .select_node_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
            .is_none()
    );
}

#[test]
fn selector_validates_before_atomic_publish_and_defers_effects() {
    let a = make_node(nid("atomic-a"), "a");
    let b = make_node(nid("atomic-b"), "b");
    let mut group = make_group("g", GroupPolicy::Selector, vec![a.id, b.id]);
    group.interrupt_connections = true;
    let automatic = make_group("automatic", GroupPolicy::URLTest, vec![a.id, b.id]);
    let manager = Arc::new(GroupManager::new(
        &[group, automatic],
        &[a.clone(), b.clone()],
    ));
    let persisted = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let calls = Arc::clone(&persisted);
    manager.set_persist_callback(Some(Arc::new(move |_, network, member| {
        calls.lock().push((network, member.clone()));
    })));
    let interrupted = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let calls = Arc::clone(&interrupted);
    manager.set_interrupt_callback(Some(Arc::new(move |_, network| calls.lock().push(network))));
    let wakeups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = Arc::clone(&wakeups);
    let weak = Arc::downgrade(&manager);
    manager.set_selector_change_callback(Some(Arc::new(move || {
        let manager = weak.upgrade().unwrap();
        let choices = manager.selector_choices("g").unwrap();
        assert_eq!(choices.tcp, choices.udp);
        manager.set_selector_change_callback(None);
        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })));
    let first = manager
        .publish_selector_choice("g", &SelectorMember::Node(b.id), SelectorNetworks::Both)
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(
        first.changed_networks,
        [SelectionNetwork::Tcp, SelectionNetwork::Udp]
    );
    assert!(persisted.lock().is_empty());
    assert!(interrupted.lock().is_empty());
    first.run_callbacks();
    assert_eq!(
        *persisted.lock(),
        [
            (SelectionNetwork::Tcp, SelectorMember::Node(b.id)),
            (SelectionNetwork::Udp, SelectorMember::Node(b.id))
        ]
    );
    assert_eq!(
        *interrupted.lock(),
        [SelectionNetwork::Tcp, SelectionNetwork::Udp]
    );
    assert_eq!(wakeups.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        manager.set_selector_choice("g", "b", SelectorNetworks::Both),
        Ok(1)
    );
    assert_eq!(persisted.lock().len(), 2);
    assert_eq!(
        manager.set_selector_choice("g", "a", SelectorNetworks::Udp),
        Ok(2)
    );
    let before = manager.selector_choices("g").unwrap();
    for (group, member, error) in [
        (
            "g",
            SelectorMember::Node(nid("outside")),
            SelectorError::NotMember,
        ),
        (
            "g",
            SelectorMember::Group("a".into()),
            SelectorError::NotMember,
        ),
        (
            "automatic",
            SelectorMember::Node(a.id),
            SelectorError::NotSelector,
        ),
        (
            "missing",
            SelectorMember::Node(a.id),
            SelectorError::GroupNotFound,
        ),
    ] {
        assert_eq!(
            manager
                .publish_selector_choice(group, &member, SelectorNetworks::Both)
                .err(),
            Some(error)
        );
        assert_eq!(manager.selector_choices("g").unwrap(), before);
    }
    assert_eq!(persisted.lock().len(), 3);
    assert_eq!(
        manager.set_selector_choice("g", "a", SelectorNetworks::Both),
        Ok(3)
    );
    assert_eq!(
        persisted.lock().last(),
        Some(&(SelectionNetwork::Tcp, SelectorMember::Node(a.id)))
    );
}

#[test]
fn exact_selector_identity_survives_duplicate_tags_and_reload() {
    let first = make_node(nid("identity-first"), "same");
    let second = make_node(nid("identity-second"), "same");
    let leaf = make_node(nid("identity-leaf"), "leaf");
    let subgroup = make_group("same", GroupPolicy::Selector, vec![leaf.id]);
    let mut parent = make_group("parent", GroupPolicy::Selector, vec![first.id, second.id]);
    parent.groups.push("same".into());
    let nodes = [first.clone(), second.clone(), leaf.clone()];
    let manager = GroupManager::new(&[subgroup.clone(), parent.clone()], &nodes);
    assert_eq!(
        manager.selector_member_by_name("parent", "same"),
        Ok(SelectorMember::Node(first.id))
    );
    manager
        .publish_selector_choice(
            "parent",
            &SelectorMember::Node(second.id),
            SelectorNetworks::Tcp,
        )
        .unwrap()
        .run_callbacks();
    manager
        .publish_selector_choice(
            "parent",
            &SelectorMember::Group("same".into()),
            SelectorNetworks::Udp,
        )
        .unwrap()
        .run_callbacks();
    assert_eq!(
        manager.select_node("parent").map(|node| node.id),
        Some(second.id)
    );
    assert_eq!(
        manager
            .select_node_for_domain("parent", ProbeDomain::DataUdp, IpVersion::V4)
            .map(|node| node.id),
        Some(leaf.id)
    );
    assert_eq!(
        manager
            .selector_warm_node("parent", SelectionNetwork::Tcp)
            .map(|node| node.id),
        Some(second.id)
    );
    assert_eq!(
        manager
            .selector_warm_node("parent", SelectionNetwork::Udp)
            .map(|node| node.id),
        Some(leaf.id)
    );
    #[cfg(feature = "native-api")]
    {
        assert!(
            matches!(manager.native_selection("parent", SelectionNetwork::Tcp).unwrap().member, NativeGroupMember::Node(node) if node.id == second.id)
        );
        assert!(
            matches!(manager.native_selection("parent", SelectionNetwork::Udp).unwrap().member, NativeGroupMember::Group(group) if group.name == "same")
        );
    }
    parent.nodes.reverse();
    let mut renamed = second.clone();
    renamed.name = "renamed".into();
    let replacement = GroupManager::new(
        &[subgroup.clone(), parent.clone()],
        &[first.clone(), renamed, leaf.clone()],
    );
    replacement.migrate_selector_choices_from(&manager);
    assert_eq!(
        replacement.select_node("parent").map(|node| node.id),
        Some(second.id)
    );
    assert_eq!(
        replacement.selector_choices("parent"),
        manager.selector_choices("parent")
    );
    parent.nodes.retain(|id| *id != second.id);
    let removed = GroupManager::new(&[subgroup, parent], &[first, leaf]);
    removed.migrate_selector_choices_from(&replacement);
    assert_eq!(
        removed.get_selector_choice("parent", SelectionNetwork::Tcp),
        None
    );
    assert_eq!(
        removed.selector_member_choice("parent", SelectionNetwork::Udp),
        Some(SelectorMember::Group("same".into()))
    );
}

#[test]
fn selecting_effective_default_pins_identity_across_member_reorder() {
    let a = make_node(nid("explicit-default-a"), "a");
    let b = make_node(nid("explicit-default-b"), "b");
    let mut group = make_group("g", GroupPolicy::Selector, vec![a.id, b.id]);
    let manager = GroupManager::new(std::slice::from_ref(&group), &[a.clone(), b.clone()]);
    manager
        .set_selector_choice("g", "a", SelectorNetworks::Tcp)
        .unwrap();
    group.nodes.reverse();
    let replacement = GroupManager::new(&[group], &[a.clone(), b.clone()]);
    replacement.migrate_selector_choices_from(&manager);
    assert_eq!(replacement.select_node("g").map(|node| node.id), Some(a.id));
    assert_eq!(
        replacement
            .select_node_for_domain("g", ProbeDomain::DataUdp, IpVersion::V4)
            .map(|node| node.id),
        Some(b.id)
    );
}
