use super::*;
use crate::transport_quality::{PressureReason, TransportPressure};

fn pressure_at(manager: &GroupManager, node_id: Uuid, family: IpVersion, at: Instant) {
    let mut observations = [None; 2];
    observations[family as usize] = Some(TransportPressure {
        observed_at: at,
        reason: PressureReason::Both,
    });
    manager.score_state.observe_carrier_pressure(
        &manager.score_authority,
        node_id,
        &["score".into()],
        true,
        observations,
        at,
    );
}

#[test]
fn carrier_pressure_reopens_only_budgeted_comparison_without_penalizing_business() {
    for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
        let nodes = [node("incumbent"), node("alternative")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let mut target = context("business.example", IpVersion::V4);
        target.network = network;
        target.probe_domain = if network == SelectionNetwork::Tcp {
            ProbeDomain::Tcp
        } else {
            ProbeDomain::DataUdp
        };
        let start = Instant::now();
        for leaf in &nodes {
            train_at(
                &manager,
                leaf,
                &target,
                20,
                Duration::from_millis(100),
                1,
                start,
            );
        }
        let ready = start + Duration::from_secs(2);
        for _ in 0..16 {
            assert_eq!(rank_at(&manager, &nodes, &target, ready), 0);
        }
        let state = manager.score_state();
        let at = ready + Duration::from_secs(1);
        let before = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
        assert_eq!(
            state
                .selection_reason_counts("score", network)
                .periodic_explore,
            0
        );
        pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
        pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
        let after = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
        assert_close(after.completed, before.completed);
        assert_close(after.useful_completed, before.useful_completed);
        assert_close(after.reliability, before.reliability);
        assert_eq!(after.fail_streak, before.fail_streak);
        assert_eq!(after.explore_backed_off, before.explore_backed_off);
        assert_eq!(after.qualified(), before.qualified());
        let refs = nodes.iter().collect::<Vec<_>>();
        let counters = state.selection_reason_counts("score", network);
        for _ in 0..10 {
            assert_eq!(state.peek_rank("score", &target, &refs), 0);
        }
        assert_eq!(state.selection_reason_counts("score", network), counters);
        assert_eq!(counters.carrier_pressure, 1);
        assert_eq!(rank_at(&manager, &nodes, &target, at), 1);
        let validated = state.selection_reason_counts("score", network);
        assert_eq!(validated.periodic_explore, 1);
        assert_eq!(validated.carrier_validation, 1);
        assert_eq!(validated.ordinary_switch, 0);
        for _ in 0..15 {
            pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
            assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
        }
        let bounded = state.selection_reason_counts("score", network);
        assert_eq!(bounded.periodic_explore, 1);
        assert_eq!(bounded.carrier_pressure, 1);
        assert_eq!(bounded.ordinary_switch, 0);
        // A successful measurement, not the hint, earns ordinary promotion.
        train_at(
            &manager,
            &nodes[1],
            &target,
            4,
            Duration::from_millis(10),
            1,
            at,
        );
        assert_eq!(
            rank_at(&manager, &nodes, &target, at + Duration::from_secs(1)),
            1
        );
        assert_eq!(
            state
                .selection_reason_counts("score", network)
                .ordinary_switch,
            1
        );
    }
}

#[test]
fn carrier_pressure_is_owner_scoped_expiring_and_cannot_create_flow_evidence() {
    let nodes = [node("one"), node("two")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    pressure_at(&manager, nodes[0].id, IpVersion::V4, start);
    assert_eq!(manager.score_cache_snapshot().aggregate_cells, 0);
    let target = context("family.example", IpVersion::V6);
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100),
            1,
            start,
        );
    }
    let at = start + Duration::from_secs(2);
    pressure_at(&manager, nodes[0].id, IpVersion::V4, at);
    let state = manager.score_state();
    let score = |context: &ScoreSelectionContext, now| {
        score_snapshot(&state.inner.lock(), "score", context, nodes[0].id, now)
    };
    assert_eq!(score(&target, at).carrier_pressure_at, Some(at));
    let mut other_carrier_family = target.clone();
    other_carrier_family.health_family = IpVersion::V6;
    assert_eq!(
        score(&other_carrier_family, at).carrier_pressure_at,
        Some(at)
    );
    let expired = at + CARRIER_PRESSURE_TTL;
    assert!(score(&target, expired).carrier_pressure_at.is_none());
    let reasons = state.selection_reason_counts("score", target.network);
    let late = [
        Some(TransportPressure {
            observed_at: at,
            reason: PressureReason::Loss,
        }),
        None,
    ];
    state.observe_carrier_pressure(
        &manager.score_authority,
        nodes[0].id,
        &["score".into()],
        true,
        late,
        expired,
    );
    assert_eq!(
        state.selection_reason_counts("score", target.network),
        reasons
    );
}

#[test]
fn replaced_runtime_and_retired_manager_cannot_publish_carrier_pressure() {
    let leaf = Node::from_share_link("socks5://127.0.0.1:1080#old").unwrap();
    let groups = [group("score", std::slice::from_ref(&leaf))];
    let old_runtimes =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&leaf)).unwrap();
    let old = GroupManager::new(&groups, std::slice::from_ref(&leaf));
    old.bind_transport_quality(&old_runtimes);
    let target = context("reload.example", IpVersion::V4);
    train_at(
        &old,
        &leaf,
        &target,
        20,
        Duration::from_millis(1),
        1,
        Instant::now() - Duration::from_secs(2),
    );
    let mut renamed = leaf.clone();
    renamed.name = "replacement".into();
    let (new_runtimes, reused) = crate::runtime::OutboundRuntimeRegistry::build_reusing(
        std::slice::from_ref(&renamed),
        64,
        Some(&old_runtimes),
    )
    .unwrap();
    assert!(reused.is_empty());
    let replacement =
        GroupManager::with_alive_set_and_score_state(&groups, &[renamed], None, old.score_state());
    replacement.bind_transport_quality(&new_runtimes);
    replacement.publish_score_membership();
    let old_quality = old_runtimes.get(&leaf.id).unwrap().transport_quality();
    old_quality.report(false, PressureReason::Loss, Instant::now());
    old.observe_transport_quality();
    replacement.observe_transport_quality();
    assert_eq!(
        replacement
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        0
    );
    new_runtimes
        .get(&leaf.id)
        .unwrap()
        .transport_quality()
        .report(false, PressureReason::Loss, Instant::now());
    replacement.observe_transport_quality();
    assert_eq!(
        replacement
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        1
    );
    let successor = GroupManager::with_alive_set_and_score_state(
        &groups,
        std::slice::from_ref(&leaf),
        None,
        old.score_state(),
    );
    successor.bind_transport_quality(&new_runtimes);
    successor.publish_score_membership();
    successor.observe_transport_quality();
    assert_eq!(
        successor
            .score_state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .carrier_pressure,
        1
    );
    assert!(
        score_snapshot(
            &successor.score_state.inner.lock(),
            "score",
            &target,
            leaf.id,
            Instant::now()
        )
        .carrier_pressure_at
        .is_none()
    );
}

#[test]
fn shadowsocks_tcp_pressure_does_not_spend_native_udp_validation() {
    let leaf = Node::from_share_link("ss://YWVzLTEyOC1nY206cGFzcw@127.0.0.1:8388#carrier").unwrap();
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let runtimes = crate::runtime::OutboundRuntimeRegistry::build(nodes).unwrap();
    manager.bind_transport_quality(&runtimes);
    let tcp = context("same-node.example", IpVersion::V4);
    let mut udp = tcp.clone();
    udp.network = SelectionNetwork::Udp;
    udp.probe_domain = ProbeDomain::DataUdp;
    for target in [&tcp, &udp] {
        train_at(
            &manager,
            &leaf,
            target,
            20,
            Duration::from_millis(10),
            1,
            Instant::now() - Duration::from_secs(2),
        );
    }
    runtimes.get(&leaf.id).unwrap().transport_quality().report(
        false,
        PressureReason::Loss,
        Instant::now(),
    );
    manager.observe_transport_quality();
    let state = manager.score_state();
    let inner = state.inner.lock();
    assert!(
        score_snapshot(&inner, "score", &tcp, leaf.id, Instant::now())
            .carrier_pressure_at
            .is_some()
    );
    assert!(
        score_snapshot(&inner, "score", &udp, leaf.id, Instant::now())
            .carrier_pressure_at
            .is_none()
    );
    drop(inner);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Udp)
            .carrier_pressure,
        0
    );
}
