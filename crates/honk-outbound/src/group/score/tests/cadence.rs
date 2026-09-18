use super::*;

#[test]
fn overlapping_layers_count_each_terminal_completion_once() {
    let leaf = node("only");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("counts.example", IpVersion::V4);
    for _ in 0..3 {
        finish_success(&manager.selection_plan_for_target("score", &target));
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        Instant::now(),
    );
    assert!((score.completed - 3.0).abs() < 0.001);
    assert!((score.useful_completed - 3.0).abs() < 0.001);
    assert!((score.hysteresis_completed - 3.0).abs() < 0.001);
}

#[test]
fn settled_cohorts_stop_sampling_and_expiry_restores_bounded_coverage() {
    for count in [2, 3, 4, 8, 32] {
        let nodes: Vec<_> = (0..count).map(|i| node(&format!("node-{i}"))).collect();
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
        let now = Instant::now();
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                20,
                Duration::from_millis(if index == 0 { 10 } else { 600 }),
                1,
                now,
            );
        }
        let period = exploration_period(count);
        for _ in 0..period * count as u64 {
            assert_eq!(
                rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
                0
            );
        }
        assert_eq!(
            manager
                .score_state()
                .verification_counters("score", SelectionNetwork::Tcp)
                .validation_selections,
            0
        );
        let mut trials = std::collections::HashSet::new();
        let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
        for request in 0..period * (count as u64 - 1) {
            let index = rank_at(&manager, &nodes, &target, expired);
            if request.is_multiple_of(period) {
                assert_ne!(index, 0);
                trials.insert(index);
            } else {
                assert_eq!(index, 0);
            }
        }
        assert_eq!(trials.len(), count - 1);
        let reasons = manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(reasons.periodic_explore, count as u64 - 1);
        assert_eq!(reasons.cold_explore, 0);
    }
}

#[test]
fn new_targets_cannot_mint_exploration_and_peek_cannot_spend_it() {
    let nodes: Vec<_> = (0..8).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let now = Instant::now();
    let state = manager.score_state();
    for request in 0..64 {
        let target = context(&format!("{request}.example"), IpVersion::V4);
        let before = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        for _ in 0..10 {
            state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>());
        }
        assert_eq!(
            state.selection_reason_counts("score", SelectionNetwork::Tcp),
            before
        );
        let index = rank_at(&manager, &nodes, &target, now);
        train_at(
            &manager,
            &nodes[index],
            &target,
            1,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert!(reasons.cold_explore <= exploration_target(nodes.len()) as u64);
    assert!(reasons.periodic_explore <= 64 / exploration_period(nodes.len()));
    assert_eq!(state.inner.lock().selection_counts.len(), 1);
}

#[test]
fn sparse_traffic_revalidates_on_time_without_minting_burst_trials() {
    let nodes: Vec<_> = (0..32).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    assert_ne!(rank_at(&manager, &nodes, &target, expired), 0);
    let before = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(before.periodic_explore, 1);
    for _ in 0..15 {
        rank_at(&manager, &nodes, &target, expired);
    }
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .periodic_explore,
        before.periodic_explore,
    );
    rank_at(&manager, &nodes, &target, expired + REVALIDATION_INTERVAL);
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .periodic_explore,
        before.periodic_explore + 1,
    );
}

#[test]
fn expired_backoff_gets_bounded_recovery_despite_normal_exclusion() {
    let nodes = [node("working"), node("failed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    for _ in 0..3 {
        manager
            .feedback_for_group_node("score", nodes[1].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    for _ in 0..32 {
        assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    }
    let expired = now + SCORE_EXPLORE_BACKOFF_BASE * 4 + Duration::from_secs(1);
    assert_eq!(rank_at(&manager, &nodes, &target, expired), 1);
    assert_eq!(rank_at(&manager, &nodes, &target, expired), 0);
}

#[test]
fn all_failing_fallback_remains_selectable() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        for _ in 0..3 {
            manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now)
                .finish_at(ScoreOutcome::Timeout, true, now);
        }
    }
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
}

#[test]
fn source_outcomes_do_not_forgive_traffic_backoff() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for _ in 0..2 {
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    for source in [ScoreSource::HealthProbe, ScoreSource::Warmup] {
        probe_at(
            &manager,
            &nodes[0],
            &target,
            source,
            Duration::from_millis(1),
            now,
        );
        manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .with_source(source)
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        now + SCORE_EXPLORE_BACKOFF_BASE,
    );
    assert_eq!(score.fail_streak, 2);
    assert!(score.explore_backed_off);
}

#[test]
fn latency_degradation_revalidation_cannot_bypass_exposure_budget() {
    let nodes: Vec<_> = (0..32).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(if index == 0 { 10 } else { 600 }),
            1,
            now,
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    train_at(
        &manager,
        &nodes[0],
        &target,
        1,
        Duration::from_millis(100),
        1,
        now + Duration::from_secs(3),
    );
    for _ in 1..15 {
        assert_eq!(
            rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
            0
        );
    }
    assert_ne!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .periodic_explore,
        1
    );
}

#[test]
fn periodic_exploration_is_scoped_by_network_and_family() {
    let nodes = [node("a"), node("b")];
    let manager = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let targeted = |network, family| ScoreSelectionContext {
        network,
        probe_domain: if network == SelectionNetwork::Tcp {
            ProbeDomain::Tcp
        } else {
            ProbeDomain::DataUdp
        },
        target_family: Some(family),
        health_family: family,
        target: Some(ScoreTarget::domain("target.example", 443)),
    };
    let aggregate = |network| {
        ScoreSelectionContext::aggregate(
            network,
            if network == SelectionNetwork::Tcp {
                ProbeDomain::Tcp
            } else {
                ProbeDomain::DataUdp
            },
            IpVersion::V4,
        )
    };
    let contexts = [
        targeted(SelectionNetwork::Tcp, IpVersion::V4),
        targeted(SelectionNetwork::Tcp, IpVersion::V6),
        targeted(SelectionNetwork::Udp, IpVersion::V4),
        targeted(SelectionNetwork::Udp, IpVersion::V6),
        aggregate(SelectionNetwork::Tcp),
        aggregate(SelectionNetwork::Udp),
    ];
    for context in &contexts {
        let _ = manager.selection_plan_for_target("score", context);
    }
    let state = manager.score_state();
    assert_eq!(state.inner.lock().selection_counts.len(), 6);
    println!(
        "cadence scope cardinality={}",
        state.inner.lock().selection_counts.len()
    );

    let tcp_v4_key = SelectionCadenceKey::new("score", &contexts[0]);
    state
        .inner
        .lock()
        .selection_counts
        .get_mut(&tcp_v4_key)
        .unwrap()
        .count = exploration_period(nodes.len()) - 1;
    let _ = manager.selection_plan_for_target("score", &contexts[2]);
    assert_eq!(
        state.inner.lock().selection_counts[&tcp_v4_key].count,
        exploration_period(nodes.len()) - 1,
        "UDP-V4 must not consume TCP-V4 cadence"
    );
    let _ = manager.selection_plan_for_target("score", &contexts[0]);
    assert_eq!(
        state.inner.lock().selection_counts[&tcp_v4_key].count,
        exploration_period(nodes.len())
    );

    let different_target = context("other.example", IpVersion::V4);
    let _ = manager.selection_plan_for_target("score", &different_target);
    assert_eq!(state.inner.lock().selection_counts.len(), 6);
}

#[test]
fn selection_count_reload_lifecycle_matches_group_name() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("reload.example", IpVersion::V4);
    let _ = old.selection_plan_for_target("score", &context);
    let state = old.score_state();
    let before: u64 = state
        .inner
        .lock()
        .selection_counts
        .values()
        .map(|cadence| cadence.count)
        .sum();

    let empty = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &[])],
        &[],
        None,
        Arc::clone(&state),
    );
    empty.publish_score_membership();
    assert_eq!(
        state
            .inner
            .lock()
            .selection_counts
            .values()
            .map(|cadence| cadence.count)
            .sum::<u64>(),
        before,
        "a committed group name retains cadence through zero leaves"
    );

    let mut selector = group("score", &nodes);
    selector.policy = GroupPolicy::Selector;
    let non_score = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[selector],
        &nodes,
        None,
        Arc::clone(&state),
    );
    non_score.publish_score_membership();
    assert_eq!(
        state
            .inner
            .lock()
            .selection_counts
            .values()
            .map(|cadence| cadence.count)
            .sum::<u64>(),
        before,
        "a surviving name retains cadence through Score to non-Score"
    );

    let removed = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &[],
        None,
        Arc::clone(&state),
    );
    removed.publish_score_membership();
    assert!(state.inner.lock().selection_counts.is_empty());
}

#[test]
fn cancelled_cold_trials_keep_alternative_coverage() {
    let nodes = [node("winner"), node("cold-b"), node("cold-c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(100),
        1,
        now,
    );
    let state = manager.score_state();
    let mut trials = std::collections::HashSet::new();
    let requests = exploration_target(nodes.len()) as u64 + exploration_period(nodes.len()) * 2;
    for _ in 0..requests {
        let before = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        let index = rank_at(&manager, &nodes, &target, now + Duration::from_secs(2));
        let after = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        if after.periodic_explore > before.periodic_explore {
            trials.insert(index);
        }
        if index != 0 {
            manager
                .feedback_for_group_node("score", nodes[index].id, target.clone())
                .unwrap()
                .start_at(now)
                .finish_at(ScoreOutcome::Cancelled, true, now);
        }
    }
    assert_eq!(trials, std::collections::HashSet::from([1, 2]));
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.periodic_explore, 2);
    for leaf in &nodes[1..] {
        let score = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now);
        assert_eq!(
            (score.attempts, score.completed, score.failures),
            (0.0, 0.0, 0.0)
        );
    }
}

#[test]
fn qualified_trial_does_not_replace_committed_incumbent_without_new_evidence() {
    let nodes = [node("incumbent"), node("near-equal-trial")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([100, 105]) {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(latency),
            1,
            now,
        );
    }
    let mut at = now + Duration::from_secs(2);
    for _ in 1..exploration_period(nodes.len()) {
        assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    }
    at += PERFORMANCE_MAX_AGE;
    assert_eq!(rank_at(&manager, &nodes, &target, at), 1);
    manager
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(100),
        1,
        at,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(50),
        1,
        at,
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, at + Duration::from_secs(1)),
        1
    );
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .periodic_explore,
        1
    );
}

#[test]
fn first_normal_selection_uses_quality_not_the_last_startup_trial() {
    let nodes = [node("better"), node("last-trial")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("startup.example", IpVersion::V4);
    let now = Instant::now();
    for (index, latency) in [100, 105].into_iter().enumerate() {
        assert_eq!(rank_at(&manager, &nodes, &target, now), index);
        train_at(
            &manager,
            &nodes[index],
            &target,
            20,
            Duration::from_millis(latency),
            1,
            now,
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
}

#[test]
fn real_success_steps_down_failure_backoff_instead_of_resetting_the_streak() {
    let leaf = node("recovering");
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let target = context("recovery.example", IpVersion::V4);
    let feedback = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let now = Instant::now();
    for _ in 0..2 {
        feedback
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let success = feedback.start_at(now);
    success.setup_succeeded_at(now);
    success.transfer_at(1, 1, now);
    success.finish_at(ScoreOutcome::Success, true, now);
    let state = manager.score_state();
    let recovered = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now);
    assert_eq!(recovered.fail_streak, 1);
    assert!(!recovered.explore_backed_off);

    feedback
        .start_at(now)
        .finish_at(ScoreOutcome::Timeout, true, now);
    let until = now + SCORE_EXPLORE_BACKOFF_BASE * 2;
    let before = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        until - Duration::from_nanos(1),
    );
    let expired = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, until);
    assert_eq!(expired.fail_streak, 2);
    assert!(before.explore_backed_off);
    assert!(!expired.explore_backed_off);
}
