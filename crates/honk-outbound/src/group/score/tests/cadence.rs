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
}

#[test]
fn settled_cohorts_stop_sampling_and_expiry_spends_only_business_funding() {
    let nodes: Vec<_> = (0..8).map(|i| node(&format!("node-{i}"))).collect();
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
    let state = manager.score_state();
    for _ in 0..32 {
        let (index, feedback) = state.rank_plan_at(
            "score",
            &target,
            &nodes.iter().collect::<Vec<_>>(),
            now + Duration::from_secs(2),
        );
        assert_eq!(index, 0);
        feedback
            .begin_at(now + Duration::from_secs(2))
            .unwrap()
            .start_at(now + Duration::from_secs(2))
            .finish_at(ScoreOutcome::Cancelled, false, now + Duration::from_secs(2));
    }
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        0
    );
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let mut sampled = std::collections::HashSet::new();
    for _ in 0..128 {
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (index, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), expired);
        feedback
            .begin_at(expired)
            .unwrap()
            .start_at(expired)
            .finish_at(ScoreOutcome::Cancelled, false, expired);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        if after.trial_starts > before.trial_starts {
            sampled.insert(index);
        }
        assert!(
            after.spent + after.reserved
                <= after.cold_allowance + after.business_starts / after.earning_period
        );
    }
    assert!(
        sampled.len() > 1,
        "unfinished questions rotate across real business offers"
    );
}

#[test]
fn new_targets_cannot_mint_exploration_and_peek_cannot_spend_it() {
    let nodes: Vec<_> = (0..8).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let now = Instant::now();
    let state = manager.score_state();
    for request in 0..64 {
        let target = context(&format!("{request}.example"), IpVersion::V4);
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        for _ in 0..10 {
            state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>());
        }
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            before
        );
        let (_, feedback) =
            state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now);
        feedback.begin_at(now).unwrap().start_at(now).finish_at(
            ScoreOutcome::Cancelled,
            false,
            now,
        );
    }
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.business_starts, 64);
    assert_eq!(counts.scopes, 1);
    assert!(
        counts.spent
            <= exploration_target(nodes.len()) as u64 + 63 / exploration_period(nodes.len())
    );
}

#[test]
fn sparse_selection_without_started_business_cannot_earn_currency() {
    let nodes: Vec<_> = (0..32).map(|i| node(&format!("node-{i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for hour in 0..128 {
        rank_at(
            &manager,
            &nodes,
            &target,
            now + Duration::from_secs(hour * 3600),
        );
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            (
                counts.business_starts,
                counts.spent,
                counts.reserved,
                counts.earned_available
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            counts.cold_available,
            exploration_target(nodes.len()) as u64
        );
    }
}

#[test]
fn expired_backoff_gets_bounded_recovery_despite_normal_exclusion() {
    let nodes = [node("working"), node("failed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let aggregate = ScoreSelectionContext {
        target: None,
        target_family: None,
        ..target.clone()
    };
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
    let state = manager.score_state();
    let node_refs = [&nodes[0], &nodes[1]];
    for _ in 0..32 {
        let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, now);
        assert_eq!(index, 0);
        feedback.begin_at(now).unwrap().start_at(now).finish_at(
            ScoreOutcome::Cancelled,
            false,
            now,
        );
        assert_eq!(rank_at(&manager, &nodes, &aggregate, now), 0);
    }
    let expired = now + SCORE_EXPLORE_BACKOFF_BASE * 4 + Duration::from_secs(1);
    let mut active = Vec::new();
    for leaf in &nodes {
        let feedback = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap();
        for _ in 0..4 {
            let reporter = feedback.start_at(expired);
            reporter.setup_succeeded_at(expired);
            reporter.transfer_at(1, 1, expired);
            active.push(reporter);
        }
        probe_at(
            &manager,
            leaf,
            &target,
            ScoreSource::HealthProbe,
            Duration::from_millis(100),
            expired,
        );
    }
    let recovered = manager
        .score_state()
        .verification_snapshot_at("score", &aggregate, &[&nodes[1]], expired)
        .unwrap();
    assert_eq!(recovered.state, ScoreVerificationState::ObservedUsable);
    for reporter in active {
        reporter.finish_at(ScoreOutcome::Cancelled, true, expired);
    }
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, expired);
    assert_eq!(index, 1);
    let reporter = feedback.begin_at(expired).unwrap().start_at(expired);
    assert_eq!(rank_at(&manager, &nodes, &target, expired), 0);
    assert_eq!(rank_at(&manager, &nodes, &aggregate, expired), 0);
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.trial_starts, before.trial_starts + 1);
    assert!(
        after.trial_starts + after.reserved
            <= after.cold_allowance + after.business_starts / after.earning_period
    );
    reporter.finish_at(ScoreOutcome::Cancelled, false, expired);
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
    let state = manager.score_state();
    let node_refs = nodes.iter().collect::<Vec<_>>();
    let at = now + Duration::from_secs(4);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    for _ in 0..128 {
        let (_, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
        feedback
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, false, at);
        let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(
            counts.trial_starts + counts.reserved
                <= counts.cold_allowance + counts.business_starts / counts.earning_period
        );
    }
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts + 128);
    assert!(after.trial_starts > before.trial_starts);
    assert_eq!(after.trial_cancelled, after.trial_starts);
    assert_eq!(after.refunded, before.refunded);
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
    let node_refs = nodes.iter().collect::<Vec<_>>();
    let at = now + Duration::from_secs(2);
    for _ in 0..requests {
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
        feedback
            .begin_at(at)
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, true, at);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        if after.trial_starts > before.trial_starts {
            trials.insert(index);
        }
        assert!(
            after.trial_starts + after.reserved
                <= after.cold_allowance + after.business_starts / after.earning_period
        );
    }
    assert_eq!(trials, std::collections::HashSet::from([1, 2]));
    let counts = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.trial_cancelled, counts.trial_starts);
    assert_eq!(counts.refunded, 0);
    for leaf in &nodes[1..] {
        let score = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now);
        assert_eq!(
            (score.attempts, score.completed, score.unresolved_failure),
            (0.0, 0.0, false)
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
    let state = manager.score_state();
    let node_refs = [&nodes[0], &nodes[1]];
    let mut at = now + Duration::from_secs(2);
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
    assert_eq!(index, 0);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, false, at);
    at += PERFORMANCE_MAX_AGE;
    let (index, feedback) = state.rank_plan_at("score", &target, &node_refs, at);
    assert_eq!(index, 1);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    assert_eq!(state.peek_rank_at("score", &target, &node_refs, at), 0);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        1
    );
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        0
    );
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
            .ordinary_switch,
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
