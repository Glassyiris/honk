use super::super::ranking::{normal_eligible, ordinary_selection, performance_baseline};
use super::*;

fn udp_context() -> ScoreSelectionContext {
    let mut target = context("active-udp.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    target
}

fn snapshots(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    at: Instant,
) -> Vec<ScoreSnapshot> {
    let state = manager.score_state();
    let inner = state.inner.lock();
    nodes
        .iter()
        .map(|node| score_snapshot(&inner, "score", target, node.id, at))
        .collect()
}

#[test]
fn active_udp_keeps_earned_qualification_without_inventing_completions() {
    let nodes = [node("incumbent"), node("challenger"), node("cold")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    for (index, samples) in [4, 5, 3].into_iter().enumerate() {
        train_at(
            &manager,
            &nodes[index],
            &target,
            samples,
            Duration::from_millis(100 + index as u64 * 5),
            1,
            now,
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(1)),
        0
    );
    let active: Vec<_> = nodes
        .iter()
        .map(|leaf| {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now + Duration::from_secs(1));
            reporter.setup_succeeded_at(now + Duration::from_secs(1));
            reporter
        })
        .collect();
    for second in (2..=662).step_by(30) {
        let at = now + Duration::from_secs(second);
        for reporter in &active {
            reporter.transfer_at(1, 1, at);
        }
        let scores = snapshots(&manager, &nodes, &target, at);
        let baseline = performance_baseline(&scores);
        assert!(scores[0].useful_completed < 4.0);
        if second == 2 {
            assert!(scores[1].useful_completed >= 4.0);
        }
        assert!(baseline.any_qualified);
        assert!(normal_eligible(&scores[0], baseline));
        assert!(normal_eligible(&scores[1], baseline));
        assert!(!normal_eligible(&scores[2], baseline));
        for (score, samples) in scores.iter().zip([4.0, 5.0, 3.0]) {
            let expected = samples * (-((second - 1) as f64) / 1800.0).exp2();
            assert_close(score.completed, expected);
            assert_close(score.useful_completed, expected);
            assert_eq!(score.fail_streak, 0);
            assert!(!score.unresolved_failure);
        }
        if second == 2 {
            assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
        }
        let ordinary = ordinary_selection(
            &scores,
            &nodes.iter().collect::<Vec<_>>(),
            Some(0),
            baseline,
        );
        assert_eq!(ordinary.index, 0);
    }
    let state = manager.score_state();
    let verification = state
        .verification_snapshot_at(
            "score",
            &target,
            &nodes.iter().collect::<Vec<_>>(),
            now + Duration::from_secs(662),
        )
        .unwrap();
    assert_eq!(verification.state, ScoreVerificationState::Provisional);
    assert_eq!(verification.evidence_age_ms, None);
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Udp);
    assert_eq!(reasons.incumbent_ineligible, 0);
    assert_eq!(reasons.ordinary_switch, 0);

    train_at(
        &manager,
        &nodes[1],
        &target,
        5,
        Duration::from_millis(105),
        1,
        now + Duration::from_secs(720),
    );
    let expiry = now + Duration::from_secs(722);
    let before = snapshots(&manager, &nodes, &target, expiry - Duration::from_nanos(1));
    assert!(normal_eligible(&before[0], performance_baseline(&before)));
    let expired = snapshots(&manager, &nodes, &target, expiry);
    assert!(!normal_eligible(
        &expired[0],
        performance_baseline(&expired)
    ));
    let ordinary = ordinary_selection(
        &expired,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        performance_baseline(&expired),
    );
    assert_eq!(ordinary.index, 1);
    assert_eq!(ordinary.reason, SelectionReason::IncumbentIneligible);
    active[0].transfer_at(1, 1, expiry + Duration::from_secs(1));
    let late = snapshots(&manager, &nodes, &target, expiry + Duration::from_secs(1));
    assert!(!normal_eligible(&late[0], performance_baseline(&late)));

    let settled_at = expiry + Duration::from_secs(2);
    let before = snapshots(&manager, &nodes, &target, settled_at);
    let clone = active[0].clone();
    active[0].finish_at(ScoreOutcome::Success, true, settled_at);
    clone.finish_at(ScoreOutcome::Timeout, true, settled_at);
    clone.transfer_at(1, 1, settled_at + Duration::from_secs(1));
    let settled = snapshots(&manager, &nodes, &target, settled_at);
    assert_close(settled[0].completed, before[0].completed + 1.0);
    assert_close(
        settled[0].useful_completed,
        before[0].useful_completed + 1.0,
    );
    assert!(normal_eligible(&settled[0], performance_baseline(&settled)));
    assert!(!settled[0].unresolved_failure);
    for reporter in &active[1..] {
        reporter.finish_at(ScoreOutcome::Cancelled, true, settled_at);
    }
    let terminal_expiry = expiry + Duration::from_secs(61);
    let before = snapshots(
        &manager,
        &nodes,
        &target,
        terminal_expiry - Duration::from_nanos(1),
    );
    assert!(before[0].useful_completed < 4.0);
    assert!(normal_eligible(&before[0], performance_baseline(&before)));
    let expired = snapshots(&manager, &nodes, &target, terminal_expiry);
    assert!(!normal_eligible(
        &expired[0],
        performance_baseline(&expired)
    ));
}

#[test]
fn publishable_business_rx_restores_hold_but_never_settles_the_flow() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            1000,
            Duration::from_millis(100 + index as u64 * 10),
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let failed_at = now + Duration::from_secs(6);
    let failure = feedback.start_at(failed_at);
    failure.setup_succeeded_at(failed_at);
    failure.finish_at(ScoreOutcome::Timeout, true, failed_at);
    train_at(
        &manager,
        &nodes[1],
        &target,
        1000,
        Duration::from_millis(95),
        1,
        now + Duration::from_secs(7),
    );
    let at = now + Duration::from_secs(9);
    for source in [ScoreSource::HealthProbe, ScoreSource::Warmup] {
        let reporter = feedback.clone().with_source(source).start_at(at);
        reporter.setup_succeeded_at(at);
        reporter.transfer_at(1, 1, at);
        reporter.finish_at(ScoreOutcome::Success, true, at);
    }
    let mut untargeted = target.clone();
    untargeted.target = None;
    let unscoped = feedback
        .clone()
        .with_context(untargeted.clone())
        .start_at(at);
    unscoped.setup_succeeded_at(at);
    unscoped.transfer_at(1, 1, at);
    unscoped.finish_at(ScoreOutcome::Cancelled, true, at);
    let setup_only = feedback.start_at(at);
    setup_only.setup_succeeded_at(at);
    setup_only.finish_at(ScoreOutcome::Cancelled, false, at);
    let rx_only = feedback.start_at(at);
    rx_only.setup_succeeded_at(at);
    rx_only.transfer_at(0, 1, at);
    rx_only.finish_at(ScoreOutcome::Cancelled, true, at);
    let active = feedback.start_at(at);
    active.transfer_at(0, 1, at);
    active.setup_succeeded_at(at);
    active.transfer_at(1, 0, at);
    active.transfer_at(0, 0, at);
    let before = snapshots(&manager, &nodes, &target, at);
    assert!(before[0].unresolved_failure);
    untargeted.target_family = None;
    assert!(snapshots(&manager, &nodes, &untargeted, at)[0].unresolved_failure);
    let baseline = performance_baseline(&before);
    assert!(normal_eligible(&before[0], baseline));
    let bypass = ordinary_selection(
        &before,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        baseline,
    );
    assert_eq!(bypass.index, 1);
    assert_eq!(bypass.reason, SelectionReason::FreshFailureBypass);

    active.transfer_at(0, 1, at);
    let recovered = snapshots(&manager, &nodes, &target, at);
    assert!(!recovered[0].unresolved_failure);
    assert_close(recovered[0].attempts, before[0].attempts);
    assert_close(recovered[0].completed, before[0].completed);
    assert_close(recovered[0].useful_completed, before[0].useful_completed);
    assert_close(recovered[0].reliability, before[0].reliability);
    assert_close(recovered[0].reliability_upper, before[0].reliability_upper);
    assert_close(
        recovered[0].observed_reliability,
        before[0].observed_reliability,
    );
    assert_eq!(recovered[0].fail_streak, 1);
    assert!(recovered[0].explore_backed_off);
    assert!(recovered[0].verification.business.value.is_none());
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Udp);
    assert_eq!(reasons.incumbent_held, 1);
    assert_eq!(reasons.fresh_failure_bypass, 0);

    let next_failure = feedback.start_at(at + Duration::from_millis(100));
    next_failure.setup_succeeded_at(at + Duration::from_millis(100));
    next_failure.finish_at(ScoreOutcome::Timeout, true, at + Duration::from_millis(100));
    active.transfer_at(0, 1, at + Duration::from_millis(200));
    let throttled = snapshots(&manager, &nodes, &target, at + Duration::from_millis(200));
    assert!(throttled[0].unresolved_failure);
    // No timer flushes throttled RX: only the next publishable RX or terminal can recover.
    let published_at = at + Duration::from_secs(1);
    let before = snapshots(&manager, &nodes, &target, published_at);
    active.transfer_at(0, 1, published_at);
    let published = snapshots(&manager, &nodes, &target, published_at);
    assert!(!published[0].unresolved_failure);
    assert_eq!(published[0].fail_streak, 2);
    assert!(published[0].explore_backed_off);
    assert_close(published[0].completed, before[0].completed);
    assert_close(published[0].useful_completed, before[0].useful_completed);
    let clone = active.clone();
    active.finish_at(ScoreOutcome::Cancelled, true, published_at);
    clone.finish_at(ScoreOutcome::Success, true, published_at);
    let cancelled = snapshots(&manager, &nodes, &target, published_at);
    assert!(!cancelled[0].unresolved_failure);
    assert_close(cancelled[0].completed, published[0].completed);
    assert_close(cancelled[0].useful_completed, published[0].useful_completed);
    assert_close(
        cancelled[0].attempts,
        published[0].attempts - (-1.0_f64 / 1800.0).exp2(),
    );
    assert!(cancelled[0].verification.business.value.is_none());

    let last_failure_at = published_at + Duration::from_secs(1);
    let last_failure = feedback.start_at(last_failure_at);
    last_failure.setup_succeeded_at(last_failure_at);
    last_failure.finish_at(ScoreOutcome::Timeout, true, last_failure_at);
    let failed = snapshots(&manager, &nodes, &target, last_failure_at);
    clone.transfer_at(1, 1, last_failure_at + Duration::from_secs(1));
    clone.finish_at(
        ScoreOutcome::Timeout,
        true,
        last_failure_at + Duration::from_secs(1),
    );
    last_failure.finish_at(ScoreOutcome::Success, true, last_failure_at);
    let ignored = snapshots(&manager, &nodes, &target, last_failure_at);
    assert!(ignored[0].unresolved_failure);
    assert_eq!(ignored[0].fail_streak, 3);
    assert_close(ignored[0].completed, failed[0].completed);
    assert_close(ignored[0].useful_completed, failed[0].useful_completed);
}

#[test]
fn terminal_rx_recovers_after_verification_age_without_refreshing_verification() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    // Two failures must stay below the mature margin to isolate recovery from risk-based promotion.
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            512,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let at = now + Duration::from_secs(3);
    let active = feedback.start_at(at);
    active.setup_succeeded_at(at);
    let failure = feedback.start_at(at);
    failure.setup_succeeded_at(at);
    failure.finish_at(ScoreOutcome::Timeout, true, at);
    active.transfer_at(1, 1, at + Duration::from_millis(100));
    assert!(
        !snapshots(&manager, &nodes, &target, at + Duration::from_millis(100))[0]
            .unresolved_failure
    );
    let next_failure = feedback.start_at(at + Duration::from_millis(200));
    next_failure.setup_succeeded_at(at + Duration::from_millis(200));
    next_failure.finish_at(ScoreOutcome::Timeout, true, at + Duration::from_millis(200));
    active.transfer_at(0, 1, at + Duration::from_millis(300));
    let finished_at = now + Duration::from_secs(124);
    let before = snapshots(&manager, &nodes, &target, finished_at);
    assert!(before[0].unresolved_failure);
    active.finish_at(ScoreOutcome::Success, true, finished_at);
    let after = snapshots(&manager, &nodes, &target, finished_at);
    assert!(!after[0].unresolved_failure);
    assert_close(after[0].useful_completed, before[0].useful_completed + 1.0);
    let baseline = performance_baseline(&after);
    assert!(normal_eligible(&after[0], baseline));
    let ordinary = ordinary_selection(&after, &nodes.iter().collect::<Vec<_>>(), Some(0), baseline);
    assert_eq!(ordinary.index, 0);
    assert_eq!(ordinary.reason, SelectionReason::InsufficientEvidenceHeld);
    assert_eq!(
        manager
            .score_state()
            .verification_snapshot_at(
                "score",
                &target,
                &nodes.iter().collect::<Vec<_>>(),
                finished_at,
            )
            .unwrap()
            .state,
        ScoreVerificationState::Provisional
    );
    assert!(after[0].verification.business.value.is_none());
}

#[test]
fn reload_and_eviction_fence_progress_without_disabling_surviving_reporters() {
    let nodes = [node("survivor"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let before = Instant::now() - Duration::from_secs(10);
    for (index, samples) in [4, 5].into_iter().enumerate() {
        train_at(
            &manager,
            &nodes[index],
            &target,
            samples,
            Duration::from_millis(100),
            1,
            before,
        );
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let active = feedback.start_at(before + Duration::from_secs(2));
    active.setup_succeeded_at(before + Duration::from_secs(2));
    active.transfer_at(1, 1, before + Duration::from_secs(2));
    let qualified = snapshots(&manager, &nodes, &target, before + Duration::from_secs(2));
    assert!(normal_eligible(
        &qualified[0],
        performance_baseline(&qualified)
    ));
    let state = manager.score_state();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let after = Instant::now() + Duration::from_secs(1);
    active.transfer_at(0, 1, before + Duration::from_secs(3));
    let stale = snapshots(&replacement, &nodes, &target, after);
    assert!(!normal_eligible(&stale[0], performance_baseline(&stale)));
    active.transfer_at(0, 1, after);
    let surviving = snapshots(&replacement, &nodes, &target, after);
    assert!(!normal_eligible(
        &surviving[0],
        performance_baseline(&surviving)
    ));
    assert_close(surviving[0].useful_completed, stale[0].useful_completed);
    assert!(surviving[0].verification.business.value.is_none());

    let new_feedback = replacement
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let failure = new_feedback.start_at(after + Duration::from_secs(1));
    failure.setup_succeeded_at(after + Duration::from_secs(1));
    failure.finish_at(ScoreOutcome::Timeout, true, after + Duration::from_secs(1));
    active.transfer_at(0, 1, after + Duration::from_secs(2));
    assert!(
        !snapshots(
            &replacement,
            &nodes,
            &target,
            after + Duration::from_secs(2)
        )[0]
        .unresolved_failure
    );

    {
        let mut inner = state.inner.lock();
        inner.exact.resize(NonZeroUsize::new(1).unwrap());
        inner.aggregate.resize(NonZeroUsize::new(2).unwrap());
    }
    let evicting = replacement
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(after + Duration::from_secs(3));
    let recreated = new_feedback.start_at(after + Duration::from_secs(3));
    recreated.setup_succeeded_at(after + Duration::from_secs(3));
    recreated.finish_at(ScoreOutcome::Timeout, true, after + Duration::from_secs(3));
    let before_late = snapshots(
        &replacement,
        &nodes[..1],
        &target,
        after + Duration::from_secs(4),
    );
    assert!(before_late[0].unresolved_failure);
    active.transfer_at(0, 1, after + Duration::from_secs(4));
    active.finish_at(ScoreOutcome::Success, true, after + Duration::from_secs(4));
    let ignored = snapshots(
        &replacement,
        &nodes[..1],
        &target,
        after + Duration::from_secs(4),
    );
    assert!(ignored[0].unresolved_failure);
    assert_close(ignored[0].completed, before_late[0].completed);
    assert_close(ignored[0].useful_completed, before_late[0].useful_completed);
    assert_eq!(ignored[0].fail_streak, before_late[0].fail_streak);
    let fresh = new_feedback.start_at(after + Duration::from_secs(5));
    fresh.setup_succeeded_at(after + Duration::from_secs(5));
    fresh.transfer_at(1, 1, after + Duration::from_secs(5));
    assert!(
        !snapshots(
            &replacement,
            &nodes[..1],
            &target,
            after + Duration::from_secs(5)
        )[0]
        .unresolved_failure
    );
    fresh.finish_at(
        ScoreOutcome::Cancelled,
        true,
        after + Duration::from_secs(5),
    );
    evicting.finish_at(
        ScoreOutcome::Cancelled,
        true,
        after + Duration::from_secs(5),
    );
}

#[test]
fn delayed_terminal_bridges_qualification_to_already_observed_newer_rx() {
    let nodes = [node("delayed"), node("qualified")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = udp_context();
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        4,
        Duration::from_millis(100),
        1,
        now,
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let active = feedback.start_at(now + Duration::from_secs(1));
    active.setup_succeeded_at(now + Duration::from_secs(1));
    for second in (1..=1801).step_by(30) {
        active.transfer_at(1, 1, now + Duration::from_secs(second));
    }
    let state = manager.score_state();
    let started = now + Duration::from_secs(1802);
    let cells = state.start_at(&target, feedback.attributions(), started);
    train_at(
        &manager,
        &nodes[1],
        &target,
        5,
        Duration::from_millis(105),
        1,
        now + Duration::from_secs(1869),
    );
    active.transfer_at(0, 1, now + Duration::from_secs(1871));
    let terminal_at = now + Duration::from_secs(1881);
    let before = snapshots(&manager, &nodes, &target, terminal_at);
    assert!(!normal_eligible(&before[0], performance_baseline(&before)));

    // RX at +50 was delivered late; RX at +70 alone could not bridge the +60 expiry.
    let sample = FlowSample {
        outcome: ScoreOutcome::Success,
        setup: Some(Duration::ZERO),
        source: ScoreSource::Traffic,
        tx: 1,
        rx: 1,
        last_rx_at: Some(now + Duration::from_secs(1851)),
        elapsed: terminal_at.duration_since(started),
        count_usefulness: true,
    };
    state.finish_at(
        &target,
        feedback.attributions(),
        &cells,
        &sample,
        terminal_at,
    );
    let bridged_at = now + Duration::from_secs(1921);
    let bridged = snapshots(&manager, &nodes, &target, bridged_at);
    assert!(bridged[0].useful_completed < 4.0);
    assert!(normal_eligible(&bridged[0], performance_baseline(&bridged)));
    let ordinary = ordinary_selection(
        &bridged,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        performance_baseline(&bridged),
    );
    assert_eq!(ordinary.index, 0);
    let expires_at = now + Duration::from_secs(1931);
    let before_expiry = snapshots(
        &manager,
        &nodes,
        &target,
        expires_at - Duration::from_nanos(1),
    );
    assert!(normal_eligible(
        &before_expiry[0],
        performance_baseline(&before_expiry)
    ));
    let expired = snapshots(&manager, &nodes, &target, expires_at);
    assert!(!normal_eligible(
        &expired[0],
        performance_baseline(&expired)
    ));
    active.transfer_at(0, 1, expires_at + Duration::from_secs(1));
    let gap = snapshots(
        &manager,
        &nodes,
        &target,
        expires_at + Duration::from_secs(1),
    );
    assert!(!normal_eligible(&gap[0], performance_baseline(&gap)));
    active.finish_at(
        ScoreOutcome::Cancelled,
        true,
        expires_at + Duration::from_secs(1),
    );
}
