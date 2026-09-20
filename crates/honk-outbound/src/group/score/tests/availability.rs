use super::*;

fn availability_at(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    at: Instant,
) -> ScoreVerificationSnapshot {
    manager
        .score_state()
        .verification_snapshot_at("score", target, &nodes.iter().collect::<Vec<_>>(), at)
        .unwrap()
}

#[test]
fn distinct_live_udp_flows_establish_usability_without_terminal_successes() {
    let nodes = [Node::from_share_link("socks5://127.0.0.1:1080#live").unwrap()];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let mut target = context("live.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4)
        .map(|_| {
            let reporter = feedback.start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.transfer_at(1, 0, now);
            reporter
        })
        .collect();
    for reporter in &reporters[..3] {
        reporter.transfer_at(0, 1, now);
    }
    let clone = reporters[0].clone();
    for second in 1..=5 {
        clone.transfer_at(0, 1, now + Duration::from_secs(second));
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, now + Duration::from_secs(5)).state,
        ScoreVerificationState::Provisional,
        "repeated replies and clones must not replace a fourth distinct flow"
    );
    let observed = now + Duration::from_secs(6);
    reporters[3].transfer_at(0, 1, observed);
    let report = availability_at(&manager, &nodes, &target, observed);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, observed);
    assert_eq!(score.completed, 0.0);
    assert_eq!(score.useful_completed, 0.0);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Cancelled, true, observed);
    }
}

fn prepared(feedback: &ScoreFeedback, at: Instant) -> ScoreReporter {
    let reporter = feedback.start_at(at);
    reporter.setup_succeeded_at(at);
    reporter.transfer_at(1, 0, at);
    reporter
}

#[test]
fn continuous_rx_keeps_live_availability_but_idle_settlement_cannot_refresh_it() {
    let nodes = [node("live")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("continuous.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, now);
    }
    for second in (30..=150).step_by(30) {
        let at = now + Duration::from_secs(second);
        reporters[0].transfer_at(0, 1, at);
        let report = availability_at(&manager, &nodes, &target, at);
        assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
        assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
        assert_eq!(report.valid_for_ms, Some(60_000));
    }
    let state = manager.score_state();
    let at = now + Duration::from_secs(150);
    let live = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
    assert_eq!(live.completed, 0.0);
    assert_eq!(live.useful_completed, 0.0);
    let counters = state.verification_counters("score", target.network);
    let expiry = at + Duration::from_secs(60);
    assert_eq!(
        availability_at(&manager, &nodes, &target, expiry - Duration::from_nanos(1)).state,
        ScoreVerificationState::ObservedUsable
    );
    assert_eq!(
        availability_at(&manager, &nodes, &target, expiry).state,
        ScoreVerificationState::Provisional
    );
    assert_eq!(
        state.verification_counters("score", target.network),
        counters
    );
    let retired = at + Duration::from_secs(120);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Success, true, retired);
    }
    let report = availability_at(&manager, &nodes, &target, retired);
    assert_eq!(report.state, ScoreVerificationState::Provisional);
    assert_eq!(report.evidence_age_ms, None);
    let settled = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, retired);
    assert_eq!(settled.completed, 4.0);
    assert_eq!(settled.useful_completed, 4.0);
}

#[test]
fn exactly_sixty_seconds_of_silence_requires_four_reporters_again() {
    let nodes = [node("returning")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("silence.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, now);
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, now).state,
        ScoreVerificationState::ObservedUsable
    );
    let returned = now + Duration::from_secs(60);
    reporters[0].transfer_at(0, 1, returned);
    assert_eq!(
        availability_at(&manager, &nodes, &target, returned).state,
        ScoreVerificationState::Provisional
    );
    reporters[1].transfer_at(0, 1, returned - Duration::from_secs(1));
    for reporter in &reporters[2..] {
        reporter.transfer_at(0, 1, returned + Duration::from_secs(1));
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, returned + Duration::from_secs(1)).state,
        ScoreVerificationState::Provisional
    );
    reporters[1].transfer_at(0, 1, returned + Duration::from_secs(2));
    assert_eq!(
        availability_at(&manager, &nodes, &target, returned + Duration::from_secs(2)).state,
        ScoreVerificationState::ObservedUsable
    );
    for reporter in &reporters {
        reporter.finish_at(
            ScoreOutcome::Cancelled,
            true,
            returned + Duration::from_secs(2),
        );
    }
}

#[test]
fn settlement_cannot_count_live_reporters_twice() {
    let nodes = [node("deduplicated")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("dedup.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    for _ in 0..3 {
        let reporter = prepared(&feedback, now);
        reporter.transfer_at(0, 1, now);
        reporter.finish_at(ScoreOutcome::Success, true, now);
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, now).state,
        ScoreVerificationState::Provisional
    );
    let fourth = prepared(&feedback, now);
    fourth.transfer_at(0, 1, now);
    fourth.finish_at(ScoreOutcome::Cancelled, true, now);
    assert_eq!(
        availability_at(&manager, &nodes, &target, now).state,
        ScoreVerificationState::ObservedUsable
    );
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, now);
    assert_eq!(score.completed, 3.0);
    assert_eq!(score.useful_completed, 3.0);
}

#[test]
fn failure_fences_live_rx_without_requiring_survivors_to_settle() {
    let nodes = [node("recovering")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("failure.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, now);
    }
    let fence = now + Duration::from_secs(10);
    let older_failure = feedback.start_at(now);
    feedback
        .start_at(now)
        .finish_at(ScoreOutcome::Timeout, true, fence);
    older_failure.finish_at(ScoreOutcome::Timeout, true, fence - Duration::from_secs(1));
    for at in [fence - Duration::from_secs(1), fence] {
        for reporter in &reporters {
            reporter.transfer_at(0, 1, at);
        }
        assert_eq!(
            availability_at(&manager, &nodes, &target, fence).state,
            ScoreVerificationState::Provisional
        );
    }
    let recovered = fence + Duration::from_secs(2);
    let state = manager.score_state();
    let failed = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        recovered,
    );
    for reporter in &reporters[..3] {
        reporter.transfer_at(0, 1, recovered);
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, recovered).state,
        ScoreVerificationState::Provisional
    );
    reporters[3].transfer_at(0, 1, recovered);
    reporters[3].transfer_at(0, 1, recovered - Duration::from_secs(1));
    let report = availability_at(
        &manager,
        &nodes,
        &target,
        recovered + Duration::from_secs(1),
    );
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(1000));
    assert_eq!(report.valid_for_ms, Some(59_000));
    let before = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        recovered,
    );
    assert_close(before.completed, failed.completed);
    assert_close(before.useful_completed, failed.useful_completed);
    assert_close(before.reliability, failed.reliability);
    assert_eq!(before.fail_streak, 2);
    assert!(before.explore_backed_off);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Cancelled, true, recovered);
    }
    let after = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        recovered,
    );
    assert_close(after.completed, before.completed);
    assert_close(after.reliability, before.reliability);
    assert_eq!(after.fail_streak, before.fail_streak);
}

#[test]
fn neutral_settlement_flushes_throttled_eligible_rx_at_its_event_time() {
    let nodes = [node("neutral")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("neutral.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, now);
    }
    feedback.start_at(now).finish_at(
        ScoreOutcome::Timeout,
        true,
        now + Duration::from_millis(100),
    );
    let received = now + Duration::from_millis(200);
    for reporter in &reporters {
        reporter.transfer_at(0, 1, received);
    }
    let finished = now + Duration::from_secs(1);
    assert_eq!(
        availability_at(&manager, &nodes, &target, finished).state,
        ScoreVerificationState::Provisional
    );
    let state = manager.score_state();
    let before = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, finished);
    for (reporter, outcome) in reporters.iter().zip([
        ScoreOutcome::Cancelled,
        ScoreOutcome::Rejected,
        ScoreOutcome::Shutdown,
        ScoreOutcome::Cancelled,
    ]) {
        reporter.finish_at(outcome, true, finished);
    }
    let report = availability_at(&manager, &nodes, &target, finished);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(800));
    assert_eq!(report.valid_for_ms, Some(59_200));
    let after = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, finished);
    assert_close(after.completed, before.completed);
    assert_close(after.useful_completed, before.useful_completed);
    assert_close(after.reliability, before.reliability);
    assert_eq!(after.fail_streak, 1);
    assert_eq!(
        availability_at(
            &manager,
            &nodes,
            &target,
            received + Duration::from_secs(60)
        )
        .state,
        ScoreVerificationState::Provisional
    );
}

#[test]
fn reload_requires_new_rx_from_each_surviving_reporter() {
    let nodes = [node("surviving")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("reload.example", IpVersion::V4);
    let before = Instant::now() - Duration::from_secs(10);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, before)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, before);
    }
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        manager.score_state(),
    );
    replacement.publish_score_membership();
    let after = Instant::now() + Duration::from_secs(1);
    for reporter in &reporters {
        reporter.transfer_at(0, 1, before + Duration::from_secs(1));
    }
    assert_eq!(
        availability_at(&replacement, &nodes, &target, after).state,
        ScoreVerificationState::Provisional
    );
    for reporter in &reporters[..3] {
        reporter.transfer_at(0, 1, after);
    }
    assert_eq!(
        availability_at(&replacement, &nodes, &target, after).state,
        ScoreVerificationState::Provisional
    );
    reporters[3].transfer_at(0, 1, after);
    assert_eq!(
        availability_at(&replacement, &nodes, &target, after).state,
        ScoreVerificationState::ObservedUsable
    );
    let state = replacement.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, after);
    assert_eq!(score.completed, 0.0);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Cancelled, true, after);
    }
}

#[test]
fn only_targeted_traffic_rx_after_setup_and_tx_establishes_availability() {
    for case in [
        "setup-only",
        "tx-only",
        "rx-only",
        "rx-before-tx",
        "rx-before-setup",
        "rx-predates-prerequisites",
        "health-probe",
        "warmup",
        "unscoped",
    ] {
        let nodes = [node("admission")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("admission.example", IpVersion::V4);
        let mut aggregate = target.clone();
        aggregate.target = None;
        aggregate.target_family = None;
        let now = Instant::now();
        let finished = now + Duration::from_secs(2);
        let feedback = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap();
        let invalid = match case {
            "health-probe" => feedback.clone().with_source(ScoreSource::HealthProbe),
            "warmup" => feedback.clone().with_source(ScoreSource::Warmup),
            "unscoped" => feedback.clone().with_context(aggregate.clone()),
            _ => feedback.clone(),
        };
        let reporters: Vec<_> = (0..4).map(|_| invalid.start_at(now)).collect();
        for reporter in &reporters {
            if case == "rx-before-setup" {
                reporter.transfer_at(1, 1, now);
            }
            let setup_at = if case == "rx-predates-prerequisites" {
                now + Duration::from_secs(1)
            } else {
                now
            };
            reporter.setup_succeeded_at(setup_at);
            match case {
                "setup-only" | "rx-before-setup" => {}
                "tx-only" => reporter.transfer_at(1, 0, now),
                "rx-only" => reporter.transfer_at(0, 1, now),
                "rx-before-tx" => {
                    reporter.transfer_at(0, 1, now);
                    reporter.transfer_at(1, 0, now);
                }
                "rx-predates-prerequisites" => {
                    reporter.transfer_at(1, 0, setup_at);
                    reporter.transfer_at(0, 1, now);
                }
                _ => reporter.transfer_at(1, 1, now),
            }
        }
        for reporter in &reporters {
            reporter.finish_at(ScoreOutcome::Success, true, finished);
        }
        for scope in [&target, &aggregate] {
            assert_eq!(
                availability_at(&manager, &nodes, scope, finished).state,
                ScoreVerificationState::Provisional,
                "ineligible admission case {case}"
            );
        }
        if matches!(case, "rx-before-tx" | "rx-before-setup") {
            let state = manager.score_state();
            let score =
                score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, finished);
            assert_eq!(score.completed, 4.0);
            assert_eq!(score.useful_completed, 4.0);
            assert!(score.qualification_retained);
        }
        let fresh = finished + Duration::from_secs(1);
        let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, fresh)).collect();
        for reporter in &reporters {
            reporter.transfer_at(0, 1, fresh);
        }
        assert_eq!(
            availability_at(&manager, &nodes, &target, fresh).state,
            ScoreVerificationState::ObservedUsable
        );
        for reporter in &reporters {
            reporter.finish_at(ScoreOutcome::Cancelled, true, fresh);
        }
    }
}

#[test]
fn global_family_and_exact_cells_credit_their_own_availability_cohorts() {
    let nodes = [node("scoped")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("scoped.example", IpVersion::V4);
    let mut family = target.clone();
    family.target = None;
    let mut global = family.clone();
    global.target_family = None;
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &reporters {
        reporter.transfer_at(0, 1, now);
    }
    for (index, failed_family) in [IpVersion::V6, IpVersion::V4].into_iter().enumerate() {
        let failed_at = now + Duration::from_secs(2 + index as u64 * 3);
        manager
            .feedback_for_group_node(
                "score",
                nodes[0].id,
                context("other.example", failed_family),
            )
            .unwrap()
            .start_at(failed_at)
            .finish_at(ScoreOutcome::Timeout, true, failed_at);
        let at = failed_at + Duration::from_secs(1);
        for reporter in &reporters[..3] {
            reporter.transfer_at(0, 1, at);
        }
        assert_eq!(
            availability_at(&manager, &nodes, &global, at).state,
            ScoreVerificationState::Provisional
        );
        assert_eq!(
            availability_at(&manager, &nodes, &family, at).state,
            if index == 0 {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            }
        );
        assert_eq!(
            availability_at(&manager, &nodes, &target, at).state,
            ScoreVerificationState::ObservedUsable
        );
        reporters[3].transfer_at(0, 1, at);
        for scope in [&global, &family, &target] {
            assert_eq!(
                availability_at(&manager, &nodes, scope, at).state,
                ScoreVerificationState::ObservedUsable
            );
        }
    }
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Cancelled, true, now + Duration::from_secs(7));
    }
}

#[test]
fn recreated_cells_reject_old_live_reporters_even_after_fresh_rx() {
    let nodes = [node("recreated")];
    let manager = GroupManager::new(&[group("score", &nodes), group("other", &nodes)], &nodes);
    let target = context("recreated.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    {
        let mut inner = state.inner.lock();
        inner.exact.resize(NonZeroUsize::new(1).unwrap());
        inner.aggregate.resize(NonZeroUsize::new(2).unwrap());
    }
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let old: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    for reporter in &old {
        reporter.transfer_at(0, 1, now);
    }
    assert_eq!(
        availability_at(&manager, &nodes, &target, now).state,
        ScoreVerificationState::ObservedUsable
    );
    let evicting = manager
        .feedback_for_group_node("other", nodes[0].id, target.clone())
        .unwrap()
        .start_at(now);
    let fresh: Vec<_> = (0..4).map(|_| prepared(&feedback, now)).collect();
    let at = now + Duration::from_secs(1);
    for reporter in &old {
        reporter.transfer_at(0, 1, at);
        reporter.finish_at(ScoreOutcome::Success, true, at);
    }
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, at);
    assert_eq!(score.completed, 0.0);
    for reporter in &fresh[..3] {
        reporter.transfer_at(0, 1, at);
    }
    let mut aggregate = target.clone();
    aggregate.target = None;
    aggregate.target_family = None;
    for scope in [&target, &aggregate] {
        assert_eq!(
            availability_at(&manager, &nodes, scope, at).state,
            ScoreVerificationState::Provisional
        );
    }
    fresh[3].transfer_at(0, 1, at);
    for scope in [&target, &aggregate] {
        assert_eq!(
            availability_at(&manager, &nodes, scope, at).state,
            ScoreVerificationState::ObservedUsable
        );
    }
    for reporter in &fresh {
        reporter.finish_at(ScoreOutcome::Cancelled, true, at);
    }
    evicting.finish_at(ScoreOutcome::Cancelled, false, at);
}
