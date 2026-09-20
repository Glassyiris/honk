use super::*;

fn verification_at(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> ScoreVerificationSnapshot {
    manager
        .score_state()
        .verification_snapshot_at("score", target, &nodes.iter().collect::<Vec<_>>(), now)
        .unwrap()
}

#[test]
fn idle_terminal_does_not_refresh_old_business_evidence() {
    let nodes = [node("idle")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let mut target = context("business.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    let now = Instant::now();
    let reporters: Vec<_> = (0..5)
        .map(|_| {
            let reporter = manager
                .feedback_for_group_node("score", nodes[0].id, target.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now);
            reporter.transfer_at(1, 1, now);
            reporter
        })
        .collect();
    for second in [20, 40, 60, 80, 100] {
        for reporter in &reporters {
            reporter.transfer_at(1, 0, now + Duration::from_secs(second));
        }
    }
    let expired = now + Duration::from_secs(120);
    for reporter in &reporters {
        reporter.finish_at(ScoreOutcome::Success, true, expired);
        reporter.finish_at(ScoreOutcome::Timeout, true, expired);
    }
    let report = verification_at(&manager, &nodes, &target, expired);
    assert_eq!(report.state, ScoreVerificationState::Provisional);
    assert_eq!(report.evidence_age_ms, None);
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, expired);
    assert_eq!(score.completed, 5.0);
    assert_eq!(score.useful_completed, 5.0);
    assert_eq!(score.fail_streak, 0);
}

#[test]
fn recent_business_uses_latest_rx_across_out_of_order_completions() {
    let nodes = [node("live")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..5)
        .map(|_| {
            let reporter = feedback.start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.transfer_at(1, 1, now + Duration::from_secs(10));
            reporter
        })
        .collect();
    reporters[0].transfer_at(0, 1, now + Duration::from_secs(20));
    reporters[0].transfer_at(0, 1, now + Duration::from_secs(15));
    reporters[0].finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(30));
    let terminal = now + Duration::from_secs(31);
    for reporter in &reporters[1..] {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    let report = verification_at(&manager, &nodes, &target, terminal);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(11_000));
    assert_eq!(report.valid_for_ms, Some(49_000));
    assert_eq!(
        verification_at(&manager, &nodes, &target, now + Duration::from_secs(81)).state,
        ScoreVerificationState::Provisional
    );
}

#[test]
fn delayed_settlement_preserves_fresh_live_availability_without_refreshing_old_rx() {
    let nodes = [node("delayed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let replied = |rx_at| {
        let reporter = feedback.start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, rx_at);
        reporter
    };
    for _ in 0..5 {
        replied(now).finish_at(ScoreOutcome::Success, true, now);
    }
    let stale: Vec<_> = (0..3).map(|_| replied(now)).collect();
    let fresh: Vec<_> = (0..5)
        .map(|_| replied(now + Duration::from_secs(110)))
        .collect();
    let terminal = now + Duration::from_secs(130);
    fresh[0].finish_at(ScoreOutcome::Success, true, terminal);
    assert_eq!(
        verification_at(&manager, &nodes, &target, terminal).state,
        ScoreVerificationState::ObservedUsable
    );
    for reporter in &stale {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    assert_eq!(
        verification_at(&manager, &nodes, &target, terminal).state,
        ScoreVerificationState::ObservedUsable
    );
    for reporter in &fresh[1..] {
        reporter.finish_at(ScoreOutcome::Success, true, terminal);
    }
    let report = verification_at(&manager, &nodes, &target, terminal);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(20_000));
}

#[test]
fn failure_requires_strictly_newer_rx_even_after_older_failure_completion() {
    let nodes = [node("recovering")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let fence = now + Duration::from_secs(10);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let replied = |rx_at| {
        let reporter = feedback.start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.transfer_at(1, 1, rx_at);
        reporter
    };
    let old: Vec<_> = (0..5).map(|_| replied(now)).collect();
    let tied: Vec<_> = (0..5).map(|_| replied(fence)).collect();
    let surviving: Vec<_> = (0..5).map(|_| replied(now)).collect();
    let older_failure = feedback.start_at(now);
    feedback
        .start_at(now)
        .finish_at(ScoreOutcome::Timeout, true, fence);
    older_failure.finish_at(ScoreOutcome::Timeout, true, fence - Duration::from_secs(1));
    let terminal = fence + Duration::from_secs(1);
    for batch in [&old, &tied] {
        for reporter in batch {
            reporter.finish_at(ScoreOutcome::Success, true, terminal);
        }
        let report = verification_at(&manager, &nodes, &target, terminal);
        assert_eq!(report.state, ScoreVerificationState::Provisional);
        assert_eq!(report.evidence_age_ms, None);
    }
    for reporter in &surviving {
        reporter.transfer_at(0, 1, terminal);
        reporter.finish_at(
            ScoreOutcome::Success,
            true,
            terminal + Duration::from_secs(1),
        );
    }
    let report = verification_at(&manager, &nodes, &target, terminal + Duration::from_secs(1));
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(1000));
}

#[test]
fn reload_rejects_old_rx_but_accepts_surviving_flow_progress() {
    let nodes = [node("survivor")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let before = Instant::now() - Duration::from_secs(1);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let reporters: Vec<_> = (0..10)
        .map(|_| {
            let reporter = feedback.start_at(before);
            reporter.setup_succeeded_at(before);
            reporter.transfer_at(1, 1, before);
            reporter
        })
        .collect();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        manager.score_state(),
    );
    replacement.publish_score_membership();
    let after = Instant::now() + Duration::from_secs(1);
    for reporter in &reporters[..5] {
        reporter.finish_at(ScoreOutcome::Success, true, after);
    }
    let report = verification_at(&replacement, &nodes, &target, after);
    assert_eq!(report.state, ScoreVerificationState::Provisional);
    assert_eq!(report.evidence_age_ms, None);
    for reporter in &reporters[5..] {
        reporter.transfer_at(0, 1, after);
        reporter.finish_at(ScoreOutcome::Success, true, after + Duration::from_secs(1));
    }
    let report = verification_at(
        &replacement,
        &nodes,
        &target,
        after + Duration::from_secs(1),
    );
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.evidence_age_ms, Some(1000));
}

#[test]
fn real_flow_gaps_become_usable_and_supported_with_measured_exposure() {
    let nodes = [node("quick"), node("unvalidated")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let initial = verification_at(&manager, &nodes, &target, now);
    assert_eq!(initial.state, ScoreVerificationState::Provisional);
    assert_eq!(initial.pending_count, 2);
    assert_eq!(initial.next_action, ScoreValidationAction::NextBusinessFlow);
    let state = manager.score_state();
    let mut first_usable = None;
    let mut confirmed_at = None;
    let mut resolved_at = None;
    for second in 0..100 {
        let at = now + Duration::from_secs(second);
        let index = rank_at(&manager, &nodes, &target, at);
        let snapshot = verification_at(&manager, &nodes, &target, at);
        if snapshot.state == ScoreVerificationState::ObservedUsable && first_usable.is_none() {
            first_usable = Some(second);
        }
        let counts = state.verification_counters("score", SelectionNetwork::Tcp);
        assert!(counts.validation_selections <= 2 + second / exploration_period(2));
        if snapshot.comparison == ScoreComparison::Supported {
            assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
            assert_eq!(snapshot.compared_count, 2);
            assert_eq!(snapshot.basis, ScoreEvidenceBasis::TargetResponse);
            assert!(snapshot.missing.transfer);
            confirmed_at.get_or_insert(second);
            if snapshot.pending_count == 0 {
                assert_eq!(snapshot.next_action, ScoreValidationAction::AwaitTransfer);
                resolved_at = Some(second);
                break;
            }
            assert!(!snapshot.missing.availability);
            assert!(!snapshot.missing.response);
            assert_eq!(
                snapshot.next_action,
                ScoreValidationAction::NextBusinessFlow
            );
        }
        train_at(
            &manager,
            &nodes[index],
            &target,
            1,
            Duration::from_millis(if index == 0 { 10 } else { 600 }),
            1,
            at,
        );
    }
    let confirmed_at =
        confirmed_at.expect("actual candidate trials must resolve the response dispute");
    let resolved_at =
        resolved_at.expect("bounded trials must also complete ordinary qualification");
    let counts = state.verification_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.confirmations, 2);
    assert_eq!(
        counts.confirmation_millis,
        (first_usable.unwrap() + confirmed_at) * 1000
    );
    assert!(counts.validation_selections >= 4);
    assert_eq!(
        counts.provisional_selections + counts.usable_selections,
        resolved_at + 1
    );
    println!(
        "response confirmed in {confirmed_at}s with {} validation flows",
        counts.validation_selections
    );
}

#[test]
fn sparse_large_group_focuses_promising_contender_until_graduation() {
    let nodes: Vec<_> = (0..32)
        .map(|index| node(&format!("leaf-{index}")))
        .collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(600),
        1,
        now,
    );
    for (index, leaf) in nodes.iter().enumerate() {
        probe_at(
            &manager,
            leaf,
            &probe,
            ScoreSource::HealthProbe,
            Duration::from_millis(if index == 31 { 1 } else { 600 }),
            now,
        );
    }
    let state = manager.score_state();
    let mut graduate = None;
    let mut focused_trials = 0;
    for second in 2..300 {
        let at = now + Duration::from_secs(second);
        let before = state.verification_counters("score", SelectionNetwork::Tcp);
        let index = rank_at(&manager, &nodes, &target, at);
        let after = state.verification_counters("score", SelectionNetwork::Tcp);
        if second == 2 {
            assert_eq!(
                index, 31,
                "same-cohort fresh hint should choose a promising question"
            );
        }
        let validation = after.validation_selections > before.validation_selections;
        if validation && index == 31 {
            focused_trials += 1;
        }
        if index == 31 && !validation {
            graduate = Some(second);
            break;
        }
        train_at(
            &manager,
            &nodes[index],
            &target,
            1,
            Duration::from_millis(if index == 31 { 10 } else { 600 }),
            1,
            at,
        );
        assert!(after.validation_selections <= exploration_target(32) as u64 + second / 30);
    }
    let second = graduate
        .expect("round-robin sparse evidence must not strand a promising leaf below qualification");
    assert!((5..=8).contains(&focused_trials));
    assert!(second < 250);
    let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(second));
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert!(
        snapshot.pending_count > 0,
        "untried rivals cannot be called beaten"
    );
    println!("32-leaf sparse graduation={second}s focused trials={focused_trials}");
}

#[test]
fn equivalent_response_stops_trials_while_transfer_remains_unknown() {
    let nodes = [node("first"), node("equivalent")];
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
    for _ in 0..256 {
        assert_eq!(
            rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
            0
        );
    }
    let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    assert_eq!(snapshot.comparison, ScoreComparison::Equivalent);
    assert_eq!(snapshot.pending_count, 0);
    assert!(snapshot.missing.transfer);
    assert_eq!(snapshot.next_action, ScoreValidationAction::AwaitTransfer);
    assert_eq!(
        manager
            .score_state()
            .verification_counters("score", SelectionNetwork::Tcp)
            .validation_selections,
        0
    );
}

#[test]
fn old_history_cannot_refresh_availability_with_one_new_success() {
    for history in [100.0, 10_000.0] {
        let nodes = [node("historical")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
        let now = Instant::now();
        let state = manager.score_state();
        state.inner.lock().exact.put(
            ExactKey {
                group: "score".into(),
                network: target.network,
                family: IpVersion::V4,
                target: target.target.clone().unwrap(),
                node_id: nodes[0].id,
            },
            trained_stats(history, 100.0, now),
        );
        assert_eq!(
            verification_at(&manager, &nodes, &target, now).state,
            ScoreVerificationState::ObservedUsable
        );
        rank_at(&manager, &nodes, &target, now);
        let before = state.verification_counters("score", SelectionNetwork::Tcp);
        let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
        let snapshot = verification_at(&manager, &nodes, &target, expired);
        assert_eq!(snapshot.state, ScoreVerificationState::Provisional);
        assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
        assert_eq!(
            state.verification_counters("score", SelectionNetwork::Tcp),
            before
        );
        rank_at(&manager, &nodes, &target, expired);
        assert_eq!(
            state
                .verification_counters("score", SelectionNetwork::Tcp)
                .expired,
            1
        );
        train_at(
            &manager,
            &nodes[0],
            &target,
            1,
            Duration::from_millis(10),
            1,
            expired,
        );
        assert_eq!(
            verification_at(&manager, &nodes, &target, expired + Duration::from_secs(2)).state,
            ScoreVerificationState::Provisional
        );
        train_at(
            &manager,
            &nodes[0],
            &target,
            4,
            Duration::from_millis(10),
            1,
            expired + Duration::from_secs(3),
        );
        assert_eq!(
            verification_at(&manager, &nodes, &target, expired + Duration::from_secs(5)).state,
            ScoreVerificationState::ObservedUsable
        );
    }
}

#[test]
fn transfer_expiry_failure_and_reload_retract_only_supported_claims() {
    let nodes = [node("a"), node("b")];
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
            1_000_000,
            now,
        );
    }
    rank_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    assert!(!snapshot.missing.transfer);
    assert_eq!(snapshot.next_action, ScoreValidationAction::None);
    let state = manager.score_state();
    let refreshed = now + Duration::from_secs(70);
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            5,
            Duration::from_millis(100),
            1,
            refreshed,
        );
    }
    let at = refreshed + Duration::from_secs(2);
    let snapshot = verification_at(&manager, &nodes, &target, at);
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(snapshot.comparison, ScoreComparison::Equivalent);
    assert!(snapshot.missing.transfer);
    assert_eq!(snapshot.next_action, ScoreValidationAction::AwaitTransfer);
    assert_eq!(snapshot.evidence_age_ms, Some(1900));
    assert_eq!(snapshot.valid_for_ms, Some(58100));
    rank_at(&manager, &nodes, &target, at);
    assert_eq!(
        state
            .verification_counters("score", SelectionNetwork::Tcp)
            .expired,
        1
    );
    for leaf in &nodes {
        manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Timeout, true, at);
    }
    assert_eq!(
        verification_at(&manager, &nodes, &target, at).state,
        ScoreVerificationState::Provisional
    );
    assert_eq!(
        verification_at(&manager, &nodes, &target, at).next_action,
        ScoreValidationAction::Backoff
    );
    rank_at(&manager, &nodes, &target, at);
    assert_eq!(
        state
            .verification_counters("score", SelectionNetwork::Tcp)
            .contradicted,
        1
    );
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            5,
            Duration::from_millis(100),
            1,
            at,
        );
    }
    rank_at(&manager, &nodes, &target, at + Duration::from_secs(2));
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    manager.publish_score_membership();
    let revoked = verification_at(&manager, &nodes, &target, at + Duration::from_secs(2));
    assert_eq!(revoked.state, ScoreVerificationState::Provisional);
    assert_eq!(revoked.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
    rank_at(&manager, &nodes, &target, at + Duration::from_secs(2));
    assert_eq!(
        state
            .verification_counters("score", SelectionNetwork::Tcp)
            .contradicted,
        before.contradicted + 1
    );
}

#[test]
fn probes_and_singletons_never_certify_unknown_business_scope() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("private-business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([10, 100]) {
        for _ in 0..8 {
            probe_at(
                &manager,
                leaf,
                &probe,
                ScoreSource::HealthProbe,
                Duration::from_millis(latency),
                now,
            );
        }
    }
    let aggregate_snapshot = verification_at(&manager, &nodes, &aggregate, now);
    assert_eq!(
        aggregate_snapshot.state,
        ScoreVerificationState::Provisional
    );
    assert_eq!(aggregate_snapshot.comparison, ScoreComparison::Supported);
    assert_eq!(
        aggregate_snapshot.basis,
        ScoreEvidenceBasis::ConfiguredProbe
    );
    assert!(aggregate_snapshot.missing.availability && aggregate_snapshot.missing.transfer);
    let exact = verification_at(&manager, &nodes, &target, now);
    assert_eq!(exact.comparison, ScoreComparison::Unconfirmed);
    assert!(exact.missing.availability && exact.missing.response && exact.missing.transfer);
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
    let other = context("different-business.example", IpVersion::V4);
    assert_eq!(
        verification_at(&manager, &nodes, &other, now + Duration::from_secs(2)).state,
        ScoreVerificationState::Provisional
    );
    let fallback = verification_at(&manager, &nodes, &other, now + Duration::from_secs(2));
    assert_eq!(fallback.basis, ScoreEvidenceBasis::AggregateResponse);
    assert_eq!(fallback.comparison, ScoreComparison::Unconfirmed);
    assert!(fallback.missing.availability && fallback.missing.response);
    let singleton = verification_at(&manager, &nodes[..1], &target, now + Duration::from_secs(2));
    assert_eq!(singleton.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(singleton.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(singleton.candidate_count, 1);
}

#[test]
fn one_unrelated_probe_cannot_suppress_comparable_http_pair() {
    let nodes = [node("raw-direct"), node("http-slow"), node("http-fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    let uri = "https://health.example/check";
    for (leaf, latency) in nodes[1..].iter().zip([600, 10]) {
        let feedback = manager
            .feedback_for_http_probe(leaf.id, probe.clone(), uri, uri)
            .unwrap()
            .with_probe_identity(uri, "HEAD");
        for _ in 0..4 {
            let reporter = feedback.start_at(now);
            reporter.probe_latency_at(Duration::from_millis(latency), now);
            reporter.finish_at(ScoreOutcome::Success, false, now);
        }
    }
    assert_eq!(
        manager
            .score_state()
            .peek_rank("score", &aggregate, &nodes.iter().collect::<Vec<_>>()),
        2
    );
    let snapshot = verification_at(&manager, &nodes, &aggregate, now);
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(snapshot.compared_count, 2);
    assert_eq!(snapshot.pending_count, 3);
    assert_eq!(snapshot.basis, ScoreEvidenceBasis::ConfiguredProbe);
}

#[test]
fn sparse_cancellations_rotate_without_confirmation_or_unbounded_exposure() {
    let nodes = [node("working"), node("cancelled-a"), node("cancelled-b")];
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
    let mut trials = [0u64; 3];
    for step in 0..16 {
        let at = now + Duration::from_secs(2) + REVALIDATION_INTERVAL * step;
        train_at(
            &manager,
            &nodes[0],
            &target,
            5,
            Duration::from_millis(100),
            1,
            at,
        );
        let before = state.verification_counters("score", SelectionNetwork::Tcp);
        for _ in 0..10 {
            verification_at(&manager, &nodes, &target, at);
        }
        assert_eq!(
            state.verification_counters("score", SelectionNetwork::Tcp),
            before
        );
        let index = rank_at(&manager, &nodes, &target, at);
        assert_ne!(index, 0);
        trials[index] += 1;
        manager
            .feedback_for_group_node("score", nodes[index].id, target.clone())
            .unwrap()
            .start_at(at)
            .finish_at(ScoreOutcome::Cancelled, true, at);
        let snapshot = verification_at(&manager, &nodes, &target, at);
        assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
        assert_eq!(snapshot.pending_count, 2);
        assert_eq!(
            snapshot.next_action,
            ScoreValidationAction::NextBusinessFlow
        );
    }
    assert_eq!(trials, [0, 8, 8]);
    let counts = state.verification_counters("score", SelectionNetwork::Tcp);
    assert_eq!(counts.validation_selections, 16);
    assert_eq!(
        counts.confirmations, 1,
        "only the selected known usable path is confirmed"
    );
    assert_eq!(counts.provisional_selections, 16);
}

#[test]
fn exhausted_budget_and_retired_authority_cannot_publish_confirmation() {
    let nodes = [node("unknown-a"), node("unknown-b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    for _ in 0..64 {
        rank_at(&manager, &nodes, &target, now);
    }
    let snapshot = verification_at(&manager, &nodes, &target, now);
    assert_eq!(snapshot.state, ScoreVerificationState::Provisional);
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(snapshot.pending_count, 2);
    assert_eq!(
        snapshot.next_action,
        ScoreValidationAction::NextBusinessFlow
    );
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    assert_eq!(before.confirmations, 0);
    assert!(before.validation_selections <= 2 + 64 / exploration_period(2));
    let authority = state.inner.lock().active_authority.clone().unwrap();
    state.publish_membership(nodes.iter().map(|node| ("score".to_owned(), node.id)));
    state.rank(
        &authority,
        "score",
        &target,
        &nodes.iter().collect::<Vec<_>>(),
    );
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
}

#[test]
fn fresh_excluded_failure_is_known_inferior_not_an_unknown_rival() {
    let nodes = [node("working"), node("slower"), node("failed")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([10, 100, 1]) {
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
    for _ in 0..3 {
        manager
            .feedback_for_group_node("score", nodes[2].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let snapshot = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    assert_eq!(snapshot.comparison, ScoreComparison::Supported);
    assert_eq!(snapshot.candidate_count, 3);
    assert_eq!(snapshot.compared_count, 2);
    assert_eq!(snapshot.pending_count, 0);
    let at = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    for leaf in &nodes[..2] {
        train_at(
            &manager,
            leaf,
            &target,
            5,
            Duration::from_millis(100),
            1,
            at,
        );
    }
    let snapshot = verification_at(&manager, &nodes, &target, at + Duration::from_secs(2));
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(snapshot.pending_count, 1);
    assert_eq!(snapshot.next_action, ScoreValidationAction::Backoff);
}

#[test]
fn partial_success_cannot_pin_a_cancelled_validation_run_forever() {
    let nodes = [node("working"), node("partial"), node("other")];
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
    let at = now + Duration::from_secs(2);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 1);
    train_at(
        &manager,
        &nodes[1],
        &target,
        1,
        Duration::from_millis(10),
        1,
        at,
    );
    let mut run = 0;
    let mut max_run = 0;
    let mut other_trials = 0;
    for _ in 0..exploration_period(3) * 12 {
        let before = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        let index = rank_at(&manager, &nodes, &target, at);
        let after = state.selection_reason_counts("score", SelectionNetwork::Tcp);
        if after.periodic_explore > before.periodic_explore {
            if index == 1 {
                run += 1;
                max_run = max_run.max(run);
            } else {
                run = 0;
                other_trials += 1;
            }
        }
        if index != 0 {
            manager
                .feedback_for_group_node("score", nodes[index].id, target.clone())
                .unwrap()
                .start_at(at)
                .finish_at(ScoreOutcome::Cancelled, true, at);
        }
    }
    assert!(max_run <= 8);
    assert!(other_trials > 0);
    assert_eq!(
        verification_at(&manager, &nodes, &target, at).comparison,
        ScoreComparison::Unconfirmed
    );
}

#[test]
fn availability_validity_does_not_depend_on_decaying_terminal_completions() {
    let nodes = [node("barely-qualified")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    manager.score_state().inner.lock().exact.put(
        ExactKey {
            group: "score".into(),
            network: target.network,
            family: IpVersion::V4,
            target: target.target.clone().unwrap(),
            node_id: nodes[0].id,
        },
        trained_stats(4.0, 100.0, now),
    );
    let snapshot = verification_at(&manager, &nodes, &target, now);
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    let validity = snapshot.valid_for_ms.unwrap();
    assert_eq!(validity, 60_000);
    assert_eq!(
        verification_at(&manager, &nodes, &target, now + Duration::from_secs(1)).state,
        ScoreVerificationState::ObservedUsable
    );
    assert_eq!(
        verification_at(
            &manager,
            &nodes,
            &target,
            now + Duration::from_millis(validity + 1)
        )
        .state,
        ScoreVerificationState::Provisional
    );
}

#[test]
fn removed_confirmed_winner_defers_revocation_count_until_apply() {
    let nodes = [node("removed"), node("retained")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([10, 100]) {
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
    let at = now + Duration::from_secs(2);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    let state = manager.score_state();
    let before = state.verification_counters("score", SelectionNetwork::Tcp);
    let remaining = &nodes[1..];
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", remaining)],
        remaining,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    assert_eq!(
        verification_at(&replacement, remaining, &target, at).state,
        ScoreVerificationState::Provisional
    );
    assert_eq!(
        state.verification_counters("score", SelectionNetwork::Tcp),
        before
    );
    rank_at(&replacement, remaining, &target, at);
    assert_eq!(
        state
            .verification_counters("score", SelectionNetwork::Tcp)
            .contradicted,
        before.contradicted + 1
    );
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .switch_flap,
        0
    );
}

#[test]
fn singleton_can_prove_transfer_observation_without_a_comparison() {
    let nodes = [node("only")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("transfer.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        8,
        Duration::from_millis(50),
        128 * 1024,
        now,
    );
    let report = verification_at(&manager, &nodes, &target, now + Duration::from_secs(2));
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    assert!(!report.missing.transfer);
    assert_eq!(report.next_action, ScoreValidationAction::None);
}

#[test]
fn singleton_response_claim_expires_before_newer_business_success() {
    let nodes = [node("only")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("response.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        8,
        Duration::from_millis(50),
        1,
        now,
    );
    let later = now + Duration::from_secs(59);
    for _ in 0..8 {
        let reporter = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start_at(later);
        reporter.setup_succeeded_at(later);
        reporter.transfer_at(1, 1, later);
        reporter.finish_at(ScoreOutcome::Success, true, later);
    }
    let report = verification_at(&manager, &nodes, &target, later);
    assert_eq!(report.state, ScoreVerificationState::ObservedUsable);
    assert!(!report.missing.response);
    assert!(report.valid_for_ms.unwrap() <= 1050);
    let expired = verification_at(&manager, &nodes, &target, now + Duration::from_secs(61));
    assert_eq!(expired.state, ScoreVerificationState::ObservedUsable);
    assert!(expired.missing.response);
}

#[test]
fn a_measured_throughput_tradeoff_has_an_explicit_comparison_basis() {
    let nodes = [node("throughput"), node("response")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("tradeoff.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        8,
        Duration::from_millis(100),
        1_048_576,
        now,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        8,
        Duration::from_millis(90),
        65_536,
        now,
    );
    let at = now + Duration::from_secs(2);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    let report = verification_at(&manager, &nodes, &target, at);
    assert_eq!(report.comparison, ScoreComparison::Supported);
    assert_eq!(report.basis, ScoreEvidenceBasis::Download);
    assert_eq!(report.next_action, ScoreValidationAction::None);
}

#[test]
fn upload_support_is_not_hidden_by_a_qualified_download_comparison() {
    let nodes = [node("upload"), node("response"), node("download")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("direction.example", IpVersion::V4);
    let now = Instant::now();
    for (index, (latency, upload, download)) in [
        (100, 1_048_576, 524_288),
        (90, 524_288, 419_430),
        (200, 524_288, 1_048_576),
    ]
    .into_iter()
    .enumerate()
    {
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("score", nodes[index].id, target.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now + Duration::from_millis(latency));
            reporter.transfer_at(upload, download, now + Duration::from_secs(1));
            reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
        }
    }
    let at = now + Duration::from_secs(2);
    assert_eq!(rank_at(&manager, &nodes, &target, at), 0);
    let report = verification_at(&manager, &nodes, &target, at);
    assert_eq!(report.comparison, ScoreComparison::Supported);
    assert_eq!(report.basis, ScoreEvidenceBasis::Upload);
    assert_eq!(report.next_action, ScoreValidationAction::None);
}
