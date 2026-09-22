use super::super::verification as verification_engine;
use super::*;

fn train_cross_pair_responses(
    manager: &GroupManager,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
    aligned: bool,
) {
    let later = now + Duration::from_secs(16);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            manager,
            leaf,
            target,
            4,
            Duration::from_millis(100 * (index as u64 + 1)),
            1,
            if aligned || index == 0 || index % 2 == 1 {
                now
            } else {
                later
            },
        );
    }
    train_at(
        manager,
        &nodes[0],
        target,
        4,
        Duration::from_millis(100),
        1,
        later,
    );
}

#[test]
fn cross_pair_response_misalignment_requests_funded_validation_for_control_and_challengers() {
    for aligned in [true, false] {
        let nodes = [node("timing a"), node("timing b"), node("timing c")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("timing.example", IpVersion::V4);
        let now = Instant::now();
        train_cross_pair_responses(&manager, &nodes, &target, now, aligned);
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = now + Duration::from_secs(19);
        let decision = decision_at(&state.inner.lock(), &nodes, &target, 0, at);
        assert_eq!(decision.ordinary.index, 0);
        assert!(decision.scores.iter().all(ScoreSnapshot::qualified));
        for index in [1, 2] {
            let pair = decision.pairs.get(index).unwrap();
            assert!(pair.response.is_some());
            assert!(pair.upload.is_none() && pair.download.is_none());
        }
        let evaluation = verification_engine::evaluate(&decision, &refs, &target, None, at);
        let budget_before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let verification_before = state.verification_counters("score", SelectionNetwork::Tcp);
        for _ in 0..4 {
            let snapshot = state
                .verification_snapshot_at("score", &target, &refs, at)
                .unwrap();
            assert_eq!(snapshot, evaluation.snapshot);
            assert!(!snapshot.missing.availability);
            assert_eq!(snapshot.missing.response, !aligned);
            assert_eq!(
                snapshot.comparison,
                if aligned {
                    ScoreComparison::Supported
                } else {
                    ScoreComparison::Unconfirmed
                }
            );
        }
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            budget_before
        );
        assert_eq!(
            state.verification_counters("score", SelectionNetwork::Tcp),
            verification_before
        );
        if aligned {
            assert_eq!(
                evaluation.snapshot.next_action,
                ScoreValidationAction::AwaitTransfer
            );
            assert!(
                evaluation
                    .candidates
                    .iter()
                    .all(|candidate| { candidate.question == ScoreEvidenceQuestion::None })
            );
            continue;
        }
        assert_eq!(
            evaluation.snapshot.question,
            ScoreEvidenceQuestion::Response
        );
        assert_eq!(
            evaluation.snapshot.next_action,
            ScoreValidationAction::NextBusinessFlow
        );
        assert_eq!(
            evaluation.snapshot.wait_reason,
            ScoreWaitReason::ComparableTraffic
        );
        assert_eq!(evaluation.snapshot.pending_count, 3);
        for candidate in &evaluation.candidates {
            assert_eq!(candidate.question, ScoreEvidenceQuestion::Response);
            assert_eq!(candidate.required, 4);
        }
        let mut reporters = Vec::new();
        for _ in 0..4 {
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
            assert_eq!(index, 1);
            reporters.push(attempt.begin_at(at).unwrap().start_at(at));
        }
        for reporter in reporters {
            reporter.finish_at(ScoreOutcome::Cancelled, true, at);
        }
        let spent = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(spent.trial_starts, 4);
        assert_eq!(spent.cold_trial_starts, 3);
        assert_eq!(spent.periodic_trial_starts, 1);
        assert_eq!(spent.reserved, 0);
        assert_eq!(spent.cold_available, 0);
        assert_eq!(spent.earned_available, 0);
        assert!(spent.spent <= spent.cold_allowance + spent.business_starts / spent.earning_period);
        let exhausted = state
            .verification_snapshot_at("score", &target, &refs, at)
            .unwrap();
        assert_eq!(exhausted.question, ScoreEvidenceQuestion::Response);
        assert_eq!(exhausted.wait_reason, ScoreWaitReason::Budget);
        assert_eq!(
            manager.score_budget_counters("score", SelectionNetwork::Tcp),
            spent
        );
        for step in 0..12 {
            let control_at = at + Duration::from_secs(1) + Duration::from_millis(step * 200);
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, control_at);
            assert_eq!(index, 0);
            let reporter = attempt.begin_at(control_at).unwrap().start_at(control_at);
            reporter.setup_succeeded_at(control_at);
            let response_at = control_at + Duration::from_millis(100);
            reporter.first_response_at(response_at);
            reporter.transfer_at(1, 1, response_at);
            reporter.finish_at(ScoreOutcome::Success, true, response_at);
        }
        let earned = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(earned.business_starts, 32);
        assert_eq!(earned.trial_starts, 4);
        assert_eq!(earned.earned_available, 1);
        let funded_at = at + Duration::from_secs(4);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, funded_at);
        assert_eq!(index, 1);
        attempt
            .begin_at(funded_at)
            .unwrap()
            .start_at(funded_at)
            .finish_at(ScoreOutcome::Cancelled, true, funded_at);
        let funded = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(funded.trial_starts, 5);
        assert_eq!(funded.periodic_trial_starts, 2);
        assert_eq!(funded.earned_available, 0);
        assert!(
            funded.spent + funded.reserved
                <= funded.cold_allowance + funded.business_starts / funded.earning_period
        );
    }
}

#[test]
fn cross_pair_response_misalignment_does_not_relabel_a_capped_nonparticipant() {
    let nodes = [
        node("timing a"),
        node("timing b"),
        node("timing c"),
        node("timing d"),
        node("timing e"),
        node("timing f"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("timing.example", IpVersion::V4);
    let now = Instant::now();
    train_cross_pair_responses(&manager, &nodes, &target, now, false);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = now + Duration::from_secs(19);
    let decision = decision_at(&state.inner.lock(), &nodes, &target, 0, at);
    assert_eq!(decision.ordinary.index, 0);
    let evaluation = verification_engine::evaluate(&decision, &refs, &target, None, at);
    assert_eq!(evaluation.snapshot.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(evaluation.snapshot.pending_count, 5);
    for (index, candidate) in evaluation.candidates.iter().enumerate() {
        assert_eq!(
            candidate.question,
            if index == 0 || decision.pairs.get(index).is_some() {
                ScoreEvidenceQuestion::Response
            } else {
                ScoreEvidenceQuestion::None
            }
        );
    }
}

#[test]
fn cross_pair_response_repair_requires_shared_fresh_reporters_after_old_blocks_expire() {
    let nodes = [node("timing a"), node("timing b"), node("timing c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("timing.example", IpVersion::V4);
    let now = Instant::now();
    train_cross_pair_responses(&manager, &nodes, &target, now, false);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    for (offset, samples) in [(32, 1), (96, 1), (98, 3)] {
        let at = now + Duration::from_secs(offset);
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                samples,
                Duration::from_millis(100 * (index as u64 + 1)),
                1,
                at,
            );
        }
        let snapshot = state
            .verification_snapshot_at("score", &target, &refs, at + Duration::from_secs(2))
            .unwrap();
        if offset == 98 {
            assert_eq!(snapshot.comparison, ScoreComparison::Supported);
            assert!(!snapshot.missing.response);
            assert_eq!(snapshot.pending_count, 0);
            assert_eq!(snapshot.next_action, ScoreValidationAction::AwaitTransfer);
        } else {
            assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
            assert!(snapshot.missing.response);
            if offset == 32 {
                assert!(!snapshot.missing.availability);
                assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
            } else {
                let decision = decision_at(
                    &state.inner.lock(),
                    &nodes,
                    &target,
                    0,
                    at + Duration::from_secs(2),
                );
                for index in [1, 2] {
                    assert!(decision.pairs.get(index).unwrap().response.is_none());
                }
            }
        }
    }
}

#[test]
fn disjoint_response_support_schedules_comparable_business_not_bulk_transfer() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("shared.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[1],
        &target,
        8,
        Duration::from_millis(100),
        1,
        now,
    );
    let later = now + Duration::from_secs(16);
    train_at(
        &manager,
        &nodes[0],
        &target,
        8,
        Duration::from_millis(10),
        1,
        later,
    );
    let at = later + Duration::from_secs(2);
    let state = manager.score_state();
    let snapshot = state
        .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at)
        .unwrap();
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(snapshot.question, ScoreEvidenceQuestion::Response);
    assert_eq!(
        snapshot.next_action,
        ScoreValidationAction::NextBusinessFlow
    );
    assert_eq!(snapshot.wait_reason, ScoreWaitReason::ComparableTraffic);
    let (index, feedback) =
        state.rank_plan_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at);
    assert_eq!(index, 1);
    feedback
        .begin_at(at)
        .unwrap()
        .start_at(at)
        .finish_at(ScoreOutcome::Cancelled, true, at);
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        1
    );
}

#[test]
fn aggregate_transfer_claim_expires_with_crossed_direction_support() {
    let nodes = [node("uploader"), node("downloader")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("shared.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now + Duration::from_millis(100));
            let (tx, rx) = if index == 0 {
                (1_048_576, 524_288)
            } else {
                (524_288, 1_048_576)
            };
            reporter.transfer_at(tx, rx, now + Duration::from_secs(1));
            reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
        }
    }
    let later = now + Duration::from_secs(45);
    for leaf in &nodes {
        let reporter = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .start_at(later);
        reporter.setup_succeeded_at(later);
        reporter.transfer_at(1, 1, later + Duration::from_secs(1));
        reporter.finish_at(
            ScoreOutcome::Cancelled,
            true,
            later + Duration::from_secs(1),
        );
    }
    let state = manager.score_state();
    let snapshot = state
        .verification_snapshot_at(
            "score",
            &aggregate,
            &nodes.iter().collect::<Vec<_>>(),
            later + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(snapshot.comparison, ScoreComparison::Unconfirmed);
    assert!(snapshot.local_comparison.directional_tradeoff);
    assert!(!snapshot.missing.transfer);
    assert_eq!(snapshot.next_action, ScoreValidationAction::None);
    assert_eq!(snapshot.question, ScoreEvidenceQuestion::None);
    assert_eq!(snapshot.wait_reason, ScoreWaitReason::None);
    assert!(snapshot.valid_for_ms.unwrap() <= 13_100);
    let expired = state
        .verification_snapshot_at(
            "score",
            &aggregate,
            &nodes.iter().collect::<Vec<_>>(),
            now + Duration::from_secs(61),
        )
        .unwrap();
    assert!(expired.missing.transfer);
}

#[test]
fn winner_only_probe_does_not_replace_common_business_response_evidence() {
    let nodes = [node("business winner"), node("business peer")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("shared.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            4,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    let at = now + Duration::from_secs(2);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let before = state
        .verification_snapshot_at("score", &aggregate, &refs, at)
        .unwrap();
    assert_eq!(before.comparison, ScoreComparison::Equivalent);
    assert_eq!(before.basis, ScoreEvidenceBasis::CommonTargets);
    let winner = state.peek_rank_at("score", &aggregate, &refs, at);
    probe_at(
        &manager,
        &nodes[winner],
        &context("health.example", IpVersion::V4),
        ScoreSource::HealthProbe,
        Duration::from_millis(100),
        at,
    );
    let after = state
        .verification_snapshot_at("score", &aggregate, &refs, at)
        .unwrap();
    assert_eq!(after.comparison, before.comparison);
    assert_eq!(after.missing, before.missing);
    assert_eq!(after.evidence_age_ms, before.evidence_age_ms);
    assert_eq!(after.valid_for_ms, before.valid_for_ms);
}

#[test]
fn comparison_validity_cannot_outlive_a_required_candidate_availability_lease() {
    let nodes = [node("fresh winner"), node("older availability")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("lease.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(now);
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now + Duration::from_millis(100));
            reporter.transfer_at(1, 1, now + Duration::from_secs(10));
            reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(10));
        }
    }
    let later = now + Duration::from_secs(61);
    for (index, leaf) in nodes.iter().enumerate() {
        for _ in 0..4 {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .start_at(later);
            reporter.setup_succeeded_at(later);
            reporter.first_response_at(later + Duration::from_millis(100));
            reporter.transfer_at(u64::from(index == 0), 1, later + Duration::from_millis(100));
            reporter.finish_at(
                ScoreOutcome::Cancelled,
                true,
                later + Duration::from_millis(100),
            );
        }
        probe_at(
            &manager,
            leaf,
            &context("health.example", IpVersion::V4),
            ScoreSource::HealthProbe,
            Duration::from_millis(100),
            later,
        );
    }
    let state = manager.score_state();
    for scope in [&target, &aggregate] {
        let snapshot = state
            .verification_snapshot_at(
                "score",
                scope,
                &nodes.iter().collect::<Vec<_>>(),
                now + Duration::from_secs(62),
            )
            .unwrap();
        assert_eq!(snapshot.comparison, ScoreComparison::Equivalent);
        assert_eq!(snapshot.valid_for_ms, Some(8000));
        let expired = state
            .verification_snapshot_at(
                "score",
                scope,
                &nodes.iter().collect::<Vec<_>>(),
                now + Duration::from_secs(71),
            )
            .unwrap();
        assert_eq!(expired.comparison, ScoreComparison::Unconfirmed);
        assert!(expired.missing.availability && expired.missing.response);
    }
}

#[test]
fn response_age_uses_event_time_while_validity_uses_the_support_block() {
    let nodes = [node("timed evidence")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    let seed = manager
        .feedback_for_group_node(
            "score",
            nodes[0].id,
            context("block-origin.example", IpVersion::V4),
        )
        .unwrap()
        .start_at(start);
    seed.setup_succeeded_at(start);
    seed.first_response_at(start);
    seed.finish_at(ScoreOutcome::Cancelled, false, start);
    let target = context("observed-later.example", IpVersion::V4);
    let observed = start + Duration::from_secs(7);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    for _ in 0..4 {
        let reporter = feedback.start_at(observed);
        reporter.setup_succeeded_at(observed);
        reporter.first_response_at(observed);
        reporter.transfer_at(1, 1, observed);
        reporter.finish_at(ScoreOutcome::Success, true, observed);
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let snapshot = state
        .verification_snapshot_at("score", &target, &refs, start + Duration::from_secs(9))
        .unwrap();
    assert_eq!(snapshot.state, ScoreVerificationState::ObservedUsable);
    assert!(!snapshot.missing.response);
    assert_eq!(snapshot.evidence_age_ms, Some(2000));
    assert_eq!(snapshot.valid_for_ms, Some(51_000));
    let expired = state
        .verification_snapshot_at("score", &target, &refs, start + Duration::from_secs(60))
        .unwrap();
    assert_eq!(expired.state, ScoreVerificationState::ObservedUsable);
    assert!(expired.missing.response);
}

#[test]
fn sparse_common_support_is_local_only_and_completeness_recovers() {
    let nodes = [node("partial a"), node("partial b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let dense = context("a.dense.example", IpVersion::V4);
    let sparse = context("b.sparse.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &sparse,
            1,
            Duration::from_millis(100),
            1,
            now,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let unknown = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        unknown.local_comparison.comparison,
        ScoreComparison::Unconfirmed
    );
    assert!(unknown.missing.response);
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &dense,
            4,
            Duration::from_millis(100),
            1,
            now + Duration::from_secs(2),
        );
    }
    let partial = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(4))
        .unwrap();
    assert_eq!(partial.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(
        partial.local_comparison.comparison,
        ScoreComparison::Equivalent
    );
    assert_eq!(
        partial.local_comparison.basis,
        ScoreEvidenceBasis::CommonTargets
    );
    assert!(partial.missing.response);
    assert_eq!(partial.question, ScoreEvidenceQuestion::Response);
    let exact = state
        .verification_snapshot_at("score", &dense, &refs, now + Duration::from_secs(4))
        .unwrap();
    assert_eq!(exact.comparison, ScoreComparison::Equivalent);
    assert!(!exact.missing.response);
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &sparse,
            3,
            Duration::from_millis(100),
            1,
            now + Duration::from_secs(4),
        );
    }
    let complete = state
        .verification_snapshot_at("score", &aggregate, &refs, now + Duration::from_secs(6))
        .unwrap();
    assert_eq!(complete.comparison, ScoreComparison::Equivalent);
    assert!(!complete.missing.response);
}
