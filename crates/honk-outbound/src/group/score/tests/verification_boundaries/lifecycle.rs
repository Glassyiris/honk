use super::*;

#[test]
fn banked_validation_completes_with_real_interleaved_control_flows() {
    let nodes = [node("run control"), node("run challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("run.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            Duration::from_millis(100 + 15 * index as u64),
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    assert_eq!(
        state
            .rank_plan_at("score", &target, &refs, start + Duration::from_secs(2))
            .0,
        0
    );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    let mut allocated = [0_usize; 2];
    for step in 0..8 {
        let at = start + Duration::from_secs(75 + step * 5);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        allocated[index] += 1;
        let reporter = attempt.begin_at(at).unwrap().start_at(at);
        reporter.setup_succeeded_at(at);
        let received = at + Duration::from_millis(100 + 15 * index as u64);
        reporter.first_response_at(received);
        reporter.transfer_at(1, 1, received);
        reporter.finish_at(ScoreOutcome::Success, true, received);
        let counters = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert!(
            counters.spent + counters.reserved
                <= counters.cold_allowance + counters.business_starts / counters.earning_period
        );
    }
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(allocated, [4, 4]);
    assert_eq!(after.business_starts - before.business_starts, 8);
    assert_eq!(after.trial_starts - before.trial_starts, 4);
    let snapshot = state
        .verification_snapshot_at("score", &target, &refs, start + Duration::from_secs(111))
        .unwrap();
    assert_eq!(snapshot.comparison, ScoreComparison::Supported);
    assert!(!snapshot.missing.response);
    assert_eq!(snapshot.pending_count, 0);
}

#[test]
fn unbegun_run_plans_expire_refund_and_do_not_advance_control() {
    let nodes = [node("pending control"), node("pending challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("pending-run.example", IpVersion::V4);
    let other = context("different-run.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            Duration::from_millis(100 + 15 * index as u64),
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    assert_eq!(
        state
            .rank_plan_at("score", &target, &refs, start + Duration::from_secs(2))
            .0,
        0
    );
    let at = start + Duration::from_secs(75);
    let (index, unbegun) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    drop(unbegun);
    let (index, control) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    let reporter = control.begin_at(at).unwrap().start_at(at);
    reporter.setup_succeeded_at(at);
    reporter.first_response_at(at + Duration::from_millis(100));
    reporter.transfer_at(1, 1, at + Duration::from_millis(100));
    reporter.finish_at(ScoreOutcome::Success, true, at + Duration::from_millis(100));
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at + Duration::from_secs(1));
    assert_eq!(index, 1);
    let reserved = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(reserved.reserved, 1);
    for _ in 0..8 {
        let (_, ordinary) = state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(2));
        ordinary
            .begin_at(at + Duration::from_secs(2))
            .unwrap()
            .start_at(at + Duration::from_secs(2))
            .finish_at(ScoreOutcome::Cancelled, true, at + Duration::from_secs(2));
    }
    assert_eq!(
        manager
            .score_budget_counters("score", SelectionNetwork::Tcp)
            .trial_starts,
        reserved.trial_starts
    );
    assert!(pending.begin_at(at + Duration::from_secs(45)).is_err());
    let expired = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(expired.reserved, 0);
    assert_eq!(expired.refunded, reserved.refunded + 1);
    assert_eq!(expired.spent, reserved.spent);
}

#[test]
fn node_failure_between_run_plan_and_begin_cancels_unstarted_exposure() {
    let nodes = [node("fenced control"), node("fenced challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("fenced-run.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            128,
            Duration::from_millis(100 + 15 * index as u64),
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(75);
    let (_, pending) = state.rank_plan_at("score", &target, &refs, at);
    let failure = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(at);
    failure.finish_at(
        ScoreOutcome::NodeFailure,
        true,
        at + Duration::from_millis(1),
    );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(pending.begin_at(at + Duration::from_millis(2)).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts);
    assert_eq!(after.spent, before.spent);
}

#[test]
fn other_target_reference_and_escape_preserve_pending_validation() {
    for escape in [false, true] {
        let nodes = [node("isolated control"), node("isolated challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("active-run.example", IpVersion::V4);
        let other = context("other-run.example", IpVersion::V4);
        let start = Instant::now();
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                128,
                Duration::from_millis(100 + 15 * index as u64),
                1,
                start,
            );
            train_at(
                &manager,
                leaf,
                &other,
                128,
                Duration::from_millis(if (index == 0) == escape { 100 } else { 200 }),
                1,
                start,
            );
        }
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = start + Duration::from_secs(75);
        if escape {
            assert_eq!(
                state
                    .rank_plan_at("score", &other, &refs, start + Duration::from_secs(2))
                    .0,
                0
            );
        }
        let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 0);
        if escape {
            manager
                .feedback_for_group_node("score", nodes[0].id, other.clone())
                .unwrap()
                .start_at(at)
                .finish_at(
                    ScoreOutcome::TargetFailure,
                    true,
                    at + Duration::from_millis(1),
                );
        }
        let (index, unrelated) =
            state.rank_plan_at("score", &other, &refs, at + Duration::from_secs(1));
        assert_eq!(index, 1);
        answer_run_attempt(unrelated, at + Duration::from_secs(1));
        answer_run_attempt(pending, at + Duration::from_secs(2));
    }
}

#[test]
fn binding_a_staged_run_fences_its_original_unbegun_plan() {
    let nodes = [node("staged control"), node("staged challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("staged.example", IpVersion::V4);
    let start = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            if index == 0 { 8 } else { 1 },
            Duration::from_millis(100),
            1,
            start,
        );
    }
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(2);
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 1);
    let (index, ordinary) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 0);
    drop(ordinary);
    manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(at)
        .finish_at(
            ScoreOutcome::NodeFailure,
            true,
            at + Duration::from_millis(1),
        );
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(pending.begin_at(at + Duration::from_millis(2)).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.business_starts, before.business_starts);
    assert_eq!(after.spent, before.spent);
    assert_eq!(after.refunded, before.refunded + 1);
}

#[test]
fn staged_run_releases_unanswered_focus_after_sixteen_matching_offers() {
    let nodes = [node("known control"), node("unanswered challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &context("old.example", IpVersion::V4),
        20,
        Duration::from_millis(100),
        1,
        start,
    );
    let target = context("unanswered.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let at = start + Duration::from_secs(2);
    let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
    assert_eq!(index, 1);
    let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    for _ in 0..16 {
        let (index, ordinary) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 0);
        ordinary
            .begin_at(at)
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    assert!(pending.begin_at(at).is_err());
    let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert_eq!(after.spent, before.spent);
    assert_eq!(after.business_starts, before.business_starts + 16);
    assert_eq!(after.refunded, before.refunded + 1);
}

#[test]
fn promising_cold_target_run_waits_for_ordinary_reference_observation() {
    let nodes = [
        node("known control"),
        node("first cold challenger"),
        node("other cold challenger"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &context("old.example", IpVersion::V4),
        20,
        Duration::from_millis(100),
        1,
        start,
    );
    let target = context("new.example", IpVersion::V4);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let mut challenger_replies = 0;
    for step in 0..12 {
        let at = start + Duration::from_secs(2 + step);
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        assert!(
            index <= 1,
            "a new target must not scatter a promising staged challenger"
        );
        if step == 0 {
            assert_eq!(index, 1);
        }
        challenger_replies += usize::from(index == 1);
        answer_run_attempt(attempt, at);
        if challenger_replies == 4 {
            break;
        }
    }
    assert_eq!(challenger_replies, 4);
}

#[test]
fn staged_failure_invalidates_pending_work_without_another_rank() {
    for (failed_index, outcome, unrelated, admitted) in [
        (0, ScoreOutcome::TargetFailure, false, false),
        (1, ScoreOutcome::TargetFailure, false, false),
        (0, ScoreOutcome::TargetFailure, true, true),
        (1, ScoreOutcome::TargetFailure, true, true),
        (0, ScoreOutcome::NodeFailure, true, false),
        (1, ScoreOutcome::NodeFailure, true, false),
        (0, ScoreOutcome::shared_node_failure(), false, true),
    ] {
        let nodes = [node("staged control"), node("staged challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("staged.example", IpVersion::V4);
        let failed_target = if unrelated {
            context("other.example", IpVersion::V6)
        } else {
            target.clone()
        };
        let feedback = manager
            .feedback_for_group_node("score", nodes[failed_index].id, failed_target)
            .unwrap();
        let start = Instant::now();
        let delayed = if matches!(outcome, ScoreOutcome::SharedNodeFailure(_)) {
            let delayed = feedback.start_at(start);
            feedback.start_at(start).finish_at(outcome, true, start);
            Some(delayed)
        } else {
            None
        };
        for (index, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                if index == 0 { 8 } else { 1 },
                Duration::from_millis(100),
                1,
                start + Duration::from_secs(1),
            );
        }
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let at = start + Duration::from_secs(3);
        let (index, pending) = state.rank_plan_at("score", &target, &refs, at);
        assert_eq!(index, 1);
        delayed.unwrap_or_else(|| feedback.start_at(at)).finish_at(
            outcome,
            true,
            at + Duration::from_millis(1),
        );
        let before = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        let guard = pending.begin_at(at + Duration::from_millis(2));
        assert_eq!(
            guard.is_ok(),
            admitted,
            "failed_index={failed_index}, outcome={outcome:?}, unrelated={unrelated}"
        );
        drop(guard);
        let after = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        assert_eq!(
            after.business_starts,
            before.business_starts + u64::from(admitted)
        );
        assert_eq!(after.spent, before.spent + u64::from(admitted));
        assert_eq!(after.refunded, before.refunded + u64::from(!admitted));
    }
}
