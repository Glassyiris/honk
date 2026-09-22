use super::super::budget;
use super::*;

fn counts(manager: &GroupManager, group: &str) -> ScoreBudgetCounters {
    manager.score_budget_counters(group, SelectionNetwork::Tcp)
}

#[test]
fn unstarted_plans_refund_once_after_last_clone_without_minting_business() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("pending.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let first = plan.entries[0].feedback.as_ref().unwrap().clone();
    let second = first.clone();
    assert_eq!(counts(&manager, "score").reserved, 1);
    drop(plan);
    drop(first);
    assert_eq!(counts(&manager, "score").reserved, 1);
    drop(second);
    let after = counts(&manager, "score");
    assert_eq!(
        (after.business_starts, after.spent, after.reserved),
        (0, 0, 0)
    );
    assert_eq!((after.cold_available, after.refunded), (2, 1));
    assert_eq!(manager.score_state().root_business_starts(), 0);
}

#[test]
fn concurrent_begin_clones_spend_once_and_cancel_without_refund() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("clones.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let feedback = plan.entries[0].feedback.as_ref().unwrap().clone();
    assert!(feedback.continuation().is_err());
    assert!(feedback.clone().with_context(target.clone()).is_err());
    let mut guards = std::thread::scope(|scope| {
        let starts: Vec<_> = (0..32)
            .map(|_| {
                let clone = feedback.clone();
                scope.spawn(move || clone.begin())
            })
            .collect();
        starts
            .into_iter()
            .filter_map(|start| start.join().unwrap().ok())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        guards.len(),
        1,
        "cloned attempts must have one cancellation owner"
    );
    assert_eq!(counts(&manager, "score").trial_cancelled, 0);
    let started = counts(&manager, "score");
    assert_eq!(
        (started.business_starts, started.spent, started.reserved),
        (1, 1, 0)
    );
    assert_eq!(manager.score_state().root_business_starts(), 1);
    drop(guards.pop());
    let cancelled = counts(&manager, "score");
    assert_eq!(
        (
            cancelled.trial_cancelled,
            cancelled.refunded,
            cancelled.cold_available
        ),
        (1, 0, 1)
    );
    assert!(feedback.begin().is_err());
    assert_eq!(counts(&manager, "score"), cancelled);
    assert_eq!(
        manager
            .score_state()
            .exact_stats("score", &target, plan.entries[0].node.id),
        None
    );
}

#[test]
fn stale_generation_start_refunds_and_never_publishes_root_or_scope_counts() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("reload.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let state = manager.score_state();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes[..1])],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    assert!(plan.entries[0].feedback.as_ref().unwrap().begin().is_err());
    let after = counts(&replacement, "score");
    assert_eq!(
        (after.business_starts, after.spent, after.reserved),
        (0, 0, 0)
    );
    assert_eq!(
        (
            after.cold_allowance,
            after.cold_available,
            after.earning_period
        ),
        (2, 2, 16)
    );
    assert_eq!(state.root_business_starts(), 0);
    let new_plan =
        replacement.selection_plan_for_target("score", &context("new.example", IpVersion::V4));
    assert!(
        new_plan.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .is_ok()
    );
    assert_eq!(counts(&replacement, "score").scopes, 1);
    assert_eq!(counts(&replacement, "score").cold_allowance, 2);
}

#[test]
fn nested_losers_refund_and_selected_chain_shares_one_original_business() {
    let nodes = [node("a"), node("b"), node("c"), node("d")];
    let manager = GroupManager::new(
        &[
            group("left", &nodes[..2]),
            group("right", &nodes[2..]),
            group_with_children("score", &[], &["left", "right"]),
        ],
        &nodes,
    );
    let target = context("nested.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let feedback = plan.entries[0].feedback.as_ref().unwrap();
    let selected = feedback.attributions()[1].group.as_str();
    let loser = if selected == "left" { "right" } else { "left" };
    assert_eq!(counts(&manager, loser).reserved, 0);
    assert_eq!(counts(&manager, loser).refunded, 1);
    let _business = feedback.begin().unwrap();
    assert_eq!(manager.score_state().root_business_starts(), 1);
    assert_eq!(counts(&manager, "score").business_starts, 1);
    assert_eq!(counts(&manager, selected).business_starts, 1);
    assert_eq!(counts(&manager, loser).business_starts, 0);
    assert_eq!(counts(&manager, "score").spent, 1);
    assert_eq!(counts(&manager, selected).spent, 1);
}

#[test]
fn retry_and_related_context_preserve_original_identity_without_optional_cost() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("retry.example", IpVersion::V4);
    let original = manager.selection_plan_for_target("score", &target);
    let entry = &original.entries[0];
    let feedback = entry.feedback.as_ref().unwrap();
    feedback.begin().unwrap().finish(ScoreOutcome::Timeout);
    let retry = manager.score_retry_plan_for_target(
        "score",
        &target,
        entry.node.id,
        &entry.final_owners,
        &feedback.continuation().unwrap(),
    );
    let recovery = retry.entries[0].feedback.clone().unwrap();
    let _business = recovery.begin().unwrap();
    assert_eq!(counts(&manager, "score").business_starts, 1);
    assert_eq!(counts(&manager, "score").spent, 1);
    assert_eq!(counts(&manager, "score").reserved, 0);
    assert_eq!(
        (
            counts(&manager, "score").cold_trial_starts,
            counts(&manager, "score").recovery_starts
        ),
        (1, 1)
    );
    let mut udp = target.clone();
    udp.network = SelectionNetwork::Udp;
    udp.probe_domain = ProbeDomain::DnsUdp;
    let related = recovery.with_context(udp).unwrap();
    let _related = related.begin().unwrap();
    assert_eq!(manager.score_state().root_business_starts(), 1);
    let udp_counts = manager.score_budget_counters("score", SelectionNetwork::Udp);
    assert_eq!(
        (
            udp_counts.business_starts,
            udp_counts.spent,
            udp_counts.reserved
        ),
        (1, 0, 0)
    );
    assert_eq!(udp_counts.recovery_starts, 1);
}

#[test]
fn trial_outcomes_and_setup_histogram_do_not_change_terminal_reliability_units() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("telemetry.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target("score", &target);
    let start = Instant::now();
    let reporter = plan.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin_at(start)
        .unwrap()
        .start_at(start);
    reporter.setup_succeeded_at(start + Duration::from_millis(16));
    reporter.setup_succeeded_at(start + Duration::from_millis(20));
    let clone = reporter.clone();
    reporter.finish_at(
        ScoreOutcome::Cancelled,
        false,
        start + Duration::from_millis(30),
    );
    clone.finish_at(
        ScoreOutcome::Timeout,
        true,
        start + Duration::from_millis(40),
    );
    let c = counts(&manager, "score");
    assert_eq!(
        (
            c.trial_starts,
            c.trial_success,
            c.trial_failure,
            c.trial_cancelled
        ),
        (1, 0, 0, 1)
    );
    assert_eq!(c.trial_setup_histogram[4], 1);
    assert_eq!(c.trial_setup_histogram.iter().sum::<u64>(), 1);
    assert_eq!((c.trial_setup_millis, c.trial_elapsed_millis), (16, 30));
    assert_eq!(
        manager
            .score_state()
            .exact_stats("score", &target, plan.entries[0].node.id),
        Some((0, 0, 0))
    );
}

#[test]
fn earned_credit_is_capped_and_target_churn_or_peeks_never_replenish_cold_allowance() {
    let nodes: Vec<_> = (0..45)
        .map(|index| node(&format!("leaf-{index}")))
        .collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    for index in 0..640 {
        let target = context(&format!("{index}.example"), IpVersion::V4);
        let feedback = manager
            .feedback_for_group_node("score", nodes[0].id, target)
            .unwrap();
        feedback
            .business()
            .begin()
            .unwrap()
            .finish(ScoreOutcome::Cancelled);
    }
    let before = counts(&manager, "score");
    assert_eq!(
        (
            before.business_starts,
            before.cold_allowance,
            before.cold_available,
            before.earned_available
        ),
        (640, 8, 8, 8)
    );
    for _ in 0..64 {
        manager.get_score_selection_for_network("score", SelectionNetwork::Tcp);
        manager.score_verification_for_network("score", SelectionNetwork::Tcp);
    }
    assert_eq!(counts(&manager, "score"), before);
    assert_eq!(before.scopes, 1);
}

#[test]
fn sparse_arrivals_obey_spent_plus_reserved_bound_without_clock_currency() {
    let nodes: Vec<_> = (0..45)
        .map(|index| node(&format!("leaf-{index}")))
        .collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let start = Instant::now();
    for arrival in 0..128 {
        let now = start + Duration::from_secs(arrival * 3600);
        let target = context(&format!("arrival-{arrival}.example"), IpVersion::V4);
        let work = {
            let mut inner = state.inner.lock();
            budget::reserve(
                &state,
                &mut inner,
                "score",
                &target,
                nodes[0].id,
                (ScoreEvidenceQuestion::Availability, 4),
                now,
            )
        }
        .unwrap_or_else(|| {
            budget::Work::new(
                &state,
                "score",
                &target,
                nodes[0].id,
                ScoreTrialSource::None,
            )
        });
        let opportunity = budget::Opportunity::default();
        let attributions = [ScoreAttribution {
            group: "score".into(),
            node_id: nodes[0].id,
        }];
        let before = counts(&manager, "score");
        assert!(before.spent + before.reserved <= 8 + before.business_starts / 64);
        assert!(budget::begin(
            &state,
            &manager.score_authority,
            &target,
            &attributions,
            &opportunity,
            std::slice::from_ref(&work),
            now
        ));
        budget::finish(
            &state,
            std::slice::from_ref(&work),
            ScoreOutcome::Cancelled,
            now,
        );
        let after = counts(&manager, "score");
        assert!(after.spent + after.reserved <= 8 + after.business_starts / 64);
    }
    let c = counts(&manager, "score");
    assert_eq!(c.business_starts, 128);
    assert_eq!(
        c.spent, 9,
        "arrival 128 cannot borrow its own newly earned credit"
    );
    assert_eq!(c.earned_available, 1);
    assert_eq!(state.root_business_starts(), 128);
}

#[test]
fn pending_expiry_refunds_and_started_expiry_only_releases_suppression() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("expiry.example", IpVersion::V4);
    let now = Instant::now();
    let pending = budget::reserve(
        &state,
        &mut state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        (ScoreEvidenceQuestion::Availability, 1),
        now,
    )
    .unwrap();
    assert_eq!(
        budget::wait_reason(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            ScoreEvidenceQuestion::Availability,
            1,
            now
        ),
        ScoreWaitReason::InFlight
    );
    let later = now + Duration::from_secs(61);
    let next = budget::reserve(
        &state,
        &mut state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        (ScoreEvidenceQuestion::Availability, 1),
        later,
    )
    .unwrap();
    assert_eq!(counts(&manager, "score").refunded, 1);
    let attribution = [ScoreAttribution {
        group: "score".into(),
        node_id: nodes[0].id,
    }];
    assert!(!budget::begin(
        &state,
        &manager.score_authority,
        &target,
        &attribution,
        &budget::Opportunity::default(),
        std::slice::from_ref(&pending),
        later
    ));
    assert!(budget::begin(
        &state,
        &manager.score_authority,
        &target,
        &attribution,
        &budget::Opportunity::default(),
        std::slice::from_ref(&next),
        later
    ));
    let expired = later + Duration::from_secs(61);
    let replacement = budget::reserve(
        &state,
        &mut state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        (ScoreEvidenceQuestion::Availability, 1),
        expired,
    )
    .unwrap();
    assert_eq!(
        (
            counts(&manager, "score").spent,
            counts(&manager, "score").refunded
        ),
        (1, 1)
    );
    budget::finish(
        &state,
        std::slice::from_ref(&next),
        ScoreOutcome::Cancelled,
        expired,
    );
    drop(replacement);
    assert_eq!(
        (
            counts(&manager, "score").spent,
            counts(&manager, "score").reserved
        ),
        (1, 0)
    );
}

#[test]
fn setup_cost_includes_pre_reporter_work_and_local_refusal_is_neutral() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("setup-cost.example", IpVersion::V4);
    let state = manager.score_state();
    let start = Instant::now();
    let work = budget::reserve(
        &state,
        &mut state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        (ScoreEvidenceQuestion::Availability, 4),
        start,
    )
    .unwrap();
    let attributions = vec![ScoreAttribution {
        group: "score".into(),
        node_id: nodes[0].id,
    }];
    let opportunity = Arc::new(budget::Opportunity::default());
    let feedback = ScoreAttempt::planned(
        ScoreFeedback::new(
            state,
            Arc::clone(&manager.score_authority),
            target,
            attributions,
        ),
        opportunity,
        vec![work],
        ScoreTrialSource::None,
    );
    let business = feedback.begin_at(start).unwrap();
    let reporter = business.start_at(start + Duration::from_millis(40));
    reporter.setup_succeeded_at(start + Duration::from_millis(100));
    reporter.finish_at(
        ScoreOutcome::Rejected,
        false,
        start + Duration::from_millis(120),
    );
    let c = counts(&manager, "score");
    assert_eq!((c.trial_setup_millis, c.trial_elapsed_millis), (100, 120));
    assert_eq!(
        (c.trial_success, c.trial_failure, c.trial_cancelled),
        (0, 0, 1)
    );
}

#[test]
fn accepted_reporters_no_longer_suppress_missing_distinct_support() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("support.example", IpVersion::V4);
    let now = Instant::now();
    let reporter = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(now);
    reporter.setup_succeeded_at(now);
    reporter.transfer_at(1, 1, now + Duration::from_millis(10));
    let state = manager.score_state();
    assert_eq!(
        budget::wait_reason(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            ScoreEvidenceQuestion::Availability,
            1,
            now + Duration::from_millis(10)
        ),
        ScoreWaitReason::None
    );
    assert_eq!(
        budget::wait_reason(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            ScoreEvidenceQuestion::Qualification,
            1,
            now + Duration::from_millis(10)
        ),
        ScoreWaitReason::InFlight
    );
    reporter.finish_at(
        ScoreOutcome::Cancelled,
        false,
        now + Duration::from_millis(20),
    );
    assert_eq!(
        budget::wait_reason(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            ScoreEvidenceQuestion::Qualification,
            1,
            now + Duration::from_millis(20)
        ),
        ScoreWaitReason::None
    );
}

#[test]
fn reusable_factory_stays_independent_after_explicit_business_admission() {
    let nodes = [node("a"), node("b")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("template.example", IpVersion::V4);
    let feedback = manager
        .feedback_for_group_node("score", nodes[0].id, target)
        .unwrap();
    let reporters: Vec<_> = (0..4).map(|_| feedback.start()).collect();
    assert_eq!(counts(&manager, "score").business_starts, 4);
    assert_eq!(manager.score_state().root_business_starts(), 4);
    for reporter in reporters {
        reporter.finish(ScoreOutcome::Cancelled);
    }
    let attempt = feedback.business();
    let original = attempt.begin().unwrap().start();
    assert!(attempt.clone().begin().is_err());
    let clone = feedback.clone().start();
    assert_eq!(counts(&manager, "score").business_starts, 6);
    assert_eq!(manager.score_state().root_business_starts(), 6);
    original.finish(ScoreOutcome::Cancelled);
    clone.finish(ScoreOutcome::Cancelled);
}

#[test]
fn related_route_selections_do_not_reserve_optional_work_with_cold_credit_remaining() {
    let nodes = [node("a"), node("b"), node("c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("first.example", IpVersion::V4);
    let plan = manager.selection_plan_for_target_with_health_fallback("score", &target, None);
    let original = plan.entries[0].feedback.as_ref().unwrap();
    original
        .begin()
        .unwrap()
        .start()
        .finish(ScoreOutcome::Cancelled);
    let continuation = original.continuation().unwrap();
    let before = counts(&manager, "score");
    assert_eq!((before.spent, before.cold_available), (1, 2));
    for host in ["redirect.example", "reroute.example", "again.example"] {
        let target = context(host, IpVersion::V4);
        let related = manager.selection_plan_for_target_with_health_fallback(
            "score",
            &target,
            Some(&continuation),
        );
        let selected = counts(&manager, "score");
        assert_eq!(
            (selected.reserved, selected.spent, selected.refunded),
            (0, 1, 0)
        );
        related.entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .begin()
            .unwrap()
            .start()
            .finish(ScoreOutcome::Cancelled);
        assert_eq!(counts(&manager, "score").business_starts, 1);
        assert_eq!(manager.score_state().root_business_starts(), 1);
    }
    let after = counts(&manager, "score");
    assert_eq!(
        (
            after.trial_starts,
            after.recovery_starts,
            after.cold_available
        ),
        (1, 3, 2)
    );
    let fresh =
        manager.selection_plan_for_target("score", &context("new-original.example", IpVersion::V4));
    fresh.entries[0]
        .feedback
        .as_ref()
        .unwrap()
        .begin()
        .unwrap()
        .start()
        .finish(ScoreOutcome::Cancelled);
    assert_eq!(
        (
            counts(&manager, "score").business_starts,
            counts(&manager, "score").spent
        ),
        (2, 2)
    );
}
