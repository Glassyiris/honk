use super::*;

#[test]
fn recovered_historical_failure_holds_five_percent_latency_jitter() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let past = now - Duration::from_secs(3600);
    let failure = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(past);
    failure.setup_succeeded_at(past);
    failure.finish_at(ScoreOutcome::Io(io::ErrorKind::ConnectionReset), true, past);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            200,
            Duration::from_millis(100 + index as u64 * 10),
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(4)),
        0
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        200,
        Duration::from_millis(95),
        1,
        now + Duration::from_secs(5),
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(7)),
        0
    );
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.incumbent_held, 1);
    assert_eq!(reasons.fresh_failure_bypass, 0);
}

#[test]
fn only_newer_business_rx_restores_incumbent_protection() {
    for recovery in [
        "none",
        "old-rx",
        "same-time-rx",
        "setup-only",
        "probe",
        "warmup",
        "neutral",
        "other-target",
        "business-rx",
        "new-rx-before-old-finish",
    ] {
        let nodes = [node("incumbent"), node("challenger")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
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
        let late = matches!(
            recovery,
            "old-rx" | "same-time-rx" | "new-rx-before-old-finish"
        )
        .then(|| {
            let at = if recovery == "same-time-rx" {
                failed_at
            } else {
                failed_at - Duration::from_secs(1)
            };
            let reporter = feedback.start_at(at);
            reporter.setup_succeeded_at(at);
            reporter.transfer_at(1, 1, at);
            reporter
        });
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
        match recovery {
            "business-rx" | "new-rx-before-old-finish" | "other-target" => {
                let recovered_target = if recovery == "other-target" {
                    context("other.example", IpVersion::V4)
                } else {
                    target.clone()
                };
                train_at(
                    &manager,
                    &nodes[0],
                    &recovered_target,
                    20,
                    Duration::from_millis(100),
                    1,
                    at,
                );
            }
            "setup-only" | "neutral" | "probe" | "warmup" => {
                let source = match recovery {
                    "probe" => ScoreSource::HealthProbe,
                    "warmup" => ScoreSource::Warmup,
                    _ => ScoreSource::Traffic,
                };
                let reporter = feedback.clone().with_source(source).start_at(at);
                reporter.setup_succeeded_at(at);
                if recovery != "setup-only" {
                    reporter.transfer_at(1, 1, at);
                }
                let outcome = if recovery == "neutral" {
                    ScoreOutcome::Cancelled
                } else {
                    ScoreOutcome::Success
                };
                reporter.finish_at(outcome, recovery != "setup-only", at);
            }
            _ => {}
        }
        let selected_at = now + Duration::from_secs(11);
        if let Some(late) = late {
            late.finish_at(ScoreOutcome::Success, true, selected_at);
        }
        let recovered = matches!(
            recovery,
            "business-rx" | "new-rx-before-old-finish" | "neutral"
        );
        assert_eq!(
            rank_at(&manager, &nodes, &target, selected_at),
            usize::from(!recovered),
            "{recovery}"
        );
        let reasons = manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp);
        assert_eq!(
            reasons.fresh_failure_bypass,
            u64::from(!recovered),
            "{recovery}"
        );
        assert_eq!(reasons.incumbent_ineligible, 0, "{recovery}");
    }
}

#[test]
fn stale_manager_authority_stays_revoked_after_same_name_recreation() {
    let survivor = node("survivor");
    let removed = node("removed");
    let replacement_node = node("replacement");
    let old_nodes = [survivor.clone(), removed.clone()];
    let old = super::super::super::GroupManager::new(&[group("score", &old_nodes)], &old_nodes);
    let state = old.score_state();
    let seeded_context = context("seeded.example", IpVersion::V4);
    finish_success(&old.selection_plan_for_target("score", &seeded_context));

    let deleted = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[],
        &[],
        None,
        Arc::clone(&state),
    );
    deleted.publish_score_membership();
    let replacement_nodes = [survivor.clone(), replacement_node];
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &replacement_nodes)],
        &replacement_nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.selection_counts.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!((before.1, before.2, before.3), (0, 0, 0));

    let stale = old.selection_plan_for_target("score", &context("stale.example", IpVersion::V4));
    assert!(stale.entries[0].feedback.is_none());
    assert!(
        old.feedback_for_group_node("score", survivor.id, seeded_context.clone())
            .is_none(),
        "the surviving ID must not restore old-manager feedback authority"
    );
    assert!(
        old.feedback_for_group_node("score", removed.id, seeded_context)
            .is_none(),
        "the replaced ID must not restore old-manager feedback authority"
    );
    let after_stale = {
        let inner = state.inner.lock();
        (
            inner.tick,
            inner.selection_counts.len(),
            inner.aggregate.len(),
            inner.exact.len(),
        )
    };
    assert_eq!(after_stale, before);

    let current =
        replacement.selection_plan_for_target("score", &context("current.example", IpVersion::V4));
    assert!(current.entries[0].feedback.is_some());
    let after_current = state.inner.lock();
    assert_eq!(after_current.selection_counts.len(), 1);
    assert_eq!(after_current.aggregate.len(), 1);
    assert!(after_current.tick > before.0);
}

#[test]
fn captured_feedback_requires_current_authority_at_start() {
    let nodes = [node("a"), node("b")];
    let old = super::super::super::GroupManager::new(&[group("score", &nodes)], &nodes);
    let context = context("captured.example", IpVersion::V4);
    let feedback = old
        .feedback_for_group_node("score", nodes[0].id, context.clone())
        .unwrap();
    let state = old.score_state();
    let replacement = super::super::super::GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes)],
        &nodes,
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    let before_tick = state.inner.lock().tick;

    let reporter = feedback.start();
    reporter.setup_succeeded();
    reporter.first_response();
    reporter.tx(123);
    reporter.rx(456);
    reporter.finish(ScoreOutcome::Timeout);
    drop(reporter);

    assert!(!state.has_exact("score", &context, nodes[0].id));
    assert_eq!(state.inner.lock().tick, before_tick);
}

pub(super) fn inner_update_response(state: &ScorePolicyState, key: AggregateKey, latency_ms: f64) {
    let mut inner = state.inner.lock();
    let stats = inner.aggregate.get_mut(&key).unwrap();
    stats.performance.response.sum = latency_ms * stats.performance.response.weight;
}

#[test]
fn parsed_score_policy_learns_without_a_feature_flag() {
    let config = honk_config::parser::parse_dae_config(
        r#"
node {
    a: 'socks5://127.0.0.1:10001'
    b: 'socks5://127.0.0.1:10002'
}
group {
    scored {
        policy: score
        filter: name('a', 'b')
    }
}
"#,
    )
    .unwrap();
    let manager = super::super::super::GroupManager::new(&config.groups, &config.nodes);
    let context = context("example.com", IpVersion::V4);

    let first = manager.selection_plan_for_target("scored", &context);
    assert_eq!(first.entries[0].node.name, "a");
    finish_failure(&first);

    let second = manager.selection_plan_for_target("scored", &context);
    assert_eq!(second.entries[0].node.name, "b");
    finish_success(&second);
    assert_eq!(
        manager
            .selection_plan_for_target("scored", &context)
            .entries[0]
            .node
            .id,
        config.nodes[1].id
    );
}
