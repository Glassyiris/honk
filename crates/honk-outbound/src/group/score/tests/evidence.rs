use super::*;
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

#[test]
fn single_failure_layer_freshness_is_unchanged() {
    // Given: one aggregate failure cell with exactly one half-life of age.
    let node = node("leaf");
    let context = context("example.com", IpVersion::V4);
    let start = Instant::now();
    let mut inner = StateInner::default();
    inner.aggregate.put(
        AggregateKey {
            group: "score".into(),
            network: SelectionNetwork::Tcp,
            family: None,
            node_id: node.id,
        },
        Stats {
            setup_failure: 2.0,
            updated_at: Some(start),
            ..Default::default()
        },
    );

    // When: the scorer snapshots the single layer after one half-life.
    let score = score_snapshot(
        &inner,
        "score",
        &context,
        node.id,
        start + SCORE_EVIDENCE_HALF_LIFE,
    );

    // Then: existing decay remains unchanged and no absent layer contributes.
    println!("single failure layer envelope={:.12}", score.failures);
    assert_close(score.failures, 1.0);
}

fn layered_failure_value(ages: [Option<Duration>; 3]) -> f64 {
    let node = node("leaf");
    let context = context("example.com", IpVersion::V4);
    let start = Instant::now();
    let now = start + Duration::from_secs(60);
    let mut inner = StateInner::default();
    for (index, age) in ages.into_iter().enumerate() {
        let Some(age) = age else {
            continue;
        };
        let stats = Stats {
            setup_failure: 1.0,
            updated_at: Some(now - age),
            ..Default::default()
        };
        match index {
            0 | 1 => {
                inner.aggregate.put(
                    AggregateKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: (index == 1).then_some(IpVersion::V4),
                        node_id: node.id,
                    },
                    stats,
                );
            }
            2 => {
                inner.exact.put(
                    ExactKey {
                        group: "score".into(),
                        network: SelectionNetwork::Tcp,
                        family: IpVersion::V4,
                        target: context.target.clone().unwrap(),
                        node_id: node.id,
                    },
                    stats,
                );
            }
            _ => unreachable!(),
        }
    }
    score_snapshot(&inner, "score", &context, node.id, now).failures
}

#[test]
fn layered_failure_freshness_uses_one_envelope() {
    // Given: the same 30-second-old failure appears in overlapping layers.
    let age = Some(Duration::from_secs(30));

    // When: one, two, and three layers are independently snapshotted.
    let global_only = layered_failure_value([age, None, None]);
    let global_family = layered_failure_value([age, age, None]);
    let global_family_exact = layered_failure_value([age, age, age]);
    println!(
        "layered failure envelope: global_only={global_only:.12} global_family={global_family:.12} global_family_exact={global_family_exact:.12}"
    );

    // Then: replication does not increase the effective failure envelope.
    assert_close(global_family, global_only);
    assert_close(global_family_exact, global_only);
    let aged = layered_failure_value([
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
        Some(Duration::from_secs(SCORE_EVIDENCE_HALF_LIFE.as_secs() * 8)),
    ]);
    let incumbent =
        super::super::ranking::snapshot(&trained_stats(8.0, 100.0, Instant::now()), Instant::now());
    let challenger = ScoreSnapshot {
        failures: 0.0,
        ..incumbent
    };
    let retained = super::super::ranking::hold_decision(
        &ScoreSnapshot {
            failures: aged,
            ..incumbent
        },
        &challenger,
        super::super::ranking::performance_baseline(&[incumbent, challenger]),
    ) == HoldDecision::Held;
    println!("aged layered envelope={aged:.12} retained_incumbent={retained}");
    assert!(aged < SCORE_FAILURE_FORGIVENESS_THRESHOLD);
    assert!(retained);
}

#[test]
fn specific_failure_freshness_is_not_hidden() {
    // Given: global, family, and exact evidence are respectively 30, 20, and 10 seconds old.
    let global = evidence_decay(Duration::from_secs(30));
    let family = evidence_decay(Duration::from_secs(20));
    let exact = evidence_decay(Duration::from_secs(10));

    // When: all three overlapping layers are snapshotted together.
    let effective = layered_failure_value([
        Some(Duration::from_secs(30)),
        Some(Duration::from_secs(20)),
        Some(Duration::from_secs(10)),
    ]);
    println!(
        "specific failure envelope: global_30s={global:.12} family_20s={family:.12} exact_10s={exact:.12} effective={effective:.12}"
    );

    // Then: the freshest specific layer is the effective envelope.
    assert_close(effective, exact);
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
