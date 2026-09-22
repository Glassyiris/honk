use super::super::comparison::{
    self, Basis, MAX_CELLS, MAX_CHALLENGERS, MAX_LOGICAL_BYTES, PairEvidence,
};
use super::super::evidence::Observation;
use super::super::ranking::{ordinary_selection, performance_baseline};
use super::*;

fn exact(leaf: &Node, target: &ScoreSelectionContext) -> ExactKey {
    ExactKey {
        group: "score".into(),
        network: target.network,
        family: target.target_family.unwrap(),
        target: target.target.clone().unwrap(),
        node_id: leaf.id,
    }
}

fn publish(
    inner: &mut StateInner,
    leaf: &Node,
    target: &ScoreSelectionContext,
    id: u64,
    at: Instant,
    observation: Observation,
) {
    let key = exact(leaf, target);
    if inner.exact.peek(&key).is_none() {
        inner.tick += 1;
        inner.exact.put(
            key.clone(),
            Stats {
                incarnation: inner.tick,
                useful_success: 8.0,
                setup_success: 8.0,
                updated_at: Some(at),
                ..Stats::default()
            },
        );
    }
    let incarnation = inner.exact.peek(&key).unwrap().incarnation;
    let mut cells = [StartedCells {
        exact: Some(incarnation),
        ..StartedCells::default()
    }];
    let attribution = [ScoreAttribution {
        group: "score".into(),
        node_id: leaf.id,
    }];
    comparison::observe(
        inner,
        target,
        &attribution,
        (&cells, id),
        ScoreSource::Traffic,
        &observation,
        at,
    );
    inner.valid.insert(("score".into(), leaf.id));
    ScorePolicyState::observe(
        inner,
        target,
        &attribution,
        &mut cells,
        ScoreSource::Traffic,
        observation,
        at,
    );
}

fn response(
    inner: &mut StateInner,
    leaf: &Node,
    target: &ScoreSelectionContext,
    count: usize,
    ms: u64,
    at: Instant,
) {
    for _ in 0..count {
        publish(
            inner,
            leaf,
            target,
            comparison::next_reporter_id(),
            at,
            Observation::Response(Duration::from_millis(ms)),
        );
    }
}

fn scores(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> super::super::ranking::Decision {
    decision_at(inner, nodes, target, 0, now)
}

fn pair(
    inner: &StateInner,
    nodes: &[Node],
    target: &ScoreSelectionContext,
    now: Instant,
) -> PairEvidence {
    scores(inner, nodes, target, now).pairs.get(1).unwrap()
}

#[test]
fn common_targets_do_not_promote_a_simpson_mixture() {
    let now = Instant::now();
    let nodes = [node("mixture incumbent"), node("mixture candidate")];
    let fast = context("a.fast", IpVersion::V4);
    let slow = context("b.slow", IpVersion::V4);
    let unseen = context("unseen", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &fast, 4, 100, now);
    response(&mut inner, &nodes[0], &slow, 36, 1000, now);
    response(&mut inner, &nodes[1], &slow, 4, 1100, now);
    response(&mut inner, &nodes[1], &fast, 36, 110, now);
    let mut snapshots = scores(&inner, &nodes, &unseen, now);
    // Heuristic proposals may prefer the candidate's lighter mix; proof may not.
    for (score, ms) in snapshots.scores.iter_mut().zip([1000.0, 110.0]) {
        score.completed = 8.0;
        score.useful_completed = 8.0;
        score.performance.response = MetricSnapshot {
            value: Some(ms),
            confidence: 1.0,
        };
    }
    let evidence = snapshots.pairs.get(1).unwrap();
    assert_eq!(evidence.basis, Basis::CommonTargets);
    assert_close(evidence.response.unwrap().incumbent, 550.0);
    assert_close(evidence.response.unwrap().candidate, 605.0);
    let chosen = ordinary_selection(
        &snapshots.scores,
        &nodes.iter().collect::<Vec<_>>(),
        Some(0),
        performance_baseline(&snapshots.scores),
        &snapshots.pairs,
    );
    assert_eq!(chosen.index, 0);
}

#[test]
fn common_time_blocks_receive_equal_weights_not_reporter_mix_weights() {
    let now = Instant::now();
    let nodes = [node("block incumbent"), node("block candidate")];
    let target = context("blocks", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &target, 4, 100, now);
    response(&mut inner, &nodes[1], &target, 36, 110, now);
    response(
        &mut inner,
        &nodes[0],
        &target,
        36,
        1000,
        now + Duration::from_secs(15),
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1100,
        now + Duration::from_secs(15),
    );
    let metric = pair(&inner, &nodes, &target, now + Duration::from_secs(16))
        .response
        .unwrap();
    assert_close(metric.incumbent, 550.0);
    assert_close(metric.candidate, 605.0);
}

#[test]
fn a_fresh_sample_does_not_rejuvenate_old_blocks_or_diversity() {
    let now = Instant::now();
    let nodes = [node("age incumbent"), node("age candidate")];
    let target = context("independent-expiry", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        response(&mut inner, leaf, &target, 4, 100, now);
        response(
            &mut inner,
            leaf,
            &target,
            1,
            100,
            now + Duration::from_secs(45),
        );
    }
    let before = pair(&inner, &nodes, &target, now + Duration::from_secs(59))
        .response
        .unwrap();
    assert_eq!(before.expires_at, now + Duration::from_secs(60));
    assert_eq!(before.oldest_at, now);
    assert_eq!(before.span, Duration::from_secs(45));
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(60))
            .response
            .is_none()
    );
    let expired = scores(&inner, &nodes, &target, now + Duration::from_secs(60));
    assert!(expired.evidence[0].response.is_none());
    assert!(
        expired.scores[0]
            .target_performance
            .response
            .value
            .is_some()
    );
}

#[test]
fn reporter_diversity_is_a_union_not_a_sum_of_bucket_counts() {
    let now = Instant::now();
    let nodes = [node("union incumbent"), node("union candidate")];
    let target = context("union", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        let reporters: Vec<_> = (0..3).map(|_| comparison::next_reporter_id()).collect();
        for block in 0..4 {
            for id in &reporters {
                publish(
                    &mut inner,
                    leaf,
                    &target,
                    *id,
                    now + Duration::from_secs(block * 15),
                    Observation::Response(Duration::from_millis(100)),
                );
            }
        }
    }
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(46))
            .response
            .is_none()
    );
    for leaf in &nodes {
        response(
            &mut inner,
            leaf,
            &target,
            1,
            100,
            now + Duration::from_secs(47),
        );
    }
    assert_eq!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(48))
            .response
            .unwrap()
            .reporters,
        4
    );
}

#[test]
fn failures_delayed_events_and_recreated_incarnations_cannot_revive_proof() {
    let now = Instant::now();
    let nodes = [node("fence incumbent"), node("fence candidate")];
    let target = context("fence", IpVersion::V4);
    let mut inner = StateInner::default();
    for leaf in &nodes {
        response(&mut inner, leaf, &target, 4, 100, now);
    }
    assert!(pair(&inner, &nodes, &target, now).response.is_some());
    let key = exact(&nodes[1], &target);
    inner
        .exact
        .get_mut(&key)
        .unwrap()
        .invalidate_business(now + Duration::from_secs(10));
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1,
        now + Duration::from_secs(5),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(11))
            .response
            .is_none()
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        100,
        now + Duration::from_secs(12),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(13))
            .response
            .is_some()
    );
    let old = StartedCells {
        exact: Some(inner.exact.peek(&key).unwrap().incarnation),
        ..StartedCells::default()
    };
    inner.exact.get_mut(&key).unwrap().incarnation += 100;
    comparison::observe(
        &mut inner,
        &target,
        &[ScoreAttribution {
            group: "score".into(),
            node_id: nodes[1].id,
        }],
        (&[old], comparison::next_reporter_id()),
        ScoreSource::Traffic,
        &Observation::Response(Duration::from_millis(1)),
        now + Duration::from_secs(14),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(14))
            .response
            .is_none()
    );
    response(
        &mut inner,
        &nodes[1],
        &target,
        1,
        1,
        now + Duration::from_secs(14),
    );
    assert!(
        pair(&inner, &nodes, &target, now + Duration::from_secs(14))
            .response
            .is_none()
    );
}

#[test]
fn reload_clears_comparison_and_fences_delayed_support() {
    let nodes = [node("reload incumbent"), node("reload candidate")];
    let groups = vec![group("score", &nodes)];
    let manager = GroupManager::new(&groups, &nodes);
    let target = context("reload-comparison", IpVersion::V4);
    let now = Instant::now();
    for leaf in &nodes {
        train_at(
            &manager,
            leaf,
            &target,
            4,
            Duration::from_millis(10),
            1,
            now,
        );
    }
    let state = manager.score_state();
    assert!(
        pair(
            &state.inner.lock(),
            &nodes,
            &target,
            now + Duration::from_secs(1)
        )
        .response
        .is_some()
    );
    let replacement =
        GroupManager::with_alive_set_and_score_state(&groups, &nodes, None, state.clone());
    replacement.publish_score_membership();
    assert_eq!(state.inner.lock().comparisons.cell_count(), 0);
    assert!(
        pair(
            &state.inner.lock(),
            &nodes,
            &target,
            now + Duration::from_secs(2)
        )
        .response
        .is_none()
    );
}

#[test]
fn comparison_memory_cap_counts_keys_and_container_capacity_and_eviction_loses_support() {
    let now = Instant::now();
    let leaf = node("capacity");
    let mut inner = StateInner::default();
    let first = context(&format!("{:04}{}", 0, "x".repeat(1015)), IpVersion::V4);
    response(&mut inner, &leaf, &first, 4, 100, now);
    for index in 1..=MAX_CELLS {
        let target = context(&format!("{index:04}{}", "x".repeat(1015)), IpVersion::V4);
        response(
            &mut inner,
            &leaf,
            &target,
            1,
            100,
            now + Duration::from_millis(index as u64),
        );
    }
    let store = &inner.comparisons;
    assert_eq!(store.cell_count(), MAX_CELLS);
    assert_eq!(store.evicted, 1);
    assert!(store.logical_bytes() <= comparison::Store::logical_capacity_bound());
    assert!(comparison::Store::logical_capacity_bound() <= MAX_LOGICAL_BYTES);
    assert!(store.logical_bytes() >= MAX_CELLS * 1024);
    println!(
        "comparison logical bytes={} bound={} cells={}",
        store.logical_bytes(),
        comparison::Store::logical_capacity_bound(),
        store.cell_count()
    );
    response(
        &mut inner,
        &leaf,
        &first,
        1,
        100,
        now + Duration::from_secs(1),
    );
    assert!(
        scores(
            &inner,
            std::slice::from_ref(&leaf),
            &first,
            now + Duration::from_secs(1)
        )
        .evidence[0]
            .response
            .is_none()
    );
    let oversize = context(&"z".repeat(MAX_LOGICAL_BYTES), IpVersion::V4);
    let before = inner.comparisons.logical_bytes();
    response(
        &mut inner,
        &leaf,
        &oversize,
        1,
        100,
        now + Duration::from_secs(2),
    );
    assert_eq!(inner.comparisons.logical_bytes(), before);
    assert_eq!(inner.comparisons.rejected, 1);
    assert!(inner.exact.peek(&exact(&leaf, &oversize)).is_some());
}

#[test]
fn target_and_challenger_limits_choose_identity_order_not_favorable_values() {
    let now = Instant::now();
    let nodes: Vec<_> = (0..10)
        .map(|index| node(&format!("bounded {index}")))
        .collect();
    let mut inner = StateInner::default();
    for index in 0..9 {
        let target = context(&format!("{index}.target"), IpVersion::V4);
        for (position, leaf) in nodes.iter().enumerate() {
            response(
                &mut inner,
                leaf,
                &target,
                4,
                if position == 0 {
                    100
                } else if index < 8 {
                    200
                } else {
                    1
                },
                now,
            );
        }
    }
    let unseen = context("unseen", IpVersion::V4);
    let scores = scores(&inner, &nodes, &unseen, now);
    assert_eq!(scores.pairs.pairs.iter().flatten().count(), MAX_CHALLENGERS);
    for (_, pair) in scores.pairs.pairs.iter().flatten() {
        assert_close(pair.response.unwrap().candidate, 200.0);
    }
    let summary = comparison::summarize(&scores, now);
    assert_eq!(summary.compared_candidates, MAX_CHALLENGERS + 1);
    assert!(!summary.complete);
}

#[test]
fn disjoint_time_blocks_do_not_compare_even_when_both_nodes_are_fresh() {
    let now = Instant::now();
    let nodes = [node("early"), node("late")];
    let target = context("disjoint", IpVersion::V4);
    let mut inner = StateInner::default();
    response(&mut inner, &nodes[0], &target, 4, 100, now);
    response(
        &mut inner,
        &nodes[1],
        &target,
        4,
        1,
        now + Duration::from_secs(15),
    );
    let scores = scores(&inner, &nodes, &target, now + Duration::from_secs(16));
    assert!(
        scores
            .evidence
            .iter()
            .all(|evidence| evidence.response.is_some())
    );
    assert!(scores.pairs.get(1).unwrap().response.is_none());
    assert!(!comparison::summarize(&scores, now + Duration::from_secs(16)).complete);
}

#[test]
fn configured_probe_proof_requires_the_same_request_cohort_and_independent_freshness() {
    let nodes = [node("probe incumbent"), node("probe candidate")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    let publish_probe = |leaf: &Node, uri: &str, at: Instant| {
        for _ in 0..4 {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .with_source(ScoreSource::HealthProbe)
                .with_probe_identity(uri, "GET")
                .start_at(at);
            reporter.probe_latency_at(Duration::from_millis(100), at);
            reporter.finish_at(ScoreOutcome::Success, false, at);
        }
    };
    publish_probe(&nodes[0], "https://probe/a", now);
    publish_probe(&nodes[1], "https://probe/b", now);
    let state = manager.score_state();
    assert!(
        pair(&state.inner.lock(), &nodes, &target, now)
            .response
            .is_none()
    );
    publish_probe(&nodes[1], "https://probe/a", now + Duration::from_secs(1));
    let paired = pair(
        &state.inner.lock(),
        &nodes,
        &target,
        now + Duration::from_secs(1),
    );
    assert_eq!(paired.basis, Basis::ConfiguredProbe);
    assert!(paired.response.is_some());
    assert!(paired.upload.is_none() && paired.download.is_none());
    assert!(
        pair(
            &state.inner.lock(),
            &nodes,
            &target,
            now + Duration::from_secs(60)
        )
        .response
        .is_none()
    );
}

#[test]
fn replaced_probe_cohort_cannot_return_with_old_qualification() {
    let nodes = [node("cohort incumbent"), node("cohort candidate")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let now = Instant::now();
    let publish = |leaf: &Node, uri: &str, count: usize, at: Instant| {
        for _ in 0..count {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .with_source(ScoreSource::HealthProbe)
                .with_probe_identity(uri, "GET")
                .start_at(at);
            reporter.probe_latency_at(Duration::from_millis(100), at);
            reporter.finish_at(ScoreOutcome::Success, false, at);
        }
    };
    for leaf in &nodes {
        publish(leaf, "https://probe/a", 4, now);
    }
    let state = manager.score_state();
    assert!(
        pair(&state.inner.lock(), &nodes, &target, now)
            .response
            .is_some()
    );
    let later = now + Duration::from_secs(1);
    publish(&nodes[1], "https://probe/b", 1, later);
    assert!(
        pair(&state.inner.lock(), &nodes, &target, later)
            .response
            .is_none()
    );
    publish(&nodes[1], "https://probe/a", 1, later);
    assert!(
        pair(&state.inner.lock(), &nodes, &target, later)
            .response
            .is_none()
    );
    publish(&nodes[1], "https://probe/a", 3, later);
    assert!(
        pair(&state.inner.lock(), &nodes, &target, later)
            .response
            .is_some()
    );
}

#[test]
fn global_equivalence_checks_the_full_response_range() {
    let nodes = [node("center"), node("low"), node("high")];
    let target = context("range", IpVersion::V4);
    let now = Instant::now();
    let mut inner = StateInner::default();
    for (leaf, latency) in nodes.iter().zip([100, 91, 109]) {
        response(&mut inner, leaf, &target, 8, latency, now);
    }
    let scores = scores(&inner, &nodes, &target, now);
    let summary = comparison::summarize(&scores, now);
    assert!(summary.complete);
    assert!(!summary.equivalent);
}
