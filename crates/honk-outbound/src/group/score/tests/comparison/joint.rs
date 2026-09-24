use super::*;

#[test]
fn joint_response_uses_qualified_common_blocks_without_more_traffic() {
    for shared in [3, 4] {
        let nodes = [node("joint a"), node("joint b"), node("joint c")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("joint.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, latency) in nodes[..2].iter().zip([100, 200]) {
            train_at(&manager, leaf, &target, 4, latency, 1, now);
            train_at(
                &manager,
                leaf,
                &target,
                shared,
                latency,
                1,
                now + Duration::from_secs(16),
            );
        }
        train_at(
            &manager,
            &nodes[2],
            &target,
            4,
            300,
            1,
            now + Duration::from_secs(16),
        );
        let at = now + Duration::from_secs(18);
        let state = manager.score_state();
        let decision = scores(&state.inner.lock(), &nodes, &target, at);
        let progress = comparison::response_progress(
            &state.inner.lock(),
            "score",
            &target,
            nodes[0].id,
            nodes[2].id,
            at,
        )
        .unwrap();
        assert_eq!(progress.0, [shared as u8, 4]);
        let summary = comparison::summarize(&decision, at);
        let report = evaluate(
            &decision,
            &nodes.iter().collect::<Vec<_>>(),
            &target,
            None,
            at,
        )
        .snapshot;
        if shared == 4 {
            assert_ne!(
                decision.pairs.get(1).unwrap().response.unwrap().support,
                decision.pairs.get(2).unwrap().response.unwrap().support
            );
            assert!(summary.complete && summary.supported && !summary.response_misaligned);
            assert_eq!(summary.reporters, 4);
            // The original pair's older block still participates in the adverse-evidence veto.
            assert_eq!(summary.oldest_at, Some(at - Duration::from_millis(17_900)));
            let original = decision.pairs.get(1).unwrap().response.unwrap();
            let narrowed = decision.pairs.summary_pair(1).unwrap().response.unwrap();
            assert!(original.expires_at < narrowed.expires_at);
            assert_eq!(summary.expires_at, Some(original.expires_at));
            assert_eq!(
                report.local_comparison.valid_for_ms,
                Some(original.expires_at.duration_since(at).as_millis() as u64)
            );
            assert_eq!(report.comparison, ScoreComparison::Supported);
            assert!(!report.missing.response);
            let renewed = scores(&state.inner.lock(), &nodes, &target, original.expires_at);
            assert_eq!(
                renewed
                    .pairs
                    .summary_pair(1)
                    .unwrap()
                    .response
                    .unwrap()
                    .support,
                narrowed.support
            );
            let renewed = comparison::summarize(&renewed, original.expires_at);
            assert!(renewed.complete && renewed.supported && !renewed.response_misaligned);
            assert_ne!(renewed.support, summary.support);
            assert_eq!(renewed.expires_at, Some(narrowed.expires_at));
            let expired = scores(
                &state.inner.lock(),
                &nodes,
                &target,
                now + Duration::from_secs(76),
            );
            assert!(!comparison::summarize(&expired, now + Duration::from_secs(76)).complete);
        } else {
            assert!(!summary.complete);
            assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
            assert!(report.missing.response);
        }
    }
}

#[test]
fn disjoint_pair_blocks_do_not_make_a_joint_certificate() {
    let nodes = [node("split a"), node("split b"), node("split c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("split.example", IpVersion::V4);
    let now = Instant::now();
    let probe =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    for leaf in &nodes {
        probe_at(&manager, leaf, &probe, 50, now);
    }
    for (index, seconds) in [(0, 0), (1, 0), (0, 16), (2, 16)] {
        train_at(
            &manager,
            &nodes[index],
            &target,
            4,
            100 + index as u64 * 100,
            1,
            now + Duration::from_secs(seconds),
        );
    }
    let at = now + Duration::from_secs(18);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(
        comparison::response_progress(
            &state.inner.lock(),
            "score",
            &target,
            nodes[1].id,
            nodes[2].id,
            at
        )
        .unwrap()
        .0,
        [0, 0]
    );
    let summary = comparison::summarize(&decision, at);
    assert!(summary.response_misaligned);
    assert!(!summary.complete && !summary.supported && !summary.equivalent);
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &target,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    assert!(report.missing.response);
}

#[test]
fn joint_narrowing_keeps_adverse_original_pair_evidence() {
    let nodes = [node("veto a"), node("veto b"), node("veto c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("veto.example", IpVersion::V4);
    let now = Instant::now();
    for (index, (leaf, latency)) in nodes[..2].iter().zip([1000, 1]).enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            4,
            latency,
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    for (leaf, latency) in nodes.iter().zip([100, 200, 300]) {
        train_at(
            &manager,
            leaf,
            &target,
            4,
            latency,
            1,
            now + Duration::from_secs(16),
        );
    }
    let at = now + Duration::from_secs(18);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    let narrowed = decision.pairs.summary_pair(1).unwrap().response.unwrap();
    assert_close(narrowed.incumbent, 100.0);
    assert_close(narrowed.candidate, 200.0);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete && !summary.response_misaligned);
    assert!(!summary.supported && !summary.equivalent);
}

#[test]
fn joint_common_targets_keep_partial_coverage_and_response_bound_directions() {
    let nodes = [node("targets a"), node("targets b"), node("targets c")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let now = Instant::now();
    let common = context("a.common", IpVersion::V4);
    let extra = context("b.extra", IpVersion::V4);
    for (leaf, latency) in nodes.iter().zip([100, 200, 300]) {
        train_transfers(
            &manager,
            leaf,
            &common,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES, 1),
            now + Duration::from_secs(16),
        );
    }
    for (leaf, latency) in nodes[..2].iter().zip([100, 200]) {
        train_transfers(
            &manager,
            leaf,
            &extra,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES * 8, 1),
            now + Duration::from_secs(16),
        );
    }
    let at = now + Duration::from_secs(19);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &aggregate, at);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.supported && summary.upload_known && !summary.response_misaligned);
    assert!(summary.target_limited && !summary.complete);
    for index in [1, 2] {
        let pair = decision.pairs.summary_pair(index).unwrap();
        assert_close(
            pair.upload.unwrap().incumbent,
            MIN_THROUGHPUT_BYTES as f64 / 2.0,
        );
        assert_close(
            pair.upload.unwrap().candidate,
            MIN_THROUGHPUT_BYTES as f64 / 2.0,
        );
    }
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &aggregate,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    assert_eq!(
        report.local_comparison.comparison,
        ScoreComparison::Supported
    );
}

#[test]
fn joint_narrowing_cannot_discard_a_broader_directional_defeat() {
    let nodes = [
        node("direction veto a"),
        node("direction veto b"),
        node("direction veto c"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("direction-veto.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, upload) in nodes[..2]
        .iter()
        .zip([MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_BYTES * 4])
    {
        train_transfers(
            &manager,
            leaf,
            &target,
            (4, 4),
            Duration::from_millis(100),
            (upload, 1),
            now,
        );
    }
    for (leaf, latency) in nodes.iter().zip([100, 100, 200]) {
        train_transfers(
            &manager,
            leaf,
            &target,
            (4, 4),
            Duration::from_millis(latency),
            (MIN_THROUGHPUT_BYTES, 1),
            now + Duration::from_secs(16),
        );
    }
    let at = now + Duration::from_secs(19);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    let narrowed = decision.pairs.summary_pair(1).unwrap().upload.unwrap();
    assert_close(narrowed.incumbent, narrowed.candidate);
    let original = decision.pairs.get(1).unwrap().upload.unwrap();
    assert!(original.candidate > original.incumbent * 1.1);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete && summary.upload_known && !summary.response_misaligned);
    assert!(!summary.supported && !summary.equivalent);
}

#[test]
fn optional_original_pair_vetoes_joint_support_until_its_own_expiry() {
    let nodes: Vec<_> = (0..4)
        .map(|index| node(&format!("optional veto {index}")))
        .collect();
    let refs = nodes.iter().collect::<Vec<_>>();
    let target = context("optional-veto.example", IpVersion::V4);
    let mut inner = StateInner::default();
    let start = Instant::now();
    // Optional evidence precedes both covered pairs and their shared block.
    for (seconds, members) in [
        (0, &[0, 3][..]),
        (16, &[0, 1][..]),
        (32, &[0, 1, 2][..]),
        (48, &[0, 2][..]),
    ] {
        for &index in members {
            response(
                &mut inner,
                &nodes[index],
                &target,
                4,
                if index == 3 { 50 } else { 100 },
                start + Duration::from_secs(seconds),
            );
        }
    }
    let decision_at = |at| {
        let mut decision = scores(&inner, &nodes, &target, at);
        for score in &mut decision.scores {
            assert!(score.qualified());
            score.observed_reliability = 1.0;
        }
        decision.membership.covered[3] = false;
        decision.pairs = pairs_at(
            &inner,
            &target,
            &refs,
            (&decision.scores, decision.baseline),
            (&decision.membership, 0),
            at,
        );
        decision
    };
    let at = start + Duration::from_secs(49);
    let decision = decision_at(at);
    let expiry = decision.pairs.get(3).unwrap().response.unwrap().expires_at;
    let covered_expiry = decision.pairs.get(1).unwrap().response.unwrap().expires_at;
    assert!(expiry < covered_expiry);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete && !summary.response_misaligned);
    assert!(!summary.equivalent && !summary.supported);
    assert_eq!(summary.expires_at, Some(expiry));

    let renewed = comparison::summarize(&decision_at(expiry), expiry);
    assert!(renewed.complete && renewed.equivalent && !renewed.response_misaligned);
    assert_ne!(renewed.support, summary.support);
    assert_eq!(renewed.expires_at, Some(covered_expiry));
}

#[test]
fn optional_pair_cannot_choose_the_covered_claim_basis() {
    for optional_exact in [true, false] {
        let nodes: Vec<_> = (0..4)
            .map(|index| node(&format!("basis {index}")))
            .collect();
        let refs: Vec<_> = nodes.iter().collect();
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("required.example", IpVersion::V4);
        let other = context("other.example", IpVersion::V4);
        let start = Instant::now();
        let train = |indices: &[usize], scope: &ScoreSelectionContext, seconds| {
            for &index in indices {
                train_at(
                    &manager,
                    &nodes[index],
                    scope,
                    4,
                    100,
                    1,
                    start + Duration::from_secs(seconds),
                );
            }
        };
        let at = if optional_exact {
            train(&[0, 1, 2, 3], &other, 0);
            train(&[2, 3], &target, 16);
            train(&[0, 1], &target, 32);
            start + Duration::from_secs(34)
        } else {
            train(&[0, 2], &target, 0);
            train(&[0, 2, 3], &target, 16);
            train(&[0, 3], &target, 32);
            train(&[0, 1], &other, 34);
            start + Duration::from_secs(36)
        };
        let state = manager.score_state();
        let inner = state.inner.lock();
        let mut decision = scores(&inner, &nodes, &target, at);
        decision.membership.covered[1] = false;
        decision.pairs = pairs_at(
            &inner,
            &target,
            &refs,
            (&decision.scores, decision.baseline),
            (&decision.membership, 0),
            at,
        );
        let summary = comparison::summarize(&decision, at);
        assert!(summary.complete && summary.equivalent);
        let report = evaluate(&decision, &refs, &target, None, at).snapshot;
        assert_eq!(
            report.comparison,
            if optional_exact {
                ScoreComparison::Unconfirmed
            } else {
                ScoreComparison::Equivalent
            },
            "an optional pair must neither lend nor erase exact-target support",
        );
    }
}
