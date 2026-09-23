use super::*;

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
    assert!(summary.candidate_limited && summary.target_limited);
}

#[test]
fn global_equivalence_checks_the_full_response_range() {
    let nodes = [node("center"), node("low"), node("high")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("range", IpVersion::V4);
    let now = Instant::now();
    for (index, latency) in [(1, 91), (0, 100), (2, 109)] {
        train_at(
            &manager,
            &nodes[index],
            &target,
            8,
            Duration::from_millis(latency),
            1,
            now,
        );
    }
    let at = now + Duration::from_secs(2);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(decision.ordinary.index, 0);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete);
    assert!(!summary.equivalent && !summary.supported && !summary.response_misaligned);
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &target,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    assert!(!report.missing.response);
}

#[test]
fn common_target_cap_follows_qualification_and_directional_metrics_keep_that_cohort() {
    let nodes = [node("qualified a"), node("qualified b")];
    let now = Instant::now();
    let mut inner = StateInner::default();
    let unseen = context("unseen", IpVersion::V4);
    for index in (0..17).rev() {
        let target = context(&format!("{index:02}.target"), IpVersion::V4);
        for (side, leaf) in nodes.iter().enumerate() {
            response(
                &mut inner,
                leaf,
                &target,
                if index < 8 { 1 } else { 4 },
                if index == 16 && side == 1 { 1 } else { 100 },
                now,
            );
            if index != 8 {
                for _ in 0..4 {
                    publish(
                        &mut inner,
                        leaf,
                        &target,
                        comparison::next_reporter_id(),
                        now,
                        Observation::Transfer {
                            tx: 1_048_576,
                            rx: 1_048_576,
                            elapsed: Duration::from_secs(1),
                        },
                    );
                }
            }
        }
    }
    for reference in [0, 1] {
        let decision = decision_at(&inner, &nodes, &unseen, reference, now);
        let pair = decision.pairs.get(1 - reference).unwrap();
        assert_close(pair.response.unwrap().incumbent, 100.0);
        assert_close(pair.response.unwrap().candidate, 100.0);
        assert!(pair.upload.is_none() && pair.download.is_none());
        let summary = comparison::summarize(&decision, now);
        assert!(summary.equivalent && !summary.complete);
    }
    let exact = pair(&inner, &nodes, &context("16.target", IpVersion::V4), now);
    assert_eq!(exact.basis, Basis::ExactTarget);
    assert_close(exact.response.unwrap().candidate, 1.0);
    assert!(!exact.partial);
}

#[test]
fn response_support_is_independent_of_completion_maturity() {
    for samples in [4, 8, 16] {
        let nodes = [node("faster"), node("slower")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("maturity.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, latency) in nodes.iter().zip([100, 115]) {
            train_at(
                &manager,
                leaf,
                &target,
                samples,
                Duration::from_millis(latency),
                1,
                now,
            );
        }
        let at = now + Duration::from_secs(2);
        let state = manager.score_state();
        for reference in [0, 1] {
            let decision = decision_at(&state.inner.lock(), &nodes, &target, reference, at);
            assert!(decision.scores.iter().all(ScoreSnapshot::qualified));
            assert_close(
                decision.scores[0].observed_reliability,
                decision.scores[1].observed_reliability,
            );
            let summary = comparison::summarize(&decision, at);
            assert!(summary.complete && !summary.equivalent);
            assert_eq!(
                summary.supported,
                reference == 0,
                "samples={samples} reference={reference}"
            );
        }
        let report = state
            .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at)
            .unwrap();
        assert_eq!(
            report.comparison,
            ScoreComparison::Supported,
            "samples={samples}"
        );
        assert!(!report.missing.availability && !report.missing.response);
    }
}

#[test]
fn response_equivalence_uses_actual_symmetric_tolerance_including_zero() {
    for (left, right, expected) in [
        (100_000_000, 109_999_000, ScoreComparison::Equivalent),
        (100_000_000, 110_000_000, ScoreComparison::Equivalent),
        (100_000_000, 110_001_000, ScoreComparison::Supported),
        (100_000, 109_999, ScoreComparison::Equivalent),
        (100_000, 110_000, ScoreComparison::Equivalent),
        (100_000, 110_001, ScoreComparison::Supported),
        (0, 0, ScoreComparison::Equivalent),
        (0, 1, ScoreComparison::Supported),
    ] {
        let nodes = [node("lower"), node("higher")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("boundary.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, nanos) in nodes.iter().zip([left, right]) {
            train_at(
                &manager,
                leaf,
                &target,
                8,
                Duration::from_nanos(nanos),
                1,
                now,
            );
        }
        let at = now + Duration::from_secs(2);
        let state = manager.score_state();
        for reference in [0, 1] {
            let decision = decision_at(&state.inner.lock(), &nodes, &target, reference, at);
            let summary = comparison::summarize(&decision, at);
            assert!(summary.complete && !summary.response_misaligned);
            assert_eq!(
                summary.equivalent,
                expected == ScoreComparison::Equivalent,
                "{left}/{right}"
            );
            assert_eq!(
                summary.supported,
                reference == 0 && expected == ScoreComparison::Supported,
                "{left}/{right} reference={reference}"
            );
            assert_eq!(decision.ordinary.index, reference);
            let report = evaluate(
                &decision,
                &nodes.iter().collect::<Vec<_>>(),
                &target,
                None,
                at,
            )
            .snapshot;
            let expected_selected = if expected == ScoreComparison::Equivalent || reference == 0 {
                expected
            } else {
                ScoreComparison::Unconfirmed
            };
            assert_eq!(
                report.comparison, expected_selected,
                "{left}/{right} reference={reference}"
            );
        }
    }
}

#[test]
fn a_held_incumbent_cannot_hide_a_materially_faster_rival() {
    let nodes = [node("held"), node("faster"), node("slower")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("held.example", IpVersion::V4);
    let now = Instant::now();
    for (index, latency) in [(1, 100), (0, 115), (2, 200)] {
        train_at(
            &manager,
            &nodes[index],
            &target,
            8,
            Duration::from_millis(latency),
            1,
            now,
        );
    }
    let at = now + Duration::from_secs(2);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(decision.ordinary.index, 0);
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete && !summary.response_misaligned);
    assert!(!summary.supported && !summary.equivalent);
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &target,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
    assert!(!report.missing.response);
}

#[test]
fn qualified_reliability_cannot_buy_a_material_response_regression() {
    for slower in [105, 115] {
        let nodes = [node("faster less reliable"), node("slower reliable")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("reliability.example", IpVersion::V4);
        let now = Instant::now();
        let failed = manager
            .feedback_for_group_node("score", nodes[0].id, target.clone())
            .unwrap()
            .start_at(now);
        failed.setup_succeeded_at(now);
        failed.finish_at(ScoreOutcome::Timeout, true, now);
        for (leaf, latency) in nodes.iter().zip([100, slower]) {
            train_at(
                &manager,
                leaf,
                &target,
                32,
                Duration::from_millis(latency),
                1,
                now + Duration::from_secs(1),
            );
        }
        let at = now + Duration::from_secs(3);
        let state = manager.score_state();
        for reference in [0, 1] {
            let decision = decision_at(&state.inner.lock(), &nodes, &target, reference, at);
            assert!(decision.scores.iter().all(ScoreSnapshot::qualified));
            assert!(
                decision.scores[0].observed_reliability < decision.scores[1].observed_reliability
            );
            let summary = comparison::summarize(&decision, at);
            assert!(summary.complete && !summary.response_misaligned);
            assert_eq!(summary.supported, reference == 1 && slower == 105);
            if slower == 115 {
                assert!(!summary.equivalent);
            }
        }
        if slower == 115 {
            let report = state
                .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at)
                .unwrap();
            assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
            assert!(!report.missing.response);
        }
    }
}

#[test]
fn unqualified_upload_noise_cannot_revoke_response_support() {
    let mut baseline = None;
    for noise in [false, true] {
        let nodes = [node("selected"), node("second"), node("third")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("unqualified.example", IpVersion::V4);
        let now = Instant::now();
        for (index, (leaf, latency)) in nodes.iter().zip([100, 200, 300]).enumerate() {
            train_transfers(
                &manager,
                leaf,
                &target,
                (4, usize::from(noise && index < 2)),
                Duration::from_millis(latency),
                (MIN_THROUGHPUT_BYTES, 1),
                now,
            );
        }
        let at = now + Duration::from_secs(3);
        let state = manager.score_state();
        let decision = scores(&state.inner.lock(), &nodes, &target, at);
        for index in [1, 2] {
            let pair = decision.pairs.get(index).unwrap();
            assert!(pair.response.is_some() && pair.upload.is_none() && pair.download.is_none());
        }
        let summary = comparison::summarize(&decision, at);
        assert!(summary.complete && summary.supported && !summary.response_misaligned);
        let identity = (summary.support, summary.valid_for);
        if let Some(baseline) = baseline {
            assert_eq!(identity, baseline);
        } else {
            baseline = Some(identity);
        }
        let report = state
            .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), at)
            .unwrap();
        assert_eq!(report.comparison, ScoreComparison::Supported);
        assert!(!report.missing.response && !report.local_comparison.upload_known);
    }
}

#[test]
fn common_target_aggregation_discards_lost_direction_identity() {
    let mut baseline = None;
    for noise in [false, true] {
        let nodes = [node("selected"), node("second"), node("third")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let now = Instant::now();
        let targets = [
            context("a.example", IpVersion::V4),
            context("b.example", IpVersion::V4),
        ];
        for (target_index, target) in targets.iter().enumerate() {
            for (index, (leaf, latency)) in nodes.iter().zip([100, 200, 300]).enumerate() {
                let uploads = if noise && target_index == 0 && index < 2 {
                    4
                } else {
                    0
                };
                train_transfers(
                    &manager,
                    leaf,
                    target,
                    (4, uploads),
                    Duration::from_millis(latency),
                    (MIN_THROUGHPUT_BYTES, 1),
                    now,
                );
            }
        }
        let at = now + Duration::from_secs(3);
        let aggregate = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let state = manager.score_state();
        let inner = state.inner.lock();
        assert_eq!(
            pair(&inner, &nodes, &targets[0], at).upload.is_some(),
            noise
        );
        let decision = scores(&inner, &nodes, &aggregate, at);
        for index in [1, 2] {
            let pair = decision.pairs.get(index).unwrap();
            assert!(pair.upload.is_none() && pair.download.is_none());
        }
        let summary = comparison::summarize(&decision, at);
        assert!(summary.complete && summary.supported && !summary.response_misaligned);
        let identity = (summary.support, summary.valid_for);
        if let Some(baseline) = baseline {
            assert_eq!(identity, baseline);
        } else {
            baseline = Some(identity);
        }
        let report = evaluate(
            &decision,
            &nodes.iter().collect::<Vec<_>>(),
            &aggregate,
            None,
            at,
        )
        .snapshot;
        assert_eq!(report.comparison, ScoreComparison::Supported);
        assert_eq!(report.basis, ScoreEvidenceBasis::CommonTargets);
        assert!(!report.missing.response && !report.local_comparison.upload_known);
    }
}

#[test]
fn incoherent_upload_cannot_supply_a_win_or_hide_a_measured_tradeoff() {
    for crossed in [false, true] {
        let nodes = [node("selected"), node("second"), node("third")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("direction-cohorts.example", IpVersion::V4);
        let now = Instant::now();
        let reporters: Vec<Vec<_>> = nodes
            .iter()
            .map(|leaf| {
                let feedback = manager
                    .feedback_for_group_node("score", leaf.id, target.clone())
                    .unwrap();
                (0..4).map(|_| feedback.start_at(now)).collect()
            })
            .collect();
        for (index, reporters) in reporters.iter().enumerate() {
            for reporter in reporters {
                reporter.setup_succeeded_at(now);
                reporter.first_response_at(now + Duration::from_millis(100));
                let upload = match index {
                    0 => 1_048_576,
                    1 => 524_288,
                    _ => 1,
                };
                let download = if crossed && index == 0 {
                    1_048_576
                } else {
                    524_288
                };
                reporter.transfer_at(upload, download, now + Duration::from_secs(1));
            }
        }
        for index in [0, 2] {
            for reporter in &reporters[index] {
                reporter.transfer_at(1, 1, now + Duration::from_secs(16));
                let upload = if index == 2 && crossed {
                    2_097_152
                } else if index == 0 {
                    1_048_576
                } else {
                    524_288
                };
                reporter.transfer_at(upload, 1, now + Duration::from_secs(17));
            }
        }
        for reporters in reporters {
            for reporter in reporters {
                reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(17));
            }
        }
        let at = now + Duration::from_secs(18);
        let state = manager.score_state();
        let decision = scores(&state.inner.lock(), &nodes, &target, at);
        let second = decision.pairs.get(1).unwrap();
        let third = decision.pairs.get(2).unwrap();
        assert_eq!(
            second.response.unwrap().support,
            third.response.unwrap().support
        );
        assert_ne!(
            second.upload.unwrap().support,
            third.upload.unwrap().support
        );
        let summary = comparison::summarize(&decision, at);
        assert!(summary.complete && !summary.response_misaligned);
        assert!(!summary.upload_known && summary.download_known);
        assert_eq!(summary.directional_tradeoff, crossed);
        assert!(!summary.supported && !summary.equivalent);
        assert_eq!(decision.ordinary.index, 0);
        let report = evaluate(
            &decision,
            &nodes.iter().collect::<Vec<_>>(),
            &target,
            None,
            at,
        )
        .snapshot;
        assert_eq!(report.comparison, ScoreComparison::Unconfirmed);
        assert!(!report.missing.response && !report.missing.transfer);
        assert_eq!(report.next_action, ScoreValidationAction::None);
    }
}

#[test]
fn response_win_against_another_peer_cannot_hide_a_qualified_rate_defeat() {
    let nodes = [
        node("held rate"),
        node("better rate"),
        node("slower response"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("held-rate.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, (response, upload)) in nodes.iter().zip([(100, 524_288), (100, 589_824), (200, 1)]) {
        train_transfers(
            &manager,
            leaf,
            &target,
            (8, 8),
            Duration::from_millis(response),
            (upload, 1),
            now,
        );
    }
    let at = now + Duration::from_secs(3);
    let state = manager.score_state();
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(decision.ordinary.index, 0);
    assert!(decision.pairs.get(1).unwrap().upload.is_some());
    assert!(decision.pairs.get(2).unwrap().upload.is_none());
    let summary = comparison::summarize(&decision, at);
    assert!(summary.complete && !summary.response_misaligned);
    assert!(!summary.upload_known);
    assert!(!summary.supported && !summary.equivalent, "{summary:?}");
}

#[test]
fn later_challenger_direction_controls_claim_identity_and_expiry() {
    let nodes = [node("selected"), node("second"), node("third")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("claim-support.example", IpVersion::V4);
    let now = Instant::now();
    let reporters: Vec<Vec<_>> = nodes
        .iter()
        .map(|leaf| {
            let feedback = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap();
            (0..4).map(|_| feedback.start_at(now)).collect()
        })
        .collect();
    for reporters in &reporters {
        for reporter in reporters {
            reporter.setup_succeeded_at(now);
            reporter.first_response_at(now + Duration::from_millis(100));
            reporter.transfer_at(1, 1, now + Duration::from_secs(1));
        }
    }
    for index in [0, 2] {
        for reporter in &reporters[index] {
            reporter.transfer_at(1, 1, now + Duration::from_secs(16));
            reporter.transfer_at(524_288, 1, now + Duration::from_secs(17));
        }
    }
    for (leaf, latency) in nodes.iter().zip([100, 200, 300]) {
        train_at(
            &manager,
            leaf,
            &target,
            8,
            Duration::from_millis(latency),
            1,
            now + Duration::from_secs(32),
        );
    }
    let at = now + Duration::from_secs(63);
    let state = manager.score_state();
    let before = scores(&state.inner.lock(), &nodes, &target, at);
    let response_support = before.pairs.get(2).unwrap().response.unwrap().support;
    let expiry = before.pairs.get(2).unwrap().upload.unwrap().expires_at;
    assert!(before.pairs.get(1).unwrap().upload.is_none());
    let before = comparison::summarize(&before, at);
    assert!(before.complete && before.supported && !before.response_misaligned);
    assert_eq!(before.valid_for, Some(expiry.duration_since(at)));
    for index in [0, 2] {
        for reporter in &reporters[index] {
            reporter.transfer_at(1, 1, now + Duration::from_secs(61));
            reporter.transfer_at(524_288, 1, now + Duration::from_secs(62));
        }
    }
    for reporters in reporters {
        for reporter in reporters {
            reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(62));
        }
    }
    let decision = scores(&state.inner.lock(), &nodes, &target, at);
    assert_eq!(
        decision.pairs.get(2).unwrap().response.unwrap().support,
        response_support
    );
    let after = comparison::summarize(&decision, at);
    assert!(after.complete && after.supported && !after.response_misaligned);
    assert_ne!(after.support, before.support);
    assert_eq!(after.valid_for, before.valid_for);
    let report = evaluate(
        &decision,
        &nodes.iter().collect::<Vec<_>>(),
        &target,
        None,
        at,
    )
    .snapshot;
    assert_eq!(report.comparison, ScoreComparison::Supported);
    assert_eq!(
        report.local_comparison.valid_for_ms,
        Some(expiry.duration_since(at).as_millis() as u64)
    );
    assert!(report.valid_for_ms.unwrap() <= report.local_comparison.valid_for_ms.unwrap());

    let decision = scores(&state.inner.lock(), &nodes, &target, expiry);
    let response = decision.pairs.get(2).unwrap().response.unwrap();
    assert_eq!(response.support, response_support);
    let expired = comparison::summarize(&decision, expiry);
    assert!(expired.complete && expired.supported && !expired.response_misaligned);
    assert_ne!(expired.support, after.support);
    assert_eq!(
        expired.valid_for,
        Some(response.expires_at.duration_since(expiry))
    );
}
