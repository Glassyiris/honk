use super::*;

#[test]
fn open_flow_progress_changes_selection_without_terminal_completions() {
    let nodes = [node("incumbent"), node("live-faster")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("stream.example", IpVersion::V4);
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
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    let start = now + Duration::from_secs(2);
    let live = manager
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(start);
    live.setup_succeeded_at(start);
    live.first_response_at(start + Duration::from_millis(100));
    for second in 1..=4 {
        live.transfer_at(1, 8_000_000, start + Duration::from_secs(second));
    }
    let state = manager.score_state();
    let at = start + Duration::from_secs(4);
    let before = score_snapshot(&state.inner.lock(), "score", &target, nodes[1].id, at);
    assert!(
        before.completed < 20.001,
        "live windows must not settle Beta completions"
    );
    assert_eq!(rank_at(&manager, &nodes, &target, at), 1);
    live.finish_at(ScoreOutcome::Cancelled, false, at);
    let after = score_snapshot(&state.inner.lock(), "score", &target, nodes[1].id, at);
    assert_close(after.completed, before.completed);
    assert_eq!(
        after.target_performance.download.value,
        before.target_performance.download.value
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, at),
        1,
        "factual committed observations survive cancellation"
    );
    live.transfer_at(1, u64::MAX, at + Duration::from_secs(1));
    live.first_response_at(at + Duration::from_secs(1));
    live.finish_at(ScoreOutcome::Timeout, true, at + Duration::from_secs(1));
    let late = score_snapshot(&state.inner.lock(), "score", &target, nodes[1].id, at);
    assert_eq!(
        late.target_performance.download.value,
        after.target_performance.download.value
    );
    assert_close(late.completed, after.completed);
}

#[test]
fn response_is_published_once_at_event_time_not_terminal_time() {
    let leaf = node("leaf");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("stream.example", IpVersion::V4);
    let now = Instant::now();
    let live = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    live.setup_succeeded_at(now + Duration::from_millis(10));
    live.first_response_at(now + Duration::from_millis(50));
    live.first_response_at(now + Duration::from_secs(1));
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.target_performance.response.value, Some(50.0));
    assert_eq!(score.completed, 0.0);
    let expired = now + PERFORMANCE_MAX_AGE + Duration::from_secs(1);
    live.finish_at(ScoreOutcome::Success, true, expired);
    let score = score_snapshot(&state.inner.lock(), "score", &target, leaf.id, expired);
    assert!(score.target_performance.response.value.is_none());
    assert_eq!(score.completed, 1.0);
}

#[test]
fn live_windows_are_directional_nonoverlapping_and_ignore_idle_bursts() {
    let leaf = node("leaf");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("stream.example", IpVersion::V4);
    let now = Instant::now();
    let live = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    live.setup_succeeded_at(now);
    live.first_response_at(now);
    live.transfer_at(1, 65_536, now + Duration::from_millis(999));
    let state = manager.score_state();
    assert!(
        score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now)
            .target_performance
            .download
            .value
            .is_none()
    );
    live.transfer_at(1, 0, now + Duration::from_secs(1));
    let first = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(first.target_performance.download.value, Some(65_536.0));
    assert!(first.target_performance.upload.value.is_none());
    live.transfer_at(131_072, 1, now + Duration::from_secs(2));
    let second = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(2),
    );
    assert_eq!(
        second.target_performance.download.value,
        first.target_performance.download.value
    );
    assert_eq!(second.target_performance.upload.value, Some(131_072.0));
    live.transfer_at(1, 10_000_000, now + Duration::from_secs(30));
    let idle = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(30),
    );
    assert_eq!(
        idle.target_performance.download.value,
        first.target_performance.download.value
    );
    live.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(30));
    let terminal = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(30),
    );
    assert_eq!(
        terminal.target_performance.upload.value,
        second.target_performance.upload.value
    );
    assert_eq!(
        terminal.target_performance.download.value,
        first.target_performance.download.value
    );
    assert_eq!(terminal.completed, 1.0);
}

#[test]
fn nontraffic_bytes_and_responses_never_become_business_quality() {
    let leaf = node("leaf");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("configured.example", IpVersion::V4);
    let now = Instant::now();
    for source in [ScoreSource::HealthProbe, ScoreSource::Warmup] {
        let reporter = manager
            .feedback_for_group_node("score", leaf.id, target.clone())
            .unwrap()
            .with_source(source)
            .start_at(now);
        reporter.setup_succeeded_at(now);
        reporter.first_response_at(now + Duration::from_millis(1));
        reporter.transfer_at(1, 10_000_000, now + Duration::from_secs(1));
        reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(2),
    );
    assert_eq!(score.completed, 0.0);
    assert!(score.target_performance.response.value.is_none());
    assert!(score.target_performance.download.value.is_none());
    assert!(
        score.probe.value.is_none(),
        "setup/response is not an explicitly measured probe RTT"
    );
}

#[test]
fn cloned_reporters_serialize_live_observations_against_terminal_settlement() {
    let leaf = node("leaf");
    let manager = GroupManager::new(
        &[group("score", std::slice::from_ref(&leaf))],
        std::slice::from_ref(&leaf),
    );
    let target = context("race.example", IpVersion::V4);
    let now = Instant::now();
    let reporter = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    reporter.setup_succeeded_at(now);
    reporter.transfer_at(1, 1, now);
    let clone = reporter.clone();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            clone.first_response_at(now + Duration::from_millis(50));
            clone.transfer_at(1, 100_000, now + Duration::from_secs(1));
            clone.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
        });
        barrier.wait();
        reporter.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
    });
    drop(clone);
    let state = manager.score_state();
    let settled = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(settled.completed, 1.0);
    assert_eq!(settled.useful_completed, 1.0);
    reporter.first_response_at(now + Duration::from_secs(5));
    reporter.transfer_at(u64::MAX, u64::MAX, now + Duration::from_secs(5));
    drop(reporter);
    let after = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(
        after.target_performance.response.value,
        settled.target_performance.response.value
    );
    assert_eq!(
        after.target_performance.download.value,
        settled.target_performance.download.value
    );
    assert_eq!(after.completed, 1.0);
}

#[test]
fn evicted_live_reporter_cannot_update_recreated_exact_or_aggregate_cells() {
    let leaf = node("leaf");
    let groups = [
        group("score", std::slice::from_ref(&leaf)),
        group("other", std::slice::from_ref(&leaf)),
    ];
    let manager = GroupManager::new(&groups, std::slice::from_ref(&leaf));
    let target = context("stream.example", IpVersion::V4);
    let state = manager.score_state();
    {
        let mut inner = state.inner.lock();
        inner.exact.resize(NonZeroUsize::new(1).unwrap());
        inner.aggregate.resize(NonZeroUsize::new(2).unwrap());
    }
    let now = Instant::now();
    let old = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    let other = manager
        .feedback_for_group_node("other", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    let current = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    old.setup_succeeded_at(now);
    old.first_response_at(now);
    old.transfer_at(1, 10_000_000, now + Duration::from_secs(1));
    old.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.completed, 0.0);
    assert!(score.performance.response.value.is_none());
    assert!(score.target_performance.download.value.is_none());
    current.setup_succeeded_at(now);
    current.first_response_at(now);
    current.transfer_at(1, 100_000, now + Duration::from_secs(1));
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.target_performance.download.value, Some(100_000.0));
    drop(other);
}

#[test]
fn live_old_generation_reports_survivors_but_cannot_start_again() {
    let nodes = [node("survivor"), node("removed")];
    let old = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("stream.example", IpVersion::V4);
    let now = Instant::now();
    let captured = old
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap();
    let survivor = captured.start_at(now);
    let removed = old
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .start_at(now);
    let state = old.score_state();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", &nodes[..1])],
        &nodes[..1],
        None,
        Arc::clone(&state),
    );
    replacement.publish_score_membership();
    for reporter in [&survivor, &removed] {
        reporter.setup_succeeded_at(now);
        reporter.first_response_at(now + Duration::from_millis(50));
        reporter.transfer_at(1, 100_000, now + Duration::from_secs(1));
    }
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.target_performance.response.value, Some(50.0));
    assert_eq!(score.target_performance.download.value, Some(100_000.0));
    assert!(!state.has_exact("score", &target, nodes[1].id));
    let stale = captured.start_at(now);
    stale.setup_succeeded_at(now);
    stale.first_response_at(now);
    stale.transfer_at(1, u64::MAX, now + Duration::from_secs(1));
    stale.finish_at(ScoreOutcome::Timeout, true, now + Duration::from_secs(1));
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[0].id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.target_performance.response.value, Some(50.0));
    assert_eq!(score.completed, 0.0);
}

#[test]
fn setup_quality_survives_neutral_completion_without_a_response() {
    for outcome in [
        ScoreOutcome::Cancelled,
        ScoreOutcome::Rejected,
        ScoreOutcome::Shutdown,
    ] {
        let nodes = [node("slow-setup"), node("fast-setup")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("setup.example", IpVersion::V4);
        let now = Instant::now();
        for (leaf, latency) in nodes.iter().zip([600, 60]) {
            for _ in 0..4 {
                let reporter = manager
                    .feedback_for_group_node("score", leaf.id, target.clone())
                    .unwrap()
                    .start_at(now);
                reporter.setup_succeeded_at(now + Duration::from_millis(latency));
                reporter.finish_at(outcome, true, now + Duration::from_secs(1));
            }
        }
        let state = manager.score_state();
        let score = score_snapshot(
            &state.inner.lock(),
            "score",
            &target,
            nodes[1].id,
            now + Duration::from_secs(1),
        );
        assert_eq!(score.target_performance.setup.value, Some(60.0));
        assert_eq!(
            (score.attempts, score.completed, score.unresolved_failure),
            (0.0, 0.0, false)
        );
        assert_eq!(
            state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>()),
            1,
            "neutral completion must retain measured setup quality: {outcome:?}"
        );
    }
}

#[test]
fn concurrent_failed_probe_cannot_retire_successful_probe_evidence() {
    let nodes = [node("slow"), node("fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("configured.example", IpVersion::V4);
    let now = Instant::now();
    probe_at(
        &manager,
        &nodes[0],
        &target,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        now,
    );
    let feedback = manager
        .feedback_for_group_node("score", nodes[1].id, target.clone())
        .unwrap()
        .with_source(ScoreSource::HealthProbe);
    let successful = feedback.start_at(now);
    let failed = feedback.start_at(now);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            successful.probe_latency_at(Duration::from_millis(5), now);
            successful.finish_at(ScoreOutcome::Success, false, now);
        });
        failed.finish_at(ScoreOutcome::Timeout, false, now);
        barrier.wait();
    });
    let state = manager.score_state();
    let score = score_snapshot(&state.inner.lock(), "score", &target, nodes[1].id, now);
    assert_eq!(score.probe.value, Some(5.0));
    assert_eq!(
        (score.attempts, score.completed, score.unresolved_failure),
        (0.0, 0.0, false)
    );
    assert_eq!(
        state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>()),
        1
    );
}

#[test]
fn generation_publication_rejects_pending_health_but_keeps_admitted_traffic() {
    let leaf = node("survivor");
    let nodes = std::slice::from_ref(&leaf);
    let old = GroupManager::new(&[group("score", nodes)], nodes);
    let target = context("configured.example", IpVersion::V4);
    let now = Instant::now();
    let feedback = old
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap();
    let traffic = feedback.start_at(now);
    let health = feedback.with_source(ScoreSource::HealthProbe).start_at(now);
    let state = old.score_state();
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[group("score", nodes)],
        nodes,
        None,
        Arc::clone(&state),
    );
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            health.probe_latency_at(Duration::from_millis(1), now);
            health.finish_at(ScoreOutcome::Success, false, now);
            traffic.setup_succeeded_at(now);
            traffic.first_response_at(now + Duration::from_millis(70));
            traffic.transfer_at(1, 1, now + Duration::from_secs(1));
            traffic.finish_at(ScoreOutcome::Success, true, now + Duration::from_secs(1));
        });
        replacement.publish_score_membership();
        probe_at(
            &replacement,
            &leaf,
            &target,
            ScoreSource::HealthProbe,
            Duration::from_millis(600),
            now,
        );
        barrier.wait();
    });
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.probe.value, Some(600.0));
    assert_eq!(score.target_performance.response.value, Some(70.0));
    assert_eq!(score.completed, 1.0);
}

#[test]
fn warmup_setup_quality_remains_available_without_business_completions() {
    let nodes = [node("slow"), node("fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("warm.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([600, 60]) {
        for _ in 0..4 {
            let reporter = manager
                .feedback_for_group_node("score", leaf.id, target.clone())
                .unwrap()
                .with_source(ScoreSource::Warmup)
                .start_at(now);
            reporter.setup_succeeded_at(now + Duration::from_millis(latency));
            reporter.finish_at(ScoreOutcome::Success, false, now + Duration::from_secs(1));
        }
    }
    let state = manager.score_state();
    let score = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        nodes[1].id,
        now + Duration::from_secs(1),
    );
    assert_eq!(score.completed, 0.0);
    assert_eq!(
        state.peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>()),
        1
    );
}
