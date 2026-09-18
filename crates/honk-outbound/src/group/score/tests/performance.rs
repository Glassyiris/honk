use super::*;

#[test]
fn one_exact_success_cannot_weaken_mature_incumbent_protection() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let previous = context("previous.example", IpVersion::V4);
    let target = context("new.example", IpVersion::V4);
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &previous,
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
        &nodes[0],
        &target,
        1,
        Duration::from_millis(100),
        1,
        now + Duration::from_secs(5),
    );
    train_at(
        &manager,
        &nodes[1],
        &previous,
        200,
        Duration::from_millis(95),
        1,
        now + Duration::from_secs(7),
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(9)),
        0
    );
    let state = manager.score_state();
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .incumbent_held,
        1
    );

    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(if index == 0 { 600 } else { 60 }),
            1,
            now + Duration::from_secs(10 + index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(14)),
        1
    );
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        1
    );
}

#[test]
fn expired_incumbent_holds_unmatched_refresh_but_shared_probe_can_promote() {
    let nodes = [node("a-100ms"), node("b-110ms"), node("c-120ms")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let start = now - Duration::from_secs(124);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100 + index as u64 * 10),
            1,
            start + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, start + Duration::from_secs(6)),
        0
    );
    for (index, leaf) in nodes.iter().enumerate().skip(1) {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100 + index as u64 * 10),
            1,
            start + Duration::from_secs(80 + index as u64 * 2),
        );
    }
    let state = manager.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    assert_eq!(state.peek_rank("score", &target, &refs), 0);
    let _ = rank_at(&manager, &nodes, &target, now);
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    let reasons = state.selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.insufficient_evidence_held, 2);
    assert_eq!(reasons.ordinary_switch, 0);
    assert_eq!(reasons.periodic_explore, 0);

    let probe = context("configured.example", IpVersion::V4);
    for (leaf, latency) in nodes[..2].iter().zip([600, 60]) {
        probe_at(
            &manager,
            leaf,
            &probe,
            ScoreSource::HealthProbe,
            Duration::from_millis(latency),
            now,
        );
    }
    assert_eq!(rank_at(&manager, &nodes, &target, now), 1);
    assert_eq!(
        state
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .ordinary_switch,
        1
    );
}

#[test]
fn unsupported_global_best_cannot_mask_comparable_third_challenger() {
    let nodes = [
        node("incumbent"),
        node("unmatched-fast"),
        node("shared-probe-fast"),
    ];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let start = now - Duration::from_secs(124);
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100 + index as u64 * 10),
            1,
            start + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, start + Duration::from_secs(6)),
        0
    );
    for (index, latency) in [(1, 10), (2, 100)] {
        train_at(
            &manager,
            &nodes[index],
            &target,
            20,
            Duration::from_millis(latency),
            1,
            start + Duration::from_secs(80 + index as u64 * 2),
        );
    }
    let probe = context("configured.example", IpVersion::V4);
    for (index, latency) in [(0, 600), (2, 60)] {
        probe_at(
            &manager,
            &nodes[index],
            &probe,
            ScoreSource::HealthProbe,
            Duration::from_millis(latency),
            now,
        );
    }
    assert_eq!(
        manager
            .score_state()
            .peek_rank("score", &target, &nodes.iter().collect::<Vec<_>>()),
        2
    );
}

#[test]
fn opposite_direction_strengths_do_not_create_a_pairwise_rate_gain() {
    let nodes = [node("upload"), node("download"), node("extreme-upload")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    for (index, leaf) in nodes.iter().enumerate() {
        train_at(
            &manager,
            leaf,
            &target,
            20,
            Duration::from_millis(100),
            1,
            now + Duration::from_secs(index as u64 * 2),
        );
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(6)),
        0
    );
    for (index, (tx, rx)) in [
        (1_000_000, 100_000),
        (100_000, 1_000_000),
        (10_000_000, 65_536),
    ]
    .into_iter()
    .enumerate()
    {
        let at = now + Duration::from_secs(7 + index as u64 * 2);
        let feedback = manager
            .feedback_for_group_node("score", nodes[index].id, target.clone())
            .unwrap();
        let reporters: Vec<_> = (0..4).map(|_| feedback.start_at(at)).collect();
        for reporter in &reporters {
            reporter.setup_succeeded_at(at);
        }
        for reporter in &reporters {
            reporter.first_response_at(at + Duration::from_millis(100));
        }
        for reporter in &reporters {
            reporter.transfer_at(tx, rx, at + Duration::from_secs(1));
        }
        for reporter in reporters {
            reporter.finish_at(ScoreOutcome::Success, true, at + Duration::from_secs(1));
        }
    }
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(13)),
        0
    );
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.incumbent_held, 1);
    assert_eq!(reasons.ordinary_switch, 0);
}

#[test]
fn less_sampled_faster_leaf_wins_normal_selection() {
    let nodes = [node("historical"), node("faster")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        1000,
        Duration::from_millis(600),
        2_000_000,
        now,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(60),
        8_000_000,
        now,
    );
    assert_eq!(selected(&manager, &target), nodes[1].id);
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.performance_winner, 1);
    assert_eq!(reasons.cold_explore + reasons.periodic_explore, 0);
}

#[test]
fn sparse_fast_leaf_earns_normal_traffic_with_bounded_validation() {
    let nodes = [node("established"), node("unvalidated")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        1000,
        Duration::from_millis(600),
        2_000_000,
        now,
    );
    let mut trials = 0;
    let mut normal_winner = false;
    for request in 0..96 {
        let before = manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp);
        let index = rank_at(&manager, &nodes, &target, now + Duration::from_secs(2));
        let after = manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp);
        if index == 1 {
            if after.cold_explore + after.periodic_explore
                == before.cold_explore + before.periodic_explore
            {
                normal_winner = true;
                break;
            }
            trials += 1;
            assert!(trials <= 1 + request / 16);
        }
        train_at(
            &manager,
            &nodes[index],
            &target,
            1,
            Duration::from_millis(if index == 0 { 600 } else { 60 }),
            if index == 0 { 2_000_000 } else { 8_000_000 },
            now,
        );
    }
    assert!(
        normal_winner,
        "successful validation must graduate out of exploration"
    );
    assert!(trials <= 6);
}

#[test]
fn fast_health_probes_cannot_erase_real_failures() {
    let nodes = [node("working"), node("failing")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
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
    train_at(
        &manager,
        &nodes[1],
        &target,
        1000,
        Duration::from_millis(10),
        1,
        now,
    );
    for _ in 0..3 {
        manager
            .feedback_for_group_node("score", nodes[1].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    let probe = context("configured.example", IpVersion::V4);
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    assert_eq!(
        manager
            .score_state()
            .selection_reason_counts("score", SelectionNetwork::Tcp)
            .fail_streak_excluded,
        1
    );
}

#[test]
fn excluded_leaf_cannot_change_eligible_performance_winner_or_reason() {
    let nodes = [node("balanced"), node("bandwidth"), node("failing-fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(100),
        1_000_000,
        now,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(200),
        2_000_000,
        now,
    );
    train_at(
        &manager,
        &nodes[2],
        &target,
        1000,
        Duration::from_millis(1),
        2_000_000,
        now,
    );
    for _ in 0..3 {
        manager
            .feedback_for_group_node("score", nodes[2].id, target.clone())
            .unwrap()
            .start_at(now)
            .finish_at(ScoreOutcome::Timeout, true, now);
    }
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    let reasons = manager
        .score_state()
        .selection_reason_counts("score", SelectionNetwork::Tcp);
    assert_eq!(reasons.performance_winner, 1);
    assert_eq!(reasons.reliability_winner, 0);
}

#[test]
fn stale_exact_volume_cannot_override_fresh_comparable_probes() {
    for samples in [100, 10_000] {
        let nodes = [node("old-target-winner"), node("fresh-probe-winner")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
        let probe = context("configured.example", IpVersion::V4);
        let start = Instant::now();
        train_at(
            &manager,
            &nodes[0],
            &target,
            samples,
            Duration::from_millis(60),
            1,
            start,
        );
        train_at(
            &manager,
            &nodes[1],
            &target,
            20,
            Duration::from_millis(600),
            1,
            start,
        );
        assert_eq!(
            rank_at(&manager, &nodes, &target, start + Duration::from_secs(2)),
            0
        );
        let now = start + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
        probe_at(
            &manager,
            &nodes[0],
            &probe,
            ScoreSource::HealthProbe,
            Duration::from_millis(600),
            now,
        );
        probe_at(
            &manager,
            &nodes[1],
            &probe,
            ScoreSource::HealthProbe,
            Duration::from_millis(60),
            now,
        );
        assert_eq!(
            rank_at(&manager, &nodes, &target, now),
            1,
            "history volume={samples}"
        );
    }
}

#[test]
fn trustworthy_target_beats_probe_only_while_target_is_fresh() {
    let nodes = [node("target-winner"), node("probe-winner")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("configured.example", IpVersion::V4);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(60),
        1,
        start,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(600),
        1,
        start,
    );
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        start,
    );
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(60),
        start,
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, start + Duration::from_secs(2)),
        0
    );
    let expired = start + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        expired,
    );
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(60),
        expired,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, expired), 1);
}

#[test]
fn starts_and_warmups_do_not_renew_business_freshness() {
    let nodes = [node("old-target-winner"), node("probe-winner")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("configured.example", IpVersion::V4);
    let start = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        1000,
        Duration::from_millis(60),
        1,
        start,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(600),
        1,
        start,
    );
    let now = start + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let unfinished = manager
        .feedback_for_group_node("score", nodes[0].id, target.clone())
        .unwrap()
        .start_at(now);
    probe_at(
        &manager,
        &nodes[0],
        &target,
        ScoreSource::Warmup,
        Duration::from_millis(1),
        now,
    );
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        now,
    );
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(60),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 1);
    unfinished.finish_at(ScoreOutcome::Cancelled, false, now);
}

#[test]
fn qualified_half_faster_goodput_switches_but_latency_jitter_holds() {
    let nodes = [node("incumbent"), node("challenger")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    train_at(
        &manager,
        &nodes[0],
        &target,
        20,
        Duration::from_millis(100),
        1_000_000,
        now,
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(110),
        1_000_000,
        now,
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(95),
        1_000_000,
        now,
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        0
    );
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(100),
        1_500_000,
        now,
    );
    assert_eq!(
        rank_at(&manager, &nodes, &target, now + Duration::from_secs(2)),
        1
    );
}

#[test]
fn probe_domains_and_health_families_are_not_comparable() {
    let nodes = [node("declared-first"), node("dns-only-fast")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let mut target = context("business.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
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
    train_at(
        &manager,
        &nodes[1],
        &target,
        20,
        Duration::from_millis(100),
        1,
        now,
    );
    let now = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let mut probe = target.clone();
    probe.target = Some(ScoreTarget::domain("configured.example", 443));
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        now,
    );
    probe.probe_domain = ProbeDomain::DnsUdp;
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    probe.probe_domain = ProbeDomain::DataUdp;
    probe.health_family = IpVersion::V6;
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 0);
    probe.health_family = IpVersion::V4;
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 1);
}

#[test]
fn one_healthy_probe_scope_does_not_replace_another() {
    let nodes = [node("slow"), node("fast-quic")];
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let mut target = context("business.example", IpVersion::V4);
    target.network = SelectionNetwork::Udp;
    target.probe_domain = ProbeDomain::DataUdp;
    let now = Instant::now();
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
    let now = now + PERFORMANCE_MAX_AGE + Duration::from_secs(2);
    let mut probe = target.clone();
    probe.target = Some(ScoreTarget::domain("configured.example", 443));
    probe_at(
        &manager,
        &nodes[0],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(600),
        now,
    );
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_millis(1),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 1);
    probe.probe_domain = ProbeDomain::DnsUdp;
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_secs(10),
        now,
    );
    probe.probe_domain = ProbeDomain::DataUdp;
    probe.health_family = IpVersion::V6;
    probe_at(
        &manager,
        &nodes[1],
        &probe,
        ScoreSource::HealthProbe,
        Duration::from_secs(10),
        now,
    );
    assert_eq!(rank_at(&manager, &nodes, &target, now), 1);
}

fn http_probe_at(
    manager: &GroupManager,
    leaf: &Node,
    probe_context: &ScoreSelectionContext,
    uri: &str,
    method: &str,
    latency: Duration,
    now: Instant,
) {
    let feedback = manager
        .feedback_for_http_probe(leaf.id, probe_context.clone(), uri, uri)
        .unwrap()
        .with_probe_identity(uri, method);
    for _ in 0..4 {
        let reporter = feedback.start_at(now);
        reporter.probe_latency_at(latency, now);
        reporter.finish_at(ScoreOutcome::Success, false, now);
    }
}

#[test]
fn http_probe_path_query_and_method_define_distinct_comparison_cohorts() {
    let original = "https://configured.example/first?mode=a";
    for (uri, method) in [
        ("https://configured.example/second?mode=a", "GET"),
        ("https://configured.example/first?mode=b", "GET"),
        (original, "POST"),
    ] {
        let nodes = [node("same-workload"), node("other-workload")];
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let target = context("business.example", IpVersion::V4);
        let probe = context("configured.example", IpVersion::V4);
        let now = Instant::now();
        http_probe_at(
            &manager,
            &nodes[0],
            &probe,
            original,
            "GET",
            Duration::from_millis(600),
            now,
        );
        http_probe_at(
            &manager,
            &nodes[1],
            &probe,
            uri,
            method,
            Duration::from_millis(1),
            now,
        );
        let state = manager.score_state();
        let refs = nodes.iter().collect::<Vec<_>>();
        assert_eq!(
            state.peek_rank("score", &target, &refs),
            0,
            "{uri} {method} is not the same workload"
        );
        http_probe_at(
            &manager,
            &nodes[1],
            &probe,
            original,
            "GET",
            Duration::from_millis(1),
            now,
        );
        assert_eq!(state.peek_rank("score", &target, &refs), 1);
    }
}

#[test]
fn same_host_probe_url_reload_discards_baselines_at_commit_before_new_samples() {
    let nodes = [node("old-winner"), node("new-winner")];
    let old_uri = "https://configured.example/first?mode=a";
    let new_uri = "https://configured.example/second?mode=b";
    let mut configured = group("score", &nodes);
    configured.check_url = Some(old_uri.into());
    let old = GroupManager::new(std::slice::from_ref(&configured), &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("configured.example", IpVersion::V4);
    let now = Instant::now();
    for (leaf, latency) in nodes.iter().zip([1, 600]) {
        http_probe_at(
            &old,
            leaf,
            &probe,
            old_uri,
            "GET",
            Duration::from_millis(latency),
            now,
        );
    }
    let state = old.score_state();
    let refs = nodes.iter().collect::<Vec<_>>();
    assert_eq!(state.peek_rank("score", &target, &refs), 0);
    configured.check_url = Some(new_uri.into());
    let replacement = GroupManager::with_alive_set_and_score_state(
        &[configured],
        &nodes,
        None,
        Arc::clone(&state),
    );
    assert_eq!(
        score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, now)
            .probe
            .value,
        Some(1.0)
    );
    replacement.publish_score_membership();
    for leaf in &nodes {
        assert!(
            score_snapshot(&state.inner.lock(), "score", &target, leaf.id, now)
                .probe
                .value
                .is_none()
        );
    }
    http_probe_at(
        &replacement,
        &nodes[0],
        &probe,
        new_uri,
        "GET",
        Duration::from_millis(600),
        now,
    );
    assert!(
        score_snapshot(&state.inner.lock(), "score", &target, nodes[1].id, now)
            .probe
            .value
            .is_none()
    );
    http_probe_at(
        &replacement,
        &nodes[1],
        &probe,
        new_uri,
        "GET",
        Duration::from_millis(60),
        now,
    );
    assert_eq!(
        score_snapshot(&state.inner.lock(), "score", &target, nodes[0].id, now)
            .probe
            .value,
        Some(600.0)
    );
    assert_eq!(state.peek_rank("score", &target, &refs), 1);
}

#[test]
fn health_probe_targets_cannot_evict_live_business_evidence() {
    let leaf = node("leaf");
    let nodes = std::slice::from_ref(&leaf);
    let manager = GroupManager::new(&[group("score", nodes)], nodes);
    let target = context("business.example", IpVersion::V4);
    let state = manager.score_state();
    {
        let mut inner = state.inner.lock();
        inner.exact.resize(NonZeroUsize::new(1).unwrap());
        inner.aggregate.resize(NonZeroUsize::new(2).unwrap());
    }
    let now = Instant::now();
    let traffic = manager
        .feedback_for_group_node("score", leaf.id, target.clone())
        .unwrap()
        .start_at(now);
    for host in ["first.example", "second.example"] {
        probe_at(
            &manager,
            &leaf,
            &context(host, IpVersion::V6),
            ScoreSource::HealthProbe,
            Duration::from_millis(5),
            now,
        );
    }
    traffic.setup_succeeded_at(now);
    traffic.first_response_at(now + Duration::from_millis(70));
    traffic.finish_at(ScoreOutcome::Cancelled, true, now + Duration::from_secs(1));
    let exact = score_snapshot(
        &state.inner.lock(),
        "score",
        &target,
        leaf.id,
        now + Duration::from_secs(1),
    );
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let global = score_snapshot(
        &state.inner.lock(),
        "score",
        &aggregate,
        leaf.id,
        now + Duration::from_secs(1),
    );
    assert_eq!(exact.target_performance.response.value, Some(70.0));
    assert_eq!(global.performance.response.value, Some(70.0));
    assert_eq!(global.completed, 0.0);
}
