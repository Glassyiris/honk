//! Ignored load probes for decision cost, behavior transcripts and single-target coverage:
//! `cargo test -p honk-outbound --release --lib score::tests::loaded -- --ignored --nocapture --test-threads=1`.
//! `loaded_transcript` writes to `SCORE_TRANSCRIPT`; byte-compare it across behavior-preserving changes.
use super::*;
use std::fmt::Write as _;

fn loaded(count: usize, targets: usize) -> (Vec<Node>, GroupManager, Instant) {
    let nodes: Vec<_> = (0..count).map(|i| node(&format!("perf {i}"))).collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let base = Instant::now();
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    for (i, leaf) in nodes.iter().enumerate().step_by(3) {
        probe_at(
            &manager,
            leaf,
            &aggregate,
            ScoreSource::HealthProbe,
            Duration::from_millis(30 + (i as u64 * 11) % 40),
            base,
        );
    }
    for t in 0..targets {
        let target = context(&format!("{t}.perf"), IpVersion::V4);
        for (i, leaf) in nodes.iter().enumerate() {
            train_at(
                &manager,
                leaf,
                &target,
                4,
                Duration::from_millis(20 + ((i * 7 + t * 3) % 50) as u64),
                128 * 1024 * (1 + (i % 5) as u64),
                base + Duration::from_millis(t as u64),
            );
        }
    }
    (nodes, manager, base)
}

fn time<T>(label: &str, iterations: usize, mut f: impl FnMut() -> T) {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        std::hint::black_box(f());
        samples.push(start.elapsed());
    }
    samples.sort();
    println!(
        "{label}: median {:?} p90 {:?}",
        samples[iterations / 2],
        samples[iterations * 9 / 10]
    );
}

#[test]
#[ignore]
fn loaded_decision_timing() {
    for (count, targets) in [(50, 82), (100, 40)] {
        let (nodes, manager, base) = loaded(count, targets);
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let target = context(&format!("{}.perf", targets - 1), IpVersion::V4);
        let aggregate = ScoreSelectionContext::aggregate(
            SelectionNetwork::Tcp,
            ProbeDomain::Tcp,
            IpVersion::V4,
        );
        let at = base + Duration::from_secs(3);
        let cache = state.cache_snapshot();
        println!(
            "n={count} exact={} comparison={} logical={}",
            state.exact_len(),
            cache.comparison_cells,
            cache.comparison_logical_bytes,
        );
        let scores: Vec<_> = {
            let inner = state.inner.lock();
            refs.iter()
                .map(|leaf| score_snapshot(&inner, "score", &target, leaf.id, at))
                .collect()
        };
        let baseline = ranking::performance_baseline(&scores);
        time("stage_scores", 2000, || {
            let inner = state.inner.lock();
            refs.iter()
                .map(|leaf| score_snapshot(&inner, "score", &target, leaf.id, at))
                .collect::<Vec<_>>()
        });
        time("stage_node_evidence", 2000, || {
            let inner = state.inner.lock();
            super::super::comparison::node_evidence(&inner, "score", &target, &refs, &scores, at)
        });
        time("stage_pairs", 2000, || {
            let inner = state.inner.lock();
            super::super::comparison::pairs(
                &inner,
                "score",
                &target,
                &refs,
                (&scores, baseline),
                0,
                at,
            )
            .reference
        });
        time("decision", 2000, || {
            let inner = state.inner.lock();
            ranking::decision(&inner, "score", &target, &refs, at)
                .ordinary
                .index
        });
        time("peek_target", 2000, || {
            state.peek_rank_at("score", &target, &refs, at)
        });
        time("peek_aggregate", 2000, || {
            state.peek_rank_at("score", &aggregate, &refs, at)
        });
        time("verification", 2000, || {
            state.verification_snapshot_at("score", &target, &refs, at)
        });
        time("rank_plan", 2000, || {
            state.rank_plan_at("score", &target, &refs, at).0
        });
    }
}

#[test]
#[ignore]
fn loaded_transcript() {
    let (nodes, manager, base) = loaded(20, 12);
    let state = manager.score_state();
    let refs: Vec<_> = nodes.iter().collect();
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let mut out = String::new();
    for step in 0..600_u64 {
        let at = base + Duration::from_millis(2000 + step * 250);
        let family = if step.is_multiple_of(7) {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let target = context(&format!("{}.perf", step % 14), family);
        if step % 50 == 25 {
            for (i, leaf) in nodes.iter().enumerate().step_by(4) {
                probe_at(
                    &manager,
                    leaf,
                    &aggregate,
                    ScoreSource::HealthProbe,
                    Duration::from_millis(25 + (i as u64 + step) % 30),
                    at,
                );
            }
        }
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        write!(out, "{step} {index}").unwrap();
        if !step.is_multiple_of(3)
            && let Ok(guard) = attempt.begin_at(at)
        {
            let reporter = guard.start_at(at);
            reporter.setup_succeeded_at(at);
            reporter.first_response_at(
                at + Duration::from_millis(10 + (index as u64 * 13 + step) % 40),
            );
            reporter.transfer_at(1, 200_000, at + Duration::from_secs(1));
            let outcome = if (index as u64 + step).is_multiple_of(17) {
                ScoreOutcome::Timeout
            } else {
                ScoreOutcome::Success
            };
            reporter.finish_at(outcome, true, at + Duration::from_secs(1));
            write!(out, " begun").unwrap();
        }
        write!(
            out,
            " peek={} agg={}",
            state.peek_rank_at("score", &target, &refs, at),
            state.peek_rank_at("score", &aggregate, &refs, at)
        )
        .unwrap();
        for context in [&target, &aggregate] {
            if let Some(snapshot) = state.verification_snapshot_at("score", context, &refs, at) {
                write!(out, " {snapshot:?}").unwrap();
            }
        }
        writeln!(out).unwrap();
    }
    for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
        let mut budget = manager.score_budget_counters("score", network);
        budget.trial_setup_millis = 0;
        budget.trial_elapsed_millis = 0;
        budget.trial_setup_histogram = [0; 8];
        writeln!(
            out,
            "{budget:?}\n{:?}\n{:?}",
            state.selection_reason_counts("score", network),
            state.verification_counters("score", network)
        )
        .unwrap();
    }
    std::fs::write(std::env::var("SCORE_TRANSCRIPT").unwrap(), out).unwrap();
}

#[test]
#[ignore]
fn single_target_coverage() {
    for count in [2, 3, 5, 6, 8] {
        let nodes: Vec<_> = (0..count).map(|i| node(&format!("coverage {i}"))).collect();
        let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
        let state = manager.score_state();
        let refs: Vec<_> = nodes.iter().collect();
        let target = context("coverage.example", IpVersion::V4);
        let base = Instant::now();
        let (mut confirmed, mut sampled, mut max_compared, mut first) = (0, 0, 0, None);
        for step in 0..4800_u64 {
            let at = base + Duration::from_millis(1000 + step * 50);
            let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
            if let Ok(guard) = attempt.begin_at(at) {
                let reporter = guard.start_at(at);
                reporter.setup_succeeded_at(at);
                reporter.transfer_at(1, 0, at + Duration::from_millis(1));
                reporter.first_response_at(at + Duration::from_millis(20 + index as u64));
                reporter.transfer_at(0, 1, at + Duration::from_millis(21 + index as u64));
                reporter.finish_at(ScoreOutcome::Success, true, at + Duration::from_millis(25));
            }
            if step.is_multiple_of(20) && step >= 1200 {
                let snapshot = state
                    .verification_snapshot_at(
                        "score",
                        &target,
                        &refs,
                        at + Duration::from_millis(30),
                    )
                    .unwrap();
                sampled += 1;
                if snapshot.comparison != ScoreComparison::Unconfirmed {
                    confirmed += 1;
                    first.get_or_insert(step);
                }
                max_compared = max_compared.max(snapshot.compared_count);
            }
        }
        let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
        println!(
            "coverage n={count}: confirmed {confirmed}/{sampled} first_step={first:?} max_compared={max_compared} trials={} business={}",
            budget.trial_starts, budget.business_starts
        );
    }
}
