use super::super::evaluation::{self, EvaluationSet};
use super::super::ranking::performance_baseline;
use super::*;

fn members(count: usize) -> Vec<Node> {
    (0..count)
        .map(|index| node(&format!("member-{index}")))
        .collect()
}

fn idle_scores(count: usize) -> (Vec<ScoreSnapshot>, PerformanceBaseline) {
    let scores = vec![ScoreSnapshot::default(); count];
    let baseline = performance_baseline(&scores);
    (scores, baseline)
}

#[test]
fn evaluation_limit_follows_offered_business_only_at_refresh() {
    let nodes = members(40);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let now = Instant::now();
    let idle = evaluation::derive(None, &refs, &scores, baseline, now);
    let idle_membership = idle.membership(&refs, 0);
    assert_eq!(idle_membership.evaluated.iter().filter(|v| **v).count(), 4);
    let mut busy = idle;
    for second in 0..600 {
        busy.record_demand(now + Duration::from_secs(second));
    }
    let before_refresh = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        baseline,
        now + Duration::from_secs(240),
    );
    assert_eq!(
        before_refresh
            .membership(&refs, 0)
            .evaluated
            .iter()
            .filter(|v| **v)
            .count(),
        4,
        "growth waits for the refresh period"
    );
    let refreshed = evaluation::derive(
        Some(&busy),
        &refs,
        &scores,
        baseline,
        now + Duration::from_secs(600),
    );
    let evaluated = refreshed
        .membership(&refs, 0)
        .evaluated
        .iter()
        .filter(|v| **v)
        .count();
    assert!((10..=26).contains(&evaluated), "{evaluated}");
}

#[test]
fn members_missing_from_one_view_keep_their_place() {
    let nodes = members(12);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let now = Instant::now();
    let set = evaluation::derive(None, &refs, &scores, baseline, now);
    let ranked = set
        .membership(&refs, usize::MAX)
        .covered
        .iter()
        .position(|covered| *covered)
        .unwrap();
    let absent = refs[ranked].id;
    let view: Vec<_> = refs
        .iter()
        .copied()
        .filter(|node| node.id != absent)
        .collect();
    let (view_scores, view_baseline) = idle_scores(view.len());
    let later = evaluation::derive(
        Some(&set),
        &view,
        &view_scores,
        view_baseline,
        now + Duration::from_secs(600),
    );
    assert!(
        later.evaluates(absent),
        "a retry or filtered view is not a membership removal"
    );
}

#[test]
fn ranked_members_join_coverage_at_their_first_qualification() {
    let nodes = members(3);
    let refs: Vec<_> = nodes.iter().collect();
    let now = Instant::now();
    let (idle, _) = idle_scores(3);
    let qualified = ScoreSnapshot {
        useful_completed: PERFORMANCE_VALIDATION_SAMPLES,
        ..Default::default()
    };
    let unknown = ScoreSnapshot::default();
    let derive = |stored: Option<&EvaluationSet>, scores: &[ScoreSnapshot]| {
        evaluation::derive(stored, &refs, scores, performance_baseline(scores), now)
    };
    let covered = |set: &EvaluationSet| set.membership(&refs, 0).covered;
    // Qualification cannot gate coverage before any member is qualified.
    let cold = derive(None, &idle);
    assert_eq!(covered(&cold), [true, true, true]);
    // Once one is, members still acquiring evidence are evaluated but cannot stall a claim.
    let first = derive(Some(&cold), &[qualified, qualified, unknown]);
    assert_eq!(covered(&first), [true, true, false]);
    assert!(first.membership(&refs, 0).evaluated[2]);
    // Admission outlives a later lapse, so the lapse reopens the claim instead of shrinking it.
    let lapsed = derive(Some(&first), &[qualified, unknown, unknown]);
    assert_eq!(covered(&lapsed), [true, true, false]);
}

#[test]
fn rotation_visits_every_member_outside_the_ranked_set() {
    let nodes = members(10);
    let refs: Vec<_> = nodes.iter().collect();
    let (scores, baseline) = idle_scores(nodes.len());
    let start = Instant::now();
    let mut set: Option<EvaluationSet> = None;
    let mut visited = std::collections::HashSet::new();
    for slot in 0..10 {
        let derived = evaluation::derive(
            set.as_ref(),
            &refs,
            &scores,
            baseline,
            start + Duration::from_secs(600 * slot),
        );
        let membership = derived.membership(&refs, usize::MAX);
        for (index, node) in refs.iter().enumerate() {
            if membership.evaluated[index] && !membership.covered[index] {
                visited.insert(node.id);
            }
        }
        set = Some(derived);
    }
    let final_set = set.unwrap();
    let outside = refs
        .iter()
        .enumerate()
        .filter(|(index, _)| !final_set.membership(&refs, usize::MAX).covered[*index])
        .count();
    assert_eq!(outside, 8);
    assert_eq!(visited.len(), outside);
}

#[test]
fn readonly_reads_never_store_an_evaluation_set() {
    let nodes = members(10);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let now = Instant::now();
    let state = manager.score_state();
    state
        .verification_snapshot_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now)
        .unwrap();
    state.peek_rank_at("score", &target, &nodes.iter().collect::<Vec<_>>(), now);
    assert!(state.inner.lock().evaluation.is_empty());
    rank_at(&manager, &nodes, &target, now);
    assert_eq!(state.inner.lock().evaluation.len(), 1);
}

#[test]
fn unevaluated_members_keep_probes_out_of_comparison_cells() {
    let nodes = members(10);
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let now = Instant::now();
    rank_at(&manager, &nodes, &target, now);
    let state = manager.score_state();
    let key = SelectionReasonKey::new("score", SelectionNetwork::Tcp);
    let (inside, outside) = {
        let inner = state.inner.lock();
        let set = &inner.evaluation[&key];
        (
            nodes
                .iter()
                .find(|node| set.evaluates(node.id))
                .unwrap()
                .clone(),
            nodes
                .iter()
                .find(|node| set.excludes(node.id))
                .unwrap()
                .clone(),
        )
    };
    let cells = || state.inner.lock().comparisons.cell_count();
    let before = cells();
    probe_at(&manager, &outside, &probe, 10, now);
    assert_eq!(cells(), before);
    probe_at(&manager, &inside, &probe, 10, now);
    assert_eq!(cells(), before + 1);
}

#[test]
fn a_hundred_members_reach_a_bounded_claim_at_moderate_traffic() {
    let nodes = members(100);
    let refs: Vec<_> = nodes.iter().collect();
    let manager = GroupManager::new(&[group("score", &nodes)], &nodes);
    let state = manager.score_state();
    let target = context("business.example", IpVersion::V4);
    let probe = context("health.example", IpVersion::V4);
    let aggregate =
        ScoreSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
    let latency = |index: usize| 40 + (index as u64 * 37) % 400;
    let start = Instant::now();
    let mut confirmed = None;
    let mut widest = 0;
    // About 1.5 business flows per second for 25 minutes, with 30-second configured probes.
    for step in 0..2250u64 {
        let at = start + Duration::from_millis(step * 667);
        if step % 45 == 0 {
            for (index, leaf) in nodes.iter().enumerate() {
                probe_at(&manager, leaf, &probe, latency(index), at);
            }
        }
        let (index, attempt) = state.rank_plan_at("score", &target, &refs, at);
        respond_at(attempt, Duration::from_millis(latency(index)), at);
        if step % 15 == 0 {
            let snapshot = state
                .verification_snapshot_at("score", &aggregate, &refs, at)
                .unwrap();
            widest = widest.max(snapshot.evaluated_count);
            assert!(snapshot.pending_count <= snapshot.evaluated_count);
            if snapshot.comparison != ScoreComparison::Unconfirmed {
                confirmed.get_or_insert(snapshot);
            }
        }
    }
    let snapshot = confirmed.expect("a bounded evaluation set must be able to confirm");
    assert!(snapshot.evaluated_count < snapshot.candidate_count);
    assert!(widest <= 26, "{widest}");
    let budget = manager.score_budget_counters("score", SelectionNetwork::Tcp);
    assert!(
        budget.trial_starts
            <= exploration_target(100) as u64 + budget.business_starts / SCORE_EXPLORATION_PERIOD
    );
}
