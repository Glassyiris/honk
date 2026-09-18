use super::evidence::evidence_decay;
use super::{
    AggregateKey, ExactKey, HoldDecision, MIN_TRAINED_EVIDENCE, MetricSnapshot,
    PERFORMANCE_SWITCH_MARGIN, PERFORMANCE_VALIDATION_SAMPLES, PerformanceBaseline,
    PerformanceSnapshot, RELIABILITY_CLOSE, REVALIDATION_INTERVAL, RankedSelection,
    SCORE_EXPLORATION_MAX_PERIOD, SCORE_EXPLORATION_MIN_PERIOD, SCORE_EXPLORE_BACKOFF_BASE,
    SCORE_EXPLORE_BACKOFF_MAX, SCORE_FAIL_STREAK_EXCLUDE, SCORE_FAILURE_FORGIVENESS_THRESHOLD,
    SCORE_SWITCH_FULL_EVIDENCE, ScoreAuthority, ScorePolicyState, ScoreSelectionContext,
    ScoreSnapshot, SelectionCadence, SelectionCadenceKey, SelectionHistoryKey, SelectionReason,
    SelectionReasonKey, StateInner, Stats,
};
use honk_config::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(super) fn explore_backoff(streak: u32) -> Duration {
    SCORE_EXPLORE_BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(streak.saturating_sub(1).min(7)))
        .min(SCORE_EXPLORE_BACKOFF_MAX)
}

pub(super) fn exploration_target(candidate_count: usize) -> usize {
    if candidate_count <= 4 {
        candidate_count
    } else {
        (((candidate_count as f64).sqrt().ceil() as usize) + 1).min(candidate_count)
    }
}

pub(super) fn exploration_period(candidate_count: usize) -> u64 {
    (candidate_count as u64)
        .saturating_mul(2)
        .clamp(SCORE_EXPLORATION_MIN_PERIOD, SCORE_EXPLORATION_MAX_PERIOD)
}

impl ScorePolicyState {
    pub(in crate::group) fn rank(
        &self,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_inner(Some(authority), group, context, nodes, Instant::now(), true)
    }

    pub(in crate::group) fn peek_rank(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_inner(None, group, context, nodes, Instant::now(), false)
    }

    #[cfg(test)]
    pub(super) fn rank_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .unwrap_or_else(|| Arc::new(ScoreAuthority));
        self.rank_inner(Some(&authority), group, context, nodes, now, true)
    }

    fn rank_inner(
        &self,
        authority: Option<&Arc<ScoreAuthority>>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
        apply: bool,
    ) -> usize {
        if nodes.is_empty() {
            return 0;
        }
        let mut inner = self.inner.lock();
        let authorized = apply
            && authority.is_some_and(|authority| {
                inner
                    .active_authority
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, authority))
            })
            && inner.valid_groups.contains(group);
        let snapshots: Vec<_> = nodes
            .iter()
            .map(|node| score_snapshot(&inner, group, context, node.id, now))
            .collect();
        let performance = performance_baseline(&snapshots);
        let cadence_key = SelectionCadenceKey::new(group, context);
        let history_key = SelectionHistoryKey::new(group, context);
        let incumbent = inner
            .selection_history
            .peek(&history_key)
            .filter(|history| history.selections > 0)
            .and_then(|history| nodes.iter().position(|node| node.id == history.current));
        let (selection_count, due) = if authorized {
            let cadence =
                inner
                    .selection_counts
                    .entry(cadence_key.clone())
                    .or_insert(SelectionCadence {
                        count: 0,
                        revalidated_count: 0,
                        revalidated_at: now,
                        validation_node: None,
                        validation_attempts: 0,
                    });
            cadence.count = cadence.count.saturating_add(1);
            let elapsed_count = cadence.count.saturating_sub(cadence.revalidated_count);
            let degraded = incumbent
                .and_then(|index| snapshots[index].degraded_at)
                .is_some_and(|at| at > cadence.revalidated_at);
            let due = elapsed_count >= exploration_period(nodes.len())
                || now.saturating_duration_since(cadence.revalidated_at) >= REVALIDATION_INTERVAL
                || (degraded && elapsed_count >= SCORE_EXPLORATION_MIN_PERIOD);
            (cadence.count, due)
        } else {
            (
                inner
                    .selection_counts
                    .get(&cadence_key)
                    .map_or(0, |cadence| cadence.count),
                false,
            )
        };
        let ordinary = ordinary_selection(&snapshots, nodes, incumbent, performance);
        if !authorized {
            return ordinary.index;
        }
        let evaluation = super::verification::evaluate(
            &snapshots,
            nodes,
            ordinary.index,
            context,
            inner.selection_counts.get(&cadence_key),
            performance,
            now,
        );
        let mut selection = ordinary;
        if selection_count <= exploration_target(nodes.len()) as u64 {
            let startup = best_index(&snapshots, nodes, selection_count, true, performance);
            if startup.reason.is_exploration() {
                selection = startup;
            }
        }
        if due
            && !selection.reason.is_exploration()
            && let Some(index) = evaluation.validation_index
            && Some(index) != incumbent.filter(|&previous| previous != ordinary.index)
        {
            selection = RankedSelection {
                index,
                reason: SelectionReason::PeriodicExplore,
            };
        }
        if selection.reason.is_exploration()
            && let Some(cadence) = inner.selection_counts.get_mut(&cadence_key)
        {
            cadence.revalidated_count = selection_count;
            cadence.revalidated_at = now;
            let node_id = nodes[selection.index].id;
            if cadence.validation_node == Some(node_id) {
                cadence.validation_attempts = cadence.validation_attempts.saturating_add(1);
            } else if cadence.validation_node.is_none()
                || selection.reason != SelectionReason::ColdExplore
            {
                cadence.validation_node = Some(node_id);
                cadence.validation_attempts = 1;
            }
        }
        Self::record_verification(
            &mut inner,
            &history_key,
            nodes[ordinary.index].id,
            super::verification::usable(&snapshots[selection.index]),
            selection.reason.is_exploration(),
            &evaluation,
            now,
        );
        if nodes.len() > 1 {
            let streak_excluded = snapshots
                .iter()
                .filter(|score| {
                    performance.any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE
                })
                .count() as u64;
            let backed_off = snapshots
                .iter()
                .filter(|score| score.explore_backed_off)
                .count() as u64;
            let counts = inner
                .selection_reasons
                .entry(SelectionReasonKey::new(group, context.network))
                .or_default();
            counts.fail_streak_excluded =
                counts.fail_streak_excluded.saturating_add(streak_excluded);
            counts.explore_backed_off = counts.explore_backed_off.saturating_add(backed_off);
            Self::record_selection_reason(&mut inner, group, context.network, selection);
            Self::record_switch_flap(
                &mut inner,
                &history_key,
                nodes[selection.index].id,
                selection.reason,
            );
        }
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        mark_selected(&mut inner, group, context, nodes[selection.index].id, tick);
        selection.index
    }
}

pub(super) fn ordinary_selection(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    incumbent: Option<usize>,
    performance: PerformanceBaseline,
) -> RankedSelection {
    let best = best_index(snapshots, nodes, 0, false, performance);
    let Some(index) = incumbent.filter(|&index| index != best.index) else {
        return best;
    };
    if !normal_eligible(&snapshots[index], performance) {
        return if snapshots[index].failures >= SCORE_FAILURE_FORGIVENESS_THRESHOLD {
            RankedSelection {
                index: best.index,
                reason: SelectionReason::FreshFailureBypass,
            }
        } else {
            best
        };
    }
    match hold_decision(&snapshots[index], &snapshots[best.index], performance) {
        HoldDecision::Held => RankedSelection {
            index,
            reason: SelectionReason::IncumbentHeld,
        },
        HoldDecision::FreshFailureBypass => RankedSelection {
            index: best.index,
            reason: SelectionReason::FreshFailureBypass,
        },
        HoldDecision::UseBest => best,
    }
}

pub(super) fn best_index(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    selection_count: u64,
    explore: bool,
    performance: PerformanceBaseline,
) -> RankedSelection {
    // The startup allowance is coarse-scope and finite. Cancellation, a new
    // target or an evicted exact cell cannot mint another startup allowance.
    if explore
        && snapshots.len() > 1
        && selection_count <= exploration_target(snapshots.len()) as u64
        && let Some((index, _)) = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| {
                score.completed < MIN_TRAINED_EVIDENCE && !score.explore_backed_off
            })
            .min_by(|(left_index, left), (right_index, right)| {
                left.attempts
                    .total_cmp(&right.attempts)
                    .then_with(|| super::verification::untried_hint(left, right))
                    .then_with(|| left.selected_at.cmp(&right.selected_at))
                    .then_with(|| left_index.cmp(right_index))
            })
    {
        return RankedSelection {
            index,
            reason: SelectionReason::ColdExplore,
        };
    }
    let index = snapshots
        .iter()
        .enumerate()
        .filter(|(_, score)| normal_eligible(score, performance))
        .max_by(|(left_index, left), (right_index, right)| {
            utility(left, performance)
                .total_cmp(&utility(right, performance))
                .then_with(|| right_index.cmp(left_index))
                .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
        })
        .map(|(index, _)| index)
        .unwrap_or(0);
    let alternatives = snapshots
        .iter()
        .enumerate()
        .any(|(other, score)| other != index && normal_eligible(score, performance));
    RankedSelection {
        index,
        reason: if alternatives {
            SelectionReason::PerformanceWinner
        } else {
            SelectionReason::ReliabilityWinner
        },
    }
}

pub(super) fn normal_eligible(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> bool {
    if baseline.any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE {
        return false;
    }
    if baseline.any_qualified {
        score.useful_completed >= PERFORMANCE_VALIDATION_SAMPLES
            && score.reliability_upper + RELIABILITY_CLOSE >= baseline.best_reliability
            && score.observed_reliability + RELIABILITY_CLOSE >= baseline.best_observed_reliability
    } else {
        score.reliability + RELIABILITY_CLOSE >= baseline.best_reliability
    }
}

pub(super) fn switch_margin(completed: f64) -> f64 {
    // Ten percent of the available performance range: a 50% rate gain
    // clears this margin, while small latency jitter does not.
    0.05 * PERFORMANCE_SWITCH_MARGIN * (completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0)
}

pub(super) fn hold_decision(
    incumbent: &ScoreSnapshot,
    best: &ScoreSnapshot,
    performance: PerformanceBaseline,
) -> HoldDecision {
    let trained =
        incumbent.completed >= MIN_TRAINED_EVIDENCE && best.completed >= MIN_TRAINED_EVIDENCE;
    if !normal_eligible(incumbent, performance)
        || !trained
        || utility(best, performance) - utility(incumbent, performance)
            >= switch_margin(incumbent.hysteresis_completed)
    {
        HoldDecision::UseBest
    } else if incumbent.failures < SCORE_FAILURE_FORGIVENESS_THRESHOLD {
        HoldDecision::Held
    } else {
        HoldDecision::FreshFailureBypass
    }
}

fn mark_selected(
    inner: &mut StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node_id: Uuid,
    tick: u64,
) {
    let key = AggregateKey {
        group: group.to_string(),
        network: context.network,
        family: context.target_family,
        node_id,
    };
    if let Some(stats) = inner.aggregate.get_mut(&key) {
        stats.selected_at = tick;
    } else {
        if inner.aggregate.len() == inner.aggregate.cap().get() {
            inner.aggregate_evictions = inner.aggregate_evictions.saturating_add(1);
        }
        inner.aggregate.put(
            key,
            Stats {
                incarnation: tick,
                selected_at: tick,
                ..Default::default()
            },
        );
    }
    if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) {
        let key = ExactKey {
            group: group.to_string(),
            network: context.network,
            family,
            target: target.clone(),
            node_id,
        };
        if let Some(stats) = inner.exact.get_mut(&key) {
            stats.selected_at = tick;
        }
    }
}

pub(super) fn score_snapshot(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    node_id: Uuid,
    now: Instant,
) -> ScoreSnapshot {
    let layer = |family| {
        inner.aggregate.peek(&AggregateKey {
            group: group.to_string(),
            network: context.network,
            family,
            node_id,
        })
    };
    let global_stats = layer(None);
    let mut score = global_stats.map_or_else(
        || snapshot(&Stats::default(), now),
        |stats| snapshot(stats, now),
    );
    if let Some(stats) = context.target_family.and_then(|family| layer(Some(family))) {
        let family = snapshot(stats, now);
        let weight = (family.useful_completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0);
        score.reliability = blend(score.reliability, family.reliability, weight);
        score.reliability_upper = blend(score.reliability_upper, family.reliability_upper, weight);
        score.observed_reliability = blend(
            score.observed_reliability,
            family.observed_reliability,
            weight,
        );
        score.completed = score.completed.max(family.completed);
        score.useful_completed = score.useful_completed.max(family.useful_completed);
        score.attempts = score.attempts.max(family.attempts);
        score.hysteresis_completed = if family.completed > 0.0 {
            family.completed
        } else {
            score.hysteresis_completed
        };
        score.performance = prefer_specific(score.performance, family.performance);
        score.failures = score.failures.max(family.failures);
        score.fail_streak = score.fail_streak.max(family.fail_streak);
        score.explore_backed_off |= family.explore_backed_off;
        score.selected_at = score.selected_at.max(family.selected_at);
        score.last_attempt = score.last_attempt.max(family.last_attempt);
        score.degraded_at = score.degraded_at.max(family.degraded_at);
    }
    // Proxy health-family and probe protocol are independent of target family.
    if let Some(stats) = global_stats {
        let probe = &stats.probes[super::evidence::probe_slot(context)];
        score.probe = probe.latency.snapshot(now);
        score.probe_scope = probe.scope;
    }
    if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref())
        && let Some(stats) = inner.exact.peek(&ExactKey {
            group: group.to_string(),
            network: context.network,
            family,
            target: target.clone(),
            node_id,
        })
    {
        score.verification = super::verification::VerificationEvidence::new(stats, now);
        let exact = snapshot(stats, now);
        let weight = (exact.useful_completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0);
        score.reliability = blend(score.reliability, exact.reliability, weight);
        score.reliability_upper = blend(score.reliability_upper, exact.reliability_upper, weight);
        score.observed_reliability = blend(
            score.observed_reliability,
            exact.observed_reliability,
            weight,
        );
        score.completed = score.completed.max(exact.completed);
        score.useful_completed = score.useful_completed.max(exact.useful_completed);
        score.hysteresis_completed = if exact.completed > 0.0 {
            exact.completed
        } else {
            score.hysteresis_completed
        };
        score.target_performance = exact.performance;
        score.failures = score.failures.max(exact.failures);
        score.fail_streak = score.fail_streak.max(exact.fail_streak);
        score.explore_backed_off |= exact.explore_backed_off;
        score.selected_at = score.selected_at.max(exact.selected_at);
        score.degraded_at = score.degraded_at.max(exact.degraded_at);
    }
    if context.target.is_none() {
        score.verification = layer(context.target_family)
            .map(|stats| super::verification::VerificationEvidence::new(stats, now))
            .unwrap_or_default();
    }
    score
}

pub(super) fn snapshot(stats: &Stats, now: Instant) -> ScoreSnapshot {
    let factor = stats
        .updated_at
        .map_or(1.0, |at| evidence_decay(now.saturating_duration_since(at)));
    let (reliability, reliability_upper) = stats.reliability_bounds(factor);
    let failures = stats.useful_failure + stats.setup_failure * 2.0;
    let observations = stats.useful_success + failures;
    ScoreSnapshot {
        attempts: stats.attempts * factor,
        completed: stats.completed() * factor,
        hysteresis_completed: stats.completed() * factor,
        useful_completed: stats.useful_completed() * factor,
        reliability,
        reliability_upper,
        observed_reliability: if observations > 0.0 {
            stats.useful_success / observations
        } else {
            0.5
        },
        performance: stats.performance.snapshot(now),
        warm_setup: stats.warm_setup_ms.snapshot(now),
        failures: (stats.setup_failure + stats.useful_failure) * factor,
        explore_backed_off: stats.explore_not_before.is_some_and(|until| until > now),
        degraded_at: stats
            .degraded_at
            .filter(|at| now.saturating_duration_since(*at) < super::PERFORMANCE_MAX_AGE),
        fail_streak: stats.fail_streak,
        selected_at: stats.selected_at,
        last_attempt: stats.last_attempt,
        ..Default::default()
    }
}

fn blend(base: f64, specific: f64, weight: f64) -> f64 {
    base * (1.0 - weight) + specific * weight
}

fn prefer_specific(
    base: PerformanceSnapshot,
    specific: PerformanceSnapshot,
) -> PerformanceSnapshot {
    let pick = |base: MetricSnapshot, specific: MetricSnapshot| {
        if specific.value.is_some() {
            specific
        } else {
            base
        }
    };
    PerformanceSnapshot {
        setup: pick(base.setup, specific.setup),
        response: pick(base.response, specific.response),
        upload: pick(base.upload, specific.upload),
        download: pick(base.download, specific.download),
    }
}

pub(super) fn performance_baseline(snapshots: &[ScoreSnapshot]) -> PerformanceBaseline {
    let any_healthy = snapshots
        .iter()
        .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
    let healthy =
        |score: &&ScoreSnapshot| !any_healthy || score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE;
    let any_qualified = snapshots
        .iter()
        .filter(healthy)
        .any(|score| score.useful_completed >= PERFORMANCE_VALIDATION_SAMPLES);
    let best_reliability = snapshots
        .iter()
        .filter(healthy)
        .filter(|score| !any_qualified || score.useful_completed >= PERFORMANCE_VALIDATION_SAMPLES)
        .map(|score| score.reliability)
        .fold(0.0, f64::max);
    let best_observed_reliability = snapshots
        .iter()
        .filter(healthy)
        .filter(|score| !any_qualified || score.useful_completed >= PERFORMANCE_VALIDATION_SAMPLES)
        .map(|score| score.observed_reliability)
        .fold(0.0, f64::max);
    let mut baseline = PerformanceBaseline {
        performance: PerformanceSnapshot::default(),
        target_performance: PerformanceSnapshot::default(),
        probe: MetricSnapshot::default(),
        probe_scope: 0,
        warm_setup: MetricSnapshot::default(),
        best_reliability,
        best_observed_reliability,
        any_healthy,
        any_qualified,
    };
    let eligible = |score: &&ScoreSnapshot| normal_eligible(score, baseline);
    baseline.probe_scope = snapshots
        .iter()
        .filter(eligible)
        .find(|score| {
            score.probe.value.is_some()
                && snapshots
                    .iter()
                    .filter(eligible)
                    .filter(|other| {
                        other.probe.value.is_some() && other.probe_scope == score.probe_scope
                    })
                    .take(2)
                    .count()
                    == 2
        })
        .map_or(0, |score| score.probe_scope);
    let metric = |get: fn(&ScoreSnapshot) -> MetricSnapshot, larger: bool, scope: Option<u64>| {
        let mut values = snapshots
            .iter()
            .filter(|score| normal_eligible(score, baseline))
            .filter(|score| scope.is_none_or(|scope| score.probe_scope == scope))
            .filter_map(|score| get(score).value);
        let first = values.next();
        let second = values.next();
        match (first, second) {
            (Some(a), Some(b)) => MetricSnapshot {
                value: Some(values.fold(
                    if larger { a.max(b) } else { a.min(b) },
                    |best, value| {
                        if larger {
                            best.max(value)
                        } else {
                            best.min(value)
                        }
                    },
                )),
                confidence: 1.0,
                observed_at: None,
            },
            _ => MetricSnapshot::default(),
        }
    };
    let performance = PerformanceSnapshot {
        setup: metric(|s| s.performance.setup, false, None),
        response: metric(|s| s.performance.response, false, None),
        upload: metric(|s| s.performance.upload, true, None),
        download: metric(|s| s.performance.download, true, None),
    };
    let target_performance = PerformanceSnapshot {
        setup: metric(|s| s.target_performance.setup, false, None),
        response: metric(|s| s.target_performance.response, false, None),
        upload: metric(|s| s.target_performance.upload, true, None),
        download: metric(|s| s.target_performance.download, true, None),
    };
    let probe = metric(|s| s.probe, false, Some(baseline.probe_scope));
    let warm_setup = metric(|s| s.warm_setup, false, None);
    baseline.performance = performance;
    baseline.target_performance = target_performance;
    baseline.probe = probe;
    baseline.warm_setup = warm_setup;
    baseline
}

fn relative(metric: MetricSnapshot, best: MetricSnapshot, larger: bool) -> Option<f64> {
    match (metric.value, best.value) {
        (Some(value), Some(best)) => Some(if larger {
            (value / best.max(1.0)).clamp(0.0, 1.0)
        } else {
            (best.max(1.0) / value.max(1.0)).clamp(0.0, 1.0)
        }),
        _ => None,
    }
}

fn correction(base: f64, metric: MetricSnapshot, best: MetricSnapshot, larger: bool) -> f64 {
    relative(metric, best, larger).map_or(base, |value| blend(base, value, metric.confidence))
}

fn scoped_correction(
    base: f64,
    aggregate: MetricSnapshot,
    aggregate_best: MetricSnapshot,
    exact: MetricSnapshot,
    exact_best: MetricSnapshot,
    larger: bool,
) -> f64 {
    if relative(exact, exact_best, larger).is_some() {
        correction(base, exact, exact_best, larger)
    } else {
        correction(base, aggregate, aggregate_best, larger)
    }
}

pub(super) fn utility(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> f64 {
    let mut latency = if score.probe_scope == baseline.probe_scope {
        correction(0.0, score.probe, baseline.probe, false)
    } else {
        0.0
    };
    if baseline.probe.value.is_none() {
        if baseline.performance.setup.value.is_none() {
            latency = correction(latency, score.warm_setup, baseline.warm_setup, false);
        }
        latency = scoped_correction(
            latency,
            score.performance.setup,
            baseline.performance.setup,
            score.target_performance.setup,
            baseline.target_performance.setup,
            false,
        );
    }
    latency = scoped_correction(
        latency,
        score.performance.response,
        baseline.performance.response,
        score.target_performance.response,
        baseline.target_performance.response,
        false,
    );
    let upload = scoped_correction(
        0.0,
        score.performance.upload,
        baseline.performance.upload,
        score.target_performance.upload,
        baseline.target_performance.upload,
        true,
    );
    let download = scoped_correction(
        0.0,
        score.performance.download,
        baseline.performance.download,
        score.target_performance.download,
        baseline.target_performance.download,
        true,
    );
    // Uncertainty gates admission, not the payoff: zero observed failures
    // must not reward a thousand samples over twenty forever.
    score.observed_reliability + 0.03 * latency + 0.02 * upload.max(download)
}
