use super::evidence::evidence_decay;
use super::{
    AggregateKey, ExactKey, HoldDecision, MIN_TRAINED_EVIDENCE, PerformanceBaseline,
    RELIABILITY_CLOSE, RankedSelection, SCORE_EXPLORATION_MAX_PERIOD, SCORE_EXPLORATION_MIN_PERIOD,
    SCORE_EXPLORE_BACKOFF_BASE, SCORE_EXPLORE_BACKOFF_MAX, SCORE_FAIL_STREAK_EXCLUDE,
    SCORE_FAILURE_FORGIVENESS_THRESHOLD, SCORE_SWITCH_FULL_EVIDENCE, SCORE_SWITCH_MARGIN,
    ScoreAuthority, ScorePolicyState, ScoreSelectionContext, ScoreSnapshot, SelectionCadenceKey,
    SelectionHistoryKey, SelectionReason, SelectionReasonKey, StateInner, Stats,
};
use honk_config::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Exploration retry delay for a consecutive-failure streak, tracked outside
/// the decaying evidence so a dead leaf is not rediscovered as cold.
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

fn exploration_attempts(score: &ScoreSnapshot) -> f64 {
    if score.targeted {
        score.target_attempts
    } else {
        score.attempts
    }
}

fn exploration_completed(score: &ScoreSnapshot) -> f64 {
    if score.targeted {
        score.target_completed
    } else {
        score.completed
    }
}

impl ScorePolicyState {
    pub(in crate::group) fn rank(
        &self,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        self.rank_at_with_authority(authority, group, context, nodes, Instant::now())
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
        self.rank_at_with_authority(&authority, group, context, nodes, now)
    }

    fn rank_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> usize {
        self.rank_inner(Some(authority), group, context, nodes, now, true)
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
        if nodes.len() < 2 {
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
        let selection_count = if authorized {
            let count = inner
                .selection_counts
                .entry(cadence_key.clone())
                .or_default();
            *count = count.saturating_add(1);
            *count
        } else {
            let count = inner
                .selection_counts
                .get(&cadence_key)
                .copied()
                .unwrap_or(0);
            if apply {
                count.saturating_add(1)
            } else {
                count
            }
        };
        let best = best_index(&snapshots, nodes, selection_count, apply, performance);
        let incumbent = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| score.selected_at != 0)
            .max_by(|(left_index, left), (right_index, right)| {
                left.selected_at
                    .cmp(&right.selected_at)
                    .then_with(|| left_index.cmp(right_index))
            })
            .map(|(index, _)| index);
        let selection = if best.reason.is_exploration() {
            best
        } else {
            match incumbent.filter(|&index| index != best.index) {
                Some(index) => {
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
                None => best,
            }
        };
        if authorized {
            let any_healthy = snapshots
                .iter()
                .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
            let streak_excluded = snapshots
                .iter()
                .filter(|score| any_healthy && score.fail_streak >= SCORE_FAIL_STREAK_EXCLUDE)
                .count() as u64;
            let backed_off = snapshots
                .iter()
                .filter(|score| score.explore_backed_off)
                .count() as u64;
            if streak_excluded > 0 || backed_off > 0 {
                let counts = inner
                    .selection_reasons
                    .entry(SelectionReasonKey::new(group, context.network))
                    .or_default();
                counts.fail_streak_excluded =
                    counts.fail_streak_excluded.saturating_add(streak_excluded);
                counts.explore_backed_off = counts.explore_backed_off.saturating_add(backed_off);
            }
            Self::record_selection_reason(&mut inner, group, context.network, selection);
            Self::record_switch_flap(
                &mut inner,
                &SelectionHistoryKey::new(group, context),
                nodes[selection.index].id,
                selection.reason,
            );
            inner.tick = inner.tick.saturating_add(1);
            let selection_tick = inner.tick;
            mark_selected(
                &mut inner,
                group,
                context,
                nodes[selection.index].id,
                selection_tick,
            );
        }
        selection.index
    }
}

pub(super) fn best_index(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    selection_count: u64,
    explore: bool,
    performance: PerformanceBaseline,
) -> RankedSelection {
    if explore {
        let candidate_count = snapshots.len();
        let target = exploration_target(candidate_count);
        let explored = snapshots
            .iter()
            .filter(|score| exploration_attempts(score) >= MIN_TRAINED_EVIDENCE)
            .count();
        let cold = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| {
                exploration_completed(score) < MIN_TRAINED_EVIDENCE && !score.explore_backed_off
            })
            .min_by(|(left_index, left), (right_index, right)| {
                exploration_attempts(left)
                    .total_cmp(&exploration_attempts(right))
                    .then_with(|| left_index.cmp(right_index))
                    .then_with(|| nodes[*left_index].id.cmp(&nodes[*right_index].id))
            })
            .map(|(index, _)| index);
        let periodic = candidate_count > target
            && selection_count != 0
            && selection_count.is_multiple_of(exploration_period(candidate_count));
        if let Some(index) = cold
            && (explored < target || candidate_count <= target)
        {
            return RankedSelection {
                index,
                reason: SelectionReason::ColdExplore,
            };
        }
        if periodic {
            let incumbent = snapshots
                .iter()
                .enumerate()
                .filter(|(_, score)| score.selected_at != 0)
                .max_by_key(|(_, score)| score.selected_at)
                .map(|(index, _)| index);
            if let Some((index, _)) = snapshots
                .iter()
                .enumerate()
                .filter(|(index, score)| Some(*index) != incumbent && !score.explore_backed_off)
                .max_by(|(left_index, left), (right_index, right)| {
                    left.reliability_upper
                        .total_cmp(&right.reliability_upper)
                        .then_with(|| {
                            exploration_attempts(right).total_cmp(&exploration_attempts(left))
                        })
                        .then_with(|| right_index.cmp(left_index))
                        .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
                })
            {
                return RankedSelection {
                    index,
                    reason: SelectionReason::PeriodicExplore,
                };
            }
        }
    }
    // Fresh consecutive failures outweigh decayed success history.
    let any_healthy = snapshots
        .iter()
        .any(|score| score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE);
    let rankable =
        |score: &&ScoreSnapshot| !any_healthy || score.fail_streak < SCORE_FAIL_STREAK_EXCLUDE;
    let best_reliability = snapshots
        .iter()
        .filter(rankable)
        .map(|score| score.reliability)
        .fold(0.0_f64, f64::max);
    let index = snapshots
        .iter()
        .enumerate()
        .filter(|(_, score)| {
            rankable(score) && best_reliability - score.reliability <= RELIABILITY_CLOSE
        })
        .max_by(|(left_index, left), (right_index, right)| {
            utility(left, performance)
                .total_cmp(&utility(right, performance))
                .then_with(|| right_index.cmp(left_index))
                .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
        })
        .map(|(index, _)| index)
        .unwrap_or(0);
    let reason = if snapshots
        .iter()
        .enumerate()
        .filter(|(candidate, _)| *candidate != index)
        .all(|(_, alternative)| {
            snapshots[index].reliability - alternative.reliability > RELIABILITY_CLOSE
        }) {
        SelectionReason::ReliabilityWinner
    } else {
        SelectionReason::PerformanceWinner
    };
    RankedSelection { index, reason }
}

pub(super) fn switch_margin(completed: f64) -> f64 {
    SCORE_SWITCH_MARGIN * (completed / SCORE_SWITCH_FULL_EVIDENCE).clamp(0.0, 1.0)
}

pub(super) fn hold_decision(
    incumbent: &ScoreSnapshot,
    best: &ScoreSnapshot,
    performance: PerformanceBaseline,
) -> HoldDecision {
    let trained =
        incumbent.completed >= MIN_TRAINED_EVIDENCE && best.completed >= MIN_TRAINED_EVIDENCE;
    let margin = switch_margin(incumbent.hysteresis_completed);
    let within_switch_margin =
        utility(best, performance) - utility(incumbent, performance) < margin;
    if !trained || !within_switch_margin {
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
        // A full cache means this put evicts the LRU tail.
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
    let family_score = context.target_family.and_then(|family| {
        inner
            .aggregate
            .peek(&AggregateKey {
                group: group.to_string(),
                network: context.network,
                family: Some(family),
                node_id,
            })
            .map(|stats| snapshot(stats, now))
    });
    let global_score = inner
        .aggregate
        .peek(&AggregateKey {
            group: group.to_string(),
            network: context.network,
            family: None,
            node_id,
        })
        .map_or_else(
            || snapshot(&Stats::default(), now),
            |stats| snapshot(stats, now),
        );
    let aggregate_score = family_score.map_or(global_score, |family| {
        let reliability_weight = (family.useful_completed / 8.0).clamp(0.0, 1.0);
        let setup_weight = (family.completed / 8.0).clamp(0.0, 1.0);
        ScoreSnapshot {
            attempts: family.attempts,
            completed: global_score.completed + family.completed,
            hysteresis_completed: if family.completed > 0.0 {
                family.hysteresis_completed
            } else {
                global_score.hysteresis_completed
            },
            useful_completed: global_score.useful_completed + family.useful_completed,
            reliability: blend(
                global_score.reliability,
                family.reliability,
                reliability_weight,
            ),
            reliability_upper: blend(
                global_score.reliability_upper,
                family.reliability_upper,
                reliability_weight,
            ),
            latency_ms: blend_option(global_score.latency_ms, family.latency_ms, setup_weight),
            latency_confidence: blend(
                global_score.latency_confidence,
                family.latency_confidence,
                setup_weight,
            ),
            throughput: blend_option(
                global_score.throughput,
                family.throughput,
                reliability_weight,
            ),
            throughput_confidence: blend(
                global_score.throughput_confidence,
                family.throughput_confidence,
                reliability_weight,
            ),
            failures: global_score.failures.max(family.failures),
            explore_backed_off: global_score.explore_backed_off,
            fail_streak: global_score.fail_streak,
            selected_at: global_score.selected_at.max(family.selected_at),
            targeted: false,
            target_attempts: 0.0,
            target_completed: 0.0,
        }
    });
    let exact_score = match (context.target_family, context.target.as_ref()) {
        (Some(family), Some(target)) => inner
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| snapshot(stats, now)),
        _ => None,
    };
    let Some(exact) = exact_score else {
        return aggregate_score;
    };
    let reliability_weight = (exact.useful_completed / 8.0).clamp(0.0, 1.0);
    let setup_weight = (exact.completed / 8.0).clamp(0.0, 1.0);
    ScoreSnapshot {
        attempts: exact.attempts,
        completed: aggregate_score.completed + exact.completed,
        hysteresis_completed: if exact.completed > 0.0 {
            exact.hysteresis_completed
        } else {
            aggregate_score.hysteresis_completed
        },
        useful_completed: aggregate_score.useful_completed + exact.useful_completed,
        reliability: blend(
            aggregate_score.reliability,
            exact.reliability,
            reliability_weight,
        ),
        reliability_upper: blend(
            aggregate_score.reliability_upper,
            exact.reliability_upper,
            reliability_weight,
        ),
        latency_ms: blend_option(aggregate_score.latency_ms, exact.latency_ms, setup_weight),
        latency_confidence: blend(
            aggregate_score.latency_confidence,
            exact.latency_confidence,
            setup_weight,
        ),
        throughput: blend_option(
            aggregate_score.throughput,
            exact.throughput,
            reliability_weight,
        ),
        throughput_confidence: blend(
            aggregate_score.throughput_confidence,
            exact.throughput_confidence,
            reliability_weight,
        ),
        failures: aggregate_score.failures.max(exact.failures),
        explore_backed_off: aggregate_score.explore_backed_off,
        fail_streak: aggregate_score.fail_streak,
        selected_at: aggregate_score.selected_at.max(exact.selected_at),
        targeted: exact.completed >= MIN_TRAINED_EVIDENCE
            || aggregate_score.completed < MIN_TRAINED_EVIDENCE,
        target_attempts: exact.attempts,
        target_completed: exact.completed,
    }
}
pub(super) fn snapshot(stats: &Stats, now: Instant) -> ScoreSnapshot {
    let factor = stats.updated_at.map_or(1.0, |updated_at| {
        evidence_decay(now.saturating_duration_since(updated_at))
    });
    let (latency_ms, latency_weight) = stats
        .first_response_ms
        .mean()
        .map(|mean| (Some(mean), stats.first_response_ms.weight))
        .unwrap_or_else(|| (stats.setup_ms.mean(), stats.setup_ms.weight));
    // Dominant-direction bytes per second; utility normalizes this within the group.
    let throughput =
        (stats.throughput_seconds > 0.0).then(|| stats.throughput_bytes / stats.throughput_seconds);
    let (reliability, reliability_upper) = stats.reliability_bounds(factor);
    ScoreSnapshot {
        attempts: stats.attempts * factor,
        completed: stats.completed() * factor,
        hysteresis_completed: stats.completed() * factor,
        useful_completed: stats.useful_completed() * factor,
        reliability,
        reliability_upper,
        latency_ms,
        latency_confidence: (latency_weight * factor / 8.0).clamp(0.0, 1.0),
        throughput,
        throughput_confidence: (stats.throughput_windows * factor / 8.0).clamp(0.0, 1.0),
        failures: (stats.setup_failure + stats.useful_failure) * factor,
        explore_backed_off: stats.explore_not_before.is_some_and(|until| until > now),
        fail_streak: stats.fail_streak,
        selected_at: stats.selected_at,
        targeted: false,
        target_attempts: 0.0,
        target_completed: 0.0,
    }
}
fn blend(base: f64, exact: f64, exact_weight: f64) -> f64 {
    base * (1.0 - exact_weight) + exact * exact_weight
}

fn blend_option(base: Option<f64>, exact: Option<f64>, exact_weight: f64) -> Option<f64> {
    match (base, exact) {
        (Some(base), Some(exact)) => Some(blend(base, exact, exact_weight)),
        (None, exact) => exact,
        (base, None) => base,
    }
}

pub(super) fn performance_baseline(snapshots: &[ScoreSnapshot]) -> PerformanceBaseline {
    let best_reliability = snapshots
        .iter()
        .map(|score| score.reliability)
        .fold(0.0_f64, f64::max);
    let eligible = || {
        snapshots
            .iter()
            .filter(|score| best_reliability - score.reliability <= RELIABILITY_CLOSE)
    };
    PerformanceBaseline {
        latency_ms: eligible()
            .filter_map(|score| score.latency_ms)
            .map(|latency| latency.max(1.0))
            .min_by(f64::total_cmp),
        throughput: eligible()
            .filter_map(|score| score.throughput)
            .max_by(f64::total_cmp),
    }
}

pub(super) fn utility(score: &ScoreSnapshot, baseline: PerformanceBaseline) -> f64 {
    let latency_penalty = match (score.latency_ms, baseline.latency_ms) {
        (Some(latency), Some(best)) => {
            (1.0 - best / latency.max(1.0)).clamp(0.0, 1.0) * 0.03 * score.latency_confidence
        }
        _ => 0.0,
    };
    let throughput_bonus = match (score.throughput, baseline.throughput) {
        (Some(throughput), Some(best)) if best > 0.0 => {
            (throughput / best).clamp(0.0, 1.0) * 0.02 * score.throughput_confidence
        }
        _ => 0.0,
    };
    score.reliability + throughput_bonus - latency_penalty
}
