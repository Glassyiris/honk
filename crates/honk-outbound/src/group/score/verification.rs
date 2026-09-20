use super::ranking::{normal_eligible, ordinary_selection, performance_baseline, score_snapshot};
use super::*;
use honk_config::node::Node;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoreEvidenceKind {
    Availability,
    Response,
    Transfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreVerificationState {
    Provisional,
    ObservedUsable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreComparison {
    Unconfirmed,
    Equivalent,
    Supported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreEvidenceBasis {
    None,
    ConfiguredProbe,
    TargetResponse,
    AggregateResponse,
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoreEvidenceGaps {
    pub availability: bool,
    pub response: bool,
    pub transfer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreValidationAction {
    None,
    NextBusinessFlow,
    AwaitTransfer,
    Backoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoreVerificationSnapshot {
    pub state: ScoreVerificationState,
    pub comparison: ScoreComparison,
    pub basis: ScoreEvidenceBasis,
    pub missing: ScoreEvidenceGaps,
    pub next_action: ScoreValidationAction,
    pub candidate_count: usize,
    pub compared_count: usize,
    pub pending_count: usize,
    pub evidence_age_ms: Option<u64>,
    pub valid_for_ms: Option<u64>,
    pub health_family: IpVersion,
    pub network: SelectionNetwork,
    pub target_family: Option<IpVersion>,
    pub target_specific: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoreVerificationCounters {
    pub provisional_selections: u64,
    pub usable_selections: u64,
    pub validation_selections: u64,
    pub confirmations: u64,
    pub expired: u64,
    pub contradicted: u64,
    pub confirmation_millis: u64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct VerificationEvidence {
    pub business: MetricSnapshot,
    pub performance: PerformanceSnapshot,
    pub failed_at: Option<Instant>,
}

impl VerificationEvidence {
    pub(super) fn new(stats: &Stats, now: Instant) -> Self {
        Self {
            business: stats.availability.snapshot(now),
            performance: stats.performance.snapshot(now),
            failed_at: stats.failed_at,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct VerificationHistory {
    started_at: Instant,
    pub(super) claims: u8,
    comparison: ScoreComparison,
    support: u64,
    expires_at: Option<Instant>,
}

pub(super) struct Evaluation {
    pub snapshot: ScoreVerificationSnapshot,
    pub validation_index: Option<usize>,
    claims: u8,
    support: u64,
    expires_at: Option<Instant>,
}

fn qualified(metric: MetricSnapshot) -> bool {
    metric.value.is_some() && metric.confidence >= 1.0
}

pub(super) fn usable(score: &ScoreSnapshot) -> bool {
    qualified(score.verification.business)
}

fn milliseconds(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn claim(kind: ScoreEvidenceKind) -> u8 {
    1 << kind as u8
}

pub(super) fn untried_hint(left: &ScoreSnapshot, right: &ScoreSnapshot) -> std::cmp::Ordering {
    if left.selected_at != 0 || right.selected_at != 0 {
        return std::cmp::Ordering::Equal;
    }
    let (left_metric, right_metric) = if left.verification.performance.response.value.is_some()
        || right.verification.performance.response.value.is_some()
    {
        (
            left.verification.performance.response,
            right.verification.performance.response,
        )
    } else if left.probe_scope == right.probe_scope {
        (left.probe, right.probe)
    } else {
        return std::cmp::Ordering::Equal;
    };
    left_metric
        .value
        .unwrap_or(f64::INFINITY)
        .total_cmp(&right_metric.value.unwrap_or(f64::INFINITY))
}

// These are recent empirical comparisons with a practical tolerance, not a
// confidence sequence or a guarantee about an unobserved future workload.
pub(super) fn evaluate(
    snapshots: &[ScoreSnapshot],
    nodes: &[&Node],
    selected: usize,
    context: &ScoreSelectionContext,
    cadence: Option<&SelectionCadence>,
    baseline: PerformanceBaseline,
    now: Instant,
) -> Evaluation {
    let winner = &snapshots[selected];
    let excluded = |score: &ScoreSnapshot| {
        !normal_eligible(score, baseline)
            && score
                .verification
                .failed_at
                .is_some_and(|at| now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE)
    };
    let relevant = |score: &&ScoreSnapshot| !excluded(score);
    let coverage = snapshots.iter().filter(relevant).count();
    let business_response = snapshots
        .iter()
        .filter(relevant)
        .all(|score| usable(score) && qualified(score.verification.performance.response));
    let use_probe = !business_response && context.target.is_none() && qualified(winner.probe);
    let response = |score: &ScoreSnapshot| {
        if use_probe {
            score.probe
        } else {
            score.verification.performance.response
        }
    };
    let degraded_at = winner.degraded_at;
    let response_gap = |score: &ScoreSnapshot| {
        !qualified(response(score))
            || (!use_probe && !usable(score))
            || (use_probe && score.probe_scope != winner.probe_scope)
            || degraded_at
                .is_some_and(|at| response(score).observed_at.is_none_or(|seen| seen < at))
    };
    // Live availability can precede the qualification needed to compete with trained candidates.
    let gap = |score: &ScoreSnapshot| {
        !excluded(score)
            && (!usable(score)
                || response_gap(score)
                || score.fail_streak > 0
                || (baseline.any_qualified && !score.qualified()))
    };
    let availability = snapshots
        .iter()
        .filter(relevant)
        .any(|score| !usable(score));
    let missing_response = snapshots.iter().filter(relevant).any(response_gap);
    let pending_count = snapshots.iter().filter(|score| gap(score)).count();
    let compared_count = snapshots
        .iter()
        .filter(relevant)
        .filter(|score| {
            qualified(response(score))
                && if use_probe {
                    score.probe_scope == winner.probe_scope
                } else {
                    usable(score)
                }
        })
        .count();
    let complete = coverage >= 2 && !missing_response && !excluded(winner);
    let compare = |metric: &dyn Fn(&ScoreSnapshot) -> MetricSnapshot, larger: bool| {
        let chosen = metric(winner).value.unwrap_or_default().max(1.0);
        let mut min = chosen;
        let mut max = chosen;
        for score in snapshots.iter().filter(relevant) {
            let value = metric(score).value.unwrap_or_default().max(1.0);
            min = min.min(value);
            max = max.max(value);
        }
        if max <= min * (1.0 + PERFORMANCE_SWITCH_MARGIN) {
            ScoreComparison::Equivalent
        } else if (larger && chosen * (1.0 + PERFORMANCE_SWITCH_MARGIN) >= max)
            || (!larger && chosen <= min * (1.0 + PERFORMANCE_SWITCH_MARGIN))
        {
            ScoreComparison::Supported
        } else {
            ScoreComparison::Unconfirmed
        }
    };
    let mut comparison = if complete {
        compare(&response, false)
    } else {
        ScoreComparison::Unconfirmed
    };
    let mut basis = if use_probe {
        ScoreEvidenceBasis::ConfiguredProbe
    } else if winner.verification.performance.response.value.is_some() {
        if context.target.is_some() {
            ScoreEvidenceBasis::TargetResponse
        } else {
            ScoreEvidenceBasis::AggregateResponse
        }
    } else if winner.performance.response.value.is_some() {
        ScoreEvidenceBasis::AggregateResponse
    } else if winner.probe.value.is_some() {
        ScoreEvidenceBasis::ConfiguredProbe
    } else {
        ScoreEvidenceBasis::None
    };
    let direction = |get: fn(&ScoreSnapshot) -> MetricSnapshot| {
        coverage > 0
            && snapshots
                .iter()
                .filter(relevant)
                .all(|score| usable(score) && qualified(get(score)))
    };
    let download = |score: &ScoreSnapshot| score.verification.performance.download;
    let upload = |score: &ScoreSnapshot| score.verification.performance.upload;
    let has_download = direction(download);
    let has_upload = direction(upload);
    let prefer_upload = has_upload
        && (!has_download
            || (compare(&download, true) != ScoreComparison::Supported
                && compare(&upload, true) == ScoreComparison::Supported));
    let transfer_metric: Option<fn(&ScoreSnapshot) -> MetricSnapshot> = if prefer_upload {
        Some(upload)
    } else if has_download {
        Some(download)
    } else {
        None
    };
    if complete
        && comparison != ScoreComparison::Supported
        && let Some(metric) = transfer_metric
        && compare(&metric, true) == ScoreComparison::Supported
    {
        comparison = ScoreComparison::Supported;
        basis = if prefer_upload {
            ScoreEvidenceBasis::Upload
        } else {
            ScoreEvidenceBasis::Download
        };
    }
    let mut oldest = None;
    let mut expires_at = None;
    let mut support_metric = |metric: MetricSnapshot, lifetime: Duration| {
        if let Some(at) = metric.observed_at {
            oldest = Some(oldest.map_or(at, |old: Instant| old.min(at)));
            let until = at + lifetime;
            expires_at = Some(expires_at.map_or(until, |old: Instant| old.min(until)));
        }
    };
    let mut claims = 0;
    if usable(winner) {
        claims |= claim(ScoreEvidenceKind::Availability);
        support_metric(winner.verification.business, LIVE_QUALIFICATION_TTL);
    }
    if !excluded(winner) && !response_gap(winner) {
        claims |= claim(ScoreEvidenceKind::Response);
        support_metric(response(winner), PERFORMANCE_MAX_AGE / 2);
    }
    if comparison != ScoreComparison::Unconfirmed {
        claims |= claim(ScoreEvidenceKind::Response);
        for score in snapshots.iter().filter(relevant) {
            support_metric(response(score), PERFORMANCE_MAX_AGE / 2);
            if !use_probe {
                support_metric(score.verification.business, LIVE_QUALIFICATION_TTL);
            }
        }
    }
    if let Some(metric) = transfer_metric {
        claims |= claim(ScoreEvidenceKind::Transfer);
        for score in snapshots.iter().filter(relevant) {
            support_metric(metric(score), PERFORMANCE_MAX_AGE / 2);
            support_metric(score.verification.business, LIVE_QUALIFICATION_TTL);
        }
    }
    let focused = cadence.and_then(|cadence| {
        (cadence.validation_attempts < 8)
            .then_some(cadence.validation_node)
            .flatten()
    });
    let validation_index = snapshots
        .iter()
        .enumerate()
        .filter(|(index, score)| *index != selected && gap(score) && !score.explore_backed_off)
        .min_by(|(left_index, left), (right_index, right)| {
            // A short run resolves one real question; no-progress/cancelled work
            // rotates by recency instead of pinning that run indefinitely.
            let focus = |index: usize, score: &ScoreSnapshot| {
                focused == Some(nodes[index].id) && score.verification.business.value.is_some()
            };
            focus(*right_index, right)
                .cmp(&focus(*left_index, left))
                .then_with(|| untried_hint(left, right))
                .then_with(|| left.selected_at.cmp(&right.selected_at))
                .then_with(|| left.last_attempt.cmp(&right.last_attempt))
                .then_with(|| right.reliability_upper.total_cmp(&left.reliability_upper))
                .then_with(|| left_index.cmp(right_index))
        })
        .map(|(index, _)| index);
    let actionable = snapshots
        .iter()
        .any(|score| gap(score) && !score.explore_backed_off);
    let next_action = if pending_count > 0 {
        if actionable {
            ScoreValidationAction::NextBusinessFlow
        } else {
            ScoreValidationAction::Backoff
        }
    } else if transfer_metric.is_none() {
        ScoreValidationAction::AwaitTransfer
    } else {
        ScoreValidationAction::None
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    nodes[selected].id.hash(&mut hasher);
    for (node, score) in nodes.iter().zip(snapshots) {
        node.id.hash(&mut hasher);
        excluded(score).hash(&mut hasher);
        if use_probe {
            score.probe_scope.hash(&mut hasher);
        }
    }
    (basis as u8).hash(&mut hasher);
    for score in snapshots {
        if (comparison != ScoreComparison::Unconfirmed || transfer_metric.is_some())
            && excluded(score)
            && let Some(at) = score.verification.failed_at
        {
            let until = at + PERFORMANCE_MAX_AGE;
            expires_at = Some(expires_at.map_or(until, |old| old.min(until)));
        }
    }
    Evaluation {
        snapshot: ScoreVerificationSnapshot {
            state: if usable(winner) {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            },
            comparison,
            basis,
            missing: ScoreEvidenceGaps {
                availability,
                response: missing_response,
                transfer: transfer_metric.is_none(),
            },
            next_action,
            candidate_count: snapshots.len(),
            compared_count,
            pending_count,
            evidence_age_ms: oldest.map(|at| milliseconds(now.saturating_duration_since(at))),
            valid_for_ms: expires_at.map(|at| milliseconds(at.saturating_duration_since(now))),
            network: context.network,
            target_family: context.target_family,
            health_family: context.health_family,
            target_specific: context.target.is_some(),
        },
        validation_index,
        claims,
        support: hasher.finish(),
        expires_at,
    }
}

impl ScorePolicyState {
    pub(in crate::group) fn verification_selection(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
    ) -> Option<(usize, ScoreVerificationSnapshot)> {
        self.verification_selection_at(group, context, nodes, Instant::now())
    }

    #[cfg(test)]
    pub(super) fn verification_snapshot_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> Option<ScoreVerificationSnapshot> {
        self.verification_selection_at(group, context, nodes, now)
            .map(|(_, snapshot)| snapshot)
    }

    fn verification_selection_at(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
        nodes: &[&Node],
        now: Instant,
    ) -> Option<(usize, ScoreVerificationSnapshot)> {
        if nodes.is_empty() {
            return None;
        }
        let inner = self.inner.lock();
        let snapshots: Vec<_> = nodes
            .iter()
            .map(|node| score_snapshot(&inner, group, context, node.id, now))
            .collect();
        let incumbent = inner
            .selection_history
            .peek(&SelectionHistoryKey::new(group, context))
            .filter(|history| history.selections > 0)
            .and_then(|history| nodes.iter().position(|node| node.id == history.current));
        let baseline = performance_baseline(&snapshots);
        let selected = ordinary_selection(&snapshots, nodes, incumbent, baseline);
        Some((
            selected.index,
            evaluate(
                &snapshots,
                nodes,
                selected.index,
                context,
                inner
                    .selection_counts
                    .get(&SelectionCadenceKey::new(group, context)),
                baseline,
                now,
            )
            .snapshot,
        ))
    }

    pub(in crate::group) fn verification_counters(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> ScoreVerificationCounters {
        self.inner
            .lock()
            .verification_counters
            .get(&SelectionReasonKey::new(group, network))
            .copied()
            .unwrap_or_default()
    }

    pub(super) fn record_verification(
        inner: &mut StateInner,
        key: &SelectionHistoryKey,
        selected: Uuid,
        selected_usable: bool,
        validation: bool,
        evaluation: &Evaluation,
        now: Instant,
    ) {
        let previous = inner
            .selection_history
            .peek(key)
            .and_then(|history| history.verification);
        let mut started_at = previous.map_or(now, |history| history.started_at);
        let changed_support = previous.is_some_and(|history| history.support != evaluation.support);
        let lost = previous.is_some_and(|history| {
            history.claims != 0
                && (changed_support
                    || history.claims & !evaluation.claims != 0
                    || (history.comparison != ScoreComparison::Unconfirmed
                        && history.comparison != evaluation.snapshot.comparison))
        });
        let gained = evaluation.claims != 0
            && previous.is_none_or(|history| {
                changed_support
                    || evaluation.claims & !history.claims != 0
                    || (evaluation.snapshot.comparison != ScoreComparison::Unconfirmed
                        && history.comparison != evaluation.snapshot.comparison)
            });
        let counts = inner
            .verification_counters
            .entry(SelectionReasonKey::new(&key.group, key.network))
            .or_default();
        let selections = if selected_usable {
            &mut counts.usable_selections
        } else {
            &mut counts.provisional_selections
        };
        *selections = selections.saturating_add(1);
        if validation {
            counts.validation_selections = counts.validation_selections.saturating_add(1);
        }
        if lost {
            let counter = if previous
                .and_then(|history| history.expires_at)
                .is_some_and(|at| now >= at)
            {
                &mut counts.expired
            } else {
                &mut counts.contradicted
            };
            *counter = counter.saturating_add(1);
            started_at = now;
        }
        if gained {
            counts.confirmations = counts.confirmations.saturating_add(1);
            counts.confirmation_millis = counts
                .confirmation_millis
                .saturating_add(milliseconds(now.saturating_duration_since(started_at)));
        }
        let verification = Some(VerificationHistory {
            started_at,
            claims: evaluation.claims,
            comparison: evaluation.snapshot.comparison,
            support: evaluation.support,
            expires_at: evaluation.expires_at,
        });
        if let Some(history) = inner.selection_history.get_mut(key) {
            history.verification = verification;
        } else {
            inner.selection_history.push(
                key.clone(),
                SelectionHistory {
                    current: selected,
                    previous: None,
                    selections: 0,
                    switched_at: 0,
                    verification,
                },
            );
        }
    }
}
