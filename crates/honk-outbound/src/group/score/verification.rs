use super::ranking::{Decision, decision};
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreComparison {
    #[default]
    Unconfirmed,
    Equivalent,
    Supported,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreEvidenceBasis {
    #[default]
    None,
    ConfiguredProbe,
    TargetResponse,
    CommonTargets,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreEvidenceQuestion {
    #[default]
    None,
    Availability,
    Response,
    Qualification,
    Recovery,
    Transfer,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreWaitReason {
    #[default]
    None,
    Budget,
    ComparableTraffic,
    InFlight,
    Transfer,
    Backoff,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreTrialSource {
    #[default]
    None,
    Cold,
    Periodic,
    Recovery,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoreLocalComparison {
    pub comparison: ScoreComparison,
    pub basis: ScoreEvidenceBasis,
    pub compared_candidates: usize,
    pub reporter_count: usize,
    pub span_ms: u64,
    pub evidence_age_ms: Option<u64>,
    pub valid_for_ms: Option<u64>,
    pub dispersion_ppm: u64,
    pub upload_known: bool,
    pub download_known: bool,
    pub directional_tradeoff: bool,
}

/// Counts of current candidate blockers, not cumulative failures or dispatched work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoreVerificationBlockers {
    pub recovery: usize,
    pub backoff: usize,
    pub qualification: usize,
    pub availability: usize,
    pub response_missing: usize,
    pub response_unpaired: usize,
    pub response_misaligned: usize,
    pub probe_scope: usize,
    pub response_degraded: usize,
    pub node_failure: usize,
    pub target_failure: usize,
    pub excluded: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScoreVerificationSnapshot {
    pub state: ScoreVerificationState,
    pub comparison: ScoreComparison,
    pub basis: ScoreEvidenceBasis,
    pub missing: ScoreEvidenceGaps,
    pub next_action: ScoreValidationAction,
    pub question: ScoreEvidenceQuestion,
    pub wait_reason: ScoreWaitReason,
    pub local_comparison: ScoreLocalComparison,
    pub candidate_count: usize,
    /// Members receiving comparisons; smaller than `candidate_count` when the claim is bounded.
    pub evaluated_count: usize,
    pub compared_count: usize,
    pub pending_count: usize,
    pub blockers: ScoreVerificationBlockers,
    pub target_limited: bool,
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

#[derive(Clone, Copy)]
pub(super) struct TimedMetric {
    pub value: f64,
    pub reporters: u8,
    pub observed_at: Instant,
    pub latest_at: Instant,
    pub expires_at: Instant,
}

#[derive(Clone, Copy, Default)]
pub(super) struct VerificationEvidence {
    pub business: Option<TimedMetric>,
    pub response: Option<TimedMetric>,
    pub upload: Option<TimedMetric>,
    pub download: Option<TimedMetric>,
    pub probe: Option<TimedMetric>,
    pub failed_at: Option<Instant>,
}

impl VerificationEvidence {
    pub(super) fn new(stats: &Stats, now: Instant) -> Self {
        let availability = &stats.availability;
        Self {
            business: availability
                .latest_rx_at
                .filter(|at| {
                    *at <= now && now < *at + LIVE_QUALIFICATION_TTL && availability.reporters > 0
                })
                .map(|observed_at| TimedMetric {
                    value: 1.0,
                    reporters: availability.reporters,
                    observed_at,
                    latest_at: observed_at,
                    expires_at: observed_at + LIVE_QUALIFICATION_TTL,
                }),
            failed_at: stats.failed_at,
            ..Self::default()
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
    pub candidates: Vec<CandidateQuestion>,
    claims: u8,
    support: u64,
    expires_at: Option<Instant>,
}

fn qualified(metric: Option<TimedMetric>) -> bool {
    metric.is_some_and(|metric| f64::from(metric.reporters) >= PERFORMANCE_VALIDATION_SAMPLES)
}

pub(super) fn usable(evidence: &VerificationEvidence) -> bool {
    qualified(evidence.business)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponseGap {
    None,
    Missing,
    Unpaired,
    Availability,
    ProbeScope,
    Degraded,
    Misaligned,
}

#[derive(Clone, Copy)]
pub(super) struct CandidateQuestion {
    pub question: ScoreEvidenceQuestion,
    pub required: usize,
    excluded: bool,
    dominated: bool,
    evaluated: bool,
    covered: bool,
    backed_off: bool,
    availability_missing: bool,
    response_gap: ResponseGap,
}

impl CandidateQuestion {
    fn pending(&self) -> bool {
        self.evaluated
            && !self.excluded
            && !matches!(
                self.question,
                ScoreEvidenceQuestion::None | ScoreEvidenceQuestion::Transfer
            )
    }

    pub fn actionable(&self) -> bool {
        self.pending() && !self.backed_off
    }

    fn settled(&self) -> bool {
        self.excluded || self.dominated
    }

    /// Still owed before a claim over the covered members is complete.
    fn open(&self) -> bool {
        self.covered && !self.settled()
    }

    pub fn needs_alignment(&self) -> bool {
        self.response_gap == ResponseGap::Misaligned
    }
}

fn milliseconds(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn claim(kind: ScoreEvidenceKind) -> u8 {
    1 << kind as u8
}

fn untried_hint(decision: &Decision, left: usize, right: usize) -> std::cmp::Ordering {
    let scores = &decision.scores;
    if scores[left].selected_at != 0 || scores[right].selected_at != 0 {
        return std::cmp::Ordering::Equal;
    }
    let evidence = &decision.evidence;
    let (left_metric, right_metric) =
        if evidence[left].response.is_some() || evidence[right].response.is_some() {
            (evidence[left].response, evidence[right].response)
        } else if scores[left].probe_scope == scores[right].probe_scope {
            (evidence[left].probe, evidence[right].probe)
        } else {
            return std::cmp::Ordering::Equal;
        };
    left_metric
        .map_or(f64::INFINITY, |metric| metric.value)
        .total_cmp(&right_metric.map_or(f64::INFINITY, |metric| metric.value))
}

pub(super) fn startup_index(decision: &Decision) -> Option<usize> {
    (decision.scores.len() > 1)
        .then(|| {
            decision
                .scores
                .iter()
                .enumerate()
                .filter(|(index, score)| {
                    decision.membership.evaluated[*index]
                        && score.completed < MIN_TRAINED_EVIDENCE
                        && !score.explore_backed_off
                })
                .min_by(|(left_index, left), (right_index, right)| {
                    left.attempts
                        .total_cmp(&right.attempts)
                        .then_with(|| untried_hint(decision, *left_index, *right_index))
                        .then_with(|| left.selected_at.cmp(&right.selected_at))
                        .then_with(|| left_index.cmp(right_index))
                })
                .map(|(index, _)| index)
        })
        .flatten()
}

// These are recent empirical comparisons with a practical tolerance, not a
// confidence sequence or a guarantee about an unobserved future workload.
pub(super) fn evaluate(
    decision: &Decision,
    nodes: &[&Node],
    context: &ScoreSelectionContext,
    cadence: Option<&SelectionCadence>,
    now: Instant,
) -> Evaluation {
    let snapshots = &decision.scores;
    let evidence = &decision.evidence;
    let selected = decision.ordinary.index;
    let winner = &snapshots[selected];
    let baseline = decision.baseline;
    let excluded = |index: usize| super::comparison::failure_excluded(decision, index, now);
    let summary = super::comparison::summarize(decision, now);
    let use_probe = context.target.is_none()
        && match summary.basis {
            super::comparison::Basis::ConfiguredProbe => true,
            super::comparison::Basis::None => qualified(evidence[selected].probe),
            super::comparison::Basis::ExactTarget | super::comparison::Basis::CommonTargets => {
                false
            }
        };
    let response = |index: usize| {
        if use_probe {
            evidence[index].probe
        } else {
            evidence[index].response
        }
    };
    let candidates: Vec<_> = snapshots
        .iter()
        .enumerate()
        .map(|(index, score)| {
            let pair = decision.pairs.summary_pair(index);
            let paired_at = if context.target.is_none() && !use_probe {
                pair.and_then(|pair| pair.response)
                    .map(|metric| metric.latest_at)
                    .or_else(|| {
                        (index == selected)
                            .then_some(summary.response_latest_at)
                            .flatten()
                    })
            } else {
                None
            };
            let availability_missing = !usable(&evidence[index]);
            let response_gap = if !qualified(response(index)) && paired_at.is_none() {
                ResponseGap::Missing
            } else if pair.is_some_and(|pair| pair.partial || pair.response.is_none()) {
                ResponseGap::Unpaired
            } else if !use_probe && availability_missing {
                ResponseGap::Availability
            } else if use_probe && score.probe_scope != winner.probe_scope {
                ResponseGap::ProbeScope
            } else if winner.degraded_at.is_some_and(|at| {
                response(index)
                    .map(|metric| metric.latest_at)
                    .or(paired_at)
                    .is_none_or(|seen| seen < at)
            }) {
                ResponseGap::Degraded
            } else if summary.response_misaligned
                && !excluded(index)
                && (index == selected
                    || pair
                        .and_then(|pair| pair.response)
                        .is_some_and(|metric| now < metric.expires_at))
            {
                ResponseGap::Misaligned
            } else {
                ResponseGap::None
            };
            let question = if score.fail_streak > 0 {
                ScoreEvidenceQuestion::Recovery
            } else if availability_missing {
                ScoreEvidenceQuestion::Availability
            } else if response_gap != ResponseGap::None {
                ScoreEvidenceQuestion::Response
            } else if baseline.any_qualified && !score.qualified() {
                ScoreEvidenceQuestion::Qualification
            } else {
                ScoreEvidenceQuestion::None
            };
            let supported = match question {
                ScoreEvidenceQuestion::Availability => evidence[index]
                    .business
                    .map_or(0.0, |metric| f64::from(metric.reporters)),
                ScoreEvidenceQuestion::Response
                    if matches!(
                        response_gap,
                        ResponseGap::Missing
                            | ResponseGap::Unpaired
                            | ResponseGap::ProbeScope
                            | ResponseGap::Misaligned
                    ) =>
                {
                    0.0
                }
                ScoreEvidenceQuestion::Response => {
                    response(index).map_or(0.0, |metric| f64::from(metric.reporters))
                }
                ScoreEvidenceQuestion::Qualification => score.useful_completed,
                _ => PERFORMANCE_VALIDATION_SAMPLES,
            };
            CandidateQuestion {
                question,
                required: (PERFORMANCE_VALIDATION_SAMPLES - supported)
                    .ceil()
                    .clamp(1.0, 4.0) as usize,
                excluded: excluded(index),
                dominated: super::comparison::dominated(winner, score, baseline),
                evaluated: decision.membership.evaluated[index],
                covered: decision.membership.covered[index],
                backed_off: score.explore_backed_off,
                availability_missing,
                response_gap,
            }
        })
        .collect();
    let availability = candidates
        .iter()
        .any(|candidate| candidate.open() && candidate.availability_missing);
    let missing_response = candidates
        .iter()
        .any(|candidate| candidate.open() && candidate.response_gap != ResponseGap::None);
    let pending_count = candidates
        .iter()
        .filter(|candidate| candidate.pending())
        .count();
    let mut blockers = ScoreVerificationBlockers::default();
    for (index, candidate) in candidates.iter().enumerate() {
        if !candidate.covered {
            continue;
        }
        blockers.node_failure += usize::from(snapshots[index].node_failure);
        blockers.target_failure += usize::from(snapshots[index].target_failure);
        if candidate.settled() {
            blockers.excluded += 1;
            continue;
        }
        blockers.recovery += usize::from(candidate.question == ScoreEvidenceQuestion::Recovery);
        blockers.backoff += usize::from(candidate.backed_off && candidate.pending());
        blockers.qualification +=
            usize::from(baseline.any_qualified && !snapshots[index].qualified());
        blockers.availability += usize::from(candidate.availability_missing);
        match candidate.response_gap {
            ResponseGap::Missing => blockers.response_missing += 1,
            ResponseGap::Unpaired => blockers.response_unpaired += 1,
            ResponseGap::Misaligned => blockers.response_misaligned += 1,
            ResponseGap::ProbeScope => blockers.probe_scope += 1,
            ResponseGap::Degraded => blockers.response_degraded += 1,
            ResponseGap::None | ResponseGap::Availability => {}
        }
    }
    let basis = match summary.basis {
        super::comparison::Basis::ExactTarget => ScoreEvidenceBasis::TargetResponse,
        super::comparison::Basis::CommonTargets => ScoreEvidenceBasis::CommonTargets,
        super::comparison::Basis::ConfiguredProbe => ScoreEvidenceBasis::ConfiguredProbe,
        super::comparison::Basis::None if use_probe => ScoreEvidenceBasis::ConfiguredProbe,
        super::comparison::Basis::None if qualified(response(selected)) => {
            ScoreEvidenceBasis::TargetResponse
        }
        super::comparison::Basis::None => ScoreEvidenceBasis::None,
    };
    let local_comparison = ScoreLocalComparison {
        comparison: if summary.equivalent {
            ScoreComparison::Equivalent
        } else if summary.supported {
            ScoreComparison::Supported
        } else {
            ScoreComparison::Unconfirmed
        },
        basis,
        compared_candidates: summary.compared_candidates,
        reporter_count: usize::from(summary.reporters),
        span_ms: summary.span.map_or(0, milliseconds),
        evidence_age_ms: summary.evidence_age.map(milliseconds),
        valid_for_ms: summary.valid_for.map(milliseconds),
        dispersion_ppm: (summary.dispersion * 1_000_000.0).clamp(0.0, u64::MAX as f64) as u64,
        upload_known: summary.upload_known,
        download_known: summary.download_known,
        directional_tradeoff: summary.directional_tradeoff,
    };
    let complete = summary.complete
        && !missing_response
        && !candidates[selected].excluded
        && (context.target.is_none() || summary.basis == super::comparison::Basis::ExactTarget);
    let comparison = if complete {
        local_comparison.comparison
    } else {
        ScoreComparison::Unconfirmed
    };
    let compared_count = summary
        .compared_candidates
        .max(usize::from(qualified(response(selected))));
    let has_transfer = if snapshots.len() == 1 {
        usable(&evidence[selected])
            && (qualified(evidence[selected].upload) || qualified(evidence[selected].download))
    } else {
        complete && (summary.upload_known || summary.download_known)
    };
    let mut oldest = None;
    let mut expires_at = None;
    let mut support_metric = |metric: Option<TimedMetric>| {
        if let Some(metric) = metric {
            oldest = Some(oldest.map_or(metric.observed_at, |old: Instant| {
                old.min(metric.observed_at)
            }));
            expires_at = Some(
                expires_at.map_or(metric.expires_at, |old: Instant| old.min(metric.expires_at)),
            );
        }
    };
    let mut claims = 0;
    if usable(&evidence[selected]) {
        claims |= claim(ScoreEvidenceKind::Availability);
        support_metric(evidence[selected].business);
    }
    if !candidates[selected].excluded
        && candidates[selected].response_gap == ResponseGap::None
        && qualified(response(selected))
    {
        claims |= claim(ScoreEvidenceKind::Response);
        support_metric(response(selected));
    }
    if has_transfer {
        claims |= claim(ScoreEvidenceKind::Transfer);
        for metric in [evidence[selected].upload, evidence[selected].download] {
            if qualified(metric) {
                support_metric(metric);
            }
        }
    }
    if !use_probe && (comparison != ScoreComparison::Unconfirmed || has_transfer) {
        for (_, evidence) in evidence
            .iter()
            .enumerate()
            .filter(|(index, _)| candidates[*index].open())
        {
            support_metric(evidence.business);
        }
    }
    if comparison != ScoreComparison::Unconfirmed {
        claims |= claim(ScoreEvidenceKind::Response);
    }
    if comparison != ScoreComparison::Unconfirmed || has_transfer {
        if let Some(age) = summary.evidence_age {
            let at = now.checked_sub(age).unwrap_or(now);
            oldest = Some(oldest.map_or(at, |old: Instant| old.min(at)));
        }
        if let Some(valid_for) = summary.valid_for {
            let until = now + valid_for;
            expires_at = Some(expires_at.map_or(until, |old: Instant| old.min(until)));
        }
    }
    let focused = cadence
        .and_then(|cadence| cadence.run.as_ref())
        .and_then(|run| run.focused(context, now));
    let validation_index = snapshots
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != selected && candidates[*index].actionable())
        .min_by(|(left_index, left), (right_index, right)| {
            // A short run resolves one real question; no-progress/cancelled work
            // rotates by recency instead of pinning that run indefinitely.
            let focus = |index: usize| {
                focused == Some(nodes[index].id) && evidence[index].business.is_some()
            };
            focus(*right_index)
                .cmp(&focus(*left_index))
                .then_with(|| untried_hint(decision, *left_index, *right_index))
                .then_with(|| left.selected_at.cmp(&right.selected_at))
                .then_with(|| left.last_attempt.cmp(&right.last_attempt))
                .then_with(|| right.reliability_upper.total_cmp(&left.reliability_upper))
                .then_with(|| left_index.cmp(right_index))
        })
        .map(|(index, _)| index);
    let question_index = validation_index
        .or_else(|| candidates.iter().position(CandidateQuestion::actionable))
        .or_else(|| candidates.iter().position(CandidateQuestion::pending));
    let (next_action, question, wait_reason) = if let Some(index) = question_index {
        let candidate = candidates[index];
        if candidate.backed_off {
            (
                ScoreValidationAction::Backoff,
                candidate.question,
                ScoreWaitReason::Backoff,
            )
        } else {
            (
                ScoreValidationAction::NextBusinessFlow,
                candidate.question,
                ScoreWaitReason::ComparableTraffic,
            )
        }
    } else if !has_transfer {
        (
            ScoreValidationAction::AwaitTransfer,
            ScoreEvidenceQuestion::Transfer,
            ScoreWaitReason::Transfer,
        )
    } else {
        (
            ScoreValidationAction::None,
            ScoreEvidenceQuestion::None,
            ScoreWaitReason::None,
        )
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    nodes[selected].id.hash(&mut hasher);
    for (index, (node, score)) in nodes.iter().zip(snapshots).enumerate() {
        node.id.hash(&mut hasher);
        (candidates[index].covered, candidates[index].settled()).hash(&mut hasher);
        if use_probe {
            score.probe_scope.hash(&mut hasher);
        }
    }
    (basis as u8).hash(&mut hasher);
    summary.support.hash(&mut hasher);
    if comparison != ScoreComparison::Unconfirmed || has_transfer {
        for (index, candidate) in candidates.iter().enumerate().filter(|(_, c)| c.covered) {
            let failure = evidence[index]
                .failed_at
                .filter(|_| candidate.excluded)
                .map(|at| at + PERFORMANCE_MAX_AGE);
            // Dominance holds only while both sides remain completion-qualified.
            let dominance = candidate.dominated.then(|| {
                let lapse = winner
                    .useful_completed
                    .min(snapshots[index].useful_completed)
                    / PERFORMANCE_VALIDATION_SAMPLES;
                now + SCORE_EVIDENCE_HALF_LIFE.mul_f64(lapse.log2())
            });
            if let Some(until) = failure.max(dominance) {
                expires_at = Some(expires_at.map_or(until, |old| old.min(until)));
            }
        }
    }
    Evaluation {
        snapshot: ScoreVerificationSnapshot {
            state: if usable(&evidence[selected]) {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            },
            comparison,
            basis: summary.advantage_basis.unwrap_or(basis),
            missing: ScoreEvidenceGaps {
                availability,
                response: missing_response,
                transfer: !has_transfer,
            },
            next_action,
            question,
            wait_reason,
            local_comparison,
            candidate_count: snapshots.len(),
            evaluated_count: candidates
                .iter()
                .filter(|candidate| candidate.evaluated)
                .count(),
            compared_count,
            pending_count,
            blockers,
            target_limited: summary.target_limited,
            evidence_age_ms: oldest.map(|at| milliseconds(now.saturating_duration_since(at))),
            valid_for_ms: expires_at.map(|at| milliseconds(at.saturating_duration_since(now))),
            network: context.network,
            target_family: context.target_family,
            health_family: context.health_family,
            target_specific: context.target.is_some(),
        },
        validation_index,
        candidates,
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
        let decision = decision(&inner, group, context, nodes, now);
        let mut evaluation = evaluate(
            &decision,
            nodes,
            context,
            inner
                .selection_counts
                .get(&SelectionCadenceKey::new(group, context)),
            now,
        );
        super::validation::apply_budget_wait(
            &inner,
            group,
            context,
            nodes,
            decision.ordinary.index,
            now,
            &mut evaluation,
        );
        Some((decision.ordinary.index, evaluation.snapshot))
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
