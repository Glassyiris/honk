//! Group claim derivation: each member's open question, the blockers it implies, and what the
//! current evidence supports until its weakest consulted metric expires.
use super::super::comparison::{Basis, Summary};
use super::super::ranking::Decision;
use super::*;

fn qualified(metric: Option<TimedMetric>) -> bool {
    metric.is_some_and(|metric| f64::from(metric.reporters) >= PERFORMANCE_VALIDATION_SAMPLES)
}

pub(in crate::group::score) fn usable(evidence: &VerificationEvidence) -> bool {
    qualified(evidence.business)
}

/// When decayed completions fall below qualification; `None` if they already have.
fn completion_lapse(useful_completed: f64, now: Instant) -> Option<Instant> {
    (useful_completed >= PERFORMANCE_VALIDATION_SAMPLES).then(|| {
        now + SCORE_EVIDENCE_HALF_LIFE
            .mul_f64((useful_completed / PERFORMANCE_VALIDATION_SAMPLES).log2())
    })
}

/// When decay and lease expiry together end a snapshot's qualification.
fn qualification_lapse(score: &ScoreSnapshot, now: Instant) -> Option<Instant> {
    completion_lapse(score.useful_completed, now).max(score.qualified_until)
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
pub(in crate::group::score) struct CandidateQuestion {
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

pub(super) fn milliseconds(duration: Duration) -> u64 {
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

pub(in crate::group::score) fn startup_index(decision: &Decision) -> Option<usize> {
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

/// Which response metric a claim reads: configured probes stand in only for targetless claims whose
/// comparison has no business response basis.
#[derive(Clone, Copy)]
struct Responses<'a> {
    evidence: &'a [VerificationEvidence],
    probe: bool,
}

impl<'a> Responses<'a> {
    fn new(decision: &'a Decision, context: &ScoreSelectionContext, summary: &Summary) -> Self {
        let probe = context.target.is_none()
            && match summary.basis {
                Basis::ConfiguredProbe => true,
                Basis::None => qualified(decision.evidence[decision.ordinary.index].probe),
                Basis::ExactTarget | Basis::CommonTargets => false,
            };
        Self {
            evidence: &decision.evidence,
            probe,
        }
    }

    fn get(self, index: usize) -> Option<TimedMetric> {
        if self.probe {
            self.evidence[index].probe
        } else {
            self.evidence[index].response
        }
    }
}

/// One member's open question and why its response evidence cannot yet support a claim.
fn candidate_question(
    decision: &Decision,
    context: &ScoreSelectionContext,
    summary: &Summary,
    responses: Responses<'_>,
    index: usize,
    now: Instant,
) -> CandidateQuestion {
    let snapshots = &decision.scores;
    let evidence = &decision.evidence;
    let selected = decision.ordinary.index;
    let winner = &snapshots[selected];
    let score = &snapshots[index];
    let excluded = super::comparison::failure_excluded(decision, index, now);
    let pair = decision.pairs.summary_pair(index);
    let paired_at = if context.target.is_none() && !responses.probe {
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
    let response_gap = if !qualified(responses.get(index)) && paired_at.is_none() {
        ResponseGap::Missing
    } else if pair.is_some_and(|pair| pair.partial || pair.response.is_none()) {
        ResponseGap::Unpaired
    } else if !responses.probe && availability_missing {
        ResponseGap::Availability
    } else if responses.probe && score.probe_scope != winner.probe_scope {
        ResponseGap::ProbeScope
    } else if winner.degraded_at.is_some_and(|at| {
        responses
            .get(index)
            .map(|metric| metric.latest_at)
            .or(paired_at)
            .is_none_or(|seen| seen < at)
    }) {
        ResponseGap::Degraded
    } else if summary.response_misaligned
        && !excluded
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
    } else if decision.baseline.any_qualified && !score.qualified() {
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
        ScoreEvidenceQuestion::Response => responses
            .get(index)
            .map_or(0.0, |metric| f64::from(metric.reporters)),
        ScoreEvidenceQuestion::Qualification => score.useful_completed,
        _ => PERFORMANCE_VALIDATION_SAMPLES,
    };
    CandidateQuestion {
        question,
        required: (PERFORMANCE_VALIDATION_SAMPLES - supported)
            .ceil()
            .clamp(1.0, 4.0) as usize,
        excluded,
        dominated: super::comparison::dominated(winner, score, decision.baseline),
        evaluated: decision.membership.evaluated[index],
        covered: decision.membership.covered[index],
        backed_off: score.explore_backed_off,
        availability_missing,
        response_gap,
    }
}

fn blockers(decision: &Decision, candidates: &[CandidateQuestion]) -> ScoreVerificationBlockers {
    let mut blockers = ScoreVerificationBlockers::default();
    for (candidate, score) in candidates.iter().zip(&decision.scores) {
        if !candidate.covered {
            continue;
        }
        blockers.node_failure += usize::from(score.node_failure);
        blockers.target_failure += usize::from(score.target_failure);
        if candidate.settled() {
            blockers.excluded += 1;
            continue;
        }
        blockers.recovery += usize::from(candidate.question == ScoreEvidenceQuestion::Recovery);
        blockers.backoff += usize::from(candidate.backed_off && candidate.pending());
        blockers.qualification +=
            usize::from(decision.baseline.any_qualified && !score.qualified());
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
    blockers
}

fn evidence_basis(
    summary: &Summary,
    responses: Responses<'_>,
    selected: usize,
) -> ScoreEvidenceBasis {
    match summary.basis {
        Basis::ExactTarget => ScoreEvidenceBasis::TargetResponse,
        Basis::CommonTargets => ScoreEvidenceBasis::CommonTargets,
        Basis::ConfiguredProbe => ScoreEvidenceBasis::ConfiguredProbe,
        Basis::None if responses.probe => ScoreEvidenceBasis::ConfiguredProbe,
        Basis::None if qualified(responses.get(selected)) => ScoreEvidenceBasis::TargetResponse,
        Basis::None => ScoreEvidenceBasis::None,
    }
}

fn local_comparison(
    summary: &Summary,
    basis: ScoreEvidenceBasis,
    now: Instant,
) -> ScoreLocalComparison {
    ScoreLocalComparison {
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
        evidence_age_ms: summary
            .oldest_at
            .map(|at| milliseconds(now.saturating_duration_since(at))),
        valid_for_ms: summary
            .expires_at
            .map(|at| milliseconds(at.saturating_duration_since(now))),
        dispersion_ppm: (summary.dispersion * 1_000_000.0).clamp(0.0, u64::MAX as f64) as u64,
        upload_known: summary.upload_known,
        download_known: summary.download_known,
        directional_tradeoff: summary.directional_tradeoff,
    }
}

/// What the whole group may claim now, which evidence it rests on, and when it expires.
struct Claim {
    comparison: ScoreComparison,
    has_transfer: bool,
    claims: u8,
    oldest: Option<Instant>,
    expires_at: Option<Instant>,
    support: u64,
}

impl Claim {
    fn new(
        (decision, nodes, context): (&Decision, &[&Node], &ScoreSelectionContext),
        (summary, candidates, responses): (&Summary, &[CandidateQuestion], Responses<'_>),
        (local, basis, missing_response): (ScoreComparison, ScoreEvidenceBasis, bool),
        now: Instant,
    ) -> Self {
        let snapshots = &decision.scores;
        let evidence = &decision.evidence;
        let selected = decision.ordinary.index;
        let winner = &snapshots[selected];
        let complete = summary.complete
            && !missing_response
            && !candidates[selected].excluded
            && (context.target.is_none() || summary.basis == Basis::ExactTarget);
        let comparison = if complete {
            local
        } else {
            ScoreComparison::Unconfirmed
        };
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
            && qualified(responses.get(selected))
        {
            claims |= claim(ScoreEvidenceKind::Response);
            support_metric(responses.get(selected));
        }
        if has_transfer {
            claims |= claim(ScoreEvidenceKind::Transfer);
            for metric in [evidence[selected].upload, evidence[selected].download] {
                if qualified(metric) {
                    support_metric(metric);
                }
            }
        }
        if !responses.probe && (comparison != ScoreComparison::Unconfirmed || has_transfer) {
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
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        nodes[selected].id.hash(&mut hasher);
        for (index, (node, score)) in nodes.iter().zip(snapshots).enumerate() {
            node.id.hash(&mut hasher);
            (candidates[index].covered, candidates[index].settled()).hash(&mut hasher);
            if responses.probe {
                score.probe_scope.hash(&mut hasher);
            }
        }
        (basis as u8).hash(&mut hasher);
        summary.support.hash(&mut hasher);
        if comparison != ScoreComparison::Unconfirmed || has_transfer {
            if let Some(at) = summary.oldest_at {
                oldest = Some(oldest.map_or(at, |old: Instant| old.min(at)));
            }
            if let Some(until) = summary.expires_at {
                expires_at = Some(expires_at.map_or(until, |old: Instant| old.min(until)));
            }
            for (index, candidate) in candidates.iter().enumerate().filter(|(_, c)| c.covered) {
                let failure = evidence[index]
                    .failed_at
                    .filter(|_| candidate.excluded)
                    .map(|at| at + PERFORMANCE_MAX_AGE);
                let score = &snapshots[index];
                // Dominance needs both sides completion-qualified; a currently qualified member's
                // comparison also ends when it or the winner loses that qualification.
                let lapse = if candidate.dominated {
                    completion_lapse(winner.useful_completed.min(score.useful_completed), now)
                } else if candidate.excluded {
                    None
                } else {
                    qualification_lapse(score, now).map(|until| {
                        qualification_lapse(winner, now).map_or(until, |winner| until.min(winner))
                    })
                };
                if let Some(until) = failure.max(lapse) {
                    expires_at = Some(expires_at.map_or(until, |old| old.min(until)));
                }
            }
        }
        Self {
            comparison,
            has_transfer,
            claims,
            oldest,
            expires_at,
            support: hasher.finish(),
        }
    }
}

/// The member optional validation should serve next, if any is actionable.
fn validation_index(
    decision: &Decision,
    nodes: &[&Node],
    candidates: &[CandidateQuestion],
    focused: Option<Uuid>,
) -> Option<usize> {
    let selected = decision.ordinary.index;
    decision
        .scores
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != selected && candidates[*index].actionable())
        .min_by(|(left_index, left), (right_index, right)| {
            // A short run resolves one real question; no-progress/cancelled work
            // rotates by recency instead of pinning that run indefinitely.
            let focus = |index: usize| {
                focused == Some(nodes[index].id) && decision.evidence[index].business.is_some()
            };
            focus(*right_index)
                .cmp(&focus(*left_index))
                .then_with(|| untried_hint(decision, *left_index, *right_index))
                .then_with(|| left.selected_at.cmp(&right.selected_at))
                .then_with(|| left.last_attempt.cmp(&right.last_attempt))
                .then_with(|| right.reliability_upper.total_cmp(&left.reliability_upper))
                .then_with(|| left_index.cmp(right_index))
        })
        .map(|(index, _)| index)
}

fn next_step(
    candidates: &[CandidateQuestion],
    validation_index: Option<usize>,
    has_transfer: bool,
) -> (
    ScoreValidationAction,
    ScoreEvidenceQuestion,
    ScoreWaitReason,
) {
    let question_index = validation_index
        .or_else(|| candidates.iter().position(CandidateQuestion::actionable))
        .or_else(|| candidates.iter().position(CandidateQuestion::pending));
    if let Some(index) = question_index {
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
    }
}

// These are recent empirical comparisons with a practical tolerance, not a
// confidence sequence or a guarantee about an unobserved future workload.
pub(in crate::group::score) fn evaluate(
    decision: &Decision,
    nodes: &[&Node],
    context: &ScoreSelectionContext,
    cadence: Option<&SelectionCadence>,
    now: Instant,
) -> Evaluation {
    let selected = decision.ordinary.index;
    let evidence = &decision.evidence;
    let summary = super::comparison::summarize(decision, now);
    let responses = Responses::new(decision, context, &summary);
    let candidates: Vec<_> = (0..decision.scores.len())
        .map(|index| candidate_question(decision, context, &summary, responses, index, now))
        .collect();
    let availability = candidates
        .iter()
        .any(|candidate| candidate.open() && candidate.availability_missing);
    let missing_response = candidates
        .iter()
        .any(|candidate| candidate.open() && candidate.response_gap != ResponseGap::None);
    let basis = evidence_basis(&summary, responses, selected);
    let local_comparison = local_comparison(&summary, basis, now);
    let claim = Claim::new(
        (decision, nodes, context),
        (&summary, &candidates, responses),
        (local_comparison.comparison, basis, missing_response),
        now,
    );
    let focused = cadence
        .and_then(|cadence| cadence.run.as_ref())
        .and_then(|run| run.focused(context, now));
    let validation_index = validation_index(decision, nodes, &candidates, focused);
    let (next_action, question, wait_reason) =
        next_step(&candidates, validation_index, claim.has_transfer);
    Evaluation {
        snapshot: ScoreVerificationSnapshot {
            state: if usable(&evidence[selected]) {
                ScoreVerificationState::ObservedUsable
            } else {
                ScoreVerificationState::Provisional
            },
            comparison: claim.comparison,
            basis: summary.advantage_basis.unwrap_or(basis),
            missing: ScoreEvidenceGaps {
                availability,
                response: missing_response,
                transfer: !claim.has_transfer,
            },
            next_action,
            question,
            wait_reason,
            local_comparison,
            candidate_count: decision.scores.len(),
            evaluated_count: candidates
                .iter()
                .filter(|candidate| candidate.evaluated)
                .count(),
            covered_count: candidates
                .iter()
                .filter(|candidate| candidate.covered)
                .count(),
            compared_count: summary
                .compared_candidates
                .max(usize::from(qualified(responses.get(selected)))),
            pending_count: candidates
                .iter()
                .filter(|candidate| candidate.pending())
                .count(),
            blockers: blockers(decision, &candidates),
            target_limited: summary.target_limited,
            evidence_age_ms: claim
                .oldest
                .map(|at| milliseconds(now.saturating_duration_since(at))),
            valid_for_ms: claim
                .expires_at
                .map(|at| milliseconds(at.saturating_duration_since(now))),
            network: context.network,
            target_family: context.target_family,
            health_family: context.health_family,
            target_specific: context.target.is_some(),
        },
        validation_index,
        candidates,
        claims: claim.claims,
        support: claim.support,
        expires_at: claim.expires_at,
    }
}
