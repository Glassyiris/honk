use super::ranking::decision;
use super::*;
use honk_config::node::Node;
use std::hash::{Hash, Hasher};

mod claim;
use claim::milliseconds;
pub(super) use claim::{CandidateQuestion, evaluate, startup_index, usable};

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
    /// Members a claim covers: the selection plus evaluated members admitted by qualification.
    pub covered_count: usize,
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
        let decision = decision(&inner, group, context, nodes, now, false);
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
