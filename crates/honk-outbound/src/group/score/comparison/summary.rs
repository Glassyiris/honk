use super::super::ranking::{Decision, normal_eligible};
use super::super::{
    PERFORMANCE_MAX_AGE, PERFORMANCE_SWITCH_MARGIN, PERFORMANCE_VALIDATION_SAMPLES,
    PerformanceBaseline, ScoreEvidenceBasis, ScoreSnapshot,
};
use super::{Basis, MetricPair, PairEvidence};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::group::score) struct Summary {
    pub basis: Basis,
    pub advantage_basis: Option<ScoreEvidenceBasis>,
    pub compared_candidates: usize,
    pub complete: bool,
    pub equivalent: bool,
    pub supported: bool,
    pub response_misaligned: bool,
    pub target_limited: bool,
    pub reporters: u8,
    pub span: Option<Duration>,
    pub evidence_age: Option<Duration>,
    pub response_latest_at: Option<Instant>,
    pub valid_for: Option<Duration>,
    pub dispersion: f64,
    pub upload_known: bool,
    pub download_known: bool,
    pub directional_tradeoff: bool,
    pub support: u64,
}

fn reversed(pair: PairEvidence) -> PairEvidence {
    fn reverse(metric: MetricPair) -> MetricPair {
        MetricPair {
            incumbent: metric.candidate,
            candidate: metric.incumbent,
            ..metric
        }
    }
    PairEvidence {
        response: pair.response.map(reverse),
        upload: pair.upload.map(reverse),
        download: pair.download.map(reverse),
        ..pair
    }
}

fn equivalent(left: f64, right: f64) -> bool {
    let low = left.min(right);
    let high = left.max(right);
    // Averaging and unit conversion can round an inclusive boundary by a few ulps.
    high - low <= low * PERFORMANCE_SWITCH_MARGIN + high * f64::EPSILON * 8.0
}

/// Outside the eligibility band, yet completion-qualified with lower observed reliability than a
/// completion-qualified selection, so [`advantage`] can never credit it as a rival. Coverage
/// resolves it among eligible members; its unpaired metrics are not measured as equivalent.
pub(in crate::group::score) fn dominated(
    winner: &ScoreSnapshot,
    candidate: &ScoreSnapshot,
    baseline: PerformanceBaseline,
) -> bool {
    !normal_eligible(candidate, baseline)
        && winner.useful_completed.min(candidate.useful_completed) >= PERFORMANCE_VALIDATION_SAMPLES
        && candidate.observed_reliability < winner.observed_reliability
}

/// A recent failure excludes an ineligible member until its performance evidence expires.
pub(in crate::group::score) fn failure_excluded(
    decision: &Decision,
    index: usize,
    now: Instant,
) -> bool {
    !normal_eligible(&decision.scores[index], decision.baseline)
        && decision.evidence[index]
            .failed_at
            .is_some_and(|at| now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE)
}

fn advantage(
    pair: PairEvidence,
    qualified: (bool, bool),
    reliability: (f64, f64),
) -> (bool, [f64; 2]) {
    let Some(response) = pair.response else {
        return (false, [0.0; 2]);
    };
    let qualified = qualified.0 && qualified.1;
    if qualified && reliability.1 < reliability.0 {
        return (false, [0.0; 2]);
    }
    if !equivalent(response.incumbent, response.candidate) {
        return (response.candidate < response.incumbent, [0.0; 2]);
    }
    if qualified && reliability.1 > reliability.0 {
        return (true, [0.0; 2]);
    }
    if !qualified
        || [pair.upload, pair.download]
            .into_iter()
            .flatten()
            .any(|metric| {
                metric.incumbent - metric.candidate > metric.incumbent * PERFORMANCE_SWITCH_MARGIN
            })
    {
        return (false, [0.0; 2]);
    }
    (
        false,
        [pair.upload, pair.download].map(|metric| {
            metric.map_or(0.0, |metric| {
                let change = metric.candidate - metric.incumbent;
                if change > 0.0 && change >= metric.incumbent * PERFORMANCE_SWITCH_MARGIN {
                    change / metric.candidate
                } else {
                    0.0
                }
            })
        }),
    )
}

pub(in crate::group::score) fn summarize(decision: &Decision, now: Instant) -> Summary {
    let snapshots = &decision.scores;
    let selected = decision.pairs.reference;
    let Some(winner) = snapshots.get(selected) else {
        return Summary::default();
    };
    let mut summary = Summary::default();
    let mut support = std::collections::hash_map::DefaultHasher::new();
    selected.hash(&mut support);
    let baseline = decision.baseline;
    let covered = &decision.membership.covered;
    // The selected member is always covered and needs no pair.
    let mut resolved = 1;
    let mut response_support = None;
    let mut directional_support = [None; 2];
    let mut directional_known = [true; 2];
    let mut ranges: [Option<(f64, f64)>; 3] = [None; 3];
    let mut pairwise_equivalent = true;
    let mut undefeated = true;
    let mut response_advantage = false;
    let mut selected_rates = [0.0_f64; 2];
    let mut rate_nonregression = true;
    let mut all_responses = true;
    let mut oldest: Option<Instant> = None;
    let mut expires: Option<Instant> = None;
    for (index, candidate) in snapshots.iter().enumerate() {
        if index == selected || !decision.membership.evaluated[index] {
            continue;
        }
        if dominated(winner, candidate, baseline) || failure_excluded(decision, index, now) {
            resolved += usize::from(covered[index]);
            continue;
        }
        let Some(pair) = decision.pairs.get(index) else {
            continue;
        };
        if covered[index] && decision.pairs.joint.is_some() {
            let original = PairEvidence {
                response: pair.response.filter(|metric| now < metric.expires_at),
                upload: pair.upload.filter(|metric| now < metric.expires_at),
                download: pair.download.filter(|metric| now < metric.expires_at),
                ..pair
            };
            // Narrowing support cannot erase a qualified defeat on the original pair.
            let (rival_advantage, rates) = advantage(
                original,
                (winner.qualified(), candidate.qualified()),
                (winner.observed_reliability, candidate.observed_reliability),
            );
            undefeated &= !rival_advantage && rates.into_iter().all(|gain| gain <= 0.0);
            for (metric_index, metric) in [original.response, original.upload, original.download]
                .into_iter()
                .enumerate()
            {
                if let Some(metric) = metric {
                    (index, original.basis as u8, metric_index, metric.support).hash(&mut support);
                    oldest = Some(oldest.map_or(metric.oldest_at, |old| old.min(metric.oldest_at)));
                    expires =
                        Some(expires.map_or(metric.expires_at, |old| old.min(metric.expires_at)));
                }
            }
        }
        let pair = decision
            .pairs
            .summary_pair(index)
            .expect("original pair exists");
        let pair = PairEvidence {
            response: pair.response.filter(|metric| now < metric.expires_at),
            upload: pair.upload.filter(|metric| now < metric.expires_at),
            download: pair.download.filter(|metric| now < metric.expires_at),
            ..pair
        };
        // Evaluated members outside coverage (rotation, still qualifying) contribute vetoes and
        // ranges, never coverage or alignment.
        if covered[index] {
            summary.target_limited |= pair.partial;
        }
        let Some(supporting) = [pair.response, pair.upload, pair.download]
            .into_iter()
            .flatten()
            .next()
        else {
            continue;
        };
        if covered[index] {
            all_responses &= pair.response.is_some();
            if let Some(response) = pair.response {
                // Optional pairs cannot lend their target/probe basis to the covered claim.
                if response_support.is_none() {
                    summary.basis = pair.basis;
                }
                let identity = (pair.basis, response.support);
                summary.response_misaligned |= response_support.is_some_and(|old| old != identity);
                response_support = Some(identity);
                summary.response_latest_at = Some(
                    summary
                        .response_latest_at
                        .map_or(response.latest_at, |old| old.min(response.latest_at)),
                );
            }
        }
        if summary.compared_candidates == 0 {
            summary.basis = pair.basis;
            summary.compared_candidates = 1;
            summary.reporters = supporting.reporters;
        }
        summary.compared_candidates += 1;
        resolved += usize::from(covered[index]);
        let mut improved = false;
        let mut regressed = false;
        for (direction, metric) in [pair.upload, pair.download].into_iter().enumerate() {
            directional_known[direction] &= metric.is_some();
            if let Some(metric) = metric {
                let identity = (pair.basis, metric.support);
                directional_known[direction] &=
                    directional_support[direction].is_none_or(|old| old == identity);
                directional_support[direction] = Some(identity);
                improved |= metric.candidate - metric.incumbent
                    >= metric.incumbent * PERFORMANCE_SWITCH_MARGIN
                    && metric.candidate > metric.incumbent;
                regressed |= metric.incumbent - metric.candidate
                    > metric.incumbent * PERFORMANCE_SWITCH_MARGIN;
                if winner.qualified() && candidate.qualified() {
                    rate_nonregression &= metric.candidate - metric.incumbent
                        <= metric.candidate * PERFORMANCE_SWITCH_MARGIN;
                }
            }
        }
        summary.directional_tradeoff |= improved && regressed;
        let (rival_advantage, rates) = advantage(
            pair,
            (winner.qualified(), candidate.qualified()),
            (winner.observed_reliability, candidate.observed_reliability),
        );
        undefeated &= !rival_advantage && rates.into_iter().all(|gain| gain <= 0.0);
        let (wins, reverse_rates) = advantage(
            reversed(pair),
            (candidate.qualified(), winner.qualified()),
            (candidate.observed_reliability, winner.observed_reliability),
        );
        response_advantage |= wins;
        for direction in 0..2 {
            selected_rates[direction] = selected_rates[direction].max(reverse_rates[direction]);
        }
        index.hash(&mut support);
        (pair.basis as u8).hash(&mut support);
        for (metric_index, (range, metric)) in ranges
            .iter_mut()
            .zip([pair.response, pair.upload, pair.download])
            .enumerate()
        {
            let Some(metric) = metric else {
                continue;
            };
            (metric_index, metric.support).hash(&mut support);
            let low = metric.incumbent.min(metric.candidate);
            let high = metric.incumbent.max(metric.candidate);
            pairwise_equivalent &= equivalent(low, high);
            *range = Some(range.map_or((low, high), |(min, max)| (min.min(low), max.max(high))));
            summary.reporters = summary.reporters.min(metric.reporters);
            summary.span = Some(summary.span.map_or(metric.span, |old| old.min(metric.span)));
            summary.dispersion = summary.dispersion.max(metric.dispersion);
            oldest = Some(oldest.map_or(metric.oldest_at, |old| old.min(metric.oldest_at)));
            expires = Some(expires.map_or(metric.expires_at, |old| old.min(metric.expires_at)));
        }
    }
    let compared = summary.compared_candidates >= 2;
    summary.upload_known = compared && directional_known[0];
    summary.download_known = compared && directional_known[1];
    let mut rate_advantage = 0.0;
    for (direction, basis) in [ScoreEvidenceBasis::Upload, ScoreEvidenceBasis::Download]
        .into_iter()
        .enumerate()
    {
        if directional_known[direction] && selected_rates[direction] > rate_advantage {
            rate_advantage = selected_rates[direction];
            summary.advantage_basis = Some(basis);
        }
    }
    let comparable = compared && all_responses && !summary.response_misaligned;
    // A claim needs a covered challenger; the selection alone would make one vacuous.
    let covered_count = covered.iter().filter(|covered| **covered).count();
    summary.complete =
        comparable && !summary.target_limited && covered_count > 1 && resolved == covered_count;
    summary.equivalent = comparable
        && pairwise_equivalent
        && ranges
            .into_iter()
            .zip([true, summary.upload_known, summary.download_known])
            .filter_map(|(range, known)| known.then_some(range).flatten())
            .all(|(min, max)| equivalent(min, max))
        && undefeated
        && !summary.directional_tradeoff;
    summary.supported = comparable
        && undefeated
        && (response_advantage || (rate_advantage > 0.0 && rate_nonregression));
    if compared {
        summary.support = support.finish();
    }
    summary.evidence_age = oldest.map(|at| now.saturating_duration_since(at));
    summary.valid_for = expires.map(|at| at.saturating_duration_since(now));
    summary
}
