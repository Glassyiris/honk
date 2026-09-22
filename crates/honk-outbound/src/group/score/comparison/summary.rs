use super::super::ranking::{Decision, normal_eligible, promotion_result, switch_margin};
use super::super::{PERFORMANCE_MAX_AGE, PERFORMANCE_SWITCH_MARGIN, ScoreEvidenceBasis};
use super::{Basis, MetricPair, PairEvidence};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default)]
pub(in crate::group::score) struct Summary {
    pub basis: Basis,
    pub advantage_basis: Option<ScoreEvidenceBasis>,
    pub compared_candidates: usize,
    pub complete: bool,
    pub equivalent: bool,
    pub supported: bool,
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

pub(in crate::group::score) fn summarize(decision: &Decision, now: Instant) -> Summary {
    let snapshots = &decision.scores;
    let selected = decision.pairs.reference;
    let Some(winner) = snapshots.get(selected) else {
        return Summary::default();
    };
    let mut summary = Summary::default();
    let baseline = decision.baseline;
    let mut excluded = 0;
    let mut coherent = true;
    let mut ranges: [Option<(f64, f64)>; 3] = [None; 3];
    let mut undefeated = true;
    let mut advantage = false;
    let mut rate_advantage = 0.0;
    let mut all_upload = true;
    let mut all_download = true;
    let mut all_responses = true;
    let mut oldest: Option<Instant> = None;
    let mut expires: Option<Instant> = None;
    for (index, candidate) in snapshots.iter().enumerate() {
        if index == selected {
            continue;
        }
        if !normal_eligible(candidate, baseline)
            && decision.evidence[index]
                .failed_at
                .is_some_and(|at| now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE)
        {
            excluded += 1;
            continue;
        }
        let Some(pair) = decision.pairs.get(index) else {
            continue;
        };
        let result = promotion_result(
            pair,
            (winner.qualified(), candidate.qualified()),
            (winner.observed_reliability, candidate.observed_reliability),
        );
        summary.directional_tradeoff |= result.directional_tradeoff;
        let Some(supporting) = [pair.response, pair.upload, pair.download]
            .into_iter()
            .flatten()
            .find(|metric| now < metric.expires_at)
        else {
            continue;
        };
        all_responses &= pair.response.is_some_and(|metric| now < metric.expires_at);
        if let Some(response) = pair.response {
            summary.response_latest_at = Some(
                summary
                    .response_latest_at
                    .map_or(response.latest_at, |old| old.min(response.latest_at)),
            );
        }
        if summary.compared_candidates == 0 {
            summary.basis = pair.basis;
            summary.support = pair.support;
            summary.compared_candidates = 1;
            summary.reporters = supporting.reporters;
        } else {
            coherent &= summary.basis == pair.basis && summary.support == pair.support;
        }
        summary.compared_candidates += 1;
        all_upload &= result.upload_known;
        all_download &= result.download_known;
        let reverse_pair = reversed(pair);
        let reverse_result = promotion_result(
            reverse_pair,
            (candidate.qualified(), winner.qualified()),
            (candidate.observed_reliability, winner.observed_reliability),
        );
        undefeated &= result.gain < switch_margin(winner.completed) || result.gain <= 0.0;
        let margin = switch_margin(candidate.completed);
        let wins = reverse_result.gain >= margin && reverse_result.gain > 0.0;
        advantage |= wins;
        if wins && (reverse_result.upload_known || reverse_result.download_known) {
            let response_gain = reverse_result.response_gain;
            if response_gain < margin || response_gain <= 0.0 {
                for (basis, metric) in [
                    (ScoreEvidenceBasis::Upload, reverse_pair.upload),
                    (ScoreEvidenceBasis::Download, reverse_pair.download),
                ] {
                    let Some(metric) = metric else {
                        continue;
                    };
                    let gain = (metric.candidate - metric.incumbent)
                        / metric.candidate.max(metric.incumbent).max(1.0);
                    if gain > rate_advantage {
                        rate_advantage = gain;
                        summary.advantage_basis = Some(basis);
                    }
                }
            }
        }
        for (range, metric) in ranges
            .iter_mut()
            .zip([pair.response, pair.upload, pair.download])
        {
            let Some(metric) = metric else {
                continue;
            };
            let low = metric.incumbent.min(metric.candidate);
            let high = metric.incumbent.max(metric.candidate);
            *range = Some(range.map_or((low, high), |(min, max)| (min.min(low), max.max(high))));
            summary.reporters = summary.reporters.min(metric.reporters);
            summary.span = Some(summary.span.map_or(metric.span, |old| old.min(metric.span)));
            summary.dispersion = summary.dispersion.max(metric.dispersion);
            oldest = Some(oldest.map_or(metric.oldest_at, |old| old.min(metric.oldest_at)));
            expires = Some(expires.map_or(metric.expires_at, |old| old.min(metric.expires_at)));
        }
    }
    let compared = summary.compared_candidates >= 2;
    summary.complete = compared
        && all_responses
        && coherent
        && summary.compared_candidates + excluded == snapshots.len();
    summary.equivalent = compared
        && all_responses
        && coherent
        && ranges
            .into_iter()
            .flatten()
            .all(|(min, max)| max - min <= min * PERFORMANCE_SWITCH_MARGIN)
        && undefeated
        && !summary.directional_tradeoff;
    summary.supported = compared && all_responses && coherent && undefeated && advantage;
    summary.upload_known = compared && all_upload;
    summary.download_known = compared && all_download;
    summary.evidence_age = oldest.map(|at| now.saturating_duration_since(at));
    summary.valid_for = expires.map(|at| at.saturating_duration_since(now));
    summary
}
