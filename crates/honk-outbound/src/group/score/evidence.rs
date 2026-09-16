use super::ranking::explore_backoff;
use super::{
    AggregateKey, FlowSample, IpVersion, MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_DURATION,
    RELIABILITY_CONFIDENCE_Z, SCORE_EVIDENCE_HALF_LIFE, ScoreAttribution, ScoreOutcome,
    ScoreSelectionContext, StateInner, Stats, WeightedMean,
};
use lru::LruCache;
use std::time::{Duration, Instant};

impl WeightedMean {
    fn decay(&mut self, factor: f64) {
        self.sum *= factor;
        self.weight *= factor;
    }

    pub(super) fn record(&mut self, sample: f64) {
        self.sum += sample;
        self.weight += 1.0;
    }

    pub(super) fn mean(&self) -> Option<f64> {
        (self.weight > 0.0).then(|| self.sum / self.weight)
    }
}

impl Stats {
    pub(super) fn completed(&self) -> f64 {
        self.setup_success + self.setup_failure
    }

    pub(super) fn useful_completed(&self) -> f64 {
        self.useful_success + self.useful_failure
    }

    pub(super) fn reliability_bounds(&self, factor: f64) -> (f64, f64) {
        // Setup failure is already a useful failure. Counting two additional
        // failures makes it the strongest negative signal without a knob.
        let successes = self.useful_success * factor;
        let failures = (self.useful_failure + self.setup_failure * 2.0) * factor;
        let a = successes + 1.0;
        let b = failures + 1.0;
        let sum = a + b;
        let mean = a / sum;
        let deviation = (a * b / (sum * sum * (sum + 1.0))).sqrt();
        (
            (mean - RELIABILITY_CONFIDENCE_Z * deviation).clamp(0.0, 1.0),
            (mean + RELIABILITY_CONFIDENCE_Z * deviation).clamp(0.0, 1.0),
        )
    }

    pub(super) fn decay_to(&mut self, now: Instant) {
        let Some(updated_at) = self.updated_at.replace(now) else {
            return;
        };
        let factor = evidence_decay(now.saturating_duration_since(updated_at));
        self.attempts *= factor;
        self.setup_success *= factor;
        self.setup_failure *= factor;
        self.useful_success *= factor;
        self.useful_failure *= factor;
        self.setup_ms.decay(factor);
        self.first_response_ms.decay(factor);
        self.throughput_bytes *= factor;
        self.throughput_seconds *= factor;
        self.throughput_windows *= factor;
    }

    fn record_start(&mut self, now: Instant) {
        self.decay_to(now);
        self.attempts += 1.0;
    }

    pub(super) fn record_finish(
        &mut self,
        now: Instant,
        sample: &FlowSample,
        count_usefulness: bool,
    ) {
        self.decay_to(now);
        if matches!(
            sample.outcome,
            ScoreOutcome::Rejected | ScoreOutcome::Cancelled | ScoreOutcome::Shutdown
        ) {
            self.attempts = (self.attempts - evidence_decay(sample.elapsed)).max(0.0);
            return;
        }
        if !sample.streak_neutral {
            if sample.outcome == ScoreOutcome::Success {
                // Liveness is proven, but the streak steps down one at a
                // time: a flapping leaf earns the fast cadence back.
                self.fail_streak = self.fail_streak.saturating_sub(1);
                self.explore_not_before = None;
            } else {
                self.fail_streak = self.fail_streak.saturating_add(1);
                self.explore_not_before = Some(now + explore_backoff(self.fail_streak));
            }
        }
        if let Some(setup) = sample.setup {
            self.setup_success += 1.0;
            self.setup_ms.record(setup.as_secs_f64() * 1000.0);
        } else {
            self.setup_failure += 1.0;
        }
        if let Some(first_response) = sample.first_response {
            self.first_response_ms
                .record(first_response.as_secs_f64() * 1000.0);
        }
        if count_usefulness {
            let useful = sample.outcome == ScoreOutcome::Success && sample.tx > 0 && sample.rx > 0;
            if useful {
                self.useful_success += 1.0;
                if sample.elapsed >= MIN_THROUGHPUT_DURATION
                    && sample.tx.max(sample.rx) >= MIN_THROUGHPUT_BYTES
                {
                    self.throughput_bytes += sample.tx.max(sample.rx) as f64;
                    self.throughput_seconds += sample.elapsed.as_secs_f64();
                    self.throughput_windows += 1.0;
                }
            } else {
                self.useful_failure += 1.0;
            }
        }
    }
}

pub(super) fn evidence_decay(elapsed: Duration) -> f64 {
    (-elapsed.as_secs_f64() / SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()).exp2()
}

pub(super) fn record_cell_start<K>(
    cache: &mut LruCache<K, Stats>,
    key: K,
    now: Instant,
    tick: u64,
    evictions: &mut u64,
) -> u64
where
    K: std::hash::Hash + Eq,
{
    if let Some(stats) = cache.get_mut(&key) {
        stats.record_start(now);
        return stats.incarnation;
    }
    let mut stats = Stats {
        incarnation: tick,
        ..Default::default()
    };
    stats.record_start(now);
    // A full cache means this put evicts the LRU tail.
    if cache.len() == cache.cap().get() {
        *evictions = evictions.saturating_add(1);
    }
    cache.put(key, stats);
    tick
}

pub(super) fn record_cell_finish<K>(
    cache: &mut LruCache<K, Stats>,
    key: &K,
    incarnation: Option<u64>,
    now: Instant,
    sample: &FlowSample,
    count_usefulness: bool,
) where
    K: std::hash::Hash + Eq,
{
    let Some(incarnation) = incarnation else {
        return;
    };
    let remove_empty = match cache.get_mut(key) {
        Some(stats) if stats.incarnation == incarnation => {
            stats.record_finish(now, sample, count_usefulness);
            stats.attempts == 0.0 && stats.completed() == 0.0
        }
        _ => false,
    };
    if remove_empty {
        cache.pop(key);
    }
}

fn aggregate_families(context: &ScoreSelectionContext) -> [Option<IpVersion>; 2] {
    [None, context.target_family]
}

pub(super) fn record_aggregate_start(
    inner: &mut StateInner,
    attribution: &ScoreAttribution,
    context: &ScoreSelectionContext,
    now: Instant,
    tick: u64,
) -> [Option<u64>; 2] {
    let mut cells = [None; 2];
    for (index, family) in aggregate_families(context).into_iter().enumerate() {
        if index == 1 && family.is_none() {
            break;
        }
        let key = AggregateKey {
            group: attribution.group.clone(),
            network: context.network,
            family,
            node_id: attribution.node_id,
        };
        cells[index] = Some(record_cell_start(
            &mut inner.aggregate,
            key,
            now,
            tick,
            &mut inner.aggregate_evictions,
        ));
    }
    cells
}

pub(super) fn record_aggregate_finish(
    inner: &mut StateInner,
    attribution: &ScoreAttribution,
    context: &ScoreSelectionContext,
    cells: [Option<u64>; 2],
    now: Instant,
    sample: &FlowSample,
) {
    for (index, family) in aggregate_families(context).into_iter().enumerate() {
        if index == 1 && family.is_none() {
            break;
        }
        let key = AggregateKey {
            group: attribution.group.clone(),
            network: context.network,
            family,
            node_id: attribution.node_id,
        };
        record_cell_finish(
            &mut inner.aggregate,
            &key,
            cells[index],
            now,
            sample,
            sample.count_usefulness && context.target.is_some(),
        );
    }
}
