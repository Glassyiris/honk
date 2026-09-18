use super::ranking::explore_backoff;
use super::{
    AggregateKey, ExactKey, FlowSample, MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES,
    MIN_THROUGHPUT_DURATION, PERFORMANCE_MAX_AGE, PERFORMANCE_VALIDATION_SAMPLES,
    RELIABILITY_CONFIDENCE_Z, SCORE_EVIDENCE_HALF_LIFE, ScoreAttribution, ScoreAuthority,
    ScoreOutcome, ScorePolicyState, ScoreSelectionContext, ScoreSource, StartedCells, Stats,
    WeightedMean,
};
use lru::LruCache;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub(super) struct Performance {
    pub setup: WeightedMean,
    pub response: WeightedMean,
    pub upload: WeightedMean,
    pub download: WeightedMean,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProbeMetric {
    pub latency: WeightedMean,
    pub scope: u64,
}

pub(super) fn probe_slot(context: &ScoreSelectionContext) -> usize {
    context.probe_domain as usize * 2 + context.health_family as usize
}

#[derive(Clone, Copy, Default)]
pub(super) struct MetricSnapshot {
    pub value: Option<f64>,
    pub confidence: f64,
    pub observed_at: Option<Instant>,
}

#[derive(Clone, Copy, Default)]
pub(super) struct PerformanceSnapshot {
    pub setup: MetricSnapshot,
    pub response: MetricSnapshot,
    pub upload: MetricSnapshot,
    pub download: MetricSnapshot,
}

impl Performance {
    pub(super) fn snapshot(&self, now: Instant) -> PerformanceSnapshot {
        PerformanceSnapshot {
            setup: self.setup.snapshot(now),
            response: self.response.snapshot(now),
            upload: self.upload.snapshot(now),
            download: self.download.snapshot(now),
        }
    }
}

impl WeightedMean {
    pub(super) fn record(&mut self, sample: f64, now: Instant) {
        if self
            .observed_at
            .is_none_or(|at| now.saturating_duration_since(at) >= PERFORMANCE_MAX_AGE)
        {
            self.sum = 0.0;
            self.weight = 0.0;
        }
        // Bound inertia as well as freshness: ten thousand old samples must
        // not outvote the next few observations of a degraded path.
        if self.weight >= PERFORMANCE_VALIDATION_SAMPLES {
            self.sum *= (PERFORMANCE_VALIDATION_SAMPLES - 1.0) / self.weight;
            self.weight = PERFORMANCE_VALIDATION_SAMPLES - 1.0;
        }
        self.sum += sample;
        self.weight += 1.0;
        self.observed_at = Some(now);
    }

    pub(super) fn snapshot(&self, now: Instant) -> MetricSnapshot {
        let Some(at) = self.observed_at else {
            return MetricSnapshot::default();
        };
        let age = now.saturating_duration_since(at);
        if age >= PERFORMANCE_MAX_AGE || self.weight <= 0.0 {
            return MetricSnapshot::default();
        }
        let freshness =
            (2.0 * (1.0 - age.as_secs_f64() / PERFORMANCE_MAX_AGE.as_secs_f64())).min(1.0);
        MetricSnapshot {
            value: Some(self.sum / self.weight),
            confidence: (self.weight / PERFORMANCE_VALIDATION_SAMPLES).min(1.0) * freshness,
            observed_at: Some(at),
        }
    }
}

pub(super) enum Observation {
    Setup(Duration),
    Response(Duration),
    Probe {
        latency: Duration,
        scope: u64,
        slot: usize,
    },
    Transfer {
        tx: u64,
        rx: u64,
        elapsed: Duration,
    },
}

impl Stats {
    pub(super) fn completed(&self) -> f64 {
        self.setup_success + self.setup_failure
    }

    pub(super) fn useful_completed(&self) -> f64 {
        self.useful_success + self.useful_failure
    }

    pub(super) fn reliability_bounds(&self, factor: f64) -> (f64, f64) {
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
    }

    fn record_start(&mut self, now: Instant, source: ScoreSource) {
        if source == ScoreSource::Traffic {
            self.decay_to(now);
            self.attempts += 1.0;
            self.last_attempt = Some(now);
        }
    }

    fn observe(&mut self, observation: &Observation, source: ScoreSource, now: Instant) {
        match (source, observation) {
            (
                ScoreSource::Traffic,
                Observation::Setup(latency) | Observation::Response(latency),
            ) => {
                let metric = if matches!(observation, Observation::Setup(_)) {
                    &mut self.performance.setup
                } else {
                    &mut self.performance.response
                };
                let sample = latency.as_secs_f64() * 1000.0;
                let previous = metric.snapshot(now);
                if previous.confidence == 1.0
                    && previous
                        .value
                        .is_some_and(|old| sample > old.max(1.0) * 1.5)
                {
                    self.degraded_at = Some(now);
                }
                metric.record(sample, now);
            }
            (ScoreSource::Warmup, Observation::Setup(latency)) => {
                self.warm_setup_ms
                    .record(latency.as_secs_f64() * 1000.0, now);
            }
            (
                ScoreSource::HealthProbe,
                Observation::Probe {
                    latency,
                    scope,
                    slot,
                },
            ) => {
                let probe = &mut self.probes[*slot];
                if probe.scope != *scope {
                    probe.latency = WeightedMean::default();
                    probe.scope = *scope;
                }
                probe.latency.record(latency.as_secs_f64() * 1000.0, now);
            }
            (ScoreSource::Traffic, Observation::Transfer { tx, rx, elapsed })
                if *elapsed >= MIN_THROUGHPUT_DURATION && *elapsed <= MAX_THROUGHPUT_DURATION =>
            {
                // Directional rates are not summed: a request body and its
                // response are different workloads, not twice the capacity.
                if *tx >= MIN_THROUGHPUT_BYTES {
                    self.performance
                        .upload
                        .record(*tx as f64 / elapsed.as_secs_f64(), now);
                }
                if *rx >= MIN_THROUGHPUT_BYTES {
                    self.performance
                        .download
                        .record(*rx as f64 / elapsed.as_secs_f64(), now);
                }
            }
            _ => {}
        }
    }

    pub(super) fn invalidate_business(&mut self, now: Instant) {
        self.useful_business = WeightedMean::default();
        self.business_invalidated_through = Some(
            self.business_invalidated_through
                .map_or(now, |at| at.max(now)),
        );
    }

    pub(super) fn record_finish(
        &mut self,
        now: Instant,
        sample: &FlowSample,
        count_usefulness: bool,
    ) {
        if sample.source != ScoreSource::Traffic {
            return;
        }
        self.decay_to(now);
        if matches!(
            sample.outcome,
            ScoreOutcome::Rejected | ScoreOutcome::Cancelled | ScoreOutcome::Shutdown
        ) {
            self.attempts = (self.attempts - evidence_decay(sample.elapsed)).max(0.0);
            return;
        }
        if sample.outcome == ScoreOutcome::Success {
            self.fail_streak = self.fail_streak.saturating_sub(1);
            self.explore_not_before = None;
        } else {
            self.fail_streak = self.fail_streak.saturating_add(1);
            self.explore_not_before = Some(now + explore_backoff(self.fail_streak));
            self.invalidate_business(now);
            self.failed_at = Some(self.failed_at.map_or(now, |at| at.max(now)));
        }
        if sample.setup.is_some() {
            self.setup_success += 1.0;
        } else {
            self.setup_failure += 1.0;
        }
        if count_usefulness {
            if sample.outcome == ScoreOutcome::Success && sample.tx > 0 && sample.rx > 0 {
                self.useful_success += 1.0;
                if let Some(at) = sample.last_rx_at
                    && now.saturating_duration_since(at) < PERFORMANCE_MAX_AGE
                    && self
                        .business_invalidated_through
                        .is_none_or(|fence| at > fence)
                {
                    // Terminal order is not RX order; expired weight must not be revived.
                    if self.useful_business.observed_at.is_some_and(|seen| {
                        now.saturating_duration_since(seen) >= PERFORMANCE_MAX_AGE
                    }) {
                        self.useful_business = WeightedMean::default();
                    }
                    let at = self
                        .useful_business
                        .observed_at
                        .map_or(at, |seen| seen.max(at));
                    self.useful_business.record(1.0, at);
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

fn record_cell_start<K: std::hash::Hash + Eq>(
    cache: &mut LruCache<K, Stats>,
    key: K,
    now: Instant,
    tick: u64,
    evictions: &mut u64,
    source: ScoreSource,
) -> u64 {
    if let Some(stats) = cache.get_mut(&key) {
        stats.record_start(now, source);
        return stats.incarnation;
    }
    let mut stats = Stats {
        incarnation: tick,
        ..Default::default()
    };
    stats.record_start(now, source);
    if cache.len() == cache.cap().get() {
        *evictions = evictions.saturating_add(1);
    }
    cache.put(key, stats);
    tick
}

fn update_cell<K: std::hash::Hash + Eq>(
    cache: &mut LruCache<K, Stats>,
    key: &K,
    incarnation: Option<u64>,
    update: &mut impl FnMut(&mut Stats, bool),
    exact: bool,
) {
    if let Some(stats) = cache.get_mut(key)
        && Some(stats.incarnation) == incarnation
    {
        update(stats, exact);
    }
}

impl ScorePolicyState {
    #[cfg(test)]
    pub(super) fn start(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
    ) -> Vec<StartedCells> {
        self.start_at(context, attributions, Instant::now())
    }

    #[cfg(test)]
    pub(super) fn start_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
    ) -> Vec<StartedCells> {
        let authority = self
            .inner
            .lock()
            .active_authority
            .clone()
            .unwrap_or_else(|| Arc::new(ScoreAuthority));
        self.start_at_with_authority(&authority, context, attributions, now, ScoreSource::Traffic)
    }

    pub(super) fn start_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
        source: ScoreSource,
    ) -> Vec<StartedCells> {
        let mut inner = self.inner.lock();
        if !inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
        {
            return vec![StartedCells::default(); attributions.len()];
        }
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        let mut cells = Vec::with_capacity(attributions.len());
        for attribution in attributions {
            let mut started = StartedCells::default();
            if inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                for (index, family) in [None, context.target_family].into_iter().enumerate() {
                    if index == 1 && (family.is_none() || source == ScoreSource::HealthProbe) {
                        break;
                    }
                    let key = AggregateKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        node_id: attribution.node_id,
                    };
                    let super::StateInner {
                        aggregate,
                        aggregate_evictions,
                        ..
                    } = &mut *inner;
                    started.aggregate[index] = Some(record_cell_start(
                        aggregate,
                        key,
                        now,
                        tick,
                        aggregate_evictions,
                        source,
                    ));
                }
                if source != ScoreSource::HealthProbe
                    && let (Some(family), Some(target)) =
                        (context.target_family, context.target.as_ref())
                {
                    let key = ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    };
                    let super::StateInner {
                        exact,
                        exact_evictions,
                        ..
                    } = &mut *inner;
                    started.exact = Some(record_cell_start(
                        exact,
                        key,
                        now,
                        tick,
                        exact_evictions,
                        source,
                    ));
                }
            }
            cells.push(started);
        }
        cells
    }

    fn update_started(
        inner: &mut super::StateInner,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        mut update: impl FnMut(&mut Stats, bool),
    ) {
        for (attribution, started) in attributions.iter().zip(cells) {
            if !inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                continue;
            }
            for (index, family) in [None, context.target_family].into_iter().enumerate() {
                if started.aggregate[index].is_none() {
                    continue;
                }
                if index == 1 && family.is_none() {
                    break;
                }
                let key = AggregateKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    node_id: attribution.node_id,
                };
                update_cell(
                    &mut inner.aggregate,
                    &key,
                    started.aggregate[index],
                    &mut update,
                    false,
                );
            }
            if started.exact.is_some()
                && let (Some(family), Some(target)) =
                    (context.target_family, context.target.as_ref())
            {
                let key = ExactKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    target: target.clone(),
                    node_id: attribution.node_id,
                };
                update_cell(&mut inner.exact, &key, started.exact, &mut update, true);
            }
        }
    }

    pub(super) fn observe(
        inner: &mut super::StateInner,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        source: ScoreSource,
        observation: Observation,
        now: Instant,
    ) {
        Self::update_started(inner, context, attributions, cells, |stats, _| {
            stats.observe(&observation, source, now)
        });
    }

    #[cfg(test)]
    pub(super) fn finish(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
    ) {
        self.finish_at(context, attributions, cells, sample, Instant::now());
    }

    pub(super) fn finish_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
        now: Instant,
    ) {
        Self::update_started(
            &mut self.inner.lock(),
            context,
            attributions,
            cells,
            |stats, exact| {
                stats.record_finish(
                    now,
                    sample,
                    sample.count_usefulness && (exact || context.target.is_some()),
                );
            },
        );
    }
}
