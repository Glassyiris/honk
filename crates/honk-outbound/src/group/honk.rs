use super::{IpVersion, ProbeDomain, SelectionNetwork};
use honk_config::node::Node;
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const EXACT_CAPACITY: usize = 4096;
const AGGREGATE_CAPACITY: usize = 4096;
const RELIABILITY_CLOSE: f64 = 0.05;

/// A normalized business target used only as an in-memory score key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HonkTarget {
    Domain { host: String, port: u16 },
    Socket(SocketAddr),
}

impl HonkTarget {
    pub fn domain(host: &str, port: u16) -> Self {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        Self::Domain { host, port }
    }
}

impl From<SocketAddr> for HonkTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

/// Business-target scoring dimensions plus the independent proxy-health
/// dimensions used to form the alive candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HonkSelectionContext {
    pub network: SelectionNetwork,
    pub probe_domain: ProbeDomain,
    pub target_family: Option<IpVersion>,
    pub health_family: IpVersion,
    pub target: Option<HonkTarget>,
}

impl HonkSelectionContext {
    /// Context for traffic without a trustworthy business target (warm-up
    /// and preconnect). Feedback updates aggregate state only.
    pub fn aggregate(
        network: SelectionNetwork,
        probe_domain: ProbeDomain,
        health_family: IpVersion,
    ) -> Self {
        Self {
            network,
            probe_domain,
            target_family: None,
            health_family,
            target: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HonkAttribution {
    pub group: String,
    pub node_id: Uuid,
}

/// Compact terminal result; formatted error strings never enter score state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HonkOutcome {
    Success,
    Timeout,
    Io(io::ErrorKind),
    Cancelled,
    Shutdown,
    Other,
}

impl HonkOutcome {
    pub fn from_error(error: &anyhow::Error) -> Self {
        error
            .chain()
            .find_map(|source| source.downcast_ref::<io::Error>())
            .map_or(Self::Other, |error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    Self::Timeout
                } else {
                    Self::Io(error.kind())
                }
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExactKey {
    group: String,
    network: SelectionNetwork,
    family: IpVersion,
    target: HonkTarget,
    node_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AggregateKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
    node_id: Uuid,
}

#[derive(Debug, Clone, Default)]
struct Stats {
    incarnation: u64,
    started: u64,
    setup_success: u64,
    setup_failure: u64,
    useful_success: u64,
    useful_failure: u64,
    setup_ms: Option<f64>,
    first_response_ms: Option<f64>,
    throughput: Option<f64>,
    last_used: u64,
}

impl Stats {
    fn completed(&self) -> u64 {
        self.setup_success.saturating_add(self.setup_failure)
    }
    fn useful_completed(&self) -> u64 {
        self.useful_success.saturating_add(self.useful_failure)
    }

    fn reliability(&self) -> f64 {
        // Setup failure is already a useful failure. Counting two additional
        // failures makes it the strongest negative signal without a knob.
        let successes = self.useful_success as f64;
        let failures = self
            .useful_failure
            .saturating_add(self.setup_failure.saturating_mul(2)) as f64;
        let a = successes + 1.0;
        let b = failures + 1.0;
        let sum = a + b;
        let mean = a / sum;
        let deviation = (a * b / (sum * sum * (sum + 1.0))).sqrt();
        (mean - 1.64 * deviation).clamp(0.0, 1.0)
    }

    fn record_start(&mut self, tick: u64) {
        self.started = self.started.saturating_add(1);
        self.last_used = tick;
    }

    fn record_finish(&mut self, sample: &FlowSample, count_usefulness: bool, tick: u64) {
        if matches!(
            sample.outcome,
            HonkOutcome::Cancelled | HonkOutcome::Shutdown
        ) {
            self.started = self.started.saturating_sub(1);
            self.last_used = tick;
            return;
        }
        if let Some(setup) = sample.setup {
            self.setup_success = self.setup_success.saturating_add(1);
            update_ewma(&mut self.setup_ms, setup.as_secs_f64() * 1000.0);
        } else {
            self.setup_failure = self.setup_failure.saturating_add(1);
        }
        if let Some(first_response) = sample.first_response {
            update_ewma(
                &mut self.first_response_ms,
                first_response.as_secs_f64() * 1000.0,
            );
        }
        if count_usefulness {
            let useful = sample.outcome == HonkOutcome::Success && sample.tx > 0 && sample.rx > 0;
            if useful {
                self.useful_success = self.useful_success.saturating_add(1);
                let seconds = sample.elapsed.as_secs_f64().max(0.001);
                let rate = sample.tx.saturating_add(sample.rx) as f64 / seconds;
                update_ewma(&mut self.throughput, (1.0 + rate).log2().clamp(0.0, 30.0));
            } else {
                self.useful_failure = self.useful_failure.saturating_add(1);
            }
        }
        self.last_used = tick;
    }
}

fn record_cell_start<K>(cache: &mut LruCache<K, Stats>, key: K, tick: u64) -> u64
where
    K: std::hash::Hash + Eq,
{
    if let Some(stats) = cache.get_mut(&key) {
        stats.record_start(tick);
        return stats.incarnation;
    }
    let mut stats = Stats {
        incarnation: tick,
        ..Default::default()
    };
    stats.record_start(tick);
    cache.put(key, stats);
    tick
}

fn record_cell_finish<K>(
    cache: &mut LruCache<K, Stats>,
    key: &K,
    incarnation: Option<u64>,
    sample: &FlowSample,
    count_usefulness: bool,
    tick: u64,
) where
    K: std::hash::Hash + Eq,
{
    let Some(incarnation) = incarnation else {
        return;
    };
    let remove_empty = match cache.get_mut(key) {
        Some(stats) if stats.incarnation == incarnation => {
            stats.record_finish(sample, count_usefulness, tick);
            stats.started == 0 && stats.completed() == 0
        }
        _ => false,
    };
    if remove_empty {
        cache.pop(key);
    }
}

#[derive(Clone, Copy, Default)]
struct StartedCells {
    aggregate: [Option<u64>; 2],
    exact: Option<u64>,
}

fn update_ewma(value: &mut Option<f64>, sample: f64) {
    *value = Some(value.map_or(sample, |old| (old + sample) * 0.5));
}

struct StateInner {
    exact: LruCache<ExactKey, Stats>,
    aggregate: LruCache<AggregateKey, Stats>,
    valid: HashSet<(String, Uuid)>,
    tick: u64,
}

impl Default for StateInner {
    fn default() -> Self {
        Self {
            exact: LruCache::new(NonZeroUsize::new(EXACT_CAPACITY).expect("non-zero capacity")),
            aggregate: LruCache::new(
                NonZeroUsize::new(AGGREGATE_CAPACITY).expect("non-zero capacity"),
            ),
            valid: HashSet::new(),
            tick: 0,
        }
    }
}

/// Process-memory-only score state shared by old and replacement managers.
#[derive(Default)]
pub struct HonkPolicyState {
    inner: Mutex<StateInner>,
}

impl HonkPolicyState {
    /// Atomically publish committed Honk group/leaf membership and prune
    /// removed cells. Construction with a reused state never calls this.
    pub fn publish_membership<I>(&self, membership: I)
    where
        I: IntoIterator<Item = (String, Uuid)>,
    {
        let mut inner = self.inner.lock();
        inner.valid = membership.into_iter().collect();
        let invalid_exact: Vec<_> = inner
            .exact
            .iter()
            .filter(|(key, _)| !inner.valid.contains(&(key.group.clone(), key.node_id)))
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_exact {
            inner.exact.pop(&key);
        }
        let invalid_aggregate: Vec<_> = inner
            .aggregate
            .iter()
            .filter(|(key, _)| !inner.valid.contains(&(key.group.clone(), key.node_id)))
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_aggregate {
            inner.aggregate.pop(&key);
        }
    }

    fn start(
        &self,
        context: &HonkSelectionContext,
        attributions: &[HonkAttribution],
    ) -> Vec<StartedCells> {
        let mut inner = self.inner.lock();
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        let mut cells = Vec::with_capacity(attributions.len());
        for attribution in attributions {
            let mut started = StartedCells::default();
            if inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                started.aggregate = record_aggregate_start(&mut inner, attribution, context, tick);
                if let (Some(family), Some(target)) =
                    (context.target_family, context.target.as_ref())
                {
                    let key = ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    };
                    started.exact = Some(record_cell_start(&mut inner.exact, key, tick));
                }
            }
            cells.push(started);
        }
        cells
    }

    fn finish(
        &self,
        context: &HonkSelectionContext,
        attributions: &[HonkAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
    ) {
        let mut inner = self.inner.lock();
        inner.tick = inner.tick.saturating_add(1);
        let tick = inner.tick;
        for (index, attribution) in attributions.iter().enumerate() {
            if !inner
                .valid
                .contains(&(attribution.group.clone(), attribution.node_id))
            {
                continue;
            }
            let started = cells.get(index).copied().unwrap_or_default();
            record_aggregate_finish(
                &mut inner,
                attribution,
                context,
                started.aggregate,
                sample,
                sample.count_usefulness && context.target.is_some(),
                tick,
            );
            if let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) {
                let key = ExactKey {
                    group: attribution.group.clone(),
                    network: context.network,
                    family,
                    target: target.clone(),
                    node_id: attribution.node_id,
                };
                record_cell_finish(
                    &mut inner.exact,
                    &key,
                    started.exact,
                    sample,
                    sample.count_usefulness,
                    tick,
                );
            }
        }
    }

    pub(super) fn rank(
        &self,
        group: &str,
        context: &HonkSelectionContext,
        nodes: &[&Node],
    ) -> usize {
        if nodes.len() < 2 {
            return 0;
        }
        let inner = self.inner.lock();
        let snapshots: Vec<_> = nodes
            .iter()
            .map(|node| score_snapshot(&inner, group, context, node.id))
            .collect();
        let best_reliability = snapshots
            .iter()
            .map(|score| score.reliability)
            .fold(0.0_f64, f64::max);
        if let Some((index, _)) = snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| score.completed == 0)
            .min_by_key(|(index, score)| (score.started, *index, nodes[*index].id))
        {
            return index;
        }
        let total_started = snapshots.iter().map(|score| score.started).sum::<u64>() as f64;
        snapshots
            .iter()
            .enumerate()
            .filter(|(_, score)| best_reliability - score.reliability <= RELIABILITY_CLOSE)
            .max_by(|(left_index, left), (right_index, right)| {
                utility(left, total_started)
                    .total_cmp(&utility(right, total_started))
                    .then_with(|| right_index.cmp(left_index))
                    .then_with(|| nodes[*right_index].id.cmp(&nodes[*left_index].id))
            })
            .map(|(index, _)| index)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn exact_len(&self) -> usize {
        self.inner.lock().exact.len()
    }

    #[cfg(test)]
    pub(super) fn has_exact(
        &self,
        group: &str,
        context: &HonkSelectionContext,
        node_id: Uuid,
    ) -> bool {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return false;
        };
        self.inner.lock().exact.contains(&ExactKey {
            group: group.to_string(),
            network: context.network,
            family,
            target: target.clone(),
            node_id,
        })
    }
    #[cfg(test)]
    fn exact_stats(
        &self,
        group: &str,
        context: &HonkSelectionContext,
        node_id: Uuid,
    ) -> Option<(u64, u64, u64)> {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return None;
        };
        self.inner
            .lock()
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| (stats.started, stats.setup_success, stats.setup_failure))
    }

    #[cfg(test)]
    fn exact_useful_failures(
        &self,
        group: &str,
        context: &HonkSelectionContext,
        node_id: Uuid,
    ) -> Option<u64> {
        let (Some(family), Some(target)) = (context.target_family, context.target.as_ref()) else {
            return None;
        };
        self.inner
            .lock()
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .map(|stats| stats.useful_failure)
    }

    #[cfg(test)]
    pub(super) fn aggregate_stats(
        &self,
        group: &str,
        network: SelectionNetwork,
        node_id: Uuid,
    ) -> Option<(u64, u64, u64)> {
        self.inner
            .lock()
            .aggregate
            .peek(&AggregateKey {
                group: group.to_string(),
                network,
                family: None,
                node_id,
            })
            .map(|stats| (stats.started, stats.setup_success, stats.setup_failure))
    }
}

fn aggregate_families(context: &HonkSelectionContext) -> [Option<IpVersion>; 2] {
    [None, context.target_family]
}

fn record_aggregate_start(
    inner: &mut StateInner,
    attribution: &HonkAttribution,
    context: &HonkSelectionContext,
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
        cells[index] = Some(record_cell_start(&mut inner.aggregate, key, tick));
    }
    cells
}

fn record_aggregate_finish(
    inner: &mut StateInner,
    attribution: &HonkAttribution,
    context: &HonkSelectionContext,
    cells: [Option<u64>; 2],
    sample: &FlowSample,
    count_usefulness: bool,
    tick: u64,
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
            sample,
            count_usefulness,
            tick,
        );
    }
}

#[derive(Clone, Copy)]
struct ScoreSnapshot {
    started: u64,
    completed: u64,
    reliability: f64,
    latency_ms: Option<f64>,
    throughput: Option<f64>,
}

fn score_snapshot(
    inner: &StateInner,
    group: &str,
    context: &HonkSelectionContext,
    node_id: Uuid,
) -> ScoreSnapshot {
    let family_aggregate = context.target_family.and_then(|family| {
        inner
            .aggregate
            .peek(&AggregateKey {
                group: group.to_string(),
                network: context.network,
                family: Some(family),
                node_id,
            })
            .cloned()
    });
    let global_aggregate = inner
        .aggregate
        .peek(&AggregateKey {
            group: group.to_string(),
            network: context.network,
            family: None,
            node_id,
        })
        .cloned()
        .unwrap_or_default();
    let global_score = snapshot(&global_aggregate);
    let aggregate_score = family_aggregate.map_or(global_score, |family| {
        let family_score = snapshot(&family);
        let reliability_weight = (family.useful_completed() as f64 / 8.0).clamp(0.0, 1.0);
        let setup_weight = (family.completed() as f64 / 8.0).clamp(0.0, 1.0);
        ScoreSnapshot {
            started: family.started,
            completed: global_aggregate
                .completed()
                .saturating_add(family.completed()),
            reliability: blend(
                global_score.reliability,
                family_score.reliability,
                reliability_weight,
            ),
            latency_ms: blend_option(
                global_score.latency_ms,
                family_score.latency_ms,
                setup_weight,
            ),
            throughput: blend_option(
                global_score.throughput,
                family_score.throughput,
                reliability_weight,
            ),
        }
    });
    let exact = match (context.target_family, context.target.as_ref()) {
        (Some(family), Some(target)) => inner
            .exact
            .peek(&ExactKey {
                group: group.to_string(),
                network: context.network,
                family,
                target: target.clone(),
                node_id,
            })
            .cloned(),
        _ => None,
    };
    let Some(exact) = exact else {
        return aggregate_score;
    };
    let reliability_weight = (exact.useful_completed() as f64 / 8.0).clamp(0.0, 1.0);
    let setup_weight = (exact.completed() as f64 / 8.0).clamp(0.0, 1.0);
    let exact_score = snapshot(&exact);
    ScoreSnapshot {
        started: exact.started,
        completed: aggregate_score.completed.saturating_add(exact.completed()),
        reliability: blend(
            aggregate_score.reliability,
            exact_score.reliability,
            reliability_weight,
        ),
        latency_ms: blend_option(
            aggregate_score.latency_ms,
            exact_score.latency_ms,
            setup_weight,
        ),
        throughput: blend_option(
            aggregate_score.throughput,
            exact_score.throughput,
            reliability_weight,
        ),
    }
}

fn snapshot(stats: &Stats) -> ScoreSnapshot {
    ScoreSnapshot {
        started: stats.started,
        completed: stats.completed(),
        reliability: stats.reliability(),
        latency_ms: stats.first_response_ms.or(stats.setup_ms),
        throughput: stats.throughput,
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

fn utility(score: &ScoreSnapshot, total_started: f64) -> f64 {
    let exploration = ((total_started + 1.0).ln() / (score.started as f64 + 1.0))
        .sqrt()
        .min(1.0)
        * RELIABILITY_CLOSE;
    let latency_penalty = score
        .latency_ms
        .map(|latency| (latency.max(1.0).log2() / 20.0).min(0.03))
        .unwrap_or(0.0);
    let throughput_bonus = score
        .throughput
        .map(|throughput| throughput / 30.0 * 0.02)
        .unwrap_or(0.0);
    score.reliability + exploration + throughput_bonus - latency_penalty
}

#[derive(Clone)]
pub struct HonkFeedback {
    state: Arc<HonkPolicyState>,
    context: HonkSelectionContext,
    attributions: Arc<[HonkAttribution]>,
}

impl std::fmt::Debug for HonkFeedback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HonkFeedback")
            .finish_non_exhaustive()
    }
}
impl HonkFeedback {
    pub(super) fn new(
        state: Arc<HonkPolicyState>,
        context: HonkSelectionContext,
        attributions: Vec<HonkAttribution>,
    ) -> Self {
        Self {
            state,
            context,
            attributions: attributions.into(),
        }
    }

    pub fn attributions(&self) -> &[HonkAttribution] {
        &self.attributions
    }
    pub fn context(&self) -> &HonkSelectionContext {
        &self.context
    }

    /// Add an outer Honk group when a terminal `final` outbound supplies the
    /// leaf. Existing nested attribution order remains outer-to-inner.
    pub fn prepend_attribution(mut self, group: String, node_id: Uuid) -> Self {
        if !self
            .attributions
            .iter()
            .any(|attribution| attribution.group == group)
        {
            let mut attributions = Vec::with_capacity(self.attributions.len() + 1);
            attributions.push(HonkAttribution { group, node_id });
            attributions.extend(self.attributions.iter().cloned());
            self.attributions = attributions.into();
        }
        self
    }
    /// Reuse the selected group chain for a related attempt with different
    /// transport dimensions, such as a UDP DNS reply retried over TCP.
    pub fn with_context(mut self, context: HonkSelectionContext) -> Self {
        self.context = context;
        self
    }

    /// Call only when the physical dial or logical stream actually starts.
    pub fn start(&self) -> HonkReporter {
        let cells = self.state.start(&self.context, &self.attributions);
        HonkReporter {
            shared: Arc::new(ReporterShared {
                state: Arc::clone(&self.state),
                context: self.context.clone(),
                attributions: Arc::clone(&self.attributions),
                cells: cells.into(),
                started: Instant::now(),
                finished: AtomicBool::new(false),
                handles: AtomicUsize::new(1),
                tx: AtomicU64::new(0),
                rx: AtomicU64::new(0),
                progress: Mutex::new(ReporterProgress::default()),
            }),
        }
    }
}

#[derive(Default)]
struct ReporterProgress {
    setup: Option<Duration>,
    first_response: Option<Duration>,
}

struct ReporterShared {
    state: Arc<HonkPolicyState>,
    context: HonkSelectionContext,
    attributions: Arc<[HonkAttribution]>,
    cells: Arc<[StartedCells]>,
    started: Instant,
    finished: AtomicBool,
    handles: AtomicUsize,
    tx: AtomicU64,
    rx: AtomicU64,
    progress: Mutex<ReporterProgress>,
}

/// Cloneable exact-once flow reporter. The first terminal call wins; dropping
/// the final unfinished handle reports cancellation.
pub struct HonkReporter {
    shared: Arc<ReporterShared>,
}

impl Clone for HonkReporter {
    fn clone(&self) -> Self {
        self.shared.handles.fetch_add(1, Ordering::Relaxed);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl HonkReporter {
    pub fn setup_succeeded(&self) {
        let mut progress = self.shared.progress.lock();
        progress
            .setup
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn setup_failed(&self, outcome: HonkOutcome) {
        self.finish(outcome);
    }

    pub fn first_response(&self) {
        let mut progress = self.shared.progress.lock();
        progress
            .first_response
            .get_or_insert_with(|| self.shared.started.elapsed());
    }

    pub fn tx(&self, bytes: u64) {
        saturating_add(&self.shared.tx, bytes);
    }

    pub fn rx(&self, bytes: u64) {
        saturating_add(&self.shared.rx, bytes);
    }

    /// Recover the immutable attribution plan for a related physical attempt.
    pub fn feedback(&self) -> HonkFeedback {
        HonkFeedback {
            state: Arc::clone(&self.shared.state),
            context: self.shared.context.clone(),
            attributions: Arc::clone(&self.shared.attributions),
        }
    }

    /// Complete a successful preparation that carried no application payload.
    pub fn finish_setup_only(&self) {
        self.finish_inner(HonkOutcome::Success, false);
    }

    pub fn finish(&self, outcome: HonkOutcome) {
        self.finish_inner(outcome, true);
    }

    fn finish_inner(&self, outcome: HonkOutcome, count_usefulness: bool) {
        if self
            .shared
            .finished
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let progress = self.shared.progress.lock();
        let sample = FlowSample {
            outcome,
            setup: progress.setup,
            first_response: progress.first_response,
            tx: self.shared.tx.load(Ordering::Relaxed),
            rx: self.shared.rx.load(Ordering::Relaxed),
            elapsed: self.shared.started.elapsed(),
            count_usefulness,
        };
        self.shared.state.finish(
            &self.shared.context,
            &self.shared.attributions,
            &self.shared.cells,
            &sample,
        );
    }
}

impl Drop for HonkReporter {
    fn drop(&mut self) {
        if self.shared.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_inner(HonkOutcome::Cancelled, false);
        }
    }
}

fn saturating_add(value: &AtomicU64, amount: u64) {
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(amount))
    });
}

struct FlowSample {
    outcome: HonkOutcome,
    setup: Option<Duration>,
    first_response: Option<Duration>,
    tx: u64,
    rx: u64,
    elapsed: Duration,
    count_usefulness: bool,
}

impl super::GroupManager {
    /// Shared scorer handle for fallible reload construction.
    pub fn honk_state(&self) -> Arc<HonkPolicyState> {
        Arc::clone(&self.honk_state)
    }

    /// Publish committed group/leaf membership and prune only removed pairs.
    /// Extant non-Honk groups remain valid for reporters started before a
    /// policy change; new selection creates feedback only for Honk groups.
    pub fn publish_honk_membership(&self) {
        let membership = self.groups.values().flat_map(|group| {
            let mut node_ids: HashSet<_> = self
                .leaf_nodes_in_group(&group.name)
                .into_iter()
                .map(|node| node.id)
                .collect();
            let mut visited = HashSet::new();
            self.collect_final_outbound_node_ids(group, &mut visited, &mut node_ids);
            node_ids
                .into_iter()
                .map(move |node_id| (group.name.clone(), node_id))
        });
        self.honk_state.publish_membership(membership);
    }

    fn collect_final_outbound_node_ids(
        &self,
        group: &honk_config::group::Group,
        visited: &mut HashSet<String>,
        node_ids: &mut HashSet<Uuid>,
    ) {
        if !visited.insert(group.name.clone()) {
            return;
        }
        let Some(final_name) = group.final_outbound.as_deref() else {
            return;
        };
        match final_name {
            honk_config::Config::BUILTIN_DIRECT_NODE => {
                node_ids.insert(honk_config::config::DIRECT_NODE_ID);
            }
            honk_config::Config::BUILTIN_BLOCK_NODE => {
                node_ids.insert(honk_config::config::BLOCK_NODE_ID);
            }
            _ => {
                if let Some(node) = self.node_by_name(final_name) {
                    node_ids.insert(node.id);
                } else if let Some(final_group) = self.groups.get(final_name) {
                    node_ids.extend(
                        self.leaf_nodes_in_group(final_name)
                            .into_iter()
                            .map(|node| node.id),
                    );
                    self.collect_final_outbound_node_ids(final_group, visited, node_ids);
                }
            }
        }
    }

    /// Aggregate scorer feedback for concrete work scheduled by leaf ID.
    /// Every Honk group that recursively contains the leaf is attributed
    /// once, regardless of how many nested paths reach it.
    pub fn feedback_for_node(
        &self,
        node_id: Uuid,
        context: HonkSelectionContext,
    ) -> Option<HonkFeedback> {
        let attributions: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Honk)
            .filter(|group| {
                self.leaf_nodes_in_group(&group.name)
                    .iter()
                    .any(|node| node.id == node_id)
            })
            .map(|group| HonkAttribution {
                group: group.name.clone(),
                node_id,
            })
            .collect();
        (!attributions.is_empty())
            .then(|| HonkFeedback::new(Arc::clone(&self.honk_state), context, attributions))
    }

    /// Feedback for a terminal `final` leaf attributed to one outer Honk
    /// group. Ordinary selected leaves should use their plan-carried feedback.
    pub fn feedback_for_group_node(
        &self,
        group_name: &str,
        node_id: Uuid,
        context: HonkSelectionContext,
    ) -> Option<HonkFeedback> {
        self.groups
            .get(group_name)
            .filter(|group| group.policy == honk_config::group::GroupPolicy::Honk)
            .map(|group| {
                HonkFeedback::new(
                    Arc::clone(&self.honk_state),
                    context,
                    vec![HonkAttribution {
                        group: group.name.clone(),
                        node_id,
                    }],
                )
            })
    }

    /// Target-aware selection with IPv6-target/IPv4-proxy health fallback.
    /// The target family remains unchanged in feedback keys; only the
    /// candidate health filter retries with IPv4.
    pub fn selection_plan_for_target_with_health_fallback(
        &self,
        group_name: &str,
        context: &HonkSelectionContext,
    ) -> super::HonkSelectionPlan<'_> {
        let plan = self.selection_plan_for_target(group_name, context);
        if !plan.entries.is_empty() || context.health_family != IpVersion::V6 {
            return plan;
        }
        let mut fallback = context.clone();
        fallback.health_family = IpVersion::V4;
        self.selection_plan_for_target(group_name, &fallback)
    }

    /// Target-aware, candidate-safe plan with attribution captured during
    /// recursive selection rather than recovered from the selected NodeId.
    pub fn selection_plan_for_target(
        &self,
        group_name: &str,
        context: &HonkSelectionContext,
    ) -> super::HonkSelectionPlan<'_> {
        let Some(group) = self.groups.get(group_name) else {
            return super::HonkSelectionPlan {
                mode: super::SelectionPlanMode::Authoritative,
                health_family: context.health_family,
                entries: Vec::new(),
            };
        };
        self.mark_used(group_name);
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            context,
            &mut visited,
            0,
            super::SelectionEffects::Apply,
        );
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let (mode, candidates) = if candidates.is_empty() {
            let candidate = self.last_resort_candidate_for_target(
                group,
                context,
                &mut visited,
                0,
                super::SelectionEffects::Apply,
            );
            (
                super::SelectionPlanMode::Authoritative,
                candidate.into_iter().collect(),
            )
        } else if group.policy == honk_config::group::GroupPolicy::URLTest
            && !candidates.iter().any(|candidate| {
                self.node_latency(
                    candidate.node,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                    candidate.tag,
                ) != Duration::MAX
            })
        {
            (
                super::SelectionPlanMode::ColdUrlTest,
                self.order_by_latency(
                    candidates,
                    context.network,
                    context.health_family,
                    group.check_url.as_deref(),
                ),
            )
        } else {
            let candidate = match group.policy {
                honk_config::group::GroupPolicy::Selector => self.pick_selector(&candidates, group),
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::LoadBalance => self.pick_load_balance(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Fallback => self.pick_fallback(
                    &candidates,
                    group,
                    context.network,
                    super::SelectionEffects::Apply,
                ),
                honk_config::group::GroupPolicy::Honk => {
                    self.pick_honk(&candidates, group, context)
                }
            };
            (super::SelectionPlanMode::Authoritative, vec![candidate])
        };
        let candidates = candidates.into_iter().map(|mut candidate| {
            if group.policy == honk_config::group::GroupPolicy::Honk {
                candidate.attribution.insert(0, group.name.as_str());
            }
            candidate.selection_chain.insert(0, group.name.as_str());
            candidate
        });
        super::HonkSelectionPlan {
            mode,
            health_family: context.health_family,
            entries: candidates
                .map(|candidate| {
                    let attributions: Vec<_> = candidate
                        .attribution
                        .into_iter()
                        .map(|group| HonkAttribution {
                            group: group.to_string(),
                            node_id: candidate.node.id,
                        })
                        .collect();
                    let selection_chain = candidate
                        .selection_chain
                        .into_iter()
                        .map(str::to_owned)
                        .collect();
                    let feedback = (!attributions.is_empty()).then(|| {
                        HonkFeedback::new(
                            Arc::clone(&self.honk_state),
                            context.clone(),
                            attributions,
                        )
                    });
                    super::HonkSelectionEntry {
                        node: candidate.node,
                        feedback,
                        selection_chain,
                    }
                })
                .collect(),
        }
    }

    fn last_resort_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &HonkSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        let node = self.last_resort_tcp_leaf(group, context.probe_domain)?;
        if group.nodes.contains(&node.id) {
            return Some(super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            });
        }

        visited.push(group.name.as_str());
        let candidate = group.groups.iter().find_map(|tag| {
            let subgroup = self.groups.get(tag)?;
            self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
                .filter(|candidate| candidate.node.id == node.id)
                .map(|mut candidate| {
                    candidate.tag = tag.as_str();
                    candidate
                })
        });
        visited.pop();
        candidate
    }

    fn pick_candidate_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &HonkSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Option<super::Candidate<'a>> {
        let mut candidates =
            self.flatten_candidates_for_target(group, context, visited, depth, effects);
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        let mut candidate = if candidates.is_empty() {
            self.last_resort_candidate_for_target(group, context, visited, depth, effects)
        } else {
            Some(match group.policy {
                honk_config::group::GroupPolicy::Selector => self.pick_selector(&candidates, group),
                honk_config::group::GroupPolicy::URLTest => self.pick_urltest(
                    &candidates,
                    group,
                    context.network,
                    context.health_family,
                    effects,
                ),
                honk_config::group::GroupPolicy::LoadBalance => {
                    self.pick_load_balance(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Fallback => {
                    self.pick_fallback(&candidates, group, context.network, effects)
                }
                honk_config::group::GroupPolicy::Honk => {
                    self.pick_honk(&candidates, group, context)
                }
            })
        }?;
        if group.policy == honk_config::group::GroupPolicy::Honk {
            candidate.attribution.insert(0, group.name.as_str());
        }
        candidate.selection_chain.insert(0, group.name.as_str());
        Some(candidate)
    }

    fn flatten_candidates_for_target<'a>(
        &'a self,
        group: &'a honk_config::group::Group,
        context: &HonkSelectionContext,
        visited: &mut Vec<&'a str>,
        depth: usize,
        effects: super::SelectionEffects,
    ) -> Vec<super::Candidate<'a>> {
        if depth >= super::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        let mut candidates: Vec<_> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| super::Candidate {
                tag: node.name.as_str(),
                node,
                attribution: Vec::new(),
                selection_chain: vec![node.name.as_str()],
            })
            .collect();
        for tag in &group.groups {
            let Some(subgroup) = self.groups.get(tag.as_str()) else {
                continue;
            };
            if effects.applies() {
                self.mark_used(tag);
            }
            if let Some(mut candidate) =
                self.pick_candidate_for_target(subgroup, context, visited, depth + 1, effects)
            {
                candidate.tag = tag.as_str();
                candidates.push(candidate);
            }
        }
        visited.pop();
        candidates
    }

    /// Aggregate winner used by display/control surfaces.
    pub fn get_honk_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let group = self.groups.get(group_name)?;
        let context = HonkSelectionContext::aggregate(
            network,
            match network {
                SelectionNetwork::Tcp => ProbeDomain::Tcp,
                SelectionNetwork::Udp => ProbeDomain::DataUdp,
            },
            IpVersion::V4,
        );
        let mut visited = Vec::new();
        let mut candidates = self.flatten_candidates_for_target(
            group,
            &context,
            &mut visited,
            0,
            super::SelectionEffects::Peek,
        );
        candidates = self.filter_alive_candidates(
            candidates,
            context.probe_domain,
            context.health_family,
            group.check_url.as_deref(),
        );
        (!candidates.is_empty())
            .then(|| self.pick_honk(&candidates, group, &context).tag.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::group::{Group, GroupPolicy};

    fn node(name: &str) -> Node {
        Node {
            id: Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
            name: name.into(),
            ..Default::default()
        }
    }

    fn group(name: &str, nodes: &[Node]) -> Group {
        Group {
            id: Uuid::new_v4(),
            name: name.into(),
            policy: GroupPolicy::Honk,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }
    }

    fn context(host: &str, family: IpVersion) -> HonkSelectionContext {
        HonkSelectionContext {
            network: SelectionNetwork::Tcp,
            probe_domain: ProbeDomain::Tcp,
            target_family: Some(family),
            health_family: IpVersion::V4,
            target: Some(HonkTarget::domain(host, 443)),
        }
    }

    fn finish_success(plan: &super::super::HonkSelectionPlan<'_>) {
        let reporter = plan.entries[0]
            .feedback
            .as_ref()
            .expect("Honk candidate must carry feedback")
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(HonkOutcome::Success);
    }
    fn finish_failure(plan: &super::super::HonkSelectionPlan<'_>) {
        plan.entries[0]
            .feedback
            .as_ref()
            .expect("Honk candidate must carry feedback")
            .start()
            .setup_failed(HonkOutcome::Timeout);
    }

    fn selected(manager: &super::super::GroupManager, context: &HonkSelectionContext) -> Uuid {
        manager.selection_plan_for_target("honk", context).entries[0]
            .node
            .id
    }

    #[test]
    fn normalizes_domain_key_and_keeps_target_dimensions_independent() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);

        let a = context("EXAMPLE.COM.", IpVersion::V4);
        finish_success(&manager.selection_plan_for_target("honk", &a));
        let normalized = context("example.com", IpVersion::V4);
        assert!(
            manager
                .honk_state()
                .has_exact("honk", &normalized, nodes[0].id)
        );
        assert!(!manager.honk_state().has_exact(
            "honk",
            &context("example.com", IpVersion::V6),
            nodes[0].id,
        ));
        assert!(!manager.honk_state().has_exact(
            "honk",
            &context("other.example", IpVersion::V4),
            nodes[0].id,
        ));
    }

    #[test]
    fn cold_exploration_is_deterministic_and_cancelled_loser_is_neutral() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        let first = manager.selection_plan_for_target("honk", &context);
        assert_eq!(first.entries[0].node.id, nodes[0].id);
        drop(first.entries[0].feedback.as_ref().unwrap().start());
        assert_eq!(
            manager.selection_plan_for_target("honk", &context).entries[0]
                .node
                .id,
            nodes[0].id
        );
        finish_success(&manager.selection_plan_for_target("honk", &context));
        assert_eq!(
            manager.selection_plan_for_target("honk", &context).entries[0]
                .node
                .id,
            nodes[1].id,
            "the first useful success must release the next cold candidate"
        );
    }

    #[test]
    fn cancelled_exact_attempt_does_not_hide_aggregate_failure() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        manager
            .feedback_for_group_node(
                "honk",
                nodes[0].id,
                HonkSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap()
            .start()
            .setup_failed(HonkOutcome::Timeout);

        let context = context("cancelled.example", IpVersion::V4);
        drop(
            manager
                .feedback_for_group_node("honk", nodes[0].id, context.clone())
                .unwrap()
                .start(),
        );

        assert!(
            !manager
                .honk_state()
                .has_exact("honk", &context, nodes[0].id)
        );
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn reload_reuses_state_and_prunes_removed_members() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let context = context("example.com", IpVersion::V4);
        finish_success(&old.selection_plan_for_target("honk", &context));
        let state = old.honk_state();
        let replacement = super::super::GroupManager::with_alive_set_and_honk_state(
            &[group("honk", &nodes[1..])],
            &nodes[1..],
            None,
            Arc::clone(&state),
        );
        replacement.publish_honk_membership();
        assert!(!state.has_exact("honk", &context, nodes[0].id));
    }

    #[test]
    fn nested_honk_groups_keep_the_target_and_complete_attribution_path() {
        let nodes = [node("a"), node("b")];
        let child = group("child", &nodes);
        let mut parent = group("parent", &[]);
        parent.groups.push("child".into());
        let manager = super::super::GroupManager::new(&[child, parent], &nodes);
        let context = context("example.com", IpVersion::V6);

        let plan = manager.selection_plan_for_target("parent", &context);
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].selection_chain, ["parent", "child", "a"]);
        let feedback = plan.entries[0].feedback.as_ref().unwrap();
        assert_eq!(
            feedback
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
        finish_success(&plan);
        for group in ["parent", "child"] {
            assert!(manager.honk_state().has_exact(group, &context, nodes[0].id));
        }
    }

    #[test]
    fn feedback_for_node_merges_nested_honk_memberships_once() {
        let leaf = node("leaf");
        let other = node("other");
        let child = group("child", std::slice::from_ref(&leaf));
        let mut bridge = group("bridge", std::slice::from_ref(&leaf));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups = vec!["child".into(), "bridge".into()];
        let manager = super::super::GroupManager::new(
            &[
                child,
                bridge,
                parent,
                group("unrelated", std::slice::from_ref(&other)),
            ],
            &[leaf.clone(), other],
        );

        let feedback = manager
            .feedback_for_node(
                leaf.id,
                HonkSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .expect("nested Honk memberships must produce feedback");
        let mut groups = feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>();
        groups.sort_unstable();
        assert_eq!(groups, ["child", "parent"]);
    }
    #[test]
    fn nested_honk_last_resort_keeps_child_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );
        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
    }

    #[test]
    fn deep_honk_last_resort_keeps_every_attribution() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut middle = group("middle", &[]);
        middle.groups.push(child.name.clone());
        let mut outer = group("outer", &[]);
        outer.groups.push(middle.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, middle, outer],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan =
            manager.selection_plan_for_target("outer", &context("deep.example", IpVersion::V4));
        assert_eq!(
            plan.entries[0].selection_chain,
            ["outer", "middle", "child", "leaf"]
        );
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["outer", "middle", "child"]
        );
    }

    #[test]
    fn duplicate_direct_leaf_stays_direct_on_last_resort() {
        let leaf = node("leaf");
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(leaf.id, ProbeDomain::Tcp, IpVersion::V4);
        let child = group("child", std::slice::from_ref(&leaf));
        let mut parent = group("parent", std::slice::from_ref(&leaf));
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::with_alive_set(
            &[child, parent],
            std::slice::from_ref(&leaf),
            Some(alive),
        );

        let plan = manager
            .selection_plan_for_target("parent", &context("last-resort.example", IpVersion::V4));
        assert_eq!(plan.entries[0].selection_chain, ["parent", "leaf"]);
        assert_eq!(
            plan.entries[0]
                .feedback
                .as_ref()
                .unwrap()
                .attributions()
                .iter()
                .map(|attribution| attribution.group.as_str())
                .collect::<Vec<_>>(),
            ["parent"]
        );
    }

    #[test]
    fn duplicate_leaf_paths_do_not_change_honk_rank() {
        let nodes = [node("a"), node("b")];
        let mut bridge = group("bridge", std::slice::from_ref(&nodes[0]));
        bridge.policy = GroupPolicy::Selector;
        let mut parent = group("honk", &nodes);
        parent.groups.push(bridge.name.clone());
        let manager = super::super::GroupManager::new(&[parent, bridge], &nodes);
        let context = context("duplicate.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("honk", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn aggregate_feedback_completion_and_cancellation_are_accounted_once() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("honk", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let feedback = manager
            .feedback_for_node(
                leaf.id,
                HonkSelectionContext::aggregate(
                    SelectionNetwork::Tcp,
                    ProbeDomain::Tcp,
                    IpVersion::V4,
                ),
            )
            .unwrap();

        drop(feedback.start());
        assert_eq!(
            manager
                .honk_state()
                .aggregate_stats("honk", SelectionNetwork::Tcp, leaf.id),
            None
        );
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish(HonkOutcome::Success);
        assert_eq!(
            manager
                .honk_state()
                .aggregate_stats("honk", SelectionNetwork::Tcp, leaf.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn setup_only_success_does_not_become_usefulness_failure() {
        let leaf = node("leaf");
        let manager = super::super::GroupManager::new(
            &[group("honk", std::slice::from_ref(&leaf))],
            std::slice::from_ref(&leaf),
        );
        let context = context("prepared.example", IpVersion::V4);
        let feedback = manager.selection_plan_for_target("honk", &context).entries[0]
            .feedback
            .clone()
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();
        assert_eq!(
            manager
                .honk_state()
                .exact_useful_failures("honk", &context, leaf.id),
            Some(0)
        );

        let related = reporter.feedback().start();
        related.setup_succeeded();
        related.finish_setup_only();

        assert_eq!(
            manager
                .honk_state()
                .exact_useful_failures("honk", &context, leaf.id),
            Some(0)
        );
    }

    #[test]
    fn setup_only_exact_samples_keep_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "honk",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V4),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(HonkOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("honk", nodes[1].id, context("b.example", IpVersion::V4))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(HonkOutcome::Success);

        let target = context("prepared.example", IpVersion::V4);
        for _ in 0..8 {
            let reporter = manager
                .feedback_for_group_node("honk", nodes[0].id, target.clone())
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.finish_setup_only();
        }

        assert_eq!(selected(&manager, &target), nodes[0].id);
    }

    #[test]
    fn setup_only_family_samples_keep_global_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        for index in 0..8 {
            let reporter = manager
                .feedback_for_group_node(
                    "honk",
                    nodes[0].id,
                    context(&format!("a-{index}.example"), IpVersion::V6),
                )
                .unwrap()
                .start();
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(HonkOutcome::Success);
        }
        let reporter = manager
            .feedback_for_group_node("honk", nodes[1].id, context("b.example", IpVersion::V6))
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(HonkOutcome::Success);

        let reporter = manager
            .feedback_for_group_node(
                "honk",
                nodes[0].id,
                context("prepared.example", IpVersion::V4),
            )
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.finish_setup_only();

        assert_eq!(
            selected(&manager, &context("fresh.example", IpVersion::V4)),
            nodes[0].id
        );
    }

    #[test]
    fn compact_outcome_finds_nested_io_errors() {
        let error = anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "secret target"))
            .context("outer context");
        assert_eq!(HonkOutcome::from_error(&error), HonkOutcome::Timeout);
    }

    #[test]
    fn exact_cache_has_a_hard_lru_bound() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("honk", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        for index in 0..=EXACT_CAPACITY {
            finish_success(&manager.selection_plan_for_target(
                "honk",
                &context(&format!("{index}.example"), IpVersion::V4),
            ));
        }
        assert_eq!(manager.honk_state().exact_len(), EXACT_CAPACITY);
    }

    #[test]
    fn setup_failure_switches_to_the_other_candidate() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let context = context("failure.example", IpVersion::V4);

        assert_eq!(selected(&manager, &context), nodes[0].id);
        finish_failure(&manager.selection_plan_for_target("honk", &context));
        assert_eq!(selected(&manager, &context), nodes[1].id);
    }

    #[test]
    fn inflight_exact_attempt_does_not_mask_aggregate_reliability() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let aggregate =
            HonkSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
        manager
            .feedback_for_group_node("honk", nodes[0].id, aggregate.clone())
            .unwrap()
            .start()
            .setup_failed(HonkOutcome::Other);
        let good = manager
            .feedback_for_group_node("honk", nodes[1].id, aggregate)
            .unwrap()
            .start();
        good.setup_succeeded();
        good.finish_setup_only();
        let target = context("inflight.example", IpVersion::V4);
        let inflight = manager
            .feedback_for_group_node("honk", nodes[0].id, target.clone())
            .unwrap()
            .start();

        assert_eq!(selected(&manager, &target), nodes[1].id);

        drop(inflight);
    }

    #[test]
    fn network_target_and_family_buckets_are_isolated() {
        let nodes = [node("a"), node("b")];
        let manager = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let tcp_a_v4 = context("a.example", IpVersion::V4);
        finish_failure(&manager.selection_plan_for_target("honk", &tcp_a_v4));

        let mut udp_a_v4 = tcp_a_v4.clone();
        udp_a_v4.network = SelectionNetwork::Udp;
        udp_a_v4.probe_domain = ProbeDomain::DataUdp;
        let tcp_b_v4 = context("b.example", IpVersion::V4);
        let tcp_a_v6 = context("a.example", IpVersion::V6);
        let state = manager.honk_state();

        assert_eq!(
            state.exact_stats("honk", &tcp_a_v4, nodes[0].id),
            Some((1, 0, 1))
        );
        for untouched in [&udp_a_v4, &tcp_b_v4, &tcp_a_v6] {
            assert_eq!(state.exact_stats("honk", untouched, nodes[0].id), None);
        }
        finish_success(&manager.selection_plan_for_target("honk", &tcp_b_v4));
        assert_eq!(
            state.exact_stats("honk", &tcp_b_v4, nodes[1].id),
            Some((1, 1, 0))
        );
        assert_eq!(state.exact_stats("honk", &tcp_a_v4, nodes[1].id), None);
    }

    #[test]
    fn dead_candidate_is_excluded_before_scoring() {
        let nodes = [node("a"), node("b")];
        let alive = Arc::new(super::super::AliveDialerSet::new());
        alive.report_unavailable_forced(nodes[0].id, ProbeDomain::Tcp, IpVersion::V4);
        let manager = super::super::GroupManager::with_alive_set(
            &[group("honk", &nodes)],
            &nodes,
            Some(alive),
        );

        assert_eq!(
            selected(&manager, &context("dead.example", IpVersion::V4)),
            nodes[1].id
        );
    }

    #[test]
    fn aggregate_cache_has_a_hard_lru_bound() {
        let state = HonkPolicyState::default();
        let node_id = node("a").id;
        let context =
            HonkSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        for (group, node_id) in memberships {
            drop(state.start(&context, &[HonkAttribution { group, node_id }]));
        }
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
    }

    #[test]
    fn stale_exact_completion_does_not_mutate_recreated_cell() {
        let node = node("a");
        let manager = super::super::GroupManager::new(
            &[group("honk", std::slice::from_ref(&node))],
            std::slice::from_ref(&node),
        );
        let evicted = context("evicted.example", IpVersion::V4);
        let reporter = manager.selection_plan_for_target("honk", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        for index in 0..EXACT_CAPACITY {
            let context = context(&format!("{index}.example"), IpVersion::V4);
            finish_success(&manager.selection_plan_for_target("honk", &context));
        }
        let replacement = manager.selection_plan_for_target("honk", &evicted).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(HonkOutcome::Success);
        assert_eq!(
            manager.honk_state().exact_stats("honk", &evicted, node.id),
            Some((1, 0, 0))
        );
        replacement.setup_succeeded();
        replacement.tx(1);
        replacement.rx(1);
        replacement.finish(HonkOutcome::Success);
        assert_eq!(
            manager.honk_state().exact_stats("honk", &evicted, node.id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn stale_aggregate_completion_does_not_mutate_recreated_cell() {
        let state = HonkPolicyState::default();
        let node_id = node("a").id;
        let context =
            HonkSelectionContext::aggregate(SelectionNetwork::Tcp, ProbeDomain::Tcp, IpVersion::V4);
        let memberships: Vec<_> = (0..=AGGREGATE_CAPACITY)
            .map(|index| (format!("group-{index}"), node_id))
            .collect();
        state.publish_membership(memberships.iter().cloned());
        let evicted = HonkAttribution {
            group: memberships[0].0.clone(),
            node_id,
        };
        let stale_cells = state.start(&context, std::slice::from_ref(&evicted));
        for (group, node_id) in memberships.iter().skip(1) {
            drop(state.start(
                &context,
                &[HonkAttribution {
                    group: group.clone(),
                    node_id: *node_id,
                }],
            ));
        }
        let current_cells = state.start(&context, std::slice::from_ref(&evicted));
        let sample = FlowSample {
            outcome: HonkOutcome::Success,
            setup: Some(Duration::ZERO),
            first_response: None,
            tx: 1,
            rx: 1,
            elapsed: Duration::from_millis(1),
            count_usefulness: true,
        };
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &stale_cells,
            &sample,
        );
        assert_eq!(state.inner.lock().aggregate.len(), AGGREGATE_CAPACITY);
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 0, 0))
        );
        state.finish(
            &context,
            std::slice::from_ref(&evicted),
            &current_cells,
            &sample,
        );
        assert_eq!(
            state.aggregate_stats(&evicted.group, SelectionNetwork::Tcp, node_id),
            Some((1, 1, 0))
        );
    }

    #[test]
    fn builtin_direct_final_is_valid_feedback_membership() {
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(honk_config::Config::BUILTIN_DIRECT_NODE.into());
        let manager = super::super::GroupManager::new(&[outer], &[]);
        let context = context("final-direct.example", IpVersion::V4);
        let feedback = manager
            .feedback_for_group_node(
                "outer",
                honk_config::config::DIRECT_NODE_ID,
                context.clone(),
            )
            .unwrap();
        let reporter = feedback.start();
        reporter.setup_succeeded();
        reporter.tx(1);
        reporter.rx(1);
        reporter.finish(HonkOutcome::Success);
        assert!(manager.honk_state().has_exact(
            "outer",
            &context,
            honk_config::config::DIRECT_NODE_ID
        ));
    }

    #[test]
    fn aggregate_display_does_not_advance_nested_load_balance() {
        let nodes = [node("a"), node("b")];
        let mut child = group("child", &nodes);
        child.policy = GroupPolicy::LoadBalance;
        let mut parent = group("parent", &[]);
        parent.groups.push(child.name.clone());
        let manager = super::super::GroupManager::new(&[parent, child], &nodes);

        assert_eq!(
            manager.get_honk_selection_for_network("parent", SelectionNetwork::Tcp),
            Some("child".into())
        );
        assert_eq!(manager.select_node("child").unwrap().id, nodes[0].id);
    }

    #[test]
    fn late_completion_keeps_extant_member_and_drops_deleted_member() {
        let nodes = [node("a"), node("b")];
        let old = super::super::GroupManager::new(&[group("honk", &nodes)], &nodes);
        let context = context("reload.example", IpVersion::V4);
        let reporter_a = old.selection_plan_for_target("honk", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        finish_success(&old.selection_plan_for_target("honk", &context));
        let reporter_b = old.selection_plan_for_target("honk", &context).entries[0]
            .feedback
            .as_ref()
            .unwrap()
            .start();
        let state = old.honk_state();
        let replacement = super::super::GroupManager::with_alive_set_and_honk_state(
            &[group("honk", &nodes[..1])],
            &nodes[..1],
            None,
            Arc::clone(&state),
        );
        replacement.publish_honk_membership();

        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(HonkOutcome::Success);
        }
        assert!(state.has_exact("honk", &context, nodes[0].id));
        assert!(!state.has_exact("honk", &context, nodes[1].id));
    }

    #[test]
    fn final_outbound_late_completion_keeps_extant_leaf_and_drops_deleted_leaf() {
        let leaves = [node("final-a"), node("final-b")];
        let mut final_group = group("final-group", &leaves);
        final_group.policy = GroupPolicy::Selector;
        let mut outer = group("outer", &[]);
        outer.final_outbound = Some(final_group.name.clone());
        let old = super::super::GroupManager::new(&[outer.clone(), final_group.clone()], &leaves);
        let context = context("final.example", IpVersion::V4);
        let reporter_a = old
            .feedback_for_group_node("outer", leaves[0].id, context.clone())
            .unwrap()
            .start();
        let reporter_b = old
            .feedback_for_group_node("outer", leaves[1].id, context.clone())
            .unwrap()
            .start();
        let state = old.honk_state();
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[0].id))
        );
        assert!(
            state
                .inner
                .lock()
                .valid
                .contains(&("outer".into(), leaves[1].id))
        );

        final_group.nodes.retain(|node_id| *node_id == leaves[0].id);
        let replacement = super::super::GroupManager::with_alive_set_and_honk_state(
            &[outer, final_group],
            std::slice::from_ref(&leaves[0]),
            None,
            Arc::clone(&state),
        );
        replacement.publish_honk_membership();
        for reporter in [&reporter_a, &reporter_b] {
            reporter.setup_succeeded();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(HonkOutcome::Success);
        }

        assert!(state.has_exact("outer", &context, leaves[0].id));
        assert!(!state.has_exact("outer", &context, leaves[1].id));
    }
}
