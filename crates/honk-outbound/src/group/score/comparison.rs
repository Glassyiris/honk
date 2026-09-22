use super::evidence::Observation;
use super::ranking::{normal_eligible, utility};
use super::verification::{TimedMetric, VerificationEvidence};
use super::{
    AggregateKey, ExactKey, MAX_THROUGHPUT_DURATION, MIN_THROUGHPUT_BYTES, MIN_THROUGHPUT_DURATION,
    ScoreAttribution, ScoreSelectionContext, ScoreSnapshot, ScoreSource, ScoreTarget, StartedCells,
    StateInner, Stats,
};
use honk_config::node::Node;
use std::cmp::Ordering;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use uuid::Uuid;

mod summary;
pub(super) use summary::summarize;

pub(super) const MAX_CELLS: usize = 256;
pub(super) const MAX_TARGETS: usize = 8;
pub(super) const MAX_CHALLENGERS: usize = 4;
pub(super) const MAX_LOGICAL_BYTES: usize = 1024 * 1024;
const MAX_KEY_BYTES: usize = 1024;
const BLOCK_SECONDS: u64 = 15;
const BLOCKS: usize = 4;
const LIFETIME: Duration = Duration::from_secs(BLOCK_SECONDS * BLOCKS as u64);
const REPORTERS: usize = 4;

pub(super) fn next_reporter_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |id| {
        id.checked_add(1)
    })
    .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Basis {
    #[default]
    None,
    ExactTarget,
    CommonTargets,
    ConfiguredProbe,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct MetricPair {
    pub incumbent: f64,
    pub candidate: f64,
    pub reporters: u8,
    pub span: Duration,
    pub oldest_at: Instant,
    pub latest_at: Instant,
    pub expires_at: Instant,
    pub dispersion: f64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PairEvidence {
    pub basis: Basis,
    pub response: Option<MetricPair>,
    pub upload: Option<MetricPair>,
    pub download: Option<MetricPair>,
    pub partial: bool,
    // Fingerprints describe selected keys/blocks, never measured values or raw API targets.
    pub support: u64,
}

pub(super) struct PairCohort {
    pub reference: usize,
    pub pairs: [Option<(usize, PairEvidence)>; MAX_CHALLENGERS],
}

impl PairCohort {
    pub fn get(&self, index: usize) -> Option<PairEvidence> {
        self.pairs
            .iter()
            .flatten()
            .find_map(|(candidate, pair)| (*candidate == index).then_some(*pair))
    }
}

#[derive(Clone, Copy, Default)]
struct Bucket {
    block: u64,
    count: u32,
    sum: f64,
    min: f64,
    max: f64,
    first: Option<Instant>,
    last: Option<Instant>,
    reporters: [u64; REPORTERS],
}

impl Bucket {
    fn record(&mut self, block: u64, value: f64, reporter: u64, now: Instant) {
        if self.count == 0 || self.block != block {
            *self = Self {
                block,
                min: value,
                max: value,
                first: Some(now),
                ..Self::default()
            };
        }
        if self.count == u32::MAX {
            return;
        }
        self.count += 1;
        self.sum += value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.first = Some(self.first.map_or(now, |at| at.min(now)));
        self.last = Some(self.last.map_or(now, |at| at.max(now)));
        if !self.reporters.contains(&reporter)
            && let Some(slot) = self.reporters.iter_mut().find(|id| **id == 0)
        {
            *slot = reporter;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum Key {
    Traffic(ExactKey),
    Probe {
        key: AggregateKey,
        scope: u64,
        slot: usize,
        interval: Option<Duration>,
    },
}

impl Key {
    fn group(&self) -> &str {
        match self {
            Self::Traffic(key) => &key.group,
            Self::Probe { key, .. } => &key.group,
        }
    }

    fn node(&self) -> Uuid {
        match self {
            Self::Traffic(key) => key.node_id,
            Self::Probe { key, .. } => key.node_id,
        }
    }

    fn network(&self) -> super::SelectionNetwork {
        match self {
            Self::Traffic(key) => key.network,
            Self::Probe { key, .. } => key.network,
        }
    }

    fn timing(&self) -> Option<Timing> {
        let interval = match self {
            Self::Probe { interval, .. } => *interval,
            Self::Traffic(_) => None,
        };
        let doubled = match interval {
            Some(interval) if !interval.is_zero() => interval.checked_mul(2)?,
            Some(_) => return None,
            None => Duration::ZERO,
        };
        let width = Duration::from_secs(BLOCK_SECONDS).max(doubled);
        width.checked_mul(BLOCKS as u32)?;
        Some(Timing {
            width,
            freshness: LIFETIME.max(doubled),
        })
    }

    fn heap_bytes(&self) -> usize {
        match self {
            Self::Traffic(key) => key.group.capacity() + target_bytes(&key.target),
            Self::Probe { key, .. } => key.group.capacity(),
        }
    }

    fn cohort_cmp(&self, other: &Self) -> Ordering {
        self.group()
            .cmp(other.group())
            .then_with(|| (self.network() as u8).cmp(&(other.network() as u8)))
            .then_with(|| match (self, other) {
                (Self::Traffic(left), Self::Traffic(right)) => (left.family as u8)
                    .cmp(&(right.family as u8))
                    .then_with(|| target_cmp(&left.target, &right.target)),
                (
                    Self::Probe {
                        scope: left,
                        slot: a,
                        interval: left_interval,
                        ..
                    },
                    Self::Probe {
                        scope: right,
                        slot: b,
                        interval: right_interval,
                        ..
                    },
                ) => a
                    .cmp(b)
                    .then_with(|| left.cmp(right))
                    .then_with(|| left_interval.cmp(right_interval)),
                (Self::Traffic(_), Self::Probe { .. }) => Ordering::Less,
                (Self::Probe { .. }, Self::Traffic(_)) => Ordering::Greater,
            })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        self.cohort_cmp(other)
            .then_with(|| self.node().cmp(&other.node()))
    }

    fn stats<'a>(&self, inner: &'a StateInner) -> Option<&'a Stats> {
        match self {
            Self::Traffic(key) => inner.exact.peek(key),
            Self::Probe { key, .. } => inner.aggregate.peek(key),
        }
    }
}

#[derive(Clone, Copy)]
struct Timing {
    width: Duration,
    freshness: Duration,
}

impl Timing {
    fn deadline(self, origin: Instant, block: u64) -> Option<Instant> {
        let nanos = self
            .width
            .as_nanos()
            .checked_mul(u128::from(block.checked_add(BLOCKS as u64)?))?;
        let duration = Duration::new(
            u64::try_from(nanos / 1_000_000_000).ok()?,
            (nanos % 1_000_000_000) as u32,
        );
        origin.checked_add(duration)
    }

    fn common(self, left: &Bucket, right: &Bucket, origin: Instant, now: Instant) -> bool {
        left.count > 0
            && right.count > 0
            && left.block == right.block
            && left.last.is_some_and(|at| at <= now)
            && right.last.is_some_and(|at| at <= now)
            && self
                .deadline(origin, left.block)
                .is_some_and(|until| now < until)
    }
}

fn target_bytes(target: &ScoreTarget) -> usize {
    match target {
        ScoreTarget::Domain { host, .. } => host.capacity(),
        ScoreTarget::Socket(_) => 0,
    }
}

fn target_cmp(left: &ScoreTarget, right: &ScoreTarget) -> Ordering {
    match (left, right) {
        (ScoreTarget::Domain { host: a, port: ap }, ScoreTarget::Domain { host: b, port: bp }) => {
            a.cmp(b).then_with(|| ap.cmp(bp))
        }
        (ScoreTarget::Socket(a), ScoreTarget::Socket(b)) => a.cmp(b),
        (ScoreTarget::Domain { .. }, ScoreTarget::Socket(_)) => Ordering::Less,
        (ScoreTarget::Socket(_), ScoreTarget::Domain { .. }) => Ordering::Greater,
    }
}

struct Cell {
    key: Key,
    incarnation: u64,
    invalidated_through: Option<Instant>,
    metrics: [[Bucket; BLOCKS]; 3],
    touched: Instant,
}

impl Cell {
    fn valid(&self, inner: &StateInner) -> bool {
        self.key.stats(inner).is_some_and(|stats| {
            stats.incarnation == self.incarnation
                && stats.business_invalidated_through == self.invalidated_through
                && match &self.key {
                    Key::Probe { scope, slot, .. } => stats.probes[*slot].scope == *scope,
                    Key::Traffic(_) => true,
                }
        })
    }
}

#[derive(Default)]
pub(super) struct Store {
    cells: Vec<Cell>,
    origin: Option<Instant>,
    key_bytes: usize,
    pub expired: u64,
    pub evicted: u64,
    pub rejected: u64,
}

// Vec has no hidden per-entry links/buckets. String capacities, the Vec's full
// allocation and the Store itself are all charged, including unused slots.
const _: () = assert!(
    size_of::<Store>() + MAX_CELLS * (size_of::<Cell>() + MAX_KEY_BYTES) <= MAX_LOGICAL_BYTES
);

impl Store {
    pub(super) fn clear(&mut self) {
        self.cells.clear();
        self.key_bytes = 0;
        self.origin = None;
    }

    pub(super) fn logical_bytes(&self) -> usize {
        size_of::<Self>() + self.cells.capacity() * size_of::<Cell>() + self.key_bytes
    }

    pub(super) fn cell_count(&self) -> usize {
        self.cells.len()
    }

    pub(super) fn logical_capacity_bound() -> usize {
        size_of::<Self>() + MAX_CELLS * (size_of::<Cell>() + MAX_KEY_BYTES)
    }

    fn remove(&mut self, index: usize) {
        self.key_bytes -= self.cells.remove(index).key.heap_bytes();
    }

    fn record(
        &mut self,
        key: Key,
        stats: &Stats,
        values: [Option<f64>; 3],
        reporter: u64,
        now: Instant,
    ) {
        if let Key::Probe {
            key, scope, slot, ..
        } = &key
            && stats.probes[*slot].scope != *scope
        {
            // Stats still holds the previous scope until this observation is published.
            let mut index = 0;
            while index < self.cells.len() {
                if matches!(&self.cells[index].key, Key::Probe { key: old, slot: old_slot, .. }
                    if old == key && old_slot == slot)
                {
                    self.remove(index);
                } else {
                    index += 1;
                }
            }
        }
        if reporter == 0
            || stats
                .business_invalidated_through
                .is_some_and(|at| now <= at)
        {
            return;
        }
        let Some(timing) = key.timing() else {
            return;
        };
        let origin = *self.origin.get_or_insert(now);
        let Some(elapsed) = now.checked_duration_since(origin) else {
            return;
        };
        let Ok(block) = u64::try_from(elapsed.as_nanos() / timing.width.as_nanos()) else {
            return;
        };
        if timing.deadline(origin, block).is_none() {
            return;
        }
        let heap = key.heap_bytes();
        if heap > MAX_KEY_BYTES {
            self.rejected = self.rejected.saturating_add(1);
            return;
        }
        let mut index = self.cells.binary_search_by(|cell| cell.key.cmp(&key));
        if index.is_err() {
            let mut position = 0;
            while position < self.cells.len() {
                let cell = &self.cells[position];
                if cell.key.timing().is_none_or(|timing| {
                    now.saturating_duration_since(cell.touched) >= timing.freshness
                }) {
                    self.remove(position);
                    self.expired = self.expired.saturating_add(1);
                } else {
                    position += 1;
                }
            }
            if self.cells.len() == MAX_CELLS
                && let Some((oldest, _)) = self
                    .cells
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, cell)| cell.touched)
            {
                self.remove(oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
            if self.cells.capacity() == 0 {
                self.cells.reserve_exact(MAX_CELLS);
            }
            if self.logical_bytes().saturating_add(heap) > MAX_LOGICAL_BYTES {
                self.rejected = self.rejected.saturating_add(1);
                return;
            }
            index = self.cells.binary_search_by(|cell| cell.key.cmp(&key));
        }
        let index = match index {
            Ok(index) => index,
            Err(index) => {
                self.key_bytes += heap;
                self.cells.insert(
                    index,
                    Cell {
                        key,
                        incarnation: stats.incarnation,
                        invalidated_through: stats.business_invalidated_through,
                        metrics: [[Bucket::default(); BLOCKS]; 3],
                        touched: now,
                    },
                );
                index
            }
        };
        let cell = &mut self.cells[index];
        if cell.incarnation != stats.incarnation
            || cell.invalidated_through != stats.business_invalidated_through
        {
            cell.metrics = [[Bucket::default(); BLOCKS]; 3];
            cell.incarnation = stats.incarnation;
            cell.invalidated_through = stats.business_invalidated_through;
        }
        cell.touched = cell.touched.max(now);
        for (metric, value) in cell.metrics.iter_mut().zip(values) {
            if let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) {
                let bucket = &mut metric[block as usize % BLOCKS];
                // A delayed callback cannot overwrite a newer block in the ring.
                if bucket.count == 0 || bucket.block <= block {
                    bucket.record(block, value, reporter, now);
                }
            }
        }
    }
}

pub(super) fn observe(
    inner: &mut StateInner,
    context: &ScoreSelectionContext,
    attributions: &[ScoreAttribution],
    (cells, reporter_id): (&[StartedCells], u64),
    source: ScoreSource,
    observation: &Observation,
    now: Instant,
) {
    if reporter_id == 0 && source != ScoreSource::HealthProbe {
        return;
    }
    let values = match (source, observation) {
        (ScoreSource::Traffic, Observation::Response(latency)) => {
            [Some(latency.as_secs_f64() * 1000.0), None, None]
        }
        (ScoreSource::Traffic, Observation::Transfer { tx, rx, elapsed })
            if *elapsed >= MIN_THROUGHPUT_DURATION && *elapsed <= MAX_THROUGHPUT_DURATION =>
        {
            [
                None,
                (*tx >= MIN_THROUGHPUT_BYTES).then(|| *tx as f64 / elapsed.as_secs_f64()),
                (*rx >= MIN_THROUGHPUT_BYTES).then(|| *rx as f64 / elapsed.as_secs_f64()),
            ]
        }
        (ScoreSource::HealthProbe, Observation::Probe { latency, .. }) => {
            [Some(latency.as_secs_f64() * 1000.0), None, None]
        }
        _ => return,
    };
    for (attribution, started) in attributions.iter().zip(cells) {
        if attribution.group.len() > MAX_KEY_BYTES {
            inner.comparisons.rejected = inner.comparisons.rejected.saturating_add(1);
            continue;
        }
        let (key, captured) = match observation {
            Observation::Probe {
                scope,
                slot,
                interval,
                ..
            } => (
                Key::Probe {
                    key: AggregateKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family: None,
                        node_id: attribution.node_id,
                    },
                    scope: *scope,
                    slot: *slot,
                    interval: *interval,
                },
                started.aggregate[0],
            ),
            _ => {
                let (Some(family), Some(target)) = (context.target_family, context.target.as_ref())
                else {
                    continue;
                };
                if attribution.group.len().saturating_add(target_bytes(target)) > MAX_KEY_BYTES {
                    inner.comparisons.rejected = inner.comparisons.rejected.saturating_add(1);
                    continue;
                }
                (
                    Key::Traffic(ExactKey {
                        group: attribution.group.clone(),
                        network: context.network,
                        family,
                        target: target.clone(),
                        node_id: attribution.node_id,
                    }),
                    started.exact,
                )
            }
        };
        // Only the admitted incarnation may publish; evicted cells are not recreated here.
        let stats = match &key {
            Key::Traffic(key) => inner.exact.peek(key),
            Key::Probe { key, .. } => inner.aggregate.peek(key),
        };
        if let Some(stats) = stats.filter(|stats| captured == Some(stats.incarnation)) {
            inner
                .comparisons
                .record(key, stats, values, reporter_id, now);
        }
    }
}

#[derive(Default)]
struct Accumulator {
    sum: f64,
    count: u64,
    min: Option<f64>,
    max: f64,
    first: Option<Instant>,
    last: Option<Instant>,
    reporters: [u64; BLOCKS * REPORTERS],
}

impl Accumulator {
    fn add(&mut self, bucket: &Bucket) {
        // Both nodes receive the same time-block weight despite different offered load.
        self.sum += bucket.sum / f64::from(bucket.count);
        self.count += 1;
        self.min = Some(self.min.map_or(bucket.min, |value| value.min(bucket.min)));
        self.max = self.max.max(bucket.max);
        if let Some(at) = bucket.first {
            self.first = Some(self.first.map_or(at, |old| old.min(at)));
        }
        if let Some(at) = bucket.last {
            self.last = Some(self.last.map_or(at, |old| old.max(at)));
        }
        for id in bucket.reporters.into_iter().filter(|id| *id != 0) {
            if !self.reporters.contains(&id)
                && let Some(slot) = self.reporters.iter_mut().find(|value| **value == 0)
            {
                *slot = id;
            }
        }
    }

    fn reporters(&self) -> usize {
        self.reporters.iter().filter(|id| **id != 0).count()
    }
}

fn metric_pair(
    left: &[Bucket; BLOCKS],
    right: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
) -> Option<MetricPair> {
    let mut a = Accumulator::default();
    let mut b = Accumulator::default();
    let mut expires = None;
    for (left, right) in left.iter().zip(right) {
        if !timing.common(left, right, origin, now) {
            continue;
        }
        let until = timing.deadline(origin, left.block)?;
        a.add(left);
        b.add(right);
        expires = Some(expires.map_or(until, |old: Instant| old.min(until)));
    }
    let reporters = a.reporters().min(b.reporters());
    if reporters < REPORTERS {
        return None;
    }
    let latest_at = a.last?.min(b.last?);
    let expires_at = expires?.min(latest_at.checked_add(timing.freshness)?);
    if now >= expires_at {
        return None;
    }
    let left = a.sum / a.count as f64;
    let right = b.sum / b.count as f64;
    Some(MetricPair {
        incumbent: left,
        candidate: right,
        reporters: reporters as u8,
        span: a
            .last?
            .saturating_duration_since(a.first?)
            .min(b.last?.saturating_duration_since(b.first?)),
        oldest_at: a.first?.min(b.first?),
        latest_at,
        expires_at,
        dispersion: ((a.max - a.min?) / left.max(1.0)).max((b.max - b.min?) / right.max(1.0)),
    })
}

fn has_common_block(left: &Cell, right: &Cell, origin: Instant, now: Instant) -> bool {
    left.key.timing().is_some_and(|timing| {
        left.metrics
            .iter()
            .zip(&right.metrics)
            .any(|(left, right)| {
                left.iter()
                    .zip(right)
                    .any(|(a, b)| timing.common(a, b, origin, now))
            })
    })
}

fn merge_metric(acc: &mut Option<MetricPair>, next: Option<MetricPair>, count: usize) {
    *acc = match (*acc, next) {
        (_, Some(next)) if count == 0 => Some(next),
        (Some(old), Some(next)) => Some(MetricPair {
            incumbent: old.incumbent + next.incumbent,
            candidate: old.candidate + next.candidate,
            reporters: old.reporters.min(next.reporters),
            span: old.span.min(next.span),
            oldest_at: old.oldest_at.min(next.oldest_at),
            latest_at: old.latest_at.min(next.latest_at),
            expires_at: old.expires_at.min(next.expires_at),
            dispersion: old.dispersion.max(next.dispersion),
        }),
        _ => None,
    };
}

fn paired_cell(
    left: &Cell,
    right: &Cell,
    origin: Instant,
    now: Instant,
    basis: Basis,
) -> PairEvidence {
    use std::hash::{Hash, Hasher};
    let mut result = PairEvidence {
        basis,
        ..PairEvidence::default()
    };
    let Some(timing) = left.key.timing() else {
        return result;
    };
    let mut support = std::collections::hash_map::DefaultHasher::new();
    match &left.key {
        Key::Traffic(key) => {
            key.target.hash(&mut support);
            (key.family as u8).hash(&mut support);
        }
        Key::Probe { scope, slot, .. } => {
            scope.hash(&mut support);
            slot.hash(&mut support);
        }
    }
    for (metric_index, ((a, b), output)) in left
        .metrics
        .iter()
        .zip(&right.metrics)
        .zip([
            &mut result.response,
            &mut result.upload,
            &mut result.download,
        ])
        .enumerate()
    {
        metric_index.hash(&mut support);
        for (a, b) in a.iter().zip(b) {
            timing
                .common(a, b, origin, now)
                .then_some(a.block)
                .hash(&mut support);
        }
        *output = metric_pair(a, b, origin, now, timing);
    }
    result.support = support.finish();
    result
}

fn compare(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    incumbent: Uuid,
    candidate: Uuid,
    now: Instant,
) -> PairEvidence {
    use std::hash::{Hash, Hasher};
    let empty = PairEvidence::default();
    let Some(origin) = inner.comparisons.origin else {
        return empty;
    };
    let mut common = PairEvidence {
        basis: Basis::CommonTargets,
        ..empty
    };
    let mut support = std::collections::hash_map::DefaultHasher::new();
    let mut count = 0;
    let mut exact = None;
    let mut probe = None;
    let mut pending: Option<&Cell> = None;
    // Sorted cohorts allow a single bounded store scan, without an all-pairs index.
    for cell in &inner.comparisons.cells {
        if cell.key.group() != group
            || cell.key.network() != context.network
            || ![incumbent, candidate].contains(&cell.key.node())
            || !cell.valid(inner)
        {
            continue;
        }
        if let Some(previous) = pending
            && previous.key.cohort_cmp(&cell.key) == Ordering::Equal
            && previous.key.node() != cell.key.node()
        {
            let pair = if previous.key.node() == incumbent {
                (previous, cell)
            } else {
                (cell, previous)
            };
            if has_common_block(pair.0, pair.1, origin, now) {
                match &cell.key {
                    Key::Traffic(key)
                        if context
                            .target_family
                            .is_none_or(|family| family == key.family) =>
                    {
                        if count == MAX_TARGETS && context.target.as_ref() != Some(&key.target) {
                            common.partial = true;
                            pending = None;
                            continue;
                        }
                        let pair = paired_cell(pair.0, pair.1, origin, now, Basis::ExactTarget);
                        if context.target.as_ref() == Some(&key.target) {
                            exact = Some(pair);
                        }
                        // Qualification, never magnitude, selects the canonical response cohort.
                        if pair.response.is_some() && count < MAX_TARGETS {
                            merge_metric(&mut common.response, pair.response, count);
                            merge_metric(&mut common.upload, pair.upload, count);
                            merge_metric(&mut common.download, pair.download, count);
                            pair.support.hash(&mut support);
                            count += 1;
                        } else {
                            common.partial = true;
                        }
                    }
                    Key::Probe { slot, .. }
                        if *slot == super::evidence::probe_slot(context) && probe.is_none() =>
                    {
                        probe = Some(paired_cell(
                            pair.0,
                            pair.1,
                            origin,
                            now,
                            Basis::ConfiguredProbe,
                        ));
                    }
                    _ => {}
                }
            }
            pending = None;
        } else {
            pending = Some(cell);
        }
    }
    common.support = support.finish();
    if count == 0 {
        common.basis = Basis::None;
    }
    for metric in [
        &mut common.response,
        &mut common.upload,
        &mut common.download,
    ]
    .into_iter()
    .flatten()
    {
        metric.incumbent /= count as f64;
        metric.candidate /= count as f64;
    }
    let mut result = exact.unwrap_or(empty);
    if result.response.is_none() && result.upload.is_none() && result.download.is_none() {
        result = common;
    }
    if result.response.is_none()
        && let Some(pair) = probe
    {
        // Do not combine business rates with an unrelated proxy-probe response.
        result = pair;
    }
    result
}

pub(super) fn node_evidence(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    now: Instant,
) -> Vec<VerificationEvidence> {
    let mut evidence: Vec<_> = nodes
        .iter()
        .map(|node| {
            let stats = if let (Some(family), Some(target)) =
                (context.target_family, context.target.as_ref())
            {
                inner.exact.peek(&ExactKey {
                    group: group.to_owned(),
                    network: context.network,
                    family,
                    target: target.clone(),
                    node_id: node.id,
                })
            } else if context.target.is_none() {
                inner.aggregate.peek(&AggregateKey {
                    group: group.to_owned(),
                    network: context.network,
                    family: context.target_family,
                    node_id: node.id,
                })
            } else {
                None
            };
            stats.map_or_else(VerificationEvidence::default, |stats| {
                VerificationEvidence::new(stats, now)
            })
        })
        .collect();
    let Some(origin) = inner.comparisons.origin else {
        return evidence;
    };
    for cell in &inner.comparisons.cells {
        if cell.key.group() != group || cell.key.network() != context.network || !cell.valid(inner)
        {
            continue;
        }
        let Some(index) = nodes.iter().position(|node| node.id == cell.key.node()) else {
            continue;
        };
        let Some(timing) = cell.key.timing() else {
            continue;
        };
        let metric = |buckets: &[Bucket; BLOCKS]| {
            metric_pair(buckets, buckets, origin, now, timing).map(|pair| TimedMetric {
                value: pair.incumbent,
                reporters: pair.reporters,
                observed_at: pair.oldest_at,
                latest_at: pair.latest_at,
                expires_at: pair.expires_at,
            })
        };
        match &cell.key {
            Key::Traffic(key)
                if Some(key.family) == context.target_family
                    && Some(&key.target) == context.target.as_ref() =>
            {
                evidence[index].response = metric(&cell.metrics[0]);
                evidence[index].upload = metric(&cell.metrics[1]);
                evidence[index].download = metric(&cell.metrics[2]);
            }
            Key::Probe { slot, scope, .. }
                if *slot == super::evidence::probe_slot(context)
                    && *scope == snapshots[index].probe_scope =>
            {
                evidence[index].probe = metric(&cell.metrics[0]);
            }
            _ => {}
        }
    }
    evidence
}

pub(super) fn pairs(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    reference: usize,
    now: Instant,
) -> PairCohort {
    let baseline = super::ranking::performance_baseline(snapshots);
    let mut proposals = [None; MAX_CHALLENGERS];
    for (index, score) in snapshots.iter().enumerate() {
        if index == reference || !normal_eligible(score, baseline) {
            continue;
        }
        let position = proposals.iter().position(|entry| {
            entry.is_none_or(|other: usize| {
                utility(score, baseline)
                    .total_cmp(&utility(&snapshots[other], baseline))
                    .then_with(|| nodes[other].id.cmp(&nodes[index].id))
                    == Ordering::Greater
            })
        });
        if let Some(position) = position {
            proposals[position..].rotate_right(1);
            proposals[position] = Some(index);
        }
    }
    PairCohort {
        reference,
        pairs: proposals.map(|index| {
            index.map(|index| {
                (
                    index,
                    compare(
                        inner,
                        group,
                        context,
                        nodes[reference].id,
                        nodes[index].id,
                        now,
                    ),
                )
            })
        }),
    }
}
