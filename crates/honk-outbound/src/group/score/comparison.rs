use super::evidence::CellStamp;
use super::ranking::{normal_eligible, utility};
use super::verification::{TimedMetric, VerificationEvidence};
use super::{AggregateKey, ExactKey, ScoreSelectionContext, ScoreSnapshot, StateInner, Stats};
use honk_config::node::Node;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use uuid::Uuid;

mod store;
use store::{Bucket, Cell, Key, Timing};
pub(super) use store::{Store, observe, target_bytes};
mod summary;
pub(super) use summary::summarize;

pub(super) const MAX_CELLS: usize = 256;
pub(super) const MAX_TARGETS: usize = 8;
pub(super) const MAX_CHALLENGERS: usize = 4;
pub(super) const MAX_LOGICAL_BYTES: usize = 1024 * 1024;
pub(super) const MAX_KEY_BYTES: usize = 1024;
const BLOCKS: usize = 4;
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
    // Fingerprints describe selected keys/blocks, never measured values or raw API targets.
    pub support: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PairEvidence {
    pub basis: Basis,
    pub response: Option<MetricPair>,
    pub upload: Option<MetricPair>,
    pub download: Option<MetricPair>,
    pub partial: bool,
}

pub(super) struct PairCohort {
    pub reference: usize,
    pub pairs: [Option<(usize, PairEvidence)>; MAX_CHALLENGERS],
    pub joint: Option<[PairEvidence; MAX_CHALLENGERS]>,
}

impl PairCohort {
    pub fn get(&self, index: usize) -> Option<PairEvidence> {
        self.pairs
            .iter()
            .flatten()
            .find_map(|(candidate, pair)| (*candidate == index).then_some(*pair))
    }

    pub fn summary_pair(&self, index: usize) -> Option<PairEvidence> {
        self.pairs.iter().enumerate().find_map(|(slot, pair)| {
            let (candidate, pair) = pair.as_ref()?;
            (*candidate == index).then(|| self.joint.as_ref().map_or(*pair, |joint| joint[slot]))
        })
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
    distinct: usize,
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
            if self.distinct < self.reporters.len()
                && !self.reporters[..self.distinct].contains(&id)
            {
                self.reporters[self.distinct] = id;
                self.distinct += 1;
            }
        }
    }

    fn reporters(&self) -> usize {
        self.distinct
    }
}

fn metric_pair(
    left: &[Bucket; BLOCKS],
    right: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
    blocks: u8,
    mut support: std::collections::hash_map::DefaultHasher,
) -> Option<MetricPair> {
    let mut a = Accumulator::default();
    let mut b = Accumulator::default();
    let mut expires = None;
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        if blocks & (1 << index) == 0 || !timing.common(left, right, origin, now) {
            continue;
        }
        let until = timing.deadline(origin, left.block)?;
        left.block.hash(&mut support);
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
        support: support.finish(),
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
        (Some(old), Some(next)) => {
            let mut support = std::collections::hash_map::DefaultHasher::new();
            (old.support, next.support).hash(&mut support);
            Some(MetricPair {
                incumbent: old.incumbent + next.incumbent,
                candidate: old.candidate + next.candidate,
                reporters: old.reporters.min(next.reporters),
                span: old.span.min(next.span),
                oldest_at: old.oldest_at.min(next.oldest_at),
                latest_at: old.latest_at.min(next.latest_at),
                expires_at: old.expires_at.min(next.expires_at),
                dispersion: old.dispersion.max(next.dispersion),
                support: support.finish(),
            })
        }
        _ => None,
    };
}

fn paired_cell(
    left: &Cell,
    right: &Cell,
    origin: Instant,
    now: Instant,
    basis: Basis,
    blocks: [u8; 3],
) -> PairEvidence {
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
    for (index, ((a, b), output)) in left
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
        *output = metric_pair(a, b, origin, now, timing, blocks[index], support.clone());
    }
    result
}

/// One challenger's accumulation against the reference, in store order.
#[derive(Default)]
struct PairScan {
    common: PairEvidence,
    count: usize,
    exact: Option<PairEvidence>,
    probe: Option<PairEvidence>,
}

impl PairScan {
    fn add(
        &mut self,
        context: &ScoreSelectionContext,
        (left, right): (&Cell, &Cell),
        origin: Instant,
        now: Instant,
    ) {
        if !has_common_block(left, right, origin, now) {
            return;
        }
        match &right.key {
            Key::Traffic(key)
                if context
                    .target_family
                    .is_none_or(|family| family == key.family) =>
            {
                if self.count == MAX_TARGETS && context.target.as_ref() != Some(&key.target) {
                    self.common.partial = true;
                    return;
                }
                let pair = paired_cell(left, right, origin, now, Basis::ExactTarget, [u8::MAX; 3]);
                if context.target.as_ref() == Some(&key.target) {
                    self.exact = Some(pair);
                }
                // Qualification, never magnitude, selects the canonical response cohort.
                if pair.response.is_some() && self.count < MAX_TARGETS {
                    merge_metric(&mut self.common.response, pair.response, self.count);
                    merge_metric(&mut self.common.upload, pair.upload, self.count);
                    merge_metric(&mut self.common.download, pair.download, self.count);
                    self.count += 1;
                } else {
                    self.common.partial = true;
                }
            }
            Key::Probe { slot, .. }
                if *slot == super::evidence::probe_slot(context) && self.probe.is_none() =>
            {
                self.probe = Some(paired_cell(
                    left,
                    right,
                    origin,
                    now,
                    Basis::ConfiguredProbe,
                    [u8::MAX; 3],
                ));
            }
            _ => {}
        }
    }

    fn finish(mut self) -> PairEvidence {
        self.common.basis = if self.count == 0 {
            Basis::None
        } else {
            Basis::CommonTargets
        };
        for metric in [
            &mut self.common.response,
            &mut self.common.upload,
            &mut self.common.download,
        ]
        .into_iter()
        .flatten()
        {
            metric.incumbent /= self.count as f64;
            metric.candidate /= self.count as f64;
        }
        let mut result = self.exact.unwrap_or_default();
        if result.response.is_none() && result.upload.is_none() && result.download.is_none() {
            result = self.common;
        }
        if result.response.is_none()
            && let Some(pair) = self.probe
        {
            // Do not combine business rates with an unrelated proxy-probe response.
            result = pair;
        }
        result
    }
}

/// Pairs every challenger with the reference in one scan; results follow `challengers`.
fn compare_all(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    (reference, reference_parent): (Uuid, Option<&Stats>),
    challengers: &[(Uuid, Option<&Stats>)],
    now: Instant,
) -> Vec<PairEvidence> {
    let Some(origin) = inner.comparisons.origin else {
        return vec![PairEvidence::default(); challengers.len()];
    };
    let mut scans: Vec<_> = challengers.iter().map(|_| PairScan::default()).collect();
    let mut order: Vec<_> = challengers
        .iter()
        .enumerate()
        .map(|(slot, (node, _))| (*node, slot))
        .collect();
    order.sort_unstable();
    // Keys are unique per node within a sorted cohort, so each cohort pairs at most once.
    let mut cells = inner.comparisons.scope(group, context.network);
    while let Some(first) = cells.first() {
        let end = cells
            .iter()
            .position(|cell| first.key.cohort_cmp(&cell.key) != Ordering::Equal)
            .unwrap_or(cells.len());
        let (cohort, rest) = cells.split_at(end);
        cells = rest;
        let Some(left) = cohort
            .iter()
            .find(|cell| cell.key.node() == reference && cell.valid(inner, reference_parent))
        else {
            continue;
        };
        for right in cohort.iter().filter(|cell| cell.key.node() != reference) {
            let node = right.key.node();
            let first = order.partition_point(|(id, _)| *id < node);
            for &(_, slot) in order[first..].iter().take_while(|(id, _)| *id == node) {
                if right.valid(inner, challengers[slot].1) {
                    scans[slot].add(context, (left, right), origin, now);
                }
            }
        }
    }
    scans.into_iter().map(PairScan::finish).collect()
}

fn global_stats<'a>(
    inner: &'a StateInner,
    group: &str,
    network: super::SelectionNetwork,
    node: Uuid,
) -> Option<&'a Stats> {
    inner.aggregate.peek(&AggregateKey {
        group: group.to_owned(),
        network,
        family: None,
        node_id: node,
    })
}

fn timed(
    buckets: &[Bucket; BLOCKS],
    origin: Instant,
    now: Instant,
    timing: Timing,
) -> Option<TimedMetric> {
    metric_pair(
        buckets,
        buckets,
        origin,
        now,
        timing,
        u8::MAX,
        std::collections::hash_map::DefaultHasher::new(),
    )
    .map(|pair| TimedMetric {
        value: pair.incumbent,
        reporters: pair.reporters,
        observed_at: pair.oldest_at,
        latest_at: pair.latest_at,
        expires_at: pair.expires_at,
    })
}

pub(super) fn node_evidence(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    now: Instant,
) -> Vec<VerificationEvidence> {
    let mut parent_key = AggregateKey {
        group: group.to_owned(),
        network: context.network,
        family: None,
        node_id: Uuid::nil(),
    };
    let mut family_key = AggregateKey {
        family: context.target_family,
        ..parent_key.clone()
    };
    let mut exact_key =
        context
            .target_family
            .zip(context.target.clone())
            .map(|(family, target)| ExactKey {
                group: group.to_owned(),
                network: context.network,
                family,
                target,
                node_id: Uuid::nil(),
            });
    let mut parents = Vec::with_capacity(nodes.len());
    let mut evidence: Vec<_> = nodes
        .iter()
        .map(|node| {
            parent_key.node_id = node.id;
            let parent = inner.aggregate.peek(&parent_key);
            parents.push(parent);
            let stamp = if let Some(key) = exact_key.as_mut() {
                key.node_id = node.id;
                inner
                    .exact
                    .peek(key)
                    .and_then(|stats| CellStamp::current(stats, parent))
            } else if context.target.is_none() {
                family_key.node_id = node.id;
                inner.aggregate.peek(&family_key).and_then(|stats| {
                    if context.target_family.is_none() {
                        Some(CellStamp::own(stats))
                    } else {
                        CellStamp::current(stats, parent)
                    }
                })
            } else {
                None
            };
            let mut evidence = stamp.map_or_else(VerificationEvidence::default, |stamp| {
                let mut evidence = VerificationEvidence::new(stamp.stats, now);
                evidence.business = evidence.business.filter(|metric| {
                    stamp
                        .invalidated_through
                        .is_none_or(|at| metric.latest_at > at)
                });
                evidence
            });
            evidence.failed_at = evidence
                .failed_at
                .max(parent.and_then(|parent| parent.failed_at));
            evidence
        })
        .collect();
    let Some(origin) = inner.comparisons.origin else {
        return evidence;
    };
    let mut order: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id, index))
        .collect();
    order.sort_unstable();
    let slot = super::evidence::probe_slot(context);
    // One scope pass; each node still sees its own cells in store order.
    for cell in inner.comparisons.scope(group, context.network) {
        let wanted = match &cell.key {
            Key::Traffic(key) => {
                Some(key.family) == context.target_family
                    && Some(&key.target) == context.target.as_ref()
            }
            Key::Probe {
                slot: cell_slot, ..
            } => *cell_slot == slot,
        };
        let Some(timing) = cell.key.timing().filter(|_| wanted) else {
            continue;
        };
        let node = cell.key.node();
        let first = order.partition_point(|(id, _)| *id < node);
        for &(_, index) in order[first..].iter().take_while(|(id, _)| *id == node) {
            if !cell.valid(inner, parents[index]) {
                continue;
            }
            let evidence = &mut evidence[index];
            match &cell.key {
                Key::Traffic(_) => {
                    evidence.response = timed(&cell.metrics[0], origin, now, timing);
                    evidence.upload = timed(&cell.metrics[1], origin, now, timing);
                    evidence.download = timed(&cell.metrics[2], origin, now, timing);
                }
                Key::Probe { scope, .. } if *scope == snapshots[index].probe_scope => {
                    evidence.probe = timed(&cell.metrics[0], origin, now, timing);
                }
                Key::Probe { .. } => {}
            }
        }
    }
    evidence
}

pub(super) fn pairs(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    nodes: &[&Node],
    (snapshots, baseline): (&[ScoreSnapshot], super::PerformanceBaseline),
    reference: usize,
    now: Instant,
) -> PairCohort {
    let mut proposals: [Option<(usize, f64)>; MAX_CHALLENGERS] = [None; MAX_CHALLENGERS];
    for (index, score) in snapshots.iter().enumerate() {
        if index == reference || !normal_eligible(score, baseline) {
            continue;
        }
        let value = utility(score, baseline);
        let position = proposals.iter().position(|entry| {
            entry.is_none_or(|(other, other_value)| {
                value
                    .total_cmp(&other_value)
                    .then_with(|| nodes[other].id.cmp(&nodes[index].id))
                    == Ordering::Greater
            })
        });
        if let Some(position) = position {
            proposals[position..].rotate_right(1);
            proposals[position] = Some((index, value));
        }
    }
    let mut parent_key = AggregateKey {
        group: group.to_owned(),
        network: context.network,
        family: None,
        node_id: nodes[reference].id,
    };
    let mut members = [(Uuid::nil(), None); MAX_CHALLENGERS + 1];
    members[0] = (parent_key.node_id, inner.aggregate.peek(&parent_key));
    let mut count = 0;
    for (index, _) in proposals.iter().flatten() {
        count += 1;
        parent_key.node_id = nodes[*index].id;
        members[count] = (parent_key.node_id, inner.aggregate.peek(&parent_key));
    }
    let compared = compare_all(inner, group, context, members[0], &members[1..=count], now);
    let mut cohort = PairCohort {
        reference,
        joint: None,
        pairs: std::array::from_fn(|slot| {
            proposals[slot].map(|(index, _)| (index, compared[slot]))
        }),
    };
    let mut identity = None;
    let needs_joint = cohort.pairs.iter().flatten().count() > 1
        && cohort.pairs.iter().flatten().any(|(_, pair)| {
            let Some(response) = pair.response else {
                return true;
            };
            let next = (pair.basis, response.support);
            let differs = identity.is_some_and(|old| old != next);
            identity = Some(next);
            differs
        });
    if needs_joint {
        for basis in [
            Basis::ExactTarget,
            Basis::CommonTargets,
            Basis::ConfiguredProbe,
        ] {
            if basis == Basis::ConfiguredProbe
                && cohort.pairs.iter().flatten().any(|(_, pair)| {
                    matches!(pair.basis, Basis::ExactTarget | Basis::CommonTargets)
                        && pair.response.is_some()
                })
            {
                continue;
            }
            if let Some(joint) = joint_pairs(inner, group, context, &members[..=count], basis, now)
            {
                cohort.joint = Some(joint);
                break;
            }
        }
    }
    cohort
}

fn joint_pairs(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    members: &[(Uuid, Option<&Stats>)],
    basis: Basis,
    now: Instant,
) -> Option<[PairEvidence; MAX_CHALLENGERS]> {
    let origin = inner.comparisons.origin?;
    let count = members.len() - 1;
    let mut result = [PairEvidence {
        basis,
        ..PairEvidence::default()
    }; MAX_CHALLENGERS];
    let mut targets = 0;
    let mut partial = false;
    // A duplicated node id resolves to its first member slot.
    let mut order: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(slot, (node, _))| (*node, slot))
        .collect();
    order.sort_unstable();
    let mut cells = inner.comparisons.scope(group, context.network);
    while let Some(first) = cells.first() {
        let end = cells
            .iter()
            .position(|cell| first.key.cohort_cmp(&cell.key) != Ordering::Equal)
            .unwrap_or(cells.len());
        let (current, rest) = cells.split_at(end);
        cells = rest;
        let eligible = match (&first.key, basis) {
            (Key::Traffic(key), Basis::ExactTarget) => {
                Some(key.family) == context.target_family
                    && Some(&key.target) == context.target.as_ref()
            }
            (Key::Traffic(key), Basis::CommonTargets) => context
                .target_family
                .is_none_or(|family| family == key.family),
            (Key::Probe { slot, .. }, Basis::ConfiguredProbe) => {
                *slot == super::evidence::probe_slot(context)
            }
            _ => false,
        };
        if !eligible {
            continue;
        }
        let mut selected = [None; MAX_CHALLENGERS + 1];
        for cell in current {
            let node = cell.key.node();
            if let Some(&(id, slot)) = order.get(order.partition_point(|(id, _)| *id < node))
                && id == node
                && cell.valid(inner, members[slot].1)
            {
                selected[slot] = Some(cell);
            }
        }
        if selected[..=count].iter().any(Option::is_none) {
            partial |= selected[0].is_some_and(|left| {
                selected[1..=count]
                    .iter()
                    .flatten()
                    .any(|right| has_common_block(left, right, origin, now))
            });
            continue;
        }
        let left = selected[0]?;
        let timing = left.key.timing()?;
        let mut blocks = [0_u8; 3];
        for (metric, mask) in blocks.iter_mut().enumerate() {
            for block in 0..BLOCKS {
                if selected[..=count].iter().flatten().all(|cell| {
                    timing.common(
                        &left.metrics[metric][block],
                        &cell.metrics[metric][block],
                        origin,
                        now,
                    )
                }) {
                    *mask |= 1 << block;
                }
            }
        }
        blocks[1] &= blocks[0];
        blocks[2] &= blocks[0];
        let mut next = [PairEvidence::default(); MAX_CHALLENGERS];
        for slot in 0..count {
            next[slot] = paired_cell(left, selected[slot + 1]?, origin, now, basis, blocks);
        }
        if next[..count].iter().any(|pair| pair.response.is_none()) {
            partial |= selected[1..=count]
                .iter()
                .flatten()
                .any(|right| has_common_block(left, right, origin, now));
            continue;
        }
        if targets == MAX_TARGETS {
            partial = true;
            continue;
        }
        for (pair, next) in result[..count].iter_mut().zip(&next[..count]) {
            merge_metric(&mut pair.response, next.response, targets);
            merge_metric(&mut pair.upload, next.upload, targets);
            merge_metric(&mut pair.download, next.download, targets);
        }
        targets += 1;
        if basis != Basis::CommonTargets {
            break;
        }
    }
    if targets == 0 {
        return None;
    }
    for pair in &mut result[..count] {
        pair.partial = basis == Basis::CommonTargets && partial;
        for metric in [&mut pair.response, &mut pair.upload, &mut pair.download]
            .into_iter()
            .flatten()
        {
            metric.incumbent /= targets as f64;
            metric.candidate /= targets as f64;
        }
    }
    Some(result)
}

pub(super) fn response_progress(
    inner: &StateInner,
    group: &str,
    context: &ScoreSelectionContext,
    reference: Uuid,
    candidate: Uuid,
    now: Instant,
) -> Option<([u8; 2], u64)> {
    let family = context.target_family?;
    let target = context.target.as_ref()?;
    if group.len().saturating_add(target_bytes(target)) > MAX_KEY_BYTES {
        return None;
    }
    let mut key = ExactKey {
        group: group.to_owned(),
        network: context.network,
        family,
        target: target.clone(),
        node_id: reference,
    };
    let mut identity = std::collections::hash_map::DefaultHasher::new();
    let mut cells = [None; 2];
    for (side, node) in [reference, candidate].into_iter().enumerate() {
        let parent = global_stats(inner, group, context.network, node)?;
        key.node_id = node;
        let stats = inner.exact.peek(&key)?;
        let stamp = CellStamp::current(stats, Some(parent))?;
        (
            parent.incarnation,
            stats.incarnation,
            stamp.invalidated_through,
        )
            .hash(&mut identity);
        cells[side] = inner
            .comparisons
            .scope(group, context.network)
            .iter()
            .find(|cell| {
                matches!(&cell.key, Key::Traffic(current) if current == &key)
                    && cell.valid(inner, Some(parent))
            });
    }
    let mut counts = [0; 2];
    if let (Some(origin), [Some(left), Some(right)]) = (inner.comparisons.origin, cells) {
        let timing = left.key.timing()?;
        let mut reporters = [Accumulator::default(), Accumulator::default()];
        for (a, b) in left.metrics[0].iter().zip(&right.metrics[0]) {
            if timing.common(a, b, origin, now) {
                reporters[0].add(a);
                reporters[1].add(b);
            }
        }
        counts = reporters.map(|reporters| reporters.reporters().min(REPORTERS) as u8);
    }
    Some((counts, identity.finish()))
}
