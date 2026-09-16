mod evidence;
mod feedback;
mod ranking;
mod selection;
#[cfg(test)]
mod tests;

use evidence::{
    record_aggregate_finish, record_aggregate_start, record_cell_finish, record_cell_start,
};
pub use feedback::{ScoreFeedback, ScoreReporter};

use super::{
    Candidate, GroupManager, IpVersion, MAX_GROUP_DEPTH, ProbeDomain, ScoreSelectionEntry,
    ScoreSelectionPlan, SelectionEffects, SelectionNetwork, SelectionPlanMode,
    removed_unique_candidate_count, unique_candidate_ids,
};
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const EXACT_CAPACITY: usize = 4096;
const AGGREGATE_CAPACITY: usize = 4096;
const RELIABILITY_CLOSE: f64 = 0.05;
const RELIABILITY_CONFIDENCE_Z: f64 = 1.64;
const SCORE_EVIDENCE_HALF_LIFE: Duration = Duration::from_secs(30 * 60);
const MIN_TRAINED_EVIDENCE: f64 = 0.5;
const SCORE_SWITCH_MARGIN: f64 = 0.01;
const SCORE_SWITCH_FULL_EVIDENCE: f64 = 8.0;
const SCORE_SWITCH_FLAP_WINDOW: u64 = 8;
const SELECTION_HISTORY_CAPACITY: usize = 4096;
const SCORE_FAILURE_FORGIVENESS_THRESHOLD: f64 = 0.01;
const SCORE_EXPLORATION_MIN_PERIOD: u64 = 16;
const SCORE_EXPLORATION_MAX_PERIOD: u64 = 64;
const SCORE_EXPLORE_BACKOFF_BASE: Duration = Duration::from_secs(5 * 60);
const SCORE_EXPLORE_BACKOFF_MAX: Duration = Duration::from_secs(6 * 3600);
/// Consecutive fresh failures that drop a leaf out of the reliability band
/// while any healthier candidate exists. Decayed history must not shield a
/// leaf that is failing right now.
const SCORE_FAIL_STREAK_EXCLUDE: u32 = 3;
const MIN_THROUGHPUT_DURATION: Duration = Duration::from_secs(1);
const MIN_THROUGHPUT_BYTES: u64 = 64 * 1024;

/// A normalized business target used only as an in-memory score key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScoreTarget {
    Domain { host: String, port: u16 },
    Socket(SocketAddr),
}

impl ScoreTarget {
    pub fn domain(host: &str, port: u16) -> Self {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        Self::Domain { host, port }
    }
}

impl From<SocketAddr> for ScoreTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

/// Business-target scoring dimensions plus the independent proxy-health
/// dimensions used to form the alive candidate set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreSelectionContext {
    pub network: SelectionNetwork,
    pub probe_domain: ProbeDomain,
    pub target_family: Option<IpVersion>,
    pub health_family: IpVersion,
    pub target: Option<ScoreTarget>,
}

impl ScoreSelectionContext {
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
pub struct ScoreAttribution {
    pub group: String,
    pub node_id: Uuid,
}

/// Compact terminal result; formatted error strings never enter score state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreOutcome {
    Success,
    Timeout,
    Io(io::ErrorKind),
    Rejected,
    Cancelled,
    Shutdown,
    Other,
}

impl ScoreOutcome {
    pub fn from_error(error: &anyhow::Error) -> Self {
        if let Some(rejection) = crate::proxy::packet_rejection(error) {
            return if rejection == crate::proxy::PacketRejection::Cancelled {
                Self::Cancelled
            } else {
                Self::Rejected
            };
        }
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
    target: ScoreTarget,
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
struct WeightedMean {
    sum: f64,
    weight: f64,
}

#[derive(Debug, Clone, Default)]
struct Stats {
    incarnation: u64,
    attempts: f64,
    setup_success: f64,
    setup_failure: f64,
    useful_success: f64,
    useful_failure: f64,
    setup_ms: WeightedMean,
    first_response_ms: WeightedMean,
    throughput_bytes: f64,
    throughput_seconds: f64,
    throughput_windows: f64,
    fail_streak: u32,
    explore_not_before: Option<Instant>,
    updated_at: Option<Instant>,
    selected_at: u64,
}

#[derive(Clone, Copy, Default)]
struct StartedCells {
    aggregate: [Option<u64>; 2],
    exact: Option<u64>,
}

#[derive(Debug)]
pub(super) struct ScoreAuthority;

#[derive(Clone, PartialEq, Eq, Hash)]
struct SelectionCadenceKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
}

impl SelectionCadenceKey {
    fn new(group: &str, context: &ScoreSelectionContext) -> Self {
        Self {
            group: group.to_owned(),
            network: context.network,
            family: context.target_family,
        }
    }
}

/// Flap history is scoped to the same target the pick was ranked for:
/// unrelated targets interleaving their own winners is not a flap. The
/// exploration cadence keeps the coarser [`SelectionCadenceKey`].
#[derive(Clone, PartialEq, Eq, Hash)]
struct SelectionHistoryKey {
    group: String,
    network: SelectionNetwork,
    family: Option<IpVersion>,
    target: Option<ScoreTarget>,
}

impl SelectionHistoryKey {
    fn new(group: &str, context: &ScoreSelectionContext) -> Self {
        Self {
            group: group.to_owned(),
            network: context.network,
            family: context.target_family,
            target: context.target.clone(),
        }
    }
}

#[derive(Clone, Copy)]
struct SelectionHistory {
    current: Uuid,
    previous: Option<Uuid>,
    /// Committed non-exploration selections seen by this target scope.
    selections: u64,
    switched_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionReason {
    ColdExplore,
    PeriodicExplore,
    ReliabilityWinner,
    PerformanceWinner,
    IncumbentHeld,
    FreshFailureBypass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HoldDecision {
    Held,
    FreshFailureBypass,
    UseBest,
}

impl SelectionReason {
    fn is_exploration(self) -> bool {
        matches!(self, Self::ColdExplore | Self::PeriodicExplore)
    }
}

#[derive(Clone, Copy)]
struct RankedSelection {
    index: usize,
    reason: SelectionReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct SelectionReasonKey {
    group: String,
    network: SelectionNetwork,
}

impl SelectionReasonKey {
    pub(super) fn new(group: &str, network: SelectionNetwork) -> Self {
        Self {
            group: group.to_owned(),
            network,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScoreReasonCounters {
    pub cold_explore: u64,
    pub periodic_explore: u64,
    pub reliability_winner: u64,
    pub performance_winner: u64,
    pub incumbent_held: u64,
    pub fresh_failure_bypass: u64,
    pub dead_filtered: u64,
    pub switch_flap: u64,
    pub fail_streak_excluded: u64,
    pub explore_backed_off: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScoreReasonGroupSnapshot {
    pub name: String,
    pub tcp: ScoreReasonCounters,
    pub udp: ScoreReasonCounters,
}

/// Occupancy and eviction totals of the two bounded evidence LRUs; carries no
/// group, node, or target identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScoreCacheSnapshot {
    pub exact_cells: usize,
    pub aggregate_cells: usize,
    pub exact_evictions: u64,
    pub aggregate_evictions: u64,
}

struct StateInner {
    exact: LruCache<ExactKey, Stats>,
    aggregate: LruCache<AggregateKey, Stats>,
    valid: HashSet<(String, Uuid)>,
    valid_groups: HashSet<String>,
    selection_counts: HashMap<SelectionCadenceKey, u64>,
    selection_history: LruCache<SelectionHistoryKey, SelectionHistory>,
    selection_reasons: HashMap<SelectionReasonKey, ScoreReasonCounters>,
    active_authority: Option<Arc<ScoreAuthority>>,
    tick: u64,
    exact_evictions: u64,
    aggregate_evictions: u64,
}

impl Default for StateInner {
    fn default() -> Self {
        Self {
            // SAFE-EXPECT: both cache capacities are positive compile-time constants.
            exact: LruCache::new(NonZeroUsize::new(EXACT_CAPACITY).expect("non-zero capacity")),
            aggregate: LruCache::new(
                // SAFE-EXPECT: both cache capacities are positive compile-time constants.
                NonZeroUsize::new(AGGREGATE_CAPACITY).expect("non-zero capacity"),
            ),
            valid: HashSet::new(),
            valid_groups: HashSet::new(),
            selection_counts: HashMap::new(),
            selection_history: LruCache::new(
                // SAFE-EXPECT: the capacity is a positive compile-time constant.
                NonZeroUsize::new(SELECTION_HISTORY_CAPACITY).expect("non-zero capacity"),
            ),
            selection_reasons: HashMap::new(),
            active_authority: None,
            tick: 0,
            exact_evictions: 0,
            aggregate_evictions: 0,
        }
    }
}

/// Process-memory-only score state shared by old and replacement managers.
#[derive(Default)]
pub struct ScorePolicyState {
    inner: Mutex<StateInner>,
}

impl ScorePolicyState {
    pub(super) fn reason_snapshot(
        &self,
        group_names: Vec<String>,
    ) -> Vec<ScoreReasonGroupSnapshot> {
        let mut groups: Vec<_> = group_names
            .into_iter()
            .map(|name| ScoreReasonGroupSnapshot {
                name,
                tcp: ScoreReasonCounters::default(),
                udp: ScoreReasonCounters::default(),
            })
            .collect();
        let inner = self.inner.lock();
        for (key, counts) in &inner.selection_reasons {
            let Ok(index) = groups.binary_search_by(|group| group.name.cmp(&key.group)) else {
                continue;
            };
            let destination = match key.network {
                SelectionNetwork::Tcp => &mut groups[index].tcp,
                SelectionNetwork::Udp => &mut groups[index].udp,
            };
            *destination = *counts;
        }
        groups
    }

    pub(super) fn cache_snapshot(&self) -> ScoreCacheSnapshot {
        let inner = self.inner.lock();
        ScoreCacheSnapshot {
            exact_cells: inner.exact.len(),
            aggregate_cells: inner.aggregate.len(),
            exact_evictions: inner.exact_evictions,
            aggregate_evictions: inner.aggregate_evictions,
        }
    }

    /// Atomically publish committed Score group/leaf membership and prune
    /// removed cells. Construction with a reused state never calls this.
    pub(super) fn publish_generation<I, G>(
        &self,
        authority: Arc<ScoreAuthority>,
        groups: G,
        membership: I,
    ) where
        I: IntoIterator<Item = (String, Uuid)>,
        G: IntoIterator<Item = String>,
    {
        let mut inner = self.inner.lock();
        inner.active_authority = Some(authority);
        inner.valid = membership.into_iter().collect();
        inner.valid_groups = groups.into_iter().collect();
        let StateInner {
            selection_counts,
            selection_reasons,
            selection_history,
            valid,
            valid_groups,
            ..
        } = &mut *inner;
        selection_counts.retain(|key, _| valid_groups.contains(&key.group));
        selection_reasons.retain(|key, _| valid_groups.contains(&key.group));
        let invalid_history: Vec<_> = selection_history
            .iter()
            .filter(|(key, history)| {
                !valid_groups.contains(&key.group)
                    || !valid.contains(&(key.group.clone(), history.current))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_history {
            selection_history.pop(&key);
        }
        let stale_previous: Vec<_> = selection_history
            .iter()
            .filter(|(key, history)| {
                history
                    .previous
                    .is_some_and(|node_id| !valid.contains(&(key.group.clone(), node_id)))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale_previous {
            if let Some(history) = selection_history.get_mut(&key) {
                history.previous = None;
            }
        }
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

    #[cfg(test)]
    fn publish_membership<I>(&self, membership: I)
    where
        I: IntoIterator<Item = (String, Uuid)>,
    {
        let membership: Vec<_> = membership.into_iter().collect();
        let groups = membership.iter().map(|(group, _)| group.clone());
        self.publish_generation(Arc::new(ScoreAuthority), groups, membership.clone());
    }

    pub(super) fn is_current_authority(&self, authority: &Arc<ScoreAuthority>) -> bool {
        self.inner
            .lock()
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
    }

    fn record_selection_reason(
        inner: &mut StateInner,
        group: &str,
        network: SelectionNetwork,
        selection: RankedSelection,
    ) {
        let counts = inner
            .selection_reasons
            .entry(SelectionReasonKey::new(group, network))
            .or_default();
        let counter = match selection.reason {
            SelectionReason::ColdExplore => &mut counts.cold_explore,
            SelectionReason::PeriodicExplore => &mut counts.periodic_explore,
            SelectionReason::ReliabilityWinner => &mut counts.reliability_winner,
            SelectionReason::PerformanceWinner => &mut counts.performance_winner,
            SelectionReason::IncumbentHeld => &mut counts.incumbent_held,
            SelectionReason::FreshFailureBypass => &mut counts.fresh_failure_bypass,
        };
        *counter = counter.saturating_add(1);
    }

    fn record_switch_flap(
        inner: &mut StateInner,
        history_key: &SelectionHistoryKey,
        node_id: Uuid,
        reason: SelectionReason,
    ) {
        if reason.is_exploration() {
            return;
        }
        let Some(history) = inner.selection_history.get_mut(history_key) else {
            inner.selection_history.push(
                history_key.clone(),
                SelectionHistory {
                    current: node_id,
                    previous: None,
                    selections: 1,
                    switched_at: 0,
                },
            );
            return;
        };
        history.selections = history.selections.saturating_add(1);
        if history.current == node_id {
            return;
        }
        let switch_flap = history.previous == Some(node_id)
            && history.selections.saturating_sub(history.switched_at) <= SCORE_SWITCH_FLAP_WINDOW;
        history.previous = Some(history.current);
        history.current = node_id;
        history.switched_at = history.selections;
        if switch_flap {
            let counter = &mut inner
                .selection_reasons
                .entry(SelectionReasonKey::new(
                    &history_key.group,
                    history_key.network,
                ))
                .or_default()
                .switch_flap;
            *counter = counter.saturating_add(1);
        }
    }

    pub(super) fn record_dead_filtered(
        &self,
        authority: &Arc<ScoreAuthority>,
        key: SelectionReasonKey,
        removed: u64,
    ) {
        if removed == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        let authorized = inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
            && inner.valid_groups.contains(&key.group);
        if !authorized {
            return;
        }
        let counter = &mut inner
            .selection_reasons
            .entry(key)
            .or_default()
            .dead_filtered;
        *counter = counter.saturating_add(removed);
    }

    #[cfg(test)]
    fn selection_reason_counts(
        &self,
        group: &str,
        network: SelectionNetwork,
    ) -> ScoreReasonCounters {
        self.inner
            .lock()
            .selection_reasons
            .get(&SelectionReasonKey::new(group, network))
            .copied()
            .unwrap_or_default()
    }

    #[cfg(test)]
    fn start(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
    ) -> Vec<StartedCells> {
        self.start_at(context, attributions, Instant::now())
    }

    #[cfg(test)]
    fn start_at(
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
        self.start_at_with_authority(&authority, context, attributions, now)
    }

    fn start_at_with_authority(
        &self,
        authority: &Arc<ScoreAuthority>,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        now: Instant,
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
                started.aggregate =
                    record_aggregate_start(&mut inner, attribution, context, now, tick);
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
                    let StateInner {
                        exact,
                        exact_evictions,
                        ..
                    } = &mut *inner;
                    started.exact = Some(record_cell_start(exact, key, now, tick, exact_evictions));
                }
            }
            cells.push(started);
        }
        cells
    }

    fn finish(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
    ) {
        self.finish_at(context, attributions, cells, sample, Instant::now());
    }

    fn finish_at(
        &self,
        context: &ScoreSelectionContext,
        attributions: &[ScoreAttribution],
        cells: &[StartedCells],
        sample: &FlowSample,
        now: Instant,
    ) {
        let mut inner = self.inner.lock();
        if !cells
            .iter()
            .any(|started| started.exact.is_some() || started.aggregate.iter().any(Option::is_some))
        {
            return;
        }
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
                now,
                sample,
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
                    now,
                    sample,
                    sample.count_usefulness,
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn exact_len(&self) -> usize {
        self.inner.lock().exact.len()
    }

    #[cfg(test)]
    pub(super) fn has_exact(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
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
        context: &ScoreSelectionContext,
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
            .map(|stats| {
                (
                    stats.attempts.round() as u64,
                    stats.setup_success.round() as u64,
                    stats.setup_failure.round() as u64,
                )
            })
    }

    #[cfg(test)]
    fn exact_useful_failures(
        &self,
        group: &str,
        context: &ScoreSelectionContext,
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
            .map(|stats| stats.useful_failure.round() as u64)
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
            .map(|stats| {
                (
                    stats.attempts.round() as u64,
                    stats.setup_success.round() as u64,
                    stats.setup_failure.round() as u64,
                )
            })
    }
}

#[derive(Clone, Copy)]
struct ScoreSnapshot {
    attempts: f64,
    completed: f64,
    hysteresis_completed: f64,
    reliability: f64,
    reliability_upper: f64,
    useful_completed: f64,
    latency_ms: Option<f64>,
    latency_confidence: f64,
    throughput: Option<f64>,
    throughput_confidence: f64,
    failures: f64,
    explore_backed_off: bool,
    fail_streak: u32,
    selected_at: u64,
    targeted: bool,
    target_attempts: f64,
    target_completed: f64,
}

#[derive(Clone, Copy)]
struct PerformanceBaseline {
    latency_ms: Option<f64>,
    throughput: Option<f64>,
}

struct FlowSample {
    outcome: ScoreOutcome,
    setup: Option<Duration>,
    first_response: Option<Duration>,
    tx: u64,
    rx: u64,
    elapsed: Duration,
    count_usefulness: bool,
    streak_neutral: bool,
}
