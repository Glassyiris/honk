mod evidence;
mod feedback;
mod pressure;
mod ranking;
mod selection;
#[cfg(test)]
mod tests;
mod verification;

use evidence::{MetricSnapshot, Performance, PerformanceSnapshot};
pub use feedback::{ScoreFeedback, ScoreReporter};
pub(in crate::group) use pressure::TransportQualitySource;
pub use verification::{
    ScoreComparison, ScoreEvidenceBasis, ScoreEvidenceGaps, ScoreValidationAction,
    ScoreVerificationCounters, ScoreVerificationSnapshot, ScoreVerificationState,
};

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
const SCORE_SWITCH_FULL_EVIDENCE: f64 = 8.0;
const SCORE_SWITCH_FLAP_WINDOW: u64 = 8;
const SELECTION_HISTORY_CAPACITY: usize = 4096;
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
// Experimental demand-driven bounds, not estimates of link capacity.
const PERFORMANCE_MAX_AGE: Duration = Duration::from_secs(120);
const MAX_THROUGHPUT_DURATION: Duration = Duration::from_secs(10);
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);
const PERFORMANCE_VALIDATION_SAMPLES: f64 = 4.0;
const PERFORMANCE_SWITCH_MARGIN: f64 = 0.1;
const LIVE_RX_INTERVAL: Duration = Duration::from_secs(1);
const LIVE_QUALIFICATION_TTL: Duration = Duration::from_secs(60);
const CARRIER_PRESSURE_TTL: Duration = Duration::from_secs(60);

/// Separates business outcomes from configured health and preparation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScoreSource {
    #[default]
    Traffic,
    HealthProbe,
    Warmup,
}

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    observed_at: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
struct Availability {
    epoch: u64,
    reporters: u8,
    latest_rx_at: Option<Instant>,
    valid_from: Option<Instant>,
}

#[derive(Debug, Clone, Default)]
struct Stats {
    incarnation: u64,
    attempts: f64,
    setup_success: f64,
    setup_failure: f64,
    useful_success: f64,
    useful_failure: f64,
    performance: Performance,
    availability: Availability,
    business_invalidated_through: Option<Instant>,
    failed_at: Option<Instant>,
    last_business_rx_at: Option<Instant>,
    qualified_until: Option<Instant>,
    warm_setup_ms: WeightedMean,
    probes: [evidence::ProbeMetric; 6],
    last_attempt: Option<Instant>,
    degraded_at: Option<Instant>,
    carrier_pressure: [Option<crate::transport_quality::TransportPressure>; 2],
    fail_streak: u32,
    explore_not_before: Option<Instant>,
    updated_at: Option<Instant>,
    selected_at: u64,
}

#[derive(Clone, Copy, Default)]
struct StartedCells {
    aggregate: [Option<u64>; 2],
    exact: Option<u64>,
    credited_aggregate: [Option<u64>; 2],
    credited_exact: Option<u64>,
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

#[derive(Clone, Copy)]
struct SelectionCadence {
    count: u64,
    revalidated_count: u64,
    revalidated_at: Instant,
    validation_node: Option<Uuid>,
    validation_attempts: u8,
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
    verification: Option<verification::VerificationHistory>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionReason {
    ColdExplore,
    PeriodicExplore,
    ReliabilityWinner,
    PerformanceWinner,
    IncumbentHeld,
    InsufficientEvidenceHeld,
    IncumbentIneligible,
    FreshFailureBypass,
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
    pub insufficient_evidence_held: u64,
    pub incumbent_ineligible: u64,
    pub fresh_failure_bypass: u64,
    pub dead_filtered: u64,
    pub ordinary_switch: u64,
    pub switch_flap: u64,
    pub fail_streak_excluded: u64,
    pub explore_backed_off: u64,
    pub carrier_pressure: u64,
    pub carrier_rtt_pressure: u64,
    pub carrier_loss_pressure: u64,
    pub carrier_validation: u64,
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
    selection_counts: HashMap<SelectionCadenceKey, SelectionCadence>,
    selection_history: LruCache<SelectionHistoryKey, SelectionHistory>,
    selection_reasons: HashMap<SelectionReasonKey, ScoreReasonCounters>,
    verification_counters: HashMap<SelectionReasonKey, ScoreVerificationCounters>,
    active_authority: Option<Arc<ScoreAuthority>>,
    published_at: Option<Instant>,
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
            verification_counters: HashMap::new(),
            published_at: None,
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
        let now = Instant::now();
        inner.active_authority = Some(authority);
        inner.published_at = Some(now);
        inner.valid = membership.into_iter().collect();
        inner.valid_groups = groups.into_iter().collect();
        let StateInner {
            selection_counts,
            selection_reasons,
            verification_counters,
            selection_history,
            valid,
            valid_groups,
            ..
        } = &mut *inner;
        selection_counts.retain(|key, _| valid_groups.contains(&key.group));
        selection_reasons.retain(|key, _| valid_groups.contains(&key.group));
        verification_counters.retain(|key, _| valid_groups.contains(&key.group));
        let invalid_history: Vec<_> = selection_history
            .iter()
            .filter(|(key, history)| {
                !valid_groups.contains(&key.group)
                    || (!valid.contains(&(key.group.clone(), history.current))
                        && history
                            .verification
                            .is_none_or(|verification| verification.claims == 0))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in invalid_history {
            selection_history.pop(&key);
        }
        // Preserve only pending claim revocation until the next authorized Apply;
        // a removed winner must no longer participate in incumbent/flap protection.
        for (key, history) in selection_history.iter_mut() {
            if !valid.contains(&(key.group.clone(), history.current)) {
                history.selections = 0;
                history.previous = None;
            }
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
        // Probe cohorts can change without changing group or leaf identity.
        // In-flight traffic keeps its cells, but a new generation must remeasure health.
        for (_, stats) in inner.aggregate.iter_mut() {
            stats.probes = Default::default();
            stats.carrier_pressure = Default::default();
            stats.invalidate_business(now);
        }
        for (_, stats) in inner.exact.iter_mut() {
            stats.invalidate_business(now);
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
            SelectionReason::InsufficientEvidenceHeld => &mut counts.insufficient_evidence_held,
            SelectionReason::IncumbentIneligible => &mut counts.incumbent_ineligible,
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
                    verification: None,
                },
            );
            return;
        };
        if history.selections == 0 {
            history.current = node_id;
            history.selections = 1;
            return;
        }
        history.selections = history.selections.saturating_add(1);
        if history.current == node_id {
            return;
        }
        let switch_flap = history.previous == Some(node_id)
            && history.selections.saturating_sub(history.switched_at) <= SCORE_SWITCH_FLAP_WINDOW;
        history.previous = Some(history.current);
        history.current = node_id;
        history.switched_at = history.selections;
        let counters = inner
            .selection_reasons
            .entry(SelectionReasonKey::new(
                &history_key.group,
                history_key.network,
            ))
            .or_default();
        counters.ordinary_switch = counters.ordinary_switch.saturating_add(1);
        if switch_flap {
            counters.switch_flap = counters.switch_flap.saturating_add(1);
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

#[derive(Clone, Copy, Default)]
struct ScoreSnapshot {
    attempts: f64,
    completed: f64,
    reliability: f64,
    reliability_upper: f64,
    useful_completed: f64,
    qualification_retained: bool,
    performance: PerformanceSnapshot,
    target_performance: PerformanceSnapshot,
    probe: MetricSnapshot,
    warm_setup: MetricSnapshot,
    probe_scope: u64,
    observed_reliability: f64,
    last_attempt: Option<Instant>,
    degraded_at: Option<Instant>,
    carrier_pressure_at: Option<Instant>,
    unresolved_failure: bool,
    explore_backed_off: bool,
    fail_streak: u32,
    selected_at: u64,
    verification: verification::VerificationEvidence,
}

impl ScoreSnapshot {
    fn qualified(&self) -> bool {
        self.useful_completed >= PERFORMANCE_VALIDATION_SAMPLES || self.qualification_retained
    }
}

#[derive(Clone, Copy)]
struct PerformanceBaseline {
    performance: PerformanceSnapshot,
    target_performance: PerformanceSnapshot,
    probe: MetricSnapshot,
    warm_setup: MetricSnapshot,
    probe_scope: u64,
    best_reliability: f64,
    best_observed_reliability: f64,
    any_healthy: bool,
    any_qualified: bool,
}

struct FlowSample {
    outcome: ScoreOutcome,
    setup: Option<Duration>,
    source: ScoreSource,
    tx: u64,
    rx: u64,
    last_rx_at: Option<Instant>,
    eligible_rx_at: Option<Instant>,
    elapsed: Duration,
    count_usefulness: bool,
}
