//! Bounded evaluation set: which members one whole-group comparison claim covers. Its size follows
//! the optional work earned from offered business, so large groups get bounded claims instead of an
//! unreachable all-member requirement.
use super::ranking::utility;
use super::*;
use honk_config::node::Node;

const REFRESH: Duration = Duration::from_secs(5 * 60);
const ROTATION_SLOT: Duration = Duration::from_secs(10 * 60);
const DEMAND_HALF_LIFE: Duration = Duration::from_secs(5 * 60);
const MIN_MEMBERS: usize = 3;
/// Keeps each member's targets and probe cohorts within the comparison store's cell cap.
const MAX_MEMBERS: usize = 25;
/// Share of earned optional work spent keeping members qualified; the rest aligns responses.
const QUALIFICATION_SHARE: f64 = 0.5;
/// Ranked members keep their place until they fall this far below the cut, so ties cannot churn claims.
const RANK_HYSTERESIS: usize = 2;
/// Recent Apply winners whose configured-probe cells stay admissible outside the ranked set.
const ANCHORS: usize = 4;

#[derive(Clone, Default)]
pub(super) struct EvaluationSet {
    ranked: Vec<Uuid>,
    /// Ranked members counted toward claims since their first qualification.
    admitted: Vec<Uuid>,
    /// Qualification gates coverage only once some member is qualified.
    gated: bool,
    rotation: Option<(Uuid, Instant)>,
    anchors: Vec<Uuid>,
    refreshed_at: Option<Instant>,
    limit: usize,
    bounded: bool,
    demand: f64,
    demand_at: Option<Instant>,
}

/// Flags aligned with the decision's node order.
#[derive(Clone, Default)]
pub(super) struct Membership {
    /// May receive comparison pairs, evidence and optional work.
    pub evaluated: Vec<bool>,
    /// Must be compared or resolved before a claim is complete.
    pub covered: Vec<bool>,
}

#[cfg(test)]
impl Membership {
    pub(super) fn all(len: usize) -> Self {
        Self {
            evaluated: vec![true; len],
            covered: vec![true; len],
        }
    }
}

fn decayed(value: f64, elapsed: Duration, half_life: Duration) -> f64 {
    value * (-elapsed.as_secs_f64() / half_life.as_secs_f64()).exp2()
}

impl EvaluationSet {
    /// Counts an original business at the same deduplicated point as `business_starts`.
    pub(super) fn record_demand(&mut self, now: Instant) {
        self.demand = self.demand_now(now) + 1.0;
        self.demand_at = Some(now);
    }

    fn demand_now(&self, now: Instant) -> f64 {
        self.demand_at.map_or(0.0, |at| {
            decayed(
                self.demand,
                now.saturating_duration_since(at),
                DEMAND_HALF_LIFE,
            )
        })
    }

    /// Members the earned currency can keep qualified: each needs four effective completions under
    /// the evidence half-life, funded by one optional start per earning period.
    fn target_limit(&self, now: Instant) -> usize {
        let sustained = self.demand_now(now) * SCORE_EVIDENCE_HALF_LIFE.as_secs_f64()
            / DEMAND_HALF_LIFE.as_secs_f64();
        let challengers = QUALIFICATION_SHARE * sustained
            / (PERFORMANCE_VALIDATION_SAMPLES * SCORE_EXPLORATION_PERIOD as f64);
        (1 + challengers as usize).clamp(MIN_MEMBERS, MAX_MEMBERS)
    }

    /// Whether this member may receive comparisons and optional work under the stored set.
    pub(super) fn evaluates(&self, node: Uuid) -> bool {
        self.ranks(node) || self.rotation.is_some_and(|(id, _)| id == node)
    }

    /// Whether probe comparison cells for this member are outside the bounded store budget.
    pub(super) fn excludes(&self, node: Uuid) -> bool {
        !self.evaluates(node) && !self.anchors.contains(&node)
    }

    pub(super) fn anchor(&mut self, node: Uuid) {
        self.anchors.retain(|id| *id != node);
        self.anchors.insert(0, node);
        self.anchors.truncate(ANCHORS);
    }

    /// Membership changes keep only the decayed demand, which reflects offered business.
    pub(super) fn reset_members(&mut self) {
        *self = Self {
            demand: self.demand,
            demand_at: self.demand_at,
            ..Self::default()
        };
    }

    fn ranks(&self, node: Uuid) -> bool {
        !self.bounded || self.ranked.contains(&node)
    }

    pub(super) fn membership(&self, nodes: &[&Node], reference: usize) -> Membership {
        let covered: Vec<_> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                index == reference
                    || (self.ranks(node.id) && (!self.gated || self.admitted.contains(&node.id)))
            })
            .collect();
        let evaluated = nodes
            .iter()
            .zip(&covered)
            .map(|(node, covered)| *covered || self.evaluates(node.id))
            .collect();
        Membership { evaluated, covered }
    }
}

/// Pure projection of the stored set onto current members; only an authorized Apply stores it.
pub(super) fn derive(
    stored: Option<&EvaluationSet>,
    nodes: &[&Node],
    snapshots: &[ScoreSnapshot],
    baseline: PerformanceBaseline,
    now: Instant,
) -> EvaluationSet {
    let mut set = stored.cloned().unwrap_or_default();
    if set
        .refreshed_at
        .is_none_or(|at| now.saturating_duration_since(at) >= REFRESH)
    {
        let target = set.target_limit(now);
        // Growth waits for a refresh; shrinking also needs a two-member margin.
        if target > set.limit || target + 2 <= set.limit {
            set.limit = target;
        }
        set.bounded = nodes.len() > set.limit;
        let utilities: Vec<_> = snapshots
            .iter()
            .map(|score| utility(score, baseline))
            .collect();
        // Untried members tie on utility; the configured probe then hints the promising ones.
        // Only one measurement scope is comparable, so use the members' most common one.
        let mut scopes: Vec<_> = snapshots.iter().map(|score| score.probe_scope).collect();
        scopes.sort_unstable();
        let scope = scopes
            .chunk_by(|left, right| left == right)
            .max_by_key(|run| run.len())
            .map_or(0, |run| run[0]);
        let probe = |index: usize| {
            (snapshots[index].probe_scope == scope)
                .then_some(snapshots[index].probe.value)
                .flatten()
                .unwrap_or(f64::INFINITY)
        };
        let mut order: Vec<_> = (0..nodes.len()).collect();
        order.sort_by(|&left, &right| {
            utilities[right]
                .total_cmp(&utilities[left])
                .then_with(|| probe(left).total_cmp(&probe(right)))
                .then_with(|| nodes[left].id.cmp(&nodes[right].id))
        });
        let ranked_len = if set.bounded {
            set.limit - 1
        } else {
            nodes.len()
        };
        let rank = |id: &Uuid| order.iter().position(|&index| nodes[index].id == *id);
        // A member missing from this filtered or retry view keeps its place; absence is not removal.
        set.ranked
            .retain(|id| rank(id).is_none_or(|rank| rank < ranked_len + RANK_HYSTERESIS));
        set.ranked.sort_by_key(|id| rank(id).unwrap_or(usize::MAX));
        set.ranked.truncate(ranked_len);
        for &index in &order {
            if set.ranked.len() == ranked_len {
                break;
            }
            if !set.ranked.contains(&nodes[index].id) {
                set.ranked.push(nodes[index].id);
            }
        }
        set.refreshed_at = Some(now);
    }
    // Members join claims at their first qualification, never by measured value, so members still
    // acquiring evidence cannot stall a claim; once admitted they stay until ranked out.
    set.gated = baseline.any_qualified;
    let bounded = set.bounded;
    set.admitted
        .retain(|id| !bounded || set.ranked.contains(id));
    for (node, score) in nodes.iter().zip(snapshots) {
        if score.qualified() && set.ranks(node.id) && !set.admitted.contains(&node.id) {
            set.admitted.push(node.id);
        }
    }
    if !set.bounded {
        set.rotation = None;
        return set;
    }
    let rotation_due = set.rotation.is_none_or(|(id, since)| {
        set.ranked.contains(&id) || now.saturating_duration_since(since) >= ROTATION_SLOT
    });
    if rotation_due {
        let previous = set.rotation.map(|(id, _)| id);
        let mut outside: Vec<_> = nodes
            .iter()
            .map(|node| node.id)
            .filter(|id| !set.ranked.contains(id))
            .collect();
        outside.sort_unstable();
        set.rotation = outside
            .iter()
            .find(|id| previous.is_some_and(|previous| **id > previous))
            .or(outside.first())
            .map(|id| (*id, now));
    }
    set
}
