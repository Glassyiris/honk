//! Node group manager — Selector (manual), URLTest (auto lowest-latency with
//! separate TCP/UDP selections), LoadBalance (per-group round-robin) and
//! Fallback (sticky first-alive). Filters dead nodes via `AliveDialerSet`.
//! Modeled after sing-box outbound groups.
//!
//! UDP candidate filtering is per-node: a node with both UDP probe domains
//! (DataUDP + DnsUDP) explicitly dead is excluded from UDP selection even
//! when its TCP is alive; nodes never probed for UDP inherit TCP liveness
//! (see `filter_alive_candidates`).
//!
//! Groups nest (sing-box style): `Group.groups` lists sub-group tags whose
//! own current selection contributes one member candidate each (the leaf
//! node the sub-group's policy picks). Every policy's pick therefore
//! resolves recursively to a single leaf node — the dial path stays
//! authoritative. Member-facing APIs report tags (node names + sub-group
//! tags); leaf-facing APIs (`leaf_node_names_in_group`,
//! `delay_test_members`) expand sub-groups to the real nodes underneath.

use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::alive::{AliveDialerSet, IpVersion, ProbeDomain};

/// Tolerance for URLTest cache replacement: a new measurement must beat
/// the current selection by at least `group.tolerance` ms.  Default 50 ms
/// matches sing-box.
#[allow(dead_code)]
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

/// Maximum nesting depth for group → sub-group resolution. Construction-
/// time cycle breaking keeps the group graph acyclic; this bound (plus the
/// per-resolution visited set) is defense in depth against pathological
/// configs.
pub const MAX_GROUP_DEPTH: usize = 8;

/// Network dimension for per-network group selections.
///
/// sing-box keeps `selectedOutboundTCP` and `selectedOutboundUDP` apart;
/// honk does the same for URLTest groups so a node with fast TCP but
/// broken UDP does not drag UDP flows down (and vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionNetwork {
    Tcp,
    Udp,
}

impl SelectionNetwork {
    /// Map a health-check probe domain onto the selection network: TCP
    /// stays TCP; both UDP probe domains share the single UDP selection.
    pub fn from_probe_domain(domain: ProbeDomain) -> Self {
        match domain {
            ProbeDomain::Tcp => SelectionNetwork::Tcp,
            ProbeDomain::DnsUdp | ProbeDomain::DataUdp => SelectionNetwork::Udp,
        }
    }
}

/// Provenance of a group selection plan.
///
/// The mode is explicit because one surviving candidate does not make a cold
/// URLTest selection authoritative: callers must preserve the selection
/// policy rather than infer it from `nodes.len()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionPlanMode {
    /// Selector, LoadBalance, Fallback, and warm URLTest have already chosen
    /// their one authoritative leaf.
    Authoritative,
    /// A top-level URLTest group has no usable measurement and may prepare
    /// its ordered eligible leaves with UDP staggering.
    ColdUrlTest,
}

/// Concrete leaf nodes plus the selection provenance that produced them.
#[derive(Debug, Clone)]
pub struct SelectionPlan<'a> {
    pub mode: SelectionPlanMode,
    pub nodes: Vec<&'a Node>,
}

/// Per-group URLTest selection entry. `tag` is the member tag the group
/// selected (a direct member's node name, or a sub-group's tag) — it is
/// the selection's identity for hysteresis and display; `node_id` records
/// the leaf the tag resolved to at selection time.
#[derive(Debug, Clone)]
struct UrlTestEntry {
    /// Leaf the selection resolved to when it was made. Informational —
    /// selection identity is `tag`, so a sub-group swapping its internal
    /// leaf keeps the parent's selection stable.
    #[allow(dead_code)]
    node_id: uuid::Uuid,
    tag: String,
    latency: Duration,
    #[allow(dead_code)]
    updated_at: Instant,
}

/// Per-group URLTest selections, one per network. The UDP selection is
/// ranked by UDP probe data; when no UDP measurements exist it mirrors
/// the TCP selection (sing-box `Now()` fallback semantics).
#[derive(Debug, Default)]
struct UrlTestSelections {
    tcp: Option<UrlTestEntry>,
    udp: Option<UrlTestEntry>,
}

impl UrlTestSelections {
    fn get(&self, network: SelectionNetwork) -> Option<&UrlTestEntry> {
        match network {
            SelectionNetwork::Tcp => self.tcp.as_ref(),
            SelectionNetwork::Udp => self.udp.as_ref(),
        }
    }

    fn set(&mut self, network: SelectionNetwork, entry: UrlTestEntry) {
        match network {
            SelectionNetwork::Tcp => self.tcp = Some(entry),
            SelectionNetwork::Udp => self.udp = Some(entry),
        }
    }
}

/// Callback invoked when a Selector group's choice changes (group, node).
/// Used by honk-core to persist choices to cache.db.
pub type PersistCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Callback invoked when a group's selected node changes while the group
/// has `interrupt_connections = true`. Argument is the group name;
/// honk-core closes the group's tracked connections.
pub type InterruptCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Shared, hot-swappable handle to the current [`GroupManager`].
///
/// The outer cell is stable and cloned into the control plane, per-
/// connection handles, and the clash API; a config reload swaps the inner
/// `Arc` so every holder sees the rebuilt manager at once. Reads are
/// effectively uncontended (reloads are rare), so a `parking_lot` RwLock
/// keeps the hot path cheap.
pub type SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>;

/// A dialable candidate of a group: a leaf node plus how the group
/// reached it. Direct members carry their own node name as `tag`;
/// candidates contributed by a nested sub-group carry the sub-group's tag
/// (with `via` naming that sub-group) and the leaf the sub-group's own
/// policy currently selects.
#[derive(Debug, Clone, Copy)]
struct Candidate<'a> {
    /// Display tag: node name for direct members, sub-group tag for nested.
    tag: &'a str,
    /// Leaf node that would actually be dialed.
    node: &'a Node,
    /// Sub-group tag through which the leaf was reached (`None` for direct
    /// members). Kept for introspection/debugging; selection identity uses
    /// `tag` alone.
    #[allow(dead_code)]
    via: Option<&'a str>,
}

pub struct GroupManager {
    groups: HashMap<String, Group>,
    /// Node lookup by UUID.
    nodes: HashMap<uuid::Uuid, Node>,
    /// Alive / health tracking (may be None in tests).
    alive_set: Option<Arc<AliveDialerSet>>,
    /// Per-group URLTest selection cache, split by network (TCP/UDP).
    urltest_cache: RwLock<HashMap<String, UrlTestSelections>>,
    /// Per-group, per-network round-robin counters for LoadBalance. TCP and
    /// UDP must not advance each other's sequence.
    lb_counters: HashMap<(String, SelectionNetwork), AtomicUsize>,
    /// Per-group, per-network Fallback pin. A TCP-alive/UDP-dead member must
    /// not pin both traffic classes to the same leaf.
    fallback_cache: RwLock<HashMap<(String, SelectionNetwork), String>>,
    /// Per-group last-used timestamp for idle timeout.
    last_used: RwLock<HashMap<String, Instant>>,
    /// Per-group selector choice (set via API, persisted by caller).
    /// group_name → selected node name.
    selector_choice: RwLock<HashMap<String, String>>,
    /// Invoked on selector choice changes (cache.db persistence hook).
    persist_callback: RwLock<Option<PersistCallback>>,
    /// Invoked on selection changes for groups with interrupt_connections.
    interrupt_callback: RwLock<Option<InterruptCallback>>,
}

mod selection;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod udp_selection_repro_tests;
