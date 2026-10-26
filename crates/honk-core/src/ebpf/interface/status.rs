//! What became of each configured interface entry: its state per pass, the
//! `interface_binding` degradation that implies, its log episode, the
//! reconcile-level failure episode, and the sysctl writes owed on sight. Pure
//! except for [`InterfaceState::settle`] and friends, which only log and set
//! the degradation registry; the default sysctl writer is the one I/O step.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;

use tracing::{debug, error, info, warn};

use super::{Binding, Direction, InterfacePlan, Topology, UnboundReason};
use crate::degradations::{Component, Degradations, Issue};

type Key = (NonZeroU32, Direction);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryState {
    Bound,
    /// Absent, or `auto` without a default route: appears later on its own.
    Pending,
    /// TCX create/update/verification failed; retried.
    AttachFailed,
    /// Refused (type, vrf root, honk's own link): fixed by changing the configuration.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The configured entry as written.
    pub name: String,
    pub state: EntryState,
    pub detail: String,
}

/// A binding that failed to bind or to verify, kept as text so a pass that does
/// not re-verify can carry it forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindFailure {
    pub key: Key,
    pub program: &'static str,
    pub interface: String,
    pub message: String,
}

impl BindFailure {
    pub(crate) fn new(binding: &Binding, error: &anyhow::Error) -> Self {
        Self {
            key: (binding.ifindex, binding.direction),
            program: binding.program.name(),
            interface: binding.interface.clone(),
            message: format!("{error:#}"),
        }
    }
}

/// State of every configured entry after a pass. `owned` is what the owner
/// holds once the pass committed; `failures` what could not be bound or verified.
pub(crate) fn entry_states(
    plan: &InterfacePlan,
    owned: &[Key],
    failures: &[BindFailure],
) -> Vec<Entry> {
    let mut entries: Vec<Entry> = plan
        .unbound
        .iter()
        .map(|(name, reason)| {
            let (state, detail) = match reason {
                UnboundReason::Absent => (EntryState::Pending, "no such interface".to_string()),
                UnboundReason::AutoUnresolved => (
                    EntryState::Pending,
                    "auto: no IPv4 default route yet".to_string(),
                ),
                UnboundReason::Refused(refused) => (EntryState::Unsupported, refused.to_string()),
            };
            Entry {
                name: name.clone(),
                state,
                detail,
            }
        })
        .collect();
    for (name, derived) in &plan.bound {
        let failure = failures.iter().find(|f| derived.contains(&f.key.0));
        let missing = plan
            .bindings
            .iter()
            .find(|b| derived.contains(&b.ifindex) && !owned.contains(&(b.ifindex, b.direction)));
        let (state, detail) = match (failure, missing) {
            (Some(f), _) => (
                EntryState::AttachFailed,
                format!("{} on {}: {}", f.program, f.interface, f.message),
            ),
            (None, Some(b)) => (
                EntryState::Pending,
                format!("{} on {} is not bound yet", b.program.name(), b.interface),
            ),
            (None, None) => (EntryState::Bound, String::new()),
        };
        entries.push(Entry {
            name: name.clone(),
            state,
            detail,
        });
    }
    entries
}

/// The `interface_binding` reason: `attach_failed` > `unsupported_type` >
/// `pending`; `None` when every configured entry is bound.
pub(crate) fn degradation_reason(entries: &[Entry]) -> Option<&'static str> {
    let has = |state| entries.iter().any(|entry| entry.state == state);
    if has(EntryState::AttachFailed) {
        Some("attach_failed")
    } else if has(EntryState::Unsupported) {
        Some("unsupported_type")
    } else if has(EntryState::Pending) {
        Some("pending")
    } else {
        None
    }
}

fn interface_issue(reason: &'static str) -> Issue {
    Issue {
        code: "interface_binding_incomplete",
        message: "A configured network interface is not bound; its traffic is not intercepted until it is.",
        reason,
    }
}

pub(crate) fn publish(degradations: &Degradations, reason: Option<&'static str>) {
    match reason {
        Some(reason) => degradations.set(Component::InterfaceBinding, interface_issue(reason)),
        None => degradations.clear(Component::InterfaceBinding),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    /// A new unbound condition for the entry: WARN (ERROR when unsupported).
    Begins,
    /// A bound or partly bound entry disappeared: INFO.
    Lost,
    /// The condition goes on: DEBUG.
    Continues,
    /// Bound after an unbound episode, or first seen bound: INFO.
    Bound,
}

/// One log episode per configured entry, bounded by the configured list.
#[derive(Debug, Default)]
pub(crate) struct Episodes {
    last: HashMap<String, EntryState>,
}

impl Episodes {
    /// Transitions for this pass, in `entries` order; quiet entries are omitted.
    pub(crate) fn observe(&mut self, entries: &[Entry]) -> Vec<(usize, Transition)> {
        let mut transitions = Vec::new();
        for (at, entry) in entries.iter().enumerate() {
            let previous = self.last.insert(entry.name.clone(), entry.state);
            let transition = match (previous, entry.state) {
                (Some(EntryState::Bound), EntryState::Bound) => None,
                (_, EntryState::Bound) => Some(Transition::Bound),
                (Some(before), now) if before == now => Some(Transition::Continues),
                (Some(EntryState::Bound | EntryState::AttachFailed), EntryState::Pending) => {
                    Some(Transition::Lost)
                }
                _ => Some(Transition::Begins),
            };
            transitions.extend(transition.map(|transition| (at, transition)));
        }
        self.last
            .retain(|name, _| entries.iter().any(|entry| &entry.name == name));
        transitions
    }
}

fn log_entry(entry: &Entry, transition: Transition) {
    let (name, detail) = (&entry.name, &entry.detail);
    match (transition, entry.state) {
        (Transition::Bound, _) => info!(interface = %name, "configured interface is bound"),
        (Transition::Lost, _) => {
            info!(interface = %name, "configured interface is no longer bound: {detail}")
        }
        (Transition::Begins, EntryState::Unsupported) => {
            error!(interface = %name, "configured interface is not supported: {detail}")
        }
        (Transition::Begins, EntryState::AttachFailed) => {
            warn!(interface = %name, "configured interface attach failed; retrying: {detail}")
        }
        (Transition::Begins, _) => {
            warn!(interface = %name, "configured interface is not bound yet: {detail}")
        }
        (Transition::Continues, _) => {
            debug!(interface = %name, state = ?entry.state, "configured interface still not bound: {detail}")
        }
    }
}

/// The blocking stage of a reconcile that failed as a whole, which leaves the
/// existing bindings (and the degradation) as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Topology,
    Snapshot,
    Join,
}

impl Step {
    fn what(self) -> &'static str {
        match self {
            Self::Topology => "read the network topology",
            Self::Snapshot => "snapshot interface bindings",
            Self::Join => "run the interface reconcile task",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepTransition {
    Begins,
    Continues,
}

/// WARN once per failing step, DEBUG while it persists, INFO on recovery.
#[derive(Debug, Default)]
pub(crate) struct StepEpisode {
    step: Option<Step>,
}

impl StepEpisode {
    pub(crate) fn failed(&mut self, step: Step) -> StepTransition {
        if self.step.replace(step) == Some(step) {
            StepTransition::Continues
        } else {
            StepTransition::Begins
        }
    }

    pub(crate) fn recovered(&mut self) -> Option<Step> {
        self.step.take()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SysctlKey {
    AcceptRa,
    RpFilter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SysctlWrite {
    pub key: SysctlKey,
    pub ifindex: NonZeroU32,
    pub name: String,
    /// The second, final write of this ifindex; its failure only logs at DEBUG.
    pub reassert: bool,
}

/// A late device's own udev `systemd-sysctl` run lands after our first write
/// (~20 ms on Arch) and puts back the distribution default.
const SYSCTL_REASSERT_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// Devices written, by ifindex: once on sight and once more after udev has
/// run, then never again, so an operator's later setting is left alone and a
/// host without IPv6 does not spawn `sysctl -w` every pass. A failed write
/// counts. A recreated device (new ifindex) starts over.
#[derive(Debug, Default)]
pub(crate) struct SysctlTracker {
    /// `Some(first write)` until the second write; `None` once settled.
    attempted: HashMap<(SysctlKey, NonZeroU32), Option<tokio::time::Instant>>,
}

impl SysctlTracker {
    /// The writes owed now: `accept_ra=2` for every WAN-role root and
    /// `rp_filter=0` for the first existing, bindable resolved LAN name.
    pub(crate) fn claim(
        &mut self,
        plan: &InterfacePlan,
        topology: &Topology,
        now: tokio::time::Instant,
    ) -> Vec<SysctlWrite> {
        let present: HashSet<NonZeroU32> = topology.links.iter().map(|l| l.ifindex).collect();
        self.attempted
            .retain(|(_, ifindex), _| present.contains(ifindex));
        let lan = plan
            .lan
            .iter()
            .filter(|name| {
                plan.bound.iter().any(|(entry, _)| {
                    entry == *name
                        || (honk_config::config::is_auto_interface(entry)
                            && topology.default_route.as_ref() == Some(*name))
                })
            })
            .find_map(|name| topology.links.iter().find(|link| &link.name == name))
            .map(|link| (link.ifindex, link.name.clone()));
        for ((key, ifindex), first) in &mut self.attempted {
            let targeted = match key {
                SysctlKey::AcceptRa => plan.wan_roots.iter().any(|(root, _)| root == ifindex),
                SysctlKey::RpFilter => lan.as_ref().is_some_and(|(lan, _)| lan == ifindex),
            };
            if !targeted {
                *first = None;
            }
        }
        let targets = plan
            .wan_roots
            .iter()
            .map(|(ifindex, name)| (SysctlKey::AcceptRa, *ifindex, name.clone()))
            .chain(lan.map(|(ifindex, name)| (SysctlKey::RpFilter, ifindex, name)));
        let mut owed = Vec::new();
        for (key, ifindex, name) in targets {
            let reassert = match self.attempted.get(&(key, ifindex)) {
                None => false,
                Some(Some(first)) if now >= *first + SYSCTL_REASSERT_AFTER => true,
                Some(_) => continue,
            };
            self.attempted
                .insert((key, ifindex), (!reassert).then_some(now));
            owed.push(SysctlWrite {
                key,
                ifindex,
                name,
                reassert,
            });
        }
        owed
    }

    /// When the next second write is due, if any.
    pub(crate) fn due(&self) -> Option<tokio::time::Instant> {
        self.attempted
            .values()
            .flatten()
            .min()
            .map(|first| *first + SYSCTL_REASSERT_AFTER)
    }
}

/// Run the writes; a failed first write is one WARN per ifindex, a failed
/// second write is DEBUG (the first already reported it).
pub(crate) fn perform(
    writes: &[SysctlWrite],
    write: &(dyn Fn(&SysctlWrite) -> anyhow::Result<()> + Send + Sync),
) {
    for owed in writes {
        if let Err(error) = write(owed) {
            if owed.reassert {
                debug!(interface = %owed.name, "failed to set {:?} again: {error:#}", owed.key);
            } else {
                warn!(interface = %owed.name, "failed to set {:?}: {error:#}", owed.key);
            }
        }
    }
}

/// The production writer.
pub(crate) fn write_sysctl(owed: &SysctlWrite) -> anyhow::Result<()> {
    match owed.key {
        SysctlKey::AcceptRa => crate::sysctl::enable_wan_accept_ra(&owed.name),
        SysctlKey::RpFilter => crate::sysctl::disable_rp_filter(&owed.name),
    }
}

/// Everything startup and the watcher share about the configured interfaces.
#[derive(Debug, Default)]
pub(crate) struct InterfaceState {
    episodes: Episodes,
    steps: StepEpisode,
    pub(crate) sysctl: SysctlTracker,
}

impl InterfaceState {
    /// After a pass: log each entry's transition and publish the aggregate.
    pub(crate) fn settle(
        &mut self,
        plan: &InterfacePlan,
        owned: &[Key],
        failures: &[BindFailure],
        degradations: &Degradations,
    ) {
        let entries = entry_states(plan, owned, failures);
        for (at, transition) in self.episodes.observe(&entries) {
            log_entry(&entries[at], transition);
        }
        publish(degradations, degradation_reason(&entries));
    }

    /// A stage of the reconcile failed: bindings and degradation stay as they were.
    pub(crate) fn step_failed(&mut self, step: Step, error: &anyhow::Error) {
        match self.steps.failed(step) {
            StepTransition::Begins => {
                warn!("failed to {}: {error:#}; retrying", step.what())
            }
            StepTransition::Continues => {
                debug!("still failing to {}: {error:#}", step.what())
            }
        }
    }

    /// A whole pass ran without a failed stage.
    pub(crate) fn step_recovered(&mut self) {
        if let Some(step) = self.steps.recovered() {
            info!(
                "interface reconcile recovered: able to {} again",
                step.what()
            );
        }
    }
}

/// Keys the owner holds after applying `remove` and `add` to `held`.
pub(crate) fn owned_after(held: &[Key], remove: &[Key], add: &[Key]) -> Vec<Key> {
    let mut owned: Vec<Key> = held
        .iter()
        .copied()
        .filter(|key| !remove.contains(key))
        .collect();
    for key in add {
        if !owned.contains(key) {
            owned.push(*key);
        }
    }
    owned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::interface::plan;
    use crate::netlink::LinkSnapshot;

    fn link(ifindex: u32, name: &str) -> LinkSnapshot {
        LinkSnapshot {
            ifindex: NonZeroU32::new(ifindex).unwrap(),
            name: name.into(),
            arphrd: 1,
            flags: 0,
            master: None,
            kind: None,
            mac: None,
        }
    }

    fn planned(lan: &[&str], wan: &[&str], links: Vec<LinkSnapshot>) -> InterfacePlan {
        let owned = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let topology = Topology {
            links,
            default_route: None,
        };
        plan(&owned(lan), &owned(wan), &topology)
    }

    fn keys(plan: &InterfacePlan) -> Vec<Key> {
        plan.bindings
            .iter()
            .map(|b| (b.ifindex, b.direction))
            .collect()
    }

    fn entry(name: &str, state: EntryState) -> Entry {
        Entry {
            name: name.into(),
            state,
            detail: String::new(),
        }
    }

    fn states(
        plan: &InterfacePlan,
        owned: &[Key],
        failures: &[BindFailure],
    ) -> Vec<(String, EntryState)> {
        entry_states(plan, owned, failures)
            .into_iter()
            .map(|e| (e.name, e.state))
            .collect()
    }

    #[test]
    fn degradation_reason_orders_attach_failed_over_unsupported_over_pending_and_clears() {
        use EntryState::*;
        let reason = |states: &[EntryState]| {
            let entries: Vec<_> = states.iter().map(|s| entry("x", *s)).collect();
            degradation_reason(&entries)
        };
        assert_eq!(reason(&[]), None);
        assert_eq!(reason(&[Bound, Bound]), None);
        assert_eq!(reason(&[Bound, Pending]), Some("pending"));
        assert_eq!(reason(&[Pending, Unsupported]), Some("unsupported_type"));
        assert_eq!(
            reason(&[Unsupported, Pending, AttachFailed, Bound]),
            Some("attach_failed")
        );
    }

    #[test]
    fn entry_states_follow_the_plan_the_owner_and_the_failures() {
        let plan = planned(
            &["eth0", "gone"],
            &["lo", "eth1"],
            vec![
                link(1, "lo").with_arphrd(772),
                link(2, "eth0"),
                link(3, "eth1"),
            ],
        );
        let all = keys(&plan);
        let state = |plan: &InterfacePlan, owned: &[Key], failures: &[BindFailure]| {
            states(plan, owned, failures)
        };
        let got = state(&plan, &all, &[]);
        assert!(got.contains(&("gone".into(), EntryState::Pending)));
        assert!(got.contains(&("lo".into(), EntryState::Unsupported)));
        assert!(got.contains(&("eth0".into(), EntryState::Bound)));
        assert!(got.contains(&("eth1".into(), EntryState::Bound)));

        // eth1's egress is not owned and nothing failed: it is still converging.
        let eth1 = NonZeroU32::new(3).unwrap();
        let owned: Vec<Key> = all
            .iter()
            .copied()
            .filter(|k| *k != (eth1, Direction::Egress))
            .collect();
        assert!(state(&plan, &owned, &[]).contains(&("eth1".into(), EntryState::Pending)));

        // A failure on a derived ifindex wins, owned or not.
        let failure = BindFailure {
            key: (eth1, Direction::Ingress),
            program: "wan_ingress_l2",
            interface: "eth1".into(),
            message: "boom".into(),
        };
        let got = entry_states(&plan, &owned, std::slice::from_ref(&failure));
        let eth1_entry = got.iter().find(|e| e.name == "eth1").unwrap();
        assert_eq!(eth1_entry.state, EntryState::AttachFailed);
        assert!(eth1_entry.detail.contains("boom"), "{}", eth1_entry.detail);
        assert!(
            got.iter()
                .find(|e| e.name == "eth0")
                .is_some_and(|e| e.state == EntryState::Bound)
        );
    }

    #[test]
    fn a_bridge_entry_is_unbound_when_any_port_is_unbound() {
        let mut bridge = link(10, "br0");
        bridge.kind = Some("bridge".into());
        let mut port = link(11, "p1");
        port.master = NonZeroU32::new(10);
        let plan = planned(&["br0"], &[], vec![bridge, port]);
        assert_eq!(plan.bound[0].1.len(), 2);
        let port_ingress = (NonZeroU32::new(11).unwrap(), Direction::Ingress);
        let owned: Vec<Key> = keys(&plan)
            .into_iter()
            .filter(|k| *k != port_ingress)
            .collect();
        assert_eq!(
            states(&plan, &owned, &[]),
            [("br0".to_string(), EntryState::Pending)]
        );
    }

    #[test]
    fn episodes_warn_once_log_recovery_and_keep_a_refusal_quiet() {
        use EntryState::{AttachFailed, Pending, Unsupported};
        use Transition::{Begins, Continues, Lost};
        let bound = EntryState::Bound;
        let mut episodes = Episodes::default();
        let step = |episodes: &mut Episodes, state| {
            episodes
                .observe(&[entry("eth1", state)])
                .into_iter()
                .map(|(_, t)| t)
                .collect::<Vec<_>>()
        };
        assert_eq!(step(&mut episodes, Pending), [Begins]);
        assert_eq!(step(&mut episodes, Pending), [Continues]);
        assert_eq!(step(&mut episodes, Pending), [Continues]);
        assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
        assert_eq!(step(&mut episodes, bound), []);
        // Deleted: an expected loss, then DEBUG while it persists.
        assert_eq!(step(&mut episodes, Pending), [Lost]);
        assert_eq!(step(&mut episodes, Pending), [Continues]);
        // A device that is there but cannot be attached starts a new episode.
        assert_eq!(step(&mut episodes, AttachFailed), [Begins]);
        assert_eq!(step(&mut episodes, AttachFailed), [Continues]);
        assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
        // A bound entry that now fails verification is a WARN, not a quiet loss.
        assert_eq!(step(&mut episodes, AttachFailed), [Begins]);
        // Deletion after a failed attach is still an expected lifecycle event.
        assert_eq!(step(&mut episodes, Pending), [Lost]);
        assert_eq!(step(&mut episodes, Pending), [Continues]);

        let mut episodes = Episodes::default();
        assert_eq!(step(&mut episodes, Unsupported), [Begins]);
        for _ in 0..3 {
            assert_eq!(step(&mut episodes, Unsupported), [Continues]);
        }
        // Started bound: one INFO, then silence; dropped entries are forgotten.
        let mut episodes = Episodes::default();
        assert_eq!(step(&mut episodes, bound), [Transition::Bound]);
        assert_eq!(step(&mut episodes, bound), []);
        assert!(episodes.observe(&[]).is_empty());
        assert!(episodes.last.is_empty());
    }

    #[test]
    fn a_failing_step_warns_once_and_recovers_once() {
        let mut steps = StepEpisode::default();
        assert_eq!(steps.failed(Step::Snapshot), StepTransition::Begins);
        assert_eq!(steps.failed(Step::Snapshot), StepTransition::Continues);
        assert_eq!(steps.failed(Step::Topology), StepTransition::Begins);
        assert_eq!(steps.recovered(), Some(Step::Topology));
        assert_eq!(steps.recovered(), None);
        assert_eq!(steps.failed(Step::Topology), StepTransition::Begins);
    }

    fn write_names(owed: &[SysctlWrite]) -> Vec<(SysctlKey, &str, bool)> {
        owed.iter()
            .map(|w| (w.key, w.name.as_str(), w.reassert))
            .collect()
    }

    #[test]
    fn sysctl_is_written_on_sight_and_once_more_after_udev_then_left_alone() {
        let t0 = tokio::time::Instant::now();
        let after = |ms: u64| t0 + std::time::Duration::from_millis(ms);
        let links = || vec![link(2, "wan.100"), link(3, "br0"), link(4, "eth1")];
        let mut tracker = SysctlTracker::default();
        let topology = Topology {
            links: links(),
            default_route: None,
        };
        let plan = plan_of(&["br0", "eth1"], &["wan.100"], &topology);
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, t0)),
            [
                (SysctlKey::AcceptRa, "wan.100", false),
                (SysctlKey::RpFilter, "br0", false)
            ]
        );
        assert_eq!(tracker.due(), Some(after(1000)));
        // Inside udev's window nothing is owed, failed or not.
        assert!(tracker.claim(&plan, &topology, after(999)).is_empty());
        // After it, the second and last write of each.
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, after(1000))),
            [
                (SysctlKey::AcceptRa, "wan.100", true),
                (SysctlKey::RpFilter, "br0", true)
            ]
        );
        assert_eq!(tracker.due(), None);
        assert!(tracker.claim(&plan, &topology, after(60_000)).is_empty());

        // The WAN device is recreated under a new ifindex: it starts over.
        let mut recreated = links();
        recreated[0].ifindex = NonZeroU32::new(9).unwrap();
        let topology = Topology {
            links: recreated,
            default_route: None,
        };
        let plan = plan_of(&["br0", "eth1"], &["wan.100"], &topology);
        let owed = tracker.claim(&plan, &topology, after(61_000));
        assert_eq!(
            write_names(&owed),
            [(SysctlKey::AcceptRa, "wan.100", false)]
        );
        assert_eq!(owed[0].ifindex.get(), 9);

        // The first LAN vanishes: rp_filter moves to the first one that exists.
        let topology = Topology {
            links: vec![link(9, "wan.100"), link(4, "eth1")],
            default_route: None,
        };
        let plan = plan_of(&["br0", "eth1"], &["wan.100"], &topology);
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, after(61_500))),
            [(SysctlKey::RpFilter, "eth1", false)]
        );
        // Everything gone: the tracker forgets it, so a return is written again.
        let topology = Topology::default();
        let plan = plan_of(&["br0"], &["wan.100"], &topology);
        assert!(tracker.claim(&plan, &topology, after(62_000)).is_empty());
        assert!(tracker.attempted.is_empty());
        assert_eq!(tracker.due(), None);
    }

    #[test]
    fn moving_sysctl_targets_cancel_the_old_deadlines_while_devices_remain() {
        let t0 = tokio::time::Instant::now();
        let mut topology = Topology {
            links: vec![link(2, "eth1"), link(3, "wan0"), link(4, "wan1")],
            default_route: Some("wan0".into()),
        };
        let mut tracker = SysctlTracker::default();
        let plan = plan_of(&["br0", "eth1"], &["auto"], &topology);
        assert_eq!(tracker.claim(&plan, &topology, t0).len(), 2);

        topology.links.push(link(5, "br0"));
        topology.default_route = Some("wan1".into());
        let plan = plan_of(&["br0", "eth1"], &["auto"], &topology);
        let moved = t0 + std::time::Duration::from_millis(500);
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, moved)),
            [
                (SysctlKey::AcceptRa, "wan1", false),
                (SysctlKey::RpFilter, "br0", false),
            ]
        );
        assert_eq!(tracker.due(), Some(moved + SYSCTL_REASSERT_AFTER));
        assert_eq!(tracker.claim(&plan, &topology, moved + SYSCTL_REASSERT_AFTER).len(), 2);
        assert_eq!(tracker.due(), None);
    }

    #[test]
    fn rp_filter_skips_refused_lan_entries_including_auto() {
        let topology = Topology {
            links: vec![link(1, "lo").with_arphrd(libc::ARPHRD_LOOPBACK), link(2, "eth1")],
            default_route: Some("lo".into()),
        };
        for first in ["lo", "auto"] {
            let plan = plan_of(&[first, "eth1"], &[], &topology);
            let mut tracker = SysctlTracker::default();
            assert_eq!(
                write_names(&tracker.claim(&plan, &topology, tokio::time::Instant::now())),
                [(SysctlKey::RpFilter, "eth1", false)],
                "{first}"
            );
        }
    }

    fn plan_of(lan: &[&str], wan: &[&str], topology: &Topology) -> InterfacePlan {
        let owned = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        plan(&owned(lan), &owned(wan), topology)
    }

    #[test]
    fn a_wan_that_is_also_lan_gets_accept_ra_once() {
        let topology = Topology {
            links: vec![link(2, "eth0")],
            default_route: None,
        };
        let plan = plan_of(&["eth0"], &["eth0"], &topology);
        let mut tracker = SysctlTracker::default();
        assert_eq!(
            write_names(&tracker.claim(&plan, &topology, tokio::time::Instant::now())),
            [
                (SysctlKey::AcceptRa, "eth0", false),
                (SysctlKey::RpFilter, "eth0", false)
            ]
        );
    }

    #[test]
    fn owned_after_applies_removals_and_additions() {
        let key = |i: u32, d| (NonZeroU32::new(i).unwrap(), d);
        let held = [key(2, Direction::Ingress), key(2, Direction::Egress)];
        let after = owned_after(
            &held,
            &[key(2, Direction::Egress)],
            &[key(3, Direction::Ingress), key(2, Direction::Ingress)],
        );
        assert_eq!(
            after,
            [key(2, Direction::Ingress), key(3, Direction::Ingress)]
        );
    }

    trait WithArphrd {
        fn with_arphrd(self, arphrd: u16) -> Self;
    }
    impl WithArphrd for LinkSnapshot {
        fn with_arphrd(mut self, arphrd: u16) -> Self {
            self.arphrd = arphrd;
            self
        }
    }
}
