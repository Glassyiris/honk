//! Interface binding plan: one pure function from the configured LAN/WAN
//! entries and one rtnetlink topology snapshot to the set of TCX bindings the
//! datapath wants. No Aya, no I/O except [`read_topology`] and [`local_ip`].
//!
//! Relations (at most two levels, anything deeper or looping is an `Err`, never
//! a half plan):
//! - a member of a `bond`/`bridge` resolves to that master; a bond that is a
//!   bridge port resolves to the bridge;
//! - a member of any other master except `vrf`/`openvswitch` resolves to that
//!   master (one level); `vrf`/`openvswitch` members stay themselves;
//! - a LAN-intent bridge root also binds every port (a bond port stays one
//!   logical port); a bond root binds only itself, never its members.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;

use anyhow::{Context as _, bail};
use honk_config::config::{default_route_interface_from, is_auto_interface};

use crate::netlink::{LinkSnapshot, NlSock};

pub(crate) mod status;
use status::{Step, StepError};

const DUMP_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TcProgram {
    LanIngressL2,
    LanIngressL3,
    LanEgressL2,
    LanEgressL3,
    WanIngressL2,
    WanIngressL3,
    WanEgressL2,
    WanEgressL3,
}

impl TcProgram {
    pub const ALL: [Self; 8] = [
        Self::LanIngressL2,
        Self::LanIngressL3,
        Self::LanEgressL2,
        Self::LanEgressL3,
        Self::WanIngressL2,
        Self::WanIngressL3,
        Self::WanEgressL2,
        Self::WanEgressL3,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::LanIngressL2 => "lan_ingress_l2",
            Self::LanIngressL3 => "lan_ingress_l3",
            Self::LanEgressL2 => "lan_egress_l2",
            Self::LanEgressL3 => "lan_egress_l3",
            Self::WanIngressL2 => "wan_ingress_l2",
            Self::WanIngressL3 => "wan_ingress_l3",
            Self::WanEgressL2 => "wan_egress_l2",
            Self::WanEgressL3 => "wan_egress_l3",
        }
    }

    /// `lan` selects the LAN program family; `l2` the Ethernet framing.
    fn select(lan: bool, direction: Direction, l2: bool) -> Self {
        match (lan, direction, l2) {
            (true, Direction::Ingress, true) => Self::LanIngressL2,
            (true, Direction::Ingress, false) => Self::LanIngressL3,
            (true, Direction::Egress, true) => Self::LanEgressL2,
            (true, Direction::Egress, false) => Self::LanEgressL3,
            (false, Direction::Ingress, true) => Self::WanIngressL2,
            (false, Direction::Ingress, false) => Self::WanIngressL3,
            (false, Direction::Egress, true) => Self::WanEgressL2,
            (false, Direction::Egress, false) => Self::WanEgressL3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub ifindex: NonZeroU32,
    pub direction: Direction,
    pub program: TcProgram,
    /// Name of the bound link itself (a bridge port, not its root).
    pub interface: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnboundReason {
    /// No link with that name in the snapshot.
    Absent,
    /// `auto` with no IPv4 default route.
    AutoUnresolved,
    /// Present but never bindable; fixed by changing the configuration.
    Refused(RefusedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusedReason {
    /// The canonical root has no framing the programs can parse.
    UnsupportedType { arphrd: u16 },
    /// A `vrf` device: members see the traffic, never the VRF itself.
    VrfRoot,
    /// `dae0` / `dae0peer`.
    OwnedLink,
}

impl std::fmt::Display for RefusedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedType { arphrd } => write!(f, "unsupported link type {arphrd}"),
            Self::VrfRoot => f.write_str("a vrf device (configure a member instead)"),
            Self::OwnedLink => f.write_str("a link honk owns"),
        }
    }
}

/// Which TC program family fits a link; decided from `(ifi_type, ifi_flags)`
/// alone, so a bond or team master follows its current first port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// Ethernet header at the TC hook.
    L2,
    /// Bare IP at the TC hook.
    L3,
    Unsupported,
}

const ARPHRD_RAWIP: u16 = 519;
const ARPHRD_IP6GRE: u16 = 823;

impl Framing {
    pub(crate) fn of(arphrd: u16, flags: u32) -> Self {
        match arphrd {
            libc::ARPHRD_ETHER => Self::L2,
            libc::ARPHRD_NONE
            | libc::ARPHRD_PPP
            | ARPHRD_RAWIP
            | libc::ARPHRD_TUNNEL
            | libc::ARPHRD_TUNNEL6
            | libc::ARPHRD_SIT => Self::L3,
            // A GRE device with `header_ops` (multicast or no remote) prepends
            // a tunnel header; only a point-to-point, non-broadcast one is bare IP.
            libc::ARPHRD_IPGRE | ARPHRD_IP6GRE
                if flags & libc::IFF_POINTOPOINT as u32 != 0
                    && flags & libc::IFF_BROADCAST as u32 == 0 =>
            {
                Self::L3
            }
            _ => Self::Unsupported,
        }
    }
}

fn refusal(root: &LinkSnapshot) -> Option<RefusedReason> {
    if root.kind.as_deref() == Some("vrf") {
        Some(RefusedReason::VrfRoot)
    } else if Framing::of(root.arphrd, root.flags) == Framing::Unsupported {
        Some(RefusedReason::UnsupportedType {
            arphrd: root.arphrd,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Topology {
    pub links: Vec<LinkSnapshot>,
    /// Interface of the lowest-metric IPv4 default route; only read (and only
    /// meaningful) when some configured entry is `auto`.
    pub default_route: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InterfacePlan {
    /// Unique `(ifindex, direction)`, sorted by that key.
    pub bindings: Vec<Binding>,
    /// Configured entries as written that are not bound this round.
    pub unbound: Vec<(String, UnboundReason)>,
    /// Resolved configured names (absent ones included), config order,
    /// `auto` resolved, deduplicated. Unresolved `auto` is omitted.
    pub lan: Vec<String>,
    pub wan: Vec<String>,
    /// Canonical roots of the existing LAN names (self-protection, local_ip).
    pub lan_roots: Vec<String>,
    /// Canonical roots with WAN intent, `LanWan` included (accept_ra targets).
    pub wan_roots: Vec<(NonZeroU32, String)>,
    /// Configured entries as written that resolve to a bindable root, with every
    /// ifindex their bindings derive from (root and bridge ports).
    /// Unresolved `auto`, absent and refused entries are in `unbound` instead.
    pub bound: Vec<(String, Vec<NonZeroU32>)>,
}

/// What the owner holds; moved into the apply step.
#[derive(Debug, Default)]
pub struct BindingSnapshot {
    pub(crate) programs: Vec<(TcProgram, OwnedFd)>,
    /// `(binding, link id, dup of the link fd)`.
    pub(crate) owned: Vec<(Binding, u32, OwnedFd)>,
}

#[derive(Debug, Default)]
pub struct BindingCommit {
    pub(crate) add: Vec<(Binding, u32, OwnedFd)>,
    pub(crate) remove: Vec<(NonZeroU32, Direction)>,
    pub(crate) reprogram: Vec<(NonZeroU32, Direction, TcProgram)>,
    /// Retained keys whose link now has another name (same ifindex).
    pub(crate) rename: Vec<(NonZeroU32, Direction, String)>,
}

impl BindingCommit {
    pub(crate) fn is_empty(&self) -> bool {
        self.add.is_empty()
            && self.remove.is_empty()
            && self.reprogram.is_empty()
            && self.rename.is_empty()
    }

    /// Apply to an owner's `(binding, link id, link fd)` table: removals, then
    /// reprograms and renames, then adds. An add for an existing
    /// `(ifindex, direction)` replaces it; a removal, reprogram or rename of a
    /// missing key is ignored. The replaced or removed FDs are returned so the
    /// caller closes them outside any lock.
    pub(crate) fn apply_to(self, owned: &mut Vec<(Binding, u32, OwnedFd)>) -> Vec<OwnedFd> {
        let mut closed = Vec::new();
        let key = |b: &Binding| (b.ifindex, b.direction);
        for gone in self.remove {
            if let Some(at) = owned.iter().position(|(b, ..)| key(b) == gone) {
                closed.push(owned.swap_remove(at).2);
            }
        }
        for (ifindex, direction, program) in self.reprogram {
            if let Some((b, ..)) = owned
                .iter_mut()
                .find(|(b, ..)| (b.ifindex, b.direction) == (ifindex, direction))
            {
                b.program = program;
            }
        }
        for (ifindex, direction, interface) in self.rename {
            if let Some((b, ..)) = owned
                .iter_mut()
                .find(|(b, ..)| key(b) == (ifindex, direction))
            {
                b.interface = interface;
            }
        }
        for added in self.add {
            if let Some(at) = owned.iter().position(|(b, ..)| key(b) == key(&added.0)) {
                closed.push(std::mem::replace(&mut owned[at], added).2);
            } else {
                owned.push(added);
            }
        }
        closed
    }
}

#[derive(Debug, Default)]
pub(crate) struct ApplyReport {
    pub commit: BindingCommit,
    pub failed: Vec<(Binding, anyhow::Error)>,
    pub topology_changed: bool,
}

/// Blocking: rtnetlink link dump, retried up to three times when it races a
/// table change.
pub(crate) fn dump_links() -> io::Result<Vec<LinkSnapshot>> {
    retry_interrupted(|| NlSock::new()?.dump_links())
}

/// Blocking: rtnetlink link dump (up to three attempts when it races a table
/// change) and, only when `need_default_route`, the route table. A failed
/// route read is an error, never "no default route". Both views are the
/// calling thread's network namespace (`/proc/net` would be the process's).
pub(crate) fn read_topology(need_default_route: bool) -> anyhow::Result<Topology> {
    let links = dump_links().context("dump links")?;
    let default_route = if need_default_route {
        default_route(std::fs::read_to_string("/proc/thread-self/net/route"))?
    } else {
        None
    };
    Ok(Topology {
        links,
        default_route,
    })
}

/// One topology read through `read` and the plan derived from it; the error
/// says which of the two stages failed.
pub(crate) fn read_and_plan_with(
    read: impl FnOnce(bool) -> anyhow::Result<Topology>,
    lan: &[String],
    wan: &[String],
) -> Result<(Topology, InterfacePlan), StepError> {
    let any_auto = lan.iter().chain(wan).any(|name| is_auto_interface(name));
    let topology = read(any_auto).map_err(|error| StepError {
        step: Step::Topology,
        error,
    })?;
    let plan = plan(lan, wan, &topology).map_err(|error| StepError {
        step: Step::Plan,
        error,
    })?;
    Ok((topology, plan))
}

/// [`read_and_plan_with`] over the live topology.
pub(crate) fn read_and_plan(
    lan: &[String],
    wan: &[String],
) -> anyhow::Result<(Topology, InterfacePlan)> {
    read_and_plan_with(read_topology, lan, wan).map_err(|failed| failed.error)
}

fn retry_interrupted<T>(mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut attempt = 1;
    loop {
        match op() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted && attempt < DUMP_ATTEMPTS => {
                attempt += 1;
            }
            result => return result,
        }
    }
}

fn default_route(read: io::Result<String>) -> anyhow::Result<Option<String>> {
    let text = read.context("read /proc/net/route")?;
    Ok(default_route_interface_from(&text))
}

struct Index<'a> {
    by_name: HashMap<&'a str, &'a LinkSnapshot>,
    by_index: HashMap<NonZeroU32, &'a LinkSnapshot>,
}

impl<'a> Index<'a> {
    fn new(links: &'a [LinkSnapshot]) -> Self {
        Self {
            by_name: links
                .iter()
                .map(|link| (link.name.as_str(), link))
                .collect(),
            by_index: links.iter().map(|link| (link.ifindex, link)).collect(),
        }
    }

    fn master(&self, link: &LinkSnapshot) -> Option<&'a LinkSnapshot> {
        self.by_index.get(&link.master?).copied()
    }
}

fn is_bond_or_bridge(link: &LinkSnapshot) -> bool {
    matches!(link.kind.as_deref(), Some("bond" | "bridge"))
}

fn canonical_root<'a>(
    index: &Index<'a>,
    link: &'a LinkSnapshot,
) -> anyhow::Result<&'a LinkSnapshot> {
    let Some(master) = index.master(link) else {
        return Ok(link);
    };
    if master.ifindex == link.ifindex {
        bail!("interface '{}' is its own master", link.name);
    }
    match master.kind.as_deref() {
        Some("vrf" | "openvswitch") => Ok(link),
        Some(kind @ ("bond" | "bridge")) => {
            let Some(upper) = index.master(master) else {
                return Ok(master);
            };
            match (kind, upper.kind.as_deref()) {
                ("bond", Some("bridge")) => {
                    if index.master(upper).is_some_and(is_bond_or_bridge) {
                        bail!(
                            "interface '{}' nests more than two bond/bridge levels ({} -> {} -> {})",
                            link.name,
                            master.name,
                            upper.name,
                            index.master(upper).map_or("?", |top| top.name.as_str())
                        );
                    }
                    Ok(upper)
                }
                (_, Some("bond" | "bridge")) => bail!(
                    "interface '{}' has unsupported bond/bridge nesting ({} -> {})",
                    link.name,
                    master.name,
                    upper.name
                ),
                _ => Ok(master),
            }
        }
        _ => Ok(master),
    }
}

struct Root<'a> {
    link: &'a LinkSnapshot,
    lan: bool,
    wan: bool,
    /// Root plus the bridge ports its intent binds.
    derived: Vec<NonZeroU32>,
}

/// Resolve entries to names in config order: `auto` through the default route,
/// deduplicated by name. Unresolved `auto` goes to `unbound`.
fn resolve(
    entries: &[String],
    default_route: Option<&str>,
    unbound: &mut Vec<(String, UnboundReason)>,
) -> Vec<(String, String)> {
    let mut resolved: Vec<(String, String)> = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = if is_auto_interface(entry) {
            match default_route {
                Some(name) => name,
                None => {
                    note_unbound(unbound, entry, UnboundReason::AutoUnresolved);
                    continue;
                }
            }
        } else {
            entry.as_str()
        };
        if !resolved.iter().any(|(existing, _)| existing == name) {
            resolved.push((name.to_string(), entry.clone()));
        }
    }
    resolved
}

fn note_unbound(unbound: &mut Vec<(String, UnboundReason)>, entry: &str, reason: UnboundReason) {
    if !unbound.iter().any(|(e, r)| e == entry && *r == reason) {
        unbound.push((entry.to_string(), reason));
    }
}

/// Mark the root of every bindable name with `lan`/`wan` intent; refused and
/// absent names are reported in `unbound` and mark nothing.
fn mark_roots<'a>(
    index: &Index<'a>,
    names: &[(String, String)],
    lan: bool,
    roots: &mut Vec<Root<'a>>,
    unbound: &mut Vec<(String, UnboundReason)>,
) -> anyhow::Result<Vec<Option<NonZeroU32>>> {
    let mut ids = Vec::with_capacity(names.len());
    for (name, entry) in names {
        // honk's own links are refused by configured name (`dae0peer` is in daens).
        let owned = matches!(name.as_str(), "dae0" | "dae0peer");
        let link = index.by_name.get(name.as_str());
        let (Some(link), false) = (link, owned) else {
            let reason = if owned {
                UnboundReason::Refused(RefusedReason::OwnedLink)
            } else {
                UnboundReason::Absent
            };
            note_unbound(unbound, entry, reason);
            ids.push(None);
            continue;
        };
        let root = canonical_root(index, link)?;
        if let Some(reason) = refusal(root) {
            note_unbound(unbound, entry, UnboundReason::Refused(reason));
            ids.push(None);
            continue;
        }
        let slot = match roots.iter().position(|r| r.link.ifindex == root.ifindex) {
            Some(slot) => slot,
            None => {
                roots.push(Root {
                    link: root,
                    lan: false,
                    wan: false,
                    derived: vec![root.ifindex],
                });
                roots.len() - 1
            }
        };
        if lan {
            roots[slot].lan = true;
        } else {
            roots[slot].wan = true;
        }
        ids.push(Some(root.ifindex));
    }
    Ok(ids)
}

fn bind(
    bindings: &mut BTreeMap<(NonZeroU32, Direction), Binding>,
    link: &LinkSnapshot,
    direction: Direction,
    lan: bool,
) {
    // A bridge port the programs cannot parse is skipped.
    let l2 = match Framing::of(link.arphrd, link.flags) {
        Framing::L2 => true,
        Framing::L3 => false,
        Framing::Unsupported => return,
    };
    let program = TcProgram::select(lan, direction, l2);
    bindings
        .entry((link.ifindex, direction))
        .or_insert_with(|| Binding {
            ifindex: link.ifindex,
            direction,
            program,
            interface: link.name.clone(),
        });
}

fn dedup_roots(ids: &[Option<NonZeroU32>]) -> Vec<NonZeroU32> {
    let mut out: Vec<NonZeroU32> = Vec::new();
    for id in ids.iter().flatten() {
        if !out.contains(id) {
            out.push(*id);
        }
    }
    out
}

pub(crate) fn plan(
    lan: &[String],
    wan: &[String],
    topology: &Topology,
) -> anyhow::Result<InterfacePlan> {
    let index = Index::new(&topology.links);
    let mut unbound = Vec::new();
    let lan_names = resolve(lan, topology.default_route.as_deref(), &mut unbound);
    let wan_names = resolve(wan, topology.default_route.as_deref(), &mut unbound);

    let mut roots: Vec<Root> = Vec::new();
    let lan_ids = mark_roots(&index, &lan_names, true, &mut roots, &mut unbound)?;
    let wan_ids = mark_roots(&index, &wan_names, false, &mut roots, &mut unbound)?;

    // Roots first: a root's own role binding wins over any expansion.
    let mut bindings = BTreeMap::new();
    for root in &roots {
        // Lan: lan/lan. Wan: wan/wan. LanWan: LAN ingress, WAN egress.
        bind(&mut bindings, root.link, Direction::Ingress, root.lan);
        bind(
            &mut bindings,
            root.link,
            Direction::Egress,
            root.lan && !root.wan,
        );
    }
    for root in &mut roots {
        if root.link.kind.as_deref() == Some("bridge") && root.lan {
            for port in topology
                .links
                .iter()
                .filter(|l| l.master == Some(root.link.ifindex))
            {
                bind(&mut bindings, port, Direction::Ingress, true);
                bind(&mut bindings, port, Direction::Egress, true);
                root.derived.push(port.ifindex);
            }
        }
    }

    let mut bound: Vec<(String, Vec<NonZeroU32>)> = Vec::new();
    for (names, ids) in [(&lan_names, &lan_ids), (&wan_names, &wan_ids)] {
        for ((_, entry), id) in names.iter().zip(ids) {
            let Some(id) = id else { continue };
            if !bound.iter().any(|(existing, _)| existing == entry)
                && let Some(root) = roots.iter().find(|r| r.link.ifindex == *id)
            {
                bound.push((entry.clone(), root.derived.clone()));
            }
        }
    }
    let lan_list: Vec<String> = lan_names.into_iter().map(|(name, _)| name).collect();
    let wan_list: Vec<String> = wan_names.into_iter().map(|(name, _)| name).collect();

    let root_named = |id: NonZeroU32| index.by_index[&id].name.clone();
    let lan_roots = dedup_roots(&lan_ids).into_iter().map(root_named).collect();
    let wan_roots = dedup_roots(&wan_ids)
        .into_iter()
        .map(|id| (id, root_named(id)))
        .collect();

    Ok(InterfacePlan {
        bindings: bindings.into_values().collect(),
        unbound,
        lan: lan_list,
        wan: wan_list,
        lan_roots,
        wan_roots,
        bound,
    })
}

/// The canonical root the binding uses: first LAN root, else first WAN root
/// (refused and absent names never reach either list).
pub(crate) fn local_ip_interface(plan: &InterfacePlan) -> Option<&str> {
    plan.lan_roots
        .first()
        .or_else(|| plan.wan_roots.first().map(|(_, name)| name))
        .map(String::as_str)
}

/// First IPv4 of [`local_ip_interface`] as `u32::from_ne_bytes(octets)`; 0 if none.
pub(crate) fn local_ip(plan: &InterfacePlan) -> u32 {
    let Some(name) = local_ip_interface(plan) else {
        return 0;
    };
    nix::ifaddrs::getifaddrs()
        .ok()
        .and_then(|mut addrs| {
            addrs.find_map(|ifa| {
                if ifa.interface_name != name {
                    return None;
                }
                ifa.address?
                    .as_sockaddr_in()
                    .map(|sock| u32::from_ne_bytes(sock.ip().octets()))
            })
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
