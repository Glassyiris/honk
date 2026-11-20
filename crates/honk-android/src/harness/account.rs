//! Per-role accounting over one measurement window, from `sys` thread readings: CPU time,
//! context switches, last CPU, the CPU masks read back, the cpuset, the tun counters, the
//! payload and the app's platform state at both ends.
//!
//! Owns the checks that reject a window: no engine thread, a thread whose mask differs from its
//! role's pin, a mask that changes or a thread that exits inside the window, engine threads at
//! the end that are not the ones at the start (hev may start threads at any time), a cpuset that
//! changes or cannot be read, a screen that is off or a bench Activity that is not in front at
//! either end. It reads /proc (the masks too, through each thread's handle), the engine and the
//! host, never pins; the runner thread calls `open` right before the window starts and `close`
//! right after it ends.
//!
//! Every counter (thread CPU time and switches, tun, payload) is read between the window's two
//! boundary timestamps, so the elapsed time covers all they count. The platform probe, which
//! calls into the app, the cpuset and the masks are read outside them. The threads are read one
//! after another, so a thread's counters cover the window less the two scans at most, whose
//! lengths the window records.

use super::engine::Running;
use super::load::Workload;
use super::plan::Cpus;
use super::run::Host;
use crate::sys::{self, Thread, ThreadSample};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::io;
use std::time::Instant;

/// `Display.STATE_ON`.
pub const DISPLAY_STATE_ON: i32 = 2;

/// The app's state at one end of a window, from the host's `platform()` JSON object.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Platform {
    /// `PowerManager.isInteractive()`.
    pub interactive: bool,
    /// `Display.getState()` of the default display.
    pub display_state: i32,
    /// The bench Activity is the resumed top activity.
    pub bench_activity_resumed: bool,
    /// `Build.VERSION.SDK_INT_FULL` and `Build.ID`.
    pub sdk_int_full: i64,
    pub build_id: String,
    /// Whatever else the app reports (thermal state, brightness, ...), recorded as given.
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

/// Reads the platform state; `reasons` gets why it rejects the window.
fn platform(host: &dyn Host, end: &str, reasons: &mut Vec<String>) -> Option<Platform> {
    match host.platform() {
        Ok(p) => {
            if !p.interactive || p.display_state != DISPLAY_STATE_ON {
                reasons.push(format!("screen off at the window {end}"));
            }
            if !p.bench_activity_resumed {
                reasons.push(format!("not foreground at the window {end}"));
            }
            Some(p)
        }
        Err(e) => {
            reasons.push(format!("platform unreadable at the window {end}: {e}"));
            None
        }
    }
}

/// Reads the cpuset, which a window needs at both ends: a move resets every mask.
fn cpuset(end: &str, reasons: &mut Vec<String>) -> Option<String> {
    sys::cpuset()
        .map_err(|e| reasons.push(format!("cpuset unreadable at the window {end}: {e}")))
        .ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Engine,
    Relay,
    Generator,
    Sink,
}

/// Packets and bytes the engine read from and wrote to the tun.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Tun {
    pub reads: u64,
    pub read_bytes: u64,
    pub writes: u64,
    pub write_bytes: u64,
}

impl Tun {
    /// The change since `start`; None if a counter went back (the engine was reset).
    fn since(self, start: Tun) -> Option<Tun> {
        Some(Tun {
            reads: self.reads.checked_sub(start.reads)?,
            read_bytes: self.read_bytes.checked_sub(start.read_bytes)?,
            writes: self.writes.checked_sub(start.writes)?,
            write_bytes: self.write_bytes.checked_sub(start.write_bytes)?,
        })
    }
}

/// One thread over the window; a value is null when the thread could not be read.
#[derive(Clone, Debug, Serialize)]
pub struct ThreadStats {
    pub tid: i32,
    pub comm: Option<String>,
    /// Its CPU mask, read back when the window opened.
    pub cpus: Option<String>,
    pub last_cpu: Option<i32>,
    pub cpu_ns: Option<u64>,
}

/// Sums over a set of threads. A sum is null when a thread's value could not be read; the
/// record's `reason` or `unreadable` says why.
#[derive(Debug, Serialize)]
pub struct Totals {
    /// schedstat run time, the CPU time figure; the ticks give only the user/system split.
    pub cpu_ns: Option<u64>,
    pub user_ticks: Option<u64>,
    pub system_ticks: Option<u64>,
    pub voluntary_switches: Option<u64>,
    pub nonvoluntary_switches: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RoleStats {
    #[serde(flatten)]
    pub totals: Totals,
    pub threads: Vec<ThreadStats>,
}

#[derive(Debug, Serialize)]
pub struct Roles {
    pub engine: RoleStats,
    /// hev only.
    pub relay: Option<RoleStats>,
    pub generator: RoleStats,
    pub sink: RoleStats,
    /// Engine and relay together: what hev costs including its extra user-space hop.
    pub engine_relay: Totals,
}

/// The threads of one role to account, and the CPUs they must stay on.
pub struct RoleThreads<'a> {
    pub role: Role,
    pub tids: Vec<i32>,
    pub cpus: &'a Cpus,
}

/// A thread from the window's start: its handle, mask and first reading, or None if it was
/// gone by then.
struct Watched {
    tid: i32,
    start: Option<(Thread, Vec<usize>, ThreadSample)>,
}

struct Opened {
    role: Role,
    threads: Vec<Watched>,
}

/// A window between `open` and `close`.
pub struct Window {
    roles: Vec<Opened>,
    cpuset: Option<String>,
    tun: Result<Tun, String>,
    platform: Option<Platform>,
    start_ns: u64,
    at: Instant,
    scan_start_ns: u64,
    reasons: Vec<String>,
}

/// What a closed window recorded.
pub struct Closed {
    pub boottime_start_ns: u64,
    pub boottime_end_ns: u64,
    pub elapsed_ns: u64,
    /// From the start to the last thread's first reading, and from the first thread's last
    /// reading to the end: what each thread's counters may leave out of the window.
    pub scan_start_ns: u64,
    pub scan_end_ns: u64,
    pub roles: Roles,
    pub cpuset_start: Option<String>,
    pub cpuset_end: Option<String>,
    /// The change over the window, or why there is none.
    pub tun: Result<Tun, String>,
    /// Payload the receiving side read in the window, and the sparse sends; None without a
    /// workload.
    pub received: Option<u64>,
    pub sends: Option<u64>,
    pub platform_start: Option<Platform>,
    pub platform_end: Option<Platform>,
    /// Why the measurement is rejected; empty if it is not.
    pub reasons: Vec<String>,
    /// Why a value above is null.
    pub unreadable: Vec<String>,
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Engine => "engine",
        Role::Relay => "relay",
        Role::Generator => "generator",
        Role::Sink => "sink",
    }
}

impl Window {
    /// Reads the platform, the cpuset and every thread's mask, then starts the window: its
    /// timestamps, the tun counters and every thread's counters. A workload's flows start after
    /// this returns, so its payload starts at zero.
    pub fn open(roles: &[RoleThreads], host: &dyn Host, engine: &Running) -> Window {
        let mut reasons = Vec::new();
        let platform = platform(host, "start", &mut reasons);
        let cpuset = cpuset("start", &mut reasons);
        let mut masked = Vec::new();
        for r in roles {
            let name = role_name(r.role);
            if r.role == Role::Engine && r.tids.is_empty() {
                reasons.push("no engine thread".into());
            }
            let mut threads = Vec::new();
            for &tid in &r.tids {
                match Thread::open(tid).and_then(|t| Ok((t.affinity()?, t))) {
                    Ok((mask, t)) => {
                        if mask != r.cpus.as_slice() {
                            reasons.push(format!(
                                "{name} thread {tid} runs on {}, pinned to {}",
                                sys::format_cpu_list(&mask),
                                r.cpus
                            ));
                        }
                        threads.push((tid, Some((t, mask))));
                    }
                    Err(e) => {
                        reasons.push(format!("{name} thread {tid} is gone: {e}"));
                        threads.push((tid, None));
                    }
                }
            }
            masked.push((r.role, threads));
        }
        let start_ns = sys::boottime_ns();
        let at = Instant::now();
        let tun = engine.tun(host);
        let mut opened = Vec::new();
        for (role, threads) in masked {
            let mut watched = Vec::new();
            for (tid, handle) in threads {
                let start = handle.and_then(|(t, mask)| match t.sample() {
                    Ok(s) => Some((t, mask, s)),
                    Err(e) => {
                        reasons.push(format!("{} thread {tid} is gone: {e}", role_name(role)));
                        None
                    }
                });
                watched.push(Watched { tid, start });
            }
            opened.push(Opened {
                role,
                threads: watched,
            });
        }
        let scan_start_ns = sys::boottime_ns() - start_ns;
        Window {
            roles: opened,
            cpuset,
            tun,
            platform,
            start_ns,
            at,
            scan_start_ns,
            reasons,
        }
    }

    /// Reads every counter again (and `load`'s payload), ends the window, then reads the
    /// platform, the cpuset, the engine's threads and the masks.
    pub fn close(self, host: &dyn Host, engine: &Running, load: Option<&Workload>) -> Closed {
        let scan_ns = sys::boottime_ns();
        let ends: Vec<Vec<_>> = (self.roles.iter())
            .map(|r| {
                (r.threads.iter())
                    .map(|w| w.start.as_ref().map(|(t, _, _)| t.sample()))
                    .collect()
            })
            .collect();
        let tun_end = engine.tun(host);
        let payload = load.map(|w| (w.received(), w.sends()));
        let end_ns = sys::boottime_ns();
        let elapsed_ns = self.at.elapsed().as_nanos() as u64;
        let mut reasons = self.reasons;
        let platform_end = platform(host, "end", &mut reasons);
        let cpuset_end = cpuset("end", &mut reasons);
        if let (Some(a), Some(b)) = (&self.cpuset, &cpuset_end)
            && a != b
        {
            reasons.push(format!("cpuset changed from {a} to {b}"));
        }
        let engine_tids = (self.roles.iter())
            .filter(|r| r.role == Role::Engine)
            .flat_map(|r| r.threads.iter().map(|w| w.tid));
        if let Some(e) = threads_changed(engine_tids.collect(), engine.threads()) {
            reasons.push(e);
        }
        let mut unreadable = Vec::new();
        let deltas: Vec<_> = (self.roles.iter().zip(ends))
            .map(|(r, ends)| (r.role, close_role(r, ends, &mut reasons, &mut unreadable)))
            .collect();
        let tun = match (self.tun, tun_end) {
            (Ok(a), Ok(b)) => b
                .since(a)
                .ok_or_else(|| "the counters went back".to_owned()),
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
        if let Err(e) = &tun {
            unreadable.push(format!("tun: {e}"));
        }
        Closed {
            boottime_start_ns: self.start_ns,
            boottime_end_ns: end_ns,
            elapsed_ns,
            scan_start_ns: self.scan_start_ns,
            scan_end_ns: end_ns - scan_ns,
            roles: roles(&deltas),
            cpuset_start: self.cpuset,
            cpuset_end,
            tun,
            received: payload.map(|p| p.0),
            sends: payload.map(|p| p.1),
            platform_start: self.platform,
            platform_end,
            reasons,
            unreadable,
        }
    }
}

/// Why the engine's threads at the end, `now`, are not the `opened` ones; None if they are.
fn threads_changed(mut opened: Vec<i32>, now: Result<Vec<i32>, String>) -> Option<String> {
    let mut now = match now {
        Ok(now) => now,
        Err(e) => return Some(format!("engine threads at the window end: {e}")),
    };
    opened.sort_unstable();
    now.sort_unstable();
    if opened == now {
        return None;
    }
    let list = |a: &[i32], b: &[i32]| {
        let tids: Vec<_> = (a.iter())
            .filter(|t| !b.contains(t))
            .map(i32::to_string)
            .collect();
        tids.join(", ")
    };
    let (added, removed) = (list(&now, &opened), list(&opened, &now));
    Some(format!(
        "engine threads changed in the window: added [{added}], removed [{removed}]"
    ))
}

/// One thread's change over the window.
struct Delta {
    stats: ThreadStats,
    /// utime and stime.
    ticks: Option<(u64, u64)>,
    /// Voluntary and nonvoluntary.
    switches: Option<(u64, u64)>,
}

/// Every thread of `r` with its end reading: its change, and why the window is rejected or a
/// value null. A thread that was gone or exited stays, with null values.
fn close_role(
    r: &Opened,
    ends: Vec<Option<io::Result<ThreadSample>>>,
    reasons: &mut Vec<String>,
    unreadable: &mut Vec<String>,
) -> Vec<Delta> {
    let name = role_name(r.role);
    let mut out = Vec::new();
    for (w, end) in r.threads.iter().zip(ends) {
        let tid = w.tid;
        let gone = |comm: Option<&String>, mask: Option<&Vec<usize>>| Delta {
            stats: ThreadStats {
                tid,
                comm: comm.cloned(),
                cpus: mask.map(|m| sys::format_cpu_list(m)),
                last_cpu: None,
                cpu_ns: None,
            },
            ticks: None,
            switches: None,
        };
        // Gone at the start: `open` gave the reason.
        let Some((thread, mask, start)) = &w.start else {
            out.push(gone(None, None));
            continue;
        };
        let Some(Ok(end)) = end else {
            reasons.push(format!(
                "{name} thread {tid} ({}) exited in the window",
                start.comm
            ));
            out.push(gone(Some(&start.comm), Some(mask)));
            continue;
        };
        match thread.affinity() {
            Ok(now) if now == *mask => {}
            Ok(now) => reasons.push(format!(
                "{name} thread {tid} ({}) mask changed from {} to {}",
                end.comm,
                sys::format_cpu_list(mask),
                sys::format_cpu_list(&now)
            )),
            Err(e) => reasons.push(format!("{name} thread {tid} mask: {e}")),
        }
        let cpu_ns = match (&start.runtime_ns, &end.runtime_ns) {
            (Ok(a), Ok(b)) => Some(b.saturating_sub(*a)),
            (Err(e), _) | (_, Err(e)) => {
                unreadable.push(format!("{name} thread {tid} {e}"));
                None
            }
        };
        let switches = match (&start.ctxt_switches, &end.ctxt_switches) {
            (Ok(a), Ok(b)) => Some((b.0.saturating_sub(a.0), b.1.saturating_sub(a.1))),
            (Err(e), _) | (_, Err(e)) => {
                unreadable.push(format!("{name} thread {tid} {e}"));
                None
            }
        };
        out.push(Delta {
            stats: ThreadStats {
                tid,
                comm: Some(end.comm),
                cpus: Some(sys::format_cpu_list(mask)),
                last_cpu: end.processor,
                cpu_ns,
            },
            ticks: Some((
                end.utime.saturating_sub(start.utime),
                end.stime.saturating_sub(start.stime),
            )),
            switches,
        });
    }
    out
}

fn totals<'a>(deltas: impl IntoIterator<Item = &'a Delta>) -> Totals {
    let add = |a: Option<u64>, b: Option<u64>| Some(a? + b?);
    let mut t = Totals {
        cpu_ns: Some(0),
        user_ticks: Some(0),
        system_ticks: Some(0),
        voluntary_switches: Some(0),
        nonvoluntary_switches: Some(0),
    };
    for d in deltas {
        t.cpu_ns = add(t.cpu_ns, d.stats.cpu_ns);
        t.user_ticks = add(t.user_ticks, d.ticks.map(|x| x.0));
        t.system_ticks = add(t.system_ticks, d.ticks.map(|x| x.1));
        t.voluntary_switches = add(t.voluntary_switches, d.switches.map(|s| s.0));
        t.nonvoluntary_switches = add(t.nonvoluntary_switches, d.switches.map(|s| s.1));
    }
    t
}

fn role_stats(deltas: &[Delta]) -> RoleStats {
    RoleStats {
        totals: totals(deltas),
        threads: deltas.iter().map(|d| d.stats.clone()).collect(),
    }
}

fn roles(by_role: &[(Role, Vec<Delta>)]) -> Roles {
    let get = |role| by_role.iter().find(|(r, _)| *r == role).map(|(_, d)| d);
    let engine = get(Role::Engine).map_or(&[][..], Vec::as_slice);
    let relay = get(Role::Relay);
    Roles {
        engine: role_stats(engine),
        relay: relay.map(|d| role_stats(d)),
        generator: role_stats(get(Role::Generator).map_or(&[][..], Vec::as_slice)),
        sink: role_stats(get(Role::Sink).map_or(&[][..], Vec::as_slice)),
        engine_relay: totals(engine.iter().chain(relay.into_iter().flatten())),
    }
}
