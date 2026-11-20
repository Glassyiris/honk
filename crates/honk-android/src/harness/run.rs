//! Runs a plan: for each measurement a fresh tun, sink, relay (hev) and engine, one window, and
//! one JSON line of results. Owns the measurement sequence, the workload timing and the record.
//!
//! `run` blocks its caller, the app's bench thread, until the plan ends or `stop` is set, and
//! pins that thread to the generator CPUs so its own wakeups stay off the measured cores. Every
//! wait has a deadline: the setup and the teardown fixed ones, a window the plan's; `stop` cuts
//! the warmup, the wait for the flows, a window and its drain short, and the measurement is
//! still torn down (flows joined, engine stopped) before `run` returns. Nothing here retries a
//! failed measurement: it is written as rejected. An engine that does not stop ends the run.

use super::account::{Closed, Platform, Role, RoleThreads, Roles, Tun, Window};
use super::engine::{self, Running};
use super::load::{CANCELLED, Flows, Stop, Traffic, Workload};
use super::plan::{Case, Dir, Engine, Pin, Plan, Step};
use super::relay::Relay;
use super::sink::Sink;
use crate::sys;
use serde::Serialize;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Where the generator connects: inside the VPN's 198.18.0.0/15 route. The engine ignores the
/// destination and hands every flow to the sink.
pub const TARGET: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 18, 0, 1), 5201));
/// Quiet time between the warmup and the window.
const SETTLE: Duration = Duration::from_secs(2);
/// Bound of the warmup and of the flows connecting.
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound of the flows draining at a window's end, and of their ending after it.
const TEARDOWN: Duration = Duration::from_secs(10);

/// What only the app can do. Called on the runner thread, except `start_hev`: it runs on a
/// thread pinned to the engine CPUs, so that hev's threads inherit them.
///
/// The tun fd has one owner, the host: neither engine closes it (honk's `Handle::stop` and hev's
/// shutdown leave a passed-in fd open), and the runner calls `close_tun` only after the engine
/// has stopped.
pub trait Host: Sync {
    /// Establishes the VPN with this MTU and returns the tun fd, open until `close_tun`.
    fn open_tun(&self, mtu: u16) -> Result<RawFd, String>;
    fn close_tun(&self);
    /// Starts hev-socks5-tunnel with this YAML config on `tun`; returns once its thread exists.
    /// The calling thread is named `engine::HEV_THREAD` when hev creates its threads.
    fn start_hev(&self, config: &str, tun: RawFd) -> Result<(), String>;
    /// Stops hev and waits for its thread; Err if hev may still run, on the tun as well.
    fn stop_hev(&self) -> Result<(), String>;
    /// hev's tun counters; read before `stop_hev`, which resets them.
    fn hev_tun(&self) -> Result<Tun, String>;
    /// The app's state at a window end.
    fn platform(&self) -> Result<Platform, String>;
    /// `done` of `total` measurements are written.
    fn progress(&self, done: usize, total: usize);
}

/// The sink-side CLOCK_BOOTTIME marks of a tail case; the window that follows is the tail.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TailMarks {
    pub burst_start_ns: u64,
    /// When the sink read the burst's end (EOF).
    pub burst_end_ns: u64,
}

/// What one measurement produced. It is rejected when `reasons` is not empty.
#[derive(Default)]
pub struct Measured {
    pub window: Option<Closed>,
    /// Payload the receiving side read in the window; for tail, in the burst.
    pub bytes: Option<u64>,
    /// sparse: application sends in the window.
    pub sends: Option<u64>,
    /// bulk and sparse: CLOCK_BOOTTIME when the senders stopped; the window ends once the
    /// receivers have read all they sent.
    pub cut_ns: Option<u64>,
    pub tail: Option<TailMarks>,
    pub reasons: Vec<String>,
}

impl Measured {
    fn rejected(reason: impl Into<String>) -> Measured {
        Measured {
            reasons: vec![reason.into()],
            ..Measured::default()
        }
    }
}

/// What a measurement runs against.
pub struct Setup<'a> {
    pub target: SocketAddr,
    pub host: &'a dyn Host,
    pub engine: &'a Running,
    pub sink: &'a Sink,
    pub relay: Option<&'a Relay>,
    pub pin: &'a Pin,
}

impl Setup<'_> {
    /// Opens a window over every role's threads. The engine's are listed now, so threads it
    /// created after its start count; a listing error leaves none, which rejects the window.
    fn open(&self, flows: Option<&Flows>) -> Window {
        let mut roles = vec![RoleThreads {
            role: Role::Engine,
            tids: self.engine.threads().unwrap_or_default(),
            cpus: &self.pin.engine,
        }];
        if let (Some(relay), Some(cpus)) = (self.relay, &self.pin.relay) {
            roles.push(RoleThreads {
                role: Role::Relay,
                tids: relay.server.threads(),
                cpus,
            });
        }
        roles.push(RoleThreads {
            role: Role::Generator,
            tids: flows.map_or_else(Vec::new, |f| f.threads.list()),
            cpus: &self.pin.generator,
        });
        roles.push(RoleThreads {
            role: Role::Sink,
            tids: self.sink.server.threads(),
            cpus: &self.pin.sink,
        });
        Window::open(&roles, self.host, self.engine)
    }

    fn close(&self, w: Window, load: Option<&Workload>) -> Closed {
        w.close(self.host, self.engine, load)
    }
}

/// Runs one case against `s`, a bulk case with `flows` flows.
pub fn measure(case: &Case, flows: u32, s: &Setup, stop: &Stop) -> Measured {
    let secs = Duration::from_secs;
    let mut m = match *case {
        Case::Bulk { dir, seconds, .. } => {
            let traffic = match dir {
                Dir::Up => Traffic::Up,
                Dir::Down => Traffic::Down,
            };
            with_flows(s, traffic, flows, secs(seconds), stop)
        }
        Case::Sparse {
            interval_ms,
            bytes,
            seconds,
        } => {
            let traffic = Traffic::Sparse {
                interval: Duration::from_millis(interval_ms),
                bytes: bytes as usize,
            };
            with_flows(s, traffic, 1, secs(seconds), stop)
        }
        Case::Idle { seconds } => {
            let w = s.open(None);
            let stopped = stop.wait(secs(seconds));
            let mut m = Measured {
                window: Some(s.close(w, None)),
                ..Measured::default()
            };
            if stopped {
                m.reasons.push(CANCELLED.into());
            }
            m
        }
        Case::Tail {
            burst_seconds,
            observe_seconds,
        } => tail(s, secs(burst_seconds), secs(observe_seconds), stop),
    };
    if let Some(w) = &mut m.window {
        m.reasons.append(&mut w.reasons);
        let r = &w.roles;
        if [&r.engine_relay, &r.generator.totals, &r.sink.totals]
            .iter()
            .any(|t| t.cpu_ns.is_none())
        {
            m.reasons.push("CPU time unreadable".into());
        }
    }
    m
}

/// Opens `n` flows of a new workload and waits until all are connected at both ends. A start
/// that fails closes the flows, connects in progress too, and tears them down by its deadline.
fn start_flows(
    s: &Setup,
    traffic: Traffic,
    n: u32,
    stop: &Stop,
) -> Result<(Arc<Workload>, Flows), String> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let w = Workload::new(traffic);
    s.sink.set_workload(Some(w.clone()));
    let mut flows = Flows::open(s.target, n, &w, s.pin.generator.as_slice());
    let ready = stop
        .wait_for(
            deadline,
            |until| w.wait_ready(n as usize, until),
            || format!("{n} flows not connected within {SETUP_TIMEOUT:?}"),
        )
        .and_then(|()| w.failed().map_or(Ok(()), Err));
    if let Err(e) = ready {
        flows.shutdown();
        let _ = teardown(s, &w, &mut flows, deadline);
        return Err(e);
    }
    Ok((w, flows))
}

/// Stops the workload and waits until every flow has ended at the generator, sink and relay;
/// past `deadline`, shuts their streams down and fails.
fn teardown(s: &Setup, w: &Workload, flows: &mut Flows, deadline: Instant) -> Result<(), String> {
    w.stop();
    let ended = flows.threads.wait_empty(deadline)
        && s.sink.server.wait_idle(deadline)
        && s.relay.is_none_or(|r| r.server.wait_idle(deadline));
    if !ended {
        flows.shutdown();
        s.sink.server.shutdown_conns();
        if let Some(r) = s.relay {
            r.server.shutdown_conns();
        }
    }
    flows.join();
    s.sink.set_workload(None);
    if ended {
        Ok(())
    } else {
        Err("flows did not end in time".into())
    }
}

/// bulk and sparse: the window runs from the barrier for `d`, then the senders stop, and it is
/// read once the receivers have read all they sent, every flow thread still there: its CPU
/// time, tun counters and payload cover the same transfer. It passes only with payload at the
/// receiver, tun reads and writes in it, and every flow delivering all it sent.
fn with_flows(s: &Setup, traffic: Traffic, n: u32, d: Duration, stop: &Stop) -> Measured {
    let (w, mut flows) = match start_flows(s, traffic, n, stop) {
        Ok(x) => x,
        Err(e) => return Measured::rejected(e),
    };
    let window = s.open(Some(&flows));
    w.open();
    let stopped = stop.wait(d);
    let cut_ns = sys::boottime_ns();
    w.cut();
    let drained = if stopped {
        Err(CANCELLED.into())
    } else {
        stop.wait_for(
            Instant::now() + TEARDOWN,
            |until| w.wait_drained(n as usize, until),
            || format!("flows did not drain within {TEARDOWN:?}"),
        )
    };
    let closed = s.close(window, Some(&w));
    let mut reasons = Vec::new();
    if let Err(e) = &drained {
        reasons.push(e.clone());
    } else {
        if closed.received == Some(0) {
            reasons.push("no payload reached the receiver".into());
        }
        match &closed.tun {
            Ok(t) if t.reads > 0 && t.writes > 0 => {}
            Ok(_) => reasons.push("no tun reads or writes in the window".into()),
            Err(e) => reasons.push(format!("tun counters: {e}")),
        }
    }
    if let Err(e) = teardown(s, &w, &mut flows, Instant::now() + TEARDOWN) {
        reasons.push(e);
    } else if drained.is_ok() {
        reasons.extend(undelivered(&w, n));
    }
    Measured {
        bytes: closed.received,
        sends: closed
            .sends
            .filter(|_| matches!(traffic, Traffic::Sparse { .. })),
        cut_ns: Some(cut_ns),
        window: Some(closed),
        reasons,
        ..Measured::default()
    }
}

/// Why some of the `n` flows of `w`, all ended, did not deliver all they sent.
fn undelivered(w: &Workload, n: u32) -> Option<String> {
    let k = w.broken();
    (k > 0).then(|| format!("{k} of {n} flows did not deliver all they sent"))
}

/// A burst of one up flow for `burst`, then a window over the quiet engine that ends `observe`
/// after the sink read the burst's end. A window that opens only after that, once the burst's
/// teardown is done, observes nothing and is rejected.
fn tail(s: &Setup, burst: Duration, observe: Duration, stop: &Stop) -> Measured {
    let (w, mut flows) = match start_flows(s, Traffic::Up, 1, stop) {
        Ok(x) => x,
        Err(e) => return Measured::rejected(e),
    };
    let burst_start_ns = sys::boottime_ns();
    w.open();
    let stopped = stop.wait(burst);
    let ended = teardown(s, &w, &mut flows, Instant::now() + TEARDOWN);
    if stopped {
        return Measured::rejected(CANCELLED);
    }
    if let Err(e) = ended {
        return Measured::rejected(e);
    }
    if let Some(e) = undelivered(&w, 1) {
        return Measured::rejected(e);
    }
    let marks = TailMarks {
        burst_start_ns,
        burst_end_ns: s.sink.last_end_ns(),
    };
    let window = s.open(None);
    let end_ns = marks.burst_end_ns + observe.as_nanos() as u64;
    let stopped = stop.wait(Duration::from_nanos(
        end_ns.saturating_sub(sys::boottime_ns()),
    ));
    let closed = s.close(window, None);
    let late_ns = closed.boottime_start_ns.checked_sub(end_ns);
    let mut m = Measured {
        window: Some(closed),
        bytes: Some(w.received()),
        tail: Some(marks),
        ..Measured::default()
    };
    if let Some(ns) = late_ns {
        m.reasons.push(format!(
            "the window opened {} ms after the observe period ended",
            ns / 1_000_000
        ));
    }
    if stopped {
        m.reasons.push(CANCELLED.into());
    } else if w.received() == 0 {
        m.reasons.push("no payload reached the receiver".into());
    }
    m
}

/// One step: a fresh tun, sink, relay and engine around one measurement. The second value is
/// Err when the engine did not stop: the tun then stays open with the host, and the run ends.
fn measure_step(
    plan: &Plan,
    step: &Step,
    host: &dyn Host,
    stop: &Stop,
) -> (Measured, Result<(), String>) {
    let tun = match host.open_tun(step.mtu) {
        Ok(fd) => fd,
        Err(e) => return (Measured::rejected(format!("open tun: {e}")), Ok(())),
    };
    let sink = match Sink::start(plan.pin.sink.as_slice()) {
        Ok(s) => s,
        Err(e) => {
            host.close_tun();
            return (Measured::rejected(e), Ok(()));
        }
    };
    let relay = match (step.engine, &plan.pin.relay) {
        (Engine::Hev, Some(cpus)) => Relay::start(sink.server.addr, cpus.as_slice()).map(Some),
        _ => Ok(None),
    };
    let (m, stopped) = match relay {
        Ok(relay) => {
            let r = on_engine(plan, step, tun, &sink, relay.as_ref(), host, stop);
            if let Some(r) = relay {
                r.server.stop();
            }
            r
        }
        Err(e) => (Measured::rejected(e), Ok(())),
    };
    sink.server.stop();
    if stopped.is_ok() {
        host.close_tun();
    }
    (m, stopped)
}

fn on_engine(
    plan: &Plan,
    step: &Step,
    tun: RawFd,
    sink: &Sink,
    relay: Option<&Relay>,
    host: &dyn Host,
    stop: &Stop,
) -> (Measured, Result<(), String>) {
    let pin = &plan.pin;
    let upstream = relay.map_or(sink.server.addr, |r| r.server.addr);
    let running = match engine::start(step.engine, tun, step.mtu, upstream, &pin.engine, host) {
        Ok(r) => r,
        Err(e) => return (Measured::rejected(e), Ok(())),
    };
    let setup = Setup {
        target: TARGET,
        host,
        engine: &running,
        sink,
        relay,
        pin,
    };
    let mut m = match engine::warmup(TARGET, sink, relay, stop, SETUP_TIMEOUT) {
        Ok(()) if stop.wait(SETTLE) => Measured::rejected(CANCELLED),
        Ok(()) => measure(&plan.cases[step.case], step.flows, &setup, stop),
        Err(e) => Measured::rejected(e),
    };
    let stopped = running.stop(host);
    if let Err(e) = &stopped {
        m.reasons.push(format!("stop the engine: {e}"));
    }
    (m, stopped)
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Rejected,
}

/// One line of results.jsonl.
#[derive(Serialize)]
struct Record<'a> {
    run: &'a str,
    /// 0-based position in the schedule, and its length.
    seq: usize,
    steps: usize,
    /// Index of the plan's `cases` entry.
    case_index: usize,
    rep: u32,
    engine: Engine,
    mtu: u16,
    flows: u32,
    /// The plan's case as this step runs it: a bulk case with this step's flow count.
    case: serde_json::Value,
    pin: &'a Pin,
    /// USER_HZ, the unit of the role ticks.
    clk_tck: u64,
    boottime_start_ns: Option<u64>,
    boottime_end_ns: Option<u64>,
    elapsed_ns: Option<u64>,
    /// The thread-sampling scans at the window's start and end (`Closed::scan_start_ns`).
    scan_start_ns: Option<u64>,
    scan_end_ns: Option<u64>,
    boottime_cut_ns: Option<u64>,
    bytes: Option<u64>,
    sends: Option<u64>,
    tail: Option<TailMarks>,
    roles: Option<Roles>,
    cpuset_start: Option<String>,
    cpuset_end: Option<String>,
    tun: Option<Tun>,
    platform_start: Option<Platform>,
    platform_end: Option<Platform>,
    status: Status,
    /// Why it is rejected.
    reason: Option<String>,
    /// Why a value above is null.
    unreadable: Vec<String>,
}

fn record<'a>(
    run: &'a str,
    (seq, steps): (usize, usize),
    plan: &'a Plan,
    step: &Step,
    m: Measured,
) -> serde_json::Result<Record<'a>> {
    let reason = (!m.reasons.is_empty()).then(|| m.reasons.join("; "));
    let mut case = serde_json::to_value(&plan.cases[step.case])?;
    if let Some(flows) = case.get_mut("flows") {
        *flows = step.flows.into();
    }
    let mut rec = Record {
        run,
        seq,
        steps,
        case_index: step.case,
        rep: step.rep,
        engine: step.engine,
        mtu: step.mtu,
        flows: step.flows,
        case,
        pin: &plan.pin,
        clk_tck: sys::clock_ticks(),
        boottime_start_ns: None,
        boottime_end_ns: None,
        elapsed_ns: None,
        scan_start_ns: None,
        scan_end_ns: None,
        boottime_cut_ns: m.cut_ns,
        bytes: m.bytes,
        sends: m.sends,
        tail: m.tail,
        roles: None,
        cpuset_start: None,
        cpuset_end: None,
        tun: None,
        platform_start: None,
        platform_end: None,
        status: if reason.is_none() {
            Status::Ok
        } else {
            Status::Rejected
        },
        reason,
        unreadable: Vec::new(),
    };
    if let Some(w) = m.window {
        rec.boottime_start_ns = Some(w.boottime_start_ns);
        rec.boottime_end_ns = Some(w.boottime_end_ns);
        rec.elapsed_ns = Some(w.elapsed_ns);
        rec.scan_start_ns = Some(w.scan_start_ns);
        rec.scan_end_ns = Some(w.scan_end_ns);
        rec.roles = Some(w.roles);
        rec.cpuset_start = w.cpuset_start;
        rec.cpuset_end = w.cpuset_end;
        rec.tun = w.tun.ok();
        rec.platform_start = w.platform_start;
        rec.platform_end = w.platform_end;
        rec.unreadable = w.unreadable;
    }
    Ok(rec)
}

/// Runs every step of `plan`, writing one line to `out` per measurement, rejected ones
/// included. Returns early only when stopped, when an engine does not stop, or when `out`
/// fails, with every reason that applies.
pub fn run(
    plan: &Plan,
    run_id: &str,
    host: &dyn Host,
    out: &mut dyn Write,
    stop: &Stop,
) -> Result<(), String> {
    let cpus = &plan.pin.generator;
    sys::set_affinity(cpus.as_slice()).map_err(|e| format!("pin the runner to {cpus}: {e}"))?;
    let steps = plan.schedule();
    let cooldown = Duration::from_secs(plan.cooldown_seconds);
    for (seq, step) in steps.iter().enumerate() {
        if stop.is_set() {
            return Err(CANCELLED.into());
        }
        let (m, engine_stop) = measure_step(plan, step, host, stop);
        if !m.reasons.is_empty() {
            sys::log_warn(&format!("bench step {seq}: {}", m.reasons.join("; ")));
        }
        let written = record(run_id, (seq, steps.len()), plan, step, m)
            .and_then(|rec| serde_json::to_writer(&mut *out, &rec))
            .map_err(io::Error::from)
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|e| format!("write results: {e}"));
        if written.is_ok() {
            host.progress(seq + 1, steps.len());
        }
        let engine_stop =
            engine_stop.map_err(|e| format!("the engine did not stop ({e}); its tun is left open"));
        match (engine_stop, written) {
            (Ok(()), Ok(())) => {}
            (Err(a), Err(b)) => return Err(format!("{a}; {b}")),
            (Err(e), _) | (_, Err(e)) => return Err(e),
        }
        if stop.is_set() || (seq + 1 < steps.len() && stop.wait(cooldown)) {
            return Err(CANCELLED.into());
        }
    }
    Ok(())
}
