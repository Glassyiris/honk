//! Test doubles shared by the harness tests: the stub app and hev, the stand-in engine threads,
//! the forwarding engine, and the CPUs every role is pinned to.

use honkengine::harness::account::{DISPLAY_STATE_ON, Platform, Tun};
use honkengine::harness::engine::{HEV_THREAD, Running};
use honkengine::harness::load::{Server, Stop};
use honkengine::harness::plan::{Case, Pin, Plan};
use honkengine::harness::run::{Host, Measured, Setup, measure};
use honkengine::harness::sink::Sink;
use honkengine::sys;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Four CPUs this process may use, one for each role.
pub fn cpus() -> [usize; 4] {
    let all = sys::affinity(0).unwrap();
    assert!(all.len() >= 4, "the tests need four CPUs, have {all:?}");
    [all[0], all[1], all[2], all[3]]
}

pub fn pin() -> Pin {
    let [e, g, r, s] = cpus();
    let json = format!(r#"{{"engine": "{e}", "generator": "{g}", "relay": "{r}", "sink": "{s}"}}"#);
    serde_json::from_str(&json).unwrap()
}

pub fn plan(engines: &str, cases: &str) -> Plan {
    Plan::parse(&format!(
        r#"{{ "engines": {engines}, "mtu": [8500], "cases": {cases}, "pin": {},
              "repeat": 1, "cooldown_seconds": 0, "interleave": true }}"#,
        serde_json::to_string(&pin()).unwrap()
    ))
    .unwrap()
}

/// The screen on and the bench Activity in front.
pub fn in_front() -> Platform {
    Platform {
        interactive: true,
        display_state: DISPLAY_STATE_ON,
        bench_activity_resumed: true,
        sdk_int_full: 3_600_000,
        build_id: "TEST".into(),
        other: Default::default(),
    }
}

/// A thread that runs `then` once told, keeps what it returns, and exits when told again or
/// dropped (which joins it).
pub struct StandIn {
    pub tid: i32,
    go: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl StandIn {
    /// Spawned by `b`, so it inherits the calling thread's name unless `b` names it; pinned to
    /// `cpus`, or it inherits those as well.
    pub fn spawn<T: 'static>(
        b: thread::Builder,
        cpus: Option<Vec<usize>>,
        then: impl FnOnce() -> T + Send + 'static,
    ) -> StandIn {
        let (tid_tx, tid_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        let thread = b
            .spawn(move || {
                if let Some(cpus) = cpus {
                    sys::set_affinity(&cpus).unwrap();
                }
                tid_tx.send(sys::gettid()).unwrap();
                let _ = go_rx.recv();
                let kept = then();
                let _ = go_rx.recv();
                drop(kept);
            })
            .unwrap();
        StandIn {
            tid: tid_rx.recv().unwrap(),
            go: Some(go_tx),
            thread: Some(thread),
        }
    }

    /// One of the engine's threads, named and pinned as hev's are.
    pub fn engine<T: 'static>(then: impl FnOnce() -> T + Send + 'static) -> StandIn {
        StandIn::engine_on(&pin(), then)
    }

    pub fn engine_on<T: 'static>(pin: &Pin, then: impl FnOnce() -> T + Send + 'static) -> StandIn {
        let b = thread::Builder::new().name(HEV_THREAD.into());
        StandIn::spawn(b, Some(pin.engine.as_slice().to_vec()), then)
    }

    pub fn go(&self) {
        let _ = self.go.as_ref().unwrap().send(());
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.go.take();
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

/// What the stub's `hev_tun` returns.
#[derive(Clone, Copy, Default)]
pub enum Counters {
    /// One more packet each way at every read.
    #[default]
    Rising,
    Flat,
    Unreadable,
}

/// The app and hev stand-in. hev's start makes two threads that inherit the starter's name and
/// CPUs; the first creates a third once told (as hev's task aide starts on first use).
#[derive(Default)]
pub struct StubHost {
    /// What `open_tun` hands out; none: no VpnService here.
    pub tun: Option<RawFd>,
    pub tun_opened: AtomicBool,
    pub tun_closed: AtomicBool,
    pub hev: Mutex<Vec<StandIn>>,
    /// `stop_hev` fails and leaves hev's threads running.
    pub hev_stop_fails: bool,
    /// Runs inside `start_hev`.
    pub during_hev_start: Option<Box<dyn Fn() + Sync>>,
    pub counters: Counters,
    /// How long reading the tun counters takes.
    pub tun_delay: Duration,
    pub reads: AtomicU64,
    /// `platform()` from the number of earlier calls; `in_front` without it.
    pub platform: Option<Box<dyn Fn(usize) -> Platform + Sync>>,
    pub platform_calls: AtomicUsize,
    pub progress: Mutex<Vec<(usize, usize)>>,
    /// Set once three steps are written.
    pub stop: Stop,
}

impl StubHost {
    /// Stops hev's threads and waits for them.
    pub fn end_hev(&self) {
        self.hev.lock().unwrap().clear();
    }
}

impl Host for StubHost {
    fn open_tun(&self, _mtu: u16) -> Result<RawFd, String> {
        self.tun_opened.store(true, Relaxed);
        self.tun.ok_or_else(|| "no VpnService here".into())
    }
    fn close_tun(&self) {
        self.tun_closed.store(true, Relaxed);
    }
    fn start_hev(&self, config: &str, _tun: RawFd) -> Result<(), String> {
        assert!(config.contains("socks5:"));
        let aide = || StandIn::spawn(thread::Builder::new(), None, || ());
        let mut hev = self.hev.lock().unwrap();
        hev.push(StandIn::spawn(thread::Builder::new(), None, aide));
        hev.push(StandIn::spawn(thread::Builder::new(), None, || ()));
        if let Some(f) = &self.during_hev_start {
            f();
        }
        Ok(())
    }
    fn stop_hev(&self) -> Result<(), String> {
        if self.hev_stop_fails {
            return Err("stub: hev still runs".into());
        }
        self.end_hev();
        Ok(())
    }
    fn hev_tun(&self) -> Result<Tun, String> {
        thread::sleep(self.tun_delay);
        let n = self.reads.fetch_add(1, Relaxed);
        match self.counters {
            Counters::Rising => Ok(Tun {
                reads: n,
                read_bytes: n * 100,
                writes: n,
                write_bytes: n * 100,
            }),
            Counters::Flat => Ok(Tun::default()),
            Counters::Unreadable => Err("hevStats failed".into()),
        }
    }
    fn platform(&self) -> Result<Platform, String> {
        let calls = self.platform_calls.fetch_add(1, Relaxed);
        Ok(self.platform.as_ref().map_or_else(in_front, |f| f(calls)))
    }
    fn progress(&self, done: usize, total: usize) {
        self.progress.lock().unwrap().push((done, total));
        if done == 3 {
            self.stop.set();
        }
    }
}

/// Runs `case` (bulk: with `flows` flows) from the generator straight into a fresh sink, with
/// `host` as the app and the threads named `HEV_THREAD` as the engine.
pub fn measure_direct(case: Case, flows: u32, host: &StubHost, stop: &Stop) -> (Measured, Sink) {
    measure_pinned(&pin(), case, flows, host, stop)
}

/// `measure_direct` with the roles on `pin`.
pub fn measure_pinned(
    pin: &Pin,
    case: Case,
    flows: u32,
    host: &StubHost,
    stop: &Stop,
) -> (Measured, Sink) {
    let sink = Sink::start(pin.sink.as_slice()).unwrap();
    let setup = Setup {
        target: sink.server.addr,
        host,
        engine: &Running::Hev,
        sink: &sink,
        relay: None,
        pin,
    };
    (measure(&case, flows, &setup, stop), sink)
}

/// `m`'s reasons, but the cpuset's on a host whose kernel has no cpusets.
pub fn reasons(m: &Measured) -> Vec<&str> {
    let no_cpuset = sys::cpuset().is_err();
    (m.reasons.iter())
        .map(String::as_str)
        .filter(|r| !(no_cpuset && r.starts_with("cpuset unreadable")))
        .collect()
}

/// The engine's threads once at most `n` are listed, or after a few seconds: an engine start's
/// starter outlives its join briefly (the runner lists them after the warmup).
pub fn settled(running: &Running, n: usize) -> Vec<i32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let tids = running.threads().unwrap();
        if tids.len() <= n || Instant::now() > deadline {
            return tids;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Spends `ns` of the calling thread's CPU time.
pub fn burn(ns: u64) {
    let cpu_ns = || {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: t is valid for writes.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    let end = cpu_ns() + ns;
    while cpu_ns() < end {}
}

/// What goes wrong on a `forwarder`'s path.
#[derive(Clone, Copy, PartialEq)]
pub enum Fault {
    None,
    /// It resets the sink's end of the first connection after 1 MiB, swallows the rest, and
    /// holds the client until another connection has ended.
    ResetFirst,
    /// It forwards every answer this late.
    SlowAnswer(Duration),
}

/// An engine on the data path of up flows: forwards every connection to `to` on one thread,
/// named and pinned as hev's, spending `ns_per_byte` of CPU on each byte it forwards up, then
/// forwards the answer down.
pub fn forwarder(to: SocketAddr, ns_per_byte: u64, fault: Fault) -> Server {
    let first = AtomicBool::new(fault == Fault::ResetFirst);
    let ended = (Mutex::new(0), Condvar::new());
    let shared = Arc::new((first, ended));
    Server::start(HEV_THREAD, pin().engine.as_slice(), move |client, _| {
        let (first, (ended, cv)) = &*shared;
        let Ok(up) = TcpStream::connect(to) else {
            return;
        };
        let reset = first.swap(false, Relaxed);
        let (mut up, mut sent) = (Some(up), 0);
        let mut buf = vec![0u8; 64 << 10];
        while let Ok(k @ 1..) = (&client).read(&mut buf) {
            burn(k as u64 * ns_per_byte);
            let Some(u) = &up else { continue };
            if (&*u).write_all(&buf[..k]).is_err() {
                break;
            }
            sent += k;
            if reset && sent >= 1 << 20 {
                reset_close(up.take().unwrap());
            }
        }
        match up {
            Some(up) => {
                let _ = up.shutdown(Shutdown::Write);
                if let Fault::SlowAnswer(d) = fault {
                    thread::sleep(d);
                }
                let _ = std::io::copy(&mut &up, &mut &client);
                let _ = client.shutdown(Shutdown::Write);
                *ended.lock().unwrap() += 1;
                cv.notify_all();
            }
            None => drop(cv.wait_while(ended.lock().unwrap(), |n| *n == 0).unwrap()),
        }
    })
    .unwrap()
}

/// Closes `s` with a reset (SO_LINGER 0).
pub fn reset_close(s: TcpStream) {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let len = size_of_val(&l) as libc::socklen_t;
    // SAFETY: plain setsockopt on an open socket, reading `len` bytes of `l`.
    let r = unsafe {
        let opt = (&raw const l).cast();
        libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, opt, len)
    };
    assert_eq!(r, 0);
}

/// A results file on a full disk.
pub struct Full;

impl Write for Full {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
