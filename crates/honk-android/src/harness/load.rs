//! Traffic: the generator flows, the workload they share with the sink (`super::sink`), and the
//! loopback server that the sink and the relay run on. Owns every socket and thread of those
//! roles; plain blocking sockets, one thread per connection, each registered under its role so
//! the accounting can find it.
//!
//! Must not wake on its own: no timeouts or polling inside a flow, since idle and sparse
//! measure wakeups. Blocking calls are bounded from outside instead: the runner (one thread)
//! opens a `Workload`'s barrier, cuts and stops it, and shuts streams down, a connect in progress
//! too, after its own deadline; every path that opens flows must end with `Workload::stop`, or
//! their threads wait at the barrier or, after the cut, at the end of what they received.

use crate::sys;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Size of every bulk write and of every read buffer.
pub const WRITE_SIZE: usize = 64 * 1024;
/// What a warmup connection carries to the sink.
pub const WARMUP: &[u8] = b"warmup";

pub(super) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Waits on `cv` until `done` holds or `deadline` passes; false at the deadline.
fn wait_until<T>(m: &Mutex<T>, cv: &Condvar, deadline: Instant, done: impl Fn(&T) -> bool) -> bool {
    let mut g = lock(m);
    while !done(&g) {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        g = cv
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    true
}

/// The reason a measurement ends with when `Stop` is set.
pub const CANCELLED: &str = "cancelled";
/// How often a setup wait that cannot wake on `Stop` checks it.
const TICK: Duration = Duration::from_millis(100);

/// A flag that sleepers can wait on, so stopping never waits out a sleep.
#[derive(Default)]
pub struct Stop {
    set: Mutex<bool>,
    cv: Condvar,
}

impl Stop {
    pub const fn new() -> Stop {
        Stop {
            set: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    pub fn set(&self) {
        *lock(&self.set) = true;
        self.cv.notify_all();
    }

    pub fn reset(&self) {
        *lock(&self.set) = false;
    }

    pub fn is_set(&self) -> bool {
        *lock(&self.set)
    }

    /// Sleeps until `deadline` or until set; true if set.
    pub fn wait_until(&self, deadline: Instant) -> bool {
        wait_until(&self.set, &self.cv, deadline, |&set| set)
    }

    pub fn wait(&self, d: Duration) -> bool {
        self.wait_until(Instant::now() + d)
    }

    /// Repeats `wait`, which waits at most until the instant it is given, in short slices until
    /// it returns true (Ok), `deadline` passes (Err `timeout`) or this is set (Err `CANCELLED`).
    pub fn wait_for(
        &self,
        deadline: Instant,
        mut wait: impl FnMut(Instant) -> bool,
        timeout: impl FnOnce() -> String,
    ) -> Result<(), String> {
        loop {
            if wait(deadline.min(Instant::now() + TICK)) {
                return Ok(());
            }
            if self.is_set() {
                return Err(CANCELLED.into());
            }
            if Instant::now() >= deadline {
                return Err(timeout());
            }
        }
    }
}

/// Live thread IDs of one role, each registered by the thread itself.
#[derive(Default)]
pub struct Threads {
    tids: Mutex<Vec<i32>>,
    cv: Condvar,
}

impl Threads {
    pub fn list(&self) -> Vec<i32> {
        lock(&self.tids).clone()
    }

    /// Registers the calling thread until the guard drops.
    pub fn enter(&self) -> ThreadGuard<'_> {
        let tid = sys::gettid();
        lock(&self.tids).push(tid);
        ThreadGuard(self, tid)
    }

    /// Waits until no thread is registered; false at the deadline.
    pub fn wait_empty(&self, deadline: Instant) -> bool {
        wait_until(&self.tids, &self.cv, deadline, Vec::is_empty)
    }
}

pub struct ThreadGuard<'a>(&'a Threads, i32);

impl Drop for ThreadGuard<'_> {
    fn drop(&mut self) {
        lock(&self.0.tids).retain(|&t| t != self.1);
        self.0.cv.notify_all();
    }
}

/// The open streams of one role, so stopping can shut them down and unblock their threads. A
/// stream is listed only while its `Tracked` guard lives, so the list never delays a close.
/// Closing shuts every stream down and refuses new ones under the same lock, so a thread that
/// comes to track a stream after the close gets an error instead of blocking on it.
#[derive(Default)]
pub struct Streams(Mutex<StreamList>);

#[derive(Default)]
struct StreamList {
    last_id: u64,
    open: Vec<(u64, TcpStream)>,
    closed: bool,
}

impl Streams {
    pub fn track(&self, s: &TcpStream) -> io::Result<Tracked<'_>> {
        let clone = s.try_clone()?;
        let mut g = lock(&self.0);
        if g.closed {
            return Err(io::Error::other("closed"));
        }
        g.last_id += 1;
        let id = g.last_id;
        g.open.push((id, clone));
        Ok(Tracked(self, id))
    }

    pub fn shutdown_all(&self) {
        for (_, s) in &lock(&self.0).open {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    /// Shuts every stream down and refuses new ones.
    pub fn close(&self) {
        let mut g = lock(&self.0);
        g.closed = true;
        for (_, s) in &g.open {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    pub fn is_closed(&self) -> bool {
        lock(&self.0).closed
    }
}

pub struct Tracked<'a>(&'a Streams, u64);

impl Drop for Tracked<'_> {
    fn drop(&mut self) {
        lock(&(self.0).0).open.retain(|(id, _)| *id != self.1);
    }
}

/// Starts a named thread pinned to `cpus` and waits until it has pinned itself; threads it
/// creates inherit the mask.
pub fn spawn_pinned<F>(name: &str, cpus: &[usize], f: F) -> Result<JoinHandle<()>, String>
where
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let list = cpus.to_vec();
    let handle = thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let pinned = sys::set_affinity(&list);
            let ok = pinned.is_ok();
            let _ = tx.send(pinned);
            if ok {
                f();
            }
        })
        .map_err(|e| format!("spawn {name}: {e}"))?;
    let pinned = rx.recv().map_err(|_| format!("{name} exited"));
    match pinned {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(e)) => {
            let _ = handle.join();
            Err(format!("pin {name} to {}: {e}", sys::format_cpu_list(cpus)))
        }
        Err(e) => Err(e),
    }
}

// ---- server ----

/// What a connection handler shares with its server: the role's connection threads and open
/// streams.
#[derive(Default)]
pub struct Conns {
    pub threads: Threads,
    pub streams: Streams,
}

/// A loopback TCP server: a pinned acceptor thread and one thread per connection, which
/// inherits the acceptor's CPUs.
pub struct Server {
    pub addr: SocketAddr,
    acceptor_tid: i32,
    conns: Arc<Conns>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    acceptor: JoinHandle<()>,
}

impl Server {
    pub fn start<F>(name: &str, cpus: &[usize], handle: F) -> Result<Server, String>
    where
        F: Fn(TcpStream, &Conns) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("{name} bind: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("{name}: {e}"))?;
        let conns = Arc::new(Conns::default());
        let handlers = Arc::new(Mutex::new(Vec::new()));
        let (tid_tx, tid_rx) = mpsc::channel();
        let (thread_name, handle) = (name.to_owned(), Arc::new(handle));
        let (c, h) = (conns.clone(), handlers.clone());
        let acceptor = spawn_pinned(name, cpus, move || {
            let _ = tid_tx.send(sys::gettid());
            for stream in listener.incoming() {
                if c.streams.is_closed() {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let _ = stream.set_nodelay(true);
                let (c, handle) = (c.clone(), handle.clone());
                let spawned = thread::Builder::new()
                    .name(thread_name.clone())
                    .spawn(move || {
                        let _guard = c.threads.enter();
                        if let Ok(_tracked) = c.streams.track(&stream) {
                            handle(stream, &c);
                        }
                    });
                if let Ok(t) = spawned {
                    lock(&h).push(t);
                }
            }
        })?;
        let acceptor_tid = tid_rx.recv().map_err(|_| format!("{name} exited"))?;
        Ok(Server {
            addr,
            acceptor_tid,
            conns,
            handlers,
            acceptor,
        })
    }

    /// The acceptor and every live connection thread.
    pub fn threads(&self) -> Vec<i32> {
        let mut tids = vec![self.acceptor_tid];
        tids.extend(self.conns.threads.list());
        tids
    }

    /// Waits until no connection thread is left; false at the deadline.
    pub fn wait_idle(&self, deadline: Instant) -> bool {
        self.conns.threads.wait_empty(deadline)
    }

    pub fn shutdown_conns(&self) {
        self.conns.streams.shutdown_all();
    }

    /// Shuts every connection down and waits for all threads: each handler either has its
    /// streams shut down here or finds the server closed when it tracks them.
    pub fn stop(self) {
        self.conns.streams.close();
        // Wakes the acceptor out of accept().
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        let _ = self.acceptor.join();
        let handlers: Vec<_> = lock(&self.handlers).drain(..).collect();
        for h in handlers {
            let _ = h.join();
        }
    }
}

// ---- workload ----

/// What the flows of one measurement do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Traffic {
    /// The generator writes, the sink reads.
    Up,
    /// The sink writes, the generator reads.
    Down,
    /// The generator writes `bytes` every `interval`, the sink reads.
    Sparse { interval: Duration, bytes: usize },
}

#[derive(Default)]
struct Gate {
    /// Flows connected on the generator side, and accepted on the sink side.
    connected: usize,
    accepted: usize,
    /// Why a flow could not connect.
    failed: Option<String>,
    open: bool,
    /// Receiving ends that have read to the end or failed.
    drained: usize,
    /// Set by `stop`: the flows end.
    ended: bool,
    /// Flows whose sender failed or got back less than it sent.
    broken: usize,
}

/// One measurement's flows, shared by their generator and sink threads: the start barrier, the
/// cut, the end and the counters.
pub struct Workload {
    pub traffic: Traffic,
    gate: Mutex<Gate>,
    gate_cv: Condvar,
    /// Senders stop once it is set, at the cut or the end.
    stop: Stop,
    /// Payload the receiving side read.
    received: AtomicU64,
    /// sparse: the application sends.
    sends: AtomicU64,
}

#[derive(Clone, Copy)]
pub(super) enum Side {
    Generator,
    Sink,
}

impl Workload {
    pub fn new(traffic: Traffic) -> Arc<Workload> {
        Arc::new(Workload {
            traffic,
            gate: Mutex::default(),
            gate_cv: Condvar::new(),
            stop: Stop::new(),
            received: AtomicU64::new(0),
            sends: AtomicU64::new(0),
        })
    }

    pub fn received(&self) -> u64 {
        self.received.load(Relaxed)
    }

    pub fn sends(&self) -> u64 {
        self.sends.load(Relaxed)
    }

    /// Waits until `n` flows are connected at both ends or one could not connect; false at the
    /// deadline.
    pub fn wait_ready(&self, n: usize, deadline: Instant) -> bool {
        wait_until(&self.gate, &self.gate_cv, deadline, |g| {
            g.failed.is_some() || (g.connected >= n && g.accepted >= n)
        })
    }

    /// Why a flow could not connect.
    pub fn failed(&self) -> Option<String> {
        lock(&self.gate).failed.clone()
    }

    fn fail(&self, e: String) {
        lock(&self.gate).failed = Some(e);
        self.gate_cv.notify_all();
    }

    /// Lets every flow start.
    pub fn open(&self) {
        lock(&self.gate).open = true;
        self.gate_cv.notify_all();
    }

    /// Ends the transfer: senders stop and half-close, receivers read to the end and then wait
    /// for `stop`, so every thread of the flows is still there when the window is read.
    pub fn cut(&self) {
        self.stop.set();
    }

    /// Waits until `n` receivers have read to the end or failed; false at the deadline.
    pub fn wait_drained(&self, n: usize, deadline: Instant) -> bool {
        wait_until(&self.gate, &self.gate_cv, deadline, |g| g.drained >= n)
    }

    /// Ends the flows: senders stop and half-close, receivers read to EOF, answer with what they
    /// read and close. Once every flow has ended, `broken` counts those that did not deliver.
    pub fn stop(&self) {
        self.stop.set();
        {
            let mut g = lock(&self.gate);
            g.open = true;
            g.ended = true;
        }
        self.gate_cv.notify_all();
    }

    /// Flows whose sender failed to write or got back less than it wrote: a read or write error
    /// at either end (a reset too), or an early EOF.
    pub fn broken(&self) -> usize {
        lock(&self.gate).broken
    }

    /// Counts one end as connected and waits at the barrier; false if stopped first.
    fn arrive(&self, side: Side) -> bool {
        {
            let mut g = lock(&self.gate);
            match side {
                Side::Generator => g.connected += 1,
                Side::Sink => g.accepted += 1,
            }
        }
        self.gate_cv.notify_all();
        // Unbounded: every path of the runner ends with stop(), which opens the gate.
        let mut g = lock(&self.gate);
        while !g.open {
            g = self.gate_cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        !g.ended
    }

    /// Runs one end of a flow after the barrier.
    pub(super) fn run(&self, mut s: TcpStream, side: Side) {
        if !self.arrive(side) {
            return;
        }
        let receives = match side {
            Side::Generator => self.traffic == Traffic::Down,
            Side::Sink => self.traffic != Traffic::Down,
        };
        if receives {
            self.receive(&mut s);
        } else {
            let sent = self.send(&mut s);
            // The receiver answers at `stop` with what it read, unless it failed.
            let mut got = [0u8; 8];
            let answer = s.read_exact(&mut got).map(|()| u64::from_le_bytes(got));
            if sent.is_none() || answer.ok() != sent {
                lock(&self.gate).broken += 1;
            }
        }
    }

    /// Writes until stopped (`WRITE_SIZE` chunks, or `bytes` every `interval`), then half-closes;
    /// what it wrote, None after a write error.
    fn send(&self, s: &mut TcpStream) -> Option<u64> {
        let buf = vec![0x5a; WRITE_SIZE];
        let sparse = match self.traffic {
            Traffic::Sparse { interval, bytes } => Some((interval, bytes)),
            Traffic::Up | Traffic::Down => None,
        };
        let mut next = Instant::now();
        let mut sent = Some(0);
        while !self.stop.is_set() {
            match sparse {
                Some((interval, bytes)) => {
                    if s.write_all(&buf[..bytes]).is_err() {
                        sent = None;
                        break;
                    }
                    sent = sent.map(|n| n + bytes as u64);
                    self.sends.fetch_add(1, Relaxed);
                    next += interval;
                    if self.stop.wait_until(next) {
                        break;
                    }
                }
                None => match s.write(&buf) {
                    Ok(n @ 1..) => sent = sent.map(|t| t + n as u64),
                    _ => {
                        sent = None;
                        break;
                    }
                },
            }
        }
        let _ = s.shutdown(Shutdown::Write);
        sent
    }

    /// Reads to the end, waits for `stop`, then answers with what it read unless a read failed.
    fn receive(&self, s: &mut TcpStream) {
        let mut buf = vec![0u8; WRITE_SIZE];
        let mut read = 0u64;
        let ended = loop {
            match s.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    read += n as u64;
                    self.received.fetch_add(n as u64, Relaxed);
                }
                Err(e) => break Err(e),
            }
        };
        {
            let mut g = lock(&self.gate);
            g.drained += 1;
            self.gate_cv.notify_all();
            // Unbounded, as the barrier.
            while !g.ended {
                g = self.gate_cv.wait(g).unwrap_or_else(|e| e.into_inner());
            }
        }
        if ended.is_ok() {
            let _ = s.write_all(&read.to_le_bytes());
        }
    }
}

// ---- generator ----

/// The generator side of one workload's flows, each on its own pinned thread.
pub struct Flows {
    pub threads: Arc<Threads>,
    streams: Arc<Streams>,
    handles: Vec<JoinHandle<()>>,
}

impl Flows {
    /// Starts `n` flows to `target`; each connects and waits at the workload's barrier. One that
    /// cannot start or connect fails the workload (`Workload::failed`).
    pub fn open(target: SocketAddr, n: u32, w: &Arc<Workload>, cpus: &[usize]) -> Flows {
        let mut flows = Flows {
            threads: Arc::default(),
            streams: Arc::default(),
            handles: Vec::new(),
        };
        for _ in 0..n {
            let flow = w.clone();
            let (threads, streams) = (flows.threads.clone(), flows.streams.clone());
            let started = spawn_pinned("tb-gen", cpus, move || {
                let _guard = threads.enter();
                match connect(target, &streams) {
                    Ok((s, _tracked)) => flow.run(s, Side::Generator),
                    Err(e) => flow.fail(format!("connect {target}: {e}")),
                }
            });
            match started {
                Ok(h) => flows.handles.push(h),
                Err(e) => {
                    w.fail(e);
                    break;
                }
            }
        }
        flows
    }

    /// Shuts every stream down, one still connecting too, and refuses new ones.
    pub fn shutdown(&self) {
        self.streams.close();
    }

    pub fn join(&mut self) {
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

/// Connects to `target` with the stream tracked from the start, so a shutdown ends the connect.
fn connect(target: SocketAddr, streams: &Streams) -> io::Result<(TcpStream, Tracked<'_>)> {
    let s = TcpStream::from(sys::tcp_connect(target)?);
    let tracked = streams.track(&s)?;
    sys::wait_connected(s.as_raw_fd())?;
    s.set_nonblocking(false)?;
    Ok((s, tracked))
}
