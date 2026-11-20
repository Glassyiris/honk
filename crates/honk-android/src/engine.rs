//! The worker: one thread, one epoll loop. IP packets from the tun fd go into a transparent
//! honk-netstack `Stack`; every TCP flow it accepts is relayed to one fixed upstream over a
//! nonblocking socket, both ways, with backpressure; the stack's output goes back to the tun.
//! UDP and everything else is ignored. The same job as hev-socks5-tunnel plus a SOCKS
//! redirector, minus SOCKS.

use crate::sys::{self, EPOLLERR, EPOLLET, EPOLLHUP, EPOLLIN, EPOLLOUT, EPOLLRDHUP, Epoll};
use honk_netstack::{AcceptOpts, Config, ExcludeSet, FlowId, Mode, Ready, Stack, StreamError};
use std::collections::HashMap;
use std::io::{self, ErrorKind, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Counters and state the JNI side reads while the worker runs.
pub struct Shared {
    /// Packets and bytes read from the tun (sent by apps), as hev counts tx.
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    /// Packets and bytes written to the tun, as hev counts rx.
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub running: AtomicBool,
    pub tid: AtomicI32,
    /// The worker's effective CPU list after pinning.
    pub affinity: Mutex<String>,
}

pub static SHARED: Shared = Shared {
    tx_packets: AtomicU64::new(0),
    tx_bytes: AtomicU64::new(0),
    rx_packets: AtomicU64::new(0),
    rx_bytes: AtomicU64::new(0),
    running: AtomicBool::new(false),
    tid: AtomicI32::new(0),
    affinity: Mutex::new(String::new()),
};

/// Per-flow relay buffer size, each direction.
const RELAY_BUF: usize = 64 * 1024;
/// Stack send and receive buffer ceilings.
const TCP_BUF: usize = 16 * 1024 * 1024;
/// Most tun reads per loop round before the stack's output gets a turn.
const TUN_BATCH: usize = 1024;
/// Deadlines closer than this use the timerfd; epoll_wait's millisecond timeout is too coarse
/// for pacing and delayed-ACK timers.
const FINE_TIMER: Duration = Duration::from_millis(10);

const TOKEN_TUN: u64 = 0;
const TOKEN_STOP: u64 = 1;
const TOKEN_TIMER: u64 = 2;
const TOKEN_CONN: u64 = 3;

pub struct Params {
    tun: RawFd,
    mtu: u16,
    target: SocketAddr,
    cpus: Vec<usize>,
    cpu_list: String,
}

impl Params {
    pub fn parse(tun: i32, mtu: i32, host: &str, port: i32, cpus: &str) -> io::Result<Params> {
        let invalid = |m: String| io::Error::new(ErrorKind::InvalidInput, m);
        let mtu = u16::try_from(mtu).map_err(|_| invalid(format!("bad MTU {mtu}")))?;
        let port = u16::try_from(port).map_err(|_| invalid(format!("bad port {port}")))?;
        let target = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| invalid(format!("{host} has no address")))?;
        Ok(Params {
            tun,
            mtu,
            target,
            cpus: sys::parse_cpu_list(cpus)?,
            cpu_list: cpus.trim().to_owned(),
        })
    }
}

pub struct Handle {
    stop: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl Handle {
    /// Signals the worker and waits for it; the tun fd is left open for its owner.
    pub fn stop(mut self) {
        sys::eventfd_signal(self.stop.as_raw_fd());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Starts the worker and waits until it is pinned and set up.
pub fn start(p: Params) -> io::Result<Handle> {
    for c in [
        &SHARED.tx_packets,
        &SHARED.tx_bytes,
        &SHARED.rx_packets,
        &SHARED.rx_bytes,
    ] {
        c.store(0, Relaxed);
    }
    SHARED.tid.store(0, Relaxed);
    let stop = sys::eventfd()?;
    sys::set_nonblocking(p.tun)?;
    let stop_fd = stop.as_raw_fd();
    let (ready_tx, ready_rx) = mpsc::channel::<io::Result<()>>();
    SHARED.running.store(true, Relaxed);
    let thread = thread::Builder::new()
        .name("honk-engine".into())
        .spawn(move || {
            let result = Worker::new(&p, stop_fd);
            let mut worker = match result {
                Ok(w) => {
                    let _ = ready_tx.send(Ok(()));
                    w
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    SHARED.running.store(false, Relaxed);
                    return;
                }
            };
            if let Err(e) = worker.run() {
                sys::log_error(&format!("worker stopped: {e}"));
            }
            worker.publish();
            SHARED.running.store(false, Relaxed);
        });
    let thread = match thread {
        Ok(t) => t,
        Err(e) => {
            SHARED.running.store(false, Relaxed);
            return Err(e);
        }
    };
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(Handle {
            stop,
            thread: Some(thread),
        }),
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => {
            let _ = thread.join();
            Err(io::Error::other("worker died during setup"))
        }
    }
}

struct Buf {
    data: Box<[u8]>,
    off: usize,
    len: usize,
}

impl Buf {
    fn new() -> Buf {
        Buf {
            data: vec![0; RELAY_BUF].into_boxed_slice(),
            off: 0,
            len: 0,
        }
    }

    fn pending(&self) -> &[u8] {
        &self.data[self.off..self.off + self.len]
    }

    fn consume(&mut self, n: usize) {
        self.off += n;
        self.len -= n;
    }
}

/// One accepted flow and its upstream socket.
struct Conn {
    id: FlowId,
    fd: OwnedFd,
    generation: u32,
    connecting: bool,
    /// Client to upstream: read from the stack, written to the socket.
    up: Buf,
    up_eof: bool,
    up_shut: bool,
    /// Upstream to client: read from the socket, written to the stack.
    down: Buf,
    down_eof: bool,
    down_shut: bool,
}

enum Fate {
    Keep,
    /// Both directions finished cleanly.
    Done,
    /// The upstream socket failed: reset the client side.
    SocketError(io::Error),
    /// The stack side failed: reset the upstream side.
    StackError(StreamError),
}

/// Moves whatever can move in both directions without blocking.
fn pump(stack: &mut Stack, c: &mut Conn) -> Fate {
    let fd = c.fd.as_raw_fd();
    // Stack to socket.
    loop {
        if c.up.len > 0 {
            if c.connecting {
                break;
            }
            match sys::send(fd, c.up.pending()) {
                Ok(n) => c.up.consume(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Fate::SocketError(e),
            }
            continue;
        }
        if c.up_eof {
            if !c.up_shut && !c.connecting {
                sys::shutdown_write(fd);
                c.up_shut = true;
            }
            break;
        }
        match stack.tcp_read(c.id, &mut c.up.data) {
            Ok(0) => c.up_eof = true,
            Ok(n) => {
                c.up.off = 0;
                c.up.len = n;
            }
            Err(StreamError::WouldBlock) => break,
            Err(e) => return Fate::StackError(e),
        }
    }
    // Socket to stack.
    loop {
        if c.down.len > 0 {
            match stack.tcp_write(c.id, c.down.pending()) {
                Ok(n) => c.down.consume(n),
                Err(StreamError::WouldBlock) => break,
                Err(e) => return Fate::StackError(e),
            }
            continue;
        }
        if c.down_eof {
            if !c.down_shut {
                if let Err(e) = stack.tcp_shutdown(c.id) {
                    return Fate::StackError(e);
                }
                c.down_shut = true;
            }
            break;
        }
        if c.connecting {
            break;
        }
        match sys::read(fd, &mut c.down.data) {
            Ok(0) => c.down_eof = true,
            Ok(n) => {
                c.down.off = 0;
                c.down.len = n;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Fate::SocketError(e),
        }
    }
    if c.up_shut && c.down_shut {
        Fate::Done
    } else {
        Fate::Keep
    }
}

#[derive(Default)]
struct Counters {
    tx_packets: u64,
    tx_bytes: u64,
    rx_packets: u64,
    rx_bytes: u64,
    tun_write_drops: u64,
}

struct Worker {
    stack: Stack,
    ep: Epoll,
    tun: RawFd,
    stop: RawFd,
    timer: OwnedFd,
    /// The deadline the timerfd is armed for.
    armed: Option<Instant>,
    target: SocketAddr,
    conns: Vec<Option<Conn>>,
    free: Vec<usize>,
    next_generation: u32,
    flows: HashMap<FlowId, usize>,
    rx: Vec<u8>,
    tx: Vec<u8>,
    /// A packet poll_transmit produced that the tun has not taken yet.
    pending: Option<usize>,
    /// Waiting for the tun to become writable.
    tun_blocked: bool,
    n: Counters,
}

impl Worker {
    fn new(p: &Params, stop: RawFd) -> io::Result<Worker> {
        SHARED.tid.store(sys::gettid(), Relaxed);
        if !p.cpus.is_empty() {
            sys::set_affinity(&p.cpus).map_err(|e| {
                io::Error::new(e.kind(), format!("sched_setaffinity({}): {e}", p.cpu_list))
            })?;
        }
        let affinity = sys::affinity_list().unwrap_or_else(|e| format!("? ({e})"));
        *SHARED.affinity.lock().unwrap_or_else(|e| e.into_inner()) = affinity.clone();

        let ep = Epoll::new()?;
        let timer = sys::timerfd()?;
        ep.add(p.tun, EPOLLIN, TOKEN_TUN)?;
        ep.add(stop, EPOLLIN, TOKEN_STOP)?;
        ep.add(timer.as_raw_fd(), EPOLLIN, TOKEN_TIMER)?;

        let mut secret = [0u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
        let mut cfg = Config::new(secret);
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        cfg.mtu = p.mtu;
        cfg.tcp_snd_buf_max = TCP_BUF;
        cfg.tcp_rcv_buf_max = TCP_BUF;
        cfg.memory_limit = 512 * 1024 * 1024;
        let stack = Stack::new(cfg, Instant::now());

        sys::log_info(&format!(
            "worker tid {} on cpus {affinity} (asked {:?}), mtu {}, upstream {}",
            sys::gettid(),
            p.cpu_list,
            p.mtu,
            p.target
        ));
        let mtu = usize::from(p.mtu).max(1280);
        Ok(Worker {
            stack,
            ep,
            tun: p.tun,
            stop,
            timer,
            armed: None,
            target: p.target,
            conns: Vec::new(),
            free: Vec::new(),
            next_generation: 0,
            flows: HashMap::new(),
            rx: vec![0; 65536],
            tx: vec![0; mtu + 64],
            pending: None,
            tun_blocked: false,
            n: Counters::default(),
        })
    }

    fn run(&mut self) -> io::Result<()> {
        let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 256];
        let mut timeout = -1;
        loop {
            let ready = self.ep.wait(&mut events, timeout)?;
            let now = Instant::now();
            let mut tun_in = false;
            for ev in &events[..ready] {
                let (flags, token) = (ev.events, ev.u64);
                match token {
                    TOKEN_TUN => {
                        tun_in |= flags & (EPOLLIN | EPOLLERR | EPOLLHUP) != 0;
                        if flags & EPOLLOUT != 0 && self.tun_blocked {
                            self.tun_blocked = false;
                            self.ep.modify(self.tun, EPOLLIN, TOKEN_TUN)?;
                        }
                    }
                    TOKEN_STOP => {
                        sys::drain_counter(self.stop);
                        return Ok(());
                    }
                    TOKEN_TIMER => {
                        sys::drain_counter(self.timer.as_raw_fd());
                        self.armed = None;
                    }
                    _ => self.socket_event(token, flags),
                }
            }
            let busy = tun_in && self.read_tun(now)?;
            if self.stack.poll_timeout().is_some_and(|d| d <= now) {
                self.stack.handle_timeout(now);
            }
            self.accept();
            self.stack_events();
            self.flush(now)?;
            self.publish();
            timeout = if busy { 0 } else { self.next_timeout()? };
        }
    }

    /// Reads packets until EAGAIN or the batch limit; true if the limit stopped it.
    fn read_tun(&mut self, now: Instant) -> io::Result<bool> {
        for _ in 0..TUN_BATCH {
            match sys::read(self.tun, &mut self.rx) {
                Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "tun closed")),
                Ok(n) => {
                    self.n.tx_packets += 1;
                    self.n.tx_bytes += n as u64;
                    // UDP and other datagrams come back as Rx::Transparent*; they are dropped.
                    let _ = self.stack.receive(now, &self.rx[..n]);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn flush(&mut self, now: Instant) -> io::Result<()> {
        if self.tun_blocked {
            return Ok(());
        }
        loop {
            let len = match self.pending.take() {
                Some(len) => len,
                None => match self.stack.poll_transmit(now, &mut self.tx) {
                    Some(len) => len,
                    None => return Ok(()),
                },
            };
            match sys::write(self.tun, &self.tx[..len]) {
                Ok(_) => {
                    self.n.rx_packets += 1;
                    self.n.rx_bytes += len as u64;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    self.pending = Some(len);
                    self.tun_blocked = true;
                    self.ep.modify(self.tun, EPOLLIN | EPOLLOUT, TOKEN_TUN)?;
                    return Ok(());
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => self.pending = Some(len),
                Err(e) if e.raw_os_error() == Some(libc::EBADF) => return Err(e),
                Err(e) => {
                    // As hev does for ENOBUFS/ENOMEM: drop it, TCP retransmits.
                    if self.n.tun_write_drops == 0 {
                        sys::log_warn(&format!("tun write: {e}; dropping"));
                    }
                    self.n.tun_write_drops += 1;
                }
            }
        }
    }

    fn next_timeout(&mut self) -> io::Result<i32> {
        let Some(deadline) = self.stack.poll_timeout() else {
            return Ok(-1);
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(0);
        }
        if left >= FINE_TIMER {
            return Ok(left.as_millis().saturating_add(1).min(i32::MAX as u128) as i32);
        }
        if self.armed != Some(deadline) {
            sys::timerfd_arm(self.timer.as_raw_fd(), left)?;
            self.armed = Some(deadline);
        }
        Ok(-1)
    }

    fn accept(&mut self) {
        while let Some(info) = self.stack.poll_accept() {
            if let Err(e) = self.stack.tcp_accept(info.id, AcceptOpts::default()) {
                sys::log_warn(&format!("accept {}: {e}", info.original_dst));
                continue;
            }
            let fd = match sys::tcp_connect(self.target) {
                Ok(fd) => fd,
                Err(e) => {
                    sys::log_warn(&format!("connect {}: {e}", self.target));
                    self.stack.tcp_abort(info.id);
                    continue;
                }
            };
            let idx = self.free.pop().unwrap_or_else(|| {
                self.conns.push(None);
                self.conns.len() - 1
            });
            self.next_generation = self.next_generation.wrapping_add(1);
            let generation = self.next_generation;
            let token = (TOKEN_CONN + idx as u64) | (u64::from(generation) << 32);
            if let Err(e) = self.ep.add(
                fd.as_raw_fd(),
                EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
                token,
            ) {
                sys::log_warn(&format!("epoll add: {e}"));
                self.free.push(idx);
                self.stack.tcp_abort(info.id);
                continue;
            }
            self.conns[idx] = Some(Conn {
                id: info.id,
                fd,
                generation,
                connecting: true,
                up: Buf::new(),
                up_eof: false,
                up_shut: false,
                down: Buf::new(),
                down_eof: false,
                down_shut: false,
            });
            self.flows.insert(info.id, idx);
        }
    }

    fn stack_events(&mut self) {
        while let Some((id, ready)) = self.stack.poll_event() {
            let Some(&idx) = self.flows.get(&id) else {
                continue;
            };
            if ready.contains(Ready::ERROR) {
                self.finish(idx, Fate::StackError(StreamError::Reset));
                continue;
            }
            self.pump(idx);
        }
    }

    fn socket_event(&mut self, token: u64, flags: u32) {
        let idx = ((token & 0xffff_ffff) - TOKEN_CONN) as usize;
        let generation = (token >> 32) as u32;
        let Some(c) = self.conns.get_mut(idx).and_then(Option::as_mut) else {
            return;
        };
        if c.generation != generation {
            return;
        }
        if c.connecting {
            match sys::so_error(c.fd.as_raw_fd()) {
                Ok(0) if flags & (EPOLLERR | EPOLLHUP) != 0 => {
                    let e = io::Error::new(ErrorKind::ConnectionRefused, "connect failed");
                    return self.finish(idx, Fate::SocketError(e));
                }
                Ok(0) if flags & EPOLLOUT != 0 => c.connecting = false,
                Ok(0) => return,
                Ok(err) => {
                    let e = io::Error::from_raw_os_error(err);
                    return self.finish(idx, Fate::SocketError(e));
                }
                Err(e) => return self.finish(idx, Fate::SocketError(e)),
            }
        }
        self.pump(idx);
    }

    fn pump(&mut self, idx: usize) {
        let Some(c) = self.conns[idx].as_mut() else {
            return;
        };
        match pump(&mut self.stack, c) {
            Fate::Keep => {}
            fate => self.finish(idx, fate),
        }
    }

    fn finish(&mut self, idx: usize, fate: Fate) {
        let Some(c) = self.conns[idx].take() else {
            return;
        };
        self.flows.remove(&c.id);
        self.free.push(idx);
        match fate {
            Fate::Keep | Fate::Done => self.stack.tcp_close(c.id),
            Fate::SocketError(e) => {
                if e.kind() != ErrorKind::ConnectionReset {
                    sys::log_warn(&format!("upstream {}: {e}", self.target));
                }
                self.stack.tcp_abort(c.id);
            }
            Fate::StackError(e) => {
                if e != StreamError::Reset {
                    sys::log_warn(&format!("flow to {}: {e}", self.target));
                }
                sys::linger_zero(c.fd.as_raw_fd());
                self.stack.tcp_close(c.id);
            }
        }
        // Dropping the fd closes it, which also removes it from the epoll set.
    }

    fn publish(&self) {
        SHARED.tx_packets.store(self.n.tx_packets, Relaxed);
        SHARED.tx_bytes.store(self.n.tx_bytes, Relaxed);
        SHARED.rx_packets.store(self.n.rx_packets, Relaxed);
        SHARED.rx_bytes.store(self.n.rx_bytes, Relaxed);
    }
}
