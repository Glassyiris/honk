//! In-process bulk TCP benchmark: an endpoint-mode client stack and a transparent-mode server
//! stack joined by direct packet hand-off. No link model, no tun, no sockets, one thread: every
//! CPU cycle spent is the two stacks plus a thin driver loop, so the numbers are the netstack's
//! own cost per packet and per byte.
//!
//! ```text
//! cargo run --release -p honk-netstack --example tcp_bulk -- --mtu 1500
//! tcp_bulk --mtu 8500 --bytes 4294967296 --write-size 65536 --flows 1 --cpu 7
//! ```
//!
//! Flags:
//! - `--mtu <n>`          stack MTU on both sides (default 1500)
//! - `--bytes <n>`        payload bytes in total, split across flows (default 4 GiB)
//! - `--write-size <n>`   bytes per `tcp_write` call (default 64 KiB)
//! - `--flows <n>`        concurrent flows driven in the same loop (default 1)
//! - `--cpu <n>`          pin the process to this CPU with `sched_setaffinity`
//! - `--dir up|down`      up: client writes, transparent stack reads (default);
//!   down: the transparent stack writes, the client reads
//! - `--burst <n>`        at most n writes per flow per loop round; 0 = until the send buffer is
//!   full (default). `--write-size 64 --burst 1` hands the stack one small write per round, so
//!   it emits small segments instead of coalescing them into full-MSS ones.
//! - `--buf <n>`          tcp_snd_buf_max and tcp_rcv_buf_max on both sides (default: Config's)
//! - `--verify`           check the payload pattern on the reading side (costs CPU)
//! - `--no-header`        print the TSV line without the header
//!
//! Output: a TSV header and one TSV line on stdout, a readable summary on stderr. `pkts_up` are
//! client-to-server packets, `pkts_down` server-to-client; each is emitted by one stack and
//! received by the other, so `ns_per_pkt` (CPU time over both counts) is the cost of one packet's
//! transmit plus receive, and `ns_per_data_pkt` is the CPU time over the data-direction packets.

use honk_netstack::{AcceptOpts, Config, ExcludeSet, FlowId, Mode, Ready, Stack, StreamError};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::exit;
use std::time::{Duration, Instant};

const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const BASE_PORT: u16 = 8000;
/// Pattern period for `--verify`; prime so it never aligns with segment sizes.
const PERIOD: usize = 251;

struct Opts {
    mtu: u16,
    bytes: u64,
    write_size: usize,
    flows: usize,
    cpu: Option<usize>,
    down: bool,
    burst: usize,
    buf: Option<usize>,
    verify: bool,
    header: bool,
}

fn usage(msg: &str) -> ! {
    eprintln!("tcp_bulk: {msg}");
    eprintln!(
        "usage: tcp_bulk [--mtu N] [--bytes N] [--write-size N] [--flows N] [--cpu N] \
         [--dir up|down] [--burst N] [--buf N] [--verify] [--no-header]"
    );
    exit(2)
}

fn parse() -> Opts {
    let mut o = Opts {
        mtu: 1500,
        bytes: 4 << 30,
        write_size: 64 << 10,
        flows: 1,
        cpu: None,
        down: false,
        burst: 0,
        buf: None,
        verify: false,
        header: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .unwrap_or_else(|| usage(&format!("{flag} needs a value")))
        };
        fn num<T: std::str::FromStr>(flag: &str, v: String) -> T {
            v.parse()
                .unwrap_or_else(|_| usage(&format!("{flag}: bad number {v:?}")))
        }
        match flag.as_str() {
            "--mtu" => o.mtu = num(&flag, value()),
            "--bytes" => o.bytes = num(&flag, value()),
            "--write-size" => o.write_size = num(&flag, value()),
            "--flows" => o.flows = num(&flag, value()),
            "--cpu" => o.cpu = Some(num(&flag, value())),
            "--burst" => o.burst = num(&flag, value()),
            "--buf" => o.buf = Some(num(&flag, value())),
            "--dir" => {
                o.down = match value().as_str() {
                    "up" => false,
                    "down" => true,
                    v => usage(&format!("--dir: expected up or down, got {v:?}")),
                }
            }
            "--verify" => o.verify = true,
            "--no-header" => o.header = false,
            "-h" | "--help" => usage("help"),
            _ => usage(&format!("unknown flag {flag:?}")),
        }
    }
    if o.write_size == 0 || o.flows == 0 || o.bytes < o.flows as u64 {
        usage("--write-size and --flows must be positive and --bytes >= --flows");
    }
    if o.flows > usize::from(u16::MAX - BASE_PORT) {
        usage("too many flows");
    }
    o
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32;
        // `struct rusage` on 64-bit Linux: two timevals (user, system), then 14 longs.
        fn getrusage(who: i32, usage: *mut [i64; 18]) -> i32;
        fn sched_setaffinity(pid: i32, size: usize, mask: *const [u64; 16]) -> i32;
        fn sched_getcpu() -> i32;
    }
    const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

    /// Process CPU time in nanoseconds.
    pub fn cpu_ns() -> u64 {
        let mut ts = Timespec { sec: 0, nsec: 0 };
        // SAFETY: ts is a valid timespec for the duration of the call.
        unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
        ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
    }

    /// (user, system) CPU seconds of the process.
    pub fn rusage() -> (f64, f64) {
        let mut r = [0i64; 18];
        // SAFETY: r is at least as large as struct rusage on 64-bit Linux and Android.
        unsafe { getrusage(0, &mut r) };
        (
            r[0] as f64 + r[1] as f64 / 1e6,
            r[2] as f64 + r[3] as f64 / 1e6,
        )
    }

    pub fn pin(cpu: usize) -> Result<(), std::io::Error> {
        if cpu >= 1024 {
            return Err(std::io::Error::from_raw_os_error(22));
        }
        let mut mask = [0u64; 16];
        mask[cpu / 64] |= 1 << (cpu % 64);
        // SAFETY: mask is a 128-byte cpu_set_t; pid 0 is the calling thread, the only one.
        match unsafe { sched_setaffinity(0, std::mem::size_of_val(&mask), &mask) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    pub fn current_cpu() -> i64 {
        // SAFETY: no arguments.
        i64::from(unsafe { sched_getcpu() })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod sys {
    pub fn cpu_ns() -> u64 {
        0
    }
    pub fn rusage() -> (f64, f64) {
        (0.0, 0.0)
    }
    pub fn pin(_cpu: usize) -> Result<(), std::io::Error> {
        Err(std::io::Error::other("pinning needs Linux"))
    }
    pub fn current_cpu() -> i64 {
        -1
    }
}

/// One stack and its application-side view of every flow.
struct Side {
    stack: Stack,
    ids: Vec<Option<FlowId>>,
    index: HashMap<FlowId, usize>,
    /// Set by an event, cleared when the call would block.
    want: Vec<bool>,
}

impl Side {
    fn new(stack: Stack, flows: usize) -> Side {
        Side {
            stack,
            ids: vec![None; flows],
            index: HashMap::with_capacity(flows),
            want: vec![false; flows],
        }
    }

    fn bind(&mut self, i: usize, id: FlowId) {
        self.ids[i] = Some(id);
        self.index.insert(id, i);
    }

    /// Drains the event queue into `want`; an error event is fatal.
    fn events(&mut self, name: &str) -> bool {
        let mut any = false;
        while let Some((id, ready)) = self.stack.poll_event() {
            if ready.contains(Ready::ERROR) {
                fail(&format!("{name}: error event on {id:?}"));
            }
            if let Some(&i) = self.index.get(&id) {
                self.want[i] = true;
                any = true;
            }
        }
        any
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("tcp_bulk: {msg}");
    exit(1)
}

fn main() {
    let o = parse();
    if let Some(cpu) = o.cpu
        && let Err(e) = sys::pin(cpu)
    {
        fail(&format!("cannot pin to cpu {cpu}: {e}"));
    }

    let t0 = Instant::now();
    let mut ccfg = Config::new([7; 32]);
    ccfg.local_v4 = Some(CLIENT);
    let mut scfg = Config::new([8; 32]);
    scfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    for cfg in [&mut ccfg, &mut scfg] {
        cfg.mtu = o.mtu;
        if let Some(b) = o.buf {
            cfg.tcp_snd_buf_max = b;
            cfg.tcp_rcv_buf_max = b;
        }
    }
    let mut client = Side::new(Stack::new(ccfg, t0), o.flows);
    let mut server = Side::new(Stack::new(scfg, t0), o.flows);

    let per_flow = o.bytes / o.flows as u64;
    let mut to_write: Vec<u64> = vec![per_flow; o.flows];
    to_write[0] += o.bytes % o.flows as u64;
    let mut written = vec![0u64; o.flows];
    let mut read = vec![0u64; o.flows];
    let mut shut = vec![false; o.flows];
    let mut eof = vec![false; o.flows];
    let mut done = 0usize;

    let data: Vec<u8> = (0..o.write_size + PERIOD)
        .map(|k| (k % PERIOD) as u8)
        .collect();
    let mut rbuf = vec![0u8; o.write_size.max(64 << 10)];
    let mut pkt = vec![0u8; usize::from(o.mtu).max(1500) + 64];

    let cpu0 = sys::cpu_ns();
    let (user0, sys0) = sys::rusage();
    let wall0 = Instant::now();
    for i in 0..o.flows {
        let remote = SocketAddr::new(IpAddr::V4(SERVER), BASE_PORT + i as u16);
        let id = client
            .stack
            .tcp_connect(wall0, remote)
            .unwrap_or_else(|e| fail(&format!("connect: {e}")));
        client.bind(i, id);
    }

    let (mut pkts_up, mut pkts_down, mut bytes_up) = (0u64, 0u64, 0u64);
    let (mut idle_waits, mut idle_ns, mut rounds, mut stuck) = (0u64, 0u64, 0u64, 0u32);
    loop {
        rounds += 1;
        let now = Instant::now();
        let mut progress = client.events("client");

        // The writing side.
        let writer = if o.down { &mut server } else { &mut client };
        for i in 0..o.flows {
            let Some(id) = writer.ids[i] else { continue };
            if !writer.want[i] || shut[i] {
                continue;
            }
            let mut calls = 0;
            while written[i] < to_write[i] && (o.burst == 0 || calls < o.burst) {
                let n = (to_write[i] - written[i]).min(o.write_size as u64) as usize;
                let off = (written[i] % PERIOD as u64) as usize;
                match writer.stack.tcp_write(id, &data[off..off + n]) {
                    Ok(w) => {
                        written[i] += w as u64;
                        calls += 1;
                        progress = true;
                    }
                    Err(StreamError::WouldBlock) => {
                        writer.want[i] = false;
                        break;
                    }
                    Err(e) => fail(&format!("write flow {i}: {e}")),
                }
            }
            if written[i] == to_write[i] {
                writer
                    .stack
                    .tcp_shutdown(id)
                    .unwrap_or_else(|e| fail(&format!("shutdown flow {i}: {e}")));
                shut[i] = true;
                writer.want[i] = false;
                progress = true;
            }
        }
        client.stack.take_tx_wakeup();

        while let Some(n) = client.stack.poll_transmit(now, &mut pkt) {
            server.stack.receive(now, &pkt[..n]);
            pkts_up += 1;
            bytes_up += n as u64;
            progress = true;
        }

        while let Some(info) = server.stack.poll_accept() {
            let port = info.original_dst.port();
            let i = usize::from(port.wrapping_sub(BASE_PORT));
            if i >= o.flows || server.ids[i].is_some() {
                fail(&format!("unexpected SYN to port {port}"));
            }
            server
                .stack
                .tcp_accept(info.id, AcceptOpts::default())
                .unwrap_or_else(|e| fail(&format!("accept flow {i}: {e}")));
            server.bind(i, info.id);
            progress = true;
        }
        progress |= server.events("server");

        // The reading side. In `down` the server wrote above before it had read its events; the
        // next round picks those up, as an event loop would.
        let (writer, reader) = if o.down {
            (&mut server, &mut client)
        } else {
            (&mut client, &mut server)
        };
        for i in 0..o.flows {
            let Some(id) = reader.ids[i] else { continue };
            if !reader.want[i] || eof[i] {
                continue;
            }
            loop {
                match reader.stack.tcp_read(id, &mut rbuf) {
                    Ok(0) => {
                        if read[i] != to_write[i] {
                            fail(&format!("flow {i}: EOF after {} bytes", read[i]));
                        }
                        eof[i] = true;
                        done += 1;
                        reader.stack.tcp_close(id);
                        if let Some(w) = writer.ids[i] {
                            writer.stack.tcp_close(w);
                        }
                        break;
                    }
                    Ok(n) => {
                        if o.verify {
                            let base = read[i];
                            for (k, &b) in rbuf[..n].iter().enumerate() {
                                if b != ((base + k as u64) % PERIOD as u64) as u8 {
                                    fail(&format!("flow {i}: bad byte at {}", base + k as u64));
                                }
                            }
                        }
                        read[i] += n as u64;
                        progress = true;
                    }
                    Err(StreamError::WouldBlock) => {
                        reader.want[i] = false;
                        break;
                    }
                    Err(e) => fail(&format!("read flow {i}: {e}")),
                }
            }
        }
        server.stack.take_tx_wakeup();

        while let Some(n) = server.stack.poll_transmit(now, &mut pkt) {
            client.stack.receive(now, &pkt[..n]);
            pkts_down += 1;
            progress = true;
        }

        if done == o.flows {
            break;
        }

        let deadline = [client.stack.poll_timeout(), server.stack.poll_timeout()]
            .into_iter()
            .flatten()
            .min();
        if let Some(d) = deadline
            && d <= now
        {
            client.stack.handle_timeout(now);
            server.stack.handle_timeout(now);
            progress = true;
        }
        if progress {
            stuck = 0;
            continue;
        }
        // Nothing moved. Wait for the next timer (pacing, delayed ACK, RTO) or, with none armed,
        // retry every flow once in case an edge was missed; a second idle round is a stall.
        match deadline {
            Some(d) => {
                let wait = d.saturating_duration_since(Instant::now());
                idle_waits += 1;
                idle_ns += wait.as_nanos() as u64;
                if wait > Duration::from_micros(200) {
                    std::thread::sleep(wait);
                } else {
                    while Instant::now() < d {
                        std::hint::spin_loop();
                    }
                }
            }
            None => {
                stuck += 1;
                if stuck > 2 {
                    fail(&format!(
                        "stalled: written {written:?} read {read:?} client {:?} server {:?}",
                        client
                            .ids
                            .iter()
                            .map(|id| id.and_then(|id| client.stack.tcp_state(id)))
                            .collect::<Vec<_>>(),
                        server
                            .ids
                            .iter()
                            .map(|id| id.and_then(|id| server.stack.tcp_state(id)))
                            .collect::<Vec<_>>(),
                    ));
                }
                client.want.iter_mut().for_each(|w| *w = true);
                server.want.iter_mut().for_each(|w| *w = true);
            }
        }
    }

    let wall = wall0.elapsed().as_secs_f64();
    let cpu_ns = sys::cpu_ns() - cpu0;
    let (user1, sys1) = sys::rusage();
    let cpu = cpu_ns as f64 / 1e9;
    let total = o.bytes as f64;
    let gbps = total * 8.0 / wall / 1e9;
    let data_pkts = if o.down { pkts_down } else { pkts_up };
    let avg_up = if pkts_up == 0 {
        0.0
    } else {
        bytes_up as f64 / pkts_up as f64
    };
    let ns_per_pkt = cpu_ns as f64 / (pkts_up + pkts_down) as f64;
    let ns_per_data_pkt = cpu_ns as f64 / data_pkts as f64;
    let cpu_per_gb = cpu / (total / 1e9);
    let pinned = o.cpu.map_or(-1, |c| c as i64);

    if o.header {
        println!(
            "mtu\tdir\tbytes\twrite_size\tburst\tflows\tcpu\tran_on\twall_s\tgbps\tpkts_up\tpkts_down\t\
             avg_up_pkt_bytes\tns_per_pkt\tns_per_data_pkt\tcpu_s\tuser_s\tsys_s\tcpu_s_per_gb\t\
             rounds\tidle_waits\tidle_s"
        );
    }
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\t{:.3}\t{}\t{}\t{:.1}\t{:.1}\t{:.1}\t{:.4}\t{:.4}\t{:.4}\t{:.4}\t{}\t{}\t{:.4}",
        o.mtu,
        if o.down { "down" } else { "up" },
        o.bytes,
        o.write_size,
        o.burst,
        o.flows,
        pinned,
        sys::current_cpu(),
        wall,
        gbps,
        pkts_up,
        pkts_down,
        avg_up,
        ns_per_pkt,
        ns_per_data_pkt,
        cpu,
        user1 - user0,
        sys1 - sys0,
        cpu_per_gb,
        rounds,
        idle_waits,
        idle_ns as f64 / 1e9,
    );
    eprintln!(
        "tcp_bulk: {} MiB {} in {wall:.3} s = {gbps:.3} Gbit/s; {pkts_up} pkts up, {pkts_down} down; \
         {ns_per_pkt:.0} ns/pkt, {ns_per_data_pkt:.0} ns/data pkt; cpu {cpu:.3} s = {cpu_per_gb:.3} s/GB; \
         {idle_waits} timer waits ({:.3} s)",
        o.bytes >> 20,
        if o.down { "down" } else { "up" },
        idle_ns as f64 / 1e9,
    );
}
