// Minimal closed-loop UDP DNS load client for the lab DNS-listener comparison.
// Usage: dnsload <host> <port> <threads> <seconds> <mode: cache|unique> [qtype]
// Prints one summary line: mode threads qps total ok fail p50_us p95_us p99_us max_us
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in qname.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!("usage: dnsload <host> <port> <threads> <seconds> <cache|unique> [qtype]");
        std::process::exit(2);
    }
    let host = args[1].clone();
    let port: u16 = args[2].parse().unwrap();
    let threads: usize = args[3].parse().unwrap();
    let seconds: u64 = args[4].parse().unwrap();
    let unique = args[5] == "unique";
    let qtype: u16 = args.get(6).map_or(1, |v| v.parse().unwrap());
    let target = format!("{host}:{port}");
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let total = Arc::new(AtomicU64::new(0));
    let fails = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for tid in 0..threads {
        let target = target.clone();
        let total = Arc::clone(&total);
        let fails = Arc::clone(&fails);
        handles.push(std::thread::spawn(move || {
            let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
            socket.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
            let mut buf = [0u8; 2048];
            let mut latencies = Vec::new();
            let mut sent: u64 = 0;
            let mut ok: u64 = 0;
            let mut fail: u64 = 0;
            let mut id_counter: u32 = tid as u32;
            while Instant::now() < deadline {
                id_counter = id_counter.wrapping_add(1);
                let qname = if unique {
                    format!("q{}.u{}.bench.test", id_counter, tid)
                } else {
                    "cache.bench.test".to_string()
                };
                let query = build_query(id_counter as u16, &qname, qtype);
                let start = Instant::now();
                if socket.send_to(&query, &target).is_err() {
                    fail += 1;
                    continue;
                }
                sent += 1;
                match socket.recv(&mut buf) {
                    Ok(n) if n >= 12 => {
                        ok += 1;
                        latencies.push(start.elapsed().as_micros() as u64);
                    }
                    _ => fail += 1,
                }
            }
            total.fetch_add(ok, Ordering::Relaxed);
            fails.fetch_add(fail, Ordering::Relaxed);
            let _ = sent;
            latencies
        }));
    }
    let mut all: Vec<u64> = Vec::new();
    for handle in handles {
        all.extend(handle.join().expect("thread"));
    }
    all.sort_unstable();
    let pick = |p: f64| -> u64 {
        if all.is_empty() {
            return 0;
        }
        let idx = ((all.len() as f64 - 1.0) * p).round() as usize;
        all[idx]
    };
    let ok = total.load(Ordering::Relaxed);
    let fail = fails.load(Ordering::Relaxed);
    let qps = ok as f64 / seconds as f64;
    println!(
        "{} {} {:.0} {} {} {} {} {} {}",
        if unique { "unique" } else { "cache" },
        threads,
        qps,
        ok,
        fail,
        pick(0.50),
        pick(0.95),
        pick(0.99),
        all.last().copied().unwrap_or(0)
    );
}
