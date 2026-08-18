//! Benchmark a proxy node end to end: dial latency distribution, concurrent
//! dials, download throughput with process CPU, and UDP echo RTT/rate.
//!
//! Usage: bench_probe <share-link> <tcp-target> [udp-target] [dials=N]
//!        [duration=SECS] [udp_packets=N] [udp_bytes=N]
//!   share-link: any link accepted by `Node::from_share_link`
//!   targets: benchmark HTTP server and optional UDP echo server addresses

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use honk_config::node::Node;
use honk_outbound::proxy::ProxyRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn opt(name: &str, default: u64) -> u64 {
    std::env::args()
        .find_map(|a| a.strip_prefix(&format!("{name}=")).map(str::to_string))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .map(|(_, fields)| fields)
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    fields
        .get(11)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
        + fields
            .get(12)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
}

fn cpu_pct(delta_ticks: u64, seconds: f64) -> f64 {
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    delta_ticks as f64 / ticks_per_second / seconds * 100.0
}

fn pct(sorted: &[Duration], p: usize) -> Duration {
    sorted[sorted.len() * p / 100]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share-link");
    let target: SocketAddr = std::env::args().nth(2).expect("target").parse()?;
    let n_dials = opt("dials", 20) as usize;
    let duration = Duration::from_secs(opt("duration", 10));
    let udp_packets = opt("udp_packets", 10) as u32;
    let udp_bytes = opt("udp_bytes", 1200).clamp(4, u16::MAX as u64) as usize;

    let mut node = Node::from_share_link(&link)?;
    node.id = node.derive_id();
    let generation = Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(
        std::slice::from_ref(&node),
    )?);
    let registry = ProxyRegistry::default_resolver()?;

    // --- 1. Sequential dial latency ---
    let mut lat = Vec::with_capacity(n_dials);
    for _ in 0..n_dials {
        let t0 = Instant::now();
        let s = registry
            .dial_runtime(
                Arc::clone(&generation),
                node.id,
                target,
                None,
                Duration::from_secs(10),
            )
            .await?;
        lat.push(t0.elapsed());
        drop(s);
    }
    lat.sort();
    println!(
        "dial latency (n={}): min={:?} p50={:?} p95={:?} max={:?}",
        lat.len(),
        lat[0],
        pct(&lat, 50),
        pct(&lat, 95),
        lat[lat.len() - 1]
    );

    // --- 2. Concurrent dials ---
    let n_par = 10;
    let t0 = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..n_par {
        tasks.push(registry.dial_runtime(
            Arc::clone(&generation),
            node.id,
            target,
            None,
            Duration::from_secs(10),
        ));
    }
    let results = futures_util::future::join_all(tasks).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    println!(
        "concurrent dials: {ok}/{n_par} ok in {:?} (wall)",
        t0.elapsed()
    );

    // --- 3. Download throughput ---
    let mut s = registry
        .dial_runtime(
            Arc::clone(&generation),
            node.id,
            target,
            None,
            Duration::from_secs(10),
        )
        .await?;
    s.stream
        .write_all(b"GET /big.bin HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
        .await?;
    // Skip headers (scan for CRLFCRLF byte-by-byte).
    let mut hdr = [0u8; 1];
    let mut window = [0u8; 4];
    loop {
        s.stream.read_exact(&mut hdr).await?;
        window.rotate_left(1);
        window[3] = hdr[0];
        if window == *b"\r\n\r\n" {
            break;
        }
    }
    let ticks0 = cpu_ticks();
    let t0 = Instant::now();
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    while t0.elapsed() < duration {
        match tokio::time::timeout(Duration::from_secs(5), s.stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => total += n as u64,
            Ok(Err(e)) => anyhow::bail!("read error: {e}"),
        }
    }
    let elapsed = t0.elapsed();
    let secs = elapsed.as_secs_f64();
    let cpu = cpu_pct(cpu_ticks().saturating_sub(ticks0), secs);
    println!(
        "throughput: {:.1} MB in {:.1}s = {:.2} MB/s ({:.0} Mbps), cpu={cpu:.1}%",
        total as f64 / 1e6,
        secs,
        total as f64 / 1e6 / secs,
        total as f64 * 8.0 / 1e6 / secs
    );

    // --- 4. UDP echo RTT/rate ---
    let udp_target: SocketAddr = std::env::args()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or(target);
    match registry
        .dial_udp_transport_runtime(
            Arc::clone(&generation),
            node.id,
            udp_target,
            None,
            Duration::from_secs(10),
        )
        .await
    {
        Ok(transport) => {
            let mut rtts = Vec::new();
            let mut sent = vec![0x5a; udp_bytes];
            let mut received = vec![0; udp_bytes];
            let ticks0 = cpu_ticks();
            let started = Instant::now();
            for i in 0..udp_packets {
                sent[..4].copy_from_slice(&i.to_be_bytes());
                let t0 = Instant::now();
                transport.send_packet(&sent).await?;
                if let Ok(Ok((size, peer))) = tokio::time::timeout(
                    Duration::from_secs(3),
                    transport.recv_packet(&mut received),
                )
                .await
                    && peer == udp_target
                    && size == sent.len()
                    && received == sent
                {
                    rtts.push(t0.elapsed());
                }
            }
            let elapsed = started.elapsed();
            rtts.sort();
            if !rtts.is_empty() {
                println!(
                    "udp echo (n={}/{udp_packets}, bytes={udp_bytes}): min={:?} p50={:?} p95={:?} max={:?}, {:.0} packets/s, cpu={:.1}%",
                    rtts.len(),
                    rtts[0],
                    pct(&rtts, 50),
                    pct(&rtts, 95),
                    rtts[rtts.len() - 1],
                    rtts.len() as f64 / elapsed.as_secs_f64(),
                    cpu_pct(cpu_ticks().saturating_sub(ticks0), elapsed.as_secs_f64()),
                );
            } else {
                println!("udp echo: all lost or invalid");
            }
        }
        Err(e) => println!("udp: unsupported ({e})"),
    }
    generation.shutdown().await;
    Ok(())
}
