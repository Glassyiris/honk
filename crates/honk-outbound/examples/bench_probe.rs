//! Benchmark a proxy node end to end: dial latency distribution, concurrent
//! dials, download throughput through the tunnel, and UDP echo RTT.
//!
//! Usage: bench_probe <share-link> <target-addr> [dials=N] [duration=SECS]
//!   share-link: anytls://... / tuic://... (honk share-link syntax)
//!   target-addr: host:port of the bench HTTP/UDP-echo server the proxy
//!                will be asked to connect to (e.g. 127.0.0.1:8002 on the
//!                proxy server's host)

use std::net::SocketAddr;
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

fn pct(sorted: &[Duration], p: usize) -> Duration {
    sorted[sorted.len() * p / 100]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let link = std::env::args().nth(1).expect("share-link");
    let target: SocketAddr = std::env::args().nth(2).expect("target").parse()?;
    let n_dials = opt("dials", 20) as usize;
    let duration = Duration::from_secs(opt("duration", 10));

    let node = Node::from_share_link(&link)?;
    let registry = ProxyRegistry::default_resolver()?;
    let handler = registry.find(node.protocol).expect("handler for protocol");

    // --- 1. Sequential dial latency ---
    let mut lat = Vec::with_capacity(n_dials);
    for _ in 0..n_dials {
        let t0 = Instant::now();
        let s = handler
            .dial(&node, target, None, Duration::from_secs(10))
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
        tasks.push(handler.dial(&node, target, None, Duration::from_secs(10)));
    }
    let results = futures_util::future::join_all(tasks).await;
    let ok = results.iter().filter(|r| r.is_ok()).count();
    println!(
        "concurrent dials: {ok}/{n_par} ok in {:?} (wall)",
        t0.elapsed()
    );

    // --- 3. Download throughput ---
    let mut s = handler
        .dial(&node, target, None, Duration::from_secs(10))
        .await?;
    s.stream
        .write_all(b"GET / HTTP/1.1\r\nHost: bench\r\nConnection: close\r\n\r\n")
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
    let secs = t0.elapsed().as_secs_f64();
    println!(
        "throughput: {:.1} MB in {:.1}s = {:.2} MB/s ({:.0} Mbps)",
        total as f64 / 1e6,
        secs,
        total as f64 / 1e6 / secs,
        total as f64 * 8.0 / 1e6 / secs
    );

    // --- 4. UDP echo RTT ---
    let udp_target: SocketAddr = std::env::args()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or(target);
    match handler
        .dial_udp(&node, udp_target, None, Duration::from_secs(10))
        .await
    {
        Ok(udp) => {
            let mut rtts = Vec::new();
            let mut buf = [0u8; 256];
            for i in 0..10u32 {
                let t0 = Instant::now();
                udp.socket.send_to(&i.to_be_bytes(), udp.relay_addr).await?;
                if let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_secs(3), udp.socket.recv_from(&mut buf))
                        .await
                {
                    rtts.push(t0.elapsed());
                }
            }
            rtts.sort();
            if !rtts.is_empty() {
                println!(
                    "udp echo rtt (n={}): min={:?} p50={:?} max={:?}",
                    rtts.len(),
                    rtts[0],
                    pct(&rtts, 50),
                    rtts[rtts.len() - 1]
                );
            } else {
                println!("udp echo: all lost");
            }
        }
        Err(e) => println!("udp: unsupported ({e})"),
    }
    Ok(())
}
