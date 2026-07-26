//! `honk-tool sub` — subscription availability check.
//!
//! Fetches a subscription (or reads a local file), then probes every node:
//! server address families, proxied connectivity to a test host over IPv4
//! and IPv6 (a full protocol dial through the node), and a proxied latency
//! measurement (`urltest_node`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::Args;
use honk_config::node::Node;
use honk_config::subscription::Subscription;
use honk_config::types::SubscriptionType;
use honk_core::proxy::ProxyRegistry;
use honk_core::subscription::SubscriptionManager;
use honk_outbound::urltest::urltest_node;

#[derive(Args)]
pub struct SubArgs {
    /// Subscription URL (http/https) or a local file with one share link per line.
    pub source: String,
    /// Test target for proxied connectivity/latency (host:port).
    #[arg(long, default_value = "cp.cloudflare.com:443")]
    pub target: String,
    /// Latency-test URL (defaults to https://www.gstatic.com/generate_204).
    #[arg(long)]
    pub url: Option<String>,
    /// Per-probe timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,
    /// Maximum concurrent probes.
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,
    /// Probe only the first N nodes (0 = all).
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
    /// User-Agent for the subscription fetch.
    #[arg(long)]
    pub ua: Option<String>,
    /// Explicit IPv4 target for the v4 probe (dae-style, e.g. 1.1.1.1:80).
    /// Overrides DNS resolution for that family.
    #[arg(long, default_value = "1.1.1.1:443")]
    pub v4_target: Option<SocketAddr>,
    /// Explicit IPv6 target for the v6 probe (dae-style, e.g.
    /// [2606:4700:4700::1111]:80).  Use when the resolver gives no AAAA
    /// (e.g. ipversion_prefer: 4 DNS) or the host has none.
    #[arg(long, default_value = "[2606:4700:4700::1111]:443")]
    pub v6_target: Option<SocketAddr>,
}

struct ProbeOutcome {
    node_name: String,
    protocol: String,
    server_v4: bool,
    server_v6: bool,
    v4: Option<Result<Duration, String>>,
    v6: Option<Result<Duration, String>>,
    urltest: Result<Duration, String>,
    udp_dns: Option<Result<Duration, String>>,
    udp_quic: Option<Result<Duration, String>>,
}

pub async fn run(args: SubArgs) -> anyhow::Result<()> {
    let mut nodes = load_nodes(&args).await?;
    if args.limit > 0 {
        nodes.truncate(args.limit);
    }
    print_summary_header(&nodes);

    let registry = Arc::new(ProxyRegistry::default_resolver()?);
    let (url_host, url_port) = split_host_port(&args.target)?;
    let timeout = Duration::from_secs(args.timeout);

    let mut set = tokio::task::JoinSet::new();
    let mut pending = nodes.into_iter();
    let mut running = 0usize;
    let mut outcomes = Vec::new();

    loop {
        while running < args.concurrency
            && let Some(node) = pending.next()
        {
            let registry = Arc::clone(&registry);
            let targets = Arc::new(ProbeTargets {
                host: url_host.to_string(),
                port: url_port,
                url: args.url.clone(),
                timeout,
                v4: args.v4_target,
                v6: args.v6_target,
            });
            set.spawn(async move { probe_node(&registry, node, &targets).await });
            running += 1;
        }
        match set.join_next().await {
            Some(Ok(outcome)) => {
                running -= 1;
                print_outcome(&outcome);
                outcomes.push(outcome);
            }
            Some(Err(e)) => {
                running -= 1;
                eprintln!("probe task panicked: {e}");
            }
            None => break,
        }
    }

    let alive_v4 = outcomes
        .iter()
        .filter(|o| matches!(&o.v4, Some(Ok(_))))
        .count();
    let alive_v6 = outcomes
        .iter()
        .filter(|o| matches!(&o.v6, Some(Ok(_))))
        .count();
    let alive_udp = outcomes
        .iter()
        .filter(|o| matches!(&o.udp_dns, Some(Ok(_))))
        .count();
    let alive_quic = outcomes
        .iter()
        .filter(|o| matches!(&o.udp_quic, Some(Ok(_))))
        .count();
    let mut latencies: Vec<u128> = outcomes
        .iter()
        .filter_map(|o| o.urltest.as_ref().ok().map(|d| d.as_millis()))
        .collect();
    latencies.sort_unstable();
    let median = latencies
        .get(latencies.len() / 2)
        .map(|v| format!("{v}ms"))
        .unwrap_or_else(|| "n/a".into());
    println!(
        "\n== {} node(s): v4-proxied {alive_v4}, v6-proxied {alive_v6}, udp-dns {alive_udp}, udp-quic {alive_quic}, urltest-ok {}, median latency {median}",
        outcomes.len(),
        latencies.len()
    );
    Ok(())
}

/// Load nodes from a subscription URL or a local share-link file.
async fn load_nodes(args: &SubArgs) -> anyhow::Result<Vec<Node>> {
    if std::path::Path::new(&args.source).exists() {
        let content = std::fs::read_to_string(&args.source)
            .with_context(|| format!("read '{}'", args.source))?;
        return parse_lines(&content);
    }

    let sub = Subscription {
        name: "sub".into(),
        url: args.source.clone(),
        sub_type: SubscriptionType::Custom,
        user_agent: args.ua.clone(),
        ..Default::default()
    };
    let manager = SubscriptionManager::new()?;
    let started = Instant::now();
    let nodes = manager
        .fetch(&sub)
        .await
        .with_context(|| format!("fetch subscription '{}'", args.source))?;
    println!("fetched {} node(s) in {:?}", nodes.len(), started.elapsed());
    Ok(nodes)
}

/// Parse a local file of share links (one per line, `#` comments allowed).
fn parse_lines(content: &str) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    let mut skipped = 0usize;
    for line in content.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match Node::from_share_link(line) {
            Ok(node) => nodes.push(node),
            Err(_) => skipped += 1,
        }
    }
    if nodes.is_empty() {
        anyhow::bail!("no valid share links in file");
    }
    if skipped > 0 {
        println!("parsed {} node(s), {skipped} line(s) skipped", nodes.len());
    } else {
        println!("parsed {} node(s)", nodes.len());
    }
    Ok(nodes)
}

fn print_summary_header(nodes: &[Node]) {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for n in nodes {
        *counts.entry(n.protocol.as_str().to_string()).or_default() += 1;
    }
    let breakdown = counts
        .iter()
        .map(|(p, c)| format!("{p}×{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!("protocols: {breakdown}\n");
}

/// Everything a probe run needs to reach the test target.
struct ProbeTargets {
    host: String,
    port: u16,
    url: Option<String>,
    timeout: Duration,
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
}

async fn probe_node(registry: &ProxyRegistry, node: Node, targets: &ProbeTargets) -> ProbeOutcome {
    let (url_host, url_port, timeout) = (targets.host.as_str(), targets.port, targets.timeout);
    let server_families = server_families(&node).await;
    let handler = registry.find(node.protocol);

    let v4 = probe_family(
        registry, &node, url_host, url_port, false, timeout, targets.v4,
    )
    .await;
    let v6 = probe_family(
        registry, &node, url_host, url_port, true, timeout, targets.v6,
    )
    .await;

    let udp_dns = probe_udp_dns(registry, &node, timeout).await;
    // QUIC (HTTP/3) lives on 443 regardless of the TCP check target's port
    // (the dae default cp.cloudflare.com:80 is TCP-only).
    let udp_quic = probe_udp_quic(registry, &node, url_host, 443, timeout).await;

    let urltest = match handler {
        Some(handler) => {
            let url = targets.url.clone().unwrap_or_default();
            urltest_node(&node, handler, &url, timeout)
                .await
                .map_err(|e| e.to_string())
        }
        None => Err(format!("no handler for {:?}", node.protocol)),
    };

    ProbeOutcome {
        node_name: node.name.clone(),
        protocol: node.protocol.as_str().to_string(),
        server_v4: server_families.0,
        server_v6: server_families.1,
        v4,
        v6,
        urltest,
        udp_dns,
        udp_quic,
    }
}

/// Resolve the node server address and report which IP families it has.
async fn server_families(node: &Node) -> (bool, bool) {
    let lookup = format!("{}:0", node.host());
    match tokio::net::lookup_host(lookup).await {
        Ok(addrs) => {
            let mut v4 = false;
            let mut v6 = false;
            for a in addrs {
                if a.is_ipv4() {
                    v4 = true;
                } else {
                    v6 = true;
                }
            }
            (v4, v6)
        }
        Err(_) => (false, false),
    }
}

/// Probe one address family end-to-end: dial the family-specific target
/// through the node and time the full HTTP HEAD exchange (TLS handshake
/// included for https targets).  This is what makes the v4/v6 columns
/// meaningful — a bare dial() return is free for session-multiplexed
/// protocols (AnyTLS reuses the pooled session and never waits for the
/// target), so only a real round-trip proves family reachability.
async fn probe_family(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    v6: bool,
    timeout: Duration,
    explicit: Option<SocketAddr>,
) -> Option<Result<Duration, String>> {
    let addr: SocketAddr = match explicit {
        Some(a) => a,
        None => match tokio::net::lookup_host((url_host, url_port)).await {
            Ok(mut addrs) => addrs.find(|a| a.is_ipv6() == v6)?,
            Err(e) => return Some(Err(format!("resolve {url_host}: {e}"))),
        },
    };
    let handler = registry.find(node.protocol)?;
    // NB: urltest's normalize_url swaps any http:// URL for the default
    // https one — always probe with an https URL (the default targets all
    // serve TLS on 443 anyway).
    let url = format!("https://{url_host}/");
    match honk_outbound::urltest::urltest_node_addr(node, handler, &url, addr, timeout).await {
        Ok(d) => Some(Ok(d)),
        Err(e) => Some(Err(e.to_string())),
    }
}

fn print_outcome(o: &ProbeOutcome) {
    let families = format!(
        "{}{}",
        if o.server_v4 { "v4" } else { "" },
        if o.server_v6 { "+v6" } else { "" }
    );
    let family_str = |r: &Option<Result<Duration, String>>| match r {
        // None means the resolver returned no address of that family (e.g.
        // AAAA suppressed by ipversion_prefer: 4) and no explicit
        // --v4-target/--v6-target was given.
        None => "no-AAAA".to_string(),
        Some(Ok(d)) => format!("{}ms", d.as_millis()),
        Some(Err(e)) => format!("FAIL({})", short_err(e)),
    };
    let urltest_str = match &o.urltest {
        Ok(d) => format!("{}ms", d.as_millis()),
        Err(e) => format!("FAIL({})", short_err(e)),
    };
    let udp_str = |r: &Option<Result<Duration, String>>| match r {
        None => "n/a".to_string(),
        Some(Ok(d)) => format!("{}ms", d.as_millis()),
        Some(Err(e)) if e.contains("not supported") => "unsupp".to_string(),
        Some(Err(e)) => format!("FAIL({})", short_err(e)),
    };
    println!(
        "{:<40} {:<10} {:<6} v4: {:<14} v6: {:<14} urltest: {:<14} dns: {:<14} quic: {}",
        truncate(&o.node_name, 40),
        o.protocol,
        families,
        family_str(&o.v4),
        family_str(&o.v6),
        urltest_str,
        udp_str(&o.udp_dns),
        udp_str(&o.udp_quic),
    );
}

fn short_err(e: &str) -> String {
    truncate(&e.replace('\n', " "), 40)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn split_host_port(s: &str) -> anyhow::Result<(&str, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("target '{s}' must be host:port"))?;
    Ok((host, port.parse()?))
}

/// Tiny xorshift PRNG seeded from the clock (avoids a rand dependency for the
/// two probe packet builders).
fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn rand_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 | 1)
        .unwrap_or(0x9e3779b97f4a7c15)
}

/// UDP probe: one minimal DNS A query through the node's `dial_udp`.
/// Proves the node's UDP relay path end to end (mirrors the engine's
/// `probe_node_udp` health check).
async fn probe_udp_dns(
    registry: &ProxyRegistry,
    node: &Node,
    timeout: Duration,
) -> Option<Result<Duration, String>> {
    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let proxy = match registry.dial_udp(node, dns_server, None, timeout).await {
        Ok(p) => p,
        Err(e) => return Some(Err(e.to_string())),
    };

    // Minimal DNS query: id, RD, qdcount=1, A record for google.com.
    let mut rng = rand_seed();
    let id = next_rand(&mut rng) as u16;
    let mut query = vec![
        (id >> 8) as u8,
        id as u8,
        0x01,
        0x00, // RD
        0x00,
        0x01, // qdcount
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    for label in ["google", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root, A, IN

    let start = Instant::now();
    if let Err(e) = proxy.socket.send_to(&query, proxy.relay_addr).await {
        return Some(Err(format!("dns send: {e}")));
    }
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, proxy.socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            if n >= 2 && buf[0] == query[0] && buf[1] == query[1] {
                Some(Ok(start.elapsed()))
            } else {
                Some(Err("dns response id mismatch".into()))
            }
        }
        Ok(Err(e)) => Some(Err(format!("dns recv: {e}"))),
        Err(_) => Some(Err("dns timeout".into())),
    }
}

/// UDP probe for QUIC: run a real QUIC handshake through the node's
/// `dial_udp` and time it.  Unlike a bare Version-Negotiation trigger (which
/// most frontends silently drop), this proves TLS-in-QUIC reachability
/// through the node's UDP path.
async fn probe_udp_quic(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    timeout: Duration,
) -> Option<Result<Duration, String>> {
    let addr: SocketAddr = match tokio::net::lookup_host((url_host, url_port)).await {
        Ok(mut addrs) => addrs.find(|a| a.is_ipv4())?,
        Err(e) => return Some(Err(format!("resolve {url_host}: {e}"))),
    };
    let proxy = match registry.dial_udp(node, addr, None, timeout).await {
        Ok(p) => p,
        Err(e) => return Some(Err(e.to_string())),
    };

    // Liveness-only client: skip certificate verification, offer h3.
    let probe_node = Node {
        skip_cert_verify: true,
        sni: Some(url_host.to_string()),
        ..Default::default()
    };
    let config = match honk_outbound::quic::client_config(
        &probe_node,
        &[b"h3"],
        honk_outbound::quic::QuicClientOptions::default(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return Some(Err(format!("quic config: {e}"))),
    };

    match honk_outbound::quic::quic_handshake_probe(proxy, addr, url_host, &config, timeout).await {
        Ok(elapsed) => Some(Ok(elapsed)),
        Err(e) => Some(Err(e.to_string())),
    }
}
