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
    #[arg(long, default_value = "www.gstatic.com:443")]
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
}

struct ProbeOutcome {
    node_name: String,
    protocol: String,
    server_v4: bool,
    server_v6: bool,
    v4: Option<Result<Duration, String>>,
    v6: Option<Result<Duration, String>>,
    urltest: Result<Duration, String>,
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
            let url = args.url.clone();
            let (host, port) = (url_host.to_string(), url_port);
            set.spawn(async move { probe_node(&registry, node, &host, port, url, timeout).await });
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
        "\n== {} node(s): v4-proxied {alive_v4}, v6-proxied {alive_v6}, urltest-ok {}, median latency {median}",
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

async fn probe_node(
    registry: &ProxyRegistry,
    node: Node,
    url_host: &str,
    url_port: u16,
    url: Option<String>,
    timeout: Duration,
) -> ProbeOutcome {
    let server_families = server_families(&node).await;
    let handler = registry.find(node.protocol);

    let v4 = probe_family(registry, &node, url_host, url_port, false, timeout).await;
    let v6 = probe_family(registry, &node, url_host, url_port, true, timeout).await;

    let urltest = match handler {
        Some(handler) => {
            let url = url.unwrap_or_default();
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

/// Dial the test host through the node over one address family; measures the
/// full protocol handshake time (TLS included for TLS-based protocols).
async fn probe_family(
    registry: &ProxyRegistry,
    node: &Node,
    url_host: &str,
    url_port: u16,
    v6: bool,
    timeout: Duration,
) -> Option<Result<Duration, String>> {
    let addr: SocketAddr = match tokio::net::lookup_host((url_host, url_port)).await {
        Ok(mut addrs) => match addrs.find(|a| a.is_ipv6() == v6) {
            Some(a) => a,
            None => return None, // family not available for the test host
        },
        Err(e) => return Some(Err(format!("resolve {url_host}: {e}"))),
    };
    let start = Instant::now();
    let result = registry.dial(node, addr, Some(url_host), timeout).await;
    Some(match result {
        Ok(_stream) => Ok(start.elapsed()),
        Err(e) => Err(e.to_string()),
    })
}

fn print_outcome(o: &ProbeOutcome) {
    let families = format!(
        "{}{}",
        if o.server_v4 { "v4" } else { "" },
        if o.server_v6 { "+v6" } else { "" }
    );
    let family_str = |r: &Option<Result<Duration, String>>| match r {
        None => "n/a".to_string(),
        Some(Ok(d)) => format!("{}ms", d.as_millis()),
        Some(Err(e)) => format!("FAIL({})", short_err(e)),
    };
    let urltest_str = match &o.urltest {
        Ok(d) => format!("{}ms", d.as_millis()),
        Err(e) => format!("FAIL({})", short_err(e)),
    };
    println!(
        "{:<40} {:<10} {:<6} v4: {:<18} v6: {:<18} urltest: {}",
        truncate(&o.node_name, 40),
        o.protocol,
        families,
        family_str(&o.v4),
        family_str(&o.v6),
        urltest_str
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
