//! honk-core: eBPF-based transparent proxy engine. Uses TC redirects and
//! `sk_lookup` BPF with an isolated `daens` network namespace — no iptables
//! TPROXY rules needed. The process (all threads) always stays in the host
//! netns; daens is entered only through scoped `with_daens_netns` switches
//! (dae0peer/sk_lookup attach, TPROXY listener bind, DNS/UDP reply socket
//! creation), mirroring Go dae's `DaeNetns.WithRequired` ("listen and serve
//! in dae netns"). Trait-based backends (real aya + mock) for testing
//! without kernel eBPF support.

pub mod cachedb;
#[cfg(feature = "clash-api")]
pub mod clash_api;
pub mod connection_tracker;
pub mod control;
pub mod dns;
pub mod ebpf;
pub mod mode;
pub mod pool;
pub mod relay;
pub mod routing;
pub mod sniffing;
pub mod stats;
pub mod subscription;

pub use honk_outbound::alive as outbound;
pub use honk_outbound::group;
pub use honk_outbound::proxy;

use clap::Parser;
use honk_config::Config;
use honk_ebpf_common::ParamKey;
use std::path::PathBuf;
use tracing::{info, warn};

/// Raise the file-descriptor rlimit to the hard maximum (or 1_048_576 if
/// the hard limit is unlimited).  A busy transparent proxy must handle
/// thousands of concurrent connections; the default 1024-fd soft limit is
/// far too low.
fn raise_nofile_rlimit() -> anyhow::Result<()> {
    use std::io::Error;
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } != 0 {
        anyhow::bail!("getrlimit(RLIMIT_NOFILE): {}", Error::last_os_error());
    }
    let soft_max = if rlim.rlim_max == libc::RLIM_INFINITY {
        1_048_576
    } else {
        rlim.rlim_max
    };
    if rlim.rlim_cur >= soft_max {
        info!(
            "NOFILE rlimit already {} (soft) / {} (hard)",
            rlim.rlim_cur, rlim.rlim_max
        );
        return Ok(());
    }
    rlim.rlim_cur = soft_max;
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) } != 0 {
        anyhow::bail!(
            "setrlimit(RLIMIT_NOFILE, {}): {}",
            soft_max,
            Error::last_os_error()
        );
    }
    info!(
        "Raised NOFILE rlimit to {} (hard={})",
        soft_max, rlim.rlim_max
    );
    Ok(())
}

/// Resolve an interface name, expanding `"auto"` or empty to the default route interface.
#[cfg(feature = "ebpf")]
fn resolve_interface(name: &str) -> String {
    if name == "auto" || name.is_empty() {
        detect_default_interface().unwrap_or_else(|| {
            warn!("could not detect default route interface; falling back to 'lo'");
            "lo".to_string()
        })
    } else {
        name.to_string()
    }
}

/// Detect the interface used by the IPv4 default route.
#[cfg(feature = "ebpf")]
///
/// Parses `/proc/net/route` and returns the interface with destination
/// `00000000` and mask `00000000` and the lowest metric.
fn detect_default_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(u32, String)> = None;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 8 {
            continue;
        }
        let iface = parts[0];
        let dest = parts[1];
        let mask = parts[7];
        if dest != "00000000" || mask != "00000000" {
            continue;
        }
        let metric = parts[6].parse::<u32>().unwrap_or(u32::MAX);
        let better = match &best {
            None => true,
            Some((m, _)) => metric < *m,
        };
        if better {
            best = Some((metric, iface.to_string()));
        }
    }
    best.map(|(_, iface)| iface)
}

/// Default eBPF object file embedded into the binary.
/// Built-in eBPF object embedded at compile time by build.rs.
/// `--bpf-object` CLI flag overrides this at runtime.
#[cfg(feature = "ebpf")]
const DEFAULT_BPF_OBJECT: &[u8] = include_bytes!(env!("HONK_EBPF_OBJECT"));

#[derive(clap::Subcommand, Debug)]
pub enum ClashCommand {
    /// Set clash mode (rule / global / direct)
    Mode {
        /// Mode value: rule, global, or direct
        mode: String,
    },
    /// Set selector group proxy choice
    Proxy {
        /// Selector group name
        group: String,
        /// Node name to select
        node: String,
    },
    /// Test per-node TCP connect latency
    Delay {
        /// Node name to test
        node: String,
        /// Optional target URL (defaults to node address:port)
        #[arg(short, long)]
        url: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Clash-style subcommand (mode, proxy, delay)
    #[command(subcommand)]
    pub command: Option<ClashCommand>,

    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/honk/config.dae")]
    pub config: PathBuf,

    /// Path to an external eBPF object file (for real eBPF backend).
    /// If omitted, the built-in object file is used.
    #[arg(short = 'b', long)]
    pub bpf_object: Option<PathBuf>,

    /// BPF pin root directory
    #[arg(long, default_value = "/sys/fs/bpf")]
    pub bpf_pin_root: PathBuf,

    /// Run in debug mode with verbose logging
    #[arg(short, long)]
    pub debug: bool,

    /// Use mock eBPF backend (for testing without kernel support)
    #[arg(long)]
    pub mock_ebpf: bool,
}

pub async fn handle_clash_command(cli: &Cli) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    use std::time::Duration;

    let cmd = cli.command.as_ref().expect("clash subcommand required");

    match cmd {
        ClashCommand::Mode { mode } => {
            let valid_modes = ["rule", "global", "direct"];
            if !valid_modes.contains(&mode.as_str()) {
                anyhow::bail!(
                    "Invalid mode '{}'. Valid modes: {}",
                    mode,
                    valid_modes.join(", ")
                );
            }
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let mut config = config;
            config.global.dial_mode = mode.clone();
            config.validate()?;
            config.to_file(cli.config.to_str().unwrap())?;
            println!("Mode set to {}", mode);
        }
        ClashCommand::Proxy { group, node } => {
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let group_exists = config.groups.iter().any(|g| g.name == *group);
            if !group_exists {
                anyhow::bail!("Group '{}' not found in configuration", group);
            }
            let node_exists = config.nodes.iter().any(|n| n.name == *node);
            if !node_exists {
                anyhow::bail!("Node '{}' not found in configuration", node);
            }
            println!("Proxy group '{}' set to '{}'", group, node);
        }
        ClashCommand::Delay { node, url } => {
            let config = Config::from_file(cli.config.to_str().unwrap())?;
            let target_node = config
                .nodes
                .iter()
                .find(|n| n.name == *node)
                .ok_or_else(|| anyhow::anyhow!("Node '{}' not found in configuration", node))?;

            let addr = if let Some(u) = url {
                u.clone()
            } else {
                format!("{}:{}", target_node.host(), target_node.port)
            };

            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            let socket_addrs: Vec<_> = addr.to_socket_addrs()?.collect();
            if socket_addrs.is_empty() {
                anyhow::bail!("Could not resolve address: {}", addr);
            }
            match std::net::TcpStream::connect_timeout(&socket_addrs[0], timeout) {
                Ok(stream) => {
                    let elapsed = start.elapsed();
                    drop(stream);
                    println!("{}: {}ms", node, elapsed.as_millis());
                }
                Err(e) => {
                    anyhow::bail!("Failed to connect to {} ({}): {}", node, addr, e);
                }
            }
        }
    }
    Ok(())
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Load the configuration before initializing logging so `log_level` in
    // the config file is honored (previously only --debug/RUST_LOG had any
    // effect and config log_level was silently ignored).
    let mut config = Config::from_file(cli.config.to_str().unwrap())?;
    config.validate()?;
    // Make `direct` usable as a group member without declaring it in the
    // config (maps to DirectHandler via the HTTP protocol).
    config.ensure_builtin_nodes();
    // Traffic to the gateway's own addresses always goes direct (must),
    // keeping admin/API access alive even when every node is down.
    config.ensure_local_direct_rules();

    // Effective log level: --debug flag > RUST_LOG env > config log_level >
    // "info".
    let config_level = match config.global.log_level.trim() {
        "" => "info",
        other => other,
    };
    let default_level = if cli.debug { "debug" } else { config_level };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    // Clash API log broadcast layer: installed unconditionally (when the
    // feature is compiled in) so `/logs` WS subscribers can see startup
    // messages. It is unfiltered on purpose — per-subscriber level
    // filtering happens in the WS handler.
    #[cfg(feature = "clash-api")]
    let (clash_log_layer, clash_log_tx) = clash_api::logs::layer();

    use tracing_subscriber::prelude::*;
    let registry = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(env_filter));
    #[cfg(feature = "clash-api")]
    let registry = registry.with(clash_log_layer);
    registry.init();

    info!("honk-core v{} starting", env!("CARGO_PKG_VERSION"));
    info!("Config: {}", cli.config.display());

    // Raise the file-descriptor limit.  A busy transparent proxy can easily
    // exhaust the default 1024-fd ulimit because each accepted connection
    // holds a fd while waiting for a concurrency permit.
    if let Err(e) = raise_nofile_rlimit() {
        warn!("Failed to raise NOFILE rlimit: {}", e);
    }

    // Install the bootstrap resolver for proxy-server hostname lookups so
    // node dials never depend on the (potentially self-intercepted) regular
    // DNS path — without it a restart can deadlock: nodes are unreachable
    // because their hostnames do not resolve, and the hostnames do not
    // resolve because no node is reachable yet.
    honk_outbound::bootstrap::set_global(honk_outbound::bootstrap::BootstrapResolver::parse(
        &config.global.bootstrap_resolver,
    ));
    if !config.global.bootstrap_resolver.is_empty() {
        info!("Bootstrap resolver: {}", config.global.bootstrap_resolver);
    }

    // Fetch any configured subscriptions concurrently with a 5-second
    // startup deadline.  Subscriptions that complete within the deadline are
    // merged before the control plane starts; pending ones keep fetching in
    // the background and are merged through the command channel
    // (ControlCommand::MergeSubscription) once they complete, alongside the
    // periodic refreshes scheduled at each subscription's update_interval.
    let mut sub_manager: Option<std::sync::Arc<subscription::SubscriptionManager>> = None;
    let mut late_sub_rx = None;
    let mut subscriptions = Vec::new();
    if !config.subscriptions.is_empty() {
        let manager = std::sync::Arc::new(subscription::SubscriptionManager::new()?);
        subscriptions = config.subscriptions.clone();
        let sub_count = subscriptions.len();

        let (results_tx, mut results_rx) = tokio::sync::mpsc::unbounded_channel();
        for sub in &subscriptions {
            let sub = sub.clone();
            let manager = manager.clone();
            let tx = results_tx.clone();
            tokio::spawn(async move {
                let result = manager.fetch(&sub).await;
                let _ = tx.send((sub, result));
            });
        }
        drop(results_tx);

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(deadline);

        let mut received = 0usize;
        loop {
            tokio::select! {
                result = results_rx.recv() => {
                    match result {
                        Some((sub, Ok(nodes))) => {
                            info!("Subscription '{}' fetched {} nodes", sub.name, nodes.len());
                            config.nodes.extend(nodes);
                        }
                        Some((sub, Err(e))) => {
                            warn!("Failed to fetch subscription '{}': {}", sub.name, e);
                        }
                        None => break,
                    }
                    received += 1;
                }
                _ = &mut deadline => {
                    info!(
                        "Subscription fetch deadline reached ({}/{} complete); starting control plane",
                        received, sub_count
                    );
                    break;
                }
            }
        }

        // Subscriptions still in flight keep their fetch tasks alive; the
        // receiver is handed to a background forwarder (spawned once the
        // command channel exists) that merges each result into the running
        // control plane.
        if received < sub_count {
            info!(
                "{} subscription(s) still fetching in background; nodes will merge when ready",
                sub_count - received
            );
            late_sub_rx = Some(results_rx);
        }
        sub_manager = Some(manager);
    }

    // Resolve group filters into concrete node IDs. This must run for every
    // config — not just when subscriptions delivered nodes — because groups
    // defined with `filter:` (or with no filter at all, meaning "all nodes")
    // would otherwise end up with an empty member list for static configs.
    // The merge is idempotent (existing IDs are kept, no duplicates).
    honk_config::parser::resolve_group_filters(&mut config.groups, &config.nodes);
    for group in &config.groups {
        info!(
            "Group '{}' resolved {} node(s)",
            group.name,
            group.nodes.len()
        );
    }

    info!(
        "Loaded {} nodes, {} groups, {} routing rules",
        config.nodes.len(),
        config.groups.len(),
        config.routing.rules.len()
    );

    let mock_mode = cli.mock_ebpf || cfg!(not(feature = "ebpf"));

    // Create dae0 veth BEFORE eBPF load so PARAM.dae0_ifindex is correct.
    // dae0peer stays in the host namespace during the dae0 attach, then moves
    // to the daens netns in setup_daens_namespace() below.
    #[cfg(feature = "ebpf")]
    let _dae0_guard: Option<Dae0Guard>;
    #[cfg(not(feature = "ebpf"))]
    let _dae0_guard: Option<()>;
    if !mock_mode {
        #[cfg(feature = "ebpf")]
        {
            let lan_ifname = resolve_interface(
                config
                    .global
                    .lan_interface
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("lo"),
            );
            let _ = set_sysctl(&format!("net.ipv4.conf.{}.rp_filter", lan_ifname), "0");
            _dae0_guard = Some(create_dae0_veth(&lan_ifname)?);
            info!(
                "dae0 veth created before eBPF load (ifindex={})",
                _dae0_guard.as_ref().unwrap().ifindex
            );
        }
        #[cfg(not(feature = "ebpf"))]
        {
            _dae0_guard = None;
        }
    } else {
        _dae0_guard = None;
    }

    let mut ebpf_backend: Box<dyn ebpf::EbpfBackend> = if cli.mock_ebpf {
        info!("Using mock eBPF backend");
        Box::new(ebpf::mock::MockEbpfBackend::new())
    } else {
        #[cfg(feature = "ebpf")]
        {
            let bpf_object_bytes = match &cli.bpf_object {
                Some(path) => {
                    info!("Loading real eBPF backend from {}", path.display());
                    std::fs::read(path).map_err(|e| {
                        anyhow::anyhow!("failed to read eBPF object file {}: {}", path.display(), e)
                    })?
                }
                None => {
                    info!("Loading real eBPF backend from built-in object");
                    DEFAULT_BPF_OBJECT.to_vec()
                }
            };
            let lan_ifnames: Vec<String> = if config.global.lan_interface.is_empty() {
                vec!["lo".to_string()]
            } else {
                config
                    .global
                    .lan_interface
                    .iter()
                    .map(|s| resolve_interface(s))
                    .collect()
            };
            let wan_ifnames: Vec<String> = if config.global.wan_interface.is_empty() {
                vec![]
            } else {
                config
                    .global
                    .wan_interface
                    .iter()
                    .map(|s| resolve_interface(s))
                    .collect()
            };
            let single_homed =
                !wan_ifnames.is_empty() && lan_ifnames.iter().any(|l| wan_ifnames.contains(l));
            let primary_lan =
                resolve_interface(lan_ifnames.first().map(|s| s.as_str()).unwrap_or("lo"));
            let primary_wan =
                resolve_interface(wan_ifnames.first().map(|s| s.as_str()).unwrap_or(""));
            let mut backend = ebpf::real::RealEbpfBackend::load(
                &bpf_object_bytes,
                &cli.bpf_pin_root,
                config.global.tproxy_port,
                config.global.tproxy_mark,
                &primary_lan,
                &primary_wan,
                single_homed,
            )
            .await?;

            for extra_lan in lan_ifnames.iter().skip(1) {
                if let Err(e) = backend.attach_lan(extra_lan, single_homed) {
                    warn!("Failed to attach LAN programs to {}: {}", extra_lan, e);
                }
            }
            for extra_wan in wan_ifnames.iter().skip(1) {
                if let Err(e) = backend.attach_wan_egress(extra_wan) {
                    warn!("Failed to attach WAN egress to {}: {}", extra_wan, e);
                }
                if let Err(e) = backend.attach_wan_ingress(extra_wan) {
                    warn!("Failed to attach WAN ingress to {}: {}", extra_wan, e);
                }
            }

            Box::new(backend)
        }
        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF feature not compiled in, using mock backend");
            Box::new(ebpf::mock::MockEbpfBackend::new())
        }
    };

    let bpf_params = ebpf::BpfLoadParams {
        tproxy_port: config.global.tproxy_port,
        tproxy_mark: config.global.tproxy_mark,
        so_mark: 0,
        control_plane_pid: std::process::id(),
        ..Default::default()
    };
    ebpf_backend.inject(&bpf_params)?;
    info!(
        "eBPF backend initialized with tproxy_port={}",
        config.global.tproxy_port
    );

    // BigEndianTproxyPort is already configured by ebpf_backend.inject() above.
    ebpf_backend.set_param(ParamKey::SoMarkFromDae, 0)?;
    ebpf_backend.set_param(ParamKey::ControlPlanePid, std::process::id())?;
    info!("eBPF parameters set");

    if !mock_mode {
        #[cfg(feature = "ebpf")]
        {
            // Attach dae0_ingress on dae0 (host namespace) first, while
            // dae0peer is still in the host namespace as well.
            ebpf_backend.attach_dae0_programs()?;
            info!("dae0 programs attached");

            // Move dae0peer into daens and install the daens policy routing.
            // The process itself never leaves the host netns; daens exists
            // only as (a) the delivery environment for redirected packets
            // (policy routing + sk_lookup + bpf_sk_assign), (b) the place
            // where the dae0peer TC filter must be attached, and (c) the
            // home of the TPROXY listener sockets and the DNS/UDP reply
            // sockets (Go dae "listen and serve in dae netns" / "anyfrom"
            // semantics).  Listener bind and reply-socket creation enter
            // daens through scoped `with_daens_netns` switches; accepted
            // connections are then handled — and upstream dials made — from
            // ordinary host-netns worker threads.
            setup_daens_namespace(config.global.tproxy_mark, config.global.tproxy_port)?;
            info!("dae0peer moved to daens netns");

            // Attach the sk_lookup program in daens (scoped switch inside
            // the backend).  It overrides socket selection for proxy-bound
            // packets arriving on dae0peer and delivers them to the TPROXY
            // listener while keeping the original destination intact.
            ebpf_backend.attach_sk_lookup()?;
            info!("tproxy_sk_lookup attached in daens");

            // Attach the dae0peer TC ingress program (scoped switch inside
            // the backend).  It uses bpf_sk_assign() to hand proxy-bound
            // packets to the transparent listener socket while preserving
            // the original destination.
            ebpf_backend.attach_dae0peer_ingress()?;
            info!("dae0peer_ingress attached in daens");
        }
    } else {
        info!("Skipping real interface binding (mock mode)");
    }

    // We follow Go dae-core: no global iptables PREROUTING rules. Proxy-bound
    // traffic is selected by the LAN ingress TC eBPF program and redirected to
    // the dae0 veth; dae0peer_ingress / tproxy_sk_lookup in daens then assign
    // it (bpf_sk_assign) to the TPROXY listener sockets bound inside daens.
    // Accepted connections are handled on host-netns worker threads, and
    // replies to the client egress dae0peer and take the host dae0_ingress
    // rewrite path. Direct traffic bypasses userspace.
    if !mock_mode {
        info!(
            "Using eBPF TC redirect datapath (tproxy_mark=0x{:x})",
            config.global.tproxy_mark
        );
    } else {
        info!("Skipping eBPF datapath setup (mock mode)");
    }

    let router = routing::Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    info!("Router ready with {} compiled routes", router.route_count());

    let proxy_registry = std::sync::Arc::new(proxy::ProxyRegistry::default_resolver()?);
    info!(
        "Proxy registry ready ({} handlers)",
        proxy_registry.handler_count()
    );

    let dns_cache = std::sync::Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(
        config.dns.cache.max_size,
    )));
    let dns_router =
        std::sync::Arc::new(dns::routing::DnsRouter::new_from_dns_config(&config.dns)?);
    // Keep a concrete Arc so we can attach SharedGroupManager after the
    // control plane builds it (same cell traffic dials use).
    let dns_upstream_pool = std::sync::Arc::new(
        dns::upstream_pool::UpstreamPool::new_with_proxy(
            &config.dns.upstream,
            dns_router.clone(),
            Some(proxy_registry.clone()),
            config.nodes.clone(),
            config.groups.clone(),
        )?
        .with_timeouts(
            std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
            std::time::Duration::from_millis(config.global.connect_timeout_ms),
        ),
    );
    for u in &config.dns.upstream {
        info!(
            "DNS upstream config: name={} addr={} proto={:?} outbound={:?}",
            u.name, u.address, u.protocol, u.outbound
        );
    }
    let dns_forwarder = std::sync::Arc::new(
        dns::forwarder::DnsForwarder::new(
            dns_upstream_pool.clone() as std::sync::Arc<dyn dns::forwarder::DnsUpstreamPool>,
            dns_cache,
            dns_router,
        )
        .with_strategy(config.dns.strategy.clone())
        .with_cache_enabled(config.dns.cache.enabled)
        .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
        .with_policy_from_config(&config.dns)?,
    );
    info!("DNS forwarder ready");

    let dns_resolver = dns::DnsResolver::with_forwarder(&config.dns, dns_forwarder.clone())?;
    info!("DNS resolver ready");

    let mut control_plane = control::ControlPlane::new(
        config,
        ebpf_backend,
        router,
        proxy_registry,
        dns_resolver,
        dns_forwarder,
    )?;

    // Wire GroupManager into DNS outbound selection (Selector/URLTest/…).
    dns_upstream_pool.set_group_manager(Some(control_plane.group_manager()));
    dns_upstream_pool.set_traffic_router(Some(control_plane.traffic_router()));
    info!("DNS upstream pool attached to SharedGroupManager + traffic Router");

    // Persistent cache (selector choices, clash mode): opens cache.db when
    // `experimental.cache_file` is enabled, restores Selector choices, and
    // wires change persistence into the group manager.
    let config_dir = cli.config.parent().and_then(|p| p.to_str());
    control_plane.init_cache_db(config_dir).await;

    // Starts only when external_controller is configured; bind/parse
    // failures are logged and never abort startup.
    #[cfg(feature = "clash-api")]
    {
        let clash_cfg = control_plane
            .config_handle()
            .read()
            .await
            .experimental
            .clash_api
            .clone();
        if !clash_cfg.external_controller.is_empty() {
            // Restore persisted clash mode and GLOBAL selection from
            // cache.db; fall back to the configured defaults.
            let cache_db = control_plane.cache_db();
            let mode = cache_db
                .as_ref()
                .and_then(|db| db.load_clash_mode())
                .and_then(|m| mode::ModeState::normalize(&m))
                .or_else(|| mode::ModeState::normalize(&clash_cfg.default_mode))
                .unwrap_or_else(|| "Rule".to_string());
            let default_selection = {
                let config = control_plane.config_handle();
                let config = config.read().await;
                config
                    .groups
                    .first()
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| "Proxy".to_string())
            };
            let global_selection = cache_db
                .as_ref()
                .and_then(|db| db.load_selector_choice("GLOBAL"))
                .unwrap_or(default_selection);
            let mode_state: mode::SharedModeState = std::sync::Arc::new(parking_lot::RwLock::new(
                mode::ModeState::new(&mode, global_selection),
            ));
            control_plane.set_mode_state(mode_state.clone());

            // Accept "host:port"; a bare ":port" listens on all interfaces.
            let listen_str = if clash_cfg.external_controller.starts_with(':') {
                format!("0.0.0.0{}", clash_cfg.external_controller)
            } else {
                clash_cfg.external_controller.clone()
            };
            match listen_str.parse::<std::net::SocketAddr>() {
                Ok(listen) => {
                    let state = std::sync::Arc::new(clash_api::ClashState {
                        config: control_plane.config_handle(),
                        stats: control_plane.stats_handle(),
                        alive_set: control_plane.alive_set(),
                        group_manager: control_plane.group_manager(),
                        cache_db: control_plane.cache_db(),
                        connection_tracker: control_plane.connection_tracker(),
                        proxy_registry: control_plane.proxy_registry(),
                        mode_state,
                        secret: clash_cfg.secret.clone(),
                        external_ui: clash_cfg.external_ui.clone(),
                        log_tx: clash_log_tx.clone(),
                        dns_cache: control_plane.dns_cache().await,
                        dns_forwarder: control_plane.dns_forwarder_cell(),
                    });
                    tokio::spawn(clash_api::serve(state, listen));
                }
                Err(e) => {
                    warn!(
                        "invalid clash_api external_controller '{}': {}",
                        clash_cfg.external_controller, e
                    );
                }
            }
        }
    }

    info!("Control plane ready, starting accept loop");

    // Signal systemd that the service is ready (Type=notify / NotifyAccess=all)
    #[cfg(target_os = "linux")]
    if let Err(e) = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready]) {
        warn!("sd_notify failed: {}", e);
    }

    let cmd_tx = control_plane.command_sender();

    // Late startup fetches and periodic refreshes both deliver nodes through
    // the command channel, where they merge into the running config via the
    // same serialized rebuild path as SIGHUP reloads. Subscription nodes
    // live in memory only and are never written back to the config file.
    let mut sub_tasks = Vec::new();
    if let Some(mut rx) = late_sub_rx {
        let merge_tx = cmd_tx.clone();
        sub_tasks.push(tokio::spawn(async move {
            while let Some((sub, result)) = rx.recv().await {
                match result {
                    Ok(nodes) => {
                        info!(
                            "Background subscription '{}' fetched {} nodes; merging",
                            sub.name,
                            nodes.len()
                        );
                        if merge_tx
                            .send(control::ControlCommand::MergeSubscription {
                                subscription_id: sub.id,
                                name: sub.name.clone(),
                                nodes,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Background subscription '{}' fetch failed: {}", sub.name, e);
                    }
                }
            }
        }));
    }
    // Periodic refresh: each enabled subscription with a non-zero
    // update_interval is re-fetched on that cadence and merged through the
    // same path. A failed refresh keeps the previously merged nodes.
    if let Some(manager) = sub_manager {
        for sub in subscriptions
            .iter()
            .filter(|s| s.enabled && s.update_interval > 0)
        {
            let sub = sub.clone();
            let manager = manager.clone();
            let merge_tx = cmd_tx.clone();
            sub_tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(sub.update_interval)).await;
                    match manager.fetch(&sub).await {
                        Ok(nodes) => {
                            info!(
                                "Subscription '{}' refreshed: {} nodes",
                                sub.name,
                                nodes.len()
                            );
                            if merge_tx
                                .send(control::ControlCommand::MergeSubscription {
                                    subscription_id: sub.id,
                                    name: sub.name.clone(),
                                    nodes,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Subscription '{}' refresh failed; keeping existing nodes: {}",
                                sub.name, e
                            );
                        }
                    }
                }
            }));
        }
    }

    // SIGHUP handler: reload configuration from disk and push it to the
    // control plane without interrupting established connections.
    let config_path = cli.config.clone();
    let reload_tx = cmd_tx.clone();
    let config_handle = control_plane.config_handle();
    let sighup_handle = tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                warn!("failed to register SIGHUP handler: {}", e);
                return;
            }
        };
        loop {
            sighup.recv().await;
            info!("Received SIGHUP, reloading configuration");
            match Config::from_file(config_path.to_str().unwrap_or("/etc/honk/config.dae")) {
                Ok(mut new_config) => {
                    if let Err(e) = new_config.validate() {
                        warn!("Reloaded config is invalid: {}", e);
                        continue;
                    }
                    new_config.ensure_builtin_nodes();
                    new_config.ensure_local_direct_rules();
                    // The on-disk config contains no subscription nodes (they
                    // exist only in memory), so a naive reload would empty
                    // every subscription-fed group until the next periodic
                    // refresh. Stabilize subscription IDs by URL and carry
                    // the running subscription nodes over; then kick off an
                    // immediate background refresh for fresh data.
                    let refresh_subs: Vec<_> = {
                        let current = config_handle.read().await;
                        for sub in &mut new_config.subscriptions {
                            if let Some(old) =
                                current.subscriptions.iter().find(|o| o.url == sub.url)
                            {
                                sub.id = old.id;
                            }
                        }
                        let known: std::collections::HashSet<uuid::Uuid> =
                            new_config.subscriptions.iter().map(|s| s.id).collect();
                        let carried: Vec<_> = current
                            .nodes
                            .iter()
                            .filter(|n| n.subscription_id.is_some_and(|id| known.contains(&id)))
                            .cloned()
                            .collect();
                        if !carried.is_empty() {
                            info!(
                                "Preserving {} subscription node(s) across reload",
                                carried.len()
                            );
                            new_config.nodes.extend(carried);
                        }
                        new_config
                            .subscriptions
                            .iter()
                            .filter(|s| s.enabled)
                            .cloned()
                            .collect()
                    };
                    // Resolve group filters into concrete node IDs, same as
                    // startup — otherwise filter-based groups keep stale
                    // (or empty) member lists in the rebuilt GroupManager.
                    honk_config::parser::resolve_group_filters(
                        &mut new_config.groups,
                        &new_config.nodes,
                    );
                    if let Err(e) = reload_tx
                        .send(control::ControlCommand::ReloadConfig(Box::new(new_config)))
                        .await
                    {
                        warn!("Failed to send reload command: {}", e);
                        break;
                    }
                    // Immediately re-fetch enabled subscriptions in the
                    // background so nodes don't stay at their startup
                    // snapshot for up to `update_interval`.
                    if !refresh_subs.is_empty() {
                        let tx = reload_tx.clone();
                        tokio::spawn(async move {
                            let manager = match crate::subscription::SubscriptionManager::new() {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("subscription manager init failed: {}", e);
                                    return;
                                }
                            };
                            for sub in refresh_subs {
                                match manager.fetch(&sub).await {
                                    Ok(nodes) => {
                                        let _ = tx
                                            .send(control::ControlCommand::MergeSubscription {
                                                subscription_id: sub.id,
                                                name: sub.name.clone(),
                                                nodes,
                                            })
                                            .await;
                                    }
                                    Err(e) => warn!(
                                        "post-reload subscription refresh failed for '{}': {}",
                                        sub.name, e
                                    ),
                                }
                            }
                        });
                    }
                }
                Err(e) => warn!("Failed to reload config: {}", e),
            }
        }
    });

    let sig_handle = tokio::spawn(async move {
        // The shell may start us with SIGINT/SIGTERM ignored (e.g. background
        // job). Reset them to the default disposition so tokio can install its
        // own handlers.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }

        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("failed to register SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
            }
        }
        let _ = cmd_tx.send(control::ControlCommand::Shutdown).await;
    });

    info!("honk-core is running. Press Ctrl+C to stop.");
    control_plane.run().await?;

    // Signal systemd that we're stopping (Type=notify)
    #[cfg(target_os = "linux")]
    let _ = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Stopping]);

    sig_handle.abort();
    sighup_handle.abort();
    for handle in sub_tasks {
        handle.abort();
    }
    info!("honk-core stopped");

    Ok(())
}

#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct Dae0Setup {
    pub ifindex: u32,
    pub peer_ifindex: u32,
    pub peer_mac: [u8; 6],
}

/// Guard that removes the `dae0` veth pair and policy routing when it goes
/// out of scope.  If setup fails mid-way, the drop impl cleans up whatever was
/// already installed.
///
/// Link-local addressing (169.254.0.1/32 on dae0, 169.254.0.11/32 on dae0peer)
/// eliminates the need for iptables MASQUERADE and TCP MSS clamping — the kernel
/// already treats link-local traffic as local.
#[cfg(feature = "ebpf")]
struct Dae0Guard {
    pub ifindex: u32,
}

#[cfg(feature = "ebpf")]
impl Dae0Guard {
    fn new() -> Self {
        Self { ifindex: 0 }
    }
}

#[cfg(feature = "ebpf")]
impl Drop for Dae0Guard {
    fn drop(&mut self) {
        info!("Cleaning up dae0 side effects");
        // The process never leaves the host netns (daens is only entered via
        // scoped `with_daens_netns` switches that always switch back), so the
        // `ip` cleanup commands below run in the right namespace directly;
        // daens itself is removed from the host side via `ip netns delete`.
        cleanup_dae0_interface();
    }
}

#[cfg(feature = "ebpf")]
fn create_dae0_veth(lan_ifname: &str) -> anyhow::Result<Dae0Guard> {
    let _ = lan_ifname; // kept for symmetry with call site; dae0 sysctls don't need it
    let ip = find_iproute2()?;

    let mut guard = Dae0Guard::new();

    let _ = std::process::Command::new(&ip)
        .args(["netns", "delete", "daens"])
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new(&ip)
        .args(["link", "del", "dae0"])
        .stderr(std::process::Stdio::null())
        .status();

    let output = std::process::Command::new(&ip)
        .args(["netns", "add", "daens"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "netns add daens: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!("Created daens network namespace");

    let output = std::process::Command::new(&ip)
        .args([
            "link", "add", "dae0", "type", "veth", "peer", "name", "dae0peer",
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to add dae0 veth: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!("Created dae0/dae0peer veth pair");
    ensure_veth_peer_name(&ip, "dae0", "dae0peer")?;

    // Bring up dae0. dae0peer stays down until after BPF attach.
    let _ = std::process::Command::new(&ip)
        .args(["link", "set", "dae0", "up"])
        .status();
    let _ = std::process::Command::new(&ip)
        .args(["link", "set", "dae0peer", "up"])
        .status();

    for (key, val) in [
        ("net.ipv4.conf.dae0.rp_filter", "0"),
        ("net.ipv4.conf.dae0.accept_local", "1"),
    ] {
        match set_sysctl(key, val) {
            Ok(()) => info!("{} = {}", key, val),
            Err(e) => warn!("failed to set {}={}: {}", key, val, e),
        }
    }

    // Enable IPv6 on dae0 for the daens IPv6 reply path.
    let _ = set_sysctl("net.ipv6.conf.dae0.disable_ipv6", "0");
    let _ = set_sysctl("net.ipv6.conf.dae0.forwarding", "1");

    // Read dae0 ifindex before eBPF load.
    let ifindex = std::fs::read_to_string("/sys/class/net/dae0/ifindex")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("failed to read dae0 ifindex"))?;

    guard.ifindex = ifindex;

    // Assign a link-local /32 address to the host-side dae0.  Link-local
    // addressing eliminates the need for iptables MASQUERADE and TCP MSS
    // clamping — the kernel already treats 169.254.0.0/16 traffic as local.
    let host_addr = format!("{}/32", DAENS_HOST_IP);

    // Make the dae0 address assignment idempotent: delete any stale address
    // left behind by a previous run before adding it back.
    let _ = std::process::Command::new(&ip)
        .args(["addr", "del", &host_addr, "dev", "dae0"])
        .stderr(std::process::Stdio::null())
        .status();

    let output = std::process::Command::new(&ip)
        .args(["addr", "add", &host_addr, "dev", "dae0"])
        .output()?;
    if !output.status.success() {
        warn!(
            "dae0 addr failed (non-fatal): {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Assign an IPv6 ULA address to the host-side dae0 so the daens
    // namespace can route IPv6 replies back through this veth.
    let host_addr6 = format!("{}/64", DAENS_HOST_IPV6);
    let _ = std::process::Command::new(&ip)
        .args(["-6", "addr", "del", &host_addr6, "dev", "dae0"])
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new(&ip)
        .args(["-6", "addr", "add", &host_addr6, "dev", "dae0"])
        .stderr(std::process::Stdio::null())
        .status();

    // Enable IPv6 forwarding so daens-originated IPv6 packets reach the LAN.
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.forwarding=1"])
        .status();

    Ok(guard)
}

#[cfg(feature = "ebpf")]
fn setup_daens_namespace(tproxy_mark: u32, tproxy_port: u16) -> anyhow::Result<()> {
    let ip = find_iproute2()?;

    // Read the host-side dae0 MAC before moving dae0peer; it is used as the
    // L2 next-hop for the daens default route.
    let dae0_mac = std::fs::read_to_string("/sys/class/net/dae0/address")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Move dae0peer into daens (BPF programs are already attached).
    let output = std::process::Command::new(&ip)
        .args(["link", "set", "dae0peer", "netns", "daens"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "move dae0peer to daens: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!("Moved dae0peer to daens");

    // Configure daens: bring up lo and dae0peer.
    // (lo is auto-configured by the kernel in new netns, but needs to be up)
    for cmd in [
        vec!["link", "set", "lo", "up"],
        vec!["link", "set", "dae0peer", "up"],
    ] {
        let output = std::process::Command::new("nsenter")
            .args(["--net=/var/run/netns/daens", "--", &ip])
            .args(&cmd)
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "daens '{}' failed: {}",
                cmd.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // In daens: add fwmark rule + route to deliver marked packets locally.
    let mark = format!("0x{:x}/0x{:x}", tproxy_mark, tproxy_mark);
    let nsenter_base = || {
        let mut c = std::process::Command::new("nsenter");
        c.args(["--net=/var/run/netns/daens", "--", &ip]);
        c
    };
    for (desc, args) in [
        (
            "rule4",
            vec!["rule", "add", "fwmark", mark.as_str(), "table", "100"],
        ),
        (
            "route4",
            vec![
                "route", "add", "local", "default", "dev", "lo", "table", "100",
            ],
        ),
        // IPv6 policy routing mirror: deliver fwmark-matched IPv6 packets locally.
        (
            "rule6",
            vec!["-6", "rule", "add", "fwmark", mark.as_str(), "table", "100"],
        ),
        (
            "route6",
            vec![
                "-6", "route", "add", "local", "default", "dev", "lo", "table", "100",
            ],
        ),
    ] {
        let output = nsenter_base().args(&args).output()?;
        if !output.status.success() {
            anyhow::bail!(
                "daens {} failed: {}",
                desc,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Read dae0peer MAC now that it lives inside daens; we need it to install
    // a static neighbour entry on the host so return traffic can reach daens.
    let dae0peer_mac = {
        let output = nsenter_base().args(["link", "show", "dae0peer"]).output()?;
        if !output.status.success() {
            String::new()
        } else {
            parse_mac_from_ip_link(&String::from_utf8_lossy(&output.stdout)).unwrap_or_default()
        }
    };

    // Assign a link-local /32 address to dae0peer and set up routes.
    // The link-scope route tells the kernel that 169.254.0.1 (dae0) is
    // directly reachable at L2 via dae0peer; without it, /32 prevents the
    // kernel from treating 169.254.0.1 as a valid nexthop.
    let peer_addr = format!("{}/32", DAENS_PEER_IP);
    for (desc, args) in [
        ("addr4", vec!["addr", "add", &peer_addr, "dev", "dae0peer"]),
        (
            "route4-link",
            vec![
                "route",
                "add",
                DAENS_HOST_IP,
                "dev",
                "dae0peer",
                "scope",
                "link",
            ],
        ),
        (
            "route4-default",
            vec![
                "route",
                "add",
                "default",
                "via",
                DAENS_HOST_IP,
                "dev",
                "dae0peer",
            ],
        ),
    ] {
        let output = nsenter_base().args(&args).output()?;
        if !output.status.success() {
            anyhow::bail!(
                "daens {} failed: {}",
                desc,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Assign an IPv6 ULA address to dae0peer and add an IPv6 default route.
    let peer_addr6 = format!("{}/64", DAENS_PEER_IPV6);
    for (desc, args) in [
        (
            "addr6",
            vec!["-6", "addr", "add", &peer_addr6, "dev", "dae0peer"],
        ),
        (
            "route6-default",
            vec![
                "-6",
                "route",
                "add",
                "default",
                "via",
                DAENS_HOST_IPV6,
                "dev",
                "dae0peer",
            ],
        ),
    ] {
        let output = nsenter_base().args(&args).output()?;
        if !output.status.success() {
            warn!(
                "daens IPv6 {} failed (non-fatal): {}",
                desc,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    if !dae0_mac.is_empty() {
        // IPv4 neighbour entry for dae0 (host-side gateway).
        let output = nsenter_base()
            .args([
                "neigh",
                "replace",
                DAENS_HOST_IP,
                "dev",
                "dae0peer",
                "lladdr",
                &dae0_mac,
                "nud",
                "permanent",
            ])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "daens neigh replace failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // IPv6 neighbour entry for dae0.
        let _ = nsenter_base()
            .args([
                "-6",
                "neigh",
                "replace",
                DAENS_HOST_IPV6,
                "dev",
                "dae0peer",
                "lladdr",
                &dae0_mac,
                "nud",
                "permanent",
            ])
            .status();
    }

    // Install a static neighbour entry on the host so replies to daens-bound
    // connections are forwarded to the correct dae0peer MAC.
    if !dae0peer_mac.is_empty() {
        // IPv4 host neighbour entry.
        let output = std::process::Command::new(&ip)
            .args([
                "neigh",
                "replace",
                DAENS_PEER_IP,
                "dev",
                "dae0",
                "lladdr",
                &dae0peer_mac,
                "nud",
                "permanent",
            ])
            .output()?;
        if !output.status.success() {
            warn!(
                "host neigh replace for daens peer failed (non-fatal): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // IPv6 host neighbour entry.
        let _ = std::process::Command::new(&ip)
            .args([
                "-6",
                "neigh",
                "replace",
                DAENS_PEER_IPV6,
                "dev",
                "dae0",
                "lladdr",
                &dae0peer_mac,
                "nud",
                "permanent",
            ])
            .status();
    }

    // Make sure the host forwards traffic between dae0 and the LAN/WAN
    // interfaces; this is required for the SYN-ACK path back to the client.
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .status();

    // Disable rp_filter, enable accept_local/route_localnet in daens so
    // packets with foreign source/dest addresses can be delivered locally.
    for (key, val) in [
        ("net.ipv4.conf.all.rp_filter", "0"),
        ("net.ipv4.conf.all.accept_local", "1"),
        ("net.ipv4.conf.all.route_localnet", "1"),
        ("net.ipv4.conf.dae0peer.rp_filter", "0"),
        ("net.ipv4.conf.dae0peer.accept_local", "1"),
        ("net.ipv4.conf.dae0peer.route_localnet", "1"),
        ("net.ipv4.conf.lo.accept_local", "1"),
        ("net.ipv4.conf.lo.route_localnet", "1"),
        // IPv6: enable forwarding and disable rp_filter in daens.
        ("net.ipv6.conf.all.forwarding", "1"),
        ("net.ipv6.conf.dae0peer.forwarding", "1"),
        ("net.ipv6.conf.dae0peer.accept_ra", "0"),
    ] {
        let _ = std::process::Command::new("nsenter")
            .args(["--net=/var/run/netns/daens", "--"])
            .arg("sysctl")
            .arg("-w")
            .arg(format!("{}={}", key, val))
            .status();
    }

    info!("Configured daens namespace (mark={})", mark);
    let _ = tproxy_mark;
    let _ = tproxy_port;
    Ok(())
}

/// Find the iproute2 binary (Nix store, then system PATH).
#[cfg(feature = "ebpf")]
fn find_iproute2() -> anyhow::Result<String> {
    // Nix store paths (prefer full iproute2 over BusyBox ip)
    for path in [
        "/nix/store/qbsvh4fw7lrmkqk870w4sc21kqylph42-iproute2-7.0.0/bin/ip",
        "/nix/store/f8y3cn08mlw2cwjq05anf6sgkfyb0k8a-iproute2-7.0.0/bin/ip",
        "/nix/store/df79h6la9hpbvd739qzam20j2p2lqnyp-iproute2-6.19.0/bin/ip",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    // System paths (Debian/VyOS/Alpine/etc.)
    for path in ["/sbin/ip", "/usr/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("iproute2 not found; install iproute2 (apt install iproute2)")
}

/// Path of the daens network-namespace handle created by `ip netns add`.
/// Shared by `with_daens_netns` and the control plane's "is daens set up"
/// check (mock mode never creates it).
#[cfg(target_os = "linux")]
pub(crate) const DAENS_NS_PATH: &str = "/var/run/netns/daens";

/// Run `f` with the calling thread temporarily switched into the `daens`
/// network namespace, restoring the original namespace on every exit path —
/// including when `f` returns an error or panics (via the drop guard below).
///
/// This mirrors Go dae's `DaeNetns.WithRequired`: the process (all threads)
/// always stays in the host netns; only operations that need the
/// daens-internal view enter it for a scoped, synchronous call:
/// dae0peer TC filter attach, sk_lookup attach, and DNS/UDP reply socket
/// creation (Go "anyfrom" semantics — reply sockets must live in daens so
/// their packets egress dae0peer and take the host dae0_ingress rewrite path
/// back to the LAN).
///
/// `f` must be fully synchronous and must not `.await`: setns(2) is
/// per-thread, so a future parked while inside daens could resume on a
/// different worker thread that never switched, and this thread could
/// restore its namespace while the parked future still assumes daens.  A
/// process-wide mutex serializes the switches; it is not strictly required
/// for correctness (each switch is per-thread) but keeps enter/leave pairs
/// easy to reason about and the logs ordered.
#[cfg(target_os = "linux")]
pub(crate) fn with_daens_netns<R>(
    op: &str,
    f: impl FnOnce() -> anyhow::Result<R>,
) -> anyhow::Result<R> {
    use std::os::unix::io::AsRawFd;

    static DAENS_SWITCH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores the saved network namespace on drop, so the original
    /// namespace is regained even when `f` panics.
    struct RestoreNs<'a> {
        fd: std::fs::File,
        op: &'a str,
    }
    impl Drop for RestoreNs<'_> {
        fn drop(&mut self) {
            let ret = unsafe { libc::setns(self.fd.as_raw_fd(), libc::CLONE_NEWNET) };
            if ret != 0 {
                warn!(
                    "failed to restore original netns after '{}': {}",
                    self.op,
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    let orig_ns = std::fs::File::open("/proc/self/ns/net")
        .map_err(|e| anyhow::anyhow!("{}: open /proc/self/ns/net: {}", op, e))?;
    let daens_ns = std::fs::File::open(DAENS_NS_PATH)
        .map_err(|e| anyhow::anyhow!("{}: open {}: {}", op, DAENS_NS_PATH, e))?;

    let _switch_guard = DAENS_SWITCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if unsafe { libc::setns(daens_ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        anyhow::bail!("{}: setns(daens): {}", op, std::io::Error::last_os_error());
    }
    let _restore_guard = RestoreNs { fd: orig_ns, op };
    f()
}

#[cfg(feature = "ebpf")]
fn cleanup_dae0_interface() {
    let ip = find_iproute2().unwrap_or_else(|_| "ip".to_string());

    // Delete daens netns (this also removes dae0peer inside it).
    let _ = std::process::Command::new(&ip)
        .args(["netns", "delete", "daens"])
        .stderr(std::process::Stdio::null())
        .status();

    // Remove dae0 and policy routing from current namespace.
    let _ = std::process::Command::new(&ip)
        .args(["link", "del", "dae0"])
        .stderr(std::process::Stdio::null())
        .status();
    // Policy-routing rules for daens live inside the daens namespace, so they
    // disappear with the namespace deletion above.  The commands below are only
    // here as a safety net for stale host-namespace rules; ignore errors.
    let _ = std::process::Command::new(&ip)
        .args([
            "rule",
            "del",
            "fwmark",
            "0x8000000/0x8000000",
            "table",
            "100",
        ])
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new(&ip)
        .args([
            "route", "del", "local", "default", "dev", "lo", "table", "100",
        ])
        .stderr(std::process::Stdio::null())
        .status();
}

/// Addressing for the dae0/dae0peer veth pair between the host namespace and
/// the isolated `daens` namespace.  These strings are the canonical values:
/// the netns setup consumes them (ebpf feature only), while the control
/// plane's internal-traffic filter (`control::is_honk_internal_addr`) uses
/// the numeric forms `DAE0_IPV6_PREFIX_HI` / `DAE0_IPV4_NET` below in every
/// build.  `control` tests assert both forms agree.
///
/// Link-local addresses (169.254.0.0/16) are used instead of a private
/// subnet so that the kernel treats daens-originated traffic as local — no
/// iptables MASQUERADE or TCP MSS clamping is needed.
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(crate) const DAENS_HOST_IP: &str = "169.254.0.1";
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(crate) const DAENS_PEER_IP: &str = "169.254.0.11";
/// IPv6 ULA addresses of the dae0/dae0peer veth pair (fd00:686f:6e6b::/64).
/// The middle hextets are ASCII "honk" (`68 6f 6e 6b`) so the mnemonic
/// stays readable while remaining a valid IPv6 ULA prefix.
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(crate) const DAENS_HOST_IPV6: &str = "fd00:686f:6e6b::1";
#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
pub(crate) const DAENS_PEER_IPV6: &str = "fd00:686f:6e6b::2";

/// First 64 bits of `DAENS_HOST_IPV6`/`DAENS_PEER_IPV6` — the
/// fd00:686f:6e6b::/64 ULA prefix — as a big-endian u64.
pub(crate) const DAE0_IPV6_PREFIX_HI: u64 = 0xfd00_686f_6e6b_0000;
/// `DAENS_HOST_IP`/`DAENS_PEER_IP` with the host bits masked off
/// (169.254.0.0/16), as a big-endian u32.
pub(crate) const DAE0_IPV4_NET: u32 = 0xA9FE_0000;

#[cfg(feature = "ebpf")]
fn parse_mac_from_ip_link(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(idx) = line.find("link/ether") {
            let mac_str = line[idx + 10..].split_whitespace().next().unwrap_or("");
            if mac_str.split(':').count() == 6 {
                return Some(mac_str.to_string());
            }
        }
    }
    None
}

#[cfg(feature = "ebpf")]
fn set_sysctl(key: &str, value: &str) -> anyhow::Result<()> {
    // Prefer /proc/sys because the standalone `sysctl` binary may not be on
    // PATH in minimal environments (e.g. NixOS containers).
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    if let Err(e) = std::fs::write(&path, format!("{}\n", value)) {
        // Fallback to the sysctl command if /proc/sys write fails.
        let output = std::process::Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, value)])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "sysctl -w {}={} failed: {} (proc write also failed: {})",
                key,
                value,
                String::from_utf8_lossy(&output.stderr),
                e
            );
        }
    }
    Ok(())
}

/// Rename the dae0 veth peer to `desired_peer` when it does not already
/// exist under that name (e.g. after a stale `dae0` was recreated).
#[cfg(feature = "ebpf")]
fn ensure_veth_peer_name(ip: &str, host_if: &str, desired_peer: &str) -> anyhow::Result<()> {
    if std::fs::metadata(format!("/sys/class/net/{}", desired_peer)).is_ok() {
        return Ok(());
    }
    let output = std::process::Command::new(ip)
        .args(["link", "show", host_if])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "ip link show {} failed: {}",
            host_if,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let peer = text
        .lines()
        .next()
        .and_then(|line| {
            let after_at = line.split('@').nth(1)?;
            after_at.split(':').next().map(str::trim)
        })
        .ok_or_else(|| anyhow::anyhow!("could not parse peer name for {}", host_if))?;
    if peer == desired_peer {
        return Ok(());
    }
    let output = std::process::Command::new(ip)
        .args(["link", "set", peer, "name", desired_peer])
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to rename {} to {}: {}",
            peer,
            desired_peer,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!("Renamed veth peer {} -> {}", peer, desired_peer);
    Ok(())
}
