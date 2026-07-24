//! Control plane: TPROXY accept loop, routing, proxy dial, relay, graceful shutdown.

pub mod bind;
mod connection;
pub mod core;
pub mod dns_control;
pub mod drain;
pub mod janitor;
pub mod packet_sniffer;
mod probers;
pub mod quic;
mod reload;
pub mod routing_matcher;
mod sockets;
pub mod tcp_sniff;
#[cfg(test)]
mod tests;
pub mod udp_endpoint;
use crate::connection_tracker::ConnectionTracker;
use crate::control::packet_sniffer::PacketSnifferPool;
use crate::control::routing_matcher::DOMAIN_BITMAPS;
use crate::control::udp_endpoint::UdpEndpointPool;
use crate::dns::DnsResolver;
use crate::ebpf::EbpfBackend;
use crate::ebpf::maps::cidr_to_lpm_key;
use crate::group::{GroupManager, SharedGroupManager};
use crate::pool::ConnectionPool;
use crate::proxy::ProxyRegistry;
use crate::relay;
use crate::routing::{ConnectionInfo, Router};
use crate::sniffing;
use crate::stats::StatsManager;
use drain::DrainTracker;
use honk_config::node::{Group, GroupPolicy};
use honk_config::{Config, node::Node, types::DialMode};
use honk_ebpf_common::*;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use janitor::BpfJanitor;
use socket2::{Domain, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};

use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, trace, warn};

pub mod commands {
    use honk_config::{Config, node::Node};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};

    #[derive(Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum ControlCommand {
        ReloadConfig(Box<Config>),
        /// Merge freshly fetched subscription nodes into the running config,
        /// replacing the previous node set of that subscription. Used by
        /// late startup fetches and periodic refreshes; subscription nodes
        /// live in memory only and are never written back to the config file.
        MergeSubscription {
            subscription_id: uuid::Uuid,
            name: String,
            nodes: Vec<Node>,
        },
        UpdateNode(Node),
        RemoveNode(String),
        Shutdown,
        GetStats(mpsc::Sender<super::StatsSnapshot>),

        /// Set the global dial_mode (rule / global / direct).
        SetMode(String),
        /// Set the selected node for a Selector group at runtime.
        SetSelectorChoice(String, String),
        /// Test per-node TCP connect latency.
        TestNodeDelay {
            name: String,
            url: Option<String>,
            reply: oneshot::Sender<Option<Duration>>,
        },
    }
}

pub use commands::ControlCommand;
use connection::*;
use probers::*;
use reload::*;
pub use sockets::DnsBpfNotifier;
use sockets::*;

#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub per_outbound: std::collections::HashMap<String, OutboundStats>,
    pub total_connections: u64,
}

/// The main control plane.
pub struct ControlPlane {
    config: Arc<RwLock<Config>>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    router: Arc<RwLock<Router>>,
    proxy_registry: Arc<ProxyRegistry>,
    dns_resolver: Arc<DnsResolver>,
    dns_controller: Arc<crate::control::dns_control::DnsController>,
    group_manager: SharedGroupManager,
    stats: Arc<StatsManager>,
    drain_tracker: Arc<DrainTracker>,
    udp_pool: Arc<UdpEndpointPool>,
    sniffer_pool: Arc<PacketSnifferPool>,
    tcp_sniff_neg_cache: Arc<crate::control::tcp_sniff::TcpSniffNegCache>,
    command_tx: mpsc::Sender<ControlCommand>,
    command_rx: Option<mpsc::Receiver<ControlCommand>>,
    alive_set: Arc<crate::outbound::AliveDialerSet>,
    connection_pool: Arc<ConnectionPool>,
    connection_tracker: Arc<ConnectionTracker>,
    /// Persistent cache (selector choices, clash mode); opened by `run()`
    /// via `init_cache_db` when `experimental.cache_file` is enabled.
    cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    /// Node name → eBPF outbound id (push_routing_to_ebpf numbering),
    /// shared with the alive set's outbound resolver; rebuilt on reload.
    outbound_id_map: Arc<parking_lot::RwLock<std::collections::HashMap<String, u8>>>,
    /// Concurrency limiter to prevent tokio thread starvation under high load.
    /// Default: 1024 concurrent connections. Each connection handler acquires a
    /// permit before spawning; the accept loop waits when the limit is reached.
    concurrency_limit: Arc<tokio::sync::Semaphore>,
    /// Background task handles (health check, janitor) for clean shutdown.
    background_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// Shared clash mode state (Rule/Global/Direct + GLOBAL selection),
    /// installed by `set_mode_state` when the clash API is enabled.
    mode_state: Option<crate::mode::SharedModeState>,
}

impl ControlPlane {
    pub fn new(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_resolver: DnsResolver,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(256);

        // Create alive set for node health checking and pass it into the group
        // manager so dead nodes are excluded from group selection.
        // Mark probe sockets with DAE_BYPASS_MARK so the eBPF datapath does not
        // re-route the control plane's own health check traffic.
        let alive_set = Arc::new(
            crate::outbound::AliveDialerSet::new().with_so_mark(honk_ebpf_common::DAE_BYPASS_MARK),
        );
        // Register health checks per the config's group membership; reload
        // re-runs the same sync via `reload_group_manager`.
        let (added, _) = sync_health_check_nodes(&alive_set, &config);
        info!(
            "Registered {}/{} nodes for health check ({} skipped: not in any group)",
            added,
            config.nodes.len(),
            config.nodes.len().saturating_sub(added),
        );
        // Register URLTest groups for idle-aware probe suspension (lazy
        // start: probing pauses after `idle_timeout` without group usage
        // and resumes on the next dial). Members shared with Selector
        // groups are excluded — those are probed unconditionally.
        alive_set.sync_urltest_groups(&urltest_group_registrations(&config));
        // Node name → eBPF outbound id for OUTBOUND_CONNECTIVITY_MAP pushes,
        // numbered exactly like push_routing_to_ebpf (group i → UserBase+i).
        // Rebuilt on config reload.
        let outbound_id_map = Arc::new(parking_lot::RwLock::new(build_outbound_id_map(&config)));
        {
            let map = outbound_id_map.clone();
            alive_set.set_outbound_resolver(Some(Arc::new(move |node_name: &str| {
                map.read().get(node_name).copied()
            })));
        }
        let group_manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));

        let ebpf_arc = Arc::new(RwLock::new(ebpf));
        let router_arc = Arc::new(RwLock::new(router));
        let config_arc = Arc::new(RwLock::new(config));

        let dns_controller = Arc::new(crate::control::dns_control::DnsController::new(
            dns_forwarder.clone(),
            ebpf_arc.clone(),
            router_arc.clone(),
        ));

        let control_plane = Self {
            config: config_arc,
            ebpf: ebpf_arc,
            router: router_arc,
            proxy_registry,
            dns_resolver: Arc::new(dns_resolver),
            dns_controller,
            group_manager: group_manager.into_shared(),
            stats: Arc::new(StatsManager::new()),
            drain_tracker: Arc::new(DrainTracker::new()),
            udp_pool: Arc::new(UdpEndpointPool::new()),
            sniffer_pool: Arc::new(PacketSnifferPool::new()),
            tcp_sniff_neg_cache: Arc::new(crate::control::tcp_sniff::TcpSniffNegCache::new()),
            command_tx: tx,
            command_rx: Some(rx),
            alive_set,
            connection_pool: Arc::new(ConnectionPool::new()),
            connection_tracker: Arc::new(ConnectionTracker::new()),
            cache_db: None,
            outbound_id_map,
            concurrency_limit: Arc::new(tokio::sync::Semaphore::new(1024)),
            background_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            mode_state: None,
        };

        // interrupt_connections: when a group's selected node changes, close
        // its tracked connections so they re-dial through the new node.
        install_interrupt_callback(
            &control_plane.group_manager.read(),
            &control_plane.group_manager,
            &control_plane.connection_tracker,
        );

        Ok(control_plane)
    }

    /// Open the persistent cache database (sing-box `cache_file`), wire
    /// selector-choice persistence into the group manager, and restore
    /// persisted choices. No-op when `experimental.cache_file` is disabled
    /// or the database cannot be opened. Called once from `run()`.
    pub async fn init_cache_db(&mut self, config_dir: Option<&str>) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(db) = crate::cachedb::CacheDb::open(&cache_cfg, config_dir) else {
            return;
        };
        let db = Arc::new(db);

        // Restore persisted selector choices before wiring the persist
        // callback so restoration does not rewrite the same values.
        {
            let config = self.config.read().await;
            for group in &config.groups {
                if group.policy == GroupPolicy::Selector
                    && let Some(node) = db.load_selector_choice(&group.name)
                {
                    info!("cache.db: restored selector '{}' = '{}'", group.name, node);
                    self.group_manager
                        .read()
                        .set_selector_choice(&group.name, &node);
                }
            }
        }

        let db_cb = db.clone();
        self.group_manager
            .read()
            .set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
            })));

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into cache.db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.store_dns {
            let dns_cache = self.dns_controller.cache().await;
            let restored = crate::dns::persist::restore_dns_cache(&db, &dns_cache).await;
            if restored > 0 {
                info!("cache.db: restored {} persisted DNS answer(s)", restored);
            }
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            dns_cache.lock().await.set_persister(Some(persister));
        }

        self.cache_db = Some(db);
    }

    /// Shared handle to the persistent cache database (clash API, etc.).
    pub fn cache_db(&self) -> Option<Arc<crate::cachedb::CacheDb>> {
        self.cache_db.clone()
    }

    /// Install the shared clash mode state (called by `run()` when the
    /// clash API is enabled). The outbound decision path applies the
    /// mode override through this handle.
    pub fn set_mode_state(&mut self, mode_state: crate::mode::SharedModeState) {
        self.mode_state = Some(mode_state);
    }

    pub fn config_handle(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }

    pub fn stats_handle(&self) -> Arc<StatsManager> {
        self.stats.clone()
    }

    pub fn alive_set(&self) -> Arc<crate::outbound::AliveDialerSet> {
        self.alive_set.clone()
    }

    pub fn group_manager(&self) -> SharedGroupManager {
        self.group_manager.clone()
    }

    /// Shared traffic router cell (same handle DNS dial uses for dae-style
    /// "route the DNS server IP" selection).
    pub fn traffic_router(&self) -> Arc<RwLock<Router>> {
        self.router.clone()
    }

    pub fn connection_tracker(&self) -> Arc<ConnectionTracker> {
        self.connection_tracker.clone()
    }

    pub fn proxy_registry(&self) -> Arc<ProxyRegistry> {
        self.proxy_registry.clone()
    }

    /// Shared handle to the DNS response cache (used by the clash API
    /// `/cache/dns/flush` endpoint).
    pub async fn dns_cache(&self) -> Arc<tokio::sync::Mutex<crate::dns::cache::DnsCache>> {
        self.dns_controller.cache().await
    }

    /// Shared handle to the DNS forwarder (used by the clash API
    /// `/dns/query` endpoint).
    pub async fn dns_forwarder(&self) -> crate::dns::forwarder::DnsForwarder {
        self.dns_controller.forwarder().await
    }

    pub fn command_sender(&self) -> mpsc::Sender<ControlCommand> {
        self.command_tx.clone()
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let config = self.config.read().await;
        let tproxy_port = config.global.tproxy_port;
        let tproxy_mark = config.global.tproxy_mark;
        drop(config);
        let tcp4_addr = SocketAddr::new("0.0.0.0".parse()?, tproxy_port);
        let tcp6_addr = SocketAddr::new("::".parse()?, tproxy_port);
        let udp4_addr = tcp4_addr;
        let udp6_addr = tcp6_addr;

        let tcp4_listener = bind_tproxy_tcp(tcp4_addr, tproxy_mark)?;
        info!("Control plane listening for TPROXY TCPv4 on {}", tcp4_addr);

        let tcp6_listener = match bind_tproxy_tcp(tcp6_addr, tproxy_mark) {
            Ok(l) => {
                info!("Control plane listening for TPROXY TCPv6 on {}", tcp6_addr);
                Some(l)
            }
            Err(e) => {
                warn!("TPROXY TCPv6 listener unavailable: {}", e);
                None
            }
        };

        let udp4_socket = Arc::new(bind_tproxy_udp(udp4_addr, tproxy_mark)?);
        info!("Control plane listening for TPROXY UDPv4 on {}", udp4_addr);

        let udp6_socket = match bind_tproxy_udp(udp6_addr, tproxy_mark) {
            Ok(s) => {
                info!("Control plane listening for TPROXY UDPv6 on {}", udp6_addr);
                Some(s)
            }
            Err(e) => {
                warn!("TPROXY UDPv6 listener unavailable: {}", e);
                None
            }
        };

        // Publish listener socket FDs into the eBPF listen_socket_map so TC
        // programs can bpf_sk_assign() proxy-bound packets directly to userspace.
        // Key mapping: 0=tcp4, 1=udp4, 2=tcp6, 3=udp6.
        {
            use std::os::unix::io::AsRawFd;
            let tcp4_fd = tcp4_listener.as_raw_fd();
            let tcp6_fd = tcp6_listener.as_ref().map_or(tcp4_fd, |l| l.as_raw_fd());
            let udp4_fd = udp4_socket.as_raw_fd();
            let udp6_fd = udp6_socket.as_ref().map_or(udp4_fd, |s| s.as_raw_fd());
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.publish_listener_sockets(tcp4_fd, tcp6_fd, udp4_fd, udp6_fd) {
                warn!("Failed to publish listener sockets to eBPF: {}", e);
            }
        }

        let tcp6_listener = tcp6_listener;
        let udp6_socket = udp6_socket.map(Arc::new);

        let routing_pushed = {
            let config = self.config.read().await;
            let router = self.router.read().await;
            let mut ebpf = self.ebpf.write().await;
            match Self::push_routing_to_ebpf(&config, &router, &mut ebpf) {
                Ok(_) => true,
                Err(e) => {
                    warn!("Failed to push routing to eBPF (non-fatal): {}", e);
                    false
                }
            }
        };
        if routing_pushed {
            // Rebuild learned domain→IP routes with the new rule bitmaps.
            // No-op on first start (nothing learned yet).
            self.dns_controller.rebuild_domain_routes().await;
        }

        {
            let mut tasks = self.background_tasks.lock().await;

            let janitor = BpfJanitor::new(self.ebpf.clone());
            tasks.push(janitor.spawn());
            info!("BPF map janitor started");

            // Retire conntrack entries as UDP endpoints die (event-driven
            // lifecycle; the datapath/janitor timeouts remain the backstop),
            // and drop the flow from the clash-API tracker.
            let (remove_tx, mut remove_rx) = tokio::sync::mpsc::unbounded_channel::<(
                std::net::SocketAddr,
                std::net::SocketAddr,
                Option<String>,
            )>();
            self.udp_pool.set_remove_sink(remove_tx);
            let ebpf = self.ebpf.clone();
            let tracker = self.connection_tracker.clone();
            tasks.push(tokio::spawn(async move {
                while let Some((client, dst, conn_id)) = remove_rx.recv().await {
                    if let Some(id) = conn_id {
                        tracker.remove(&id);
                    }
                    let fwd = crate::control::connection::build_tuples_key(
                        dst.ip(),
                        dst.port(),
                        client.ip(),
                        client.port(),
                        17, // UDP
                    );
                    let mut rev = fwd;
                    std::mem::swap(&mut rev.src_ip, &mut rev.dst_ip);
                    std::mem::swap(&mut rev.src_port, &mut rev.dst_port);
                    let mut ebpf = ebpf.write().await;
                    for key in [&fwd, &rev] {
                        if ebpf.udp_conn_state_remove(key).is_ok() {
                            crate::ebpf::USERSPACE_CONN_STATE_DELETES
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }));

            tasks.push(self.udp_pool.spawn_janitor());

            tasks.push(self.sniffer_pool.spawn_janitor());

            tasks.push(crate::control::tcp_sniff::spawn_sniff_neg_cache_janitor(
                self.tcp_sniff_neg_cache.clone(),
            ));

            tasks.push(crate::control::dns_control::spawn_dns_workers(
                &self.dns_controller,
            ));
        }

        {
            let alive_set = self.alive_set.clone();
            let interval_secs = {
                let c = self.config.read().await;
                c.global.check_interval_secs
            };
            let check_timeout = std::time::Duration::from_secs(5);

            {
                let c = self.config.read().await;
                honk_outbound::tls::set_tls_mode(&c.global.tls_implementation);
                honk_outbound::tls::set_utls_imitate(&c.global.utls_imitate);
            }

            // Configure HTTP-based health checks from config (Go: TcpCheckOption).
            {
                let c = self.config.read().await;
                let check_url = c.global.tcp_check_url.first().cloned().unwrap_or_default();
                let check_method = if c.global.tcp_check_http_method.is_empty() {
                    "HEAD".to_string()
                } else {
                    c.global.tcp_check_http_method.clone()
                };
                if !check_url.is_empty() {
                    let prober = Arc::new(ProxyHttpProber::new(
                        self.config.clone(),
                        self.proxy_registry.clone(),
                        check_url.clone(),
                        check_method.clone(),
                    ));
                    alive_set
                        .set_http_probe(prober, check_url, check_method)
                        .await;
                    info!(
                        "HTTP health check enabled (url={}, method={})",
                        c.global.tcp_check_url.first().unwrap_or(&String::new()),
                        c.global.tcp_check_http_method
                    );
                } else {
                    info!(
                        "HTTP health check disabled (no tcp_check_url configured), using TCP connect"
                    );
                }
            }

            // Configure UDP health checks (Go: UdpCheckOption): each probe
            // cycle sends one DNS query through the node's own UDP data
            // path, so nodes with working TCP but broken UDP (e.g. an
            // AnyTLS server without UoT) are marked dead for the UDP
            // domains and excluded from UDP selection.
            {
                let dns_raw = {
                    let c = self.config.read().await;
                    c.global.udp_check_dns.first().cloned()
                };
                let dns_target = resolve_udp_check_target(dns_raw).await;
                alive_set.set_udp_probe(Arc::new(ProxyUdpProber::new(
                    self.config.clone(),
                    self.proxy_registry.clone(),
                    dns_target,
                )));
                info!("UDP health check enabled (dns={})", dns_target);
            }

            info!(
                "Starting health check loop (interval={}s, timeout={}s)",
                interval_secs,
                check_timeout.as_secs()
            );
            let ebpf = self.ebpf.clone();
            let alive_for_push = alive_set.clone();
            let group_manager_for_push = self.group_manager.clone();
            let config_for_push = self.config.clone();
            alive_set.set_ebpf_callback(Box::new(move |outbound_idx, domain, ipver, _alive| {
                // The eBPF connectivity slot is shared by every node in the
                // group, so never write the transitioning node's own state:
                // one dead member would silently TC_ACT_SHOT the whole
                // group's new flows in the kernel datapath. Write the OR of
                // member states instead — the group is "alive" in eBPF iff
                // at least one member is alive for this domain/ipver.
                let probe_domain = match domain {
                    1 => ProbeDomain::DnsUdp,
                    2 => ProbeDomain::DataUdp,
                    _ => ProbeDomain::Tcp,
                };
                let ip_version = if ipver == 1 {
                    IpVersion::V6
                } else {
                    IpVersion::V4
                };
                // Group ids are OutboundIndex::UserBase + group index.
                let group_name = config_for_push.try_read().ok().and_then(|c| {
                    let idx = outbound_idx
                        .checked_sub(honk_ebpf_common::OutboundIndex::UserBase as u8)?;
                    c.groups.get(idx as usize).map(|g| g.name.clone())
                });
                let any_alive = match group_name {
                    Some(name) => {
                        let gm = group_manager_for_push.read().clone();
                        // Leaf expansion matters here: member tags may name
                        // nested sub-groups, which have no alive state of
                        // their own (`is_alive_for` defaults unknown names
                        // to alive) — only real leaf nodes carry health.
                        gm.leaf_node_names_in_group(&name)
                            .iter()
                            .any(|n| alive_for_push.is_alive_for(n, probe_domain, ip_version))
                    }
                    // Unknown outbound: keep the datapath open (userspace
                    // makes the final decision anyway).
                    None => true,
                };
                let ebpf = ebpf.clone();
                let _handle = tokio::spawn(async move {
                    if let Ok(mut backend) = ebpf.try_write() {
                        let _ = backend.set_outbound_alive(outbound_idx, domain, ipver, any_alive);
                    }
                });
            }));
            let period = std::time::Duration::from_secs(interval_secs);
            let handle = alive_set.spawn_health_check_loop(period, check_timeout);
            self.background_tasks.lock().await.push(handle);
            info!(
                "Outbound health check loop started (interval={}s)",
                interval_secs
            );
        }

        {
            let pool_handle = self.connection_pool.spawn_janitor();
            self.background_tasks.lock().await.push(pool_handle);
            info!("Connection pool janitor started");
        }

        // Pre-establish TCP connections to configured proxy nodes so the
        // first real connection hits a warm pool instead of paying the
        // full TCP+TLS+handshake RTT on the critical path.
        {
            let config = self.config.read().await;
            let count = config.global.preconnect_node_count as usize;
            let connect_timeout =
                std::time::Duration::from_millis(config.global.connect_timeout_ms);
            let effective_count = if count == 0 {
                config.nodes.len().min(8)
            } else {
                count.min(config.nodes.len())
            };
            let max_concurrent = if count == 0 { 4usize } else { count.min(8) };
            let nodes: Vec<_> = config.nodes.iter().take(effective_count).cloned().collect();
            drop(config);

            if !nodes.is_empty() {
                let node_count = nodes.len();
                let pool = self.connection_pool.clone();
                let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
                let handle = tokio::spawn(async move {
                    let mut set = tokio::task::JoinSet::new();
                    for node in nodes {
                        let addr = format!("{}:{}", node.host(), node.port);
                        let pool = pool.clone();
                        let sem = semaphore.clone();
                        set.spawn(async move {
                            let _permit = sem.acquire_owned().await;
                            match honk_outbound::util::connect_outbound(&addr, connect_timeout)
                                .await
                            {
                                Ok(stream) => {
                                    if is_tcp_stream_alive(&stream) {
                                        pool.deposit_tcp(&addr, stream).await;
                                        debug!(
                                            "Preconnect warmup: deposited connection to {}",
                                            addr
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!("Preconnect warmup to {} failed: {}", addr, e);
                                }
                            }
                        });
                    }
                    while set.join_next().await.is_some() {}
                });
                self.background_tasks.lock().await.push(handle);
                info!(
                    "Preconnect warmup started for {} nodes (max {} concurrent)",
                    node_count, max_concurrent
                );
            }
        }

        let mut rx = self.command_rx.take().expect("command_rx already taken");
        let drain = self.drain_tracker.clone();
        let ebpf = self.ebpf.clone();

        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut loop_count = 0u64;
        // Reuse UDP buffers across loop iterations to avoid 128KB alloc per iteration.
        let mut udp4_buf = vec![0u8; 65536];
        let mut udp6_buf = vec![0u8; 65536];
        loop {
            loop_count += 1;
            tokio::select! {
                _ = heartbeat.tick() => {
                    trace!(
                        "control plane heartbeat (iteration {}, active_connections={})",
                        loop_count,
                        drain.active_count()
                    );
                    continue;
                }
                accept_result = tcp4_listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            debug!("Accepted TPROXY TCPv4 connection from {}", addr);
                            if let Err(e) = set_so_mark_zero(stream.as_raw_fd()) {
                                warn!("Failed to clear SO_MARK on accepted socket from {}: {}", addr, e);
                            }
                            if drain.should_reject() {
                                debug!("Rejecting new connection from {} (draining)", addr);
                                continue;
                            }
                            // try_acquire: never blocks the accept loop.
                            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    // At capacity — drop the connection
                                    // immediately.  Holding the fd while
                                    // waiting on the semaphore would exhaust
                                    // the file-descriptor limit far faster
                                    // than the limit's headroom allows.
                                    debug!("Dropping TCPv4 from {} (at capacity)", addr);
                                    continue;
                                }
                            };
                            let handle = self.spawn_handle();
                            let drain = drain.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _guard = ConnectionGuard::new(drain);
                                if let Err(e) = handle.serve_connection(stream, addr).await {
                                    warn!("Error handling TCPv4 from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("TCPv4 accept error: {}", e);
                            // On EMFILE, back off briefly to avoid a tight
                            // spin that floods the log.
                            if e.raw_os_error() == Some(libc::EMFILE) {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }

                accept6_result = async {
                    if let Some(ref l) = tcp6_listener {
                        l.accept().await
                    } else {
                        std::future::pending::<io::Result<(TcpStream, SocketAddr)>>().await
                    }
                } => {
                    match accept6_result {
                        Ok((stream, addr)) => {
                            debug!("Accepted TPROXY TCPv6 connection from {}", addr);
                            if let Err(e) = set_so_mark_zero(stream.as_raw_fd()) {
                                warn!("Failed to clear SO_MARK on accepted socket from {}: {}", addr, e);
                            }
                            if drain.should_reject() {
                                debug!("Rejecting new connection from {} (draining)", addr);
                                continue;
                            }
                            let permit = match self.concurrency_limit.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!("Dropping TCPv6 from {} (at capacity)", addr);
                                    continue;
                                }
                            };
                            let handle = self.spawn_handle();
                            let drain = drain.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let _guard = ConnectionGuard::new(drain);
                                if let Err(e) = handle.serve_connection(stream, addr).await {
                                    warn!("Error handling TCPv6 from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("TCPv6 accept error: {}", e);
                            if e.raw_os_error() == Some(libc::EMFILE) {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }

                recv_result = recv_from_with_orig_dst(&udp4_socket, &mut udp4_buf) => {
                    match recv_result {
                        Ok((n, src_addr, original_dst)) => {
                            if drain.should_reject() { continue; }
                            // Fast path: the datagram belongs to an established
                            // endpoint — forward it inline from the receive
                            // buffer (no spawn, no heap copy, no sniffer).
                            if udp_fast_path(&self.udp_pool, &udp4_buf[..n], src_addr, original_dst).await {
                                continue;
                            }
                            let data = bytes::Bytes::copy_from_slice(&udp4_buf[..n]);
                            let permit = self.concurrency_limit.clone().try_acquire_owned();
                            let handle = self.spawn_handle();
                            let sock = udp4_socket.clone();
                            let drain = drain.clone();
                            let limit = self.concurrency_limit.clone();
                            tokio::spawn(async move {
                                let _permit = match permit {
                                    Ok(p) => Some(p),
                                    Err(_) => limit.acquire_owned().await.ok(),
                                };
                                let _guard = ConnectionGuard::new(drain);
                                if let Err(e) = handle.serve_udp_connection(sock, data, src_addr, original_dst).await {
                                    warn!("Error handling UDP from {} (orig {}): {}", src_addr, original_dst, e);
                                }
                            });
                        }
                        Err(e) => error!("UDP recv error: {}", e),
                    }
                }

                recv6_result = async {
                    if let Some(ref s) = udp6_socket {
                        recv_from_with_orig_dst(s, &mut udp6_buf).await
                    } else {
                        std::future::pending::<io::Result<(usize, SocketAddr, SocketAddr)>>().await
                    }
                } => {
                    match recv6_result {
                        Ok((n, src_addr, original_dst)) => {
                            if drain.should_reject() { continue; }
                            // Fast path: the datagram belongs to an established
                            // endpoint — forward it inline from the receive
                            // buffer (no spawn, no heap copy, no sniffer).
                            if udp_fast_path(&self.udp_pool, &udp6_buf[..n], src_addr, original_dst).await {
                                continue;
                            }
                            let data = bytes::Bytes::copy_from_slice(&udp6_buf[..n]);
                            let permit = self.concurrency_limit.clone().try_acquire_owned();
                            let handle = self.spawn_handle();
                            let sock = udp6_socket.clone().expect("udp6_socket present");
                            let drain = drain.clone();
                            let limit = self.concurrency_limit.clone();
                            tokio::spawn(async move {
                                let _permit = match permit {
                                    Ok(p) => Some(p),
                                    Err(_) => limit.acquire_owned().await.ok(),
                                };
                                let _guard = ConnectionGuard::new(drain);
                                if let Err(e) = handle.serve_udp_connection(sock, data, src_addr, original_dst).await {
                                    warn!("Error handling UDPv6 from {} (orig {}): {}", src_addr, original_dst, e);
                                }
                            });
                        }
                        Err(e) => error!("UDPv6 recv error: {}", e),
                    }
                }

                cmd = rx.recv() => {
                    match cmd {
                        Some(ControlCommand::ReloadConfig(new_config)) => {
                            info!("Reloading configuration — draining new connections briefly");
                            self.apply_runtime_config(*new_config, &drain).await;
                        }
                        Some(ControlCommand::MergeSubscription { subscription_id, name, nodes }) => {
                            info!(
                                "Merging {} node(s) from subscription '{}'",
                                nodes.len(),
                                name
                            );
                            let new_config = {
                                let current = self.config.read().await;
                                config_with_subscription_nodes(&current, subscription_id, nodes)
                            };
                            // Same serialized rebuild path as ReloadConfig —
                            // both commands queue on this single channel.
                            self.apply_runtime_config(new_config, &drain).await;
                        }
                        Some(ControlCommand::UpdateNode(node)) => {
                            info!("Updating node: {}", node.name);
                            let mut config = self.config.write().await;
                            if let Some(existing) = config.nodes.iter_mut().find(|n| n.id == node.id) {
                                *existing = node;
                            } else { config.nodes.push(node); }
                        }
                        Some(ControlCommand::RemoveNode(id)) => {
                            info!("Removing node: {}", id);
                            let mut config = self.config.write().await;
                            config.nodes.retain(|n| n.id.to_string() != id);
                        }
                        Some(ControlCommand::GetStats(tx)) => {
                            let snap = self.stats.snapshot();
                            let total = snap.values().map(|s| s.total_conns as u64).sum();
                            let _ = tx.send(StatsSnapshot { per_outbound: snap, total_connections: total }).await;
                        }
                        Some(ControlCommand::SetMode(mode)) => {
                            info!("Setting global dial_mode to '{}'", mode);
                            let mut config = self.config.write().await;
                            config.global.dial_mode = mode;
                        }
                        Some(ControlCommand::SetSelectorChoice(group, node)) => {
                            info!("Setting selector group '{}' to node '{}'", group, node);
                            self.group_manager
                                .read()
                                .set_selector_choice(&group, &node);
                        }
                        Some(ControlCommand::TestNodeDelay { name, url, reply }) => {
                            let latency = self.test_node_delay(&name, url.as_deref()).await;
                            let _ = reply.send(latency);
                        }
                        Some(ControlCommand::Shutdown) | None => {
                            info!("Control plane shutting down, draining {} active connections",
                                drain.active_count());
                            // Abort background tasks (health check, janitor, preconnect) to prevent
                            // tokio timer panic during runtime shutdown.
                            {
                                let mut tasks = self.background_tasks.lock().await;
                                for handle in tasks.drain(..) {
                                    handle.abort();
                                }
                            }
                            // Detach BPF hooks immediately to restore network connectivity
                            // before draining connections (matches Go dae behaviour).
                            let mut ebpf = ebpf.write().await;
                            if let Err(e) = ebpf.detach_hooks() {
                                warn!("Failed to detach BPF hooks: {}", e);
                            }
                            drop(ebpf);
                            drain.drain().await?;
                            break;
                        }
                    }
                }
            }
        }

        ebpf.write().await.cleanup().await?;
        info!("Control plane stopped");
        Ok(())
    }

    fn spawn_handle(&self) -> ControlPlaneHandle {
        ControlPlaneHandle {
            config: self.config.clone(),
            router: self.router.clone(),
            proxy_registry: self.proxy_registry.clone(),
            dns_resolver: self.dns_resolver.clone(),
            group_manager: self.group_manager.clone(),
            stats: self.stats.clone(),
            ebpf: self.ebpf.clone(),
            udp_pool: self.udp_pool.clone(),
            tcp_sniff_neg_cache: self.tcp_sniff_neg_cache.clone(),
            sniffer_pool: self.sniffer_pool.clone(),
            dns_controller: self.dns_controller.clone(),
            alive_set: self.alive_set.clone(),
            connection_pool: self.connection_pool.clone(),
            connection_tracker: self.connection_tracker.clone(),
            mode_state: self.mode_state.clone(),
        }
    }

    /// Push compiled routing rules to eBPF MatchSet arrays.
    fn push_routing_to_ebpf(
        config: &Config,
        router: &Router,
        ebpf: &mut Box<dyn EbpfBackend>,
    ) -> anyhow::Result<routing_matcher::RoutingPushResult> {
        let mut outbound_name_to_id = std::collections::HashMap::new();
        outbound_name_to_id.insert("direct".into(), OutboundIndex::Direct as u8);
        outbound_name_to_id.insert("block".into(), OutboundIndex::Block as u8);
        outbound_name_to_id.insert("must_rules".into(), OutboundIndex::MustRules as u8);
        for (i, group) in config.groups.iter().enumerate() {
            let id = OutboundIndex::UserBase as u8 + i as u8;
            outbound_name_to_id.insert(group.name.clone(), id);
        }

        let fallback_outbound = config.routing.default_outbound.as_str();
        let dial_mode = config
            .global
            .dial_mode
            .parse::<DialMode>()
            .ok()
            .unwrap_or(DialMode::DomainPlusPlus);
        let push_result = routing_matcher::RoutingMatcherBuilder::build_and_push(
            ebpf.as_mut(),
            router.compiled_routes(),
            &outbound_name_to_id,
            fallback_outbound,
            dial_mode,
        )?;

        info!(
            "eBPF routing rules pushed ({} rules, {} domain bitmaps)",
            router.route_count(),
            push_result.domain_bitmaps.len()
        );
        Ok(push_result)
    }

    /// Test TCP connect latency to a node using the node's configured address:port.
    /// Returns `Some(duration)` on success, `None` on failure.
    async fn test_node_delay(
        &self,
        node_name: &str,
        url: Option<&str>,
    ) -> Option<std::time::Duration> {
        let config = self.config.read().await;
        let node = config.nodes.iter().find(|n| n.name == node_name).cloned();
        let delay_timeout = std::time::Duration::from_millis(config.global.connect_timeout_ms);
        drop(config);

        let node = node?;
        let addr = if let Some(u) = url {
            u.to_string()
        } else {
            format!("{}:{}", node.host(), node.port)
        };

        let start = std::time::Instant::now();
        match tokio::time::timeout(delay_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let elapsed = start.elapsed();
                drop(stream);
                Some(elapsed)
            }
            _ => None,
        }
    }
}
