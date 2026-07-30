//! Control plane: TPROXY accept loop, routing, proxy dial, relay, graceful shutdown.

mod connection;
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
    use tokio::sync::mpsc;

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
        Shutdown,
        GetStats(mpsc::Sender<super::StatsSnapshot>),
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
    /// Per-node runtime ownership (v3.1 phase 2A): the single owner of
    /// every outbound's session-layer resources, keyed by Node.id.
    runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
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
    datapath_healthy: Arc<std::sync::atomic::AtomicBool>,
    active_routing_plan: Arc<parking_lot::RwLock<Arc<routing_matcher::RoutingPushPlan>>>,
}

fn accepts_transparent_connection(drain: &DrainTracker) -> bool {
    !drain.should_reject()
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
        drop(dns_resolver);
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
            &config.dns,
        )?);
        let dns_upstream_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router,
                Some(Arc::clone(&proxy_registry)),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
            )?,
        );
        Self::new_with_upstream_pool(
            config,
            ebpf,
            router,
            proxy_registry,
            dns_forwarder,
            dns_upstream_pool,
        )
    }

    pub fn new_with_upstream_pool(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
        dns_upstream_pool: Arc<crate::dns::upstream_pool::UpstreamPool>,
    ) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel(256);

        // Create alive set for node health checking and pass it into the group
        // manager so dead nodes are excluded from group selection.
        // Mark probe sockets with DAE_BYPASS_MARK so the eBPF datapath does not
        // re-route the control plane's own health check traffic.
        let alive_set = Arc::new(
            crate::outbound::AliveDialerSet::new().with_so_mark(honk_ebpf_common::DAE_BYPASS_MARK),
        );
        // direct is probed against the bootstrap resolver rather than the
        // proxy check URL (which is unreachable over direct egress), so the
        // clash API gets a real direct latency too. The urltest (on-demand
        // delay) path shares the same target.
        let direct_target = direct_check_addr(&config.global.bootstrap_resolver);
        let direct_target_socket = direct_target.parse()?;
        alive_set.set_direct_check_addr(direct_target.clone());
        honk_outbound::urltest::set_urltest_direct_target(direct_target_socket);
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
        alive_set.sync_group_check_urls(&group_check_url_registrations(&config));
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
        // Custom-URL member resolution: a group's members are probed via
        // their current picks (delay_test_members = tag → representative
        // leaf), so sub-group members are measured through whatever leaf
        // they currently select, and the tag keeps the result. The cell
        // keeps working across reloads (the manager inside is swapped).
        let group_manager = group_manager.into_shared();
        // Per-node runtime registry (single owner of session-layer
        // resources, keyed by Node.id). Invalid node sets (nil/duplicate
        // UUIDs) are a fatal config error at startup.
        let runtime_registry =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes)
                .map_err(|e| anyhow::anyhow!("invalid node set: {}", e))?
                .into_shared();
        // Hand the registry to handlers with pooled sessions (AnyTLS);
        // the shared cell swaps contents on reload, installed once.
        proxy_registry.install_runtime_registry(runtime_registry.clone());
        {
            let gm_cell = group_manager.clone();
            alive_set.set_url_member_resolver(Some(Arc::new(move |group: &str| {
                gm_cell
                    .read()
                    .delay_test_members(group)
                    .into_iter()
                    .map(|(tag, node)| (tag, node.name))
                    .collect()
            })));
        }

        let pinned_router = Arc::new(Router::new(
            &config.routing.rules,
            &config.routing.default_outbound,
        )?);
        let pinned_groups = group_manager.read().clone();
        dns_upstream_pool.set_group_manager_snapshot(Arc::clone(&pinned_groups));
        dns_upstream_pool.set_traffic_router_snapshot(Arc::clone(&pinned_router));
        let policy_id = crate::dns::policy::PolicyId::from_config(&config.dns)?;
        let initial_routing_plan = Arc::new(Self::compile_routing_plan(&config, &router)?);
        let initial_push_result = initial_routing_plan.result();
        let persistence = crate::dns::runtime::ProcessPersistenceHandle::new(dns_forwarder.cache());
        let ebpf_arc = Arc::new(RwLock::new(ebpf));
        let router_arc = Arc::new(RwLock::new(router));
        let config_arc = Arc::new(RwLock::new(config));
        let initial_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation: crate::dns::runtime::RuntimeGeneration::new(0),
                forwarder: dns_forwarder.clone(),
                router: Arc::clone(&pinned_router),
                group_manager: pinned_groups,
                policy_id,
                routing_projection: Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
                    0,
                    pinned_router,
                    initial_push_result.domain_bitmaps,
                )),
                cache: dns_forwarder.cache(),
                persistence,
                transport: dns_upstream_pool,
            });
        let runtime_provider = Arc::new(crate::dns::runtime::DnsServiceProvider::new(
            initial_runtime,
        ));
        let dns_service = crate::dns::DnsService::with_provider(Arc::clone(&runtime_provider));
        let dns_resolver = Arc::new(DnsResolver::with_service(dns_service.clone()));

        let dns_controller = Arc::new(
            crate::control::dns_control::DnsController::new_with_service(
                dns_service,
                ebpf_arc.clone(),
            ),
        );
        // Health-check name resolution shares honk's own DNS forwarder
        // (routing / cache / serve-stale, and always the *current* forwarder
        // across reloads) instead of the raw system resolver; bootstrap DNS
        // stays for node hostnames and startup. The same hook backs the
        // urltest (clash delay) measurements.
        {
            let controller = dns_controller.clone();
            type HookFn = dyn Fn(
                    String,
                    u16,
                ) -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = Vec<std::net::SocketAddr>> + Send>,
                > + Send
                + Sync;
            let make_hook =
                move |controller: std::sync::Arc<crate::control::dns_control::DnsController>| {
                    let hook: Arc<HookFn> = Arc::new(move |host: String, port: u16| {
                        let controller = controller.clone();
                        Box::pin(async move {
                            controller
                                .resolve_domain(&host)
                                .await
                                .into_iter()
                                .map(|ip| std::net::SocketAddr::new(ip, port))
                                .collect()
                        })
                    });
                    hook
                };
            alive_set.set_resolver(make_hook(controller.clone()));
            honk_outbound::urltest::set_urltest_resolver(make_hook(controller));
        }

        let control_plane = Self {
            config: config_arc,
            ebpf: ebpf_arc,
            router: router_arc,
            proxy_registry,
            dns_resolver,
            dns_controller,
            group_manager,
            runtime_registry,
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
            datapath_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            active_routing_plan: Arc::new(parking_lot::RwLock::new(initial_routing_plan)),
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

        // Delay-history persistence (sing-box URLTest history storage
        // parity): restore the last real delay sample per node so URLTest
        // groups don't start cold after a restart, then mirror fresh
        // samples back every minute. Liveness is NOT restored — probes
        // re-decide that; stale entries (>24h) are dropped on load.
        {
            const DELAY_SAMPLE_MAX_AGE_SECS: u64 = 24 * 3600;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let samples = db.load_delay_samples(now_unix, DELAY_SAMPLE_MAX_AGE_SECS);
            let mut restored = 0usize;
            for (node, delay_ms, measured_at) in samples {
                self.alive_set.restore_latency(
                    &node,
                    std::time::Duration::from_millis(delay_ms),
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(measured_at),
                );
                restored += 1;
            }
            if restored > 0 {
                info!("cache.db: restored {} persisted delay sample(s)", restored);
            }
            let db_delay = db.clone();
            let alive_for_delay = self.alive_set.clone();
            let delay_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // first snapshot after one period
                loop {
                    for (node, latency, at) in alive_for_delay.latency_snapshot() {
                        let measured_at = at
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        db_delay.save_delay_sample(&node, latency.as_millis() as u64, measured_at);
                    }
                    interval.tick().await;
                }
            });
            self.background_tasks.lock().await.push(delay_task);
        }

        // store_dns: restore persisted DNS answers into the shared DNS
        // cache, then mirror future answers into cache.db through a
        // background batch writer (sing-box SaveDNSCacheAsync). Restoring
        // runs before the persister is installed so restored entries are
        // not immediately re-persisted.
        if cache_cfg.store_dns {
            let dns_cache = self.dns_controller.cache().await;
            let persister = crate::dns::persist::DnsCachePersister::spawn(db.clone());
            let policy = {
                let config = self.config.read().await;
                crate::dns::policy::PolicyId::from_config(&config.dns).ok()
            };
            match persister.restore_cache(&dns_cache, policy).await {
                Ok(restored) if restored > 0 => {
                    info!("cache.db: restored {} persisted DNS answer(s)", restored);
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "cache.db DNS restore failed"),
            }
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

    /// Shared backend cell, used by the interface watcher for dynamic attach.
    pub fn ebpf_handle(&self) -> Arc<RwLock<Box<dyn EbpfBackend>>> {
        self.ebpf.clone()
    }

    pub fn stats_handle(&self) -> Arc<StatsManager> {
        self.stats.clone()
    }

    /// Shared connection pool (bare TCP + ready streams) for the clash
    /// API's pool metrics.
    pub fn connection_pool(&self) -> Arc<ConnectionPool> {
        self.connection_pool.clone()
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

    /// Shared per-node runtime registry (session-layer ownership).
    pub fn runtime_registry(&self) -> honk_outbound::runtime::SharedRuntimeRegistry {
        self.runtime_registry.clone()
    }

    pub fn dns_service(&self) -> crate::dns::DnsService {
        self.dns_controller.dns_service()
    }

    pub fn command_sender(&self) -> mpsc::Sender<ControlCommand> {
        self.command_tx.clone()
    }

    pub fn is_datapath_healthy(&self) -> bool {
        self.datapath_healthy
            .load(std::sync::atomic::Ordering::Acquire)
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

        {
            let plan = self.active_routing_plan.read().clone();
            let mut ebpf = self.ebpf.write().await;
            match routing_matcher::RoutingMatcherBuilder::push_plan(ebpf.as_mut(), &plan) {
                Ok(_) => {
                    routing_matcher::RoutingMatcherBuilder::activate_projection(&plan);
                }
                Err(e) => {
                    warn!("Failed to push routing to eBPF (non-fatal): {}", e);
                }
            }
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
                    c.global.udp_check_dns.clone()
                };
                let dns_target = resolve_udp_check_target(
                    &dns_raw,
                    Some({
                        let controller = self.dns_controller.clone();
                        Arc::new(move |host: String, port: u16| {
                            let controller = controller.clone();
                            Box::pin(async move {
                                controller
                                    .resolve_domain(&host)
                                    .await
                                    .into_iter()
                                    .map(|ip| std::net::SocketAddr::new(ip, port))
                                    .collect()
                            })
                        })
                    }),
                )
                .await;
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
            // Connection-lifecycle hook: when a node flips alive→dead,
            // purge its pooled connections (bare + ready) and reap the UDP
            // endpoints bound to it — both would otherwise keep serving a
            // doomed node until their idle timeouts expire.
            {
                let pool = self.connection_pool.clone();
                let udp_pool = self.udp_pool.clone();
                let config_for_purge = self.config.clone();
                alive_set.set_death_callback(Some(Box::new(move |node_name: &str| {
                    udp_pool.remove_by_node(node_name);
                    let node_addr = config_for_purge.try_read().ok().and_then(|c| {
                        c.nodes
                            .iter()
                            .find(|n| n.name == node_name)
                            .map(|n| format!("{}:{}", n.host(), n.port))
                    });
                    if let Some(addr) = node_addr {
                        pool.purge_node(&addr);
                    }
                })));
            }
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
                            if !accepts_transparent_connection(&drain) {
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
                            if !accepts_transparent_connection(&drain) {
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
                            if !accepts_transparent_connection(&drain) { continue; }
                            // Fast path: the datagram belongs to an established
                            // endpoint — forward it inline from the receive
                            // buffer (no spawn, no heap copy, no sniffer).
                            if udp_fast_path(&self.udp_pool, &udp4_buf[..n], src_addr, original_dst).await {
                                continue;
                            }
                            let data = bytes::Bytes::copy_from_slice(&udp4_buf[..n]);
                            // At capacity, drop the datagram instead of
                            // queueing a task that waits on the semaphore —
                            // UDP tolerates loss; unbounded pending tasks do not.
                            let Ok(permit) = self.concurrency_limit.clone().try_acquire_owned()
                            else {
                                continue;
                            };
                            let handle = self.spawn_handle();
                            let sock = udp4_socket.clone();
                            let drain = drain.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
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
                            if !accepts_transparent_connection(&drain) { continue; }
                            // Fast path: the datagram belongs to an established
                            // endpoint — forward it inline from the receive
                            // buffer (no spawn, no heap copy, no sniffer).
                            if udp_fast_path(&self.udp_pool, &udp6_buf[..n], src_addr, original_dst).await {
                                continue;
                            }
                            let data = bytes::Bytes::copy_from_slice(&udp6_buf[..n]);
                            // Same as the v4 path: drop instead of queueing
                            // a pending task when at capacity.
                            let Ok(permit) = self.concurrency_limit.clone().try_acquire_owned()
                            else {
                                continue;
                            };
                            let handle = self.spawn_handle();
                            let sock = udp6_socket.clone().expect("udp6_socket present");
                            let drain = drain.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
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
                        Some(ControlCommand::GetStats(tx)) => {
                            let snap = self.stats.snapshot();
                            let total = snap.values().map(|s| s.total_conns as u64).sum();
                            let _ = tx.send(StatsSnapshot { per_outbound: snap, total_connections: total }).await;
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

        self.dns_controller.shutdown().await;
        let dns_cache = self.dns_controller.cache().await;
        let persistence = dns_cache.lock().await.persistence();
        if let Some(persistence) = persistence
            && let Err(error) = persistence.shutdown().await
        {
            warn!(%error, "DNS persistence shutdown failed");
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

    fn compile_routing_plan(
        config: &Config,
        router: &Router,
    ) -> anyhow::Result<routing_matcher::RoutingPushPlan> {
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
        routing_matcher::RoutingMatcherBuilder::compile(
            router.compiled_routes(),
            &outbound_name_to_id,
            fallback_outbound,
            dial_mode,
        )
    }
}

/// direct probe target: the configured `bootstrap_resolver` (scheme
/// stripped), falling back to the built-in default when unset/invalid.
/// The bootstrap resolver is a plain directly-reachable DNS server, which
/// is exactly what a direct-egress health probe should measure.
pub(crate) fn direct_check_addr(bootstrap_resolver: &str) -> String {
    let s = bootstrap_resolver.trim();
    let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    if s.parse::<std::net::SocketAddr>().is_ok() {
        s.to_string()
    } else {
        crate::outbound::DEFAULT_DIRECT_CHECK_ADDR.to_string()
    }
}
