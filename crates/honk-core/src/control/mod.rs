//! Control plane: TPROXY accept loop, routing, proxy dial, relay, graceful shutdown.

mod bootstrap;
mod cache;
mod connection;
pub mod dns_control;
mod dns_listener;
pub mod drain;
pub mod janitor;
#[cfg(feature = "ebpf")]
pub(crate) mod nfqueue;
pub mod packet_sniffer;
mod preconnect;
mod probers;
pub mod quic;
pub(crate) mod reload;
mod reload_connectivity;
mod reload_policy;
mod reload_subscription;
#[cfg(test)]
mod reload_tests;
mod reload_warm;
mod resource_budget;
mod runtime;
mod shutdown;
use runtime::try_admit_udp_slow_path;
#[cfg(test)]
use runtime::{
    UdpDnsSlowPathContext, UdpLoopState, UdpSlowPathWork, begin_udp_slow_path,
    complete_udp_dns_slow_path, dispatch_udp_slow_path, reserve_udp_slow_path,
};
pub mod routing_matcher;
mod sockets;
pub mod tcp_sniff;
#[cfg(test)]
mod tests;
mod udp_dial;
pub mod udp_endpoint;
mod udp_removal;
use crate::connection_tracker::ConnectionTracker;
use crate::control::packet_sniffer::PacketSnifferPool;
use crate::control::routing_matcher::DOMAIN_BITMAPS;
use crate::control::udp_endpoint::{EndpointReservation, UdpEndpointPool, UdpInitLease};
use crate::dns::DnsResolver;
use crate::dns::query::{ValidatedDnsQuery, validate_exact_dns_query};
use crate::ebpf::EbpfBackend;
use crate::ebpf::maps::cidr_to_lpm_key;
use crate::group::{GroupManager, SharedGroupManager};
use crate::pool::{ConnectionPool, is_tcp_stream_alive};
use crate::proxy::ProxyRegistry;
use crate::relay;
use crate::routing::{ConnectionInfo, Router};
use crate::sniffing;
use crate::stats::StatsManager;
use bytes::Bytes;
use drain::DrainTracker;
#[cfg(feature = "ebpf")]
use futures::FutureExt;
use honk_config::node::{Group, GroupPolicy};
use honk_config::{
    Config,
    node::Node,
    types::{DialMode, NodeProtocol},
};
use honk_ebpf_common::*;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use janitor::BpfJanitor;
use socket2::{Domain, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;
#[cfg(feature = "ebpf")]
use std::time::Instant;
use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, trace, warn};
#[cfg(feature = "ebpf")]
const NFQUEUE_STATS_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "ebpf")]
const NFQUEUE_INGEST_QUEUE_LEN: usize = 256;
#[cfg(feature = "ebpf")]
const NFQUEUE_INGEST_BYTE_BUDGET: usize = 8 * 1024 * 1024;
#[cfg(feature = "ebpf")]
const NFQUEUE_TOKEN_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

#[cfg(feature = "ebpf")]
#[derive(Debug, Default)]
struct NfqueueTokenRetryBackoff {
    failures: usize,
}

#[cfg(feature = "ebpf")]
impl NfqueueTokenRetryBackoff {
    fn failed(&mut self) -> Duration {
        let delay =
            NFQUEUE_TOKEN_RETRY_DELAYS[self.failures.min(NFQUEUE_TOKEN_RETRY_DELAYS.len() - 1)];
        self.failures = self.failures.saturating_add(1);
        delay
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
struct NfqueueActorQueueEntry {
    received_at: Instant,
    payload_bytes: usize,
}

#[cfg(feature = "ebpf")]
#[derive(Debug, Default)]
struct NfqueueActorQueueState {
    entries: std::collections::VecDeque<NfqueueActorQueueEntry>,
    payload_bytes: usize,
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
struct NfqueueActorQueue {
    state: parking_lot::Mutex<NfqueueActorQueueState>,
    stats: Arc<StatsManager>,
    slow_limit: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "ebpf")]
impl NfqueueActorQueue {
    fn new(stats: Arc<StatsManager>, slow_limit: Arc<tokio::sync::Semaphore>) -> Self {
        Self {
            state: parking_lot::Mutex::new(NfqueueActorQueueState::default()),
            stats,
            slow_limit,
        }
    }

    fn try_enqueue(&self, received_at: Instant, payload_bytes: usize) -> bool {
        let mut state = self.state.lock();
        if state.entries.len() >= NFQUEUE_INGEST_QUEUE_LEN
            || state.payload_bytes.saturating_add(payload_bytes) > NFQUEUE_INGEST_BYTE_BUDGET
        {
            return false;
        }
        state.entries.push_back(NfqueueActorQueueEntry {
            received_at,
            payload_bytes,
        });
        state.payload_bytes += payload_bytes;
        self.publish(&state);
        true
    }

    fn dequeue(&self, payload_bytes: usize) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .pop_front()
            .expect("NFQUEUE actor queue accounting underflow");
        debug_assert_eq!(entry.payload_bytes, payload_bytes);
        state.payload_bytes = state.payload_bytes.saturating_sub(entry.payload_bytes);
        self.publish(&state);
        drop(state);
        Arc::clone(&self.slow_limit).try_acquire_owned().ok()
    }

    fn sample(&self) {
        self.publish(&self.state.lock());
    }

    fn publish(&self, state: &NfqueueActorQueueState) {
        self.stats.update_udp_nfqueue_actor_queue(
            state.entries.len(),
            state.payload_bytes,
            state
                .entries
                .front()
                .map_or(Duration::ZERO, |entry| entry.received_at.elapsed()),
        );
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug, thiserror::Error)]
enum NfqueueRuntimeFatal {
    #[error("NFQUEUE listener failed: {0}")]
    Listener(#[source] honk_nfqueue::FatalError),
    #[error("NFQUEUE listener fatal channel closed")]
    ListenerChannelClosed,
    #[error("{0}")]
    Pending(#[source] nfqueue::PendingUdpFatal),
    #[error("NFQUEUE pending fatal channel closed")]
    PendingChannelClosed,
    #[error("UDP decision token backstop failed: {0}")]
    TokenBackstop(String),
    #[error("NFQUEUE watchdog exited unexpectedly: {0}")]
    Watchdog(String),
    #[error("NFQUEUE ingest actor exited unexpectedly: {0}")]
    IngestActor(String),
    #[error("NFQUEUE stats sampler exited unexpectedly: {0}")]
    StatsSampler(String),
}

#[cfg_attr(not(feature = "ebpf"), allow(dead_code))]
enum NfqueueRuntimeEvent {
    Fatal(anyhow::Error),
    TokenExhausted,
}

#[cfg(feature = "ebpf")]
struct NfqueueRuntime {
    service: Option<honk_nfqueue::NfqueueService>,
    listener_fatal: honk_nfqueue::FatalReceiver,
    pending_fatal: mpsc::Receiver<nfqueue::PendingUdpFatal>,
    stats: Arc<StatsManager>,
    pending: Arc<nfqueue::PendingUdpVerdicts>,
    stop: tokio::sync::watch::Sender<bool>,
    watchdog: Option<tokio::task::JoinHandle<()>>,
    ingest_worker: Option<tokio::task::JoinHandle<()>>,
    stats_sampler: Option<tokio::task::JoinHandle<()>>,
    token_backstop: tokio::time::Interval,
    token_retry: NfqueueTokenRetryBackoff,
    sequence_ready: bool,
}

#[cfg(feature = "ebpf")]
impl NfqueueRuntime {
    async fn next_event(
        &mut self,
        ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    ) -> NfqueueRuntimeEvent {
        enum ExitedTask {
            Watchdog(Result<(), tokio::task::JoinError>),
            IngestActor(Result<(), tokio::task::JoinError>),
            StatsSampler(Result<(), tokio::task::JoinError>),
        }
        loop {
            let listener_fatal = &mut self.listener_fatal;
            let pending_fatal = &mut self.pending_fatal;
            let token_backstop = &mut self.token_backstop;
            let watchdog = self
                .watchdog
                .as_mut()
                .expect("NFQUEUE watchdog is retained until shutdown");
            let stats_sampler = self
                .stats_sampler
                .as_mut()
                .expect("NFQUEUE stats sampler is retained until shutdown");
            let ingest_worker = self
                .ingest_worker
                .as_mut()
                .expect("NFQUEUE ingest actor is retained until shutdown");
            let exited = tokio::select! {
                result = listener_fatal => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(match result {
                        Ok(error) => NfqueueRuntimeFatal::Listener(error),
                        Err(_) => NfqueueRuntimeFatal::ListenerChannelClosed,
                    }));
                }
                fatal = pending_fatal.recv() => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(
                        fatal
                            .map(NfqueueRuntimeFatal::Pending)
                            .unwrap_or(NfqueueRuntimeFatal::PendingChannelClosed),
                    ));
                }
                result = watchdog => Some(ExitedTask::Watchdog(result)),
                result = ingest_worker => Some(ExitedTask::IngestActor(result)),
                result = stats_sampler => Some(ExitedTask::StatsSampler(result)),
                _ = token_backstop.tick() => None,
            };
            // A resolved JoinHandle panics if awaited again; drop it so the
            // shutdown path skips the already-consumed task.
            if let Some(exited) = exited {
                let fatal = match exited {
                    ExitedTask::Watchdog(result) => {
                        self.watchdog.take();
                        NfqueueRuntimeFatal::Watchdog(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                    ExitedTask::IngestActor(result) => {
                        self.ingest_worker.take();
                        NfqueueRuntimeFatal::IngestActor(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                    ExitedTask::StatsSampler(result) => {
                        self.stats_sampler.take();
                        NfqueueRuntimeFatal::StatsSampler(match result {
                            Ok(()) => "completed".to_string(),
                            Err(error) => error.to_string(),
                        })
                    }
                };
                return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(fatal));
            }
            match ebpf.read().await.udp_decision_sequence_status() {
                Ok(status) if status.exhausted() => {
                    self.stats.record_udp_nfqueue_token_exhaustion();
                    return NfqueueRuntimeEvent::TokenExhausted;
                }
                Ok(_) => {}
                Err(error) => {
                    return NfqueueRuntimeEvent::Fatal(anyhow::Error::new(
                        NfqueueRuntimeFatal::TokenBackstop(error.to_string()),
                    ));
                }
            }
        }
    }
    async fn check_startup_health(&mut self) -> Result<(), NfqueueRuntimeFatal> {
        match self.listener_fatal.try_recv() {
            Ok(error) => return Err(NfqueueRuntimeFatal::Listener(error)),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                return Err(NfqueueRuntimeFatal::ListenerChannelClosed);
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }
        match self.pending_fatal.try_recv() {
            Ok(error) => return Err(NfqueueRuntimeFatal::Pending(error)),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(NfqueueRuntimeFatal::PendingChannelClosed);
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        if self
            .watchdog
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::Watchdog("completed".to_string()));
        }
        if self
            .stats_sampler
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::StatsSampler("completed".to_string()));
        }
        if self
            .ingest_worker
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return Err(NfqueueRuntimeFatal::IngestActor("completed".to_string()));
        }
        Ok(())
    }
    async fn begin_pending_drain(&self) {
        self.pending.cancel_all().await;
        self.pending.wait_empty().await;
    }

    async fn stop_observers(&mut self) -> anyhow::Result<()> {
        let _ = self.stop.send(true);
        if let Some(stats_sampler) = self.stats_sampler.take() {
            stats_sampler
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE stats sampler: {error}"))?;
        }
        if let Some(watchdog) = self.watchdog.take() {
            watchdog
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE watchdog: {error}"))?;
        }
        Ok(())
    }

    async fn finish_pending_drain(&mut self) -> anyhow::Result<()> {
        let observer_result = self.stop_observers().await;
        if let Some(worker) = self.ingest_worker.take() {
            worker
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE ingest actor: {error}"))?;
        }
        self.pending.cancel_all().await;
        self.pending.wait_empty().await;
        observer_result
    }

    async fn shutdown_service(&mut self) -> anyhow::Result<()> {
        let observer_result = self.stop_observers().await;
        let service_result = async {
            let service = self
                .service
                .take()
                .ok_or_else(|| anyhow::anyhow!("NFQUEUE service already stopped"))?;
            tokio::task::spawn_blocking(move || service.shutdown())
                .await
                .map_err(|error| anyhow::anyhow!("join NFQUEUE shutdown: {error}"))?
                .map_err(|error| anyhow::anyhow!("shutdown NFQUEUE: {error}"))
        }
        .await;
        observer_result?;
        service_result
    }
    async fn hard_rebind_service(&mut self) -> anyhow::Result<()> {
        self.check_startup_health()
            .await
            .map_err(anyhow::Error::new)?;
        let service = self
            .service
            .take()
            .ok_or_else(|| anyhow::anyhow!("NFQUEUE service already stopped"))?;
        let (service, listener_fatal) = tokio::task::spawn_blocking(move || service.rebind())
            .await
            .map_err(|error| anyhow::anyhow!("join NFQUEUE hard rebind: {error}"))?
            .map_err(|error| anyhow::anyhow!("hard rebind NFQUEUE: {error}"))?;
        let old_fatal = self.listener_fatal.try_recv().ok();
        self.service = Some(service);
        self.listener_fatal = listener_fatal;
        if let Some(error) = old_fatal {
            return Err(anyhow::Error::new(NfqueueRuntimeFatal::Listener(error)));
        }
        self.check_startup_health()
            .await
            .map_err(anyhow::Error::new)
    }

    fn take_shutdown_fatal(&mut self) -> Option<NfqueueRuntimeFatal> {
        if let Ok(error) = self.listener_fatal.try_recv() {
            return Some(NfqueueRuntimeFatal::Listener(error));
        }
        if let Ok(error) = self.pending_fatal.try_recv() {
            return Some(NfqueueRuntimeFatal::Pending(error));
        }
        None
    }

    fn defer_token_retry(&mut self) {
        self.token_backstop.reset_after(self.token_retry.failed());
    }

    fn reset_token_retry(&mut self) {
        self.token_retry.reset();
        self.token_backstop.reset_after(nfqueue::WATCHDOG_INTERVAL);
    }
}
#[cfg(feature = "ebpf")]
async fn wait_nfqueue_event(
    runtime: &mut Option<NfqueueRuntime>,
    ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
) -> NfqueueRuntimeEvent {
    let Some(runtime) = runtime.as_mut() else {
        return std::future::pending::<NfqueueRuntimeEvent>().await;
    };
    runtime.next_event(ebpf).await
}

#[cfg(not(feature = "ebpf"))]
async fn wait_nfqueue_event(
    _runtime: &mut (),
    _ebpf: &Arc<RwLock<Box<dyn EbpfBackend>>>,
) -> NfqueueRuntimeEvent {
    std::future::pending::<NfqueueRuntimeEvent>().await
}

mod commands;

pub use commands::ControlCommand;
use connection::*;
use probers::*;
use reload::*;
use reload_connectivity::{
    group_check_url_registrations, sync_health_check_nodes, urltest_group_registrations,
};
pub(crate) use resource_budget::{MAX_EFFECTIVE_NOFILE, ResourceBudget};
use sockets::*;

/// The main control plane.
pub struct ControlPlane {
    config: Arc<RwLock<Config>>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    router: Arc<RwLock<Router>>,
    proxy_registry: Arc<ProxyRegistry>,
    dns_resolver: Arc<DnsResolver>,
    dns_controller: Arc<crate::control::dns_control::DnsController>,
    group_manager: SharedGroupManager,
    /// Single owner of every outbound session runtime, keyed by Node.id.
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
    tcp_flow_pins: Arc<TcpFlowPins>,
    /// Persistent cache (selector choices, clash mode); opened by `run()`
    /// via `init_cache_db` when `experimental.cache_file` is enabled.
    cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    /// Node name → eBPF outbound id (push_routing_to_ebpf numbering),
    /// shared with the alive set's outbound resolver; rebuilt on reload.
    outbound_id_map: Arc<parking_lot::RwLock<std::collections::HashMap<uuid::Uuid, u8>>>,
    resource_budget: ResourceBudget,
    /// Active TCP flow admission. Each permit accounts for the accepted
    /// client socket and one outbound socket in the descriptor budget.
    concurrency_limit: Arc<tokio::sync::Semaphore>,
    /// Cold non-DNS UDP initialization budget. Ready endpoints bypass it.
    udp_concurrency_limit: Arc<tokio::sync::Semaphore>,
    /// Port-53 ingress budget, isolated from both TCP and generic UDP floods.
    dns_concurrency_limit: Arc<tokio::sync::Semaphore>,
    /// Background task handles (health check, janitor) for clean shutdown.
    background_tasks: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    /// The generation-owned UDP warm coordinator. It is deliberately kept
    /// separate from generic background tasks so reload/shutdown can abort
    /// and drain it in the required ownership order.
    udp_warm_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// UDP warm NodeIds survive task replacement so a reload can release
    /// retention that disappeared from the replacement plan.
    udp_warm_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Generation-owned task that pins every Selector's configured leaf.
    selector_warm_task: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Choice changes wake reconciliation immediately; a short periodic pass
    /// repairs sessions lost independently of group changes.
    selector_warm_notify: Arc<tokio::sync::Notify>,
    /// Desired selector NodeIds survive task replacement across reloads so
    /// reused runtimes can release choices that disappeared.
    selector_warm_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Bare-TCP pins are userspace-pool resources rather than NodeRuntime
    /// state, so their addresses are tracked separately for exact cleanup.
    selector_bare_warm: Arc<parking_lot::Mutex<std::collections::HashMap<uuid::Uuid, String>>>,
    /// Startup mode snapshot shared by routing decisions and serialized flags updates.
    mode_state: Option<crate::mode::SharedModeState>,
    /// Sole writer for mode state and DATAPATH_FLAGS_MAP publication.
    datapath_flags: Option<crate::mode::DatapathFlagsHandle>,
    #[cfg(feature = "ebpf")]
    pending_udp_verdicts: Option<Arc<nfqueue::PendingUdpVerdicts>>,
    datapath_healthy: Arc<std::sync::atomic::AtomicBool>,
    active_routing_plan: Arc<parking_lot::RwLock<Arc<routing_matcher::RoutingPushPlan>>>,
    /// Interface watcher, stopped and joined before `detach_hooks` during
    /// shutdown so it cannot re-attach hooks mid-drain.
    #[cfg(feature = "ebpf")]
    iface_watcher: Option<crate::ebpf::real::IfaceWatcher>,
}

pub(crate) use udp_removal::spawn_udp_removal_worker;

impl ControlPlane {
    /// Install the startup mode snapshot before the flags writer starts.
    pub fn set_mode_state(&mut self, mode_state: crate::mode::SharedModeState) {
        assert!(
            self.datapath_flags.is_none(),
            "mode state cannot be replaced after datapath flags startup"
        );
        self.mode_state = Some(mode_state);
    }

    /// Install the serialized flags writer after cache-backed mode restoration.
    pub fn start_datapath_flags_coordinator(&mut self) -> anyhow::Result<()> {
        if self.datapath_flags.is_some() {
            anyhow::bail!("datapath flags writer already started");
        }
        let mode_state = self
            .mode_state
            .clone()
            .ok_or_else(|| anyhow::anyhow!("mode state is not initialized"))?;
        self.datapath_flags = Some(crate::mode::DatapathFlagsHandle::new(
            Arc::clone(&self.ebpf),
            mode_state,
            self.cache_db.clone(),
        ));
        Ok(())
    }

    pub fn datapath_flags_handle(&self) -> Option<crate::mode::DatapathFlagsHandle> {
        self.datapath_flags.clone()
    }

    async fn initialize_datapath_flags(
        &self,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
    ) -> anyhow::Result<()> {
        let static_flags = {
            let config = self.config.read().await;
            let plan = self.active_routing_plan.read();
            direct_offload_static_bit(&config, &plan)
        };
        self.datapath_flags
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not running"))?
            .initialize(static_flags, nfqueue_enabled, nfqueue_ready)
            .await
    }

    pub fn config_handle(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }

    /// Shared backend cell, used by the interface watcher for dynamic attach.
    pub fn ebpf_handle(&self) -> Arc<RwLock<Box<dyn EbpfBackend>>> {
        self.ebpf.clone()
    }

    /// Hand the interface watcher to the control plane so shutdown can stop
    /// it before detaching hooks.
    #[cfg(feature = "ebpf")]
    pub fn set_iface_watcher(&mut self, watcher: Option<crate::ebpf::real::IfaceWatcher>) {
        self.iface_watcher = watcher;
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
    #[cfg(feature = "ebpf")]
    async fn rotate_udp_decision_generation(&self) -> anyhow::Result<bool> {
        let mut backend = self.ebpf.write().await;
        backend
            .verify_udp_decision_sequence()
            .map_err(|error| anyhow::anyhow!("verify UDP decision sequence: {error}"))?;
        let status = backend.udp_decision_sequence_status()?;
        if !status.exhausted() {
            return Ok(true);
        }
        backend.quiesce_udp_staging()?;
        for offset in 1..=UDP_DECISION_GENERATION_MASK + 1 {
            let generation = (status.generation + offset) & UDP_DECISION_GENERATION_MASK;
            if backend.reset_udp_decision_sequence(generation)? {
                self.stats.record_udp_nfqueue_token_rollover();
                info!(
                    generation,
                    "rotated exhausted UDP decision token generation"
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(feature = "ebpf")]
    async fn recover_nfqueue_token_exhaustion(
        &self,
        runtime: &mut NfqueueRuntime,
    ) -> anyhow::Result<()> {
        if runtime.sequence_ready {
            let flags = self
                .datapath_flags
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not initialized"))?;
            flags.fence_nfqueue().await?;
            runtime.sequence_ready = false;
            runtime.pending.cancel_all().await;
            runtime.pending.wait_empty().await;
            runtime.hard_rebind_service().await?;
            runtime.pending.cancel_all().await;
            runtime.pending.wait_empty().await;
        }
        if !self.rotate_udp_decision_generation().await? {
            runtime.defer_token_retry();
            warn!("all UDP decision token generations remain live; NFQUEUE staging stays fenced");
            return Ok(());
        }
        runtime
            .check_startup_health()
            .await
            .map_err(anyhow::Error::new)?;
        runtime.pending.open_admission();
        self.datapath_flags
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("datapath flags writer is not initialized"))?
            .reopen_nfqueue()
            .await?;
        runtime.sequence_ready = true;
        runtime.reset_token_retry();
        Ok(())
    }

    #[cfg(feature = "ebpf")]
    async fn start_nfqueue_runtime(
        &mut self,
        enabled: bool,
    ) -> anyhow::Result<Option<NfqueueRuntime>> {
        if !enabled {
            return Ok(None);
        }

        let sequence_ready = self.rotate_udp_decision_generation().await?;
        if !sequence_ready {
            self.stats.record_udp_nfqueue_token_exhaustion();
            warn!("all UDP decision token generations are live; starting with NFQUEUE fenced");
        }

        let (pending, pending_fatal) = nfqueue::PendingUdpVerdicts::new(
            Arc::clone(&self.ebpf),
            Arc::clone(&self.udp_pool),
            Arc::clone(&self.stats),
        );
        let pending = Arc::new(pending);
        self.pending_udp_verdicts = Some(Arc::clone(&pending));

        type IngestRequest = (honk_nfqueue::QueuedPacket, honk_nfqueue::VerdictGuard);
        let (ingest_tx, mut ingest_rx) = mpsc::channel::<IngestRequest>(NFQUEUE_INGEST_QUEUE_LEN);
        let slow_limit = Arc::clone(&self.udp_concurrency_limit);
        let actor_queue = Arc::new(NfqueueActorQueue::new(Arc::clone(&self.stats), slow_limit));
        let callback_pending = Arc::clone(&pending);
        let callback_queue = Arc::clone(&actor_queue);
        let callback: honk_nfqueue::PacketCallback = Arc::new(move |packet, guard| {
            let Ok(slot) = ingest_tx.try_reserve() else {
                callback_pending.reject_actor_queue(packet, guard);
                return;
            };
            if !callback_queue.try_enqueue(packet.received_at, packet.payload.len()) {
                callback_pending.reject_actor_queue(packet, guard);
                return;
            }
            slot.send((packet, guard));
        });
        let (service, listener_fatal) = match honk_nfqueue::NfqueueService::start(callback) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.pending_udp_verdicts = None;
                return Err(anyhow::anyhow!("start UDP NFQUEUE service: {error}"));
            }
        };
        let actor_pending = Arc::clone(&pending);
        let initializer = self.spawn_handle();
        let drain = Arc::clone(&self.drain_tracker);
        let ingest_queue = Arc::clone(&actor_queue);
        let ingest_worker = tokio::spawn(async move {
            while let Some((packet, guard)) = ingest_rx.recv().await {
                let permit = ingest_queue.dequeue(packet.payload.len());
                let nfqueue::NfqueueIngest::Initialize { lease, identity } =
                    actor_pending.ingest_wait(packet, guard, permit).await
                else {
                    continue;
                };
                let initializer = initializer.clone();
                let pending = Arc::clone(&actor_pending);
                let drain = Arc::clone(&drain);
                tokio::spawn(async move {
                    let _guard = ConnectionGuard::new(drain);
                    match std::panic::AssertUnwindSafe(initializer.serve_udp_connection(lease))
                        .catch_unwind()
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            warn!(%error, "NFQUEUE UDP initializer failed");
                            let _ = pending.cancel(identity).await;
                        }
                        Err(_) => {
                            error!("NFQUEUE UDP initializer panicked");
                            let _ = pending.cancel(identity).await;
                        }
                    }
                });
            }
        });
        let (stop, stop_receiver) = tokio::sync::watch::channel(false);
        let watchdog = tokio::spawn(Arc::clone(&pending).run_watchdog(stop_receiver));
        let stats_reader = service.stats_reader();
        let sampler_stats = Arc::clone(&self.stats);
        let sampler_queue = Arc::clone(&actor_queue);
        let mut sampler_stop = stop.subscribe();
        let stats_sampler = tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + NFQUEUE_STATS_INTERVAL,
                NFQUEUE_STATS_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut unavailable = false;
            loop {
                tokio::select! {
                    changed = sampler_stop.changed() => {
                        if changed.is_err() || *sampler_stop.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        sampler_queue.sample();
                        sampler_stats.update_udp_nfqueue_local_stats(stats_reader.local_stats());
                        match stats_reader.stats().await {
                            Ok(sample) => {
                                if unavailable {
                                    info!("NFQUEUE kernel statistics are available again");
                                }
                                unavailable = false;
                                sampler_stats.update_udp_nfqueue_service_stats(sample);
                            }
                            Err(error) => {
                                sampler_stats.record_udp_nfqueue_service_stats_error();
                                if !unavailable {
                                    warn!(%error, "NFQUEUE kernel statistics are unavailable");
                                }
                                unavailable = true;
                            }
                        }
                    }
                }
            }
        });
        let mut token_retry = NfqueueTokenRetryBackoff::default();
        let first_token_check = if sequence_ready {
            nfqueue::WATCHDOG_INTERVAL
        } else {
            token_retry.failed()
        };
        let mut token_backstop = tokio::time::interval_at(
            tokio::time::Instant::now() + first_token_check,
            nfqueue::WATCHDOG_INTERVAL,
        );
        token_backstop.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Ok(Some(NfqueueRuntime {
            service: Some(service),
            listener_fatal,
            pending_fatal,
            stats: Arc::clone(&self.stats),
            pending,
            stop,
            watchdog: Some(watchdog),
            ingest_worker: Some(ingest_worker),
            stats_sampler: Some(stats_sampler),
            token_backstop,
            token_retry,
            sequence_ready,
        }))
    }
}

/// The static half of the datapath offload policy: non-`must` direct
/// offload needs no SNI re-evaluation when `dial_mode: ip` or the routing
/// config contains no domain-class rule at all.
fn direct_offload_static_bit(config: &Config, plan: &routing_matcher::RoutingPushPlan) -> u32 {
    let dial_mode = config
        .global
        .dial_mode
        .parse::<DialMode>()
        .ok()
        .unwrap_or(DialMode::DomainPlusPlus);
    if dial_mode == DialMode::Ip || !plan.has_domain_rules {
        honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES
    } else {
        0
    }
}

impl ControlPlane {
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

pub(super) use preconnect::preconnect_candidates;
