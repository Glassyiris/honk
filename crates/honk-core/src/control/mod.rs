//! Control plane: TPROXY accept loop, routing, proxy dial, relay, graceful shutdown.

mod connection;
pub mod dns_control;
mod dns_listener;
pub mod drain;
pub mod janitor;
#[cfg(feature = "ebpf")]
pub(crate) mod nfqueue;
pub mod packet_sniffer;
mod probers;
pub mod quic;
pub(crate) mod reload;
mod resource_budget;
pub mod routing_matcher;
mod sockets;
pub mod tcp_sniff;
#[cfg(test)]
mod tests;
mod udp_dial;
pub mod udp_endpoint;
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

/// Bound for shutdown stages that have no natural deadline (watcher join,
/// runtime-generation retirement, DNS controller/persistence close). The
/// datapath hooks are already detached by then, so a hung stage must time
/// out and log rather than leave the process half-torn-down forever.
const SHUTDOWN_STAGE_TIMEOUT: Duration = Duration::from_secs(10);

pub mod commands {
    use honk_config::{Config, node::Node};

    #[derive(Debug)]
    #[allow(clippy::large_enum_variant)]
    pub enum ControlCommand {
        ReloadConfig {
            request_id: u64,
            config: Box<Config>,
        },
        /// Merge freshly fetched subscription nodes into the running config,
        /// replacing the previous node set of that subscription. Used by
        /// late startup fetches and periodic refreshes; subscription nodes
        /// live in memory only and are never written back to the config file.
        MergeSubscription {
            subscription_id: uuid::Uuid,
            name: String,
            nodes: Vec<Node>,
        },
        /// Refresh generated gateway-address rules and bypass stale health
        /// backoff after a link, address, route, or interface-role change.
        NetworkChanged,
        Shutdown,
    }
}

pub use commands::ControlCommand;
use connection::*;
use probers::*;
use reload::*;
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

fn accepts_transparent_connection(drain: &DrainTracker) -> bool {
    !drain.should_reject()
}

/// Retire an endpoint only through its token-bound backend incarnation, then
/// acknowledge the exact pool tombstone while preserving kernel handoffs.
pub(crate) fn spawn_udp_removal_worker(
    udp_pool: Arc<UdpEndpointPool>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
) -> tokio::task::JoinHandle<()> {
    use crate::control::udp_endpoint::RemovalReason;
    const UDP_REMOVAL_QUEUE_CAPACITY: usize = 1024;
    const UDP_REMOVAL_BATCH_SIZE: usize = 128;
    let (remove_tx, mut remove_rx) = tokio::sync::mpsc::channel::<
        crate::control::udp_endpoint::EndpointRemoval,
    >(UDP_REMOVAL_QUEUE_CAPACITY);
    udp_pool.set_remove_sink(remove_tx);
    tokio::spawn(async move {
        let mut removals = Vec::with_capacity(UDP_REMOVAL_BATCH_SIZE);
        while let Some(first) = remove_rx.recv().await {
            removals.clear();
            removals.push(first);
            while removals.len() < UDP_REMOVAL_BATCH_SIZE {
                match remove_rx.try_recv() {
                    Ok(removal) => removals.push(removal),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            let mut backend = ebpf.write().await;
            for removal in removals.drain(..) {
                if let Some(id) = removal.conn_id.as_deref() {
                    tracker.remove(id);
                }
                let backend_clean = if removal.reason == RemovalReason::UserspaceEndpointRetired {
                    let key = crate::control::connection::build_tuples_key(
                        removal.dst.ip(),
                        removal.dst.port(),
                        removal.client.ip(),
                        removal.client.port(),
                        17,
                    );
                    match backend.remove_udp_flow(&key, removal.decision_token) {
                        Ok(crate::ebpf::UdpDecisionCommitResult::Applied)
                        | Ok(crate::ebpf::UdpDecisionCommitResult::Missing)
                        | Ok(crate::ebpf::UdpDecisionCommitResult::Superseded) => true,
                        Ok(result) => {
                            warn!(
                                ?result,
                                token = removal.decision_token,
                                generation = removal.generation,
                                "UDP retirement identity mismatch; retaining tombstone and signaling fatal"
                            );
                            let _ = fatal_tx.send(anyhow::anyhow!(
                                "UDP retirement identity mismatch: result={result:?}, token={}, generation={}",
                                removal.decision_token,
                                removal.generation
                            ));
                            false
                        }
                        Err(error) => {
                            error!(
                                %error,
                                token = removal.decision_token,
                                generation = removal.generation,
                                "token-bound UDP retirement failed; retaining tombstone and signaling fatal"
                            );
                            let _ = fatal_tx.send(anyhow::anyhow!(
                                "token-bound UDP retirement failed: {error}; token={}, generation={}",
                                removal.decision_token,
                                removal.generation
                            ));
                            false
                        }
                    }
                } else {
                    true
                };
                if backend_clean
                    && !udp_pool.complete_removal(
                        removal.client,
                        removal.dst,
                        removal.decision_token,
                        removal.generation,
                    )
                {
                    debug!(
                        token = removal.decision_token,
                        generation = removal.generation,
                        "ignored stale UDP retirement acknowledgement"
                    );
                }
            }
            drop(backend);
            udp_pool.flush_removal_dirty();
        }
    })
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
                config.dns.strategy.clone(),
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
        Self::new_with_upstream_pool_and_budget(
            config,
            ebpf,
            router,
            proxy_registry,
            dns_forwarder,
            dns_upstream_pool,
            ResourceBudget::for_nofile(MAX_EFFECTIVE_NOFILE),
        )
    }

    pub(crate) fn new_with_upstream_pool_and_budget(
        config: Config,
        ebpf: Box<dyn EbpfBackend>,
        router: Router,
        proxy_registry: std::sync::Arc<ProxyRegistry>,
        dns_forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
        dns_upstream_pool: Arc<crate::dns::upstream_pool::UpstreamPool>,
        resource_budget: ResourceBudget,
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
        // NodeId → eBPF outbound id for OUTBOUND_CONNECTIVITY_MAP pushes,
        // numbered exactly like push_routing_to_ebpf (group i → UserBase+i).
        // Rebuilt on config reload.
        let outbound_id_map = Arc::new(parking_lot::RwLock::new(build_outbound_id_map(&config)));
        {
            let map = outbound_id_map.clone();
            alive_set.set_outbound_resolver(Some(Arc::new(move |node_id: uuid::Uuid| {
                map.read().get(&node_id).copied()
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
        let dial_limit = resource_budget.clamp_dials(config.global.max_concurrent_dials);
        let (runtime_registry, _) =
            honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &config.nodes,
                dial_limit,
                resource_budget.transient_dials,
                None,
            )
            .map_err(|e| anyhow::anyhow!("invalid node set: {}", e))?;
        let runtime_registry = runtime_registry.into_shared();
        info!(
            nofile = resource_budget.effective_nofile,
            fixed = resource_budget.fixed_reserve,
            tcp_flows = resource_budget.active_tcp_flows,
            tcp_pool = resource_budget.tcp_pool_entries,
            dials = dial_limit,
            dial_ceiling = resource_budget.transient_dials,
            udp_endpoints = resource_budget.udp_endpoints,
            udp_slow = resource_budget.udp_slow_path,
            dns_slow = resource_budget.dns_slow_path,
            "Control-plane descriptor budget"
        );
        let outbound_runtime = runtime_registry.read().clone();
        dns_upstream_pool.set_runtime_generation(Arc::clone(&outbound_runtime))?;
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
        let initial_routing_plan = Arc::new(Self::compile_routing_plan(&config, &router)?);
        let initial_push_result = initial_routing_plan.result();
        let ebpf_arc = Arc::new(RwLock::new(ebpf));
        let router_arc = Arc::new(RwLock::new(router));
        let config_arc = Arc::new(RwLock::new(config));
        let initial_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation: crate::dns::runtime::RuntimeGeneration::new(0),
                forwarder: dns_forwarder.clone(),
                routing_projection: Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
                    0,
                    pinned_router,
                    initial_push_result.domain_bitmaps,
                )),
                outbound_runtime: Some(outbound_runtime),
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
            udp_pool: Arc::new(UdpEndpointPool::with_capacity_limit(
                resource_budget.udp_endpoints,
            )),
            sniffer_pool: Arc::new(PacketSnifferPool::new()),
            tcp_sniff_neg_cache: Arc::new(crate::control::tcp_sniff::TcpSniffNegCache::new()),
            command_tx: tx,
            command_rx: Some(rx),
            alive_set,
            connection_pool: Arc::new(ConnectionPool::with_capacity_limit(
                resource_budget.tcp_pool_entries,
            )),
            connection_tracker: Arc::new(ConnectionTracker::new()),
            tcp_flow_pins: Arc::new(TcpFlowPins::default()),
            cache_db: None,
            outbound_id_map,
            resource_budget,
            concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                resource_budget.active_tcp_flows,
            )),
            udp_concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                resource_budget.udp_slow_path,
            )),
            dns_concurrency_limit: Arc::new(tokio::sync::Semaphore::new(
                resource_budget.dns_slow_path,
            )),
            background_tasks: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            udp_warm_task: tokio::sync::Mutex::new(None),
            udp_warm_ids: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            selector_warm_task: tokio::sync::Mutex::new(None),
            selector_warm_notify: Arc::new(tokio::sync::Notify::new()),
            selector_warm_ids: Arc::new(parking_lot::Mutex::new(std::collections::HashSet::new())),
            selector_bare_warm: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            mode_state: None,
            datapath_flags: None,
            #[cfg(feature = "ebpf")]
            pending_udp_verdicts: None,
            datapath_healthy: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            active_routing_plan: Arc::new(parking_lot::RwLock::new(initial_routing_plan)),
            #[cfg(feature = "ebpf")]
            iface_watcher: None,
        };

        // interrupt_connections: when a group's selected node changes, close
        // its tracked connections so they re-dial through the new node.
        install_interrupt_callback(
            &control_plane.group_manager.read(),
            &control_plane.group_manager,
            &control_plane.connection_tracker,
        );
        install_selector_warm_callback(
            &control_plane.group_manager.read(),
            &control_plane.selector_warm_notify,
        );
        // Node death may race an initializer before the listener/background
        // loops start, so this production lifecycle callback belongs to
        // ControlPlane construction rather than `run()` setup.
        control_plane.install_node_death_callback();

        Ok(control_plane)
    }

    /// Reap node-bound UDP entries as soon as a real AliveDialerSet transition
    /// reports death. Installing this at construction covers blocked dials and
    /// driver-ready work before `run()` has created listener tasks.
    fn install_node_death_callback(&self) {
        let pool = self.connection_pool.clone();
        let udp_pool = self.udp_pool.clone();
        let config_for_purge = self.config.clone();
        self.alive_set.set_death_callback(Some(Box::new(
            move |node_id: uuid::Uuid, _name: &str| {
                udp_pool.remove_by_node(node_id);
                let node_addr = config_for_purge.try_read().ok().and_then(|c| {
                    c.nodes
                        .iter()
                        .find(|n| n.id == node_id)
                        .map(|n| format!("{}:{}", n.host(), n.port))
                });
                if let Some(addr) = node_addr {
                    pool.purge_node(&addr);
                }
            },
        )));
    }

    /// Open the persistent cache database (sing-box `cache_file`), wire
    /// selector-choice persistence into the group manager, and restore
    /// persisted choices. An existing cache relative to the original config
    /// directory is retained during the data-directory cutover. No-op when
    /// `experimental.cache_file` is disabled or the database cannot be opened.
    /// Called once from `run()`.
    pub async fn init_cache_db(&mut self, legacy_config_dir: Option<&Path>) {
        let cache_cfg = self.config.read().await.experimental.cache_file.clone();
        let Some(db) = crate::cachedb::CacheDb::open_with_config_dir(&cache_cfg, legacy_config_dir)
        else {
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
            // cache.db keys delay samples by node name (format unchanged);
            // resolve them onto this generation's NodeIds — samples for
            // nodes no longer configured are dropped.
            let id_by_name: std::collections::HashMap<String, uuid::Uuid> = {
                let config = self.config.read().await;
                config
                    .nodes
                    .iter()
                    .map(|n| (n.name.clone(), n.id))
                    .collect()
            };
            let mut restored = 0usize;
            for (node, delay_ms, measured_at) in samples {
                let Some(node_id) = id_by_name.get(node.as_str()).copied() else {
                    continue;
                };
                self.alive_set.restore_latency(
                    node_id,
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
            let config_for_delay = self.config.clone();
            let delay_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                interval.tick().await; // first snapshot after one period
                loop {
                    let names: std::collections::HashMap<uuid::Uuid, String> = config_for_delay
                        .read()
                        .await
                        .nodes
                        .iter()
                        .map(|n| (n.id, n.name.clone()))
                        .collect();
                    for (node_id, latency, at) in alive_for_delay.latency_snapshot() {
                        let Some(name) = names.get(&node_id) else {
                            continue;
                        };
                        let measured_at = at
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        db_delay.save_delay_sample(name, latency.as_millis() as u64, measured_at);
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
    #[cfg(feature = "ebpf")]
    async fn cleanup_nfqueue_startup_failure(&mut self, runtime: &mut Option<NfqueueRuntime>) {
        let Some(runtime) = runtime.as_mut() else {
            return;
        };
        runtime.begin_pending_drain().await;
        if let Err(error) = runtime.shutdown_service().await {
            error!(%error, "failed to stop NFQUEUE after startup failure");
        }
        if let Err(error) = runtime.finish_pending_drain().await {
            error!(%error, "failed to drain NFQUEUE after startup failure");
        }
        self.pending_udp_verdicts = None;
    }

    async fn cleanup_flags_startup_failure(&mut self) {
        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.disable().await
        {
            error!(%error, "datapath flags startup cleanup failed");
        }
    }
    async fn cleanup_pre_admission_failure(&mut self) {
        self.drain_tracker.start_rejecting();
        self.cleanup_flags_startup_failure().await;
        {
            let mut tasks = self.background_tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        }
        if let Err(error) = self.ebpf.write().await.detach_hooks() {
            error!(%error, "failed to detach eBPF hooks after startup failure");
        }
        if let Err(error) = self.finalize_shutdown().await {
            error!(%error, "failed to finalize startup rollback");
        }
    }
    async fn cleanup_started_control_tasks(
        &mut self,
        udp_removal_task: &mut tokio::task::JoinHandle<()>,
        dns_listener: Option<&mut dns_listener::DnsListener>,
    ) {
        if let Some(listener) = dns_listener {
            listener.stop_accepting();
            listener.abort_and_join().await;
        }
        if !self.udp_pool.shutdown().await {
            error!("UDP endpoint shutdown required forced cleanup during startup rollback");
        }
        if let Err(error) = udp_removal_task.await {
            error!(%error, "UDP removal worker failed during startup rollback");
        }
        self.cleanup_pre_admission_failure().await;
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let config = self.config.read().await;
        let tproxy_port = config.global.tproxy_port;
        let tproxy_mark = config.global.tproxy_mark;
        let udp_nfqueue_enabled = config.experimental.udp_nfqueue.enabled;
        let dns_bind_endpoint = config
            .dns
            .bind_endpoint()
            .map_err(|error| anyhow::anyhow!("invalid dns.bind: {error}"))?;
        drop(config);
        let bound_dns_listener = dns_bind_endpoint
            .as_ref()
            .map(dns_listener::BoundDnsListener::bind)
            .transpose()
            .map_err(|error| anyhow::anyhow!("bind dns.bind listener: {error}"))?;
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

        // Parallel UDP listeners: the eBPF datapath hashes each flow's tuple
        // into one of UDP_LISTENER_COUNT sockets per family (sk_lookup.rs);
        // each socket gets its own receive loop task below, so flows drain
        // in parallel across runtime workers.
        const UDP_LISTENER_COUNT: usize = 4;
        let udp4_sockets: Vec<Arc<UdpSocket>> =
            bind_tproxy_udp_listeners(udp4_addr, UDP_LISTENER_COUNT)?
                .into_iter()
                .map(Arc::new)
                .collect();
        info!(
            "Control plane listening for TPROXY UDPv4 x{} on {}",
            udp4_sockets.len(),
            udp4_addr
        );

        let udp6_sockets: Vec<Arc<UdpSocket>> =
            match bind_tproxy_udp_listeners(udp6_addr, UDP_LISTENER_COUNT) {
                Ok(sockets) => {
                    let sockets: Vec<Arc<UdpSocket>> = sockets.into_iter().map(Arc::new).collect();
                    info!(
                        "Control plane listening for TPROXY UDPv6 x{} on {}",
                        sockets.len(),
                        udp6_addr
                    );
                    sockets
                }
                Err(e) => {
                    warn!("TPROXY UDPv6 listener unavailable: {}", e);
                    Vec::new()
                }
            };

        // Publish listener socket FDs into the eBPF listen_socket_map so TC
        // programs can bpf_sk_assign() proxy-bound packets directly to userspace.
        {
            use std::os::unix::io::AsRawFd;
            let tcp4_fd = tcp4_listener.as_raw_fd();
            let tcp6_fd = tcp6_listener.as_ref().map_or(tcp4_fd, |l| l.as_raw_fd());
            let udp4_fds: Vec<_> = udp4_sockets.iter().map(|s| s.as_raw_fd()).collect();
            let udp6_fds: Vec<_> = udp6_sockets.iter().map(|s| s.as_raw_fd()).collect();
            let mut ebpf = self.ebpf.write().await;
            // A partially published listener set means flows are assigned to
            // sockets that don't exist — run nothing rather than that.
            ebpf.publish_listener_sockets(tcp4_fd, tcp6_fd, &udp4_fds, &udp6_fds)
                .map_err(|e| anyhow::anyhow!("publish listener sockets to eBPF: {}", e))?;
        }

        let mut dns_listener = match bound_dns_listener {
            Some(bound) => {
                let listener = bound
                    .spawn(
                        Arc::clone(&self.dns_controller),
                        Arc::clone(&self.dns_concurrency_limit),
                        Arc::clone(&self.concurrency_limit),
                        Arc::clone(&self.stats),
                        Arc::clone(&self.drain_tracker),
                    )
                    .map_err(|error| anyhow::anyhow!("start dns.bind listener: {error}"))?;
                info!(
                    address = %listener.local_addr(),
                    tcp = dns_bind_endpoint.as_ref().is_some_and(|endpoint| endpoint.tcp_enabled()),
                    udp = dns_bind_endpoint.as_ref().is_some_and(|endpoint| endpoint.udp_enabled()),
                    "Standalone DNS listener started"
                );
                Some(listener)
            }
            None => None,
        };

        // One receive loop per listener socket. The datapath hashes flows
        // into the group (see the comment above), so loops are flow-disjoint.
        {
            let state = UdpLoopState {
                udp_pool: Arc::clone(&self.udp_pool),
                stats: Arc::clone(&self.stats),
                udp_concurrency_limit: Arc::clone(&self.udp_concurrency_limit),
                dns_concurrency_limit: Arc::clone(&self.dns_concurrency_limit),
                dns_controller: Arc::clone(&self.dns_controller),
                drain: self.drain_tracker.clone(),
                handle: self.spawn_handle(),
            };
            let mut tasks = self.background_tasks.lock().await;
            for socket in &udp4_sockets {
                tasks.push(tokio::spawn(udp_listener_loop(
                    state.clone(),
                    Arc::clone(socket),
                    "v4",
                )));
            }
            for socket in &udp6_sockets {
                tasks.push(tokio::spawn(udp_listener_loop(
                    state.clone(),
                    Arc::clone(socket),
                    "v6",
                )));
            }
        }

        let tcp6_listener = tcp6_listener;
        #[cfg(feature = "ebpf")]
        let mut nfqueue_runtime = match self.start_nfqueue_runtime(udp_nfqueue_enabled).await {
            Ok(runtime) => runtime,
            Err(error) => {
                if let Some(listener) = dns_listener.as_mut() {
                    listener.stop_accepting();
                    listener.abort_and_join().await;
                }
                self.cleanup_pre_admission_failure().await;
                return Err(error);
            }
        };
        #[cfg(not(feature = "ebpf"))]
        let mut nfqueue_runtime = ();

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
        let (mut udp_removal_task, mut udp_removal_fatal_rx) = {
            let (fatal_tx, fatal_rx) = mpsc::unbounded_channel();
            let mut tasks = self.background_tasks.lock().await;

            let janitor = BpfJanitor::new(self.ebpf.clone(), self.tcp_flow_pins.clone());
            tasks.push(janitor.spawn());
            info!("BPF map janitor started");

            let removal_task = spawn_udp_removal_worker(
                Arc::clone(&self.udp_pool),
                self.ebpf.clone(),
                self.connection_tracker.clone(),
                fatal_tx,
            );

            tasks.push(self.udp_pool.spawn_janitor());

            tasks.push(self.sniffer_pool.spawn_janitor());

            tasks.push(crate::control::tcp_sniff::spawn_sniff_neg_cache_janitor(
                self.tcp_sniff_neg_cache.clone(),
            ));
            (removal_task, fatal_rx)
        };

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
                        self.runtime_registry.clone(),
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
                    self.runtime_registry.clone(),
                    self.stats.clone(),
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
                // Group slots normally publish the OR of their leaf health.
                // A sole TCP leaf without `final` stays open so userspace can
                // make the one real dial capable of proving recovery.
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
                let group = config_for_push.try_read().ok().and_then(|c| {
                    let idx = outbound_idx
                        .checked_sub(honk_ebpf_common::OutboundIndex::UserBase as u8)?;
                    c.groups.get(idx as usize).cloned()
                });
                let any_alive = match group {
                    Some(group) => {
                        let gm = group_manager_for_push.read().clone();
                        reload::group_datapath_alive(
                            &group,
                            &gm,
                            &alive_for_push,
                            probe_domain,
                            ip_version,
                        )
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
            let count = config.global.preconnect_node_count;
            let connect_timeout =
                std::time::Duration::from_millis(config.global.connect_timeout_ms);
            let max_concurrent = if count == honk_config::config::PRECONNECT_NODE_COUNT_AUTO {
                4usize
            } else {
                count.min(8)
            };
            let nodes = {
                let manager = self.group_manager.read().clone();
                preconnect_candidates(&config, &manager, count)
            };
            drop(config);

            if !nodes.is_empty() {
                let node_count = nodes.len();
                let pool = self.connection_pool.clone();
                let stats = self.stats.clone();
                let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
                let handle = tokio::spawn(async move {
                    let mut set = tokio::task::JoinSet::new();
                    for node in nodes {
                        let addr = format!("{}:{}", node.host(), node.port);
                        let pool = pool.clone();
                        let stats = stats.clone();
                        let sem = semaphore.clone();
                        set.spawn(async move {
                            let _permit = sem.acquire_owned().await;
                            match honk_outbound::util::connect_outbound(&addr, connect_timeout)
                                .await
                            {
                                Ok(stream) => {
                                    if is_tcp_stream_alive(&stream) {
                                        pool.deposit_tcp(&addr, stream).await;
                                        stats.mark_warm(
                                            node.id,
                                            crate::stats::WarmReason::Preconnect,
                                        );
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

        // Warm coordinators start only after group/runtime setup and retain
        // this exact registry Arc for their complete lifetime.
        let warm_generation = self.runtime_registry.read().clone();
        self.start_udp_warm_coordinator(Arc::clone(&warm_generation))
            .await;
        self.start_selector_warm_coordinator(warm_generation).await;

        {
            let runtime_registry = self.runtime_registry.clone();
            let handle = tokio::spawn(async move {
                let mut interval = tokio::time::interval(honk_outbound::runtime::TLS_REAP_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let generation = runtime_registry.read().clone();
                    let evicted = generation.reap_tls_connectors(std::time::Instant::now());
                    if evicted > 0 {
                        debug!(evicted, "released idle outbound TLS connectors");
                    }
                }
            });
            self.background_tasks.lock().await.push(handle);
        }

        #[cfg(feature = "ebpf")]
        let nfqueue_startup_health = match nfqueue_runtime.as_mut() {
            Some(runtime) => runtime.check_startup_health().await,
            None => Ok(()),
        };
        #[cfg(feature = "ebpf")]
        if let Err(error) = nfqueue_startup_health {
            self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                .await;
            self.cleanup_started_control_tasks(&mut udp_removal_task, dns_listener.as_mut())
                .await;
            return Err(anyhow::anyhow!("NFQUEUE failed before readiness: {error}"));
        }
        #[cfg(feature = "ebpf")]
        let nfqueue_ready = nfqueue_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.sequence_ready);
        #[cfg(not(feature = "ebpf"))]
        let nfqueue_ready = false;
        if let Err(error) = self
            .initialize_datapath_flags(udp_nfqueue_enabled, nfqueue_ready)
            .await
        {
            #[cfg(feature = "ebpf")]
            self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                .await;
            self.cleanup_started_control_tasks(&mut udp_removal_task, dns_listener.as_mut())
                .await;
            return Err(anyhow::anyhow!("initialize datapath flags: {error:#}"));
        }
        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_ref()
            && runtime.sequence_ready
        {
            runtime.pending.open_admission();
        }
        let datapath_open = {
            let mut backend = self.ebpf.write().await;
            backend.set_datapath_ready(true)
        };
        if let Err(error) = datapath_open {
            if let Some(flags) = self.datapath_flags.as_ref() {
                let _ = flags.fence_nfqueue().await;
            }
            #[cfg(feature = "ebpf")]
            self.cleanup_nfqueue_startup_failure(&mut nfqueue_runtime)
                .await;
            self.cleanup_started_control_tasks(&mut udp_removal_task, dns_listener.as_mut())
                .await;
            return Err(anyhow::anyhow!("open eBPF datapath admission: {error}"));
        }
        info!("eBPF datapath admission opened after listener publication");
        #[cfg(target_os = "linux")]
        if let Err(error) =
            libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
        {
            warn!(%error, "sd_notify readiness failed");
        }

        let mut rx = self.command_rx.take().expect("command_rx already taken");
        let drain = self.drain_tracker.clone();
        let fatal_ebpf = Arc::clone(&self.ebpf);
        let mut fatal_error = None;

        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut loop_count = 0u64;
        loop {
            loop_count += 1;
            tokio::select! {
                error = udp_removal_fatal_rx.recv() => {
                    fatal_error = Some(error.unwrap_or_else(|| {
                        anyhow::anyhow!("UDP removal fatal channel closed unexpectedly")
                    }));
                    break;
                }
                event = wait_nfqueue_event(&mut nfqueue_runtime, &fatal_ebpf) => {
                    match event {
                        NfqueueRuntimeEvent::Fatal(error) => {
                            fatal_error = Some(error);
                            break;
                        }
                        NfqueueRuntimeEvent::TokenExhausted => {
                            #[cfg(feature = "ebpf")]
                            if let Some(runtime) = nfqueue_runtime.as_mut()
                                && let Err(error) = self
                                    .recover_nfqueue_token_exhaustion(runtime)
                                    .await
                            {
                                fatal_error = Some(anyhow::anyhow!(
                                    "recover exhausted UDP decision token generation: {error:#}"
                                ));
                                break;
                            }
                        }
                    }
                }
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
                            if let Err(e) = set_so_mark_zero(&stream) {
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
                            if let Err(e) = set_so_mark_zero(&stream) {
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

                cmd = rx.recv() => {
                    match cmd {
                        Some(ControlCommand::ReloadConfig { request_id, config }) => {
                            info!("SIGHUP reload request {request_id} started");
                            if self.apply_runtime_config(*config, &drain).await {
                                info!("SIGHUP reload request {request_id} applied");
                            } else {
                                warn!("SIGHUP reload request {request_id} rejected");
                            }
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
                            let _ = self.apply_runtime_config(new_config, &drain).await;
                        }
                        Some(ControlCommand::NetworkChanged) => {
                            let new_config = {
                                let current = self.config.read().await;
                                let mut next = current.clone();
                                next.ensure_local_direct_rules().then_some(next)
                            };
                            if let Some(new_config) = new_config {
                                info!("refreshing local direct rules after network change");
                                if !self.apply_runtime_config(new_config, &drain).await {
                                    warn!("network-triggered routing refresh rejected");
                                }
                            }
                            self.alive_set.notify_network_change();
                        }
                        Some(ControlCommand::Shutdown) | None => break,
                    }
                }
            }
        }

        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.fence_nfqueue().await
        {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to fence NFQUEUE during shutdown: {error:#}")
            });
        }
        let datapath_closed = {
            let mut backend = self.ebpf.write().await;
            backend.set_datapath_ready(false)
        };
        if let Err(error) = datapath_closed {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to close eBPF datapath admission: {error:#}")
            });
        }
        drain.start_rejecting();
        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_mut() {
            runtime.begin_pending_drain().await;
            if let Err(error) = runtime.check_startup_health().await {
                fatal_error.get_or_insert_with(|| anyhow::Error::new(error));
            }
        }

        if let Err(error) = self
            .shutdown_datapath(&drain, &mut udp_removal_task, dns_listener.as_mut())
            .await
        {
            fatal_error.get_or_insert(error);
        }

        #[cfg(feature = "ebpf")]
        if let Some(runtime) = nfqueue_runtime.as_mut() {
            if let Err(error) = runtime.shutdown_service().await {
                fatal_error.get_or_insert(error);
            }
            if let Some(error) = runtime.take_shutdown_fatal() {
                fatal_error.get_or_insert_with(|| anyhow::Error::new(error));
            }
            if let Err(error) = runtime.finish_pending_drain().await {
                fatal_error.get_or_insert(error);
            }
            self.pending_udp_verdicts = None;
        }

        if let Some(flags) = self.datapath_flags.as_ref()
            && let Err(error) = flags.disable().await
        {
            fatal_error.get_or_insert_with(|| {
                anyhow::anyhow!("failed to disable datapath flags: {error:#}")
            });
        }

        if let Err(error) = self.finalize_shutdown().await {
            fatal_error.get_or_insert(error);
        }
        if let Some(error) = fatal_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    /// Datapath half of shutdown: close admission, stop background work,
    /// detach the eBPF hooks (network restored before the connection drain,
    /// Go dae behaviour), then drain flows and retire the outbound runtime
    /// generation.  Every await without a natural deadline is bounded —
    /// with the hooks already detached, a hung stage would otherwise leave
    /// the engine half-torn-down forever: links gone, process alive.
    async fn shutdown_datapath(
        &mut self,
        drain: &Arc<DrainTracker>,
        udp_removal_task: &mut tokio::task::JoinHandle<()>,
        dns_listener: Option<&mut dns_listener::DnsListener>,
    ) -> anyhow::Result<()> {
        info!(
            "Control plane shutting down, draining {} active connections",
            drain.active_count()
        );
        if let Some(listener) = dns_listener.as_ref() {
            listener.stop_accepting();
        }
        self.stop_udp_warm_coordinator().await;
        self.stop_selector_warm_coordinator().await;
        if !self.udp_pool.shutdown().await {
            error!("UDP endpoint shutdown required forced cleanup");
        }
        // Keep the removal consumer alive until terminal endpoint cleanup has
        // emitted and drained every conn-state/tracker retirement.
        if let Err(error) = (&mut *udp_removal_task).await {
            warn!("UDP removal consumer failed during shutdown: {}", error);
        }
        // Abort remaining background tasks (health check, janitors, preconnect)
        // only after UDP drivers and their removal sink have drained.
        {
            let mut tasks = self.background_tasks.lock().await;
            for handle in tasks.drain(..) {
                handle.abort();
            }
        }
        // Stop the interface watcher first: it shares the backend and could
        // re-attach hooks mid-drain. The timeout aborts the worker instead
        // of detaching it (a detached watcher could re-attach hooks after
        // detach_hooks).
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        }
        // Detach BPF hooks immediately to restore network connectivity
        // before draining connections (matches Go dae behaviour).
        info!("shutdown: detaching eBPF hooks");
        {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.detach_hooks() {
                warn!("Failed to detach BPF hooks: {}", e);
            }
        }
        info!("shutdown: draining connections");
        drain.drain().await?;
        if let Some(listener) = dns_listener {
            listener.abort_and_join().await;
        }
        // Active flows own the current runtime until the drain completes; only
        // then terminally close its session pools and reject any late warm work.
        // Dropping this future on timeout detaches nothing: the force-closes
        // are synchronous once entered and none of the runtimes touch the
        // eBPF backend.
        let generation = self.runtime_registry.read().clone();
        info!("shutdown: retiring outbound runtime generation");
        if tokio::time::timeout(SHUTDOWN_STAGE_TIMEOUT, generation.shutdown())
            .await
            .is_err()
        {
            warn!(
                "outbound runtime generation shutdown exceeded {:?}; continuing",
                SHUTDOWN_STAGE_TIMEOUT
            );
        }
        Ok(())
    }

    /// Userspace half of shutdown: DNS controller, DNS persistence, and the
    /// eBPF backend cleanup.  Bounded like `shutdown_datapath` so a stuck
    /// DNS transport cannot pin the process after the datapath is down.
    async fn finalize_shutdown(&mut self) -> anyhow::Result<()> {
        info!("shutdown: stopping DNS controller");
        self.dns_controller.shutdown(SHUTDOWN_STAGE_TIMEOUT).await;
        let dns_cache = self.dns_controller.cache().await;
        let persistence = dns_cache.lock().await.persistence();
        if let Some(persistence) = persistence {
            // The worker is a std thread that cannot be aborted, but the
            // Shutdown command is queued before the join starts, and the
            // spawn_blocking join keeps owning the thread handle even if
            // this future is dropped on timeout — no detached writer.
            match tokio::time::timeout(SHUTDOWN_STAGE_TIMEOUT, persistence.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "DNS persistence shutdown failed"),
                Err(_) => warn!(
                    "DNS persistence shutdown exceeded {:?}; continuing",
                    SHUTDOWN_STAGE_TIMEOUT
                ),
            }
        }
        info!("shutdown: cleaning up eBPF backend");
        self.ebpf.write().await.cleanup().await?;
        info!("Control plane stopped");
        Ok(())
    }

    fn spawn_handle(&self) -> ControlPlaneHandle {
        ControlPlaneHandle {
            config: self.config.clone(),
            router: self.router.clone(),
            proxy_registry: self.proxy_registry.clone(),
            runtime_registry: self.runtime_registry.clone(),
            dns_resolver: self.dns_resolver.clone(),
            group_manager: self.group_manager.clone(),
            stats: self.stats.clone(),
            ebpf: self.ebpf.clone(),
            udp_pool: self.udp_pool.clone(),
            #[cfg(feature = "ebpf")]
            pending_udp_verdicts: self.pending_udp_verdicts.clone(),
            tcp_sniff_neg_cache: self.tcp_sniff_neg_cache.clone(),
            sniffer_pool: self.sniffer_pool.clone(),
            dns_controller: self.dns_controller.clone(),
            alive_set: self.alive_set.clone(),
            connection_pool: self.connection_pool.clone(),
            connection_tracker: self.connection_tracker.clone(),
            tcp_flow_pins: self.tcp_flow_pins.clone(),
            mode_state: self.mode_state.clone(),
        }
    }
}

/// Work produced by the shared IPv4/IPv6 UDP slow-path dispatcher after a
/// fast-path miss. The accept loop never awaits PacketTransport I/O; DNS
/// resolution (when required) runs inside a slow-permit-bounded task.
enum UdpSlowPathWork {
    /// Fresh reservation: caller spawns `serve_udp_connection`.
    Initialize(UdpInitLease),
    /// DNS-shaped traffic: slow permit is already held and the payload has
    /// been copied. Run the production DNS controller first; only if it
    /// declines, continue through the same reserve/initializer path.
    DnsThenMaybeInitialize {
        permit: tokio::sync::OwnedSemaphorePermit,
        data: Bytes,
        validated: ValidatedDnsQuery,
    },
    /// Fully handled in the receive loop (enqueued / rejected / dropped).
    Done,
}

/// Shared production admission helper used by both listener families and by
/// focused tests. Order is always:
/// `slow permit → (optional heap copy for DNS task) → reserve_or_enqueue`.
/// Only strict DNS queries whose authoritative destination is port 53 return
/// [`UdpSlowPathWork::DnsThenMaybeInitialize`]; DNS-shaped non-53 UDP stays
/// on ordinary forwarding.
fn begin_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
) -> UdpSlowPathWork {
    let Some(permit) = try_admit_udp_slow_path(stats, concurrency_limit) else {
        return UdpSlowPathWork::Done;
    };
    if original_dst.port() == 53
        && let Some(validated) = validated_dns
    {
        // Permit is acquired before the heap copy required to leave the
        // receive buffer for a permit-bounded DNS task.
        return UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data: Bytes::copy_from_slice(data),
            validated,
        };
    }
    match pool.reserve_or_enqueue(src_addr, original_dst, data, permit, stats) {
        EndpointReservation::Initializing(lease) => UdpSlowPathWork::Initialize(lease),
        EndpointReservation::Enqueued
        | EndpointReservation::CapacityRejected
        | EndpointReservation::QueueFull
        | EndpointReservation::IdentityMismatch
        | EndpointReservation::QueueClosed => UdpSlowPathWork::Done,
    }
}

struct UdpDnsSlowPathContext<'a> {
    pool: &'a Arc<UdpEndpointPool>,
    stats: &'a StatsManager,
    dns_controller: &'a crate::control::dns_control::DnsController,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
}

/// Finish a DNS-forced slow path after the slow permit was acquired: run the
/// production DNS controller first. If it handles the packet, do not
/// reserve/enqueue. If it declines, continue through the same
/// `reserve_or_enqueue` path used by ordinary slow traffic.
async fn complete_udp_dns_slow_path(
    context: UdpDnsSlowPathContext<'_>,
    permit: tokio::sync::OwnedSemaphorePermit,
    data: &[u8],
    validated: ValidatedDnsQuery,
) -> Option<UdpInitLease> {
    let UdpDnsSlowPathContext {
        pool,
        stats,
        dns_controller,
        src_addr,
        original_dst,
    } = context;
    match dns_controller
        .handle_udp_dns(data, src_addr, original_dst, Some(validated))
        .await
    {
        Ok(true) => return None,
        Ok(false) => {}
        Err(error) => {
            // Preserve the historical UDP fallback: a controller failure is
            // not a reason to drop the original datagram before ordinary
            // endpoint admission has had a chance to forward it.
            warn!(
                "DNS controller error for UDP {} -> {}; continuing UDP: {}",
                src_addr, original_dst, error
            );
        }
    }
    match pool.reserve_or_enqueue(src_addr, original_dst, data, permit, stats) {
        EndpointReservation::Initializing(mut lease) => {
            // The controller was invoked exactly once for this packet. Carry
            // that fact into initialize_udp_connection so an Ok(false) or
            // Err continuation cannot call it again.
            lease.mark_dns_checked();
            Some(lease)
        }
        EndpointReservation::Enqueued
        | EndpointReservation::CapacityRejected
        | EndpointReservation::QueueFull
        | EndpointReservation::IdentityMismatch
        | EndpointReservation::QueueClosed => None,
    }
}

/// Shared IPv4/IPv6 receive-loop dispatcher after a fast-path miss. Acquires
/// the slow permit before any copy/spawn, prefers the DNS controller for
/// DNS-shaped traffic, and only then reserves or enqueues.
/// Everything a UDP listener loop needs, cloned from the control plane once
/// so each socket's loop runs as an independent task (parallel drain).
#[derive(Clone)]
struct UdpLoopState {
    udp_pool: Arc<UdpEndpointPool>,
    stats: Arc<StatsManager>,
    udp_concurrency_limit: Arc<tokio::sync::Semaphore>,
    dns_concurrency_limit: Arc<tokio::sync::Semaphore>,
    dns_controller: Arc<crate::control::dns_control::DnsController>,
    drain: Arc<DrainTracker>,
    handle: ControlPlaneHandle,
}

/// Receive loop for one UDP listener socket. The eBPF datapath hashes each
/// flow to a specific socket of the group, so loops are flow-disjoint and
/// run in parallel across runtime workers.
async fn udp_listener_loop(state: UdpLoopState, socket: Arc<UdpSocket>, family: &'static str) {
    let mut buf = vec![0u8; 64 * 1024];
    let local_addr = match socket.local_addr() {
        Ok(local_addr) => local_addr,
        Err(error) => {
            error!("{} UDP recv error: {}", family, error);
            return;
        }
    };
    loop {
        match recv_from_with_orig_dst(&socket, local_addr, &mut buf).await {
            Ok((n, src_addr, recv_meta)) => {
                let Some(destination) = udp_original_dst(&recv_meta, &buf[..n]) else {
                    debug!(
                        "Dropping {} UDP from {} without original-destination provenance",
                        family, src_addr
                    );
                    continue;
                };
                let original_dst = destination.address;
                let mut validated_dns = destination.validated_dns;
                if original_dst.port() == 53 && validated_dns.is_none() {
                    validated_dns = validate_exact_dns_query(&buf[..n]);
                }
                if !accepts_transparent_connection(&state.drain) {
                    state.stats.record_udp_slow_permit_closed();
                    continue;
                }
                // Ready flows enqueue synchronously here; this loop never
                // awaits PacketTransport I/O.
                if udp_fast_path(
                    &state.udp_pool,
                    &state.stats,
                    &buf[..n],
                    src_addr,
                    original_dst,
                    validated_dns,
                )
                .await
                {
                    continue;
                }
                dispatch_udp_slow_path(&state, src_addr, original_dst, &buf[..n], validated_dns);
            }
            Err(e) => error!("{} UDP recv error: {}", family, e),
        }
    }
}

fn dispatch_udp_slow_path(
    state: &UdpLoopState,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
    validated_dns: Option<ValidatedDnsQuery>,
) {
    let concurrency_limit = if original_dst.port() == 53 && validated_dns.is_some() {
        &state.dns_concurrency_limit
    } else {
        &state.udp_concurrency_limit
    };
    match begin_udp_slow_path(
        &state.udp_pool,
        &state.stats,
        concurrency_limit,
        src_addr,
        original_dst,
        data,
        validated_dns,
    ) {
        UdpSlowPathWork::Done => {}
        UdpSlowPathWork::Initialize(lease) => {
            let handle = state.handle.clone();
            let drain = Arc::clone(&state.drain);
            state.udp_pool.spawn_slow_path(async move {
                let _guard = ConnectionGuard::new(drain);
                if let Err(e) = handle.serve_udp_connection(lease).await {
                    warn!(
                        "Error handling UDP from {} (orig {}): {}",
                        src_addr, original_dst, e
                    );
                }
            });
        }
        UdpSlowPathWork::DnsThenMaybeInitialize {
            permit,
            data,
            validated,
        } => {
            let handle = state.handle.clone();
            let guard = ConnectionGuard::new(Arc::clone(&state.drain));
            let pool = Arc::clone(&state.udp_pool);
            let stats = Arc::clone(&state.stats);
            let dns_controller = Arc::clone(&state.dns_controller);
            state.udp_pool.spawn_slow_path(async move {
                // DNS handling is already accepted work. Register it before
                // spawning so reload/shutdown drain cannot miss work before
                // its first poll; keep the guard alive for the task lifetime.
                let _guard = guard;
                let Some(lease) = complete_udp_dns_slow_path(
                    UdpDnsSlowPathContext {
                        pool: &pool,
                        stats: &stats,
                        dns_controller: dns_controller.as_ref(),
                        src_addr,
                        original_dst,
                    },
                    permit,
                    &data,
                    validated,
                )
                .await
                else {
                    return;
                };
                if let Err(e) = handle.serve_udp_connection(lease).await {
                    warn!(
                        "Error handling UDP from {} (orig {}): {}",
                        src_addr, original_dst, e
                    );
                }
            });
        }
    }
}

/// Compatibility wrapper used by family-symmetric admission tests: acquire
/// the slow permit then synchronously reserve/enqueue (non-DNS path).
#[cfg(test)]
fn reserve_udp_slow_path(
    pool: &Arc<UdpEndpointPool>,
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
    src_addr: SocketAddr,
    original_dst: SocketAddr,
    data: &[u8],
) -> Option<UdpInitLease> {
    match begin_udp_slow_path(
        pool,
        stats,
        concurrency_limit,
        src_addr,
        original_dst,
        data,
        None,
    ) {
        UdpSlowPathWork::Initialize(lease) => Some(lease),
        UdpSlowPathWork::DnsThenMaybeInitialize { permit, data, .. } => {
            match pool.reserve_or_enqueue(src_addr, original_dst, &data, permit, stats) {
                EndpointReservation::Initializing(lease) => Some(lease),
                _ => None,
            }
        }
        UdpSlowPathWork::Done => None,
    }
}

/// Admit one datagram onto the current UDP slow path after a fast-path miss.
///
/// This is the sole production owner of `udp.slowPermit` accepted/rejected
/// counters. Queue metrics are recorded by `reserve_or_enqueue` / the driver.
pub(super) fn try_admit_udp_slow_path(
    stats: &StatsManager,
    concurrency_limit: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match concurrency_limit.clone().try_acquire_owned() {
        Ok(permit) => {
            stats.record_udp_slow_permit_accepted();
            Some(permit)
        }
        Err(_) => {
            stats.record_udp_slow_permit_rejected();
            None
        }
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

/// Pick the nodes the startup preconnect warm-up dials: each group's current
/// selection (selector pick / urltest winner, peek semantics) first, then
/// config order to fill the remaining budget. Eligibility is
/// descriptor-driven — multiplexed (AnyTLS) and QUIC nodes can never consume
/// a pooled bare TCP — and the built-in direct/block markers have no server
/// to dial. `count == 0` disables the warm-up; the
/// [`honk_config::config::PRECONNECT_NODE_COUNT_AUTO`] sentinel caps at
/// `min(nodes, 8)`.
pub(super) fn preconnect_candidates(
    config: &Config,
    group_manager: &GroupManager,
    count: usize,
) -> Vec<Node> {
    if count == 0 {
        return Vec::new();
    }
    let limit = if count == honk_config::config::PRECONNECT_NODE_COUNT_AUTO {
        config.nodes.len().min(8)
    } else {
        count
    };
    fn eligible(node: &Node) -> bool {
        !matches!(node.protocol, NodeProtocol::Direct | NodeProtocol::Block)
            && (honk_outbound::descriptor::descriptor(node.protocol).pool_bare_tcp)(node)
    }
    let mut seen = std::collections::HashSet::new();
    let mut selected: Vec<Node> = Vec::new();
    let push = |node: &Node,
                seen: &mut std::collections::HashSet<uuid::Uuid>,
                selected: &mut Vec<Node>| {
        if selected.len() < limit && eligible(node) && seen.insert(node.id) {
            selected.push(node.clone());
        }
    };
    for group in &config.groups {
        if let Some(node) = group_manager
            .peek_selection_plan_for_domain(&group.name, ProbeDomain::Tcp, IpVersion::V4)
            .nodes
            .first()
        {
            push(node, &mut seen, &mut selected);
        }
    }
    for node in &config.nodes {
        push(node, &mut seen, &mut selected);
    }
    selected
}
