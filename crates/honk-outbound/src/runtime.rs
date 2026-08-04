//! Per-node runtime ownership: the ControlPlane owns every outbound's
//! session-layer resources through immutable runtime generations.
//!
//! `OutboundRuntimeRegistry` maps `Node.id` (UUID) to a `NodeRuntime` —
//! the minimal PreparedOutbound: the immutable node config, its
//! capabilities, and the protocol runtime that owns its sessions. The
//! registry lives on the ControlPlane (never on the GroupManager — a leaf
//! node may belong to many groups, and group rebuilds must not destroy
//! live sessions). ProxyRegistry stays stateless handlers.
//!
//! AnyTLS owns its node-local session pool here; the QUIC protocols own
//! their per-node client (and thereby the shared QUIC connection) here.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
const TLS_ACTIVE_RATIO_NUMERATOR: usize = 1;
const TLS_ACTIVE_RATIO_DENOMINATOR: usize = 10;
const TLS_ACTIVE_MIN: usize = 8;
pub const TLS_IDLE_RETENTION: Duration = Duration::from_secs(10 * 60);
pub const TLS_REAP_INTERVAL: Duration = Duration::from_secs(60);

use honk_config::node::Node;

/// What a node can do, derived from its protocol and config — the basis
/// for capability-based pooling decisions (e.g. the ready-pool allowlist
/// in phase 5, bare-pool eligibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundCapabilities {
    /// Carries TCP flows (all current protocols).
    pub tcp: bool,
    /// Carries UDP flows (`dial_udp_transport` works end to end).
    pub udp: bool,
    /// Multiplexes many logical streams over one physical session —
    /// these protocols pool sessions, never bare TCP or ready streams.
    pub multiplexed: bool,
}

impl OutboundCapabilities {
    pub fn for_node(node: &Node) -> Self {
        (crate::descriptor::descriptor(node.protocol).capabilities)(node)
    }
}

/// The generation-scoped session runtime a protocol owns, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationRuntime {
    None,
    AnyTls,
    Quic,
}

impl GenerationRuntime {
    pub(crate) fn build(self) -> ProtocolRuntime {
        match self {
            GenerationRuntime::None => ProtocolRuntime::None,
            GenerationRuntime::AnyTls => ProtocolRuntime::AnyTls(AnyTlsRuntime::new()),
            GenerationRuntime::Quic => ProtocolRuntime::Quic(QuicRuntime::new()),
        }
    }
}

/// The session-layer runtime for one node. AnyTLS owns a `SessionPool`; QUIC
/// protocols own their connection/auth state here instead of in handlers so
/// a reload cannot send an old flow to a newly published generation.
#[derive(Debug)]
pub enum ProtocolRuntime {
    None,
    /// AnyTLS: the node's own session pool (2B). One pool per node — no
    /// static/global pool, no shared string keys.
    AnyTls(AnyTlsRuntime),
    /// TUIC, Juicity, and Hysteria2: type-erased, node-local client slots.
    /// Each concrete handler occupies one slot and retains its own typed
    /// `QuicClient`; the runtime retains it for this generation's lifetime.
    Quic(QuicRuntime),
}

/// A protocol client stored in [`QuicRuntime`]. Implemented by the
/// TUIC/Juicity/Hysteria2 per-server clients so a terminating generation
/// can force-close the shared connection without knowing the concrete type.
#[async_trait::async_trait]
pub trait QuicRuntimeClient: Send + Sync + 'static {
    fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;
    /// Close the cached connection and endpoint, awaiting any in-flight
    /// dial so its late-arriving connection is closed too.
    async fn force_close(&self);
}

/// Generation-owned storage for protocol-specific QUIC clients.
///
/// The mutex deliberately covers construction: TLS config construction may
/// perform ECH discovery, and admitting two first flows must still result in
/// one client/connection single-flight for this generation.
pub struct QuicRuntime {
    clients: tokio::sync::Mutex<HashMap<std::any::TypeId, Arc<dyn QuicRuntimeClient>>>,
    /// Set by [`Self::force_close_all`] under the clients lock, so a client
    /// build can never slip past a completed close.
    closed: AtomicBool,
}

impl std::fmt::Debug for QuicRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicRuntime").finish_non_exhaustive()
    }
}

impl QuicRuntime {
    pub(crate) fn new() -> Self {
        Self {
            clients: tokio::sync::Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub async fn client<T, F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        T: QuicRuntimeClient,
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<T>>>,
    {
        let mut clients = self.clients.lock().await;
        if self.closed.load(Ordering::Acquire) {
            anyhow::bail!("QUIC runtime is closed");
        }
        let key = std::any::TypeId::of::<T>();
        if let Some(client) = clients.get(&key) {
            return Arc::clone(client)
                .into_erased()
                .downcast::<T>()
                .map_err(|_| anyhow::anyhow!("QUIC client slot type mismatch"));
        }
        let client = build().await?;
        clients.insert(key, Arc::clone(&client) as Arc<dyn QuicRuntimeClient>);
        Ok(client)
    }

    /// Force-close every cached client and reject future client builds.
    /// Awaits the construction/dial critical sections: a client or
    /// connection completed just before the close is closed here rather
    /// than leaked into a terminating generation. The map is drained so a
    /// closed runtime neither pins dead clients nor reports them as warm.
    pub(crate) async fn force_close_all(&self) {
        let clients: Vec<Arc<dyn QuicRuntimeClient>> = {
            let mut clients = self.clients.lock().await;
            self.closed.store(true, Ordering::Release);
            clients.drain().map(|(_, client)| client).collect()
        };
        for client in clients {
            client.force_close().await;
        }
    }

    /// Whether any protocol client already occupies a slot. A contended lock
    /// means a client build is in flight, which counts as warm: callers use
    /// this to decide between reusing the runtime and dialing ephemerally,
    /// and the ephemeral dial would only duplicate that build.
    pub(crate) fn has_client(&self) -> bool {
        self.clients
            .try_lock()
            .map(|c| !c.is_empty())
            .unwrap_or(true)
    }

    /// Number of occupied client slots — the warm-resource gauge behind
    /// `/stats`. A contended lock reports zero rather than blocking a
    /// metrics path on an in-flight build.
    pub(crate) fn client_count(&self) -> usize {
        self.clients.try_lock().map(|c| c.len()).unwrap_or(0)
    }
}

/// Lazily built TLS state. An in-flight handshake owns an `Arc`, so evicting
/// the cached reference never invalidates active work.
#[derive(Debug, Default)]
struct TlsConnectorSlot {
    state: parking_lot::Mutex<TlsConnectorSlotState>,
}

#[derive(Debug, Default)]
struct TlsConnectorSlotState {
    cached: Option<(Arc<crate::tls::TlsConnector>, Instant)>,
    revision: u64,
}

impl TlsConnectorSlot {
    fn get_or_build(&self, node: &Node) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let mut state = self.state.lock();
        state.revision = state.revision.wrapping_add(1);
        if let Some((connector, used_at)) = state.cached.as_mut() {
            *used_at = Instant::now();
            return Ok(Arc::clone(connector));
        }
        let connector = Arc::new(crate::tls::build_connector(node)?);
        state.cached = Some((Arc::clone(&connector), Instant::now()));
        Ok(connector)
    }

    fn sample(&self) -> Option<(Instant, u64)> {
        let state = self.state.lock();
        state
            .cached
            .as_ref()
            .map(|(_, used_at)| (*used_at, state.revision))
    }

    fn evict_if_sample(&self, sample: (Instant, u64)) -> bool {
        let mut state = self.state.lock();
        let unchanged = state.revision == sample.1
            && state
                .cached
                .as_ref()
                .is_some_and(|(_, used_at)| *used_at == sample.0);
        if !unchanged {
            return false;
        }
        state.cached.take();
        state.revision = state.revision.wrapping_add(1);
        true
    }

    #[cfg(test)]
    fn is_loaded(&self) -> bool {
        self.state.lock().cached.is_some()
    }
}

/// AnyTLS session runtime: the pool stays generation-owned, while expensive
/// BoringSSL state is materialized only for nodes entering the active set.
#[derive(Debug)]
pub struct AnyTlsRuntime {
    pub(crate) pool: Arc<crate::proxy::anytls::AnyTlsPool>,
    tls: TlsConnectorSlot,
}

impl AnyTlsRuntime {
    fn new() -> Self {
        Self {
            pool: Arc::new(crate::session::SessionPool::new(
                crate::proxy::anytls::session_pool_config(),
            )),
            tls: TlsConnectorSlot::default(),
        }
    }
}

/// Live warm-session gauge of one runtime: retained AnyTLS pool sessions
/// and occupied QUIC client slots.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WarmCounts {
    pub sessions: usize,
    pub clients: usize,
}

/// The minimal per-node runtime entry (the honest, minimal
/// PreparedOutbound — not the full scaffold).
#[derive(Debug)]
pub struct NodeRuntime {
    /// Immutable node config for this generation.
    pub node: Arc<Node>,
    pub capabilities: OutboundCapabilities,
    pub runtime: ProtocolRuntime,
    /// One-shot runtime outside any generation (see [`Self::ephemeral`]).
    /// Session protocols skip their standby janitor for these: there is no
    /// long-lived owner to keep warm state for, only [`Self::close`] to
    /// release it deterministically.
    ephemeral: bool,
}

impl NodeRuntime {
    /// A generation-free runtime for one-shot callers (standalone probing,
    /// tests): session protocols get a throwaway pool per runtime. The
    /// caller MUST [`Self::close`] it when done — an unclosed ephemeral
    /// pool keeps its demux-held sessions (and their connections) open
    /// forever.
    pub fn ephemeral(node: &Node) -> Arc<Self> {
        Arc::new(Self {
            node: Arc::new(node.clone()),
            capabilities: OutboundCapabilities::for_node(node),
            runtime: crate::descriptor::descriptor(node.protocol)
                .generation_runtime
                .build(),
            ephemeral: true,
        })
    }

    pub(crate) fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Close every session-layer resource this runtime owns: AnyTLS pool
    /// sessions (connections + demux tasks) and cached QUIC clients
    /// (connection + endpoint driver). Terminal for the runtime; idempotent.
    pub async fn close(&self) {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.pool.shutdown(),
            ProtocolRuntime::Quic(runtime) => runtime.force_close_all().await,
            ProtocolRuntime::None => {}
        }
    }

    pub(crate) fn anytls_tls_connector(&self) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let ProtocolRuntime::AnyTls(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no AnyTLS runtime", self.node.name);
        };
        runtime.tls.get_or_build(&self.node)
    }

    /// Whether dialing through this runtime reuses already-warm session
    /// state instead of establishing — and then retaining — new state.
    /// Health probes key on this: a warm runtime is reused (the probe then
    /// measures the hot path), a cold one is bypassed for an ephemeral
    /// one-shot dial so a probe cycle never fills every node's pool with
    /// standby sessions. Runtimes without session state report warm: the
    /// generation and ephemeral forms of their dial are identical.
    pub fn has_warm_resources(&self) -> bool {
        match &self.runtime {
            ProtocolRuntime::None => true,
            ProtocolRuntime::AnyTls(runtime) => runtime
                .pool
                .has_usable_session(crate::proxy::anytls::POOL_KEY),
            ProtocolRuntime::Quic(runtime) => runtime.has_client(),
        }
    }

    /// Retained warm state of this runtime: live AnyTLS pool sessions and
    /// occupied QUIC client slots.
    pub fn warm_counts(&self) -> WarmCounts {
        match &self.runtime {
            ProtocolRuntime::None => WarmCounts::default(),
            ProtocolRuntime::AnyTls(runtime) => WarmCounts {
                sessions: runtime
                    .pool
                    .live_session_count(crate::proxy::anytls::POOL_KEY),
                clients: 0,
            },
            ProtocolRuntime::Quic(runtime) => WarmCounts {
                sessions: 0,
                clients: runtime.client_count(),
            },
        }
    }

    fn tls_connector_sample(&self) -> Option<(Instant, u64)> {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.sample(),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => None,
        }
    }

    fn evict_tls_connector_if_sample(&self, sample: (Instant, u64)) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.evict_if_sample(sample),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn tls_connector_loaded(&self) -> bool {
        match &self.runtime {
            ProtocolRuntime::AnyTls(runtime) => runtime.tls.is_loaded(),
            ProtocolRuntime::None | ProtocolRuntime::Quic(_) => false,
        }
    }
}

/// Full node-config equality for runtime reuse across generations, ignoring
/// the parse-time `created_at`/`updated_at` stamps (metadata, not dial
/// configuration).
fn same_node_config(a: &Node, b: &Node) -> bool {
    let (mut a, b) = (a.clone(), b.clone());
    a.created_at = b.created_at;
    a.updated_at = b.updated_at;
    a == b
}

/// Registry build/validation errors. A failure here aborts the reload
/// (the current generation stays live).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeRegistryError {
    #[error("node '{0}' has a nil UUID")]
    NilId(String),
    #[error("duplicate node UUID {0} (nodes '{1}' and '{2}')")]
    DuplicateId(uuid::Uuid, String, String),
    #[error("node '{node}' has invalid TLS configuration: {source}")]
    Tls {
        node: String,
        #[source]
        source: anyhow::Error,
    },
}

/// The single owner of per-node session runtimes for one config
/// generation. Rebuilt with the config; shutdown makes a generation
/// terminal before closing its owned pools so late work can never fall
/// through to a newer generation.
#[derive(Debug)]
pub struct OutboundRuntimeRegistry {
    nodes: HashMap<uuid::Uuid, Arc<NodeRuntime>>,
    terminal: AtomicBool,
    /// Runtimes a successor generation took over at the reload commit point.
    /// Recorded only after the successor is published, so an aborted reload
    /// leaves this generation's ownership untouched; drain/shutdown skip
    /// exactly these entries (the successor closes them as their full owner).
    moved_out: parking_lot::Mutex<HashSet<uuid::Uuid>>,
    /// Admission budget for concurrent proxied dials, scoped to this
    /// generation: a reload applies a changed limit to new work at once
    /// while in-flight dials keep their permits until they finish.
    dial_semaphore: Arc<tokio::sync::Semaphore>,
}

/// Shared cell swapped atomically on reload (same pattern as
/// `SharedGroupManager`).
pub type SharedRuntimeRegistry = Arc<parking_lot::RwLock<Arc<OutboundRuntimeRegistry>>>;

impl OutboundRuntimeRegistry {
    /// Build and validate a registry from the generation's node set.
    pub fn build(nodes: &[Node]) -> Result<Self, RuntimeRegistryError> {
        Self::build_reusing(
            nodes,
            honk_config::config::GlobalConfig::default().max_concurrent_dials,
            None,
        )
        .map(|(registry, _)| registry)
    }

    /// [`Self::build`] with an explicit dial-admission budget and optional
    /// reuse of the previous generation's runtimes for every node whose
    /// full config survived the reload unchanged (the content-derived ID
    /// alone is too narrow — it excludes dial fields like SNI, transport,
    /// and obfs). Returns the registry plus the ids of the runtimes taken
    /// from `previous`. Nothing is marked at build time: only a committed
    /// reload records the transfer on the old generation via
    /// [`Self::mark_moved_out`], so an aborted reload leaves the old
    /// generation's drain/shutdown semantics untouched.
    pub fn build_reusing(
        nodes: &[Node],
        max_concurrent_dials: usize,
        previous: Option<&Self>,
    ) -> Result<(Self, HashSet<uuid::Uuid>), RuntimeRegistryError> {
        let mut map = HashMap::with_capacity(nodes.len());
        let mut reused = HashSet::new();
        for node in nodes {
            if node.id.is_nil() {
                return Err(RuntimeRegistryError::NilId(node.name.clone()));
            }
            // Validate cheap, fail-closed TLS inputs before publishing the
            // generation. The heavyweight SSL_CTX/root store stays lazy.
            if node.tls {
                crate::tls::validate_connector_config(node).map_err(|source| {
                    RuntimeRegistryError::Tls {
                        node: node.name.clone(),
                        source,
                    }
                })?;
            }
            let reused_runtime = previous.and_then(|previous| {
                let runtime = previous.get(&node.id)?;
                same_node_config(&runtime.node, node).then_some(runtime)
            });
            let runtime = match reused_runtime {
                Some(runtime) => {
                    reused.insert(node.id);
                    runtime
                }
                None => Arc::new(NodeRuntime {
                    node: Arc::new(node.clone()),
                    capabilities: OutboundCapabilities::for_node(node),
                    runtime: crate::descriptor::descriptor(node.protocol)
                        .generation_runtime
                        .build(),
                    ephemeral: false,
                }),
            };
            if let Some(prev) = map.insert(node.id, runtime) {
                return Err(RuntimeRegistryError::DuplicateId(
                    node.id,
                    prev.node.name.clone(),
                    node.name.clone(),
                ));
            }
        }
        Ok((
            Self {
                nodes: map,
                terminal: AtomicBool::new(false),
                moved_out: parking_lot::Mutex::new(HashSet::new()),
                dial_semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent_dials.max(1))),
            },
            reused,
        ))
    }

    /// Wrap into the shared cell used by the control plane.
    pub fn into_shared(self) -> SharedRuntimeRegistry {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
    }

    pub fn get(&self, id: &uuid::Uuid) -> Option<Arc<NodeRuntime>> {
        self.nodes.get(id).map(Arc::clone)
    }

    /// Iterate every runtime of this generation (observability/gauges).
    pub fn values(&self) -> impl Iterator<Item = &Arc<NodeRuntime>> {
        self.nodes.values()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Retain the most recently used AnyTLS connectors as the hot working set.
    /// Idle entries are always released; under a broad burst, the newest 10%
    /// (at least eight) remain ready so common nodes avoid connector rebuilds.
    pub fn reap_tls_connectors(&self, now: Instant) -> usize {
        let anytls_count = self
            .nodes
            .values()
            .filter(|runtime| matches!(runtime.runtime, ProtocolRuntime::AnyTls(_)))
            .count();
        let target = anytls_count
            .saturating_mul(TLS_ACTIVE_RATIO_NUMERATOR)
            .div_ceil(TLS_ACTIVE_RATIO_DENOMINATOR)
            .max(TLS_ACTIVE_MIN)
            .min(anytls_count);
        let mut loaded: Vec<_> = self
            .nodes
            .values()
            .filter_map(|runtime| {
                runtime
                    .tls_connector_sample()
                    .map(|sample| (sample, runtime))
            })
            .collect();
        loaded.sort_unstable_by_key(|((used_at, _), _)| std::cmp::Reverse(*used_at));

        let mut evicted = 0;
        for (index, (sample, runtime)) in loaded.into_iter().enumerate() {
            if (index >= target || now.saturating_duration_since(sample.0) >= TLS_IDLE_RETENTION)
                && runtime.evict_tls_connector_if_sample(sample)
            {
                evicted += 1;
            }
        }
        evicted
    }

    /// Whether this generation has become terminal. Warm-up work must reject
    /// rather than consulting a replacement generation once this is true.
    pub fn is_shutdown(&self) -> bool {
        self.terminal.load(Ordering::Acquire)
    }

    /// Acquire one dial-admission permit from this generation's budget.
    pub async fn acquire_dial_permit(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.dial_semaphore)
            .acquire_owned()
            .await
            .expect("dial semaphore is never closed")
    }

    /// Make the generation unavailable to new generation-owned work without
    /// cutting streams that already own its sessions. The DNS runtime that
    /// captured this generation starts pool draining after its leases retire.
    pub fn begin_retirement(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    /// Record runtimes a published successor generation has taken over.
    /// Called only at the reload commit point (after the successor registry
    /// replaces this one); this generation then leaves those runtimes alone
    /// at drain/shutdown — the successor owns and closes them.
    pub fn mark_moved_out(&self, ids: impl IntoIterator<Item = uuid::Uuid>) {
        self.moved_out.lock().extend(ids);
    }

    /// Reject new pool work and let published sessions close after their last
    /// stream releases. Existing streams remain usable while draining.
    /// Runtimes transferred to a successor generation are left alone. QUIC
    /// connections need no drain step: new work is rejected by the terminal
    /// flag at the registry checks, and in-flight flows keep their
    /// connections until they finish.
    pub fn drain_session_pools(&self) {
        self.begin_retirement();
        let moved_out = self.moved_out.lock();
        for (id, runtime) in &self.nodes {
            if moved_out.contains(id) {
                continue;
            }
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.retire();
            }
        }
    }

    /// Force-close every owned runtime. Used only after process-level flow
    /// drain; unlike retirement this deliberately terminates all sessions.
    /// Idempotent, including after [`Self::begin_retirement`].
    pub async fn shutdown(&self) {
        self.terminal.store(true, Ordering::Release);
        let moved_out: HashSet<uuid::Uuid> = self.moved_out.lock().clone();
        for (id, runtime) in &self.nodes {
            if moved_out.contains(id) {
                continue;
            }
            match &runtime.runtime {
                ProtocolRuntime::AnyTls(anytls) => anytls.pool.shutdown(),
                ProtocolRuntime::Quic(quic) => quic.force_close_all().await,
                ProtocolRuntime::None => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;

    fn node(name: &str, protocol: NodeProtocol) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            protocol,
            address: "1.2.3.4:443".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn anytls_connector_is_lazy_shared_and_generation_local() {
        let node = node("anytls", NodeProtocol::AnyTLS);
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let first_runtime = first.get(&node.id).unwrap();
        assert!(!first_runtime.tls_connector_loaded());
        let first_connector = first_runtime.anytls_tls_connector().unwrap();
        assert!(first_runtime.tls_connector_loaded());
        let same_connector = first.get(&node.id).unwrap().anytls_tls_connector().unwrap();
        assert!(Arc::ptr_eq(&first_connector, &same_connector));

        let reloaded = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let reloaded_connector = reloaded
            .get(&node.id)
            .unwrap()
            .anytls_tls_connector()
            .unwrap();
        assert!(!Arc::ptr_eq(&first_connector, &reloaded_connector));
    }

    #[test]
    fn refreshed_connector_rejects_stale_reaper_sample() {
        let node = node("anytls", NodeProtocol::AnyTLS);
        let slot = TlsConnectorSlot::default();
        let first = slot.get_or_build(&node).unwrap();
        let stale_sample = slot.sample().unwrap();

        let refreshed = slot.get_or_build(&node).unwrap();
        assert!(Arc::ptr_eq(&first, &refreshed));
        assert!(!slot.evict_if_sample(stale_sample));
        assert!(slot.is_loaded());

        assert!(slot.evict_if_sample(slot.sample().unwrap()));
        assert!(!slot.is_loaded());
    }

    #[test]
    fn reap_keeps_recent_active_ratio_and_rebuilds_evicted_connectors() {
        let nodes: Vec<_> = (0..20)
            .map(|index| node(&format!("anytls-{index}"), NodeProtocol::AnyTLS))
            .collect();
        let registry = OutboundRuntimeRegistry::build(&nodes).unwrap();
        let loaded: Vec<_> = nodes
            .iter()
            .map(|node| {
                let runtime = registry.get(&node.id).unwrap();
                let connector = runtime.anytls_tls_connector().unwrap();
                (runtime, connector)
            })
            .collect();

        assert_eq!(registry.reap_tls_connectors(Instant::now()), 12);
        assert_eq!(
            loaded
                .iter()
                .filter(|(runtime, _)| runtime.tls_connector_loaded())
                .count(),
            8
        );
        let evicted = loaded
            .iter()
            .find(|(runtime, _)| !runtime.tls_connector_loaded())
            .unwrap();
        let rebuilt = evicted.0.anytls_tls_connector().unwrap();
        assert!(!Arc::ptr_eq(&evicted.1, &rebuilt));
    }

    #[test]
    fn reap_drops_idle_connector_even_inside_hot_ratio() {
        let node = node("anytls", NodeProtocol::AnyTLS);
        let registry = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let runtime = registry.get(&node.id).unwrap();
        runtime.anytls_tls_connector().unwrap();
        assert_eq!(
            registry.reap_tls_connectors(Instant::now() + TLS_IDLE_RETENTION),
            1
        );
        assert!(!runtime.tls_connector_loaded());
    }

    #[tokio::test]
    async fn warm_resources_report_session_state_only() {
        let anytls = node("anytls", NodeProtocol::AnyTLS);
        let trojan = node("trojan", NodeProtocol::Trojan);
        let tuic = node("tuic", NodeProtocol::Tuic);
        let registry =
            OutboundRuntimeRegistry::build(&[anytls.clone(), trojan.clone(), tuic.clone()])
                .unwrap();

        let anytls_runtime = registry.get(&anytls.id).unwrap();
        let tuic_runtime = registry.get(&tuic.id).unwrap();
        assert!(!anytls_runtime.has_warm_resources());
        assert!(!tuic_runtime.has_warm_resources());
        assert!(
            registry.get(&trojan.id).unwrap().has_warm_resources(),
            "session-less protocols have nothing to retain either way"
        );

        struct FakeClient;
        #[async_trait::async_trait]
        impl QuicRuntimeClient for FakeClient {
            fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
                self
            }
            async fn force_close(&self) {}
        }
        let ProtocolRuntime::Quic(quic) = &tuic_runtime.runtime else {
            panic!("tuic runtime expected");
        };
        quic.client(|| async { Ok(Arc::new(FakeClient)) })
            .await
            .unwrap();
        assert!(tuic_runtime.has_warm_resources());
    }

    #[tokio::test]
    async fn build_and_get_roundtrip() {
        let nodes = vec![
            node("a", NodeProtocol::AnyTLS),
            node("b", NodeProtocol::Trojan),
        ];
        let registry = OutboundRuntimeRegistry::build(&nodes).unwrap();
        assert_eq!(registry.len(), 2);
        let rt = registry.get(&nodes[0].id).unwrap();
        assert_eq!(rt.node.name, "a");
        assert!(rt.capabilities.multiplexed);
        assert!(rt.capabilities.udp);
        registry.shutdown().await; // terminal cleanup is idempotent
    }

    #[test]
    fn rejects_nil_uuid() {
        let mut n = node("nil", NodeProtocol::Trojan);
        n.id = uuid::Uuid::nil();
        let err = OutboundRuntimeRegistry::build(&[n]).unwrap_err();
        assert!(matches!(err, RuntimeRegistryError::NilId(_)));
    }

    #[test]
    fn rejects_duplicate_uuid() {
        let a = node("a", NodeProtocol::Trojan);
        let mut b = node("b", NodeProtocol::SS);
        b.id = a.id;
        let err = OutboundRuntimeRegistry::build(&[a, b]).unwrap_err();
        assert!(matches!(err, RuntimeRegistryError::DuplicateId(..)));
    }

    #[test]
    fn capabilities_matrix() {
        let anytls = node("x", NodeProtocol::AnyTLS);
        assert!(OutboundCapabilities::for_node(&anytls).multiplexed);
        let vmess = node("x", NodeProtocol::VMess);
        let caps = OutboundCapabilities::for_node(&vmess);
        assert!(!caps.multiplexed && !caps.udp);
        let hy2 = node("x", NodeProtocol::Hysteria2);
        let caps = OutboundCapabilities::for_node(&hy2);
        assert!(!caps.multiplexed && caps.udp);
    }

    #[test]
    fn build_reusing_reuses_unchanged_nodes_and_reports_them() {
        let unchanged = node("anytls", NodeProtocol::AnyTLS);
        let mut changed = node("tuic", NodeProtocol::Tuic);
        let first = OutboundRuntimeRegistry::build(&[unchanged.clone(), changed.clone()]).unwrap();
        let first_unchanged = first.get(&unchanged.id).unwrap();
        let first_changed = first.get(&changed.id).unwrap();

        changed.sni = Some("new.example.com".to_string());
        let (second, reused) = OutboundRuntimeRegistry::build_reusing(
            &[unchanged.clone(), changed.clone()],
            64,
            Some(&first),
        )
        .unwrap();
        assert_eq!(reused, HashSet::from([unchanged.id]));
        assert!(Arc::ptr_eq(
            &first_unchanged,
            &second.get(&unchanged.id).unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &first_changed,
            &second.get(&changed.id).unwrap()
        ));
    }

    #[tokio::test]
    async fn reused_runtime_is_closed_by_the_new_owner_only_after_commit() {
        let unchanged = node("anytls", NodeProtocol::AnyTLS);
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&unchanged)).unwrap();
        let (second, _) = OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&unchanged),
            64,
            Some(&first),
        )
        .unwrap();

        // A build alone transfers nothing: the old generation still closes
        // the runtime if the reload aborts before the commit point.
        first.shutdown().await;
        let ProtocolRuntime::AnyTls(anytls) = &second.get(&unchanged.id).unwrap().runtime else {
            panic!("anytls runtime expected");
        };
        assert!(
            anytls.pool.is_retired(),
            "aborted reload: old generation remains the owner"
        );

        // Committed transfer: the old generation skips the moved runtime;
        // the new generation closes it as its full owner.
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&unchanged)).unwrap();
        let (second, reused) = OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&unchanged),
            64,
            Some(&first),
        )
        .unwrap();
        first.mark_moved_out(reused);
        first.drain_session_pools();
        first.shutdown().await;
        let ProtocolRuntime::AnyTls(anytls) = &second.get(&unchanged.id).unwrap().runtime else {
            panic!("anytls runtime expected");
        };
        assert!(
            !anytls.pool.is_retired(),
            "committed reload: old generation leaves the moved runtime alone"
        );
        second.shutdown().await;
        assert!(
            anytls.pool.is_retired(),
            "the new generation owns the reused runtime's shutdown"
        );
    }

    #[test]
    fn build_reusing_ignores_parse_timestamps() {
        let mut parsed = node("trojan", NodeProtocol::Trojan);
        parsed.sni = Some("example.com".to_string());
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&parsed)).unwrap();
        let mut reparsed = parsed.clone();
        reparsed.created_at = chrono::Utc::now();
        reparsed.updated_at = chrono::Utc::now();
        let (second, _) = OutboundRuntimeRegistry::build_reusing(
            std::slice::from_ref(&reparsed),
            64,
            Some(&first),
        )
        .unwrap();
        assert!(Arc::ptr_eq(
            &first.get(&parsed.id).unwrap(),
            &second.get(&parsed.id).unwrap()
        ));
    }

    #[tokio::test]
    async fn quic_runtime_close_covers_clients_and_rejects_new_builds() {
        struct FakeClient(AtomicBool);
        #[async_trait::async_trait]
        impl QuicRuntimeClient for FakeClient {
            fn into_erased(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
                self
            }
            async fn force_close(&self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let runtime = QuicRuntime::new();
        let client: Arc<FakeClient> = runtime
            .client(|| async { Ok(Arc::new(FakeClient(AtomicBool::new(false)))) })
            .await
            .unwrap();
        runtime.force_close_all().await;
        assert!(client.0.load(Ordering::Acquire));
        assert!(
            runtime
                .client::<FakeClient, _, _>(|| async {
                    Ok(Arc::new(FakeClient(AtomicBool::new(false))))
                })
                .await
                .is_err(),
            "a closed QUIC runtime rejects new client builds"
        );
    }

    #[tokio::test]
    async fn retirement_is_terminal_and_shutdown_remains_idempotent() {
        let anytls = node("anytls", NodeProtocol::AnyTLS);
        let registry = OutboundRuntimeRegistry::build(&[anytls]).unwrap();
        assert!(!registry.is_shutdown());
        registry.begin_retirement();
        assert!(registry.is_shutdown());
        registry.shutdown().await;
        registry.shutdown().await;
        assert!(
            registry.is_shutdown(),
            "retirement and force shutdown remain terminal and idempotent"
        );
    }
}
