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
//! AnyTLS currently owns its node-local session pool here. QUIC runtime
//! ownership remain deferred to their dedicated migrations.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
const TLS_ACTIVE_RATIO_NUMERATOR: usize = 1;
const TLS_ACTIVE_RATIO_DENOMINATOR: usize = 10;
const TLS_ACTIVE_MIN: usize = 8;
pub const TLS_IDLE_RETENTION: Duration = Duration::from_secs(10 * 60);
pub const TLS_REAP_INTERVAL: Duration = Duration::from_secs(60);

use honk_config::node::Node;
use honk_config::types::NodeProtocol;

/// What a node can do, derived from its protocol and config — the basis
/// for capability-based pooling decisions (e.g. the ready-pool allowlist
/// in phase 5, bare-pool eligibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundCapabilities {
    /// Carries TCP flows (all current protocols).
    pub tcp: bool,
    /// Carries UDP flows (dial_udp works end to end).
    pub udp: bool,
    /// Multiplexes many logical streams over one physical session —
    /// these protocols pool sessions, never bare TCP or ready streams.
    pub multiplexed: bool,
}

impl OutboundCapabilities {
    pub fn for_node(node: &Node) -> Self {
        // UDP support matrix (verified): direct, socks5, shadowsocks
        // (+2022), trojan, hysteria2, anytls, tuic, juicity. Not vmess,
        // vless, block.
        let udp = matches!(
            node.protocol,
            NodeProtocol::Socks5
                | NodeProtocol::SS
                | NodeProtocol::Trojan
                | NodeProtocol::Hysteria2
                | NodeProtocol::AnyTLS
                | NodeProtocol::Tuic
                | NodeProtocol::Juicity
                | NodeProtocol::Direct
        );
        Self {
            tcp: true,
            udp,
            multiplexed: matches!(node.protocol, NodeProtocol::AnyTLS),
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

/// Generation-owned storage for protocol-specific QUIC clients.
///
/// The mutex deliberately covers construction: TLS config construction may
/// perform ECH discovery, and admitting two first flows must still result in
/// one client/connection single-flight for this generation.
pub struct QuicRuntime {
    clients: tokio::sync::Mutex<HashMap<std::any::TypeId, Arc<dyn std::any::Any + Send + Sync>>>,
}

impl std::fmt::Debug for QuicRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicRuntime").finish_non_exhaustive()
    }
}

impl QuicRuntime {
    fn new() -> Self {
        Self {
            clients: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub async fn client<T, F, Fut>(&self, build: F) -> anyhow::Result<Arc<T>>
    where
        T: std::any::Any + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<T>>>,
    {
        let mut clients = self.clients.lock().await;
        let key = std::any::TypeId::of::<T>();
        if let Some(client) = clients.get(&key) {
            return Arc::downcast::<T>(Arc::clone(client))
                .map_err(|_| anyhow::anyhow!("QUIC client slot type mismatch"));
        }
        let client = build().await?;
        let erased: Arc<dyn std::any::Any + Send + Sync> = client.clone();
        clients.insert(key, erased);
        Ok(client)
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

/// The minimal per-node runtime entry (the honest, minimal
/// PreparedOutbound — not the full scaffold).
#[derive(Debug)]
pub struct NodeRuntime {
    /// Immutable node config for this generation.
    pub node: Arc<Node>,
    pub capabilities: OutboundCapabilities,
    pub runtime: ProtocolRuntime,
}

impl NodeRuntime {
    pub(crate) fn anytls_tls_connector(&self) -> anyhow::Result<Arc<crate::tls::TlsConnector>> {
        let ProtocolRuntime::AnyTls(runtime) = &self.runtime else {
            anyhow::bail!("node '{}' has no AnyTLS runtime", self.node.name);
        };
        runtime.tls.get_or_build(&self.node)
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
}

/// Shared cell swapped atomically on reload (same pattern as
/// `SharedGroupManager`).
pub type SharedRuntimeRegistry = Arc<parking_lot::RwLock<Arc<OutboundRuntimeRegistry>>>;

impl OutboundRuntimeRegistry {
    /// Build and validate a registry from the generation's node set.
    pub fn build(nodes: &[Node]) -> Result<Self, RuntimeRegistryError> {
        let mut map = HashMap::with_capacity(nodes.len());
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
            let protocol_runtime = match node.protocol {
                NodeProtocol::AnyTLS => ProtocolRuntime::AnyTls(AnyTlsRuntime::new()),
                NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity => {
                    ProtocolRuntime::Quic(QuicRuntime::new())
                }
                _ => ProtocolRuntime::None,
            };
            let runtime = Arc::new(NodeRuntime {
                node: Arc::new(node.clone()),
                capabilities: OutboundCapabilities::for_node(node),
                runtime: protocol_runtime,
            });
            if let Some(prev) = map.insert(node.id, Arc::clone(&runtime)) {
                return Err(RuntimeRegistryError::DuplicateId(
                    node.id,
                    prev.node.name.clone(),
                    node.name.clone(),
                ));
            }
        }
        Ok(Self {
            nodes: map,
            terminal: AtomicBool::new(false),
        })
    }

    /// Wrap into the shared cell used by the control plane.
    pub fn into_shared(self) -> SharedRuntimeRegistry {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
    }

    pub fn get(&self, id: &uuid::Uuid) -> Option<Arc<NodeRuntime>> {
        self.nodes.get(id).map(Arc::clone)
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

    /// Make the generation unavailable to new generation-owned work without
    /// cutting streams that already own its sessions. The DNS runtime that
    /// captured this generation starts pool draining after its leases retire.
    pub fn begin_retirement(&self) {
        self.terminal.store(true, Ordering::Release);
    }

    /// Reject new pool work and let published sessions close after their last
    /// stream releases. Existing streams remain usable while draining.
    pub fn drain_session_pools(&self) {
        self.begin_retirement();
        for runtime in self.nodes.values() {
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.retire();
            }
        }
    }

    /// Force-close every owned runtime. Used only after process-level flow
    /// drain; unlike retirement this deliberately terminates all sessions.
    /// Idempotent, including after [`Self::begin_retirement`].
    pub fn shutdown(&self) {
        self.terminal.store(true, Ordering::Release);
        for runtime in self.nodes.values() {
            if let ProtocolRuntime::AnyTls(anytls) = &runtime.runtime {
                anytls.pool.shutdown();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, protocol: NodeProtocol) -> Node {
        Node {
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

    #[test]
    fn build_and_get_roundtrip() {
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
        registry.shutdown(); // terminal cleanup is idempotent
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
    fn retirement_is_terminal_and_shutdown_remains_idempotent() {
        let anytls = node("anytls", NodeProtocol::AnyTLS);
        let registry = OutboundRuntimeRegistry::build(&[anytls]).unwrap();
        assert!(!registry.is_shutdown());
        registry.begin_retirement();
        assert!(registry.is_shutdown());
        registry.shutdown();
        registry.shutdown();
        assert!(
            registry.is_shutdown(),
            "retirement and force shutdown remain terminal and idempotent"
        );
    }
}
