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
//! AnyTLS currently owns its node-local session pool here. Trojan-Go, H2,
//! and QUIC runtime ownership remain deferred to their dedicated migrations.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
        // vless, ssr, trojan-go.
        let udp = matches!(
            node.protocol,
            NodeProtocol::Socks5
                | NodeProtocol::SS
                | NodeProtocol::Trojan
                | NodeProtocol::Hysteria2
                | NodeProtocol::AnyTLS
                | NodeProtocol::Tuic
                | NodeProtocol::Juicity
        ) || (node.protocol == NodeProtocol::HTTP && node.name == "direct");
        Self {
            tcp: true,
            udp,
            multiplexed: node.mux
                || matches!(node.protocol, NodeProtocol::AnyTLS | NodeProtocol::TrojanGo),
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

/// AnyTLS session runtime: owns the node's `SessionPool` and its immutable
/// TLS setup. Keeping the connector here makes root-store, pin, and static
/// ECH parsing generation-owned rather than session-owned.
#[derive(Debug)]
pub struct AnyTlsRuntime {
    pub(crate) pool: Arc<crate::proxy::anytls::AnyTlsPool>,
    pub(crate) tls: Arc<crate::tls::TlsConnector>,
}

impl AnyTlsRuntime {
    fn new(node: &Node) -> anyhow::Result<Self> {
        Ok(Self {
            pool: Arc::new(crate::session::SessionPool::new(
                crate::proxy::anytls::session_pool_config(),
            )),
            tls: Arc::new(crate::tls::build_connector(node)?),
        })
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
            let protocol_runtime = match node.protocol {
                NodeProtocol::AnyTLS => {
                    ProtocolRuntime::AnyTls(AnyTlsRuntime::new(node).map_err(|source| {
                        RuntimeRegistryError::Tls {
                            node: node.name.clone(),
                            source,
                        }
                    })?)
                }
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
    fn anytls_connector_is_shared_within_generation_and_rebuilt_on_reload() {
        let node = node("anytls", NodeProtocol::AnyTLS);
        let first = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let first_runtime = first.get(&node.id).unwrap();
        let first_connector = match &first_runtime.runtime {
            ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.tls),
            _ => panic!("AnyTLS must own a TLS connector"),
        };
        let same_generation = first.get(&node.id).unwrap();
        let same_connector = match &same_generation.runtime {
            ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.tls),
            _ => panic!("AnyTLS must own a TLS connector"),
        };
        assert!(Arc::ptr_eq(&first_connector, &same_connector));

        let reloaded = OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
        let reloaded_runtime = reloaded.get(&node.id).unwrap();
        let reloaded_connector = match &reloaded_runtime.runtime {
            ProtocolRuntime::AnyTls(runtime) => Arc::clone(&runtime.tls),
            _ => panic!("AnyTLS must own a TLS connector"),
        };
        assert!(!Arc::ptr_eq(&first_connector, &reloaded_connector));
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
        let trojan_go = node("x", NodeProtocol::TrojanGo);
        let caps = OutboundCapabilities::for_node(&trojan_go);
        assert!(caps.multiplexed && !caps.udp);
        let vmess = node("x", NodeProtocol::VMess);
        let caps = OutboundCapabilities::for_node(&vmess);
        assert!(!caps.multiplexed && !caps.udp);
        let hy2 = node("x", NodeProtocol::Hysteria2);
        let caps = OutboundCapabilities::for_node(&hy2);
        assert!(!caps.multiplexed && caps.udp);
        let mut mux_vmess = node("x", NodeProtocol::VMess);
        mux_vmess.mux = true;
        assert!(OutboundCapabilities::for_node(&mux_vmess).multiplexed);
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
