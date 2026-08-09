//! Shared clash mode state (sing-box `mode` / `StoreMode` equivalent).
//!
//! Holds the current clash mode (`Rule` / `Global` / `Direct`) and the
//! GLOBAL group's current selection. One instance is shared between the
//! control plane (which applies the mode override on the outbound decision
//! path) and the clash API (which reads/writes it via `/configs` and
//! `/proxies/GLOBAL`). Values are restored from and persisted to cache.db.

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::{mpsc, oneshot};

type SharedEbpfBackend = Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>>;

const DATAPATH_FLAGS_CHANNEL_CAPACITY: usize = 16;
type CommandAck = oneshot::Sender<Result<(), String>>;

/// Clash mode + GLOBAL selection, shared via [`SharedModeState`].
#[derive(Debug, Clone)]
pub struct ModeState {
    /// Canonical clash mode: `"Rule"` | `"Global"` | `"Direct"`.
    pub mode: String,
    /// Current GLOBAL selection: a group name, a node name, or the virtual
    /// `"Proxy"` entry dashboards send for the default selection.
    pub global_selection: String,
}

/// Shared handle to the clash mode state.
pub type SharedModeState = Arc<parking_lot::RwLock<ModeState>>;

impl ModeState {
    /// Create a new state; an unrecognized `mode` falls back to `Rule`.
    pub fn new(mode: &str, global_selection: impl Into<String>) -> Self {
        Self {
            mode: Self::normalize(mode).unwrap_or_else(|| "Rule".to_string()),
            global_selection: global_selection.into(),
        }
    }

    /// Normalize a mode string to canonical case (`"global"` → `"Global"`).
    /// Returns `None` for values outside Rule/Global/Direct.
    pub fn normalize(mode: &str) -> Option<String> {
        if mode.eq_ignore_ascii_case("rule") {
            Some("Rule".to_string())
        } else if mode.eq_ignore_ascii_case("global") {
            Some("Global".to_string())
        } else if mode.eq_ignore_ascii_case("direct") {
            Some("Direct".to_string())
        } else {
            None
        }
    }

    /// Whether the current mode is `Direct`.
    pub fn is_direct(&self) -> bool {
        self.mode.eq_ignore_ascii_case("direct")
    }

    /// Whether the current mode is `Rule` — in `Rule` the mode override is
    /// the identity, so the eBPF datapath may offload non-`must` `direct`
    /// flows (subject to the domain-rule constraint).
    pub fn is_rule(&self) -> bool {
        self.mode.eq_ignore_ascii_case("rule")
    }

    /// Whether the current mode is `Global`.
    pub fn is_global(&self) -> bool {
        self.mode.eq_ignore_ascii_case("global")
    }

    /// The mode-dependent part of the eBPF datapath policy.
    pub fn direct_offload_mode_bits(&self) -> u32 {
        if self.is_direct() || (self.is_global() && self.global_selection == "direct") {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
        } else if self.is_rule() {
            honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
        } else {
            0
        }
    }

    /// Decide the effective outbound after clash-mode override.
    ///
    /// - `block` results and `must` results (dae `(must)` rules / eBPF
    ///   handoff must flag) are final routing decisions and are never
    ///   overridden — a block rule is an explicit safety decision and a
    ///   must rule is an explicit force, neither of which a mode switch
    ///   may bypass;
    /// - mode `Direct` forces `direct`;
    /// - mode `Global` forces the current GLOBAL selection when it
    ///   resolves (`selection_resolvable` — the caller owns the config);
    ///   an unresolvable selection keeps the routed outbound;
    /// - mode `Rule` (or anything else) keeps the routed outbound.
    pub fn override_outbound(
        &self,
        outbound_name: &str,
        must: bool,
        selection_resolvable: bool,
    ) -> String {
        if must || outbound_name == "block" {
            return outbound_name.to_string();
        }
        if self.is_direct() {
            return "direct".to_string();
        }
        if self.is_global() && !self.global_selection.is_empty() && selection_resolvable {
            return self.global_selection.clone();
        }
        outbound_name.to_string()
    }
}

#[derive(Debug)]
enum DatapathFlagsCommand {
    Initialize {
        static_flags: u32,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
        ack: CommandAck,
    },
    SetMode {
        mode: String,
        ack: CommandAck,
    },
    SetGlobalSelection {
        selection: String,
        ack: CommandAck,
    },
    SetStatic {
        flags: u32,
        ack: CommandAck,
    },
    FenceNfqueue {
        ack: CommandAck,
    },
    ReopenNfqueue {
        ack: CommandAck,
    },
    Disable {
        ack: CommandAck,
    },
}

/// Cloneable command handle for the sole datapath-flags writer.
#[derive(Clone)]
pub struct DatapathFlagsHandle {
    tx: mpsc::Sender<DatapathFlagsCommand>,
}

impl DatapathFlagsHandle {
    async fn request(
        &self,
        build: impl FnOnce(CommandAck) -> DatapathFlagsCommand,
    ) -> anyhow::Result<()> {
        let (ack, result) = oneshot::channel();
        self.tx
            .send(build(ack))
            .await
            .context("datapath flags coordinator stopped")?;
        result
            .await
            .context("datapath flags coordinator dropped an acknowledgement")?
            .map_err(anyhow::Error::msg)
    }

    pub async fn initialize(
        &self,
        static_flags: u32,
        nfqueue_enabled: bool,
        nfqueue_ready: bool,
    ) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::Initialize {
            static_flags,
            nfqueue_enabled,
            nfqueue_ready,
            ack,
        })
        .await
    }

    pub async fn set_mode(&self, mode: &str) -> anyhow::Result<()> {
        let mode = ModeState::normalize(mode).context("invalid clash mode")?;
        self.request(|ack| DatapathFlagsCommand::SetMode { mode, ack })
            .await
    }

    pub async fn set_global_selection(&self, selection: String) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::SetGlobalSelection { selection, ack })
            .await
    }

    pub async fn set_static(&self, flags: u32) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::SetStatic { flags, ack })
            .await
    }

    pub async fn fence_nfqueue(&self) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::FenceNfqueue { ack })
            .await
    }

    pub async fn reopen_nfqueue(&self) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::ReopenNfqueue { ack })
            .await
    }

    pub async fn disable(&self) -> anyhow::Result<()> {
        self.request(|ack| DatapathFlagsCommand::Disable { ack })
            .await
    }
}

#[derive(Clone)]
struct DatapathFlagsState {
    mode: ModeState,
    static_flags: u32,
    nfqueue_enabled: bool,
    nfqueue_ready: bool,
    reload_fenced: bool,
    initialized: bool,
}

impl DatapathFlagsState {
    fn managed_mask() -> u32 {
        honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_RULE_DIRECT
            | honk_ebpf_common::DATAPATH_FLAG_OFFLOAD_ALL
            | honk_ebpf_common::DATAPATH_FLAG_NFQ_ENABLED
            | honk_ebpf_common::DATAPATH_FLAG_NFQ_READY
    }

    fn sanitize_static(flags: u32) -> u32 {
        flags & !Self::managed_mask()
    }

    fn compose(&self) -> u32 {
        let mut flags = self.static_flags | self.mode.direct_offload_mode_bits();
        if self.nfqueue_enabled {
            flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_ENABLED;
            if self.nfqueue_ready && !self.reload_fenced {
                flags |= honk_ebpf_common::DATAPATH_FLAG_NFQ_READY;
            }
        }
        flags
    }
}

/// Actor owning mode mutation, persistence, and every datapath-flags write.
pub struct DatapathFlagsCoordinator {
    backend: SharedEbpfBackend,
    mode_state: SharedModeState,
    cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    state: DatapathFlagsState,
    rx: mpsc::Receiver<DatapathFlagsCommand>,
}

impl DatapathFlagsCoordinator {
    pub fn spawn(
        backend: Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::EbpfBackend>>>,
        mode_state: SharedModeState,
        cache_db: Option<Arc<crate::cachedb::CacheDb>>,
    ) -> (
        DatapathFlagsHandle,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let (tx, rx) = mpsc::channel(DATAPATH_FLAGS_CHANNEL_CAPACITY);
        let state = DatapathFlagsState {
            mode: mode_state.read().clone(),
            static_flags: 0,
            nfqueue_enabled: false,
            nfqueue_ready: false,
            reload_fenced: false,
            initialized: false,
        };
        let coordinator = Self {
            backend,
            mode_state,
            cache_db,
            state,
            rx,
        };
        let task = tokio::spawn(coordinator.run());
        (DatapathFlagsHandle { tx }, task)
    }

    async fn run(mut self) -> anyhow::Result<()> {
        while let Some(command) = self.rx.recv().await {
            let mut candidate = self.state.clone();
            let mut persist_mode = false;
            let mut persist_global = false;

            let quiesce = matches!(&command, DatapathFlagsCommand::FenceNfqueue { .. });
            let (ack, accepted, stop) = match command {
                DatapathFlagsCommand::Initialize {
                    static_flags,
                    nfqueue_enabled,
                    nfqueue_ready,
                    ack,
                } => {
                    let accepted = !candidate.initialized;
                    if accepted {
                        candidate.static_flags = DatapathFlagsState::sanitize_static(static_flags);
                        candidate.nfqueue_enabled = nfqueue_enabled;
                        candidate.nfqueue_ready = nfqueue_enabled && nfqueue_ready;
                        candidate.reload_fenced = false;
                        candidate.initialized = true;
                    }
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::SetMode { mode, ack } => {
                    let accepted = candidate.initialized;
                    candidate.mode.mode = mode;
                    persist_mode = accepted;
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::SetGlobalSelection { selection, ack } => {
                    let accepted = candidate.initialized;
                    candidate.mode.global_selection = selection;
                    persist_global = accepted;
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::SetStatic { flags, ack } => {
                    let accepted = candidate.initialized;
                    candidate.static_flags = DatapathFlagsState::sanitize_static(flags);
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::FenceNfqueue { ack } => {
                    let accepted = candidate.initialized;
                    candidate.nfqueue_ready = false;
                    candidate.reload_fenced = true;
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::ReopenNfqueue { ack } => {
                    let accepted = candidate.initialized;
                    candidate.reload_fenced = false;
                    candidate.nfqueue_ready = candidate.nfqueue_enabled;
                    (ack, accepted, false)
                }
                DatapathFlagsCommand::Disable { ack } => {
                    let accepted = candidate.initialized;
                    candidate.nfqueue_enabled = false;
                    candidate.nfqueue_ready = false;
                    candidate.reload_fenced = false;
                    (ack, accepted, accepted)
                }
            };

            if !accepted {
                let _ = ack.send(Err(
                    "datapath flags coordinator command is invalid in the current state"
                        .to_string(),
                ));
                continue;
            }

            let flags = candidate.compose();
            let mut backend = self.backend.write().await;
            let publish_result = match backend.set_datapath_flags(flags) {
                Ok(()) if quiesce => backend.quiesce_udp_staging(),
                result => result,
            };
            drop(backend);
            if let Err(error) = publish_result {
                let message = format!("failed to publish datapath flags {flags:#010x}: {error:#}");
                let _ = ack.send(Err(message.clone()));
                return Err(anyhow::Error::msg(message));
            }

            self.state = candidate;
            *self.mode_state.write() = self.state.mode.clone();
            if persist_mode && let Some(db) = &self.cache_db {
                db.save_clash_mode(&self.state.mode.mode);
            }
            if persist_global && let Some(db) = &self.cache_db {
                db.save_selector_choice("GLOBAL", &self.state.mode.global_selection);
            }
            let _ = ack.send(Ok(()));
            if stop {
                return Ok(());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_offload_mode_bits() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };
        assert_eq!(
            ModeState::new("rule", "proxy").direct_offload_mode_bits(),
            RULE
        );
        assert_eq!(
            ModeState::new("direct", "proxy").direct_offload_mode_bits(),
            ALL
        );
        assert_eq!(
            ModeState::new("global", "direct").direct_offload_mode_bits(),
            ALL
        );
        assert_eq!(
            ModeState::new("global", "Direct").direct_offload_mode_bits(),
            0
        );
        assert_eq!(
            ModeState::new("global", "proxy").direct_offload_mode_bits(),
            0
        );
    }

    #[test]
    fn test_normalize() {
        assert_eq!(ModeState::normalize("rule").as_deref(), Some("Rule"));
        assert_eq!(ModeState::normalize("GLOBAL").as_deref(), Some("Global"));
        assert_eq!(ModeState::normalize("Direct").as_deref(), Some("Direct"));
        assert_eq!(ModeState::normalize("bogus"), None);
    }

    #[test]
    fn test_new_fallback() {
        let s = ModeState::new("bogus", "proxy");
        assert_eq!(s.mode, "Rule");
        assert_eq!(s.global_selection, "proxy");
        assert!(!s.is_direct());
        assert!(!s.is_global());
    }

    #[test]
    fn test_override_outbound_rule_mode_keeps_routing() {
        let s = ModeState::new("rule", "proxy");
        assert_eq!(s.override_outbound("proxy", false, true), "proxy");
        assert_eq!(s.override_outbound("direct", false, true), "direct");
    }

    #[test]
    fn test_override_outbound_direct_and_global() {
        let direct = ModeState::new("direct", "proxy");
        assert_eq!(direct.override_outbound("proxy", false, true), "direct");

        let global = ModeState::new("global", "proxy");
        assert_eq!(global.override_outbound("other", false, true), "proxy");
        // Unresolvable GLOBAL selection keeps the routed outbound.
        assert_eq!(global.override_outbound("other", false, false), "other");
        // Empty selection behaves the same way.
        let empty = ModeState::new("global", "");
        assert_eq!(empty.override_outbound("other", false, true), "other");
    }

    #[test]
    fn test_override_outbound_block_never_overridden() {
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        assert_eq!(direct.override_outbound("block", false, true), "block");
        assert_eq!(global.override_outbound("block", false, true), "block");
    }

    /// dae must-rule semantics: a `(must)` routing result is final and
    /// must survive Direct/Global mode switches, exactly like `block`.
    #[test]
    fn test_override_outbound_must_never_overridden() {
        let rule = ModeState::new("rule", "proxy");
        let direct = ModeState::new("direct", "proxy");
        let global = ModeState::new("global", "proxy");
        for state in [&rule, &direct, &global] {
            assert_eq!(state.override_outbound("proxy", true, true), "proxy");
            assert_eq!(state.override_outbound("direct", true, true), "direct");
            assert_eq!(state.override_outbound("block", true, true), "block");
        }
    }

    type CoordinatorFixture = (
        DatapathFlagsHandle,
        SharedModeState,
        Arc<std::sync::Mutex<Vec<u32>>>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    );

    fn coordinator_fixture() -> CoordinatorFixture {
        let backend = crate::ebpf::mock::MockEbpfBackend::new();
        let writes = backend.datapath_flags_writes.clone();
        let backend: SharedEbpfBackend = Arc::new(tokio::sync::RwLock::new(Box::new(backend)));
        let state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "Proxy")));
        let (handle, task) = DatapathFlagsCoordinator::spawn(backend, Arc::clone(&state), None);
        (handle, state, writes, task)
    }

    #[tokio::test]
    async fn coordinator_fence_wins_racing_mode_global_and_static_updates() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES as STATIC,
            DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };

        let (handle, state, writes, task) = coordinator_fixture();
        handle.initialize(STATIC, true, true).await.unwrap();
        handle.fence_nfqueue().await.unwrap();
        let (mode_result, selection_result) = tokio::join!(
            handle.set_mode("Global"),
            handle.set_global_selection("direct".to_string()),
        );
        mode_result.unwrap();
        selection_result.unwrap();
        // Even a stale full policy word passed as static input cannot restore
        // coordinator-owned mode or NFQUEUE bits while the fence is latched.
        handle.set_static(STATIC | RULE | READY).await.unwrap();
        handle.reopen_nfqueue().await.unwrap();

        assert_eq!(state.read().mode, "Global");
        assert_eq!(state.read().global_selection, "direct");
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes.len(), 6);
        assert_eq!(writes[0], STATIC | RULE | ENABLED | READY);
        assert_eq!(writes[1], STATIC | RULE | ENABLED);
        assert!(writes[2..5].iter().all(|flags| flags & READY == 0));
        assert_eq!(writes[4], STATIC | ALL | ENABLED);
        assert_eq!(writes[5], STATIC | ALL | ENABLED | READY);

        handle.disable().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn coordinator_fence_quiesces_undelivered_staged_state() {
        use honk_ebpf_common::conn::{ConnState, UdpDecisionState};

        let key = honk_ebpf_common::redirect_need::TuplesKey::default();
        let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
        mock.seed_staged_udp_flow(
            &key,
            ConnState {
                state: UdpDecisionState::Pending as u8,
                decision_token: 41,
                ..ConnState::default()
            },
        );
        let backend: SharedEbpfBackend = Arc::new(tokio::sync::RwLock::new(Box::new(mock)));
        let state = Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "Proxy")));
        let (handle, task) = DatapathFlagsCoordinator::spawn(Arc::clone(&backend), state, None);

        handle.initialize(0, true, true).await.unwrap();
        handle.fence_nfqueue().await.unwrap();
        assert!(
            backend
                .read()
                .await
                .udp_conn_state_lookup(&key)
                .unwrap()
                .is_none()
        );

        handle.disable().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn accepted_command_commits_after_caller_cancels_acknowledgement() {
        use honk_ebpf_common::{
            DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
            DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        };

        let (handle, state, writes, task) = coordinator_fixture();
        handle.initialize(0, true, true).await.unwrap();

        let (ack, cancelled) = oneshot::channel();
        handle
            .tx
            .send(DatapathFlagsCommand::SetMode {
                mode: "Direct".to_string(),
                ack,
            })
            .await
            .unwrap();
        drop(cancelled);
        // This acknowledged command is a barrier after the cancelled caller's
        // accepted command.
        handle.fence_nfqueue().await.unwrap();

        assert_eq!(state.read().mode, "Direct");
        assert_eq!(
            writes.lock().unwrap().as_slice(),
            [RULE | ENABLED | READY, ALL | ENABLED | READY, ALL | ENABLED]
        );

        handle.disable().await.unwrap();
        task.await.unwrap().unwrap();
    }
}
