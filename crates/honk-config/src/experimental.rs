use serde::{Deserialize, Serialize};

/// Clash-compatible REST API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClashApiConfig {
    /// Listen address for the REST API (e.g. "0.0.0.0:9999").
    /// API is disabled when empty.
    #[serde(default)]
    pub external_controller: String,
    /// Path to external UI static files (e.g. "zashboard").
    #[serde(default)]
    pub external_ui: String,
    /// Bearer token secret for API authentication.
    /// If empty, authentication is bypassed.
    #[serde(default)]
    pub secret: String,
    /// Default clash mode: "Rule", "Global", "Direct".
    #[serde(default = "default_clash_mode")]
    pub default_mode: String,
}

fn default_clash_mode() -> String {
    "Rule".to_string()
}

impl Default for ClashApiConfig {
    fn default() -> Self {
        Self {
            external_controller: String::new(),
            external_ui: String::new(),
            secret: String::new(),
            default_mode: "Rule".to_string(),
        }
    }
}

/// Cache file for persistent state (FakeIP, DNS cache, mode/selection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheFileConfig {
    /// Enable cache file persistence.
    #[serde(default)]
    pub enabled: bool,
    /// Path to cache database file. Defaults to "cache.db" if empty.
    #[serde(default = "default_cache_path")]
    pub path: String,
    /// Unique identifier for this router instance.
    #[serde(default)]
    pub cache_id: String,
    /// Store FakeIP mappings across restarts.
    #[serde(default)]
    pub store_fakeip: bool,
    /// Store DNS cache answers across restarts.
    #[serde(default)]
    pub store_dns: bool,
}

fn default_cache_path() -> String {
    "cache.db".to_string()
}

impl Default for CacheFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "cache.db".to_string(),
            cache_id: String::new(),
            store_fakeip: false,
            store_dns: false,
        }
    }
}

/// Experimental features configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExperimentalConfig {
    #[serde(default)]
    pub clash_api: ClashApiConfig,
    #[serde(default)]
    pub cache_file: CacheFileConfig,
    #[serde(default)]
    pub udp_nfqueue: UdpNfqueueConfig,
}

/// NFQUEUE UDP staged-decision pipeline (`experimental.udp_nfqueue`).
///
/// When enabled, `lan_ingress` parks eligible UDP flows (Rule-mode,
/// non-`must`, not route-time-offloadable `direct` decisions) with
/// `NFQUEUE_PENDING_MARK` instead of redirecting them into the TPROXY
/// control plane; the `honk_nfqueue` inet prerouting chain queues those
/// packets to userspace, which commits a verdict per packet.  A converged
/// direct decision therefore never crosses a userspace socket — unlike the
/// old drop-and-PTO offload, the client's first datagram is preserved and
/// the server always sees a single 5-tuple.
///
/// Disabled by default; when disabled the datapath is byte-for-byte the
/// pre-NFQUEUE one (the eBPF branch is gated on a runtime flag that is
/// never set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpNfqueueConfig {
    /// Master switch. Everything else is ignored while false.
    #[serde(default)]
    pub enabled: bool,
    /// Which flows may be staged. Only "quic" exists for now: flows that
    /// would otherwise need userspace QUIC SNI sniffing.
    #[serde(default = "default_nfq_scope")]
    pub scope: String,
    /// First NFQUEUE queue number; workers occupy queue_base..queue_base+workers-1.
    #[serde(default = "default_nfq_queue_base")]
    pub queue_base: u16,
    /// Number of NFQUEUE queues/workers; the kernel flow-hashes packets
    /// across queue_base..queue_base+workers-1, so a flow's packets always
    /// land on the same worker.
    #[serde(default = "default_nfq_workers")]
    pub workers: u16,
    /// Kernel NFQUEUE maxlen per queue. A full queue drops new packets
    /// (failure_policy "closed") or accepts them ("availability").
    #[serde(default = "default_nfq_queue_max_packets")]
    pub queue_max_packets: u32,
    /// Global budget of packet payload bytes held by the staging pool.
    #[serde(default = "default_nfq_global_copy_bytes")]
    pub global_copy_bytes: u64,
    /// Per-flow staged packet budget.
    #[serde(default = "default_nfq_per_flow_packets")]
    pub per_flow_packets: u32,
    /// Per-flow staged payload byte budget.
    #[serde(default = "default_nfq_per_flow_bytes")]
    pub per_flow_bytes: u64,
    /// Soft decision deadline: past it the flow is escalated (logged).
    #[serde(default = "default_nfq_decision_soft_timeout_ms")]
    pub decision_soft_timeout_ms: u32,
    /// Hard decision deadline: past it the flow falls back per failure_policy.
    #[serde(default = "default_nfq_decision_hard_timeout_ms")]
    pub decision_hard_timeout_ms: u32,
    /// "closed" (default): drop on queue/worker failure — a policy decision
    /// is never bypassed silently.  "availability": accept on queue full
    /// (kernel fail-open flag).  "legacy": stop producing new pending flows
    /// and use the old TPROXY path (not implemented yet).
    #[serde(default = "default_nfq_failure_policy")]
    pub failure_policy: String,
    /// Enable NFQA_CFG_F_GSO (receive GSO super-packets). Off: the kernel
    /// segments first, so userspace always parses plain UDP datagrams.
    #[serde(default)]
    pub gso: bool,
}

fn default_nfq_scope() -> String {
    "quic".to_string()
}
fn default_nfq_queue_base() -> u16 {
    320
}
fn default_nfq_workers() -> u16 {
    4
}
fn default_nfq_queue_max_packets() -> u32 {
    4096
}
fn default_nfq_global_copy_bytes() -> u64 {
    32 * 1024 * 1024
}
fn default_nfq_per_flow_packets() -> u32 {
    16
}
fn default_nfq_per_flow_bytes() -> u64 {
    128 * 1024
}
fn default_nfq_decision_soft_timeout_ms() -> u32 {
    20
}
fn default_nfq_decision_hard_timeout_ms() -> u32 {
    100
}
fn default_nfq_failure_policy() -> String {
    "closed".to_string()
}

impl Default for UdpNfqueueConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scope: default_nfq_scope(),
            queue_base: default_nfq_queue_base(),
            workers: default_nfq_workers(),
            queue_max_packets: default_nfq_queue_max_packets(),
            global_copy_bytes: default_nfq_global_copy_bytes(),
            per_flow_packets: default_nfq_per_flow_packets(),
            per_flow_bytes: default_nfq_per_flow_bytes(),
            decision_soft_timeout_ms: default_nfq_decision_soft_timeout_ms(),
            decision_hard_timeout_ms: default_nfq_decision_hard_timeout_ms(),
            failure_policy: default_nfq_failure_policy(),
            gso: false,
        }
    }
}

impl UdpNfqueueConfig {
    pub const FAILURE_POLICIES: [&'static str; 3] = ["closed", "availability", "legacy"];

    /// Field-value validation; invoked from `Config::validate`.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        if !Self::FAILURE_POLICIES.contains(&self.failure_policy.as_str()) {
            return Err(crate::ConfigError::Validation(format!(
                "experimental.udp_nfqueue.failure_policy must be one of {:?}",
                Self::FAILURE_POLICIES
            )));
        }
        if !self.enabled {
            return Ok(());
        }
        if self.scope != "quic" {
            return Err(crate::ConfigError::Validation(
                "experimental.udp_nfqueue.scope only supports \"quic\"".into(),
            ));
        }
        if self.workers == 0 {
            return Err(crate::ConfigError::Validation(
                "experimental.udp_nfqueue.workers must be >= 1".into(),
            ));
        }
        if self.queue_base as u32 + self.workers as u32 - 1 > u16::MAX as u32 {
            return Err(crate::ConfigError::Validation(format!(
                "experimental.udp_nfqueue: queue_base {} + workers {} exceeds the u16 queue number space",
                self.queue_base, self.workers
            )));
        }
        if self.queue_max_packets == 0 {
            return Err(crate::ConfigError::Validation(
                "experimental.udp_nfqueue.queue_max_packets must be >= 1".into(),
            ));
        }
        if self.decision_soft_timeout_ms >= self.decision_hard_timeout_ms {
            return Err(crate::ConfigError::Validation(
                "experimental.udp_nfqueue.decision_soft_timeout_ms must be < decision_hard_timeout_ms".into(),
            ));
        }
        Ok(())
    }
}
