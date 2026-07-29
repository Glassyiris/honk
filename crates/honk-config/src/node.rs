use serde::{Deserialize, Serialize};

/// Deserialize a group-tag list from either an array (`["hk", "jp"]`) or a
/// single delimited string (`"hk|jp"` / `"hk, jp"`). Entries themselves may
/// also contain `,` or `|` separators.
fn deserialize_group_tags<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum GroupTags {
        List(Vec<String>),
        One(String),
    }
    let raw = GroupTags::deserialize(deserializer)?;
    let parts = match raw {
        GroupTags::List(list) => list,
        GroupTags::One(s) => vec![s],
    };
    Ok(parts
        .iter()
        .flat_map(|s| s.split([',', '|']))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

use crate::types::NodeProtocol;

/// A proxy node definition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Node {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub name: String,
    pub protocol: NodeProtocol,
    pub address: String,
    #[serde(default)]
    pub host: String,
    pub port: u16,
    /// Username / password / UUID for auth
    #[serde(default)]
    pub username: Option<String>,
    /// Password / UUID for auth
    #[serde(default)]
    pub password: Option<String>,
    /// Encryption method (for SS/SSR)
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
    /// Transport protocol (tcp/udp/ws/grpc etc.)
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub tls: bool,
    /// TLS server name (SNI)
    #[serde(default)]
    pub sni: Option<String>,
    /// Skip certificate verification
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// Enable ECH (Encrypted Client Hello) for TLS/QUIC handshakes
    #[serde(default)]
    pub ech_enabled: bool,
    /// Base64-encoded ECHConfigList; implies ech_enabled when set
    #[serde(default)]
    pub ech_config: Option<String>,
    /// Path to a file containing a base64-encoded ECHConfigList
    #[serde(default)]
    pub ech_config_path: Option<String>,
    /// Network type for V2Ray (tcp/ws/grpc/h2/quic/kcp)
    #[serde(default)]
    pub network: Option<String>,
    /// WebSocket path
    #[serde(default)]
    pub ws_path: Option<String>,
    /// WebSocket host header
    #[serde(default)]
    pub ws_host: Option<String>,
    /// gRPC service name
    #[serde(default)]
    pub grpc_service: Option<String>,
    /// Hysteria2 authentication
    #[serde(default)]
    pub hy2_auth: Option<String>,
    /// Hysteria2 obfuscation
    #[serde(default)]
    pub hy2_obfs: Option<String>,
    /// Hysteria2 upload bandwidth in Mbps; enables the brutal sender when set
    #[serde(default)]
    pub hy2_up_mbps: Option<u32>,
    /// Hysteria2 download bandwidth in Mbps (advertised via `Hysteria-CC-RX`)
    #[serde(default)]
    pub hy2_down_mbps: Option<u32>,
    /// Hysteria2 port hopping list (`mport`: "20000-30000" or "p1,p2,...")
    #[serde(default)]
    pub hy2_port_hopping: Option<String>,
    /// Hysteria2 port hopping interval in seconds (`mhop`, default 30)
    #[serde(default)]
    pub hy2_hop_interval: Option<u64>,
    /// SHA-256 fingerprint of the peer leaf certificate (hex); replaces PKI
    /// and hostname verification when set (`pinSHA256`)
    #[serde(default)]
    pub tls_pin_sha256: Option<String>,
    /// Hysteria2 initial stream receive window in bytes
    /// (`initStreamReceiveWindow`)
    #[serde(default)]
    pub hy2_init_stream_recv_window: Option<u64>,
    /// Hysteria2 initial connection receive window in bytes
    /// (`initConnReceiveWindow`)
    #[serde(default)]
    pub hy2_init_conn_recv_window: Option<u64>,
    /// Hysteria2: disable QUIC path MTU discovery (`disablePathMTUDiscovery`)
    #[serde(default)]
    pub hy2_disable_mtu_discovery: Option<bool>,
    /// QUIC protocols (hy2/tuic/juicity): UDP **payload** size in bytes
    /// (share-link `mtu=`, valid range 1200..=65527, clamped). Applied to
    /// the send-side initial MTU, the PMTUD upper bound, and the endpoint's
    /// receive advertisement — it is NOT the link/IP MTU (IPv4 payload on
    /// a 1500 link is 1472; on PMTU-unsafe last miles keep the 1252
    /// default).
    #[serde(default)]
    pub quic_mtu: Option<u16>,
    /// TUIC UUID
    #[serde(default)]
    pub tuic_uuid: Option<String>,
    /// TUIC password
    #[serde(default)]
    pub tuic_password: Option<String>,
    /// TUIC congestion control
    #[serde(default)]
    pub tuic_congestion: Option<String>,
    /// TUIC ALPN (share-link `alpn=`; comma-separated for multiple).
    /// Defaults to `tuic` when unset — servers configured with e.g. `h3`
    /// (HTTP/3 camouflage) reject the handshake otherwise.
    #[serde(default)]
    pub tuic_alpn: Option<String>,
    /// TUIC: initial per-stream receive window (`initStreamReceiveWindow`).
    /// quinn's default (1.25MB) caps a stream at ~12.5MB/s per 100ms RTT —
    /// far too small for long-fat links; unset uses honk's larger default.
    #[serde(default)]
    pub tuic_init_stream_recv_window: Option<u64>,
    /// TUIC: initial connection-level receive window (`initConnReceiveWindow`).
    #[serde(default)]
    pub tuic_init_conn_recv_window: Option<u64>,
    /// Juicity UUID
    #[serde(default)]
    pub juicity_uuid: Option<String>,
    /// Juicity password
    #[serde(default)]
    pub juicity_password: Option<String>,
    /// AnyTLS password
    #[serde(default)]
    pub anytls_password: Option<String>,
    /// Minimum idle AnyTLS sessions to maintain per node.
    #[serde(default)]
    pub anytls_min_idle_session: Option<usize>,
    /// Seconds between AnyTLS idle session heartbeat checks.
    #[serde(default)]
    pub anytls_idle_session_check_interval: Option<u64>,
    /// Seconds before an idle AnyTLS session is evicted.
    #[serde(default)]
    pub anytls_idle_session_timeout: Option<u64>,
    /// Multiplexing enabled
    #[serde(default)]
    pub mux: bool,
    /// Outbound mark for routing
    #[serde(default)]
    pub mark: Option<u32>,
    /// Tags for classification
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub subscription_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub group_id: Option<uuid::Uuid>,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "chrono::Utc::now")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_transport() -> String {
    "tcp".to_string()
}

impl Node {
    /// Get the effective host (use host field or parse from address).
    pub fn host(&self) -> &str {
        if self.host.is_empty() {
            self.address.split(':').next().unwrap_or(&self.address)
        } else {
            &self.host
        }
    }
}

/// A group of nodes for load balancing / failover.
///
/// Modeled after sing-box's outbound groups: Selector (manual), URLTest
/// (auto), LoadBalance (round-robin) and Fallback (first alive, sticky).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Group {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub name: String,
    /// Group selection policy (Selector or URLTest).
    #[serde(default)]
    pub policy: GroupPolicy,
    /// Node UUIDs that belong to this group.
    #[serde(default)]
    pub nodes: Vec<uuid::Uuid>,
    /// Filter expressions for member resolution.
    #[serde(default)]
    pub filters: Vec<String>,
    /// Tags of nested sub-groups (sing-box style nested outbounds): each
    /// tag names another group whose current selection becomes a member
    /// candidate of this group. Cycles are broken at GroupManager
    /// construction (the cycle-closing edge is dropped with a warning).
    ///
    /// Accepts either an array (`groups = ["hk", "jp"]`) or a single
    /// delimited string (`groups = "hk|jp"` or `"hk, jp"`).
    #[serde(default, deserialize_with = "deserialize_group_tags")]
    pub groups: Vec<String>,
    /// Default node name for Selector policy.
    /// The first alive node is used if empty or the default is dead.
    #[serde(default)]
    pub default: Option<String>,
    /// Fallback outbound name when all nodes in this group are dead.
    /// Can be "direct", "block", another group name, or a node name.
    #[serde(default)]
    pub final_outbound: Option<String>,
    /// URL for health checks (overrides global tcp_check_url).
    #[serde(default)]
    pub check_url: Option<String>,
    /// Health check interval override in seconds.
    #[serde(default)]
    pub check_interval: Option<u64>,
    /// Minimum latency difference (ms) before switching the URLTest selection.
    /// Zero means switch on any improvement. Default: 50 (matches sing-box).
    #[serde(default = "default_tolerance")]
    pub tolerance: u64,
    /// Stop health checks after this many seconds of inactivity.
    /// `None` means never stop. Zero means never stop.
    #[serde(default)]
    pub idle_timeout: Option<u64>,
    /// Interrupt existing connections when the selected node changes.
    #[serde(default)]
    pub interrupt_connections: bool,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn default_tolerance() -> u64 {
    50
}

/// Group policy for node selection — matches sing-box's outbound group types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GroupPolicy {
    /// Manual selection — uses `Group.default` (or first alive node as fallback).
    /// The selected node stays until changed via API or the node dies.
    #[default]
    Selector,
    /// Auto-select lowest-latency node with tolerance (like sing-box urltest).
    /// Keeps separate selections for TCP and UDP (sing-box semantics).
    URLTest,
    /// Round-robin across alive nodes (dae `roundrobin`). Each group keeps an
    /// independent rotation counter.
    #[serde(alias = "roundrobin")]
    LoadBalance,
    /// First alive node in declaration order, pinned until it dies. A
    /// recovered higher-preference node does not immediately win the pin back.
    Fallback,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_policy_serde_lowercase() {
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"selector\"").unwrap(),
            GroupPolicy::Selector
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"urltest\"").unwrap(),
            GroupPolicy::URLTest
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"loadbalance\"").unwrap(),
            GroupPolicy::LoadBalance
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"fallback\"").unwrap(),
            GroupPolicy::Fallback
        );
        // dae-style alias for LoadBalance.
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"roundrobin\"").unwrap(),
            GroupPolicy::LoadBalance
        );
        assert_eq!(
            serde_json::to_string(&GroupPolicy::LoadBalance).unwrap(),
            "\"loadbalance\""
        );
        assert_eq!(
            serde_json::to_string(&GroupPolicy::URLTest).unwrap(),
            "\"urltest\""
        );
    }
}
