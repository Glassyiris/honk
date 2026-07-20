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
    /// Server address (host:port)
    pub address: String,
    /// Server host
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
    /// TUIC UUID
    #[serde(default)]
    pub tuic_uuid: Option<String>,
    /// TUIC password
    #[serde(default)]
    pub tuic_password: Option<String>,
    /// TUIC congestion control
    #[serde(default)]
    pub tuic_congestion: Option<String>,
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
    /// Subscription ID this node belongs to
    #[serde(default)]
    pub subscription_id: Option<uuid::Uuid>,
    /// Group ID this node belongs to
    #[serde(default)]
    pub group_id: Option<uuid::Uuid>,
    /// Created at
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Updated at
    #[serde(default = "chrono::Utc::now")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_transport() -> String {
    "tcp".to_string()
}

impl Node {
    /// Build the node's connection URL string.
    /// Returns something like "ss://..." or "trojan://..."
    pub fn to_uri(&self) -> String {
        format!("{}://{}:{}", self.protocol.as_str(), self.host(), self.port)
    }

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
/// Modeled after sing-box's outbound groups: Selector (manual) and URLTest (auto).
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
