use serde::{Deserialize, Serialize};

use crate::dns::DnsConfig;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::routing::RoutingConfig;
use crate::subscription::Subscription;

/// Main honk configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

/// Global configuration matching dae `global { ... }` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_tproxy_port")]
    pub tproxy_port: u16,
    #[serde(default = "default_tproxy_mark")]
    pub tproxy_mark: u32,
    #[serde(default = "default_true")]
    pub tproxy_port_protect: bool,
    #[serde(default)]
    pub pprof_port: u16,
    #[serde(default)]
    pub so_mark_from_dae: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub disable_waiting_network: bool,
    #[serde(default)]
    pub lan_interface: Vec<String>,
    #[serde(default)]
    pub wan_interface: Vec<String>,
    #[serde(default)]
    pub auto_config_kernel_parameter: bool,
    #[serde(default = "default_tcp_check_urls")]
    pub tcp_check_url: Vec<String>,
    #[serde(default = "default_tcp_check_http_method")]
    pub tcp_check_http_method: String,
    #[serde(default = "default_udp_check_dns")]
    pub udp_check_dns: Vec<String>,
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_check_tolerance_ms")]
    pub check_tolerance_ms: u64,
    #[serde(default = "default_dial_mode")]
    pub dial_mode: String,
    // lan_tcp_mss is no longer used (link-local addressing eliminates the
    // need for iptables TCPMSS clamping).  Parsed for backward compatibility.
    #[serde(default = "default_lan_tcp_mss")]
    #[allow(dead_code)]
    pub lan_tcp_mss: u16,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default = "default_sniffing_timeout_ms")]
    pub sniffing_timeout_ms: u64,
    #[serde(default = "default_tls_impl")]
    pub tls_implementation: String,
    #[serde(default = "default_utls_imitate")]
    pub utls_imitate: String,
    #[serde(default)]
    pub tls_fragment: bool,
    #[serde(default)]
    pub tls_fragment_length: String,
    #[serde(default)]
    pub tls_fragment_interval: String,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default)]
    pub bootstrap_resolver: String,
    #[serde(default = "default_fallback_resolver")]
    pub fallback_resolver: String,
    #[serde(default)]
    pub bandwidth_max_tx: String,
    #[serde(default)]
    pub bandwidth_max_rx: String,
    #[serde(default = "default_udphop_interval_secs")]
    pub udphop_interval_secs: u64,
    /// Timeout for TCP connect (SYN/SYN-ACK) in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Timeout for DNS resolution in the control plane in milliseconds
    /// (used when resolving target domains for non-domain-capable proxies).
    #[serde(default = "default_dns_resolve_timeout_ms")]
    pub dns_resolve_timeout_ms: u64,
    /// Relay idle timeout: if no data flows in either direction for this
    /// many seconds, the relay is terminated. 0 disables the timeout.
    #[serde(default = "default_relay_idle_timeout_secs")]
    pub relay_idle_timeout_secs: u64,
    /// Number of proxy nodes to preconnect on startup (0 = auto: min(nodes, 8)).
    #[serde(default = "default_preconnect_node_count")]
    pub preconnect_node_count: usize,
}

fn default_tproxy_port() -> u16 {
    12345
}
fn default_tproxy_mark() -> u32 {
    0x08000000
}
fn default_log_level() -> String {
    "info".into()
}
fn default_true() -> bool {
    true
}
fn default_tcp_check_urls() -> Vec<String> {
    vec![
        "http://cp.cloudflare.com".into(),
        "1.1.1.1".into(),
        "2606:4700:4700::1111".into(),
    ]
}
fn default_tcp_check_http_method() -> String {
    "HEAD".into()
}
fn default_udp_check_dns() -> Vec<String> {
    vec![
        "dns.google:53".into(),
        "8.8.8.8".into(),
        "2001:4860:4860::8888".into(),
    ]
}
fn default_check_interval_secs() -> u64 {
    30
}
fn default_check_tolerance_ms() -> u64 {
    50
}
fn default_dial_mode() -> String {
    "domain".into()
}
fn default_lan_tcp_mss() -> u16 {
    0
}
fn default_sniffing_timeout_ms() -> u64 {
    30
}
fn default_tls_impl() -> String {
    "tls".into()
}
fn default_utls_imitate() -> String {
    "chrome_auto".into()
}
fn default_fallback_resolver() -> String {
    "8.8.8.8:53".into()
}
fn default_udphop_interval_secs() -> u64 {
    30
}
fn default_connect_timeout_ms() -> u64 {
    3000
}
fn default_dns_resolve_timeout_ms() -> u64 {
    2000
}
fn default_relay_idle_timeout_secs() -> u64 {
    300
}
fn default_preconnect_node_count() -> usize {
    0
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            tproxy_port: default_tproxy_port(),
            tproxy_mark: default_tproxy_mark(),
            tproxy_port_protect: true,
            pprof_port: 0,
            so_mark_from_dae: 0,
            log_level: default_log_level(),
            disable_waiting_network: false,
            lan_interface: vec![],
            wan_interface: vec![],
            auto_config_kernel_parameter: false,
            tcp_check_url: default_tcp_check_urls(),
            tcp_check_http_method: default_tcp_check_http_method(),
            udp_check_dns: default_udp_check_dns(),
            check_interval_secs: default_check_interval_secs(),
            check_tolerance_ms: default_check_tolerance_ms(),
            dial_mode: default_dial_mode(),
            lan_tcp_mss: default_lan_tcp_mss(),
            allow_insecure: false,
            sniffing_timeout_ms: default_sniffing_timeout_ms(),
            tls_implementation: default_tls_impl(),
            utls_imitate: default_utls_imitate(),
            tls_fragment: false,
            tls_fragment_length: String::new(),
            tls_fragment_interval: String::new(),
            mptcp: false,
            bootstrap_resolver: String::new(),
            fallback_resolver: default_fallback_resolver(),
            bandwidth_max_tx: String::new(),
            bandwidth_max_rx: String::new(),
            udphop_interval_secs: default_udphop_interval_secs(),
            connect_timeout_ms: default_connect_timeout_ms(),
            dns_resolve_timeout_ms: default_dns_resolve_timeout_ms(),
            relay_idle_timeout_secs: default_relay_idle_timeout_secs(),
            preconnect_node_count: default_preconnect_node_count(),
        }
    }
}

impl Config {
    /// The built-in `direct` node name (usable as a group member without
    /// being declared in the config).
    pub const BUILTIN_DIRECT_NODE: &'static str = "direct";

    /// Inject the built-in `direct` node unless the config already defines a
    /// node with that name. Idempotent.
    ///
    /// This makes `direct` a first-class group member (Selector/urltest
    /// candidate, delay-test target) without a placeholder `http://` node in
    /// the config file. The node maps to `DirectHandler` via the HTTP
    /// protocol; its address fields are unused.
    pub fn ensure_builtin_nodes(&mut self) {
        if self
            .nodes
            .iter()
            .any(|n| n.name == Self::BUILTIN_DIRECT_NODE)
        {
            return;
        }
        self.nodes.push(crate::node::Node {
            name: Self::BUILTIN_DIRECT_NODE.to_string(),
            protocol: crate::types::NodeProtocol::HTTP,
            ..Default::default()
        });
    }

    pub fn from_file(path: &str) -> Result<Self, crate::ConfigError> {
        let content = std::fs::read_to_string(path)?;

        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);

        // A recognized extension picks its format first and falls back to the
        // other structured formats.  Unknown or missing extensions keep the
        // historical dae -> TOML -> YAML -> JSON fallback chain.
        match ext.as_deref() {
            Some("json") => Self::from_json_str(&content)
                .or_else(|_| parse_toml(&content))
                .or_else(|_| parse_yaml(&content)),
            Some("yaml") | Some("yml") => parse_yaml(&content)
                .or_else(|_| parse_toml(&content))
                .or_else(|_| Self::from_json_str(&content)),
            Some("toml") => parse_toml(&content)
                .or_else(|_| parse_yaml(&content))
                .or_else(|_| Self::from_json_str(&content)),
            _ => crate::parser::parse_dae_config(&content)
                .or_else(|_| parse_toml(&content))
                .or_else(|_| parse_yaml(&content))
                .or_else(|_| Self::from_json_str(&content)),
        }
    }

    pub fn to_file(&self, path: &str) -> Result<(), crate::ConfigError> {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);

        let content = match ext.as_deref() {
            Some("json") => self.to_json_string()?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
            _ => toml::to_string_pretty(self)
                .map_err(|e| crate::ConfigError::Serialization(e.to_string()))?,
        };
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Serialize the configuration to a pretty-printed JSON string.
    pub fn to_json_string(&self) -> Result<String, crate::ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::ConfigError::Serialization(e.to_string()))
    }

    /// Parse a configuration from a JSON string.
    pub fn from_json_str(s: &str) -> Result<Self, crate::ConfigError> {
        serde_json::from_str(s).map_err(|e| crate::ConfigError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        for node in &self.nodes {
            if node.name.is_empty() {
                return Err(crate::ConfigError::Validation(
                    "Node name cannot be empty".into(),
                ));
            }
            if node.address.is_empty() && node.host.is_empty() {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' has no address or host",
                    node.name
                )));
            }
        }
        for group in &self.groups {
            if group.name.is_empty() {
                return Err(crate::ConfigError::Validation(
                    "Group name cannot be empty".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Parse a configuration from a TOML string.
fn parse_toml(content: &str) -> Result<Config, crate::ConfigError> {
    toml::from_str(content).map_err(|e| crate::ConfigError::Parse(e.to_string()))
}

/// Parse a configuration from a YAML string.
fn parse_yaml(content: &str) -> Result<Config, crate::ConfigError> {
    serde_yaml::from_str(content).map_err(|e| crate::ConfigError::Parse(e.to_string()))
}

#[cfg(test)]
mod builtin_nodes_tests {
    use super::*;

    #[test]
    fn test_ensure_builtin_nodes_injects_direct_once() {
        let mut config = Config::default();
        assert!(!config.nodes.iter().any(|n| n.name == "direct"));
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].name, "direct");
        assert_eq!(config.nodes[0].protocol, crate::types::NodeProtocol::HTTP);
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 1);
    }

    #[test]
    fn test_ensure_builtin_nodes_respects_user_defined() {
        let mut config = Config::default();
        config.nodes.push(crate::node::Node {
            name: "direct".into(),
            host: "custom.example.com".into(),
            ..Default::default()
        });
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].host, "custom.example.com");
    }
}
