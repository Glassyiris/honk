use serde::{Deserialize, Serialize};

use crate::dns::DnsConfig;
use crate::experimental::ExperimentalConfig;
use crate::group::Group;
use crate::node::Node;
use crate::routing::RoutingConfig;
use crate::subscription::Subscription;

/// Stable identity of the built-in `direct` node across reloads and restarts.
pub const DIRECT_NODE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000d1ec);
/// Stable identity of the built-in `block` node across reloads and restarts.
pub const BLOCK_NODE_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_4000_8000_00000000b10c);

/// `preconnect_node_count` sentinel for the dae `'auto'` value: preconnect
/// `min(nodes, 8)` nodes. Kept as a `usize` sentinel so the serde formats
/// stay plain integers; `0` means disabled.
pub const PRECONNECT_NODE_COUNT_AUTO: usize = usize::MAX;

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
    #[serde(default = "crate::types::default_true")]
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
    /// Number of proxy nodes to preconnect on startup. `0` disables the
    /// warm-up entirely; [`PRECONNECT_NODE_COUNT_AUTO`] (dae `'auto'`) picks
    /// `min(nodes, 8)`.
    #[serde(default = "default_preconnect_node_count")]
    pub preconnect_node_count: usize,
    /// Number of selected UDP nodes to warm on startup/reload. Zero strictly
    /// disables this independent warm-up path.
    #[serde(default = "default_udp_warm_node_count")]
    pub udp_warm_node_count: usize,
    /// Process-wide cap on concurrent proxied dials (connect + protocol
    /// handshake). Built-in direct/block dials are exempt — they are local
    /// connects already bounded by the connection admission limit.
    #[serde(default = "default_max_concurrent_dials")]
    pub max_concurrent_dials: usize,
}

fn default_tproxy_port() -> u16 {
    12345
}

/// Host CIDRs (`addr/32`, `addr/128`) for every global-scoped address on
/// `iface`, read via `ip -o addr show dev`. The literal `auto` resolves
/// through the default route's dev. Missing interfaces/tools yield an
/// empty list — best effort by design.
fn interface_host_cidrs(iface: &str) -> Vec<String> {
    let iface = iface.trim();
    let owned;
    let iface = if iface.eq_ignore_ascii_case("auto") {
        owned = default_route_iface().unwrap_or_default();
        if owned.is_empty() {
            return Vec::new();
        }
        owned.as_str()
    } else {
        iface
    };
    // getifaddrs(3) — no `ip` subprocess needed. Link-local addresses
    // (v4 169.254/16, v6 fe80::/10) are excluded, matching the old
    // "not scope link" filter.
    let mut cidrs = Vec::new();
    // SAFETY: getifaddrs allocates a linked list freed by freeifaddrs;
    // all pointers are checked before dereference.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return cidrs;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if name == iface && !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;
                if family == libc::AF_INET {
                    // s_addr is network byte order in memory — read it in
                    // native order to get the wire bytes as-is.
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr
                        .to_ne_bytes();
                    if !(a[0] == 169 && a[1] == 254) {
                        cidrs.push(format!("{}.{}.{}.{}/32", a[0], a[1], a[2], a[3]));
                    }
                } else if family == libc::AF_INET6 {
                    let a = (*(ifa.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr;
                    if !(a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
                        cidrs.push(format!("{}/128", std::net::Ipv6Addr::from(a)));
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    cidrs
}

/// Interface name owning the first default route, if any
/// (/proc/net/route — no `ip route` subprocess needed).
fn default_route_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut tokens = line.split_whitespace();
        let (Some(name), Some(dest)) = (tokens.next(), tokens.next()) else {
            continue;
        };
        if dest == "00000000" {
            return Some(name.to_string());
        }
    }
    None
}

fn default_tproxy_mark() -> u32 {
    DEFAULT_TPROXY_MARK
}

/// The only valid `global.tproxy_mark`: the eBPF datapath has the mark
/// compiled in, so userspace cannot honor any other value. honk-core pins
/// this against `honk_ebpf_common::TPROXY_MARK` with a unit test.
pub const DEFAULT_TPROXY_MARK: u32 = 0x0800_0000;
fn default_log_level() -> String {
    "info".into()
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
    PRECONNECT_NODE_COUNT_AUTO
}
fn default_udp_warm_node_count() -> usize {
    0
}
fn default_max_concurrent_dials() -> usize {
    64
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
            udp_warm_node_count: default_udp_warm_node_count(),
            max_concurrent_dials: default_max_concurrent_dials(),
        }
    }
}

impl Config {
    /// The built-in `direct` node name (usable as a group member without
    /// being declared in the config).
    pub const BUILTIN_DIRECT_NODE: &'static str = "direct";
    /// The built-in `block` node name.
    pub const BUILTIN_BLOCK_NODE: &'static str = "block";

    /// Inject the built-in `direct`/`block` nodes unless the config already
    /// defines nodes with those names. Idempotent.
    ///
    /// This makes both built-ins first-class group members (Selector/urltest
    /// candidates, delay-test targets) without declaring them in the config
    /// file; their address fields are unused.
    pub fn ensure_builtin_nodes(&mut self) {
        for builtin in [Self::builtin_direct_node(), Self::builtin_block_node()] {
            if !self.nodes.iter().any(|n| n.name == builtin.name) {
                self.nodes.push(builtin);
            }
        }
    }

    /// The built-in node registered under `name`, falling back to a fresh
    /// built-in definition when [`Self::ensure_builtin_nodes`] has not run.
    /// `None` for any non-built-in name.
    pub fn builtin_node(&self, name: &str) -> Option<crate::node::Node> {
        let fresh = match name {
            Self::BUILTIN_DIRECT_NODE => Self::builtin_direct_node(),
            Self::BUILTIN_BLOCK_NODE => Self::builtin_block_node(),
            _ => return None,
        };
        Some(
            self.nodes
                .iter()
                .find(|n| n.name == name)
                .cloned()
                .unwrap_or(fresh),
        )
    }

    /// A fresh built-in `direct` node definition.
    pub fn builtin_direct_node() -> crate::node::Node {
        crate::node::Node {
            id: DIRECT_NODE_ID,
            name: Self::BUILTIN_DIRECT_NODE.to_string(),
            protocol: crate::types::NodeProtocol::Direct,
            ..Default::default()
        }
    }

    /// A fresh built-in `block` node definition.
    pub fn builtin_block_node() -> crate::node::Node {
        crate::node::Node {
            id: BLOCK_NODE_ID,
            name: Self::BUILTIN_BLOCK_NODE.to_string(),
            protocol: crate::types::NodeProtocol::Block,
            ..Default::default()
        }
    }

    /// Inject must-direct routing rules for every address assigned to the
    /// configured lan/wan interfaces, so traffic to the gateway itself
    /// (admin UI, SSH, clash API) bypasses the proxy even when every node
    /// is dead. `must` rules never finalize, so user rules can still
    /// override; without any match these save local traffic from a
    /// proxied fallback (and from the eBPF fail-closed drop when the
    /// fallback outbound is down).
    ///
    /// Best-effort and idempotent: interfaces that cannot be read
    /// (missing, `auto` without a default route) are skipped.
    pub fn ensure_local_direct_rules(&mut self) {
        const MARK: &str = "__local_direct_";
        if self.routing.rules.iter().any(|r| r.name.starts_with(MARK)) {
            return;
        }
        let mut cidrs = Vec::new();
        for iface in &self.global.lan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        for iface in &self.global.wan_interface {
            cidrs.extend(interface_host_cidrs(iface));
        }
        cidrs.sort();
        cidrs.dedup();
        for cidr in cidrs {
            self.routing.rules.push(crate::routing::RoutingRule {
                name: format!("{MARK}{cidr}"),
                condition: crate::routing::RoutingCondition {
                    ip: vec![cidr.clone()],
                    ..Default::default()
                },
                outbound: crate::routing::RoutingOutbound::Simple("direct".to_string()),
                priority: 0,
                must: true,
                mark: 0,
            });
        }
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
        let mut config = match ext.as_deref() {
            Some("json") => Self::from_json_str(&content)
                .or_else(|_| parse_toml(&content))
                .or_else(|_| parse_yaml(&content)),
            Some("yaml") | Some("yml") => parse_yaml(&content)
                .or_else(|_| parse_toml(&content))
                .or_else(|_| Self::from_json_str(&content)),
            Some("toml") => parse_toml(&content)
                .or_else(|_| parse_yaml(&content))
                .or_else(|_| Self::from_json_str(&content)),
            _ => match crate::parser::parse_dae_config_file(path) {
                Ok(config) => Ok(config),
                // An include directive was recognized, so returning a
                // structured-format error would hide the actionable cause.
                Err(err @ crate::ConfigError::Include(_)) => Err(err),
                Err(_) => parse_toml(&content)
                    .or_else(|_| parse_yaml(&content))
                    .or_else(|_| Self::from_json_str(&content)),
            },
        }?;
        config.derive_node_ids();
        Ok(config)
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
        let mut config: Self =
            serde_json::from_str(s).map_err(|e| crate::ConfigError::Parse(e.to_string()))?;
        config.derive_node_ids();
        Ok(config)
    }

    /// Re-derive every node's content-based ID ([`Node::derive_id`]) after
    /// load. Stored/serde-default IDs are discarded so identity always
    /// reflects the current content; the built-in direct/block nodes keep
    /// their fixed IDs.
    fn derive_node_ids(&mut self) {
        for node in &mut self.nodes {
            if node.id == DIRECT_NODE_ID || node.id == BLOCK_NODE_ID {
                continue;
            }
            node.id = node.derive_id();
        }
    }

    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        // The eBPF datapath has the mark compiled in; userspace cannot inject
        // a different value, so a custom mark would silently break the proxy.
        if self.global.tproxy_mark != default_tproxy_mark() {
            return Err(crate::ConfigError::Validation(format!(
                "global.tproxy_mark must be {:#x} (compiled into the eBPF datapath)",
                default_tproxy_mark()
            )));
        }
        // skb->mark bits 29/30 are owned by the datapath
        // (NFQUEUE_PENDING_MARK / CLASSIFIED_MARK); a user mark overlapping
        // them would corrupt the NFQUEUE staging match and the bridge
        // double-attach dedup.
        let reserved = honk_ebpf_common::SKB_MARK_RESERVED_MASK;
        let mut user_marks: Vec<(String, u32)> = vec![
            ("global.tproxy_mark".into(), self.global.tproxy_mark),
            (
                "global.so_mark_from_dae".into(),
                self.global.so_mark_from_dae,
            ),
        ];
        for (i, rule) in self.routing.rules.iter().enumerate() {
            let name = if rule.name.is_empty() {
                format!("routing.rules[{i}].mark")
            } else {
                format!("routing rule '{}'.mark", rule.name)
            };
            user_marks.push((name, rule.mark));
        }
        for (what, mark) in user_marks {
            if mark & reserved != 0 {
                return Err(crate::ConfigError::Validation(format!(
                    "{what} ({mark:#x}) overlaps datapath-reserved skb mark bits {reserved:#x}"
                )));
            }
        }
        self.experimental.udp_nfqueue.validate()?;
        // Content-derived IDs collide when two nodes share protocol, server,
        // and credentials — they are the same endpoint and cannot coexist
        // in the runtime registry.
        let mut ids: std::collections::HashMap<uuid::Uuid, &str> = std::collections::HashMap::new();
        for node in &self.nodes {
            if node.id.is_nil() {
                continue;
            }
            if let Some(prev) = ids.insert(node.id, &node.name)
                && prev != node.name
            {
                return Err(crate::ConfigError::Validation(format!(
                    "Nodes '{}' and '{}' derive the same ID (identical protocol, server and credentials)",
                    prev, node.name
                )));
            }
        }
        for node in &self.nodes {
            // The injected built-ins carry no dialable address by design.
            if node.id == DIRECT_NODE_ID || node.id == BLOCK_NODE_ID {
                continue;
            }
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
            // Reject unknown transports at load time instead of silently
            // degrading to raw TCP at dial time.
            if !matches!(node.transport.as_str(), "" | "tcp" | "ws" | "grpc") {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' has unsupported transport '{}' (expected tcp/ws/grpc)",
                    node.name, node.transport
                )));
            }
            // direct/block are the injected built-ins; a user node may
            // neither take their names nor their protocols.
            if matches!(
                node.name.as_str(),
                Self::BUILTIN_DIRECT_NODE | Self::BUILTIN_BLOCK_NODE
            ) || matches!(
                node.protocol,
                crate::types::NodeProtocol::Direct | crate::types::NodeProtocol::Block
            ) {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{}' uses a name or protocol reserved for the built-in direct/block nodes",
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
    fn test_validate_rejects_unknown_transport() {
        let mut config = Config::default();
        config.nodes.push(crate::node::Node {
            name: "bad".into(),
            address: "1.2.3.4:443".into(),
            transport: "kcp".into(),
            ..Default::default()
        });
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("unsupported transport"),
            "unknown transport must be rejected at load: {err}"
        );
        for ok in ["", "tcp", "ws", "grpc"] {
            config.nodes[0].transport = ok.into();
            assert!(config.validate().is_ok(), "transport '{ok}' must pass");
        }
    }

    #[test]
    fn test_validate_rejects_reserved_builtin_names_and_protocols() {
        for (name, protocol) in [
            ("direct", crate::types::NodeProtocol::Socks5),
            ("block", crate::types::NodeProtocol::Socks5),
            ("web-proxy", crate::types::NodeProtocol::Direct),
            ("web-proxy", crate::types::NodeProtocol::Block),
        ] {
            let mut config = Config::default();
            config.nodes.push(crate::node::Node {
                name: name.into(),
                address: "1.2.3.4:8080".into(),
                protocol,
                ..Default::default()
            });
            let err = config.validate().unwrap_err();
            assert!(
                err.to_string().contains("reserved for the built-in"),
                "{name}/{protocol:?} must be rejected: {err}"
            );
        }
    }

    #[test]
    fn test_validate_rejects_derived_id_conflicts() {
        let node = |name: &str| {
            let mut n =
                crate::node::Node::from_share_link("trojan://secret@example.com:443").unwrap();
            n.name = name.into();
            n
        };
        let mut config = Config::default();
        config.nodes.push(node("alpha"));
        config.nodes.push(node("beta"));
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("'alpha' and 'beta'"),
            "conflict error must name both nodes: {err}"
        );
        // A credential change breaks the tie.
        config.nodes[1].password = Some("other".into());
        config.nodes[1].id = config.nodes[1].derive_id();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ensure_builtin_nodes_injects_direct_and_block_once() {
        let mut config = Config::default();
        assert!(!config.nodes.iter().any(|n| n.name == "direct"));
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert_eq!(config.nodes[0].name, "direct");
        assert_eq!(config.nodes[0].id, DIRECT_NODE_ID);
        assert_eq!(config.nodes[0].protocol, crate::types::NodeProtocol::Direct);
        assert_eq!(config.nodes[1].name, "block");
        assert_eq!(config.nodes[1].id, BLOCK_NODE_ID);
        assert_eq!(config.nodes[1].protocol, crate::types::NodeProtocol::Block);
        config.ensure_builtin_nodes();
        assert_eq!(config.nodes.len(), 2);
        assert!(config.validate().is_ok(), "built-ins stay valid");
    }

    #[test]
    fn test_builtin_node_resolves_registered_or_fresh() {
        let mut config = Config::default();
        let fresh = config.builtin_node("direct").unwrap();
        assert_eq!(fresh.id, DIRECT_NODE_ID);
        assert!(config.builtin_node("proxy").is_none());
        let mut registered = Config::builtin_block_node();
        registered.subscription_id = Some(uuid::Uuid::new_v4());
        config.nodes.push(registered.clone());
        assert_eq!(
            config.builtin_node("block").unwrap().subscription_id,
            registered.subscription_id,
            "a registered built-in wins over the fresh definition"
        );
    }

    #[test]
    fn test_ensure_local_direct_rules_injects_and_is_idempotent() {
        let mut config = Config::default();
        config.global.wan_interface =
            vec!["lo".to_string(), "definitely-not-an-iface0".to_string()];
        config.ensure_local_direct_rules();

        let injected: Vec<_> = config
            .routing
            .rules
            .iter()
            .filter(|r| r.name.starts_with("__local_direct_"))
            .collect();
        // lo carries 127.0.0.1 and ::1 (host scope) on every Linux host.
        assert!(
            injected
                .iter()
                .any(|r| r.condition.ip == vec!["127.0.0.1/32".to_string()]),
            "loopback v4 must be injected: {injected:?}"
        );
        assert!(injected.iter().all(|r| r.must));
        assert!(injected.iter().all(
            |r| matches!(&r.outbound, crate::routing::RoutingOutbound::Simple(o) if o == "direct")
        ));

        let count = config.routing.rules.len();
        config.ensure_local_direct_rules();
        assert_eq!(config.routing.rules.len(), count, "must be idempotent");
    }
}
