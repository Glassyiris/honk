use serde::{Deserialize, Serialize};

/// Supported proxy node protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeProtocol {
    #[default]
    SS,
    SSR,
    Trojan,
    VMess,
    VLess,
    TrojanGo,
    Socks5,
    HTTP,
    Hysteria2,
    Tuic,
    Juicity,
    AnyTLS,
}

impl NodeProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeProtocol::SS => "ss",
            NodeProtocol::SSR => "ssr",
            NodeProtocol::Trojan => "trojan",
            NodeProtocol::VMess => "vmess",
            NodeProtocol::VLess => "vless",
            NodeProtocol::TrojanGo => "trojan-go",
            NodeProtocol::Socks5 => "socks5",
            NodeProtocol::HTTP => "http",
            NodeProtocol::Hysteria2 => "hysteria2",
            NodeProtocol::Tuic => "tuic",
            NodeProtocol::Juicity => "juicity",
            NodeProtocol::AnyTLS => "anytls",
        }
    }
}

impl std::str::FromStr for NodeProtocol {
    type Err = crate::ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ss" | "shadowsocks" => Ok(NodeProtocol::SS),
            "ssr" | "shadowsocksr" => Ok(NodeProtocol::SSR),
            "trojan" => Ok(NodeProtocol::Trojan),
            "vmess" => Ok(NodeProtocol::VMess),
            "vless" => Ok(NodeProtocol::VLess),
            "trojan-go" => Ok(NodeProtocol::TrojanGo),
            "socks5" => Ok(NodeProtocol::Socks5),
            "http" => Ok(NodeProtocol::HTTP),
            "hysteria2" => Ok(NodeProtocol::Hysteria2),
            "tuic" => Ok(NodeProtocol::Tuic),
            "juicity" => Ok(NodeProtocol::Juicity),
            "anytls" => Ok(NodeProtocol::AnyTLS),
            _ => Err(crate::ConfigError::UnknownProtocol(s.to_string())),
        }
    }
}

/// Dial mode for outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DialMode {
    /// IP mode: resolve domain to IP locally, then dial proxy by IP.
    /// Sniffing is disabled in this mode.
    Ip,
    /// Domain mode: sniff domain, verify it resolves to the destination IP,
    /// then dial the proxy using the domain name.
    Domain,
    /// Domain+: like domain but skip reality verification of the sniffed domain.
    /// Useful when DNS does not go through dae.
    #[serde(rename = "domain+")]
    DomainPlus,
    /// Domain++: like domain+ but force sniffing and re-route the connection
    /// based on the sniffed domain.
    #[serde(rename = "domain++")]
    DomainPlusPlus,
}

impl std::str::FromStr for DialMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ip" => Ok(Self::Ip),
            "domain" => Ok(Self::Domain),
            "domain+" => Ok(Self::DomainPlus),
            "domain++" => Ok(Self::DomainPlusPlus),
            _ => Err(()),
        }
    }
}

/// Outbound index type for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundIndex {
    /// Must rules (highest priority)
    MustRules,
    /// Direct connection
    Direct,
    /// Block connection
    Block,
    /// Control plane routing
    ControlPlaneRouting,
    /// Logical OR of multiple outbounds
    LogicalOr,
    /// Logical AND of multiple outbounds
    LogicalAnd,
    /// Custom index
    Index(u32),
}

/// Subscription type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionType {
    /// Simple subscription (e.g., base64 encoded node list)
    #[default]
    Simple,
    /// Clash-compatible subscription
    Clash,
    /// SIP008 subscription
    Sip008,
    /// Custom parser
    Custom,
}

/// DNS upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// Plain UDP DNS
    #[default]
    Udp,
    /// DNS over TCP
    Tcp,
    /// DNS over TLS
    Tls,
    /// DNS over HTTPS
    Https,
    /// DNS over QUIC
    Quic,
}
