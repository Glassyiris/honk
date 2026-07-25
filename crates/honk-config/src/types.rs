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
    /// DNS over TLS (DoT, RFC 7858)
    Tls,
    /// DNS over HTTPS / HTTP/2 (DoH, RFC 8484)
    Https,
    /// DNS over HTTP/3 (DoH3)
    H3,
    /// DNS over QUIC (DoQ, RFC 9250)
    Quic,
}

/// Serde `default = "..."` helper for boolean fields that default to true.
pub fn default_true() -> bool {
    true
}

/// Parse a duration string like `30s`, `1m`, `500ms` or `2h` into seconds.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix("ms") {
        return v.parse::<f64>().ok().map(|v| (v / 1000.0).ceil() as u64);
    }
    if let Some(v) = s.strip_suffix('s') {
        return v.parse().ok();
    }
    if let Some(v) = s.strip_suffix('m') {
        return v.parse::<u64>().ok().map(|v| v * 60);
    }
    if let Some(v) = s.strip_suffix('h') {
        return v.parse::<u64>().ok().map(|v| v * 3600);
    }
    s.parse().ok()
}
