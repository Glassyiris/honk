//! Subscription manager for fetching and parsing proxy subscription URLs.
//!
//! Supports base64-encoded node lists (Simple format) and Clash-compatible
//! YAML subscriptions. Individual share links are parsed with the unified
//! [`Node::from_share_link`] parser from honk-config.

use honk_config::node::Node;
use honk_config::subscription::Subscription;
use honk_config::types::{NodeProtocol, SubscriptionType};

/// reqwest DNS resolver backed by honk's bootstrap resolver
/// (bypass-marked UDP/TCP), so subscription fetches do not depend on the
/// system resolver — which on a polluted network can hand back poisoned
/// answers and kill the subscription download.
struct BootstrapDnsResolve;

impl reqwest::dns::Resolve for BootstrapDnsResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = honk_outbound::bootstrap::resolve(&host).await?;
            let addrs: Vec<std::net::SocketAddr> = ips
                .into_iter()
                .map(|ip| std::net::SocketAddr::new(ip, 0))
                .collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Manager for fetching and parsing proxy subscriptions.
pub struct SubscriptionManager {
    client: reqwest::Client,
}

impl SubscriptionManager {
    pub fn new() -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .dns_resolver(std::sync::Arc::new(BootstrapDnsResolve))
            .build()?;
        Ok(Self { client })
    }

    /// Fetch a subscription URL and parse its contents into a list of nodes.
    pub async fn fetch(&self, sub: &Subscription) -> anyhow::Result<Vec<Node>> {
        let mut request = self.client.get(&sub.url);

        if let Some(ref ua) = sub.user_agent {
            request = request.header("User-Agent", ua);
        }

        for header in &sub.headers {
            request = request.header(&header.key, &header.value);
        }

        let response = request.send().await?;
        let content = response.text().await?;

        let nodes = match sub.sub_type {
            SubscriptionType::Simple | SubscriptionType::Sip008 => {
                parse_base64_subscription(&content, Some(sub.id))
            }
            SubscriptionType::Clash => parse_clash_subscription(&content, Some(sub.id)),
            SubscriptionType::Custom => parse_base64_subscription(&content, Some(sub.id))
                .or_else(|_| parse_clash_subscription(&content, Some(sub.id))),
        }?;

        // Providers legitimately list the same dialable endpoint under
        // several names; identical content-derived IDs would abort the
        // runtime registry build, so the first one wins.
        let mut seen = std::collections::HashSet::new();
        Ok(nodes
            .into_iter()
            .filter(|node| {
                seen.insert(node.id) || {
                    tracing::warn!(
                        node = %node.name,
                        "skipping subscription node with a duplicate endpoint identity"
                    );
                    false
                }
            })
            .collect())
    }
}

fn parse_base64_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let trimmed = content.trim();

    // Many providers return a raw list of node URIs even when the subscription
    // is labelled "simple". Try base64 first, then fall back to raw lines.
    let text = match decode_base64_flexible(trimmed) {
        Ok(decoded) => String::from_utf8(decoded)?,
        Err(e) => {
            tracing::debug!("subscription is not base64 ({}), parsing as raw URLs", e);
            trimmed.to_string()
        }
    };

    let uris: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    if uris.is_empty() {
        anyhow::bail!("no valid node URIs found in subscription");
    }

    let mut nodes = Vec::new();
    for uri in uris {
        match parse_node_uri(uri) {
            Ok(mut node) => {
                node.subscription_id = subscription_id;
                nodes.push(node);
            }
            Err(e) => {
                tracing::warn!("skipping unsupported node URI '{}': {}", uri, e);
            }
        }
    }

    if nodes.is_empty() {
        anyhow::bail!("no supported nodes found in subscription");
    }

    Ok(nodes)
}

fn decode_base64_flexible(input: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;

    let input = input.trim();

    if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(input) {
        return Ok(data);
    }

    let padded = if !input.len().is_multiple_of(4) {
        let padding = 4 - (input.len() % 4);
        let mut s = input.to_string();
        for _ in 0..padding {
            s.push('=');
        }
        s
    } else {
        input.to_string()
    };

    let data = base64::engine::general_purpose::STANDARD.decode(&padded)?;
    Ok(data)
}

fn parse_clash_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content)?;

    let proxies = yaml
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;

    let mut nodes = Vec::new();

    for proxy in proxies {
        let mapping = match proxy.as_mapping() {
            Some(m) => m,
            None => continue,
        };

        let get_str = |key: &str| -> Option<String> {
            mapping
                .get(serde_yaml::Value::String(key.to_string()))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

        let get_u16 = |key: &str| -> Option<u16> {
            mapping
                .get(serde_yaml::Value::String(key.to_string()))
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
        };

        let proxy_type = match get_str("type") {
            Some(t) => t,
            None => continue,
        };

        let protocol = match proxy_type.to_lowercase().as_str() {
            "socks5" => NodeProtocol::Socks5,
            "ss" | "shadowsocks" => NodeProtocol::SS,
            "trojan" => NodeProtocol::Trojan,
            "vmess" => NodeProtocol::VMess,
            "vless" => NodeProtocol::VLess,
            "hysteria2" | "hysteria" => NodeProtocol::Hysteria2,
            "tuic" => NodeProtocol::Tuic,
            "juicity" => NodeProtocol::Juicity,
            "anytls" => NodeProtocol::AnyTLS,
            _ => {
                tracing::warn!("skipping unsupported Clash proxy type: {}", proxy_type);
                continue;
            }
        };

        let server = match get_str("server") {
            Some(s) => s,
            None => continue,
        };

        let port = match get_u16("port") {
            Some(p) => p,
            None => continue,
        };

        let name = get_str("name").unwrap_or_else(|| format!("{}-{}:{}", proxy_type, server, port));

        let address = format!("{}:{}", server, port);

        let mut node = Node {
            name,
            protocol,
            address,
            host: server,
            port,
            ..Default::default()
        };

        if let Some(u) = get_str("username") {
            node.username = Some(u);
        }
        if let Some(p) = get_str("password") {
            node.password = Some(p);
        }
        if let Some(c) = get_str("cipher") {
            node.encryption = Some(c);
        }
        if let Some(p) = get_str("plugin") {
            node.plugin = Some(p);
        }
        if let Some(o) = get_str("plugin-opts") {
            node.plugin_opts = Some(o);
        }
        if let Some(n) = get_str("network") {
            node.transport = n;
        }

        if let Some(tls_val) = mapping.get(serde_yaml::Value::String("tls".to_string()))
            && let Some(b) = tls_val.as_bool()
        {
            node.tls = b;
        }
        if let Some(sni) = get_str("sni") {
            node.sni = Some(sni);
        }
        if let Some(skip) = mapping.get(serde_yaml::Value::String("skip-cert-verify".to_string()))
            && let Some(b) = skip.as_bool()
        {
            node.skip_cert_verify = b;
        }

        if let Some(path) = get_str("ws-path") {
            node.ws_path = Some(path);
        }
        if let Some(host) = get_str("ws-headers").or_else(|| get_str("ws-host")) {
            node.ws_host = Some(host);
        }

        if let Some(svc) = get_str("grpc-service") {
            node.grpc_service = Some(svc);
        }

        node.subscription_id = subscription_id;
        node.id = node.derive_id();
        nodes.push(node);
    }

    if nodes.is_empty() {
        anyhow::bail!("no supported proxies found in Clash subscription");
    }

    Ok(nodes)
}

/// Parse a single node share link via the unified parser in honk-config.
fn parse_node_uri(uri: &str) -> anyhow::Result<Node> {
    Node::from_share_link(uri).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn test_parse_socks5_uri() {
        let node = parse_node_uri("socks5://192.168.1.1:1080").unwrap();
        assert_eq!(node.protocol, NodeProtocol::Socks5);
        assert_eq!(node.host, "192.168.1.1");
        assert_eq!(node.port, 1080);
        assert_eq!(node.address, "192.168.1.1:1080");
        assert!(node.name.contains("socks5"));
    }

    #[test]
    fn test_parse_socks5_uri_with_fragment() {
        let node = parse_node_uri("socks5://10.0.0.1:1080#MySocks5").unwrap();
        assert_eq!(node.protocol, NodeProtocol::Socks5);
        assert_eq!(node.host, "10.0.0.1");
        assert_eq!(node.port, 1080);
        assert_eq!(node.name, "MySocks5");
    }

    #[test]
    fn test_parse_unsupported_protocol() {
        let result = parse_node_uri("unknown://host:1234");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown node protocol"));
    }

    #[test]
    fn test_parse_socks5_uri_with_auth() {
        let node = parse_node_uri("socks5://user:pass@10.0.0.1:1080").unwrap();
        assert_eq!(node.protocol, NodeProtocol::Socks5);
        assert_eq!(node.host, "10.0.0.1");
        assert_eq!(node.port, 1080);
        assert_eq!(node.username, Some("user".to_string()));
        assert_eq!(node.password, Some("pass".to_string()));
    }

    #[test]
    fn test_parse_base64_subscription() {
        let uris = [
            "socks5://192.168.1.1:1080#Node1",
            "socks5://10.0.0.1:2080#Node2",
        ];
        let joined = uris.join("\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
        let nodes = parse_base64_subscription(&encoded, None).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "Node1");
        assert_eq!(nodes[1].name, "Node2");
        assert_eq!(nodes[0].protocol, NodeProtocol::Socks5);
        assert_eq!(nodes[1].protocol, NodeProtocol::Socks5);
    }

    #[test]
    fn test_parse_base64_without_padding() {
        let uris = "socks5://10.0.0.1:1080#NoPad";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
        let no_pad = encoded.trim_end_matches('=');
        let nodes = parse_base64_subscription(no_pad, None).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "NoPad");
    }

    #[test]
    fn test_parse_base64_skips_unsupported() {
        let uris = ["socks5://192.168.1.1:1080#Valid", "unknown://host:1234"];
        let joined = uris.join("\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
        let nodes = parse_base64_subscription(&encoded, None).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Valid");
    }

    #[test]
    fn test_parse_base64_empty_result() {
        let uris = "unknown://host:1234\nanother-unsupported://x:1";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
        let result = parse_base64_subscription(&encoded, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_clash_subscription() {
        let yaml = r#"
proxies:
  - name: "My SOCKS5"
    type: socks5
    server: 192.168.1.1
    port: 1080
  - name: "My SS"
    type: ss
    server: 10.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "My SOCKS5");
        assert_eq!(nodes[0].protocol, NodeProtocol::Socks5);
        assert_eq!(nodes[0].host, "192.168.1.1");
        assert_eq!(nodes[0].port, 1080);
        assert_eq!(nodes[1].name, "My SS");
        assert_eq!(nodes[1].protocol, NodeProtocol::SS);
        assert_eq!(nodes[1].encryption, Some("aes-256-gcm".to_string()));
    }

    #[test]
    fn test_parse_clash_skips_removed_protocols() {
        // ssr/http/trojan-go support was removed: subscription entries are
        // skipped with a warning instead of failing the whole fetch.
        let yaml = r#"
proxies:
  - name: "SSR node"
    type: ssr
    server: 10.0.0.2
    port: 8388
  - name: "HTTP node"
    type: http
    server: 10.0.0.3
    port: 8080
  - name: "Trojan-Go node"
    type: trojan-go
    server: 10.0.0.4
    port: 443
  - name: "OK"
    type: socks5
    server: 10.0.0.1
    port: 1080
"#;
        let nodes = parse_clash_subscription(yaml, None).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "OK");
    }

    #[test]
    fn test_parse_clash_no_proxies() {
        let yaml = r#"
port: 7890
not-proxies: []
"#;
        let result = parse_clash_subscription(yaml, None);
        assert!(result.is_err());
    }
}
