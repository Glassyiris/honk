//! Subscription manager for fetching and parsing proxy subscription URLs.
//!
//! Supports base64-encoded node lists (Simple format) and Clash-compatible
//! YAML subscriptions. Individual share links are parsed with the unified
//! [`Node::from_share_link`] parser from honk-config.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use honk_config::node::Node;
use honk_config::subscription::Subscription;
use honk_config::types::{NodeProtocol, SubscriptionType};
use sha2::{Digest as _, Sha256};

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

const SUBSCRIPTION_STORE_DIR: &str = ".sub";

fn default_store_root() -> PathBuf {
    honk_config::paths::resolve_artifact_path_with_legacy(
        SUBSCRIPTION_STORE_DIR,
        Some(Path::new(SUBSCRIPTION_STORE_DIR)),
    )
}

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone, Debug)]
pub struct SubscriptionStore {
    root: Arc<PathBuf>,
}

impl SubscriptionStore {
    /// Open the subscription store below `global.data_dir`, retaining an
    /// existing legacy `./.sub` store during the data-directory cutover.
    pub fn in_data_dir() -> anyhow::Result<Self> {
        let root = default_store_root();
        let preferred = honk_config::paths::resolve_artifact_path(SUBSCRIPTION_STORE_DIR);
        if root == preferred {
            return Self::open(root);
        }
        match Self::open(root.clone()) {
            Ok(store) => {
                tracing::warn!(
                    legacy = %root.display(),
                    preferred = %preferred.display(),
                    "using legacy subscription store; move it to the runtime data directory"
                );
                Ok(store)
            }
            Err(error) => {
                tracing::warn!(
                    legacy = %root.display(),
                    preferred = %preferred.display(),
                    %error,
                    "legacy subscription store is unusable; starting a data-directory store"
                );
                Self::open(preferred)
            }
        }
    }

    fn open(root: PathBuf) -> anyhow::Result<Self> {
        ensure_store_directory(&root)?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub fn root(&self) -> &Path {
        self.root.as_path()
    }

    pub async fn load_nodes(&self, sub: &Subscription) -> anyhow::Result<Option<Vec<Node>>> {
        let path = self.path_for(sub);
        let content = match tokio::task::spawn_blocking(move || read_store_file(&path)).await? {
            Ok(content) => content,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        parse_subscription_content(sub, &content)
            .with_context(|| format!("invalid stored subscription '{}'", sub.name))
            .map(Some)
    }

    async fn store_content(&self, sub: &Subscription, content: String) -> anyhow::Result<()> {
        let root = Arc::clone(&self.root);
        let destination = self.path_for(sub);
        tokio::task::spawn_blocking(move || {
            write_store_file(&root, &destination, content.as_bytes())
        })
        .await??;
        Ok(())
    }

    fn path_for(&self, sub: &Subscription) -> PathBuf {
        self.root.join(subscription_filename(sub))
    }
}

fn subscription_filename(sub: &Subscription) -> String {
    fn add_part(hasher: &mut Sha256, value: &[u8]) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let mut hasher = Sha256::new();
    add_part(&mut hasher, sub.url.as_bytes());
    add_part(
        &mut hasher,
        sub.user_agent.as_deref().unwrap_or_default().as_bytes(),
    );
    for header in &sub.headers {
        add_part(&mut hasher, header.key.as_bytes());
        add_part(&mut hasher, header.value.as_bytes());
    }
    use base64::Engine as _;
    format!(
        "{}.sub",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
    )
}

fn ensure_store_directory(root: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "subscription store is not a directory: {}",
                root.display()
            );
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700).create(root)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn read_store_file(path: &Path) -> std::io::Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "subscription cache is not a regular file",
        ));
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn write_store_file(root: &Path, destination: &Path, content: &[u8]) -> anyhow::Result<()> {
    ensure_store_directory(root)?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid subscription cache filename")?;
    let temporary = root.join(format!(
        ".{destination_name}.{}.{}.tmp",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
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
        self.fetch_and_store(sub, None).await
    }

    pub async fn fetch_and_store(
        &self,
        sub: &Subscription,
        store: Option<&SubscriptionStore>,
    ) -> anyhow::Result<Vec<Node>> {
        let mut request = self.client.get(&sub.url);

        if let Some(ref ua) = sub.user_agent {
            request = request.header("User-Agent", ua);
        }

        for header in &sub.headers {
            request = request.header(&header.key, &header.value);
        }

        let response = request.send().await.map_err(reqwest::Error::without_url)?;
        let response = response
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let content = response.text().await.map_err(reqwest::Error::without_url)?;
        let nodes = parse_subscription_content(sub, &content)?;
        if let Some(store) = store
            && let Err(error) = store.store_content(sub, content).await
        {
            tracing::warn!(
                subscription = %sub.name,
                %error,
                "failed to persist subscription"
            );
        }
        Ok(nodes)
    }
}

fn parse_subscription_content(sub: &Subscription, content: &str) -> anyhow::Result<Vec<Node>> {
    let nodes = match sub.sub_type {
        SubscriptionType::Simple | SubscriptionType::Sip008 => {
            parse_base64_subscription(content, Some(sub.id), &sub.name)
        }
        SubscriptionType::Clash => parse_clash_subscription(content, Some(sub.id)),
        SubscriptionType::Custom => parse_base64_subscription(content, Some(sub.id), &sub.name)
            .or_else(|_| parse_clash_subscription(content, Some(sub.id))),
    }?;

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

fn parse_base64_subscription(
    content: &str,
    subscription_id: Option<uuid::Uuid>,
    subscription_tag: &str,
) -> anyhow::Result<Vec<Node>> {
    let trimmed = content.trim();

    // Many providers return a raw list of node URIs even when the subscription
    // is labelled "simple". Try base64 first, then fall back to raw lines.
    let text = match decode_base64_flexible(trimmed) {
        Ok(decoded) => String::from_utf8(decoded)?,
        Err(_) => {
            tracing::debug!(
                subscription = subscription_tag,
                category = "raw-node-list",
                "subscription content is not base64"
            );
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
            Err(_) => {
                tracing::warn!(
                    subscription = subscription_tag,
                    category = "unsupported-node-uri",
                    "skipping subscription node"
                );
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
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("no 'proxies' array found in Clash YAML"))?;
    let mut nodes = Vec::new();

    for proxy in proxies {
        let Some(mapping) = proxy.as_mapping() else {
            continue;
        };
        let get_value = |key: &str| mapping.get(serde_yaml::Value::String(key.to_string()));
        let get_str = |key: &str| {
            get_value(key)
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
        };
        let get_u16 = |key: &str| {
            get_value(key)
                .and_then(serde_yaml::Value::as_u64)
                .and_then(|number| u16::try_from(number).ok())
        };
        let get_nested_str = |section: &str, key: &str| {
            get_value(section)
                .and_then(serde_yaml::Value::as_mapping)
                .and_then(|nested| nested.get(serde_yaml::Value::String(key.to_string())))
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string)
        };

        let Some(proxy_type) = get_str("type") else {
            continue;
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
        let Some(server) = get_str("server") else {
            continue;
        };
        let Some(port) = get_u16("port") else {
            continue;
        };
        let name = get_str("name").unwrap_or_else(|| format!("{proxy_type}-{server}:{port}"));
        let address = format!("{server}:{port}");
        let mut node = Node {
            name,
            protocol,
            address,
            host: server,
            port,
            ..Default::default()
        };

        node.username = get_str("username");
        node.password = if protocol == NodeProtocol::VLess {
            get_str("uuid").or_else(|| get_str("password"))
        } else {
            get_str("password")
        };
        node.encryption = get_str("cipher");
        node.plugin = get_str("plugin");
        node.plugin_opts = get_str("plugin-opts");
        if let Some(network) = get_str("network") {
            node.transport = network;
        }
        node.flow = get_str("flow").filter(|flow| !flow.is_empty());

        if let Some(tls) = get_value("tls").and_then(serde_yaml::Value::as_bool) {
            node.tls = tls;
        }
        node.sni = get_str("servername").or_else(|| get_str("sni"));
        if let Some(skip) = get_value("skip-cert-verify").and_then(serde_yaml::Value::as_bool) {
            node.skip_cert_verify = skip;
        }

        node.ws_path = get_nested_str("ws-opts", "path").or_else(|| get_str("ws-path"));
        node.ws_host = get_value("ws-opts")
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|options| {
                options
                    .get(serde_yaml::Value::String("headers".to_string()))
                    .and_then(serde_yaml::Value::as_mapping)
            })
            .and_then(|headers| {
                headers.iter().find_map(|(key, value)| {
                    key.as_str()
                        .filter(|key| key.eq_ignore_ascii_case("host"))
                        .and_then(|_| value.as_str())
                        .map(str::to_string)
                })
            })
            .or_else(|| get_str("ws-headers"))
            .or_else(|| get_str("ws-host"));
        node.grpc_service =
            get_nested_str("grpc-opts", "grpc-service-name").or_else(|| get_str("grpc-service"));

        if protocol == NodeProtocol::VLess
            && let Some(reality_value) = get_value("reality-opts")
        {
            let Some(reality) = reality_value.as_mapping() else {
                tracing::warn!("skipping VLESS Clash node with incomplete reality-opts");
                continue;
            };
            let nested = |key: &str| {
                reality
                    .get(serde_yaml::Value::String(key.to_string()))
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_string)
            };
            let Some(public_key) = nested("public-key").filter(|value| !value.trim().is_empty())
            else {
                tracing::warn!("skipping VLESS Clash node with incomplete reality-opts");
                continue;
            };
            node.reality_public_key = Some(public_key);
            node.reality_short_id = nested("short-id");
            node.reality_spider_x = Some(
                nested("spider-x")
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "/".to_string()),
            );
            node.tls = true;
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
        let nodes = parse_base64_subscription(&encoded, None, "test").unwrap();
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
        let nodes = parse_base64_subscription(no_pad, None, "test").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "NoPad");
    }

    #[test]
    fn test_parse_base64_skips_unsupported() {
        let uris = ["socks5://192.168.1.1:1080#Valid", "unknown://host:1234"];
        let joined = uris.join("\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
        let nodes = parse_base64_subscription(&encoded, None, "test").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Valid");
    }

    #[test]
    fn test_parse_base64_empty_result() {
        let uris = "unknown://host:1234\nanother-unsupported://x:1";
        let encoded = base64::engine::general_purpose::STANDARD.encode(uris.as_bytes());
        let result = parse_base64_subscription(&encoded, None, "test");
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
    fn test_parse_clash_vless_nested_fields() {
        let subscription_id = uuid::Uuid::new_v4();
        let yaml = r#"
proxies:
  - name: reality-vision
    type: vless
    server: reality.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: legacy-password
    servername: mask.example
    sni: ignored.example
    flow: xtls-rprx-vision
    network: tcp
    client-fingerprint: chrome
    reality-opts:
      public-key: jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc
      short-id: a1b2c3d4
  - name: nested-ws
    type: vless
    server: ws.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    servername: tls.example
    network: ws
    ws-path: /flat
    ws-host: flat.example
    ws-opts:
      path: /nested
      headers:
        hOsT: websocket.example
  - name: nested-grpc
    type: vless
    server: grpc.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    tls: true
    network: grpc
    grpc-service: flat-service
    grpc-opts:
      grpc-service-name: nested-service
  - name: missing-uuid
    type: vless
    server: plain.example
    port: 80
  - name: incomplete-reality
    type: vless
    server: invalid.example
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    reality-opts:
      short-id: abcd
"#;

        let nodes = parse_clash_subscription(yaml, Some(subscription_id)).unwrap();
        assert_eq!(nodes.len(), 4);

        let reality = &nodes[0];
        assert_eq!(reality.protocol, NodeProtocol::VLess);
        assert_eq!(
            reality.password.as_deref(),
            Some("b831381d-6324-4d53-ad4f-8cda48b30811")
        );
        assert_eq!(reality.sni.as_deref(), Some("mask.example"));
        assert_eq!(reality.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(reality.transport, "tcp");
        assert!(reality.tls);
        assert_eq!(
            reality.reality_public_key.as_deref(),
            Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
        );
        assert_eq!(reality.reality_short_id.as_deref(), Some("a1b2c3d4"));
        assert_eq!(reality.reality_spider_x.as_deref(), Some("/"));

        let ws = &nodes[1];
        assert_eq!(ws.sni.as_deref(), Some("tls.example"));
        assert_eq!(ws.transport, "ws");
        assert_eq!(ws.ws_path.as_deref(), Some("/nested"));
        assert_eq!(ws.ws_host.as_deref(), Some("websocket.example"));

        let grpc = &nodes[2];
        assert_eq!(grpc.transport, "grpc");
        assert_eq!(grpc.grpc_service.as_deref(), Some("nested-service"));

        assert_eq!(nodes[3].password, None);
        for node in &nodes {
            assert_eq!(node.subscription_id, Some(subscription_id));
            assert_eq!(node.id, node.derive_id());
        }
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
    #[tokio::test]
    async fn fetch_error_chain_redacts_subscription_url() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const SENTINEL: &str = "subscription-secret-sentinel";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let subscription = Subscription {
            name: "provider".into(),
            url: format!("http://{address}/{SENTINEL}?token={SENTINEL}"),
            ..Subscription::default()
        };

        let error = SubscriptionManager::new()
            .unwrap()
            .fetch(&subscription)
            .await
            .unwrap_err();
        server.await.unwrap();
        let chain = error
            .chain()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!chain.contains(SENTINEL));
        assert!(!format!("{error:?}").contains(SENTINEL));
    }

    #[tokio::test]
    async fn subscription_store_recovers_last_valid_fetch() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let temp = tempfile::tempdir().unwrap();
        let store = SubscriptionStore::open(temp.path().join(SUBSCRIPTION_STORE_DIR)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let valid = "socks5://127.0.0.1:1080#stored";
        let server = tokio::spawn(async move {
            for body in [valid, "not a subscription"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let mut sub = Subscription {
            name: "provider".into(),
            url: format!("http://{address}/subscription"),
            ..Subscription::default()
        };
        let path = store.path_for(&sub);
        let original_id = sub.id;
        let manager = SubscriptionManager::new().unwrap();
        let fetched = manager.fetch_and_store(&sub, Some(&store)).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].subscription_id, Some(original_id));
        assert!(manager.fetch_and_store(&sub, Some(&store)).await.is_err());
        server.await.unwrap();

        sub.id = uuid::Uuid::new_v4();
        sub.name = "renamed-provider".into();
        assert_eq!(store.path_for(&sub), path);
        let restored = store.load_nodes(&sub).await.unwrap().unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].name, "stored");
        assert_eq!(restored[0].subscription_id, Some(sub.id));

        let directory_mode = fs::metadata(store.root()).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        assert_eq!(fs::read_dir(store.root()).unwrap().count(), 1);
    }

    #[test]
    fn subscription_store_rejects_symlink_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join(SUBSCRIPTION_STORE_DIR);
        symlink(target, &link).unwrap();
        assert!(SubscriptionStore::open(link).is_err());
    }
}
