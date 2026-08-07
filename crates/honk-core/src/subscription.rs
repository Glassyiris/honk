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

/// Durable raw subscription bodies keyed by their fetch identity.
#[derive(Clone, Debug)]
pub struct SubscriptionStore {
    root: Arc<PathBuf>,
}

impl SubscriptionStore {
    pub fn in_current_dir() -> anyhow::Result<Self> {
        Self::open(std::env::current_dir()?.join(SUBSCRIPTION_STORE_DIR))
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
            builder.mode(0o700).create(root)?;
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

        let content = request.send().await?.error_for_status()?.text().await?;
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
            parse_base64_subscription(content, Some(sub.id))
        }
        SubscriptionType::Clash => parse_clash_subscription(content, Some(sub.id)),
        SubscriptionType::Custom => parse_base64_subscription(content, Some(sub.id))
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
