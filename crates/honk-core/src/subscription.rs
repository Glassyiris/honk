//! Subscription manager for fetching and parsing proxy subscription URLs.
//!
//! Supports base64-encoded node lists (Simple format) and Clash-compatible
//! YAML subscriptions. Individual share links are parsed with the unified
//! [`Node::from_share_link`] parser from honk-config.

use honk_config::node::Node;
use honk_config::subscription::Subscription;
use honk_config::types::{NodeProtocol, SubscriptionType};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

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

        match sub.sub_type {
            SubscriptionType::Simple | SubscriptionType::Sip008 => {
                parse_base64_subscription(&content, Some(sub.id))
            }
            SubscriptionType::Clash => parse_clash_subscription(&content, Some(sub.id)),
            SubscriptionType::Custom => parse_base64_subscription(&content, Some(sub.id))
                .or_else(|_| parse_clash_subscription(&content, Some(sub.id))),
        }
    }
}

/// The outcome of a subscription refresh.
///
/// The variants intentionally keep fetch, command-channel, and runtime
/// publication failures separate so API callers can map them without parsing
/// diagnostic strings.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionRefreshError {
    #[error("subscription fetch failed: {0}")]
    Fetch(String),
    #[error("subscription refresh is unavailable")]
    Unavailable,
    #[error("subscription merge was rejected: {0}")]
    Rejected(String),
}

/// The part of a subscription that affects an HTTP fetch.
///
/// The header vector is deliberately kept ordered. Providers occasionally
/// distinguish repeated headers, and a reordered configuration must not join
/// an in-flight fetch for a different request specification.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FetchIdentity {
    subscription_id: uuid::Uuid,
    url: String,
    sub_type: SubscriptionType,
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
}

impl Hash for FetchIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subscription_id.hash(state);
        self.url.hash(state);
        (self.sub_type as u8).hash(state);
        self.user_agent.hash(state);
        self.headers.hash(state);
    }
}

impl FetchIdentity {
    fn from_subscription(subscription: &Subscription) -> Self {
        Self {
            subscription_id: subscription.id,
            url: subscription.url.clone(),
            sub_type: subscription.sub_type,
            user_agent: subscription.user_agent.clone(),
            headers: subscription
                .headers
                .iter()
                .map(|header| (header.key.clone(), header.value.clone()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeriodicSpec {
    interval: Duration,
    fetch: FetchIdentity,
}

struct PeriodicTask {
    spec: PeriodicSpec,
    handle: JoinHandle<()>,
}

type SharedRefresh = OnceCell<Result<(), SubscriptionRefreshError>>;

struct CoordinatorState {
    /// A cell is initialized by exactly one caller. Other callers wait on the
    /// same cell and clone its result, so a provider update and a periodic
    /// tick cannot perform duplicate fetch-and-merge work.
    flights: HashMap<FetchIdentity, Arc<SharedRefresh>>,
    periodic: HashMap<uuid::Uuid, PeriodicTask>,
    one_shots: Vec<JoinHandle<()>>,
    startup: Vec<JoinHandle<()>>,
    shutting_down: bool,
}

struct SubscriptionRefreshCoordinatorInner {
    manager: Arc<SubscriptionManager>,
    command_tx: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    state: parking_lot::Mutex<CoordinatorState>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

/// Coordinates all subscription fetches and acknowledged runtime merges.
///
/// Cloning this value only clones a handle to the one coordinator. In
/// particular, clones share the fetch single-flight map and task ownership.
#[derive(Clone)]
pub struct SubscriptionRefreshCoordinator {
    inner: Arc<SubscriptionRefreshCoordinatorInner>,
}

impl SubscriptionRefreshCoordinator {
    /// Construct a coordinator around the process-wide subscription manager
    /// and serialized control-plane command sender.
    pub fn new(
        manager: Arc<SubscriptionManager>,
        command_tx: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            inner: Arc::new(SubscriptionRefreshCoordinatorInner {
                manager,
                command_tx,
                state: parking_lot::Mutex::new(CoordinatorState {
                    flights: HashMap::new(),
                    periodic: HashMap::new(),
                    one_shots: Vec::new(),
                    startup: Vec::new(),
                    shutting_down: false,
                }),
                shutdown_tx,
                shutdown_rx,
            }),
        }
    }

    /// Fetch and acknowledge a merge for one complete subscription snapshot.
    ///
    /// Calls with the same subscription id and fetch identity share one
    /// fetch/merge result. No coordinator lock is held while doing network or
    /// command-channel work.
    pub async fn refresh(
        &self,
        subscription: Subscription,
    ) -> Result<(), SubscriptionRefreshError> {
        let key = FetchIdentity::from_subscription(&subscription);
        let cell = {
            let mut state = self.inner.state.lock();
            if state.shutting_down {
                return Err(SubscriptionRefreshError::Unavailable);
            }

            if let Some(cell) = state.flights.get(&key) {
                cell.clone()
            } else {
                let cell = Arc::new(SharedRefresh::new());
                state.flights.insert(key.clone(), cell.clone());
                cell
            }
        };

        let coordinator = self.clone();
        let result = cell
            .get_or_init(|| async move { coordinator.fetch_and_merge(subscription).await })
            .await
            .clone();

        // Remove only our cell. A newer caller may already have installed a
        // replacement after an earlier completed flight was cleaned up.
        let mut state = self.inner.state.lock();
        if state
            .flights
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &cell))
        {
            state.flights.remove(&key);
        }
        result
    }

    /// Reconcile periodic refresh ownership with the latest committed config.
    ///
    /// Removed, disabled, and changed subscriptions are aborted and joined
    /// before this method returns. An unchanged id/fetch identity/interval
    /// retains its task. New periodic tasks wait one full configured interval
    /// before their first refresh.
    pub async fn reconcile(&self, subscriptions: &[Subscription]) {
        let mut desired = HashMap::<uuid::Uuid, (PeriodicSpec, Subscription)>::new();
        for subscription in subscriptions
            .iter()
            .filter(|subscription| subscription.enabled && subscription.update_interval > 0)
        {
            let spec = PeriodicSpec {
                interval: Duration::from_secs(subscription.update_interval),
                fetch: FetchIdentity::from_subscription(subscription),
            };
            // A duplicate id is malformed config; declaration order remains
            // deterministic and the first declaration owns the task.
            desired
                .entry(subscription.id)
                .or_insert_with(|| (spec, subscription.clone()));
        }

        let stale_handles = {
            let mut state = self.inner.state.lock();
            if state.shutting_down {
                return;
            }
            let stale_ids: Vec<_> = state
                .periodic
                .iter()
                .filter_map(|(id, task)| match desired.get(id) {
                    Some((spec, _)) if spec == &task.spec => None,
                    _ => Some(*id),
                })
                .collect();

            let mut stale_handles = Vec::with_capacity(stale_ids.len());
            for id in stale_ids {
                if let Some(task) = state.periodic.remove(&id) {
                    task.handle.abort();
                    stale_handles.push(task.handle);
                }
            }

            for (id, (spec, subscription)) in desired {
                if state.periodic.contains_key(&id) {
                    continue;
                }

                let coordinator = self.clone();
                let periodic_subscription = subscription.clone();
                let subscription_name = subscription.name.clone();
                let interval = spec.interval;
                let handle = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        if let Err(error) = coordinator.refresh(periodic_subscription.clone()).await
                        {
                            tracing::warn!(
                                subscription = %subscription_name,
                                error = %error,
                                "periodic subscription refresh failed"
                            );
                        }
                    }
                });
                state.periodic.insert(id, PeriodicTask { spec, handle });
            }

            stale_handles
        };

        join_handles(stale_handles).await;
    }

    /// Schedule immediate refreshes without waiting for network or merge
    /// acknowledgements. Disabled subscriptions are intentionally ignored.
    pub fn refresh_now(&self, subscriptions: Vec<Subscription>) {
        for subscription in subscriptions
            .into_iter()
            .filter(|subscription| subscription.enabled)
        {
            let coordinator = self.clone();
            let subscription_name = subscription.name.clone();
            let handle = tokio::spawn(async move {
                if let Err(error) = coordinator.refresh(subscription).await {
                    tracing::warn!(
                        subscription = %subscription_name,
                        error = %error,
                        "one-shot subscription refresh failed"
                    );
                }
            });

            let mut state = self.inner.state.lock();
            if state.shutting_down {
                handle.abort();
            } else {
                state.one_shots.push(handle);
            }
        }
    }

    /// Adopt startup fetch tasks that outlived the startup deadline.
    ///
    /// Each successful JoinSet result carries its original full subscription
    /// into the acknowledged merge command. A failed fetch is logged and is
    /// never represented as an empty node replacement.
    pub fn adopt_startup_fetches(
        &self,
        mut startup_fetches: JoinSet<(Subscription, anyhow::Result<Vec<Node>>)>,
    ) {
        {
            let state = self.inner.state.lock();
            if state.shutting_down {
                drop(state);
                return;
            }
        }

        let coordinator = self.clone();
        let handle = tokio::spawn(async move {
            while let Some(result) = startup_fetches.join_next().await {
                match result {
                    Ok((subscription, Ok(nodes))) => {
                        let subscription_name = subscription.name.clone();
                        if let Err(error) = coordinator.merge_nodes(subscription, nodes).await {
                            tracing::warn!(
                                subscription = %subscription_name,
                                error = %error,
                                "startup subscription merge failed"
                            );
                        }
                    }
                    Ok((subscription, Err(error))) => {
                        tracing::warn!(
                            subscription = %subscription.name,
                            error = %error,
                            "startup subscription fetch failed"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "startup subscription task failed");
                    }
                }
            }
        });

        let mut state = self.inner.state.lock();
        if state.shutting_down {
            handle.abort();
        } else {
            state.startup.push(handle);
        }
    }

    /// Abort and join every periodic, one-shot, and adopted startup task.
    pub async fn shutdown(&self) {
        let handles = {
            let mut state = self.inner.state.lock();
            if !state.shutting_down {
                state.shutting_down = true;
                let _ = self.inner.shutdown_tx.send(true);
            }

            state.flights.clear();
            let mut handles = Vec::with_capacity(
                state.periodic.len() + state.one_shots.len() + state.startup.len(),
            );
            handles.extend(state.periodic.drain().map(|(_, task)| task.handle));
            handles.append(&mut state.one_shots);
            handles.append(&mut state.startup);
            handles
        };

        for handle in &handles {
            handle.abort();
        }
        join_handles(handles).await;
    }

    async fn fetch_and_merge(
        &self,
        subscription: Subscription,
    ) -> Result<(), SubscriptionRefreshError> {
        let mut shutdown = self.inner.shutdown_rx.clone();
        let fetched = tokio::select! {
            biased;
            _ = shutdown.changed() => return Err(SubscriptionRefreshError::Unavailable),
            result = self.inner.manager.fetch(&subscription) => result,
        };
        let nodes = fetched.map_err(|error| SubscriptionRefreshError::Fetch(error.to_string()))?;
        self.merge_nodes(subscription, nodes).await
    }

    async fn merge_nodes(
        &self,
        subscription: Subscription,
        nodes: Vec<Node>,
    ) -> Result<(), SubscriptionRefreshError> {
        let (completion, mut acknowledged) = oneshot::channel();
        let command = crate::control::ControlCommand::MergeSubscription {
            subscription: Box::new(subscription),
            nodes,
            completion,
        };

        let mut shutdown = self.inner.shutdown_rx.clone();
        let sent = tokio::select! {
            biased;
            _ = shutdown.changed() => return Err(SubscriptionRefreshError::Unavailable),
            result = self.inner.command_tx.send(command) => result,
        };
        sent.map_err(|_| SubscriptionRefreshError::Unavailable)?;

        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(SubscriptionRefreshError::Unavailable),
            result = &mut acknowledged => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(SubscriptionRefreshError::Rejected(error)),
                Err(_) => Err(SubscriptionRefreshError::Unavailable),
            },
        }
    }
}

async fn join_handles(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.await;
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
            "ssr" | "shadowsocksr" => NodeProtocol::SSR,
            "trojan" => NodeProtocol::Trojan,
            "vmess" => NodeProtocol::VMess,
            "vless" => NodeProtocol::VLess,
            "http" => NodeProtocol::HTTP,
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
            id: uuid::Uuid::new_v4(),
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
    fn test_parse_clash_no_proxies() {
        let yaml = r#"
port: 7890
not-proxies: []
"#;
        let result = parse_clash_subscription(yaml, None);
        assert!(result.is_err());
    }

    async fn subscription_fixture(
        hits: Arc<std::sync::atomic::AtomicUsize>,
    ) -> (String, JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = "socks5://127.0.0.1:1080#fixture";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{address}/subscription"), handle)
    }

    #[tokio::test]
    async fn coordinator_joins_concurrent_refresh_and_acknowledges_merge() {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (url, server) = subscription_fixture(Arc::clone(&hits)).await;
        let subscription = Subscription {
            id: uuid::Uuid::new_v4(),
            name: "fixture".into(),
            url,
            enabled: true,
            ..Default::default()
        };
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(4);
        let command_owner = tokio::spawn(async move {
            let Some(crate::control::ControlCommand::MergeSubscription {
                subscription,
                nodes,
                completion,
            }) = command_rx.recv().await
            else {
                panic!("expected subscription merge command");
            };
            assert_eq!(subscription.name, "fixture");
            assert_eq!(nodes.len(), 1);
            completion.send(Ok(())).unwrap();
        });
        let coordinator = SubscriptionRefreshCoordinator::new(
            Arc::new(SubscriptionManager::new().unwrap()),
            command_tx,
        );

        let (first, second) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                coordinator.refresh(subscription.clone()),
                coordinator.refresh(subscription)
            )
        })
        .await
        .unwrap();
        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        server.await.unwrap();
        command_owner.await.unwrap();
        coordinator.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn coordinator_reconcile_retains_replaces_and_joins_periodic_tasks() {
        let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);
        let coordinator = SubscriptionRefreshCoordinator::new(
            Arc::new(SubscriptionManager::new().unwrap()),
            command_tx,
        );
        let mut subscription = Subscription {
            id: uuid::Uuid::new_v4(),
            name: "periodic".into(),
            url: "http://127.0.0.1:9/subscription".into(),
            update_interval: 60,
            enabled: true,
            ..Default::default()
        };

        coordinator.reconcile(&[subscription.clone()]).await;
        let first_task = coordinator
            .inner
            .state
            .lock()
            .periodic
            .get(&subscription.id)
            .unwrap()
            .handle
            .id();
        coordinator.reconcile(&[subscription.clone()]).await;
        assert_eq!(
            coordinator
                .inner
                .state
                .lock()
                .periodic
                .get(&subscription.id)
                .unwrap()
                .handle
                .id(),
            first_task
        );

        subscription.url.push_str("-changed");
        coordinator.reconcile(&[subscription.clone()]).await;
        assert_ne!(
            coordinator
                .inner
                .state
                .lock()
                .periodic
                .get(&subscription.id)
                .unwrap()
                .handle
                .id(),
            first_task
        );

        subscription.enabled = false;
        coordinator.reconcile(&[subscription]).await;
        assert!(coordinator.inner.state.lock().periodic.is_empty());
        coordinator.shutdown().await;
        let state = coordinator.inner.state.lock();
        assert!(state.shutting_down);
        assert!(state.periodic.is_empty());
        assert!(state.one_shots.is_empty());
        assert!(state.startup.is_empty());
    }
}
