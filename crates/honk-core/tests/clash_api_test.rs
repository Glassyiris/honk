//! Integration tests for the Clash-compatible REST API (Phase 5).
//!
//! Boots the real axum router on 127.0.0.1:0 with a lightweight ClashState
//! (no eBPF involved) and exercises auth, proxies, mode persistence,
//! connections, delay, and cache-flush endpoints over HTTP.

#![cfg(feature = "clash-api")]

use honk_config::Config;
use honk_config::dns::{DnsConfig, DnsRouting};
use honk_config::experimental::CacheFileConfig;
use honk_config::node::{Group, Node};
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingOutboundType, RoutingRule};
use honk_config::subscription::Subscription;
use honk_config::types::NodeProtocol;
use honk_core::cachedb::CacheDb;
use honk_core::clash_api::{self, ClashState};
use honk_core::connection_tracker::{ConnectionCloseHandle, ConnectionEntry, ConnectionTracker};
use honk_core::dns::cache::DnsCache;
use honk_core::dns::forwarder::{DnsForwarder, DnsUpstreamPool, build_dns_query};
use honk_core::dns::routing::DnsRouter;
use honk_core::mode::ModeState;
use honk_core::stats::StatsManager;
use honk_outbound::alive::{AliveDialerSet, IpVersion, ProbeDomain};
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::ProxyRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn make_node(name: &str) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        protocol: NodeProtocol::HTTP, // direct-class handler in the registry
        address: "127.0.0.1".into(),
        port: 1,
        ..Default::default()
    }
}

/// Minimal config: one Selector group "proxy" with nodes node-a / node-b.
fn test_config() -> Config {
    let (a, b) = (make_node("node-a"), make_node("node-b"));
    let group = Group {
        name: "proxy".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id, b.id],
        ..Default::default()
    };
    Config {
        nodes: vec![a, b],
        groups: vec![group],
        ..Default::default()
    }
}

struct TestApp {
    addr: SocketAddr,
    state: Arc<ClashState>,
    db_path: std::path::PathBuf,
    commands:
        Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<honk_core::control::ControlCommand>>>,
    _tmp: tempfile::TempDir,
}

impl TestApp {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

/// Mock DNS upstream pool returning one canned wire response.
struct StaticUpstream(Vec<u8>);

#[async_trait::async_trait]
impl DnsUpstreamPool for StaticUpstream {
    async fn query(&self, _upstream: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

/// A-record response for example.com → `ip` with the given TTL.
fn a_record_response(ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let ttl = ttl.to_be_bytes();
    vec![
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
        0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
        0xc0, 0x0c, // answer name (pointer to qname)
        0x00, 0x01, 0x00, 0x01, // type A, class IN
        ttl[0], ttl[1], ttl[2], ttl[3], // TTL
        0x00, 0x04, ip[0], ip[1], ip[2], ip[3], // rdlength + rdata
    ]
}

/// NXDOMAIN response for example.com (ANCOUNT = 0, RCODE = 3).
fn nxdomain_response() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
        0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
    ]
}

fn test_dns_forwarder(cache: Arc<tokio::sync::Mutex<DnsCache>>, response: Vec<u8>) -> DnsForwarder {
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    DnsForwarder::new(Arc::new(StaticUpstream(response)), cache, router)
}

async fn spawn_app(secret: &str, external_ui: &str) -> TestApp {
    spawn_app_with_config(test_config(), secret, external_ui).await
}

async fn spawn_app_with_config(config: Config, secret: &str, external_ui: &str) -> TestApp {
    spawn_app_with_config_and_ui_url(config, secret, external_ui, None).await
}

async fn spawn_app_with_config_and_ui_url(
    config: Config,
    secret: &str,
    external_ui: &str,
    ui_download_url: Option<String>,
) -> TestApp {
    spawn_app_with_options(config, secret, external_ui, ui_download_url, true).await
}

async fn spawn_app_with_options(
    config: Config,
    secret: &str,
    external_ui: &str,
    ui_download_url: Option<String>,
    cache_enabled: bool,
) -> TestApp {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cache.db");
    let config_path = tmp.path().join("config.dae");
    let (command_tx, command_rx) = tokio::sync::mpsc::channel(16);
    let subscription_refresh = Arc::new(
        honk_core::subscription::SubscriptionRefreshCoordinator::new(
            Arc::new(honk_core::subscription::SubscriptionManager::new().unwrap()),
            command_tx.clone(),
        ),
    );
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: db_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    let db =
        cache_enabled.then(|| Arc::new(CacheDb::open(&cache_cfg, None).expect("cache.db opens")));

    let alive_set = Arc::new(AliveDialerSet::new());
    let group_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));
    // Wire the same persistence the control plane installs in production.
    if let Some(db) = &db {
        let db_cb = Arc::clone(db);
        group_manager.set_persist_callback(Some(Arc::new(move |group, node| {
            db_cb.save_selector_choice(group, node);
        })));
    }
    let group_manager = group_manager.into_shared();

    let (log_tx, _) = tokio::sync::broadcast::channel(16);
    let dns_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let dns_service = honk_core::dns::DnsService::with_forwarder(Arc::new(test_dns_forwarder(
        dns_cache,
        a_record_response([93, 184, 216, 34], 300),
    )));
    let stats = Arc::new(StatsManager::new());
    let connection_tracker = Arc::new(ConnectionTracker::new());
    let state = Arc::new(ClashState {
        config: Arc::new(tokio::sync::RwLock::new(config)),
        config_path,
        command_tx,
        subscription_refresh,
        dashboard_storage: parking_lot::RwLock::new(serde_json::json!({})),
        ui_update_lock: Arc::new(tokio::sync::Mutex::new(())),
        stats: stats.clone(),
        alive_set,
        group_manager,
        cache_db: db,
        connection_tracker: connection_tracker.clone(),
        proxy_registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
        mode_state: Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "proxy"))),
        secret: secret.to_string(),
        external_ui: external_ui.to_string(),
        ui_download_url,
        log_tx,
        dns_service,
        connection_pool: Arc::new(honk_core::pool::ConnectionPool::new()),
        stream_samplers: Arc::new(clash_api::StreamSamplers::new()),
    });

    let app = clash_api::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("axum serve error: {e:#}");
        }
    });
    // Give the server a tick to bind.
    tokio::task::yield_now().await;

    TestApp {
        addr,
        state,
        commands: Arc::new(tokio::sync::Mutex::new(command_rx)),
        db_path,
        _tmp: tmp,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap()
}

async fn next_reload(
    app: &TestApp,
) -> (
    std::path::PathBuf,
    tokio::sync::oneshot::Sender<
        Result<honk_core::control::ReloadPublication, honk_core::control::ReloadFailure>,
    >,
) {
    let command = tokio::time::timeout(Duration::from_secs(2), app.commands.lock().await.recv())
        .await
        .expect("reload command within two seconds")
        .expect("command sender remains open");
    match command {
        honk_core::control::ControlCommand::ReloadConfig { path, completion } => (path, completion),
        command => panic!("unexpected command: {command:?}"),
    }
}

async fn next_merge(
    app: &TestApp,
) -> (
    Subscription,
    Vec<Node>,
    tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let command = tokio::time::timeout(Duration::from_secs(2), app.commands.lock().await.recv())
        .await
        .expect("merge command within two seconds")
        .expect("command sender remains open");
    match command {
        honk_core::control::ControlCommand::MergeSubscription {
            subscription,
            nodes,
            completion,
        } => (*subscription, nodes, completion),
        command => panic!("unexpected command: {command:?}"),
    }
}

#[tokio::test]
async fn test_version_and_config_shape_are_sing_box_compatible() {
    let mut config = test_config();
    config.global.tproxy_port = 23456;
    config.global.log_level = "debug".into();
    let app = spawn_app_with_config(config, "", "").await;
    let client = http_client();

    let version: serde_json::Value = client
        .get(app.url("/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        version,
        serde_json::json!({
            "version": format!("sing-box honk {}", env!("CARGO_PKG_VERSION"))
        })
    );

    let configs: serde_json::Value = client
        .get(app.url("/configs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(configs["mode"], "Rule");
    assert_eq!(
        configs["mode-list"],
        serde_json::json!(["Rule", "Global", "Direct"])
    );
    assert_eq!(configs["modes"], configs["mode-list"]);
    assert_eq!(configs["tproxy-port"], 23456);
    for field in ["port", "socks-port", "redir-port", "mixed-port"] {
        assert_eq!(configs[field], 0);
    }
    assert_eq!(configs["bind-address"], "*");
    assert_eq!(configs["log-level"], "debug");
    assert_eq!(configs["ipv6"], false);
    assert_eq!(configs["allow-lan"], false);
    assert_eq!(configs["tun"]["enable"], false);
}

#[tokio::test]
async fn test_rules_match_connection_metadata_projection() {
    let mut config = test_config();
    config.routing.rules = vec![
        RoutingRule {
            name: "domains".into(),
            condition: RoutingCondition {
                domain: vec!["one.example".into(), "two.example".into()],
                port: vec!["443".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0,
        },
        RoutingRule {
            name: "complex".into(),
            condition: RoutingCondition {
                dscp: vec!["46".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Complex {
                outbound_type: RoutingOutboundType::Or,
                outbounds: vec!["node-a".into(), "node-b".into()],
            },
            priority: 1,
            must: false,
            mark: 0,
        },
    ];
    config.routing.default_outbound = "direct".into();
    let app = spawn_app_with_config(config, "", "").await;
    let body: serde_json::Value = http_client()
        .get(app.url("/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        body["rules"],
        serde_json::json!([
            {
                "type": "domain",
                "payload": "one.example,two.example",
                "proxy": "proxy",
                "index": 0,
                "size": -1
            },
            {
                "type": "dscp",
                "payload": "46",
                "proxy": "node-a",
                "index": 1,
                "size": -1
            },
            {
                "type": "Match",
                "payload": "",
                "proxy": "direct",
                "index": 2,
                "size": -1
            }
        ])
    );
}

#[tokio::test]
async fn test_config_patch_rejects_non_mode_mutations() {
    let app = spawn_app("", "").await;
    let client = http_client();
    for body in ["not-json", "[]", "{}", r#"{"mode":1}"#] {
        let response = client
            .patch(app.url("/configs"))
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "body {body}");
    }
    let response = client
        .patch(app.url("/configs"))
        .body(r#"{"mode":"Rule","port":7890}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["message"],
        "unsupported config field: port"
    );
    assert_eq!(app.state.mode_state.read().mode, "Rule");
}

#[tokio::test]
async fn test_config_put_acknowledges_reload_and_maps_failures() {
    let app = spawn_app("", "").await;
    let client = http_client();

    for url in [
        "/configs",
        "/configs?force=true",
        "/configs?reload=true&force=true",
    ] {
        let response = client.put(app.url(url)).body("{}").send().await.unwrap();
        assert_eq!(response.status(), 501, "url {url}");
    }
    let response = client
        .put(app.url("/configs?reload=true"))
        .body(r#"{"path":"replacement.dae","payload":""}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 501);
    let response = client
        .put(app.url("/configs?reload=true"))
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let pending = tokio::spawn({
        let client = client.clone();
        let url = app.url("/configs?reload=true");
        async move { client.put(url).body("{}").send().await.unwrap() }
    });
    let (path, completion) = next_reload(&app).await;
    assert_eq!(path, app.state.config_path);
    assert!(!pending.is_finished());
    completion
        .send(Ok(honk_core::control::ReloadPublication {
            subscriptions: vec![],
            refresh_subscriptions: vec![],
        }))
        .unwrap();
    assert_eq!(pending.await.unwrap().status(), 204);

    for (failure, expected) in [
        (
            honk_core::control::ReloadFailure::Invalid("bad config".into()),
            400,
        ),
        (
            honk_core::control::ReloadFailure::Rejected("runtime rejected".into()),
            409,
        ),
        (
            honk_core::control::ReloadFailure::Internal("join failed".into()),
            500,
        ),
    ] {
        let request = tokio::spawn({
            let client = client.clone();
            let url = app.url("/configs?reload=true");
            async move { client.put(url).send().await.unwrap() }
        });
        let (_, completion) = next_reload(&app).await;
        completion.send(Err(failure)).unwrap();
        assert_eq!(request.await.unwrap().status().as_u16(), expected);
    }

    let acknowledgement_closed = tokio::spawn({
        let client = client.clone();
        let url = app.url("/configs?reload=true");
        async move { client.put(url).send().await.unwrap() }
    });
    let (_, completion) = next_reload(&app).await;
    drop(completion);
    assert_eq!(acknowledgement_closed.await.unwrap().status(), 503);

    let unavailable = spawn_app("", "").await;
    unavailable.commands.lock().await.close();
    let response = client
        .put(unavailable.url("/configs?reload=true"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
}

#[tokio::test]
async fn test_dashboard_storage_validates_persists_and_deletes() {
    let app = spawn_app("", "").await;
    let client = http_client();
    let initial: serde_json::Value = client
        .get(app.url("/storage/zashboard"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(initial, serde_json::json!({}));

    let response = client
        .put(app.url("/storage/zashboard"))
        .body(r#"{"theme":"dark","nested":{"x":1}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    let stored: serde_json::Value = client
        .get(app.url("/storage/zashboard"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stored, serde_json::json!({"theme":"dark","nested":{"x":1}}));
    let compact = serde_json::to_string(&stored).unwrap();
    assert_eq!(
        app.state
            .cache_db
            .as_ref()
            .unwrap()
            .get("zashboard:storage")
            .as_deref(),
        Some(compact.as_str())
    );

    for invalid in ["not-json", "[]", "null", "1"] {
        assert_eq!(
            client
                .put(app.url("/storage/zashboard"))
                .body(invalid)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    let unchanged: serde_json::Value = client
        .get(app.url("/storage/zashboard"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unchanged, stored);

    let cache_config = CacheFileConfig {
        enabled: true,
        path: app.db_path.to_str().unwrap().to_owned(),
        ..Default::default()
    };
    let fresh_cache = CacheDb::open(&cache_config, None).unwrap();
    let persisted = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(value) = fresh_cache.get("zashboard:storage") {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&persisted).unwrap(),
        stored
    );

    assert_eq!(
        client
            .delete(app.url("/storage/zashboard"))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        client
            .get(app.url("/storage/zashboard"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap(),
        serde_json::json!({})
    );
    assert_eq!(
        app.state
            .cache_db
            .as_ref()
            .unwrap()
            .get("zashboard:storage"),
        None
    );

    let memory_only = spawn_app_with_options(test_config(), "", "", None, false).await;
    assert!(memory_only.state.cache_db.is_none());
    assert_eq!(
        client
            .put(memory_only.url("/storage/zashboard"))
            .json(&serde_json::json!({"memoryOnly": true}))
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        client
            .get(memory_only.url("/storage/zashboard"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap(),
        serde_json::json!({"memoryOnly": true})
    );
}

#[tokio::test]
async fn test_auth_open_when_no_secret() {
    let app = spawn_app("", "").await;
    let resp = http_client().get(app.url("/proxies")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_secret_enforced() {
    let app = spawn_app("topsecret", "").await;
    let client = http_client();

    // No header → 401 with the clash error shape.
    let resp = client.get(app.url("/proxies")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "Unauthorized");

    // Wrong token → 401.
    let resp = client
        .get(app.url("/proxies"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Correct Bearer token → 200.
    let resp = client
        .get(app.url("/proxies"))
        .bearer_auth("topsecret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Non-Bearer scheme → 401.
    let resp = client
        .get(app.url("/proxies"))
        .header("Authorization", "Basic topsecret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_proxies_structure_and_selector_switch() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxies = &body["proxies"];

    // The Selector group is present with both members.
    assert_eq!(proxies["proxy"]["type"], "selector");
    assert_eq!(
        proxies["proxy"]["all"],
        serde_json::json!(["node-a", "node-b"])
    );
    // Default selection falls back to the first member.
    assert_eq!(proxies["proxy"]["now"], "node-a");
    // Group members are ALSO listed as top-level entries (clash semantics):
    // dashboards resolve member names/delays through them.
    assert_eq!(proxies["node-a"]["name"], "node-a");
    assert_eq!(proxies["node-b"]["name"], "node-b");
    assert!(proxies["node-a"]["type"].is_string());
    assert!(proxies["node-a"]["history"].is_array());
    // GLOBAL synthetic group exists with the mode-state selection.
    assert_eq!(proxies["GLOBAL"]["type"], "selector");
    assert_eq!(proxies["GLOBAL"]["now"], "proxy");
    assert_eq!(proxies["GLOBAL"]["all"][0], "Proxy");
    // GLOBAL contains the group and both nodes, without duplicates.
    let global_all = proxies["GLOBAL"]["all"].as_array().unwrap();
    let unique: std::collections::HashSet<_> = global_all.iter().collect();
    assert_eq!(global_all.len(), unique.len());
    for expected in ["Proxy", "proxy", "node-a", "node-b"] {
        assert!(global_all.iter().any(|n| n == expected));
    }

    // Switch the selector to node-b.
    let resp = client
        .put(app.url("/proxies/proxy"))
        .json(&serde_json::json!({"name": "node-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["proxies"]["proxy"]["now"], "node-b");

    // The persist callback must have written cache.db.
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-b"));

    // Unknown member → 400.
    let resp = client
        .put(app.url("/proxies/proxy"))
        .json(&serde_json::json!({"name": "node-x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_proxy_udp_capabilities_nested_groups_and_test_url() {
    let cases = [
        ("direct", NodeProtocol::HTTP, true),
        ("http", NodeProtocol::HTTP, false),
        ("socks", NodeProtocol::Socks5, true),
        ("ss", NodeProtocol::SS, true),
        ("ssr", NodeProtocol::SSR, false),
        ("trojan", NodeProtocol::Trojan, true),
        ("trojan-go", NodeProtocol::TrojanGo, false),
        ("vmess", NodeProtocol::VMess, false),
        ("vless", NodeProtocol::VLess, false),
        ("hysteria2", NodeProtocol::Hysteria2, true),
        ("anytls", NodeProtocol::AnyTLS, true),
        ("tuic", NodeProtocol::Tuic, true),
        ("juicity", NodeProtocol::Juicity, true),
    ];
    let nodes = cases
        .iter()
        .map(|(name, protocol, _)| {
            let mut node = make_node(name);
            node.protocol = *protocol;
            node
        })
        .collect::<Vec<_>>();
    let udp_leaf = nodes.iter().find(|node| node.name == "ss").unwrap().id;
    let tcp_leaf = nodes.iter().find(|node| node.name == "vmess").unwrap().id;
    let nested = Group {
        name: "nested".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![udp_leaf],
        ..Default::default()
    };
    let parent = Group {
        name: "parent".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![tcp_leaf],
        groups: vec!["nested".into()],
        check_url: Some("https://probe.example/generate_204".into()),
        ..Default::default()
    };
    let tcp_only = Group {
        name: "tcp-only".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![tcp_leaf],
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            nodes,
            groups: vec![parent, nested, tcp_only],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let body: serde_json::Value = http_client()
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let proxies = &body["proxies"];

    for (name, _, expected_udp) in cases {
        assert_eq!(proxies[name]["udp"], expected_udp, "{name}");
    }
    assert_eq!(proxies["nested"]["udp"], true);
    assert_eq!(proxies["parent"]["udp"], true);
    assert_eq!(proxies["tcp-only"]["udp"], false);
    assert_eq!(proxies["GLOBAL"]["udp"], true);
    assert_eq!(
        proxies["parent"]["testUrl"],
        "https://probe.example/generate_204"
    );
    assert!(proxies["nested"].get("testUrl").is_none());
}

/// Dashboards (metacubexd/zashboard) send PUT/PATCH without a JSON
/// Content-Type; the API must still accept them (mihomo parity).
#[tokio::test]
async fn test_put_and_patch_without_content_type() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let resp = client
        .put(app.url("/proxies/proxy"))
        .body(r#"{"name":"node-b"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("proxy").as_deref(), Some("node-b"));

    let resp = client
        .patch(app.url("/configs"))
        .body(r#"{"mode":"global"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let body: serde_json::Value = client
        .get(app.url("/configs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["mode"], "Global");
}

/// Parent selector containing a sub-group: the sub-group tag appears in
/// `all`, is a valid PUT target (persisted + restored on "restart"), and
/// the selection chain resolves through it to the leaf.
#[tokio::test]
async fn test_nested_group_selector_via_api() {
    let (a, b, c) = (
        make_node("node-a"),
        make_node("node-b"),
        make_node("node-c"),
    );
    let sub = Group {
        name: "sub".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![b.id, c.id],
        ..Default::default()
    };
    let parent = Group {
        name: "parent".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id],
        groups: vec!["sub".into()],
        ..Default::default()
    };
    let config = Config {
        nodes: vec![a, b, c],
        groups: vec![parent, sub],
        ..Default::default()
    };
    let app = spawn_app_with_config(config.clone(), "", "").await;
    let client = http_client();

    // `all` lists member tags: the direct node and the sub-group tag.
    let body: serde_json::Value = client
        .get(app.url("/proxies/parent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["all"], serde_json::json!(["node-a", "sub"]));
    assert_eq!(body["now"], "node-a");

    // Select the sub-group tag.
    let resp = client
        .put(app.url("/proxies/parent"))
        .json(&serde_json::json!({"name": "sub"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let body: serde_json::Value = client
        .get(app.url("/proxies/parent"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["now"], "sub");
    // The chain resolves through the sub-group to its own selection.
    assert_eq!(
        app.state.group_manager.read().selection_chain("parent"),
        vec!["parent", "sub", "node-b"]
    );

    // A leaf inside the sub-group is NOT a direct member: sing-box drills
    // down layer by layer, so this must be rejected.
    let resp = client
        .put(app.url("/proxies/parent"))
        .json(&serde_json::json!({"name": "node-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // The persist callback wrote the sub-group tag to cache.db.
    let db = app.state.cache_db.as_ref().unwrap();
    assert_eq!(db.load_selector_choice("parent").as_deref(), Some("sub"));

    // "Restart": rebuild the manager from the same config and restore the
    // persisted choices exactly like ControlPlane::init_cache_db does.
    let restored = GroupManager::with_alive_set(
        &config.groups,
        &config.nodes,
        Some(app.state.alive_set.clone()),
    );
    for group in &config.groups {
        if group.policy == honk_config::group::GroupPolicy::Selector
            && let Some(choice) = db.load_selector_choice(&group.name)
        {
            restored.set_selector_choice(&group.name, &choice);
        }
    }
    assert_eq!(
        restored.get_selector_choice("parent").as_deref(),
        Some("sub")
    );
    // The restored choice drives selection: parent → sub → sub's leaf.
    assert_eq!(restored.select_node("parent").unwrap().name, "node-b");
    assert_eq!(
        restored.selection_chain("parent"),
        vec!["parent", "sub", "node-b"]
    );
}

#[tokio::test]
async fn test_global_selection_and_mode_persisted() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Select a group as the GLOBAL target.
    let resp = client
        .put(app.url("/proxies/GLOBAL"))
        .json(&serde_json::json!({"name": "proxy"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(app.state.mode_state.read().global_selection, "proxy");

    // Unknown GLOBAL target → 400.
    let resp = client
        .put(app.url("/proxies/GLOBAL"))
        .json(&serde_json::json!({"name": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Switch mode to Global (case-insensitive).
    let resp = client
        .patch(app.url("/configs"))
        .json(&serde_json::json!({"mode": "global"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(app.state.mode_state.read().mode, "Global");

    // GET /configs reflects the new mode; GET /proxies reflects GLOBAL.now.
    let body: serde_json::Value = client
        .get(app.url("/configs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["mode"], "Global");
    let body: serde_json::Value = client
        .get(app.url("/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["proxies"]["GLOBAL"]["now"], "proxy");

    // Invalid mode → 400.
    let resp = client
        .patch(app.url("/configs"))
        .json(&serde_json::json!({"mode": "bogus"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Point writes are acknowledged from the in-memory pending map and become
    // crash-durable on the bounded background flush.
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: app.db_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    let reopened = CacheDb::open(&cache_cfg, None).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        if reopened.load_clash_mode().as_deref() == Some("Global")
            && reopened.load_selector_choice("GLOBAL").as_deref() == Some("proxy")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cache.db point-write durability bound exceeded"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn test_connections_snapshot_and_delete() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Inject one tracked connection.
    let id = app.state.connection_tracker.register(ConnectionEntry {
        id: "conn-1".into(),
        source: "10.0.0.2:12345".into(),
        destination: "142.250.72.14:443".into(),
        proxy: "proxy".into(),
        rule: "suffix".into(),
        rule_payload: "example.com".into(),
        chains: vec!["node-a".into(), "hk".into(), "proxy".into()],
        upload: std::sync::Arc::new(AtomicU64::new(100)),
        download: std::sync::Arc::new(AtomicU64::new(200)),
        start_time: Instant::now(),
        domain: Some("example.com".into()),
        network: "tcp".into(),
        dscp: 46,
        close_handle: ConnectionCloseHandle::detached(),
    });

    let body: serde_json::Value = client
        .get(app.url("/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conns = body["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    let c = &conns[0];
    assert_eq!(c["id"], id);
    assert_eq!(c["metadata"]["sourceIP"], "10.0.0.2");
    assert_eq!(c["metadata"]["destinationIP"], "142.250.72.14");
    assert_eq!(c["metadata"]["sourcePort"], "12345");
    assert_eq!(c["metadata"]["host"], "example.com");
    assert_eq!(c["upload"], 100);
    assert_eq!(c["download"], 200);
    assert_eq!(c["rule"], "suffix");
    assert_eq!(c["rulePayload"], "example.com");
    assert_eq!(
        c["chains"],
        serde_json::json!(["node-a", "hk", "proxy"]),
        "chains must be the selection path, leaf-first"
    );
    // RFC3339 start timestamp.
    let start = c["start"].as_str().unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(start).is_ok());
    assert_eq!(body["uploadTotal"], 100);
    assert_eq!(body["downloadTotal"], 200);

    // DELETE the single connection.
    let resp = client
        .delete(app.url(&format!("/connections/{}", id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    let body: serde_json::Value = client
        .get(app.url("/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["connections"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_connections_metadata_has_stable_ipv6_types() {
    let app = spawn_app("", "").await;
    app.state.connection_tracker.register(ConnectionEntry {
        id: "ipv6".into(),
        source: "[2001:db8::1]:1234".into(),
        destination: "[2001:db8::2]:443".into(),
        proxy: "proxy".into(),
        rule: "Match".into(),
        rule_payload: String::new(),
        chains: vec!["node-a".into(), "proxy".into()],
        upload: Arc::new(AtomicU64::new(3)),
        download: Arc::new(AtomicU64::new(4)),
        start_time: Instant::now(),
        domain: Some("ipv6.example".into()),
        network: "tcp".into(),
        dscp: 12,
        close_handle: ConnectionCloseHandle::detached(),
    });

    let body: serde_json::Value = http_client()
        .get(app.url("/connections"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let metadata = body["connections"][0]["metadata"].as_object().unwrap();
    assert_eq!(metadata["sourceIP"], "2001:db8::1");
    assert_eq!(metadata["destinationIP"], "2001:db8::2");
    assert_eq!(metadata["sourcePort"], "1234");
    assert_eq!(metadata["destinationPort"], "443");
    assert_eq!(metadata["dscp"], 12);
    assert!(metadata["dscp"].is_number());
    assert!(metadata["uid"].is_number());
    let string_fields = [
        "destinationGeoIP",
        "destinationIP",
        "destinationIPASN",
        "destinationPort",
        "dnsMode",
        "host",
        "inboundIP",
        "inboundName",
        "inboundPort",
        "inboundUser",
        "network",
        "process",
        "processPath",
        "remoteDestination",
        "sniffHost",
        "sourceGeoIP",
        "sourceIP",
        "sourceIPASN",
        "sourcePort",
        "specialProxy",
        "specialRules",
        "type",
        "smartBlock",
    ];
    for field in string_fields {
        assert!(metadata[field].is_string(), "metadata.{field}");
    }
    assert_eq!(metadata.len(), string_fields.len() + 2);
    assert_eq!(body["uploadTotal"], 3);
    assert_eq!(body["downloadTotal"], 4);
}

/// Plaintext HTTP server answering 204 to everything.
async fn spawn_mock_http_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

async fn spawn_subscription_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let server_hits = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            server_hits.fetch_add(1, Ordering::AcqRel);
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = socket.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}/subscription"), hits)
}

async fn spawn_controlled_subscription_server(
    body: &'static str,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hit = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let server_hits = Arc::clone(&hits);
    let server_hit = Arc::clone(&hit);
    let server_release = Arc::clone(&release);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            server_hits.fetch_add(1, Ordering::AcqRel);
            server_hit.notify_one();
            let release = Arc::clone(&server_release);
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = socket.read(&mut request).await;
                release.notified().await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}/subscription"), hits, hit, release)
}

fn make_ui_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, contents) in entries {
        writer.start_file(*name, options).unwrap();
        std::io::Write::write_all(&mut writer, contents).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

async fn spawn_ui_archive_server(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = socket.read(&mut request).await;
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    format!("http://{addr}/dist.zip")
}

async fn spawn_controlled_ui_archive_server(
    body: Vec<u8>,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Semaphore>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hit = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let server_hits = Arc::clone(&hits);
    let server_hit = Arc::clone(&hit);
    let server_release = Arc::clone(&release);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let body = body.clone();
            let hits = Arc::clone(&server_hits);
            let hit = Arc::clone(&server_hit);
            let release = Arc::clone(&server_release);
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = socket.read(&mut request).await;
                hits.fetch_add(1, Ordering::AcqRel);
                hit.notify_one();
                let _permit = release.acquire().await.unwrap();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            });
        }
    });
    (format!("http://{addr}/dist.zip"), hits, hit, release)
}

#[tokio::test]
async fn test_group_delay_omits_failed_members() {
    let app = spawn_app("", "").await;
    let client = http_client();
    let http_addr = spawn_mock_http_server().await;

    // Pre-seed latency history; a failed measurement must clear it.
    app.state.alive_set.record_probe_latency(
        "node-a",
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(123),
    );

    // The URL is https but the server speaks plaintext HTTP: the TLS
    // handshake fails, so both members are omitted from the result.
    let url = format!("https://{}/", http_addr);
    let resp = client
        .get(app.url(&format!("/group/proxy/delay?url={}&timeout=3000", url)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let map = body.as_object().unwrap();
    assert!(
        !map.contains_key("node-a") && !map.contains_key("node-b"),
        "failed members must be omitted, got: {map:?}"
    );

    // Failure replaced the seeded history with the synthetic penalty sample,
    // so the node can no longer rank by its stale 123ms.
    assert_eq!(
        app.state
            .alive_set
            .get_last_latency("node-a", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_secs(10))
    );

    // Unknown group → 404.
    let resp = client
        .get(app.url("/group/nope/delay"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_node_delay_failure_is_503() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Nothing listens on 127.0.0.1:1 → measurement fails → 503 message body.
    let resp = client
        .get(app.url("/proxies/node-a/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("delay test"));

    // Unknown proxy → 404.
    let resp = client
        .get(app.url("/proxies/nope/delay"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Nested groups on the delay endpoints: `/group/{name}/delay` flattens
/// sub-group members to their representative leaves (failures clear the
/// LEAF's latency history), and `/proxies/{subgroup-tag}/delay` works
/// through the group branch.
#[tokio::test]
async fn test_nested_group_delay_endpoints() {
    let (a, b) = (make_node("node-a"), make_node("node-b"));
    let sub = Group {
        name: "sub".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![b.id],
        ..Default::default()
    };
    let parent = Group {
        name: "parent".into(),
        policy: honk_config::group::GroupPolicy::Selector,
        nodes: vec![a.id],
        groups: vec!["sub".into()],
        ..Default::default()
    };
    let config = Config {
        nodes: vec![a, b],
        groups: vec![parent, sub],
        ..Default::default()
    };
    let app = spawn_app_with_config(config, "", "").await;
    let client = http_client();

    // Seed latency on the sub-group's leaf: a failed measurement of the
    // parent must clear it (proof the leaf was actually measured).
    app.state.alive_set.record_probe_latency(
        "node-b",
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(55),
    );

    let resp = client
        .get(app.url("/group/parent/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let map = body.as_object().unwrap();
    assert!(
        !map.contains_key("node-a") && !map.contains_key("sub"),
        "failed members must be omitted, got: {map:?}"
    );
    assert_eq!(
        app.state
            .alive_set
            .get_last_latency("node-b", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_secs(10)),
        "sub-group leaf must have been measured (penalty sample on failure)"
    );

    // The sub-group tag itself is a valid delay target (group branch):
    // its member fails the measurement → 503, not 404.
    let resp = client
        .get(app.url("/proxies/sub/delay?url=https://127.0.0.1:1/&timeout=1000"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
}

#[tokio::test]
async fn test_cache_flush_endpoints() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let db = app.state.cache_db.as_ref().unwrap();
    db.set("fakeip:198.18.0.1", "example.com");
    assert!(db.get("fakeip:198.18.0.1").is_some());

    let resp = client
        .post(app.url("/cache/fakeip/flush"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(db.get("fakeip:198.18.0.1").is_none());
    // Unrelated keys survive the prefix flush.
    db.save_selector_choice("proxy", "node-a");
    assert!(db.load_selector_choice("proxy").is_some());

    // DNS cache flush clears both the in-memory cache and persisted answers.
    let now = honk_core::dns::persist::unix_now();
    db.save_dns_answer("example.com", 1, r#"{"r":"QUJD"}"#, now + 300);
    app.state
        .dns_service
        .cache()
        .lock()
        .await
        .put("example.com:1".into(), vec![1, 2, 3], 300);
    assert!(
        app.state
            .dns_service
            .cache()
            .lock()
            .await
            .get("example.com:1")
            .is_some()
    );
    assert_eq!(db.load_dns_answers(now).len(), 1);

    let resp = client
        .post(app.url("/cache/dns/flush"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert!(
        app.state
            .dns_service
            .cache()
            .lock()
            .await
            .get("example.com:1")
            .is_none()
    );
    assert!(db.load_dns_answers(now).is_empty());
    // The selector choice is untouched by the DNS flush.
    assert!(db.load_selector_choice("proxy").is_some());
}

#[tokio::test]
async fn test_external_ui_static_hosting() {
    let ui_tmp = tempfile::tempdir().unwrap();
    std::fs::write(ui_tmp.path().join("index.html"), "<html>honk-ui</html>").unwrap();

    let app = spawn_app("", ui_tmp.path().to_str().unwrap()).await;
    let client = http_client();

    // /ui → 301 to /ui/.
    let resp = client.get(app.url("/ui")).send().await.unwrap();
    assert_eq!(resp.status(), 301);
    assert_eq!(resp.headers()["location"], "/ui/");

    // /ui/ serves index.html.
    let resp = client.get(app.url("/ui/")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("honk-ui"));

    // Missing file → 404 (no panic).
    let resp = client.get(app.url("/ui/nope.txt")).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    // Browser-style GET / redirects to the UI; JSON clients get hello.
    let resp = client.get(app.url("/")).send().await.unwrap();
    assert_eq!(resp.status(), 302);
    let resp = client
        .get(app.url("/"))
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["hello"], "clash");
}

#[tokio::test]
async fn test_ui_upgrade_auth_failure_preservation_and_success() {
    let empty = spawn_app("topsecret", "").await;
    let client = http_client();
    assert_eq!(
        client
            .post(empty.url("/upgrade/ui"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(empty.url("/upgrade/ui"))
            .bearer_auth("topsecret")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );

    let root = tempfile::tempdir().unwrap();
    let ui_dir = root.path().join("ui");
    std::fs::create_dir_all(ui_dir.join("assets")).unwrap();
    std::fs::write(ui_dir.join("index.html"), "old-index").unwrap();
    std::fs::write(ui_dir.join("assets/app.js"), "old-asset").unwrap();
    let invalid_url = spawn_ui_archive_server(make_ui_zip(&[(
        "dist/assets/app.js",
        b"invalid-without-index".as_slice(),
    )]))
    .await;
    let invalid = spawn_app_with_config_and_ui_url(
        test_config(),
        "topsecret",
        ui_dir.to_str().unwrap(),
        Some(invalid_url),
    )
    .await;
    assert_eq!(
        client
            .post(invalid.url("/upgrade/ui"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(invalid.url("/upgrade/ui"))
            .bearer_auth("topsecret")
            .send()
            .await
            .unwrap()
            .status(),
        500
    );
    assert_eq!(
        std::fs::read_to_string(ui_dir.join("index.html")).unwrap(),
        "old-index"
    );
    assert_eq!(
        std::fs::read_to_string(ui_dir.join("assets/app.js")).unwrap(),
        "old-asset"
    );

    let download_failure = spawn_app_with_config_and_ui_url(
        test_config(),
        "topsecret",
        ui_dir.to_str().unwrap(),
        Some("http://127.0.0.1:9/dist.zip".into()),
    )
    .await;
    assert_eq!(
        client
            .post(download_failure.url("/upgrade/ui"))
            .bearer_auth("topsecret")
            .send()
            .await
            .unwrap()
            .status(),
        500
    );
    assert_eq!(
        std::fs::read_to_string(ui_dir.join("index.html")).unwrap(),
        "old-index"
    );

    let valid_url = spawn_ui_archive_server(make_ui_zip(&[
        ("dist/index.html", b"new-index".as_slice()),
        ("dist/assets/app.js", b"new-asset".as_slice()),
    ]))
    .await;
    let valid = spawn_app_with_config_and_ui_url(
        test_config(),
        "topsecret",
        ui_dir.to_str().unwrap(),
        Some(valid_url),
    )
    .await;
    assert_eq!(
        client
            .post(valid.url("/upgrade/ui"))
            .bearer_auth("topsecret")
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        std::fs::read_to_string(ui_dir.join("index.html")).unwrap(),
        "new-index"
    );
    assert_eq!(
        std::fs::read_to_string(ui_dir.join("assets/app.js")).unwrap(),
        "new-asset"
    );
    assert_eq!(
        client
            .get(valid.url("/ui/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "new-index"
    );
}

#[tokio::test]
async fn test_ui_static_reads_see_complete_tree_during_update() {
    let root = tempfile::tempdir().unwrap();
    let ui_dir = root.path().join("ui");
    std::fs::create_dir_all(ui_dir.join("assets")).unwrap();
    std::fs::write(ui_dir.join("index.html"), "old-index").unwrap();
    std::fs::write(ui_dir.join("assets/app.js"), "old-asset").unwrap();
    let (url, hits, hit, release) = spawn_controlled_ui_archive_server(make_ui_zip(&[
        ("dist/index.html", b"new-index".as_slice()),
        ("dist/assets/app.js", b"new-asset".as_slice()),
    ]))
    .await;
    let app = spawn_app_with_config_and_ui_url(
        test_config(),
        "topsecret",
        ui_dir.to_str().unwrap(),
        Some(url),
    )
    .await;
    let client = http_client();
    let update = tokio::spawn({
        let client = client.clone();
        let url = app.url("/upgrade/ui");
        async move {
            client
                .post(url)
                .bearer_auth("topsecret")
                .send()
                .await
                .unwrap()
        }
    });
    hit.notified().await;
    for _ in 0..10 {
        let index = client.get(app.url("/ui/")).send().await.unwrap();
        let asset = client
            .get(app.url("/ui/assets/app.js"))
            .send()
            .await
            .unwrap();
        assert_eq!(index.status(), 200);
        assert_eq!(asset.status(), 200);
        assert_eq!(index.text().await.unwrap(), "old-index");
        assert_eq!(asset.text().await.unwrap(), "old-asset");
    }
    release.add_permits(1);
    assert_eq!(update.await.unwrap().status(), 204);
    assert_eq!(hits.load(Ordering::Acquire), 1);
    for _ in 0..10 {
        let index = client.get(app.url("/ui/")).send().await.unwrap();
        let asset = client
            .get(app.url("/ui/assets/app.js"))
            .send()
            .await
            .unwrap();
        assert_eq!(index.status(), 200);
        assert_eq!(asset.status(), 200);
        assert_eq!(index.text().await.unwrap(), "new-index");
        assert_eq!(asset.text().await.unwrap(), "new-asset");
    }
}

#[tokio::test]
async fn test_ui_startup_and_post_updates_share_one_lock() {
    let root = tempfile::tempdir().unwrap();
    let ui_dir = root.path().join("ui");
    let (url, hits, hit, release) = spawn_controlled_ui_archive_server(make_ui_zip(&[
        ("dist/index.html", b"complete-index".as_slice()),
        ("dist/assets/app.js", b"complete-asset".as_slice()),
    ]))
    .await;
    let app = spawn_app_with_config_and_ui_url(
        test_config(),
        "topsecret",
        ui_dir.to_str().unwrap(),
        Some(url),
    )
    .await;
    hit.notified().await;
    let client = http_client();
    let update = tokio::spawn({
        let client = client.clone();
        let url = app.url("/upgrade/ui");
        async move {
            client
                .post(url)
                .bearer_auth("topsecret")
                .send()
                .await
                .unwrap()
        }
    });
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::Acquire), 1);
    release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ui_dir.join("index.html").is_file() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    hit.notified().await;
    assert_eq!(hits.load(Ordering::Acquire), 2);
    let index = client.get(app.url("/ui/")).send().await.unwrap();
    let asset = client
        .get(app.url("/ui/assets/app.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(index.status(), 200);
    assert_eq!(asset.status(), 200);
    assert_eq!(index.text().await.unwrap(), "complete-index");
    assert_eq!(asset.text().await.unwrap(), "complete-asset");
    release.add_permits(1);
    assert_eq!(update.await.unwrap().status(), 204);
}

/// /traffic pushes per-second deltas; WS auth accepts `?token=<secret>`.
#[tokio::test]
async fn test_traffic_ws_with_token_auth() {
    let app = spawn_app("topsecret", "").await;

    let ws_url = format!("ws://{}/traffic?token=topsecret", app.addr);
    let (mut ws, resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    assert_eq!(resp.status().as_u16(), 101);

    // Let the WS task take its baseline, then add traffic: the next
    // per-second frame must report exactly this delta.
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let stats = &app.state.stats;
        stats.record_bytes("proxy", 500, 1500);
    }

    use futures::StreamExt;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("traffic frame within 5s")
            .unwrap()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        if v["up"] == 500 && v["down"] == 1500 {
            break;
        }
        // Ticks before the record landed report 0/0 — keep waiting.
    }

    // WS with a wrong token → 401 during the handshake.
    let bad_url = format!("ws://{}/traffic?token=nope", app.addr);
    let err = tokio_tungstenite::connect_async(bad_url).await;
    assert!(err.is_err());
}

/// WS auth percent-decodes `?token=` before comparing to the secret, so
/// secrets containing reserved characters (`+`, `=`) authenticate both in
/// their percent-encoded form (what WS clients should send) and raw form.
#[tokio::test]
async fn test_ws_token_percent_decoded() {
    let secret = "s3+cr=t";
    let app = spawn_app(secret, "").await;

    // Percent-encoded form: %2B = '+', %3D = '='.
    let (mut ws, resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3%2Bcr%3Dt", app.addr))
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    // The stream is live: a per-second traffic frame arrives.
    use futures::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("traffic frame within 5s")
        .unwrap();
    assert!(msg.is_ok());
    drop(ws);

    // Raw form: '+' and '=' need no encoding inside a query value.
    let (_, resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3+cr=t", app.addr))
            .await
            .unwrap();
    assert_eq!(resp.status().as_u16(), 101);

    // A token decoding to a different value is still rejected.
    let err =
        tokio_tungstenite::connect_async(format!("ws://{}/traffic?token=s3%2Bcr%3Du", app.addr))
            .await;
    assert!(err.is_err());
}

/// /connections streams the same JSON shape as plain GET.
#[tokio::test]
async fn test_connections_ws_stream() {
    let app = spawn_app("", "").await;
    app.state.connection_tracker.register(ConnectionEntry {
        id: "ws-conn".into(),
        source: "10.0.0.3:5555".into(),
        destination: "1.1.1.1:443".into(),
        proxy: "proxy".into(),
        rule: "Match".into(),
        rule_payload: String::new(),
        chains: vec!["node-a".into(), "proxy".into()],
        upload: std::sync::Arc::new(AtomicU64::new(1)),
        download: std::sync::Arc::new(AtomicU64::new(2)),
        start_time: Instant::now(),
        domain: None,
        network: "tcp".into(),
        dscp: 0,
        close_handle: ConnectionCloseHandle::detached(),
    });

    let ws_url = format!("ws://{}/connections?interval=200", app.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    use futures::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("connections frame within 5s")
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
    let conns = v["connections"].as_array().unwrap();
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0]["id"], "ws-conn");
}

/// Plain GET /traffic returns a chunked JSON stream with per-second frames.
#[tokio::test]
async fn test_traffic_chunked_fallback() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/traffic")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");
    // Streaming bodies have no known length → chunked transfer encoding.
    assert_eq!(resp.headers()["transfer-encoding"], "chunked");

    // The first frame arrives after the first 1s tick.
    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("traffic frame within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let first_line = text.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert!(v.get("up").is_some() && v.get("down").is_some());
}

#[tokio::test]
async fn test_memory_ws_and_chunked_stream_real_rss() {
    use futures::StreamExt;

    let app = spawn_app("", "").await;
    let client = http_client();
    let mut response = client.get(app.url("/memory")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let chunk = tokio::time::timeout(Duration::from_secs(2), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim()).unwrap();
    assert!(frame["inuse"].as_u64().unwrap() > 0);
    assert!(frame.get("goroutines").is_none());
    drop(response);

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{}/memory", app.addr))
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: serde_json::Value = serde_json::from_str(&message.into_text().unwrap()).unwrap();
    assert!(frame["inuse"].as_u64().unwrap() > 0);
    assert!(frame.get("goroutines").is_none());
}

#[tokio::test]
async fn test_traffic_sampler_does_not_replay_disconnected_bytes() {
    let app = spawn_app("", "").await;
    let client = http_client();
    let mut first = client.get(app.url("/traffic")).send().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), first.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(first);

    app.state.stats.record_bytes("fixture", 100, 200);
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let mut reconnected = client.get(app.url("/traffic")).send().await.unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(2), reconnected.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim()).unwrap();
    assert_eq!(frame["up"], 0);
    assert_eq!(frame["down"], 0);
}

#[tokio::test]
async fn test_traffic_sampler_reports_live_tcp_deltas() {
    let app = spawn_app("", "").await;
    let upload = Arc::new(AtomicU64::new(0));
    let download = Arc::new(AtomicU64::new(0));
    app.state.connection_tracker.register(ConnectionEntry {
        id: "live-traffic".into(),
        source: "127.0.0.1:1000".into(),
        destination: "127.0.0.1:2000".into(),
        proxy: "proxy".into(),
        rule: "Match".into(),
        rule_payload: String::new(),
        chains: vec!["proxy".into()],
        upload: Arc::clone(&upload),
        download: Arc::clone(&download),
        start_time: Instant::now(),
        domain: None,
        network: "tcp".into(),
        dscp: 0,
        close_handle: ConnectionCloseHandle::detached(),
    });

    let mut response = http_client().get(app.url("/traffic")).send().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    upload.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    download.fetch_add(9, std::sync::atomic::Ordering::Relaxed);
    let chunk = tokio::time::timeout(Duration::from_secs(2), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let frame: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&chunk).unwrap().trim()).unwrap();
    assert_eq!(frame["up"], 7);
    assert_eq!(frame["down"], 9);
}

/// Plain GET /logs streams one JSON document per log event.
#[tokio::test]
async fn test_logs_chunked_fallback() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/logs")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "application/json");

    // Publish an event after the stream is set up.
    app.state
        .log_tx
        .send(honk_core::clash_api::logs::LogEvent {
            level: tracing::Level::INFO,
            payload: "chunked-log-line".into(),
        })
        .unwrap();

    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("log line within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(v["type"], "info");
    assert_eq!(v["payload"], "chunked-log-line");
}

#[tokio::test]
async fn test_logs_threshold_aliases_and_silent_lifecycle() {
    use futures::StreamExt;

    let app = spawn_app("", "").await;
    let client = http_client();
    let mut warning = client
        .get(app.url("/logs?level=warning"))
        .send()
        .await
        .unwrap();
    app.state
        .log_tx
        .send(honk_core::clash_api::logs::LogEvent {
            level: tracing::Level::INFO,
            payload: "filtered-info".into(),
        })
        .unwrap();
    app.state
        .log_tx
        .send(honk_core::clash_api::logs::LogEvent {
            level: tracing::Level::WARN,
            payload: "visible-warning".into(),
        })
        .unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(2), warning.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let event: serde_json::Value =
        serde_json::from_slice(chunk.as_ref().split(|byte| *byte == b'\n').next().unwrap())
            .unwrap();
    assert_eq!(event["type"], "warn");
    assert_eq!(event["payload"], "visible-warning");
    drop(warning);

    let mut fatal = client
        .get(app.url("/logs?level=fatal"))
        .send()
        .await
        .unwrap();
    app.state
        .log_tx
        .send(honk_core::clash_api::logs::LogEvent {
            level: tracing::Level::ERROR,
            payload: "fatal-threshold".into(),
        })
        .unwrap();
    let chunk = tokio::time::timeout(Duration::from_secs(2), fatal.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let event: serde_json::Value =
        serde_json::from_slice(chunk.as_ref().split(|byte| *byte == b'\n').next().unwrap())
            .unwrap();
    assert_eq!(event["type"], "error");
    drop(fatal);

    tokio::time::timeout(Duration::from_secs(1), async {
        while app.state.log_tx.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped log bodies release broadcast receivers");
    let mut silent = client
        .get(app.url("/logs?level=silent"))
        .send()
        .await
        .unwrap();
    assert_eq!(app.state.log_tx.receiver_count(), 0);
    assert!(
        app.state
            .log_tx
            .send(honk_core::clash_api::logs::LogEvent {
                level: tracing::Level::ERROR,
                payload: "discarded".into(),
            })
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), silent.chunk())
            .await
            .is_err()
    );
    drop(silent);
    assert_eq!(app.state.log_tx.receiver_count(), 0);

    let response = client
        .get(app.url("/logs?level=verbose"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    let silent_ws_app = spawn_app("", "").await;
    let (mut ws, response) =
        tokio_tungstenite::connect_async(format!("ws://{}/logs?level=silent", silent_ws_app.addr))
            .await
            .unwrap();
    assert_eq!(response.status().as_u16(), 101);
    assert_eq!(silent_ws_app.state.log_tx.receiver_count(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .is_err()
    );
    ws.close(None).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(silent_ws_app.state.log_tx.receiver_count(), 0);
}

#[tokio::test]
async fn test_dns_query_from_cache() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Pre-seed the shared DNS cache so the forwarder answers from cache.
    app.state.dns_service.cache().lock().await.put(
        "example.com:1".into(),
        a_record_response([93, 184, 216, 34], 300),
        300,
    );

    let body: serde_json::Value = client
        .get(app.url("/dns/query?name=example.com&type=A"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 0);
    assert_eq!(body["Question"][0]["name"], "example.com");
    assert_eq!(body["Question"][0]["type"], 1);
    assert_eq!(body["Answer"][0]["name"], "example.com");
    assert_eq!(body["Answer"][0]["type"], 1);
    assert_eq!(body["Answer"][0]["TTL"], 300);
    assert_eq!(body["Answer"][0]["data"], "93.184.216.34");
}

#[tokio::test]
async fn test_dns_query_upstream_and_nxdomain() {
    let app = spawn_app("", "").await;
    let client = http_client();

    // Cache miss → the mock upstream answers with the canned A response.
    let body: serde_json::Value = client
        .get(app.url("/dns/query?name=example.com"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 0);
    assert_eq!(body["Answer"][0]["data"], "93.184.216.34");

    // NXDOMAIN: swap in a forwarder whose upstream returns RCODE 3.
    let nx_service = honk_core::dns::DnsService::with_forwarder(Arc::new(test_dns_forwarder(
        app.state.dns_service.cache(),
        nxdomain_response(),
    )));
    let state = Arc::new(ClashState {
        config: app.state.config.clone(),
        config_path: app.state.config_path.clone(),
        command_tx: app.state.command_tx.clone(),
        subscription_refresh: app.state.subscription_refresh.clone(),
        dashboard_storage: parking_lot::RwLock::new(app.state.dashboard_storage.read().clone()),
        ui_update_lock: app.state.ui_update_lock.clone(),
        stats: app.state.stats.clone(),
        alive_set: app.state.alive_set.clone(),
        group_manager: app.state.group_manager.clone(),
        cache_db: app.state.cache_db.clone(),
        connection_tracker: app.state.connection_tracker.clone(),
        proxy_registry: app.state.proxy_registry.clone(),
        mode_state: app.state.mode_state.clone(),
        secret: String::new(),
        external_ui: String::new(),
        log_tx: app.state.log_tx.clone(),
        dns_service: nx_service,
        ui_download_url: app.state.ui_download_url.clone(),
        connection_pool: app.state.connection_pool.clone(),
        stream_samplers: app.state.stream_samplers.clone(),
    });
    let nx_app = clash_api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, nx_app).await;
    });

    // Fresh name so the negative cache from earlier queries does not apply.
    let body: serde_json::Value = client
        .get(format!("http://{}/dns/query?name=nx.example.com", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 3, "NXDOMAIN maps to Status 3");
    assert_eq!(body["Answer"].as_array().unwrap().len(), 0);

    // The NXDOMAIN is now in the negative cache; the same query again is
    // answered from it with the same proper NXDOMAIN Status 3 (a negative
    // hit must not degrade into SERVFAIL).
    let body: serde_json::Value = client
        .get(format!("http://{}/dns/query?name=nx.example.com", addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["Status"], 3);
    assert_eq!(body["Answer"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_dns_query_missing_name_is_400() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let resp = client.get(app.url("/dns/query")).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("name"));

    let resp = client
        .get(app.url("/dns/query?name=&type=A"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = client
        .get(app.url("/dns/query?name=example.com&type=bogus"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_proxy_providers_follow_subscription_identity() {
    let primary_id = uuid::Uuid::new_v4();
    let duplicate_id = uuid::Uuid::new_v4();
    let disabled_id = uuid::Uuid::new_v4();
    let updated_at = chrono::Utc::now();
    let primary = Subscription {
        id: primary_id,
        name: "provider".into(),
        url: "https://subscriptions.example/primary".into(),
        enabled: true,
        last_updated: Some(updated_at),
        ..Default::default()
    };
    let duplicate = Subscription {
        id: duplicate_id,
        name: "provider".into(),
        url: "https://subscriptions.example/duplicate".into(),
        enabled: true,
        ..Default::default()
    };
    let disabled = Subscription {
        id: disabled_id,
        name: "disabled".into(),
        url: "https://subscriptions.example/disabled".into(),
        enabled: false,
        ..Default::default()
    };
    let mut primary_node = make_node("primary-node");
    primary_node.protocol = NodeProtocol::SS;
    primary_node.subscription_id = Some(primary_id);
    let mut duplicate_node = make_node("duplicate-node");
    duplicate_node.subscription_id = Some(duplicate_id);
    let mut disabled_node = make_node("disabled-node");
    disabled_node.subscription_id = Some(disabled_id);
    let static_node = make_node("static-node");
    let mut config = Config {
        nodes: vec![primary_node, duplicate_node, disabled_node, static_node],
        subscriptions: vec![primary, duplicate, disabled],
        ..Default::default()
    };
    config.global.tcp_check_url = vec!["https://probe.example/generate_204".into()];
    let app = spawn_app_with_config(config, "", "").await;
    let client = http_client();

    let body: serde_json::Value = client
        .get(app.url("/providers/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let providers = body["providers"].as_object().unwrap();
    assert_eq!(providers.len(), 1);
    let provider = &providers["provider"];
    assert_eq!(provider["name"], "provider");
    assert_eq!(provider["type"], "Proxy");
    assert_eq!(provider["vehicleType"], "HTTP");
    assert_eq!(provider["updatedAt"], updated_at.to_rfc3339());
    assert_eq!(provider["testUrl"], "https://probe.example/generate_204");
    assert!(provider.get("subscriptionInfo").is_none());
    assert!(provider.get("quota").is_none());
    assert_eq!(
        provider["proxies"],
        serde_json::json!([{
            "name": "primary-node",
            "type": "Shadowsocks",
            "udp": true,
            "history": []
        }])
    );

    app.state.config.write().await.subscriptions.clear();
    let empty: serde_json::Value = client
        .get(app.url("/providers/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty["providers"], serde_json::json!({}));

    let rule_providers: serde_json::Value = client
        .get(app.url("/providers/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rule_providers["providers"], serde_json::json!({}));
}

#[tokio::test]
async fn test_provider_healthchecks_validate_ownership_and_scope_history() {
    let provider_id = uuid::Uuid::new_v4();
    let disabled_id = uuid::Uuid::new_v4();
    let provider = Subscription {
        id: provider_id,
        name: "provider".into(),
        url: "https://subscriptions.example/provider".into(),
        enabled: true,
        ..Default::default()
    };
    let disabled = Subscription {
        id: disabled_id,
        name: "disabled".into(),
        url: "https://subscriptions.example/disabled".into(),
        enabled: false,
        ..Default::default()
    };
    let mut member = make_node("member");
    member.subscription_id = Some(provider_id);
    let mut disabled_member = make_node("disabled-member");
    disabled_member.subscription_id = Some(disabled_id);
    let outsider = make_node("outsider");
    let mut config = Config {
        nodes: vec![member, disabled_member, outsider],
        subscriptions: vec![provider, disabled],
        ..Default::default()
    };
    config.global.tcp_check_url = vec!["https://127.0.0.1:1/".into()];
    let app = spawn_app_with_config(config, "", "").await;
    let client = http_client();
    app.state.alive_set.record_probe_latency(
        "member",
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(123),
    );
    app.state.alive_set.record_probe_latency(
        "outsider",
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(456),
    );

    let response = client
        .get(app.url(
            "/providers/proxies/provider/member/healthcheck?url=https://127.0.0.1:1/&timeout=20",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        app.state
            .alive_set
            .get_last_latency("member", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_secs(10))
    );
    assert_eq!(
        app.state
            .alive_set
            .get_last_latency("outsider", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(456))
    );

    let wrong_owner = client
        .get(app.url("/providers/proxies/provider/outsider/healthcheck?url=https://127.0.0.1:1/"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_owner.status(), 404);
    assert_eq!(
        client
            .get(app.url("/providers/proxies/nope/member/healthcheck"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(app.url("/providers/proxies/disabled/disabled-member/healthcheck",))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );

    let provider_delays: serde_json::Value =
        client
            .get(app.url(
                "/providers/proxies/provider/healthcheck?url=https://ignored.example/&timeout=20",
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(provider_delays, serde_json::json!({}));
    assert_eq!(
        app.state
            .alive_set
            .get_last_latency("outsider", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(456))
    );
    assert_eq!(
        client
            .get(app.url("/providers/proxies/nope/healthcheck"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(app.url("/providers/proxies/disabled/healthcheck"))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
}

#[tokio::test]
async fn test_provider_refresh_waits_for_merge_and_maps_failures() {
    let (subscription_url, hits) = spawn_subscription_server("socks5://127.0.0.1:1080#fresh").await;
    let subscription = Subscription {
        id: uuid::Uuid::new_v4(),
        name: "provider".into(),
        url: subscription_url.clone(),
        enabled: true,
        ..Default::default()
    };
    let disabled = Subscription {
        id: uuid::Uuid::new_v4(),
        name: "disabled".into(),
        url: subscription_url.clone(),
        enabled: false,
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            subscriptions: vec![subscription.clone(), disabled],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let client = http_client();
    let refresh_url = app.url("/providers/proxies/provider");
    let request = tokio::spawn({
        let client = client.clone();
        async move { client.put(refresh_url).send().await.unwrap() }
    });
    let (merged_subscription, nodes, completion) = next_merge(&app).await;
    assert_eq!(merged_subscription.id, subscription.id);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "fresh");
    assert_eq!(nodes[0].subscription_id, Some(subscription.id));
    assert!(!request.is_finished());
    completion.send(Ok(())).unwrap();
    assert_eq!(request.await.unwrap().status(), 204);
    assert_eq!(hits.load(Ordering::Acquire), 1);
    assert_eq!(
        client
            .put(app.url("/providers/proxies/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .put(app.url("/providers/proxies/disabled"))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );

    let rejected_subscription = Subscription {
        id: uuid::Uuid::new_v4(),
        name: "rejected".into(),
        url: subscription_url.clone(),
        enabled: true,
        ..Default::default()
    };
    let rejected = spawn_app_with_config(
        Config {
            subscriptions: vec![rejected_subscription],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    let rejected_request = tokio::spawn({
        let client = client.clone();
        let url = rejected.url("/providers/proxies/rejected");
        async move { client.put(url).send().await.unwrap() }
    });
    let (_, _, completion) = next_merge(&rejected).await;
    completion
        .send(Err("stale subscription fetch".into()))
        .unwrap();
    assert_eq!(rejected_request.await.unwrap().status(), 409);

    let fetch_failure = spawn_app_with_config(
        Config {
            subscriptions: vec![Subscription {
                id: uuid::Uuid::new_v4(),
                name: "fetch-failure".into(),
                url: "http://127.0.0.1:9/subscription".into(),
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    assert_eq!(
        client
            .put(fetch_failure.url("/providers/proxies/fetch-failure"))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );

    let unavailable = spawn_app_with_config(
        Config {
            subscriptions: vec![Subscription {
                id: uuid::Uuid::new_v4(),
                name: "unavailable".into(),
                url: subscription_url,
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    unavailable.commands.lock().await.close();
    assert_eq!(
        client
            .put(unavailable.url("/providers/proxies/unavailable"))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
}

#[tokio::test(start_paused = true)]
async fn test_provider_put_joins_periodic_refresh_single_flight() {
    let (subscription_url, hits, hit, release) =
        spawn_controlled_subscription_server("socks5://127.0.0.1:1080#fresh").await;
    let subscription = Subscription {
        id: uuid::Uuid::new_v4(),
        name: "provider".into(),
        url: subscription_url,
        enabled: true,
        update_interval: 1,
        ..Default::default()
    };
    let app = spawn_app_with_config(
        Config {
            subscriptions: vec![subscription.clone()],
            ..Default::default()
        },
        "",
        "",
    )
    .await;
    app.state
        .subscription_refresh
        .reconcile(std::slice::from_ref(&subscription))
        .await;
    tokio::task::yield_now().await;

    let request = tokio::spawn({
        let client = http_client();
        let url = app.url("/providers/proxies/provider");
        async move { client.put(url).send().await.unwrap() }
    });
    hit.notified().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    release.notify_one();

    let (merged_subscription, nodes, completion) = next_merge(&app).await;
    assert_eq!(merged_subscription.id, subscription.id);
    assert_eq!(nodes.len(), 1);
    assert!(!request.is_finished());
    completion.send(Ok(())).unwrap();
    assert_eq!(request.await.unwrap().status(), 204);
    tokio::task::yield_now().await;
    assert_eq!(hits.load(Ordering::Acquire), 1);
    assert!(matches!(
        app.commands.lock().await.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn test_store_dns_persister_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cache.db");
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: db_path.to_str().unwrap().to_string(),
        store_dns: true,
        ..Default::default()
    };
    let db = Arc::new(CacheDb::open(&cache_cfg, None).unwrap());

    let dns_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let dns_config = DnsConfig::default();
    let policy = honk_core::dns::policy::PolicyId::from_config(&dns_config).unwrap();
    let persister = honk_core::dns::persist::DnsCachePersister::spawn(db.clone());
    assert_eq!(
        persister
            .restore_cache(&dns_cache, Some(policy.clone()))
            .await
            .expect("initial restore"),
        0
    );
    dns_cache
        .lock()
        .await
        .set_persister(Some(persister.clone()));
    let forwarder = test_dns_forwarder(dns_cache.clone(), a_record_response([1, 2, 3, 4], 300))
        .with_policy_from_config(&dns_config)
        .unwrap();
    let response = forwarder
        .resolve(&build_dns_query("example.com", 1))
        .await
        .expect("initial resolve");
    assert_eq!(response, a_record_response([1, 2, 3, 4], 300));
    persister.shutdown().await.expect("persistence shutdown");
    assert_eq!(persister.counters().written, 1);

    let now = honk_core::dns::persist::unix_now();
    db.save_dns_answer("legacy.example", 1, r#"{"r":"TEVHQUNZ"}"#, now + 300);
    let fresh_cache = Arc::new(tokio::sync::Mutex::new(DnsCache::new(16)));
    let restart = honk_core::dns::persist::DnsCachePersister::spawn(db.clone());
    assert_eq!(
        restart
            .restore_cache(&fresh_cache, Some(policy))
            .await
            .expect("restart restore"),
        1
    );

    let forwarder = test_dns_forwarder(fresh_cache, nxdomain_response())
        .with_policy_from_config(&dns_config)
        .unwrap();
    let resp = forwarder
        .resolve(&build_dns_query("example.com", 1))
        .await
        .unwrap();
    assert_eq!(resp, a_record_response([1, 2, 3, 4], 300));
    restart.shutdown().await.expect("restart shutdown");
    assert_eq!(
        db.load_dns_answers(now).len(),
        1,
        "v2 restart must leave rollback-compatible legacy rows untouched"
    );
}

#[tokio::test]
async fn stats_exposes_udp_metrics() {
    let app = spawn_app("", "").await;
    app.state.stats.record_udp_endpoint_hit();
    app.state.stats.record_udp_slow_permit_accepted();

    let body: serde_json::Value = http_client()
        .get(app.url("/stats"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // UDP is additive: existing dashboard keys retain their shapes.
    assert!(body["outbounds"].is_array());
    assert!(body["pool"].is_object());

    let udp = &body["udp"];
    assert_eq!(udp["endpoint"]["hits"], 1);
    assert_eq!(udp["endpoint"]["misses"], 0);
    assert_eq!(udp["slowPermit"]["accepted"], 1);
    assert_eq!(udp["slowPermit"]["rejected"], 0);
    assert_eq!(udp["slowPermit"]["closed"], 0);
    // Endpoint-driver queue metrics are defined now but are Task 3-owned.
    assert_eq!(udp["queue"]["accepted"], 0);
    assert_eq!(udp["queue"]["full"], 0);
    assert_eq!(udp["queue"]["closed"], 0);
    assert_eq!(udp["capacity"]["rejected"], 0);
    assert_eq!(udp["firstSend"]["failures"], 0);
    assert_eq!(udp["latency"]["route"]["count"], 0);
    assert_eq!(udp["latency"]["dial"]["count"], 0);
    assert_eq!(udp["latency"]["replyReady"]["count"], 0);
    assert_eq!(udp["latency"]["firstSend"]["count"], 0);
    assert_eq!(udp["latency"]["firstReply"]["count"], 0);
    assert_eq!(udp["stagger"]["attempts"], 0);
    assert_eq!(udp["stagger"]["winners"], 0);
    assert_eq!(udp["stagger"]["cancellations"], 0);
    assert_eq!(udp["warm"]["attempts"], 0);
    assert_eq!(udp["warm"]["successes"], 0);
    assert_eq!(udp["warm"]["failures"], 0);
}
