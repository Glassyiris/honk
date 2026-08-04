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
use honk_config::types::NodeProtocol;
use honk_core::cachedb::CacheDb;
use honk_core::clash_api::{self, ClashState};
use honk_core::connection_tracker::{ConnectionEntry, ConnectionTracker};
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
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

fn make_node(name: &str) -> Node {
    Node {
        id: uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes()),
        name: name.into(),
        protocol: NodeProtocol::Socks5,
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
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("cache.db");
    let cache_cfg = CacheFileConfig {
        enabled: true,
        path: db_path.to_str().unwrap().to_string(),
        ..Default::default()
    };
    let db = Arc::new(CacheDb::open(&cache_cfg, None).expect("cache.db opens"));

    let alive_set = Arc::new(AliveDialerSet::new());
    let group_manager =
        GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive_set.clone()));
    // Wire the same persistence the control plane installs in production.
    {
        let db_cb = db.clone();
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
    let runtime_registry = honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes)
        .unwrap()
        .into_shared();
    let state = Arc::new(ClashState {
        config: Arc::new(tokio::sync::RwLock::new(config)),
        stats: stats.clone(),
        alive_set,
        group_manager,
        cache_db: Some(db),
        connection_tracker: connection_tracker.clone(),
        proxy_registry: Arc::new(ProxyRegistry::default_resolver().unwrap()),
        runtime_registry,
        mode_state: Arc::new(parking_lot::RwLock::new(ModeState::new("Rule", "proxy"))),
        secret: secret.to_string(),
        external_ui: external_ui.to_string(),
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

/// Plaintext HTTP server answering 204 to everything.
async fn spawn_mock_http_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn test_group_delay_omits_failed_members() {
    let app = spawn_app("", "").await;
    let client = http_client();
    let http_addr = spawn_mock_http_server().await;

    // Pre-seed latency history; a failed measurement must clear it.
    app.state.alive_set.record_probe_latency(
        make_node("node-a").id,
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
        app.state.alive_set.get_last_latency(
            make_node("node-a").id,
            ProbeDomain::Tcp,
            IpVersion::V4
        ),
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
        make_node("node-b").id,
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
        app.state.alive_set.get_last_latency(
            make_node("node-b").id,
            ProbeDomain::Tcp,
            IpVersion::V4
        ),
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

/// /memory streams per-second inuse/oslimit frames (chunked HTTP here).
#[tokio::test]
async fn test_memory_chunked_reports_rss() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let mut resp = client.get(app.url("/memory")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["transfer-encoding"], "chunked");

    let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
        .await
        .expect("memory frame within 5s")
        .unwrap()
        .expect("non-empty first chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(v["inuse"].as_u64().unwrap() > 0);
    assert_eq!(v["oslimit"], 0);
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
        stats: app.state.stats.clone(),
        alive_set: app.state.alive_set.clone(),
        group_manager: app.state.group_manager.clone(),
        cache_db: app.state.cache_db.clone(),
        connection_tracker: app.state.connection_tracker.clone(),
        proxy_registry: app.state.proxy_registry.clone(),
        runtime_registry: app.state.runtime_registry.clone(),
        mode_state: app.state.mode_state.clone(),
        secret: String::new(),
        external_ui: String::new(),
        log_tx: app.state.log_tx.clone(),
        dns_service: nx_service,
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
async fn test_proxy_providers_structure() {
    let app = spawn_app("", "").await;
    let client = http_client();

    let body: serde_json::Value = client
        .get(app.url("/providers/proxies"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let provider = &body["providers"]["proxy"];
    assert_eq!(provider["name"], "proxy");
    assert_eq!(provider["type"], "Proxy");
    assert_eq!(provider["vehicleType"], "Compatible");
    assert!(provider["updatedAt"].is_null());

    let proxies = provider["proxies"].as_array().unwrap();
    assert_eq!(proxies.len(), 2);
    assert_eq!(proxies[0]["name"], "node-a");
    assert_eq!(proxies[0]["type"], "Socks5");
    assert_eq!(proxies[0]["udp"], true);
    assert_eq!(proxies[1]["name"], "node-b");

    // Rule providers stay an empty list.
    let body: serde_json::Value = client
        .get(app.url("/providers/rules"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["providers"], serde_json::json!([]));
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
