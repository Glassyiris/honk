use super::*;
use crate::{
    control::{ControlCommand, ControlPlane},
    dns::DnsResolver,
    ebpf::mock::MockEbpfBackend,
    native_api::NativeServer,
    routing::Router,
    subscription::{SubscriptionStore, SubscriptionSupervisor},
};
use honk_config::{Config, node::Node};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::SystemTime,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);
const OLD: &str = "socks5://127.0.0.1:11080#old";
const NEW: &str = "socks5://127.0.0.1:11081#new";

struct Origin {
    address: SocketAddr,
    requests: mpsc::UnboundedReceiver<TcpStream>,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Origin {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, requests) = mpsc::unbounded_channel();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                }
                observed.fetch_add(1, Ordering::SeqCst);
                if sender.send(socket).is_err() {
                    break;
                }
            }
        });
        Self {
            address,
            requests,
            count,
            task,
        }
    }

    fn subscription(&self) -> Subscription {
        Subscription {
            name: "private-provider-tag".into(),
            url: format!(
                "http://{}/credential-path?token=private-query#private-fragment",
                self.address
            ),
            update_interval: 0,
            headers: vec![honk_config::subscription::SubscriptionHeader {
                key: "Authorization".into(),
                value: "Bearer private-origin-token".into(),
            }],
            ..Default::default()
        }
    }

    async fn next(&mut self) -> TcpStream {
        timeout(WAIT, self.requests.recv()).await.unwrap().unwrap()
    }
    async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn respond(mut socket: TcpStream, body: &str) {
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}

struct Fixture {
    address: SocketAddr,
    client: reqwest::Client,
    state: Arc<NativeState>,
    server: NativeServer,
    subscriptions: SubscriptionSupervisor,
    commands: mpsc::Sender<ControlCommand>,
    merges: mpsc::Receiver<ControlCommand>,
    control: JoinHandle<anyhow::Result<()>>,
}

impl Fixture {
    async fn start(
        mut config: Config,
        store: Option<SubscriptionStore>,
        initial_body: Option<&str>,
        origin: &mut Origin,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.secret = "provider-admin-token".into();
        config.experimental.native_api.listen = address.to_string();
        config.ensure_builtin_nodes();
        let preparation = tokio::spawn(async move {
            let owner = SubscriptionSupervisor::prepare(&mut config, store, Vec::new())
                .await
                .unwrap();
            (config, owner)
        });
        if let Some(body) = initial_body {
            respond(origin.next().await, body).await;
        }
        let (config, mut subscriptions) = timeout(WAIT, preparation).await.unwrap().unwrap();
        let resolver = DnsResolver::new(&config.dns).unwrap();
        let forwarder = resolver.forwarder();
        let mut control = ControlPlane::new(
            config,
            Box::new(MockEbpfBackend::new()),
            Router::new(&[], "direct").unwrap(),
            Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        control.set_mode_state(Arc::new(RwLock::new(crate::mode::ModeState::new(
            "Rule", "",
        ))));
        control.start_datapath_flags_coordinator().unwrap();
        control
            .install_startup_diagnostics(subscriptions.take_startup_diagnostics())
            .await;
        let state = Arc::new(
            NativeState::new(&mut control, address, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let commands = control.command_sender();
        let (merge_tx, merges) = mpsc::channel(16);
        subscriptions.start(merge_tx);
        state.observation.providers.attach(subscriptions.handle());
        let control = tokio::spawn(async move {
            control
                .run_native_config_test_commands(
                    Arc::new(AtomicUsize::new(0)),
                    None,
                    Arc::default(),
                )
                .await
        });
        let server = NativeServer::start(listener, Arc::clone(&state));
        Self {
            address,
            client: reqwest::Client::builder()
                .no_proxy()
                .default_headers(reqwest::header::HeaderMap::from_iter([(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_static("Bearer provider-admin-token"),
                )]))
                .timeout(WAIT)
                .build()
                .unwrap(),
            state,
            server,
            subscriptions,
            commands,
            merges,
            control,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
    async fn get(&self, path: &str) -> Value {
        let response = self.client.get(self.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }
    async fn refresh(&self, provider: Uuid, key: &str) -> reqwest::Response {
        self.client
            .post(self.url(&format!("/api/v1/providers/{provider}/refresh")))
            .header("idempotency-key", key)
            .send()
            .await
            .unwrap()
    }
    async fn publish(&mut self) {
        let command = timeout(WAIT, self.merges.recv()).await.unwrap().unwrap();
        self.commands.send(command).await.unwrap();
    }
    async fn terminal(&self, accepted: &Value) -> Value {
        timeout(WAIT, async {
            loop {
                let operation = self.get(accepted["href"].as_str().unwrap()).await;
                if matches!(operation["status"].as_str(), Some("succeeded" | "failed")) {
                    break operation;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
    async fn reload(&self, config: Config) {
        let (result, wait) = oneshot::channel();
        self.commands
            .send(ControlCommand::ReloadConfig {
                request_id: 1,
                config: Box::new(config),
                diagnostics: Vec::new(),
                sources: None,
                expected_group_revision: None,
                result,
            })
            .await
            .unwrap();
        let reply = timeout(WAIT, wait).await.unwrap().unwrap();
        assert!(reply.outcome.accepted());
        self.subscriptions
            .handle()
            .reconcile(reply.authorized)
            .await
            .unwrap();
    }
    async fn stop(self) {
        self.server.shutdown().await;
        // The test bridge is the owner of intentionally gated, not-yet-admitted merges.
        drop(self.merges);
        assert_eq!(
            timeout(WAIT, self.subscriptions.shutdown())
                .await
                .unwrap()
                .unwrap(),
            0
        );
        self.commands.send(ControlCommand::Shutdown).await.unwrap();
        timeout(WAIT, self.control).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn provider_get_is_safe_pure_and_counts_accepted_provenance_not_display_names() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut disabled = subscription.clone();
    disabled.id = Uuid::new_v4();
    disabled.enabled = false;
    let config = Config {
        subscriptions: vec![subscription.clone(), disabled.clone()],
        ..Default::default()
    };
    let fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    for _ in 0..3 {
        let list = fixture.get("/api/v1/providers").await;
        let detail = fixture
            .get(&format!("/api/v1/providers/{}", subscription.id))
            .await;
        assert_eq!(detail["node_count"], 1);
        assert_eq!(detail["status"], "ok");
        assert!(detail["updated_at"].is_string());
        assert_eq!(detail["url_redacted"], subscription.url);
        assert_eq!(detail["name"], subscription.name);
        assert!(detail["traffic"].is_null() && detail["expires_at"].is_null());
        assert_eq!(
            list["providers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == detail["id"])
                .unwrap(),
            &detail
        );
        let disabled = fixture
            .get(&format!("/api/v1/providers/{}", disabled.id))
            .await;
        assert_eq!(disabled["node_count"], 0);
        assert_eq!(disabled["status"], "stale");
        assert!(disabled["updated_at"].is_null() && disabled["last_error"].is_null());
    }
    assert_eq!(
        origin.count.load(Ordering::SeqCst),
        1,
        "GET must never fetch"
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn refresh_replays_before_busy_and_success_waits_for_real_runtime_publication() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted = fixture.refresh(subscription.id, "same").await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let accepted: Value = accepted.json().await.unwrap();
    let socket = origin.next().await;
    let replay: Value = fixture
        .refresh(subscription.id, "same")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(replay["operation_id"], accepted["operation_id"]);
    assert_eq!(
        fixture.refresh(subscription.id, "different").await.status(),
        StatusCode::CONFLICT
    );
    respond(socket, NEW).await;
    let command = timeout(WAIT, fixture.merges.recv()).await.unwrap().unwrap();
    assert_eq!(
        fixture.get(accepted["href"].as_str().unwrap()).await["status"],
        "running"
    );
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "old")
    );
    fixture.commands.send(command).await.unwrap();
    let terminal = fixture.terminal(&accepted).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(terminal["result"]["node_count"], 1);
    assert_eq!(terminal["result"]["url_redacted"], subscription.url);
    assert_eq!(terminal["result"]["name"], subscription.name);
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "new")
    );
    assert_eq!(origin.count.load(Ordering::SeqCst), 2);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn failed_fetch_and_failed_merge_preserve_previously_accepted_nodes() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    config.nodes.push(Node::from_share_link(NEW).unwrap());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "bad-body")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, "not a subscription").await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    let after_fetch = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(after_fetch["status"], "stale");
    assert_eq!(after_fetch["node_count"], 1);
    let accepted: Value = fixture
        .refresh(subscription.id, "bad-merge")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, NEW).await;
    fixture.publish().await;
    let operation = fixture.terminal(&accepted).await;
    assert_eq!(operation["status"], "failed");
    assert_eq!(operation["error"]["code"], "publication_rejected");
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .any(|node| node.name == "old" && node.subscription_id == Some(subscription.id))
    );
    assert_eq!(
        fixture
            .get(&format!("/api/v1/providers/{}", subscription.id))
            .await["updated_at"],
        after_fetch["updated_at"]
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn cache_load_is_stale_until_ack_and_startup_or_periodic_fetch_shares_api_gate() {
    let mut origin = Origin::new().await;
    let mut subscription = origin.subscription();
    subscription.update_interval = 1;
    let directory = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::in_dir(directory.path());
    store
        .store_content(&subscription, OLD.into())
        .await
        .unwrap();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, Some(store), None, &mut origin).await;
    let socket = origin.next().await;
    let cached = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(cached["status"], "stale");
    assert_eq!(cached["node_count"], 1);
    assert!(cached["updated_at"].is_string());
    assert_eq!(
        fixture
            .refresh(subscription.id, "startup-busy")
            .await
            .status(),
        StatusCode::CONFLICT
    );
    respond(socket, NEW).await;
    fixture.publish().await;
    timeout(WAIT, async {
        loop {
            if fixture
                .get(&format!("/api/v1/providers/{}", subscription.id))
                .await["status"]
                == "ok"
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut periodic = origin.next().await;
    assert_eq!(
        fixture
            .refresh(subscription.id, "periodic-busy")
            .await
            .status(),
        StatusCode::CONFLICT
    );
    fixture.stop().await;
    assert_eq!(
        timeout(WAIT, periodic.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0,
        "shutdown must close the actual fetching socket"
    );
    origin.stop().await;
}

#[tokio::test]
async fn removed_provider_late_fetch_is_rejected_and_retained_replay_remains_available() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "removed")
        .await
        .json()
        .await
        .unwrap();
    let socket = origin.next().await;
    let mut replacement = fixture.state.config.read().await.as_ref().clone();
    replacement.subscriptions.clear();
    fixture.reload(replacement).await;
    respond(socket, NEW).await;
    fixture.publish().await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .all(|node| node.subscription_id != Some(subscription.id))
    );
    let replay = fixture.refresh(subscription.id, "removed").await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["operation_id"],
        accepted["operation_id"]
    );
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn disconnected_refresh_keeps_daemon_owned_fetch_and_merge_until_completion() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let mut caller = TcpStream::connect(fixture.address).await.unwrap();
    caller.write_all(format!("POST /api/v1/providers/{}/refresh HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer provider-admin-token\r\nIdempotency-Key: lost-response\r\nContent-Length: 0\r\n\r\n", subscription.id, fixture.address).as_bytes()).await.unwrap();
    let socket = origin.next().await;
    drop(caller);
    respond(socket, NEW).await;
    fixture.publish().await;
    let replay: Value = fixture
        .refresh(subscription.id, "lost-response")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(fixture.terminal(&replay).await["status"], "succeeded");
    assert_eq!(origin.count.load(Ordering::SeqCst), 2);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn failed_initial_fetch_is_error_without_fabricated_success_time() {
    let mut origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let fixture = Fixture::start(config, None, Some("invalid body"), &mut origin).await;
    let provider = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(provider["status"], "error");
    assert_eq!(provider["node_count"], 0);
    assert!(provider["updated_at"].is_null());
    assert_eq!(provider["last_error"]["code"], "fetch_failed");
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn same_uuid_replacement_cannot_publish_old_fetch_or_borrow_new_authorization() {
    let mut origin = Origin::new().await;
    let mut replacement_origin = Origin::new().await;
    let subscription = origin.subscription();
    let mut config = Config::default();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let accepted: Value = fixture
        .refresh(subscription.id, "old-incarnation")
        .await
        .json()
        .await
        .unwrap();
    let socket = origin.next().await;
    let mut replacement = fixture.state.config.read().await.as_ref().clone();
    replacement.subscriptions[0].url = replacement_origin.subscription().url;
    fixture.reload(replacement).await;
    respond(socket, NEW).await;
    fixture.publish().await;
    assert_eq!(fixture.terminal(&accepted).await["status"], "failed");
    assert!(
        fixture
            .state
            .config
            .read()
            .await
            .nodes
            .iter()
            .all(|node| node.name != "new")
    );
    respond(
        replacement_origin.next().await,
        "socks5://127.0.0.1:11082#replacement",
    )
    .await;
    fixture.publish().await;
    timeout(WAIT, async {
        loop {
            if fixture
                .state
                .config
                .read()
                .await
                .nodes
                .iter()
                .any(|node| node.name == "replacement")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.stop().await;
    origin.stop().await;
    replacement_origin.stop().await;
}

#[tokio::test]
async fn provider_snapshot_is_immutable_and_unknown_cursor_is_invalid() {
    let mut origin = Origin::new().await;
    let mut config = Config::default();
    for _ in 0..3 {
        let mut provider = origin.subscription();
        provider.enabled = false;
        config.subscriptions.push(provider);
    }
    let fixture = Fixture::start(config, None, None, &mut origin).await;
    let first = fixture.get("/api/v1/providers?limit=1").await;
    assert_eq!(first["providers"][0]["id"], "inline");
    let cursor = first["next_cursor"].as_str().unwrap();
    let mut changed = fixture.state.config.read().await.as_ref().clone();
    changed.subscriptions.clear();
    *fixture.state.config.write().await = Arc::new(changed);
    let rest = fixture
        .get(&format!("/api/v1/providers?limit=1000&cursor={cursor}"))
        .await;
    assert_eq!(rest["providers"].as_array().unwrap().len(), 3);
    assert!(
        rest["providers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["id"] != first["providers"][0]["id"])
    );
    assert_eq!(origin.count.load(Ordering::SeqCst), 0);
    let response = fixture
        .client
        .get(fixture.url(&format!("/api/v1/providers?cursor={}:1", Uuid::new_v4())))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn provider_snapshot_over_budget_is_retryable_snapshot_unavailable() {
    let api = ProviderApi::new();
    let snapshot = Snapshot {
        id: Uuid::new_v4(),
        instance: "instance".into(),
        created: Instant::now(),
        rows: vec![Provider::inline(0), Provider::inline(0)],
        bytes: MAX_SNAPSHOT_BYTES + 1,
    };
    let id = RequestId("request-providers".into());
    let response = api.page(snapshot, 1, &id).unwrap_err().into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "1");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "snapshot_unavailable");
    assert_eq!(body["request_id"], "request-providers");
}

#[test]
fn provider_debug_omits_full_url() {
    let subscription = Subscription {
        name: "configured-provider".into(),
        url: format!(
            "https://example.test/{}?token=url-sentinel",
            "p".repeat(4096)
        ),
        ..Default::default()
    };
    let row = Provider::observed(&subscription, ProviderLoad::default(), 0);
    assert_eq!(row.url_redacted.as_deref(), Some(subscription.url.as_str()));
    assert!(!format!("{row:?}").contains("url-sentinel"));
}

#[test]
fn provider_projection_masks_only_listener_values_in_names_and_urls() {
    let mut config = Config::default();
    config.experimental.native_api.secret = "native-listener-token".into();
    config.experimental.clash_api.secret = "clash-listener-token".into();
    let subscription = Subscription {
        name: "provider-native-listener-token".into(),
        url: "https://user:password@example.test/path?token=clash-listener-token#fragment".into(),
        ..Default::default()
    };
    let id = subscription.id;
    config.subscriptions.push(subscription);
    let value = provider_value(&config, None, id, None).unwrap();
    assert_eq!(value["name"], "provider-<redacted>");
    assert_eq!(
        value["url_redacted"],
        "https://user:password@example.test/path?token=<redacted>#fragment"
    );
}

#[tokio::test]
async fn refresh_results_keep_full_urls_except_listener_values() {
    let mut origin = Origin::new().await;
    let mut subscription = origin.subscription();
    subscription.name.push_str("-provider-admin-token");
    let mut config = Config::default();
    config.experimental.clash_api.secret = "private-query".into();
    config.subscriptions.push(subscription.clone());
    let mut fixture = Fixture::start(config, None, Some(OLD), &mut origin).await;
    let expected_url = subscription.url.replace("private-query", "<redacted>");
    let expected_name = subscription
        .name
        .replace("provider-admin-token", "<redacted>");
    let before = fixture
        .get(&format!("/api/v1/providers/{}", subscription.id))
        .await;
    assert_eq!(before["url_redacted"], expected_url);
    assert_eq!(before["name"], expected_name);
    let accepted: Value = fixture
        .refresh(subscription.id, "masked-refresh")
        .await
        .json()
        .await
        .unwrap();
    respond(origin.next().await, NEW).await;
    fixture.publish().await;
    let terminal = fixture.terminal(&accepted).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(terminal["result"]["id"], subscription.id.to_string());
    assert_eq!(terminal["result"]["url_redacted"], expected_url);
    assert_eq!(terminal["result"]["name"], expected_name);
    fixture.stop().await;
    origin.stop().await;
}

#[tokio::test]
async fn refresh_without_subscription_owner_is_unsupported_not_retryable() {
    let state = crate::native_api::tests::state().await;
    let subscription = Subscription {
        url: "http://127.0.0.1:9/provider".into(),
        ..Default::default()
    };
    Arc::make_mut(&mut *state.config.write().await)
        .subscriptions
        .push(subscription.clone());
    let request = Request::post(format!("/api/v1/providers/{}/refresh", subscription.id))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = refresh(
        &state,
        &subscription.id.to_string(),
        request,
        &RequestId("test".into()),
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get("retry-after").is_none());
}
