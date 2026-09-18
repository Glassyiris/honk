//! File-authority regressions through real HTTP, reload publication and supervisor handoff.

mod transactions;

use super::coordinator::ConfigCoordinator;
use super::{ConfigService, SourceUpdate};
use crate::control::{ControlCommand, ControlPlane};
use crate::dns::DnsResolver;
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::ebpf::mock::MockEbpfBackend;
use crate::native_api::{NativeServer, NativeState};
use crate::routing::Router;
use crate::subscription::SubscriptionSupervisor;
use honk_config::{Config, parser::SourceLimits};
use honk_outbound::proxy::ProxyRegistry;
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

const SECRET: &str = "native-config-fixture-credential";
const WAIT: Duration = Duration::from_secs(5);
const CONFIG: &str = "/api/v1/config";
const VALIDATE: &str = "/api/v1/config/validate";
const RELOAD: &str = "/api/v1/operations/reload";

#[derive(Clone, Copy)]
enum Access {
    Metadata,
    Admin,
    Anonymous,
}

struct NoDns;

#[async_trait::async_trait]
impl DnsUpstreamPool for NoDns {
    async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        panic!("configuration administration must not query DNS")
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    originals: HashMap<&'static str, String>,
    addr: SocketAddr,
    client: Client,
    authenticated: bool,
    state: Weak<NativeState>,
    service: Arc<ConfigService>,
    server: Option<NativeServer>,
    coordinator: Option<ConfigCoordinator>,
    subscriptions: Option<SubscriptionSupervisor>,
    commands: mpsc::Sender<ControlCommand>,
    control: JoinSet<anyhow::Result<()>>,
    reloads: Arc<AtomicUsize>,
    gates: Option<mpsc::UnboundedReceiver<oneshot::Sender<()>>>,
}

impl Fixture {
    async fn new(access: Access, gated: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let settings = match access {
            Access::Metadata => format!("secret: '{SECRET}'"),
            Access::Admin => format!(
                "secret: '{SECRET}'\n config_write: true\n config_content: true\n writable_includes: 'editable.dae'"
            ),
            Access::Anonymous => "allow_anonymous_loopback: true".into(),
        };
        let main = format!(
            "# Entry comment retained verbatim.\ninclude {{\n 'auth.dae'\n 'editable.dae'\n 'locked.dae'\n}}\nglobal {{\n nfqueue_enable: false\n store_subscribe: false\n dial_mode: ip\n data_dir: '{}'\n}}\nrouting {{\n fallback: direct\n}}\n",
            directory.path().join("state").display()
        );
        let originals = HashMap::from([
            ("main.dae", main),
            (
                "auth.dae",
                format!(
                    "experimental {{ native_api {{\n enabled: true\n listen: '{addr}'\n {settings}\n}} }}\n"
                ),
            ),
            ("editable.dae", "# Explicitly writable include.\n".into()),
            ("locked.dae", "# Local-editor-only include.\n".into()),
        ]);
        for (name, text) in &originals {
            let path = directory.path().join(name);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let entry = directory.path().join("main.dae");
        let mut diagnostics = Vec::new();
        let loaded = Config::from_dae_file_with_sources(
            &entry,
            &HashMap::new(),
            SourceLimits::default(),
            &mut diagnostics,
        )
        .unwrap();
        let initial = SourceUpdate {
            sources: loaded.sources,
            dependencies: Vec::new(),
        };
        let mut config = loaded.config;
        config.validate_detailed().unwrap();
        config.ensure_builtin_nodes();
        let mut subscriptions = SubscriptionSupervisor::prepare(&mut config, None, diagnostics)
            .await
            .unwrap();
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
        let resolver = DnsResolver::new(&config.dns).unwrap();
        let forwarder = Arc::new(DnsForwarder::new(
            Arc::new(NoDns),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            Arc::new(DnsRouter::new_from_dns_config(&config.dns).unwrap()),
        ));
        let mut control_plane = ControlPlane::new(
            config,
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(ProxyRegistry::default_resolver().unwrap()),
            resolver,
            forwarder,
        )
        .unwrap();
        control_plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", ""),
        )));
        control_plane.start_datapath_flags_coordinator().unwrap();
        control_plane
            .install_startup_diagnostics(subscriptions.take_startup_diagnostics())
            .await;
        let state = Arc::new(
            NativeState::new(
                &mut control_plane,
                addr,
                SystemTime::now(),
                Instant::now(),
                true,
            )
            .await
            .unwrap(),
        );
        let service = Arc::clone(&state.observation.configuration);
        let commands = control_plane.command_sender();
        subscriptions.start(commands.clone());
        let coordinator = service
            .start(
                entry,
                initial,
                control_plane.config_handle(),
                control_plane.diagnostics_handle(),
                commands.clone(),
                subscriptions.handle(),
            )
            .await;
        let reloads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reloads);
        let (gate, gates) = if gated {
            let (sender, receiver) = mpsc::unbounded_channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let mut control = JoinSet::new();
        control.spawn(async move {
            control_plane
                .run_native_config_test_commands(observed, gate)
                .await
        });
        let weak = Arc::downgrade(&state);
        let server = NativeServer::start(listener, state);
        Self {
            directory,
            originals,
            addr,
            client: Client::builder().no_proxy().timeout(WAIT).build().unwrap(),
            authenticated: !matches!(access, Access::Anonymous),
            state: weak,
            service,
            server: Some(server),
            coordinator: Some(coordinator),
            subscriptions: Some(subscriptions),
            commands,
            control,
            reloads,
            gates,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let request = self
            .client
            .request(method, format!("http://{}{path}", self.addr));
        if self.authenticated {
            request.bearer_auth(SECRET)
        } else {
            request
        }
    }

    async fn get(&self, path: &str) -> Value {
        ok(self.request(Method::GET, path).send().await.unwrap()).await
    }

    fn replace(&self, source: &Value, content: &str) -> reqwest::RequestBuilder {
        self.request(Method::PUT, &source_path(source))
            .header("if-match", etag(source))
            .json(&json!({"content":content}))
    }

    fn validate(&self, mode: &str, content: &str) -> reqwest::RequestBuilder {
        self.request(Method::POST, VALIDATE).json(&json!({
            "mode":mode,"sources":[{"id":"candidate","path":"main.dae","content":content}]
        }))
    }

    async fn terminal(&self, accepted: &Value) -> Value {
        let href = accepted["href"].as_str().unwrap();
        timeout(WAIT, async {
            loop {
                let operation = self.get(href).await;
                assert_eq!(operation["operation_id"], accepted["operation_id"]);
                assert_eq!(operation["kind"], "reload");
                match operation["status"].as_str().unwrap() {
                    "succeeded" | "failed" => {
                        for field in ["created_at", "started_at", "finished_at"] {
                            chrono::DateTime::parse_from_rfc3339(
                                operation[field].as_str().unwrap(),
                            )
                            .unwrap();
                        }
                        assert!(operation.get("result").is_some());
                        assert!(operation.get("error").is_some());
                        return operation;
                    }
                    "queued" | "running" => tokio::time::sleep(Duration::from_millis(5)).await,
                    _ => panic!("invalid operation status"),
                }
            }
        })
        .await
        .expect("reload operation did not settle")
    }

    async fn barrier(&self) {
        let result = ok(self
            .validate("syntax", "routing { fallback: direct }")
            .send()
            .await
            .unwrap())
        .await;
        assert_eq!(result["valid"], true);
    }

    async fn next_reload(&mut self) -> oneshot::Sender<()> {
        timeout(WAIT, self.gates.as_mut().unwrap().recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn pause_before_replace(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, wait) = oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        *self.service.before_replace.lock() = Some(Box::new(move || {
            let _ = entered.send(());
            resume
                .recv_timeout(WAIT)
                .expect("write gate was not released");
        }));
        (wait, release)
    }

    async fn assert_last_reload(&self, operation: &Value) {
        self.barrier().await;
        let runtime = self.get("/api/v1/runtime").await;
        assert_eq!(
            runtime["last_reload"]["operation_id"],
            operation["operation_id"]
        );
        assert_eq!(runtime["last_reload"]["status"], operation["status"]);
        assert_eq!(runtime["last_reload"]["error"], operation["error"]);
        chrono::DateTime::parse_from_rfc3339(
            runtime["last_reload"]["finished_at"].as_str().unwrap(),
        )
        .unwrap();
        let config = self.get(CONFIG).await;
        assert_eq!(runtime["generation"]["active_id"], config["generation_id"]);
        assert_eq!(runtime["generation"]["config_revision"], config["revision"]);
    }

    async fn shutdown(mut self) {
        if let Some(coordinator) = self.coordinator.take() {
            timeout(WAIT, coordinator.shutdown())
                .await
                .expect("coordinator shutdown stalled");
        }
        timeout(
            Duration::from_secs(6),
            self.server.take().unwrap().shutdown(),
        )
        .await
        .unwrap();
        self.gates.take();
        timeout(WAIT, self.commands.send(ControlCommand::Shutdown))
            .await
            .unwrap()
            .unwrap();
        timeout(WAIT, self.control.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(self.control.is_empty());
        assert_eq!(
            timeout(WAIT, self.subscriptions.take().unwrap().shutdown())
                .await
                .unwrap(),
            0
        );
        assert!(
            self.state.upgrade().is_none(),
            "HTTP state leaked after owned shutdown"
        );
    }
}

fn sha256(content: &str) -> String {
    super::digest(content.as_bytes())
}
fn source_path(source: &Value) -> String {
    format!("/api/v1/config/sources/{}", source["id"].as_str().unwrap())
}
fn etag(source: &Value) -> String {
    format!("\"{}\"", source["content_sha256"].as_str().unwrap())
}
fn source<'a>(config: &'a Value, content: &str) -> &'a Value {
    config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["content_sha256"] == sha256(content))
        .unwrap()
}

fn headers(response: &Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

async fn ok(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    headers(&response);
    response.json().await.unwrap()
}

async fn accepted(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    headers(&response);
    assert!(
        response.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["kind"], "reload");
    assert_eq!(body["href"], location);
    assert_eq!(
        location,
        format!(
            "/api/v1/operations/{}",
            body["operation_id"].as_str().unwrap()
        )
    );
    assert!(matches!(
        body["status"].as_str(),
        Some("queued" | "running")
    ));
    body
}

async fn error(response: Response, status: StatusCode, code: &str) -> Value {
    assert_eq!(response.status(), status);
    headers(&response);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], code);
    assert!(body["error"]["message"].is_string());
    assert!(body["error"].get("details").is_some());
    uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).unwrap();
    assert!(!body.to_string().contains(SECRET));
    body
}

fn diagnostics(rows: &Value, source_id: &str, private: &str) {
    let rows = rows.as_array().unwrap();
    assert!(rows.iter().any(|row| row["level"] == "error"));
    for row in rows {
        for field in [
            "level",
            "source_id",
            "line",
            "column",
            "span",
            "code",
            "message",
        ] {
            assert!(row.get(field).is_some(), "missing diagnostic {field}");
        }
        assert_eq!(row["source_id"], source_id);
        assert!(!row["code"].as_str().unwrap().is_empty());
        assert!(!row.to_string().contains(private));
        assert!(!row.to_string().contains(SECRET));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DiskEntry {
    path: PathBuf,
    mode: u32,
    inode: u64,
    hash: String,
}

fn disk(root: &Path) -> Vec<DiskEntry> {
    fn visit(root: &Path, path: &Path, entries: &mut Vec<DiskEntry>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let hash = if metadata.is_file() {
            super::digest(&std::fs::read(path).unwrap())
        } else {
            String::new()
        };
        entries.push(DiskEntry {
            path: path.strip_prefix(root).unwrap().to_owned(),
            mode: metadata.mode(),
            inode: metadata.ino(),
            hash,
        });
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}

#[tokio::test]
async fn metadata_defaults_and_anonymous_never_grant_source_authority() {
    for access in [Access::Metadata, Access::Anonymous] {
        let fixture = Fixture::new(access, false).await;
        let config = fixture.get(CONFIG).await;
        assert_eq!(config["secrets_redacted"], true);
        assert!(
            config["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row.get("content").is_none() && row["writable"] == false)
        );
        assert!(!config.to_string().contains(SECRET));
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert_eq!(capabilities["resources"]["config"]["content"], false);
        assert_eq!(capabilities["resources"]["config"]["writable"], false);
        assert_eq!(capabilities["resources"]["groups"]["selection"], false);
        assert_eq!(capabilities["resources"]["groups"]["config_patch"], false);
        let main = source(&config, &fixture.originals["main.dae"]);
        let before = disk(fixture.directory.path());
        error(
            fixture
                .replace(main, "routing { fallback: block }")
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
        error(
            fixture
                .request(Method::PUT, "/api/v1/groups/unknown/selection")
                .json(&json!({}))
                .send()
                .await
                .unwrap(),
            StatusCode::NOT_FOUND,
            "capability_not_supported",
        )
        .await;
        assert_eq!(disk(fixture.directory.path()), before);
        assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
        fixture.shutdown().await;
    }
}

#[tokio::test]
async fn admin_reads_exact_accepted_bytes_but_never_auth_source_or_unapproved_writes() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["sources"].as_array().unwrap().len(), 4);
    for (name, original) in &fixture.originals {
        let row = source(&config, original);
        assert_eq!(row["path"], "<redacted>");
        assert_eq!(row["bytes"], original.len());
        assert_eq!(row["line_count"], original.lines().count());
        assert_eq!(
            row["kind"],
            if *name == "main.dae" {
                "main"
            } else {
                "include"
            }
        );
        chrono::DateTime::parse_from_rfc3339(row["loaded_at"].as_str().unwrap()).unwrap();
        let id = row["id"].as_str().unwrap();
        assert!(!id.is_empty() && !id.contains(name));
        assert_eq!(
            row["writable"],
            matches!(*name, "main.dae" | "editable.dae")
        );
        if *name == "auth.dae" {
            assert!(row.get("content").is_none());
        } else {
            assert_eq!(row["content"], *original);
            assert_eq!(
                sha256(row["content"].as_str().unwrap()),
                row["content_sha256"]
            );
        }
        assert_eq!(fixture.get(&source_path(row)).await, *row);
    }
    assert!(!config.to_string().contains(SECRET));
    let before = disk(fixture.directory.path());
    for name in ["locked.dae", "auth.dae"] {
        error(
            fixture
                .replace(
                    source(&config, &fixture.originals[name]),
                    "# not authorized\n",
                )
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    let without_auth = fixture.originals["main.dae"].replace(" 'auth.dae'\n", "");
    error(
        fixture
            .replace(
                source(&config, &fixture.originals["main.dae"]),
                &without_auth,
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
    error(
        fixture
            .request(Method::GET, "/api/v1/config/sources/unknown")
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    error(
        fixture
            .request(Method::PUT, "/api/v1/config/sources/unknown")
            .header("if-match", etag(&config["sources"][0]))
            .json(&json!({"content":"# unknown\n"}))
            .send()
            .await
            .unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), before);
    std::fs::write(
        fixture.path("editable.dae"),
        "# External edit, not accepted.\n",
    )
    .unwrap();
    assert_eq!(fixture.get(CONFIG).await, config);
    assert_eq!(
        fixture
            .get(&source_path(source(
                &config,
                &fixture.originals["editable.dae"]
            )))
            .await,
        *source(&config, &fixture.originals["editable.dae"])
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn validation_is_offline_readonly_and_distinguishes_syntax_from_full_admission() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let candidate = format!(
        "{}subscription {{ private: 'http://{}/private-candidate-token' }}\n",
        fixture.originals["main.dae"],
        listener.local_addr().unwrap()
    );
    let before = fixture.get(CONFIG).await;
    let before_disk = disk(fixture.directory.path());
    for (mode, content, valid) in [
        ("syntax", candidate.as_str(), true),
        // Full admission of a subscription that was never fetched passes with a
        // warning and, above all, without fetching it.
        ("full", candidate.as_str(), true),
        ("full", fixture.originals["main.dae"].as_str(), true),
        ("syntax", "routing {\n", false),
    ] {
        let result = ok(fixture.validate(mode, content).send().await.unwrap()).await;
        assert_eq!(result["valid"], valid);
        assert_eq!(result["generation_id"], before["generation_id"]);
        chrono::DateTime::parse_from_rfc3339(result["validated_at"].as_str().unwrap()).unwrap();
        if !valid {
            diagnostics(
                &result["diagnostics"],
                "candidate",
                "private-candidate-token",
            );
        } else if mode == "full" && content == candidate.as_str() {
            let rows = result["diagnostics"].as_array().unwrap();
            let notice = rows
                .iter()
                .find(|row| row["code"] == "subscription-not-fetched")
                .unwrap();
            assert_eq!(notice["level"], "warning");
            assert!(!result.to_string().contains("private-candidate-token"));
        }
        assert_eq!(disk(fixture.directory.path()), before_disk);
        assert_eq!(fixture.get(CONFIG).await, before);
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!fixture.path("state").exists());
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn validation_ids_and_display_paths_cannot_expand_file_authority() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let before_disk = disk(fixture.directory.path());
    for sources in [
        json!([{"id":"same","content":""},{"id":"same","content":""}]),
        json!([{"id":"a","path":"main.dae","content":""},{"id":"b","path":"main.dae","content":""}]),
        json!([{"id":"../private","content":""}]),
    ] {
        error(
            fixture
                .request(Method::POST, VALIDATE)
                .json(&json!({"mode":"syntax","sources":sources}))
                .send()
                .await
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await;
    }
    for path in ["../outside.dae", "/tmp/outside.dae"] {
        error(
            fixture
                .request(Method::POST, VALIDATE)
                .json(&json!({
                    "mode":"full","sources":[
                        {"id":"main","path":"main.dae","content":fixture.originals["main.dae"]},
                        {"id":"outside","path":path,"content":"# no authority\n"}
                    ]
                }))
                .send()
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "permission_denied",
        )
        .await;
    }
    let syntax = ok(fixture.request(Method::POST, VALIDATE).json(&json!({
        "mode":"syntax","sources":[{"id":"label","path":"../not-opened.dae","content":"routing { fallback: direct }"}]
    })).send().await.unwrap()).await;
    assert_eq!(syntax["valid"], true);
    // The display path GET /config hands out names no file; a client may echo it with the id.
    let main_id = before["sources"][0]["id"].clone();
    let echoed = ok(fixture.request(Method::POST, VALIDATE).json(&json!({
        "mode":"full","sources":[{"id":main_id,"path":"<redacted>","content":fixture.originals["main.dae"]}]
    })).send().await.unwrap()).await;
    assert_eq!(echoed["valid"], true);
    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().join("outside.dae");
    std::fs::write(&outside_path, "routing { fallback: block }").unwrap();
    let escaping = fixture.originals["main.dae"]
        .replace("'locked.dae'", &format!("'{}'", outside_path.display()));
    let result = ok(fixture.validate("full", &escaping).send().await.unwrap()).await;
    assert_eq!(result["valid"], false);
    diagnostics(
        &result["diagnostics"],
        "candidate",
        outside_path.to_str().unwrap(),
    );
    assert_eq!(disk(fixture.directory.path()), before_disk);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn conditional_and_invalid_writes_leave_files_and_generation_untouched() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let before_disk = disk(fixture.directory.path());
    let strong = etag(main);
    let conditions = [
        (
            None,
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
        ),
        (
            Some(format!("W/{strong}")),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            Some(format!("{strong}, {strong}")),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (Some("*".into()), StatusCode::BAD_REQUEST, "invalid_request"),
        (
            Some(format!("\"{}\"", "0".repeat(64))),
            StatusCode::PRECONDITION_FAILED,
            "stale_revision",
        ),
    ];
    for (condition, status, code) in conditions {
        let request = fixture
            .request(Method::PUT, &source_path(main))
            .json(&json!({"content":"routing { fallback: block }"}));
        let request = if let Some(condition) = condition {
            request.header("if-match", condition)
        } else {
            request
        };
        error(request.send().await.unwrap(), status, code).await;
        assert_eq!(disk(fixture.directory.path()), before_disk);
        assert_eq!(fixture.get(CONFIG).await, before);
    }
    let invalid = fixture.originals["main.dae"].replace(
        "nfqueue_enable: false",
        "nfqueue_enable: private-invalid-value",
    );
    let failure = error(
        fixture.replace(main, &invalid).send().await.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    diagnostics(
        &failure["error"]["details"]["diagnostics"],
        main["id"].as_str().unwrap(),
        "private-invalid-value",
    );
    assert!(
        !failure
            .to_string()
            .contains(fixture.directory.path().to_str().unwrap())
    );
    assert_eq!(disk(fixture.directory.path()), before_disk);
    assert_eq!(fixture.get(CONFIG).await, before);
    for (target, broken) in [("main.dae", "locked.dae"), ("editable.dae", "main.dae")] {
        std::fs::write(
            fixture.path(broken),
            "global { nfqueue_enable: private-invalid-value }",
        )
        .unwrap();
        let disk_before = disk(fixture.directory.path());
        let failure = error(
            fixture
                .replace(
                    source(&before, &fixture.originals[target]),
                    &fixture.originals[target],
                )
                .send()
                .await
                .unwrap(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_value",
        )
        .await;
        diagnostics(
            &failure["error"]["details"]["diagnostics"],
            source(&before, &fixture.originals[broken])["id"]
                .as_str()
                .unwrap(),
            "private-invalid-value",
        );
        assert_eq!(disk(fixture.directory.path()), disk_before);
        std::fs::write(fixture.path(broken), &fixture.originals[broken]).unwrap();
    }
    let external = format!("{}# external editor\n", fixture.originals["main.dae"]);
    std::fs::write(fixture.path("main.dae"), &external).unwrap();
    let edited = disk(fixture.directory.path());
    error(
        fixture
            .replace(main, &fixture.originals["main.dae"])
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), edited);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert!(fixture.get("/api/v1/runtime").await["last_reload"].is_null());
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn source_replacement_preserves_text_mode_and_independent_revision_generation() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block")
        + "# café: unchanged UTF-8 comments\n";
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    assert!(terminal["error"].is_null());
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        candidate
    );
    assert_eq!(
        std::fs::metadata(fixture.path("main.dae"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    for name in ["auth.dae", "editable.dae", "locked.dae"] {
        assert_eq!(
            sha256(&std::fs::read_to_string(fixture.path(name)).unwrap()),
            sha256(&fixture.originals[name])
        );
    }
    let after = fixture.get(CONFIG).await;
    assert_ne!(after["generation_id"], before["generation_id"]);
    assert_ne!(after["revision"], before["revision"]);
    assert_eq!(
        terminal["result"]["active_generation_id"],
        after["generation_id"]
    );
    assert_eq!(source(&after, &candidate)["id"], main["id"]);
    fixture.assert_last_reload(&terminal).await;
    let include = source(&after, &fixture.originals["editable.dae"]);
    let comments = format!(
        "{}# Comments-only accepted edit.\n",
        fixture.originals["editable.dae"]
    );
    let operation = accepted(fixture.replace(include, &comments).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    let commented = fixture.get(CONFIG).await;
    assert_eq!(commented["generation_id"], after["generation_id"]);
    assert_ne!(commented["revision"], after["revision"]);
    assert_eq!(source(&commented, &comments)["id"], include["id"]);
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        comments
    );
    assert_eq!(
        std::fs::metadata(fixture.path("editable.dae"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    fixture.assert_last_reload(&terminal).await;
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}
