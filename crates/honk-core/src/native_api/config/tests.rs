//! File-authority regressions through real HTTP, reload publication and supervisor handoff.

mod database;
mod geodata;
mod groups;
mod management;
mod transactions;
mod validation;

use super::ConfigService;
use super::coordinator::ConfigCoordinator;
use crate::configuration::SourceUpdate;
use crate::control::{ControlCommand, ControlPlane};
use crate::dns::DnsResolver;
use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};
use crate::dns::routing::DnsRouter;
use crate::ebpf::mock::MockEbpfBackend;
use crate::native_api::store::{DatabaseStartup, DbStore, FileStore, SourceStore};
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
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
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
    database: Option<Arc<DbStore>>,
    /// 1: the engine answers every reload `Rejected`; 2: it drops the reply. Neither applies it.
    reject_reloads: Arc<AtomicU8>,
}

impl Fixture {
    async fn new(access: Access, gated: bool) -> Self {
        Self::new_custom(access, gated, |_, _| {}).await
    }

    async fn new_custom(
        access: Access,
        gated: bool,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
    ) -> Self {
        Self::build(access, gated, setup, false).await
    }

    /// Starts from `--store db`: the tree is imported as revision 1.
    async fn new_db(access: Access) -> Self {
        Self::new_db_custom(access, |_, _| {}).await
    }

    async fn new_db_custom(
        access: Access,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
    ) -> Self {
        Self::build(access, false, setup, true).await
    }

    async fn build(
        access: Access,
        gated: bool,
        setup: impl FnOnce(&Path, &mut HashMap<&'static str, String>),
        db: bool,
    ) -> Self {
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
        let mut originals = HashMap::from([
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
        setup(directory.path(), &mut originals);
        // The db fixture keeps its tree apart from `state` so a test can delete all of it.
        let tree = directory.path().join(if db { "etc" } else { "" });
        std::fs::create_dir_all(&tree).unwrap();
        for (name, text) in &originals {
            let path = tree.join(name);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let entry = tree.join("main.dae").canonicalize().unwrap();
        let mut diagnostics = Vec::new();
        let (mut config, initial, store, database) = if db {
            let state = directory.path().join("state");
            std::fs::create_dir_all(&state).unwrap();
            let mut startup = DatabaseStartup::open(&entry, &state, &mut diagnostics).unwrap();
            startup.record().unwrap();
            let store = Arc::clone(&startup.store);
            (
                startup.config,
                startup.sources,
                Arc::clone(&store) as Arc<dyn SourceStore>,
                Some(store),
            )
        } else {
            let loaded = Config::from_dae_file_with_sources(
                &entry,
                &HashMap::new(),
                SourceLimits::default(),
                &mut diagnostics,
            )
            .unwrap();
            let store = Arc::new(FileStore::new(loaded.sources[0].path.clone()));
            let initial = SourceUpdate {
                sources: loaded.sources,
                dependencies: Vec::new(),
                geo_sources: None,
            };
            (loaded.config, initial, store as Arc<dyn SourceStore>, None)
        };
        config.validate_detailed().unwrap();
        config.ensure_builtin_nodes();
        let mut subscriptions = SubscriptionSupervisor::prepare(&mut config, None, diagnostics)
            .await
            .unwrap();
        let requirements = crate::routing::GeoRequirements::for_traffic(&config.routing.rules)
            .union(&DnsRouter::geo_requirements(&config.dns));
        let geo = crate::routing::GeoSourceSet::load_captured(
            &requirements,
            Path::new(&config.global.data_dir),
            |path| std::fs::read(path).map(Arc::from),
        )
        .unwrap();
        let router = Router::new_with_geo_sources(
            &config.routing.rules,
            &config.routing.default_outbound,
            &geo,
        )
        .unwrap();
        let forwarder = Arc::new(DnsForwarder::new(
            Arc::new(NoDns),
            Arc::new(tokio::sync::Mutex::new(DnsCache::new(16))),
            Arc::new(DnsRouter::new_with_geo_sources(&config.dns, &geo).unwrap()),
        ));
        let resolver = DnsResolver::with_forwarder(&config.dns, Arc::clone(&forwarder)).unwrap();
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
            NativeState::new(&mut control_plane, addr, SystemTime::now(), Instant::now())
                .await
                .unwrap(),
        );
        let service = Arc::clone(&state.observation.configuration);
        let commands = control_plane.command_sender();
        subscriptions.start(commands.clone());
        state.observation.providers.attach(subscriptions.handle());
        control_plane.attach_subscriptions(subscriptions.handle());
        let coordinator = service
            .start(
                Some(store),
                Some(initial),
                directory.path().join("state"),
                control_plane.config_handle(),
                control_plane.diagnostics_handle(),
                commands.clone(),
                subscriptions.handle(),
            )
            .await;
        let reloads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reloads);
        let reject_reloads = Arc::new(AtomicU8::new(0));
        let rejecting = Arc::clone(&reject_reloads);
        let (gate, gates) = if gated {
            let (sender, receiver) = mpsc::unbounded_channel();
            (Some(sender), Some(receiver))
        } else {
            (None, None)
        };
        let mut control = JoinSet::new();
        control.spawn(async move {
            control_plane
                .run_native_config_test_commands(observed, gate, rejecting)
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
            database,
            reject_reloads,
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
                assert_eq!(operation["kind"], accepted["kind"]);
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
                .unwrap()
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
    crate::configuration::digest(content.as_bytes())
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
            crate::configuration::digest(&std::fs::read(path).unwrap())
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
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert_eq!(capabilities["resources"]["config"]["content"], true);
        assert_eq!(capabilities["resources"]["config"]["writable"], false);
        assert_eq!(capabilities["resources"]["groups"]["config_patch"], false);
        for resource in [
            "providers",
            "geodata",
            "rules",
            "routing_trace",
            "flows",
            "connections",
        ] {
            assert_eq!(capabilities["resources"][resource]["available"], true);
        }
        for path in [
            "/api/v1/providers",
            "/api/v1/providers/inline",
            "/api/v1/geodata",
            "/api/v1/connections",
            "/api/v1/rules",
            "/api/v1/flows",
        ] {
            fixture.get(path).await;
        }
        let config = fixture.get(CONFIG).await;
        assert_eq!(config["secrets_redacted"], fixture.authenticated);
        assert!(
            config["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["content"].is_string() && row["writable"] == false)
        );
        assert!(!config.to_string().contains(SECRET));
        let main = source(&config, &fixture.originals["main.dae"]);
        assert_eq!(fixture.get(&source_path(main)).await, *main);
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
        assert_eq!(row["path"], *name);
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
        assert_eq!(row["writable"], *name != "auth.dae");
        assert_eq!(row["absolute_path"], fixture.path(name).to_str().unwrap());
        if *name == "auth.dae" {
            assert!(row["content"].as_str().unwrap().contains("enabled: true"));
            assert!(!row["content"].as_str().unwrap().contains(SECRET));
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
    error(
        fixture
            .replace(
                source(&config, &fixture.originals["auth.dae"]),
                "# not authorized\n",
            )
            .send()
            .await
            .unwrap(),
        StatusCode::FORBIDDEN,
        "permission_denied",
    )
    .await;
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

#[tokio::test]
async fn mixed_listener_secrets_mask_values_and_keep_ordinary_content() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace(&format!("secret: '{SECRET}'"),
            &format!("secret: 'overridden-listener-token'\n secret: '{SECRET}'"));
        auth.push_str("experimental { clash_api { secret: 'old-clash-token'\n secret: 'clash-listener-token' } }\n# old-clash-token copied here\n");
        files.get_mut("main.dae").unwrap().push_str("include { 'clash-listener-token.dae' }\n");
        files.insert("clash-listener-token.dae", "# Ordinary included content.\n".into());
        files.get_mut("locked.dae").unwrap().push_str(
            "# overridden-listener-token copied across sources\nnode { ordinary: 'socks5://user:ordinary-password@192.0.2.1:1080' }\n");
    }).await;
    let config = fixture.get(CONFIG).await;
    assert_eq!(config["secrets_redacted"], true);
    let encoded = config.to_string();
    for secret in [
        SECRET,
        "overridden-listener-token",
        "old-clash-token",
        "clash-listener-token",
    ] {
        assert!(!encoded.contains(secret), "listener value leaked");
    }
    let path_only = source(&config, &fixture.originals["clash-listener-token.dae"]);
    assert_eq!(path_only["content"], "# Ordinary included content.\n");
    assert_eq!(path_only["path"], "<redacted>.dae");
    let auth = source(&config, &fixture.originals["auth.dae"]);
    assert_eq!(auth["writable"], false);
    assert_eq!(
        auth["content"].as_str().unwrap().lines().count(),
        fixture.originals["auth.dae"].lines().count()
    );
    let mixed = source(&config, &fixture.originals["locked.dae"]);
    assert!(
        mixed["content"]
            .as_str()
            .unwrap()
            .contains("socks5://user:ordinary-password@192.0.2.1:1080")
    );
    assert_eq!(mixed["writable"], false);
    fixture.shutdown().await;
}

#[tokio::test]
async fn retired_content_flag_and_echoed_redaction_flag_do_not_grant_write_authority() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        let auth = files.get_mut("auth.dae").unwrap();
        *auth = auth.replace("config_content: true", "config_content: false");
    })
    .await;
    let config = fixture.get(CONFIG).await;
    let row = source(&config, &fixture.originals["locked.dae"]);
    assert_eq!(row["content"], fixture.originals["locked.dae"]);
    assert_eq!(row["writable"], true);
    let candidate = "# accepted include without an allowlist\n";
    let admission = accepted(
        fixture
            .replace(row, candidate)
            .json(&json!({"content": candidate, "secrets_redacted": false}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(fixture.terminal(&admission).await["status"], "succeeded");
    let response = fixture
        .request(Method::POST, "/api/v1/config/validate")
        .json(&json!({"mode":"syntax", "secrets_redacted":true,
            "sources":[{"content":"routing { fallback: direct }", "secrets_redacted":false}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok(response).await["valid"], true);
    fixture.shutdown().await;
}

#[test]
fn listener_masking_preserves_wire_identifiers_and_enums() {
    use super::ListenerSecrets;

    let mut value = json!({
        "id": "12345678-abcd-1234-abcd-123456789012",
        "next_cursor": "12345678-abcd-1234-abcd-123456789012:1",
        "network": "tcp",
        "chain": ["node-with-secret"],
        "trace_status": "complete",
        "trace": {"status": "complete", "missing": [], "steps": [
            {"chain": "traffic", "rule_id": "instance-1:2:rule:0", "expression": "pname(node-with-secret)"}
        ]}
    });
    let original = value.clone();
    assert!(ListenerSecrets::new(&[], "with-secret").mask_value(&mut value));
    assert_eq!(value["id"], original["id"]);
    assert_eq!(value["next_cursor"], original["next_cursor"]);
    assert_eq!(value["network"], "tcp");
    assert_eq!(value["chain"][0], "node-<redacted>");
    assert_eq!(value["trace"]["steps"][0]["chain"], "traffic");
    assert_eq!(value["trace"]["steps"][0]["rule_id"], "instance-1:2:rule:0");
    assert_eq!(value["trace_status"], "partial");
    assert_eq!(value["trace"]["missing"], json!(["redacted"]));
    let mut value = json!({"network": "tcp", "expression": "pname(tcpsecret)"});
    assert!(ListenerSecrets::new(&[], "tcpsecret").mask_value(&mut value));
    assert_eq!(value["network"], "tcp");
    assert_eq!(value["expression"], "pname(<redacted>)");
    assert_eq!(
        ListenerSecrets::new(&[], "abababab").mask("ababababab"),
        ("<redacted>".into(), true)
    );
    // Below the minimum a secret is left alone rather than shredding common substrings.
    assert_eq!(
        ListenerSecrets::new(&[], "tcp").mask("l4proto(tcp)"),
        ("l4proto(tcp)".into(), false)
    );
    let secret = "quoted\"token";
    let mut value = json!({"expression": format!("pname({secret:?})")});
    assert!(ListenerSecrets::new(&[], secret).mask_value(&mut value));
    assert_eq!(value["expression"], "pname(\"<redacted>\")");
}

#[tokio::test]
async fn connection_projection_masks_listener_values_without_losing_flow_references() {
    use crate::connection_tracker::ConnectionEntry;
    use std::sync::atomic::AtomicU64;

    let fixture = Fixture::new(Access::Metadata, false).await;
    let state = fixture.state.upgrade().unwrap();
    state.observation.attach_for_test();
    let flow = state.observation.flows.begin(
        "tcp",
        "192.0.2.1:31000".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
    );
    let rule_id = format!("{}:1:rule:0", state.instance_id);
    flow.routed(
        "group/name@host",
        Some(&rule_id),
        Some(&format!("pname(\"/usr/bin/{SECRET}\")")),
        "evaluation",
    );
    state.tracker.register(ConnectionEntry {
        id: "connection-visible-id".into(),
        source: "192.0.2.1:31000".into(),
        destination: "198.51.100.1:443".into(),
        proxy: "leaf".into(),
        routed_outbound: Some("group/name@host".into()),
        native_flow_id: Some(flow.id().into()),
        rule: String::new(),
        rule_payload: String::new(),
        chains: vec![],
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "tcp".into(),
        process: Some("/usr/bin/user@host".into()),
        process_path: None,
    });
    let value = fixture.get("/api/v1/connections?detail=full").await;
    let row = &value["tcp"][0];
    assert_eq!(row["id"], "connection-visible-id");
    assert_eq!(row["flow_id"], flow.id());
    assert_eq!(row["rule_id"], rule_id);
    assert_eq!(row["outbound"], "group/name@host");
    assert_eq!(row["pname"], "/usr/bin/user@host");
    assert_eq!(row["rule_expression"], "pname(\"/usr/bin/<redacted>\")");
    assert!(!value.to_string().contains(SECRET));
    drop(state);
    fixture.shutdown().await;
}

#[test]
fn malformed_credential_source_is_withheld_without_panicking() {
    let content = "experimental { native_api { secret: 'unfinished\n";
    let source = honk_config::parser::SourceSnapshot {
        path: PathBuf::from("/config/auth.dae"),
        content: Arc::from(content),
        parent: None,
        source: honk_config::diagnostic::DiagnosticSources::new(None).root(),
        contains_api_secret: true,
        loaded_at: SystemTime::now(),
    };
    let sources = [source];
    let secrets = super::ListenerSecrets::new(&sources, "listener-token");
    assert_eq!(secrets.mask(content), ("<redacted>\n".into(), true));
    assert_eq!(
        secrets.mask(&format!("before\n{content}after")),
        ("before\n<redacted>\nafter".into(), true)
    );
    assert_eq!(
        secrets.mask("ordinary content"),
        ("ordinary content".into(), false)
    );
}
