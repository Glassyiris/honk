use super::*;
use crate::native_api::geodata::download;
use tokio::io::AsyncReadExt;

const GEO: &str = "/api/v1/geodata";
const UPDATE: &str = "/api/v1/geodata/update";

fn delimited(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    let mut result = vec![tag << 3 | 2, value.len() as u8];
    result.extend_from_slice(value);
    result
}

fn geosite(domain: &str) -> Vec<u8> {
    let mut entry = delimited(1, b"test");
    let mut rule = vec![8, 3];
    rule.extend(delimited(2, domain.as_bytes()));
    entry.extend(delimited(2, &rule));
    delimited(1, &entry)
}

fn geoip(first: u8) -> Vec<u8> {
    let mut entry = delimited(1, b"test");
    let mut cidr = delimited(1, &[first, 0, 0, 0]);
    cidr.extend([16, 8]);
    entry.extend(delimited(2, &cidr));
    delimited(1, &entry)
}

#[tokio::test]
async fn trace_displays_configured_values_in_compiled_condition_order() {
    let fixture = Fixture::new_custom(Access::Metadata, false, |root, files| {
        let directory = root.join("state");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("geosite.dat"), geosite("old.example")).unwrap();
        std::fs::write(directory.join("geoip.dat"), geoip(198)).unwrap();
        files.insert("locked.dae", "routing {\n pname(curl) && !dport(53) && dip(192.0.2.0/24, geoip: test) && domain(keyword: example, geosite: test) -> block\n !domain(geosite: test) && !dip(geoip: test) -> direct\n}\n".into());
    }).await;
    let dictionary = fixture.get("/api/v1/rules").await;
    let trace = |domain| {
        fixture.request(Method::POST, "/api/v1/routing/trace").json(&json!({
        "input":{"network":"tcp","domain":domain,"dst_ip":"192.0.2.1","dst_port":443,"pname":"curl"},
        "resolve":"none"
    }))
    };
    let matched = ok(trace("old.example").send().await.unwrap()).await;
    let evaluation = &matched["evaluations"][0];
    assert_eq!(matched["generation_id"], dictionary["generation_id"]);
    assert_eq!(evaluation["outbound"], "block");
    assert_eq!(
        evaluation["rules"][0]["rule_id"],
        dictionary["rules"][0]["rule_id"]
    );
    assert_eq!(
        evaluation["rules"][0]["expression"],
        dictionary["rules"][0]["expression"]
    );
    let conditions = evaluation["rules"][0]["conditions"].as_array().unwrap();
    assert_eq!(
        conditions
            .iter()
            .map(|row| row["expression"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            r#"domain(keyword: example)"#,
            r#"domain(geosite: test)"#,
            r#"dip(192.0.2.0/24, geoip: test)"#,
            r#"pname(curl)"#,
            r#"!dport(53)"#,
        ]
    );
    assert!(conditions.iter().all(|row| row["result"] == "matched"));
    let not_matched = ok(trace("other.example").send().await.unwrap()).await;
    let evaluation = &not_matched["evaluations"][0];
    assert_eq!(evaluation["outbound"], "direct");
    assert_eq!(evaluation["rules"][0]["conditions"][0]["result"], "matched");
    assert_eq!(
        evaluation["rules"][0]["conditions"][1]["result"],
        "not_matched"
    );
    assert_eq!(evaluation["rules"][0]["conditions"][2]["result"], "skipped");
    assert_eq!(
        evaluation["rules"][1]["conditions"][0]["expression"],
        r#"!domain(geosite: test)"#
    );
    assert_eq!(
        evaluation["rules"][1]["conditions"][1]["expression"],
        r#"!dip(geoip: test)"#
    );
    assert_eq!(evaluation["rules"][1]["result"], "matched");
    fixture.shutdown().await;
}

struct AssetServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    entered: oneshot::Receiver<()>,
    release: Option<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl AssetServer {
    async fn new(site: Vec<u8>, ip: Vec<u8>, gated: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let (entered, wait) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut entered = Some(entered);
            let mut resume = Some(resume);
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    head.push(byte);
                    assert!(head.len() <= 4096);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    if gated {
                        resume.take().unwrap().await.unwrap();
                    }
                }
                let bytes = if head.starts_with(b"GET /geosite") {
                    &site
                } else {
                    &ip
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            requests,
            entered: wait,
            release: Some(release),
            tasks,
        }
    }

    async fn close(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

fn setup(root: &Path, files: &mut HashMap<&'static str, String>, address: SocketAddr) {
    let directory = root.join("state");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("geosite.dat"), geosite("old.example")).unwrap();
    std::fs::write(directory.join("geoip.dat"), geoip(198)).unwrap();
    let main = files.get_mut("main.dae").unwrap();
    *main = main.replace(
        " fallback: direct",
        " domain(geosite: test) -> block\n dip(geoip: test) -> block\n fallback: direct",
    );
    let auth = files.get_mut("auth.dae").unwrap();
    *auth = auth.replace(" enabled: true", &format!(
        " geosite_download_url: 'http://{address}/geosite/PRIVATE?token=PRIVATE'\n geoip_download_url: 'http://{address}/geoip'\n enabled: true",
    ));
}

async fn fixture(address: SocketAddr, gated_reload: bool) -> Fixture {
    Fixture::new_custom(Access::Admin, gated_reload, |root, files| {
        setup(root, files, address)
    })
    .await
}

async fn route(fixture: &Fixture, domain: &str, ip: &str) -> String {
    fixture
        .state
        .upgrade()
        .unwrap()
        .traffic_router
        .read()
        .await
        .route(&crate::routing::ConnectionInfo {
            domain: Some(domain.into()),
            dst_ip: ip.parse().unwrap(),
            dst_port: 443,
            src_ip: "192.0.2.1".parse().unwrap(),
            src_port: 12345,
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
        })
        .to_owned()
}

#[tokio::test]
async fn source_write_rejects_swapped_geo_readers_before_rename() {
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, "127.0.0.1:9".parse().unwrap());
        for (name, target) in [("geosite.dat", "site.body"), ("geoip.dat", "ip.body")] {
            let path = root.join("state").join(name);
            let target = root.join("state").join(target);
            std::fs::rename(&path, &target).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
        }
    })
    .await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let (entered, resume) = fixture.pause_before_replace();
    let request = fixture.replace(main, &candidate);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await });
    timeout(WAIT, entered).await.unwrap().unwrap();
    for (name, target) in [("geosite.dat", "ip.body"), ("geoip.dat", "site.body")] {
        let path = fixture.path(&format!("state/{name}"));
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(fixture.path(&format!("state/{target}")), path).unwrap();
    }
    resume.send(()).unwrap();
    error(
        timeout(WAIT, requests.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn updates_verified_bytes_and_keeps_loaded_metadata_after_disk_edits() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    assert_eq!(
        old["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("old.example"))
    );
    assert!(
        old["assets"][0]["source_redacted"]
            .as_str()
            .unwrap()
            .starts_with(&format!("http://{}/", server.address))
    );
    assert_eq!(
        old["assets"][0]["source_redacted"],
        format!("http://{}/geosite/PRIVATE?token=PRIVATE", server.address)
    );
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "direct");
    let operation = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "update")
            .send()
            .await
            .unwrap(),
    )
    .await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(terminal["kind"], "geodata_update");
    assert_eq!(
        terminal["result"]["assets"][0]["source_redacted"],
        old["assets"][0]["source_redacted"]
    );
    assert_eq!(
        terminal["result"]["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("new.example"))
    );
    assert_eq!(
        terminal["result"]["assets"][1]["sha256"],
        crate::configuration::digest(&geoip(203))
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "direct");
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "other.example", "203.1.2.3").await, "block");
    let loaded = fixture.get(GEO).await;
    std::fs::write(fixture.path("state/geosite.dat"), b"external-editor").unwrap();
    assert_eq!(fixture.get(GEO).await["assets"], loaded["assets"]);
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    let replay = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "update")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay, operation);
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn invalid_later_asset_never_replaces_either_file() {
    let mut malformed = geoip(203);
    let mut unused = delimited(1, b"unused");
    unused.extend(delimited(2, &[255]));
    malformed.extend(delimited(1, &unused));
    let server = AssetServer::new(geosite("new.example"), malformed, false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    assert_eq!(terminal["error"]["details"]["committed"], false);
    for asset in terminal["error"]["details"]["assets"].as_array().unwrap() {
        assert_eq!(asset["written"], false);
    }
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("old.example")
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geoip.dat")).unwrap(),
        geoip(198)
    );
    assert_eq!(fixture.get(GEO).await["assets"], old["assets"]);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(fixture.path("state")).unwrap().count(), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn disconnect_and_replay_keep_one_inflight_owner() {
    let mut server = AssetServer::new(geosite("new.example"), geoip(203), true).await;
    let fixture = fixture(server.address, false).await;
    let mut stream = TcpStream::connect(fixture.addr).await.unwrap();
    stream.write_all(format!("POST {UPDATE} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nIdempotency-Key: disconnect\r\nContent-Length: 0\r\n\r\n", fixture.addr).as_bytes()).await.unwrap();
    timeout(WAIT, &mut server.entered).await.unwrap().unwrap();
    drop(stream);
    let replay = accepted(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "disconnect")
            .send()
            .await
            .unwrap(),
    )
    .await;
    error(
        fixture
            .request(Method::POST, UPDATE)
            .header("idempotency-key", "different")
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    error(
        fixture
            .request(Method::POST, UPDATE)
            .body("{}")
            .send()
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    server.release.take().unwrap().send(()).unwrap();
    let terminal = fixture.terminal(&replay).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn failure_after_first_rename_reports_partial_write_without_activation() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let service = Arc::clone(&fixture.service);
    let second = fixture.path("state/geoip.dat");
    *fixture.service.before_replace.lock() = Some(Box::new(move || {
        *service.before_replace.lock() = Some(Box::new(move || {
            std::fs::write(second, b"concurrent-editor").unwrap();
        }));
    }));
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed");
    let details = &terminal["error"]["details"];
    assert_eq!(details["assets"][0]["written"], true);
    assert_eq!(details["assets"][0]["durability_confirmed"], true);
    assert_eq!(details["assets"][1]["written"], false);
    assert_eq!(details["committed"], false);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geoip.dat")).unwrap(),
        b"concurrent-editor"
    );
    assert_eq!(fixture.get(GEO).await["assets"], old["assets"]);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn download_bounds_actual_chunked_bytes_and_joins_timed_out_connection() {
    for (response, expected) in [
        (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n".as_slice(), "asset_too_large"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n".as_slice(), "download_timeout"),
        (b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\n\r\n".as_slice(), "http_status_rejected"),
        (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".as_slice(), "content_encoding_rejected"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/data", listener.local_addr().unwrap());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") { head.push(stream.read_u8().await.unwrap()); }
            stream.write_all(response).await.unwrap();
            let mut remaining = Vec::new();
            let read = timeout(WAIT, stream.read_to_end(&mut remaining)).await.unwrap();
            assert!(read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
        });
        let result = download(&url, "", tokio::time::Instant::now() + Duration::from_millis(100), 4).await;
        assert_eq!(result.unwrap_err(), expected);
        tasks.join_next().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn loaded_snapshot_waits_for_router_without_holding_config() {
    use futures::FutureExt as _;
    let fixture = Fixture::new(Access::Admin, false).await;
    let state = fixture.state.upgrade().unwrap();
    {
        let router = state.traffic_router.write().await;
        let capture = crate::native_api::geodata::capture(&state);
        tokio::pin!(capture);
        assert!(capture.as_mut().now_or_never().is_none());
        let config = state
            .config
            .try_write()
            .expect("snapshot must follow reload's router-before-config order");
        drop(config);
        drop(router);
        capture.await.unwrap();
    }
    drop(state);
    fixture.shutdown().await;
}

#[tokio::test]
async fn repeated_update_with_hosts_and_split_dns_assets_retains_available_metadata() {
    let server = AssetServer::new(geosite("old.example"), geoip(203), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, server.address);
        let hosts = root.join("state/hosts.rules");
        std::fs::write(&hosts, "full:host.example 192.0.2.9\n").unwrap();
        let main = files.get_mut("main.dae").unwrap();
        *main = main.replace(" dip(geoip: test) -> block\n", "");
        *main = main.replace(
            root.join("state").to_str().unwrap(),
            root.join("state/../state").to_str().unwrap(),
        );
        main.push_str(&format!(
            "dns {{\n use_host: '{}'\n routing {{\n request {{\n qname(geosite: test) -> reject\n fallback: asis\n }}\n response {{\n ip(geoip: test) -> reject\n fallback: accept\n }}\n }}\n}}\n", hosts.display(),
        ));
    }).await;
    for _ in 0..2 {
        let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
        let terminal = fixture.terminal(&operation).await;
        assert_eq!(terminal["status"], "succeeded", "{terminal}");
        assert_eq!(
            terminal["result"]["assets"][0]["sha256"],
            crate::configuration::digest(&geosite("old.example"))
        );
        assert_eq!(
            terminal["result"]["assets"][1]["sha256"],
            crate::configuration::digest(&geoip(203))
        );
        let capabilities = fixture.get("/api/v1/capabilities").await;
        assert_eq!(capabilities["resources"]["geodata"]["available"], true);
        assert_eq!(capabilities["resources"]["geodata"]["can_update"], true);
        assert_eq!(
            fixture.get(GEO).await["assets"][0]["sha256"],
            crate::configuration::digest(&geosite("old.example"))
        );
    }
    assert_eq!(server.requests.load(Ordering::SeqCst), 4);
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "block");
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn concurrent_geodata_rejections_share_the_original_admission_error() {
    use axum::response::IntoResponse as _;
    let fixture = Fixture::new(Access::Metadata, false).await;
    let state = fixture.state.upgrade().unwrap();
    let id = crate::native_api::types::RequestId("geodata-admission".into());
    {
        let request = || {
            axum::extract::Request::builder()
                .method("POST")
                .uri(UPDATE)
                .header("idempotency-key", "unavailable-update")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let router = state.traffic_router.write().await;
        let first = crate::native_api::geodata::update(&state, request(), &id);
        tokio::pin!(first);
        assert!(futures::poll!(first.as_mut()).is_pending());
        let second = crate::native_api::geodata::update(&state, request(), &id);
        tokio::pin!(second);
        assert!(futures::poll!(second.as_mut()).is_pending());
        drop(router);
        assert_eq!(
            first.await.unwrap_err().into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            second.await.unwrap_err().into_response().status(),
            StatusCode::NOT_FOUND
        );
    }
    drop(state);
    fixture.shutdown().await;
}
