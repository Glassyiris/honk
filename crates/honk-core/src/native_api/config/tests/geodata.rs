use super::*;
use crate::native_api::geodata::download_direct;

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
            r#"domain(keyword: example, geosite: test)"#,
            r#"dip(192.0.2.0/24, geoip: test)"#,
            r#"pname(curl)"#,
            r#"!dport(53)"#,
        ]
    );
    assert!(conditions.iter().all(|row| row["result"] == "matched"));
    let not_matched = ok(trace("other.org").send().await.unwrap()).await;
    let evaluation = &not_matched["evaluations"][0];
    assert_eq!(evaluation["outbound"], "direct");
    assert_eq!(
        evaluation["rules"][0]["conditions"][0]["result"],
        "not_matched"
    );
    assert_eq!(evaluation["rules"][0]["conditions"][1]["result"], "skipped");
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
        StatusCode::CONFLICT,
        "state_conflict",
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
        format!("http://{}/geosite/PRIVATE", server.address)
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
    fixture.assert_last_reload(&terminal).await;
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
async fn shutdown_abandons_an_inflight_download() {
    let mut server = AssetServer::new(geosite("new.example"), geoip(203), true).await;
    let mut fixture = fixture(server.address, false).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    timeout(WAIT, &mut server.entered).await.unwrap().unwrap();
    let coordinator = fixture.coordinator.take().unwrap();
    timeout(WAIT, coordinator.shutdown())
        .await
        .expect("shutdown waited for the download");
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "coordinator_stopped");
    assert_eq!(terminal["error"]["details"]["committed"], false);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("old.example")
    );
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
    assert_eq!(
        fixture.get("/api/v1/runtime").await["last_reload"],
        Value::Null
    );
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
        (b"HTTP/1.1 302 Found\r\nContent-Length: 1\r\n\r\n".as_slice(), "http_status_rejected"),
        (b"HTTP/1.1 302 Found\r\nContent-Length: 5\r\n\r\n12345".as_slice(), "http_status_rejected"),
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
        let result = download_direct(&url, "", (tokio::time::Instant::now() + Duration::from_millis(100)).into(), 4).await;
        assert_eq!(result.unwrap_err().code, expected);
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
async fn cached_subscription_rows_are_fenced_without_filesystem_guards() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        setup(root, files, server.address);
        files
            .get_mut("main.dae")
            .unwrap()
            .push_str("\nsubscription {\n cached: 'http://127.0.0.1:9/cached'\n}\n");
    })
    .await;
    let state = fixture.state.upgrade().unwrap();
    let subscription = state.config.read().await.subscriptions[0].clone();
    drop(state);
    let store = crate::subscription::SubscriptionStore::in_dir(&fixture.path("state"));

    for port in [17771, 17772] {
        let domain = format!("{port}.example");
        server.serve_geosite(geosite(&domain));
        store
            .store_content(&subscription, format!("socks5://127.0.0.1:{port}#cached"))
            .await
            .unwrap();
        let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
        let terminal = fixture.terminal(&operation).await;
        assert_eq!(terminal["status"], "succeeded", "{terminal}");
        assert_eq!(route(&fixture, &domain, "192.0.2.5").await, "block");
    }
    server.serve_geosite(geosite("final.example"));

    let before = fixture.get(GEO).await;
    let (entered, resume) = fixture.pause_before_replace();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    timeout(WAIT, entered).await.unwrap().unwrap();
    store
        .store_content(&subscription, "socks5://127.0.0.1:17773#changed".into())
        .await
        .unwrap();
    resume.send(()).unwrap();
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "replacement_failed");
    assert!(
        terminal["error"]["details"]["assets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|asset| asset["written"] == false)
    );
    assert_eq!(fixture.get(GEO).await["assets"], before["assets"]);
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("17772.example")
    );
    drop(store);
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
