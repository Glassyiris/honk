use super::*;

#[tokio::test]
async fn rule_details_use_accepted_expressions_without_exposing_source_content() {
    let fixture = Fixture::new_custom(Access::Metadata, false, |_, files| {
        files.get_mut("auth.dae").unwrap().push_str(
            "routing { pname(credential-source-process) -> direct }\n",
        );
        files.insert("locked.dae", "routing {\n domain(\n # private-comment\n regex: 'a->b#c'\n ) && !dport(53) -> direct(must)\n -> block\n}\n".into());
    })
    .await;
    let config = fixture.get(CONFIG).await;
    assert!(
        config["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|source| { source.get("content").is_none() && source["writable"] == false })
    );
    let before = fixture.get("/api/v1/rules").await;
    assert_eq!(before["rules"][0]["expression"], "pname(<redacted>)");
    assert!(before["rules"][0]["source"].is_null());
    assert_eq!(
        before["rules"][1]["expression"],
        "domain( regex: 'a->b#c') && !dport(53)"
    );
    assert_eq!(before["rules"][1]["outbound"], "direct");
    assert_eq!(before["rules"][1]["must"], true);
    assert_eq!(before["rules"][1]["source"]["line"], 2);
    assert_eq!(before["rules"][1]["source"]["file"], "<redacted>");
    assert!(
        !before["rules"][2]["expression"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    let encoded = before.to_string();
    for withheld in [
        SECRET,
        "credential-source-process",
        "private-comment",
        "locked.dae",
    ] {
        assert!(!encoded.contains(withheld));
    }

    std::fs::write(fixture.path("locked.dae"), "routing { dport(\n").unwrap();
    let rejected = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&rejected).await["status"], "failed");
    assert_eq!(fixture.get("/api/v1/rules").await, before);

    let candidate = fixture.originals["locked.dae"].replace("!dport(53)", "!dport(853)");
    std::fs::write(fixture.path("locked.dae"), candidate).unwrap();
    assert_eq!(fixture.get("/api/v1/rules").await, before);
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let after = fixture.get("/api/v1/rules").await;
    assert_ne!(after["generation_id"], before["generation_id"]);
    assert_ne!(after["rules"][1]["rule_id"], before["rules"][1]["rule_id"]);
    assert_eq!(after["rules"][1]["source"], before["rules"][1]["source"]);
    assert_eq!(
        after["rules"][1]["expression"],
        "domain( regex: 'a->b#c') && !dport(853)"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn discarded_202_and_concurrent_retries_share_exactly_one_write_and_reload() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let first = fixture
        .replace(main, &candidate)
        .header("idempotency-key", "lost-202")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let location = first.headers()["location"].to_str().unwrap().to_owned();
    drop(first);
    let release = fixture.next_reload().await;
    let written = disk(fixture.directory.path());
    let a = fixture
        .replace(main, &candidate)
        .header("idempotency-key", "lost-202")
        .send();
    let b = fixture
        .replace(main, &candidate)
        .header("idempotency-key", "lost-202")
        .send();
    let (a, b) = tokio::join!(a, b);
    let a = accepted(a.unwrap()).await;
    let b = accepted(b.unwrap()).await;
    assert_eq!(a, b);
    assert_eq!(a["href"], location);
    error(
        fixture
            .replace(main, &format!("{candidate}# different body\n"))
            .header("idempotency-key", "lost-202")
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "idempotency_conflict",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), written);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    assert_eq!(fixture.terminal(&a).await["status"], "succeeded");
    let replay = accepted(
        fixture
            .replace(main, &candidate)
            .header("idempotency-key", "lost-202")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], a["operation_id"]);
    error(
        fixture.replace(main, &candidate).send().await.unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    fixture.barrier().await;
    assert_eq!(disk(fixture.directory.path()), written);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    fixture.shutdown().await;
}

#[tokio::test]
async fn client_disconnect_and_coordinator_shutdown_preserve_accepted_handoff() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let (entered, resume) = fixture.pause_before_replace();
    let body = serde_json::to_string(&json!({"content":candidate})).unwrap();
    let mut socket = TcpStream::connect(fixture.addr).await.unwrap();
    let request = format!(
        "PUT {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nIf-Match: {}\r\nIdempotency-Key: disconnected\r\nConnection: close\r\n\r\n{body}",
        source_path(main),
        fixture.addr,
        body.len(),
        etag(main),
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    timeout(WAIT, entered).await.unwrap().unwrap();
    socket.shutdown().await.unwrap();
    drop(socket);
    resume.send(()).unwrap();
    let release = fixture.next_reload().await;
    let operation = accepted(
        fixture
            .replace(main, &candidate)
            .header("idempotency-key", "disconnected")
            .send()
            .await
            .unwrap(),
    )
    .await;
    let mut shutdown = JoinSet::new();
    let coordinator = fixture.coordinator.take().unwrap();
    shutdown.spawn(coordinator.shutdown());
    release.send(()).unwrap();
    timeout(WAIT, shutdown.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    assert_eq!(
        source(&fixture.get(CONFIG).await, &candidate)["id"],
        main["id"]
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    assert!(
        fixture.control.try_join_next().is_none(),
        "client loss stopped the control dispatcher"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn sighup_queued_behind_a_source_write_loads_the_written_bytes() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let (entered, resume) = fixture.pause_before_replace();
    let request = fixture.replace(main, &candidate);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await });
    timeout(WAIT, entered).await.unwrap().unwrap();
    fixture.service.request_sighup().unwrap();
    resume.send(()).unwrap();
    let release = fixture.next_reload().await;
    let operation = accepted(
        timeout(WAIT, requests.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .await;
    assert_eq!(fixture.get(CONFIG).await, before);
    release.send(()).unwrap();
    let release_sighup = fixture.next_reload().await;
    let first = fixture.get(CONFIG).await;
    assert_eq!(source(&first, &candidate)["id"], main["id"]);
    release_sighup.send(()).unwrap();
    fixture.barrier().await;
    let after = fixture.get(CONFIG).await;
    assert_eq!(after["generation_id"], first["generation_id"]);
    assert_eq!(after["revision"], first["revision"]);
    assert_eq!(source(&after, &candidate)["id"], main["id"]);
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    fixture.assert_last_reload(&terminal).await;
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_restart_reload_keeps_accepted_sources_while_written_bytes_remain() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let warm = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&warm).await["status"], "succeeded");
    let reloads_before = fixture.reloads.load(Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate =
        fixture.originals["main.dae"].replace("nfqueue_enable: false", "nfqueue_enable: true");
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let rejected = fixture.terminal(&operation).await;
    assert_eq!(rejected["status"], "failed");
    assert_eq!(rejected["error"]["code"], "reload_rejected");
    assert!(rejected["result"].is_null());
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        candidate
    );
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.get(&source_path(main)).await, *main);
    fixture.assert_last_reload(&rejected).await;
    let repaired = format!("{}# repaired locally\n", fixture.originals["main.dae"]);
    std::fs::write(fixture.path("main.dae"), &repaired).unwrap();
    let recovery = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    let terminal = fixture.terminal(&recovery).await;
    assert_eq!(terminal["status"], "succeeded");
    let after = fixture.get(CONFIG).await;
    assert_eq!(after["generation_id"], before["generation_id"]);
    assert_ne!(after["revision"], before["revision"]);
    assert_eq!(source(&after, &repaired)["id"], main["id"]);
    fixture.assert_last_reload(&terminal).await;
    assert_eq!(
        fixture.get(operation["href"].as_str().unwrap()).await,
        rejected
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), reloads_before + 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn dependency_change_before_rename_rejects_without_overwriting_external_content() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let mut external = disk(fixture.directory.path());
    let (entered, resume) = fixture.pause_before_replace();
    let request = fixture.replace(main, &candidate);
    let mut requests = JoinSet::new();
    requests.spawn(async move { request.send().await });
    timeout(WAIT, entered).await.unwrap().unwrap();
    std::fs::write(
        fixture.path("locked.dae"),
        "# Manual dependency edit must win.\n",
    )
    .unwrap();
    external
        .iter_mut()
        .find(|entry| entry.path == Path::new("locked.dae"))
        .unwrap()
        .hash = sha256("# Manual dependency edit must win.\n");
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
    assert_eq!(disk(fixture.directory.path()), external);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}

#[tokio::test]
async fn suspended_admission_rejects_without_waiting_for_busy_coordinator() {
    let mut fixture = Fixture::new(Access::Admin, true).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let accepted = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    let release = fixture.next_reload().await;
    let (phase, receiver) = tokio::sync::watch::channel(crate::control::EnginePhase::Suspending);
    fixture.service.attach_phase(receiver);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let response = fixture
        .replace(main, &candidate)
        .header("idempotency-key", "during-suspend")
        .send()
        .await
        .unwrap();
    error(response, StatusCode::CONFLICT, "state_conflict").await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    phase.send_replace(crate::control::EnginePhase::Running);
    release.send(()).unwrap();
    assert_eq!(fixture.terminal(&accepted).await["status"], "succeeded");
    fixture.barrier().await;
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    assert_eq!(
        std::fs::read_to_string(fixture.path("main.dae")).unwrap(),
        fixture.originals["main.dae"]
    );
    fixture.shutdown().await;
}
