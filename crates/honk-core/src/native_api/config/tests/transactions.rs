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
            .all(|source| { source["content"].is_string() && source["writable"] == false })
    );
    let before = fixture.get("/api/v1/rules").await;
    assert_eq!(
        before["rules"][0]["expression"],
        "pname(credential-source-process)"
    );
    assert_eq!(before["rules"][0]["source"]["file"], "auth.dae");
    assert_eq!(
        before["rules"][1]["expression"],
        "domain( regex: 'a->b#c') && !dport(53)"
    );
    assert_eq!(before["rules"][1]["outbound"], "direct");
    assert_eq!(before["rules"][1]["must"], true);
    assert_eq!(before["rules"][1]["source"]["line"], 2);
    let rule_source = &before["rules"][1]["source"];
    assert_eq!(rule_source["file"], "locked.dae");
    let config_source = config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["id"] == rule_source["source_id"])
        .unwrap();
    assert_eq!(rule_source["file"], config_source["path"]);
    assert_eq!(before["fallback"]["source"]["file"], "main.dae");
    assert!(
        !before["rules"][2]["expression"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    let encoded = before.to_string();
    for withheld in [
        SECRET,
        "private-comment",
        fixture.directory.path().to_str().unwrap(),
    ] {
        assert!(!encoded.contains(withheld));
    }
    let trace = || {
        fixture
            .request(Method::POST, "/api/v1/routing/trace")
            .json(&json!({
                "input":{"network":"tcp","domain":"example.com","dst_port":443,"pname":"curl"},
                "resolve":"none"
            }))
    };
    let traced = ok(trace().send().await.unwrap()).await;
    let evaluated = &traced["evaluations"][0]["rules"];
    assert_eq!(evaluated[1]["expression"], before["rules"][1]["expression"]);
    assert_eq!(evaluated[1]["rule_id"], before["rules"][1]["rule_id"]);
    assert_eq!(
        evaluated[1]["conditions"][0]["expression"],
        r#"domain(regex: a->b#c)"#
    );
    assert_eq!(evaluated[1]["conditions"][0]["result"], "not_matched");
    assert_eq!(evaluated[1]["conditions"][1]["expression"], r#"!dport(53)"#);
    assert_eq!(evaluated[1]["conditions"][1]["result"], "skipped");
    assert_eq!(
        evaluated[0]["conditions"][0]["expression"],
        "pname(credential-source-process)"
    );
    for withheld in [SECRET, "private-comment"] {
        assert!(!traced.to_string().contains(withheld));
    }

    std::fs::write(fixture.path("locked.dae"), "routing { dport(\n").unwrap();
    let rejected = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&rejected).await["status"], "failed");
    assert_eq!(fixture.get("/api/v1/rules").await, before);
    assert_eq!(
        ok(trace().send().await.unwrap()).await["evaluations"],
        traced["evaluations"]
    );

    let candidate = fixture.originals["locked.dae"].replace("!dport(53)", "!dport(853)");
    std::fs::write(fixture.path("locked.dae"), candidate).unwrap();
    assert_eq!(fixture.get("/api/v1/rules").await, before);
    assert_eq!(
        ok(trace().send().await.unwrap()).await["evaluations"],
        traced["evaluations"]
    );
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
    let traced_after = ok(trace().send().await.unwrap()).await;
    assert_eq!(traced_after["generation_id"], after["generation_id"]);
    assert_eq!(
        traced_after["evaluations"][0]["rules"][1]["expression"],
        after["rules"][1]["expression"]
    );
    assert_eq!(
        traced_after["evaluations"][0]["rules"][1]["conditions"][1]["expression"],
        r#"!dport(853)"#
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
async fn rejected_reload_keeps_accepted_sources_while_written_bytes_remain() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let warm = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&warm).await["status"], "succeeded");
    let reloads_before = fixture.reloads.load(Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    fixture.reject_reloads.store(1, Ordering::SeqCst);
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
    fixture.reject_reloads.store(0, Ordering::SeqCst);
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

/// Checks a 422 that names every restart-only setting the candidate changes.
fn restart_rows(failure: &Value, source_id: &str, level: &str, fields: &[&str]) {
    let rows: Vec<_> = failure
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["code"] == "restart-required")
        .collect();
    assert_eq!(rows.len(), fields.len(), "{failure}");
    for (row, field) in rows.iter().zip(fields) {
        assert_eq!(row["level"], level);
        assert_eq!(row["source_id"], source_id);
        assert!(row["message"].as_str().unwrap().contains(field));
    }
}

#[tokio::test]
async fn restart_only_change_is_refused_before_writing() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let before_disk = disk(fixture.directory.path());
    let candidate = fixture.originals["main.dae"].replace(
        "nfqueue_enable: false",
        "nfqueue_enable: true\n log_level: debug\n so_mark_from_dae: 512",
    );
    let failure = error(
        fixture.replace(main, &candidate).send().await.unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    restart_rows(
        &failure["error"]["details"]["diagnostics"],
        main["id"].as_str().unwrap(),
        "error",
        &[
            "global.so_mark_from_dae",
            "global.log_level",
            "global.nfqueue_enable",
        ],
    );
    assert_eq!(disk(fixture.directory.path()), before_disk);
    assert_eq!(fixture.get(CONFIG).await, before);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);

    // Nothing was written, so the accepted hash still matches the disk and the next write goes through.
    let edited = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let operation = accepted(fixture.replace(main, &edited).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&operation).await["status"], "succeeded");
    source(&fixture.get(CONFIG).await, &edited);

    let checked = ok(fixture.validate("full", &candidate).send().await.unwrap()).await;
    assert_eq!(checked["valid"], true, "{checked}");
    restart_rows(
        &checked["diagnostics"],
        "candidate",
        "warning",
        &[
            "global.so_mark_from_dae",
            "global.log_level",
            "global.nfqueue_enable",
        ],
    );
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
