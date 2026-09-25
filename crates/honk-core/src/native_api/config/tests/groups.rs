use super::*;

fn patch(
    fixture: &Fixture,
    group: &Value,
    revision: &str,
    body: &Value,
) -> reqwest::RequestBuilder {
    fixture
        .request(
            Method::PATCH,
            &format!("/api/v1/groups/{}", group["id"].as_str().unwrap()),
        )
        .header("if-match", format!("\"{revision}\""))
        .header("content-type", "application/json-patch+json")
        .body(body.to_string())
}

#[tokio::test]
async fn group_patch_keeps_source_bytes_and_separates_group_revision_from_disk_hash() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let source_text = "# Explicitly writable include.\r\ngroup {\r\n G { policy: fallback }\r\n G {\r\n  policy: 'fallback' # earlier\r\n  policy: \"selector\" # winner\r\n  final: direct\r\n }\r\n}\r\n";
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let groups = fixture.get("/api/v1/groups").await;
    let group = &groups[0];
    let before = fixture.get(CONFIG).await;
    let revision = before["revision"].as_str().unwrap();
    let source = source(&before, source_text);
    let body = json!([{ "op":"replace", "path":"/policy", "value":{"kind":"fallback","native":"fallback"} }]);
    let original = disk(fixture.directory.path());
    error(
        patch(
            &fixture,
            group,
            source["content_sha256"].as_str().unwrap(),
            &body,
        )
        .send()
        .await
        .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let failed = json!([{ "op":"replace", "path":"/config/tolerance", "value":100 }, {"op":"test","path":"/config/final_outbound","value":"block"}]);
    error(
        patch(&fixture, group, revision, &failed)
            .send()
            .await
            .unwrap(),
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let unsupported =
        json!([{"op":"replace","path":"/config/check_url","value":"https://127.0.0.1/"}]);
    error(
        patch(&fixture, group, revision, &unsupported)
            .send()
            .await
            .unwrap(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_value",
    )
    .await;
    let excessive = json!(vec![
        json!({"op":"test","path":"/config/final_outbound","value":"direct"});
        33
    ]);
    error(
        patch(&fixture, group, revision, &excessive)
            .send()
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
    assert_eq!(disk(fixture.directory.path()), original);
    let external = format!("{source_text}# external editor\r\n");
    std::fs::write(fixture.path("editable.dae"), &external).unwrap();
    error(
        patch(&fixture, group, revision, &body)
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        external
    );
    std::fs::write(fixture.path("editable.dae"), source_text).unwrap();
    let operation = accepted(
        patch(&fixture, group, revision, &body)
            .header("idempotency-key", "group-patch")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(operation["kind"], "group_update");
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded");
    let expected = source_text.replace("\"selector\"", "\"fallback\"");
    let written = disk(fixture.directory.path());
    assert_eq!(
        std::fs::read_to_string(fixture.path("editable.dae")).unwrap(),
        expected
    );
    for name in ["main.dae", "auth.dae", "locked.dae"] {
        assert_eq!(
            std::fs::read_to_string(fixture.path(name)).unwrap(),
            fixture.originals[name]
        );
    }
    let after = fixture.get(CONFIG).await;
    assert_eq!(terminal["result"]["group_id"], group["id"]);
    assert_eq!(terminal["result"]["config_revision"], after["revision"]);
    assert_ne!(after["revision"], before["revision"]);
    let replay = accepted(
        patch(&fixture, group, revision, &body)
            .header("idempotency-key", "group-patch")
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], operation["operation_id"]);
    assert_eq!(disk(fixture.directory.path()), written);
    error(
        patch(&fixture, group, revision, &body)
            .send()
            .await
            .unwrap(),
        StatusCode::PRECONDITION_FAILED,
        "stale_revision",
    )
    .await;
    let current_group = fixture
        .get(&format!("/api/v1/groups/{}", group["id"].as_str().unwrap()))
        .await;
    assert_eq!(current_group["policy"]["kind"], "fallback");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 2);
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_without_writable_source_is_unsupported() {
    let fixture = Fixture::new(Access::Metadata, false).await;
    error(
        patch(
            &fixture,
            &json!({"id":"any-group"}),
            "revision",
            &json!([{"op":"replace","path":"/config/tolerance","value":100}]),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    fixture.shutdown().await;
}

#[tokio::test]
async fn group_patch_in_credential_source_is_unsupported() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, files| {
        files
            .get_mut("auth.dae")
            .unwrap()
            .push_str("group {\n L {\n  policy: selector\n  final: direct\n }\n}\n");
    })
    .await;
    let group = &fixture.get("/api/v1/groups").await[0];
    let detail = fixture
        .get(&format!("/api/v1/groups/{}", group["id"].as_str().unwrap()))
        .await;
    assert_eq!(detail["capabilities"]["mutable_config"], json!([]));
    error(
        patch(
            &fixture,
            group,
            detail["config_revision"].as_str().unwrap(),
            &json!([{"op":"replace","path":"/config/tolerance","value":100}]),
        )
        .send()
        .await
        .unwrap(),
        StatusCode::NOT_FOUND,
        "capability_not_supported",
    )
    .await;
    fixture.shutdown().await;
}
