use super::*;

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
async fn full_validation_applies_include_overrides_before_semantic_admission() {
    let fixture = Fixture::new_custom(Access::Admin, false, |_, sources| {
        sources.insert("editable.dae", "global { nfqueue_enable: false }\n".into());
    })
    .await;
    let candidate =
        fixture.originals["main.dae"].replace("nfqueue_enable: false", "nfqueue_enable: invalid");
    let syntax = ok(fixture.validate("syntax", &candidate).send().await.unwrap()).await;
    assert_eq!(syntax["valid"], false);
    let full = ok(fixture.validate("full", &candidate).send().await.unwrap()).await;
    assert_eq!(full["valid"], true, "{full}");
    assert!(
        !full["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["level"] == "error")
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn full_validation_checks_unused_structure_without_applying_unused_settings() {
    let fixture = Fixture::new(Access::Admin, false).await;
    let baseline = ok(fixture
        .validate("full", &fixture.originals["main.dae"])
        .send()
        .await
        .unwrap())
    .await;
    let request = |content| {
        fixture.request(Method::POST, VALIDATE).json(&json!({
            "mode":"full","sources":[
                {"id":"main","path":"main.dae","content":fixture.originals["main.dae"]},
                {"id":"unused","path":"unused.dae","content":content}
            ]
        }))
    };
    let unused =
        "global { nfqueue_enable: invalid }\nunknown {}\ninclude { '/not-opened/private.dae' }\n";
    let valid = ok(request(unused).send().await.unwrap()).await;
    assert_eq!(valid["valid"], true, "{valid}");
    assert_eq!(valid["diagnostics"], baseline["diagnostics"]);
    for malformed in [
        "global {",
        "include { nested.dae {} }",
        "dns {\n use_host: 'unterminated\n}\n",
    ] {
        let invalid = ok(request(malformed).send().await.unwrap()).await;
        assert_eq!(invalid["valid"], false);
        diagnostics(&invalid["diagnostics"], "unused", "nested.dae");
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn full_validation_counts_unused_sources_with_every_host_materialization() {
    let fixture = Fixture::new(Access::Admin, false).await;
    std::fs::write(fixture.path("hosts.rules"), "full:alias.test 192.0.2.1\n").unwrap();
    let candidate = |count| {
        let hosts = (0..count)
            .map(|index| {
                format!(
                    " use_host: '{}/{}hosts.rules'\n",
                    fixture.directory.path().display(),
                    "./".repeat(index)
                )
            })
            .collect::<String>();
        format!(
            "global {{ nfqueue_enable: false }}\nrouting {{ fallback: direct }}\ndns {{\n{hosts}}}\n"
        )
    };
    let full = candidate(31);
    let without_unused = ok(fixture.validate("full", &full).send().await.unwrap()).await;
    assert_eq!(without_unused["valid"], true, "{without_unused}");
    let request = |content| {
        fixture.request(Method::POST, VALIDATE).json(&json!({
            "mode":"full","sources":[
                {"id":"main","path":"main.dae","content":content},
                {"id":"unused","path":"unused.dae","content":"# unused\n"}
            ]
        }))
    };
    let at_limit = ok(request(candidate(30)).send().await.unwrap()).await;
    assert_eq!(at_limit["valid"], true, "{at_limit}");
    error(
        request(full).send().await.unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request_too_large",
    )
    .await;
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
    // Returned entry-relative paths can be echoed without expanding file authority.
    let echoed_sources: Vec<_> = before["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["content"].is_string())
        .map(|row| json!({"id":row["id"],"path":row["path"],"content":row["content"]}))
        .collect();
    assert!(echoed_sources.len() > 1);
    let echoed = ok(fixture
        .request(Method::POST, VALIDATE)
        .json(&json!({
            "mode":"full","sources":echoed_sources
        }))
        .send()
        .await
        .unwrap())
    .await;
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
