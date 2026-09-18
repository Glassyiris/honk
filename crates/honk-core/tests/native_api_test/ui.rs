use super::*;
#[tokio::test]
async fn ui_serves_only_its_directory_with_navigation_and_static_cache_policy() {
    let directory = tempfile::tempdir().unwrap();
    let ui = directory.path().join("ui");
    std::fs::create_dir_all(ui.join("assets")).unwrap();
    std::fs::create_dir(ui.join("fonts")).unwrap();
    std::fs::create_dir(ui.join("icons")).unwrap();
    std::fs::write(
        directory.path().join("private.dae"),
        "private-config-marker",
    )
    .unwrap();
    let index = "<!doctype html><title>hosting fixture only</title><script src='/ui/assets/app.js'></script>";
    for (path, content) in [
        ("index.html", index),
        ("assets/app.js", "window.hostingFixture = true;"),
        ("assets/app.css", "body { color: black; }"),
        ("manifest.webmanifest", "{\"name\":\"hosting fixture\"}"),
        ("sw.js", "self.addEventListener('fetch', () => {});"),
    ] {
        std::fs::write(ui.join(path), content).unwrap();
    }
    let app =
        TestApp::new(|config| config.experimental.native_api.ui = ui.to_str().unwrap().into())
            .await;
    for path in ["/", "/ui"] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert!(response.status().is_redirection());
        assert_eq!(response.headers()["location"], "/ui/");
    }
    for (path, mime) in [
        ("/ui/", "text/html"),
        ("/ui/deep/navigation", "text/html"),
        ("/ui/assets/app.js", "text/javascript"),
        ("/ui/assets/app.css", "text/css"),
        ("/ui/manifest.webmanifest", "application/manifest+json"),
        ("/ui/sw.js", "text/javascript"),
    ] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(mime),
            "{path}"
        );
        let body = response.text().await.unwrap();
        if mime == "text/html" {
            assert_eq!(body, index);
        }
        assert!(!body.contains(SECRET));
    }
    let head = app
        .client
        .head(app.url("/ui/deep/navigation"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()["cache-control"], "no-cache");
    assert!(head.bytes().await.unwrap().is_empty());
    for path in [
        "/ui/missing.js",
        "/ui/missing.webmanifest",
        "/ui/assets/missing",
        "/ui/fonts/missing",
        "/ui/icons/missing",
        "/ui/assets/",
        "/private.dae",
        "/assets/app.js",
    ] {
        let response = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let body = response.text().await.unwrap();
        assert!(!body.contains("hosting fixture only") && !body.contains("private-config-marker"));
    }
    for path in [
        "/ui/../private.dae",
        "/ui/%2e%2e/private.dae",
        "/ui/%2E%2E%2Fprivate.dae",
        "/ui/%2e%2e%5cprivate.dae",
        "/ui/%00",
        "/ui/%FF",
        "/ui/%zz",
    ] {
        let response = raw_request(&app, path, "", b"").await;
        assert!(
            (400..500).contains(&response.status),
            "{path}: {}",
            response.status
        );
        let body = String::from_utf8_lossy(&response.body);
        assert!(!body.contains("hosting fixture only") && !body.contains("private-config-marker"));
    }
    error_response(
        app.get("/api/v1/missing").send().await.unwrap(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    )
    .await;
    error_response(
        app.client.get(app.url("/api")).send().await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    for (header, value) in [
        ("host", "attacker.example"),
        ("origin", "https://attacker.example"),
    ] {
        let response = app
            .client
            .get(app.url("/ui/"))
            .header(header, value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        error_body(
            &response.json::<Value>().await.unwrap(),
            "permission_denied",
        );
    }
    app.shutdown().await;
}

#[tokio::test]
async fn ui_without_a_readable_index_rejects_startup() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.secret = SECRET.into();
    config.experimental.native_api.ui = directory.path().to_str().unwrap().into();
    config.ensure_builtin_nodes();
    let mut control = control_plane(config);
    assert!(
        NativeState::new(
            &mut control,
            "127.0.0.1:9527".parse().unwrap(),
            SystemTime::now(),
            Instant::now(),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn slow_public_file_readers_release_capacity_at_the_connection_deadline() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), "hosting fixture").unwrap();
    let file = std::fs::File::create(directory.path().join("large.bin")).unwrap();
    let file_size = 64 * 1024 * 1024;
    file.set_len(file_size).unwrap();
    let app = TestApp::new(|config| {
        config.experimental.native_api.ui = directory.path().to_str().unwrap().into()
    })
    .await;
    let mut peers = Vec::new();
    for _ in 0..64 {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        let mut stream = socket.connect(app.addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /ui/large.bin HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    app.addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut header = Vec::new();
        timeout(IO_TIMEOUT, async {
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
                assert!(header.len() < 4096);
            }
        })
        .await
        .unwrap();
        let header = String::from_utf8(header).unwrap().to_ascii_lowercase();
        assert!(header.starts_with("http/1.1 200 "));
        assert!(header.contains(&format!("content-length: {file_size}")));
        peers.push(stream);
    }
    let mut waiting = TcpStream::connect(app.addr).await.unwrap();
    waiting.write_all(format!("GET /api HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n", app.addr).as_bytes()).await.unwrap();
    assert!(
        timeout(Duration::from_millis(50), waiting.read_u8())
            .await
            .is_err()
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    let response = read_raw_response(&mut waiting).await;
    assert_eq!(response.status, 200);
    let mut first = peers.remove(0);
    socket2::SockRef::from(&first)
        .set_recv_buffer_size(4 * 1024 * 1024)
        .unwrap();
    drop(peers);
    let received = timeout(
        IO_TIMEOUT,
        tokio::io::copy(&mut first, &mut tokio::io::sink()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        received < file_size,
        "the socket must close with the large response incomplete"
    );
    app.shutdown().await;
}
