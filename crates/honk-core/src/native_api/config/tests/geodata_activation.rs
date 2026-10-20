use super::*;

/// Group `proxy` exists in the configuration; the file routes downloads through it.
fn setup_group(root: &Path, files: &mut HashMap<&'static str, String>) {
    setup_rules(root, files);
    files
        .get_mut("editable.dae")
        .unwrap()
        .push_str("group {\n proxy { policy: fallback }\n}\n");
    let auth = files.get_mut("auth.dae").unwrap();
    *auth = auth.replace(
        " enabled: true",
        " geodata_download_detour: 'proxy'\n enabled: true",
    );
}

#[tokio::test]
async fn the_download_route_names_a_current_group_by_id() {
    let fixture = Fixture::new_with_state(Access::Admin, setup_group).await;
    let groups = fixture.get("/api/v1/groups").await;
    let proxy = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["name"] == "proxy")
        .unwrap()["id"]
        .clone();
    let seeded = fixture.get(SETTINGS).await["geodata"].clone();
    assert_eq!(
        seeded["download"],
        json!({"route": "group", "group_id": proxy})
    );
    let before = fixture.get(SETTINGS).await;
    error(
        patch_settings(
            &fixture,
            json!({"geodata": {"download": {"route": "group", "group_id": "missing"}}}),
        )
        .await,
        StatusCode::CONFLICT,
        "state_conflict",
    )
    .await;
    error(
        patch_settings(
            &fixture,
            json!({"geodata": {"download": {"route": "group", "group_id": "missing"}},
                "log": {"buffered_records": 1}}),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    )
    .await;
    assert_eq!(fixture.get(SETTINGS).await["geodata"], before["geodata"]);
    let routed = ok(patch_settings(
        &fixture,
        json!({"geodata": {"download": {"route": "routing"}}}),
    )
    .await)
    .await;
    assert_eq!(
        routed["geodata"]["download"],
        json!({"route": "routing", "group_id": null})
    );
    assert_eq!(routed["geodata"]["source"], "default");
    let grouped = ok(patch_settings(
        &fixture,
        json!({"geodata": {"download": {"route": "group", "group_id": proxy}}}),
    )
    .await)
    .await;
    assert_eq!(
        grouped["geodata"]["download"],
        json!({"route": "group", "group_id": proxy})
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_activation_records_failed_last_reload() {
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = fixture(server.address, false).await;
    fixture
        .reject_reloads
        .store(ReloadBehavior::Reject as u8, Ordering::SeqCst);
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["details"]["stage"], "reload_rejected");
    fixture.assert_last_reload(&terminal).await;
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn identical_bytes_keep_the_loaded_files_and_generation() {
    let server = AssetServer::new(geosite("old.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    let old = fixture.get(GEO).await;
    let inode = |name: &str| std::fs::metadata(fixture.path(name)).unwrap().ino();
    let before = [inode("state/geosite.dat"), inode("state/geoip.dat")];
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(terminal["result"]["assets"], old["assets"]);
    assert_eq!(
        [inode("state/geosite.dat"), inode("state/geoip.dat")],
        before
    );
    assert_eq!(std::fs::read_dir(fixture.path("state")).unwrap().count(), 2);
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.get("/api/v1/runtime").await["last_reload"],
        Value::Null
    );
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn identical_bytes_over_a_changed_loaded_file_are_not_a_success() {
    let server = AssetServer::new(geosite("old.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    std::fs::write(fixture.path("state/geosite.dat"), geosite("edited.example")).unwrap();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(
        terminal["error"]["details"]["stage"], "asset_conflict",
        "{terminal}"
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("edited.example")
    );
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn an_update_follows_a_reload_over_an_externally_edited_dependency() {
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::geodata_activation::an_update_follows_a_reload_over_an_externally_edited_dependency",
    ) {
        return;
    }
    let server = AssetServer::new(geosite("new.example"), geoip(203), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        // Real reloads resolve assets through the process-wide data directory.
        honk_config::paths::set_data_dir(root.join("state")).unwrap();
        setup(root, files, server.address);
    })
    .await;
    let hosts = fixture.path("hosts.rules");
    std::fs::write(&hosts, "full:alias.test 192.0.2.1\n").unwrap();
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = format!(
        "{}dns {{\n use_host: '{}'\n}}\n",
        fixture.originals["main.dae"],
        hosts.display()
    );
    let write = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&write).await["status"], "succeeded");
    let written = fixture.get(CONFIG).await;
    std::fs::write(&hosts, "full:alias.test 192.0.2.2\n").unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    let reloaded = fixture.get(CONFIG).await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_ne!(reloaded["revision"], written["revision"]);
    let updated = fixture.get(CONFIG).await;
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&reload).await["status"], "succeeded");
    assert_eq!(fixture.get(CONFIG).await["revision"], updated["revision"]);
    fixture.shutdown().await;
    server.close().await;
}

#[tokio::test]
async fn a_reload_keeps_runtime_admission_when_a_geo_asset_cannot_be_captured() {
    if crate::native_api::logs::tests::run_isolated(
        "native_api::config::tests::geodata_activation::a_reload_keeps_runtime_admission_when_a_geo_asset_cannot_be_captured",
    ) {
        return;
    }
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        honk_config::paths::set_data_dir(root.join("state")).unwrap();
        setup_rules(root, files);
    })
    .await;
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = format!("{}# Capture dependencies.\n", fixture.originals["main.dae"]);
    let write = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    assert_eq!(fixture.terminal(&write).await["status"], "succeeded");
    let asset = fixture.path("state/geosite.dat");
    std::fs::remove_file(&asset).unwrap();
    // A regular proc file whose reads fail even when the test runs as root.
    std::os::unix::fs::symlink("/proc/self/mem", &asset).unwrap();
    let reload = accepted(fixture.request(Method::POST, RELOAD).send().await.unwrap()).await;
    let terminal = fixture.terminal(&reload).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    fixture.shutdown().await;
}

/// A reload keeps a router whose asset bytes are unchanged, so it can go on
/// naming a packaged file after an identical copy starts shadowing it.
#[tokio::test]
async fn an_update_replaces_the_resolved_copy_of_an_unchanged_loaded_file() {
    let server = AssetServer::new(geosite("new.example"), geoip(198), false).await;
    let fixture = fixture(server.address, false).await;
    let packaged = fixture.path("packaged");
    std::fs::create_dir_all(&packaged).unwrap();
    for name in ["geosite.dat", "geoip.dat"] {
        std::fs::copy(fixture.path(&format!("state/{name}")), packaged.join(name)).unwrap();
    }
    {
        let state = fixture.state.upgrade().unwrap();
        let config = state.config.read().await.clone();
        let requirements = crate::routing::GeoRequirements::for_traffic(&config.routing.rules)
            .union(&DnsRouter::geo_requirements(&config.dns));
        let geo = crate::routing::GeoSourceSet::load_captured(&requirements, &packaged, |path| {
            std::fs::read(path).map(Arc::from)
        })
        .unwrap();
        *state.traffic_router.write().await =
            Router::from_config_with_geo_sources(&config.routing, &geo).unwrap();
    }
    let geoip_inode = std::fs::metadata(fixture.path("state/geoip.dat"))
        .unwrap()
        .ino();
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(
        terminal["result"]["assets"][0]["sha256"],
        crate::configuration::digest(&geosite("new.example"))
    );
    assert_eq!(
        std::fs::read(fixture.path("state/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert_eq!(
        std::fs::read(packaged.join("geosite.dat")).unwrap(),
        geosite("old.example")
    );
    assert_eq!(
        std::fs::metadata(fixture.path("state/geoip.dat"))
            .unwrap()
            .ino(),
        geoip_inode
    );
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    assert_eq!(route(&fixture, "old.example", "192.0.2.5").await, "direct");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    let again = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&again).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 1);
    fixture.shutdown().await;
    server.close().await;
}

/// OpenWrt's default data directory `/var/lib/honk` sits under `/var -> tmp`.
#[tokio::test]
async fn an_update_writes_through_a_linked_data_directory_prefix() {
    let server = AssetServer::new(geosite("new.example"), geoip(198), false).await;
    let fixture = Fixture::new_custom(Access::Admin, false, |root, files| {
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::os::unix::fs::symlink("tmp", root.join("state")).unwrap();
        setup(root, files, server.address)
    })
    .await;
    let operation = accepted(fixture.request(Method::POST, UPDATE).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(
        std::fs::read(fixture.path("tmp/geosite.dat")).unwrap(),
        geosite("new.example")
    );
    assert!(
        std::fs::symlink_metadata(fixture.path("state"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(route(&fixture, "new.example", "192.0.2.5").await, "block");
    fixture.shutdown().await;
    server.close().await;
}
