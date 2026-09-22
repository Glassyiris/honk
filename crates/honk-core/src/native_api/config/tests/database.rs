//! `--store db`: writes are recorded as revisions and never need the imported tree.

use super::*;

/// `(number, parent, principal, origin)` of every revision, oldest first.
fn revisions(fixture: &Fixture) -> Vec<(i64, Option<i64>, String, String)> {
    let path = fixture.path("state/native-api/config.db");
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = connection
        .prepare("SELECT number, parent, principal, origin FROM revision ORDER BY number")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[tokio::test]
async fn main_source_write_records_a_revision_after_the_tree_is_deleted() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let parsed = Config::from_dae_file_with_sources(
        &fixture.path("etc/main.dae"),
        &HashMap::new(),
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .config;
    std::fs::remove_dir_all(fixture.path("etc")).unwrap();
    assert_eq!(
        store.head(),
        Ok(Some(1)),
        "startup import records revision 1"
    );
    let stored = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(stored.config, parsed);

    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "succeeded", "{terminal}");
    assert_eq!(store.head(), Ok(Some(2)));
    assert_eq!(
        revisions(&fixture),
        [
            (1, None, "startup".into(), "import".into()),
            (2, Some(1), "control".into(), "write".into()),
        ]
    );
    let after = fixture.get(CONFIG).await;
    assert_eq!(source(&after, &candidate)["id"], main["id"]);
    assert!(!fixture.path("etc").exists());
    fixture.shutdown().await;
}

#[tokio::test]
async fn rejected_reload_leaves_the_db_head_alone() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    fixture.reject_reloads.store(true, Ordering::SeqCst);
    let before = fixture.get(CONFIG).await;
    let main = source(&before, &fixture.originals["main.dae"]);
    assert_eq!(main["writable"], true);
    let candidate = fixture.originals["main.dae"].replace("fallback: direct", "fallback: block");
    let operation = accepted(fixture.replace(main, &candidate).send().await.unwrap()).await;
    let terminal = fixture.terminal(&operation).await;
    assert_eq!(terminal["status"], "failed", "{terminal}");
    assert_eq!(terminal["error"]["code"], "reload_rejected");
    assert_eq!(terminal["error"]["details"]["written"], false);
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(revisions(&fixture).len(), 1);
    let after = fixture.get(CONFIG).await;
    assert_eq!(after["revision"], before["revision"]);
    fixture.shutdown().await;
}

#[tokio::test]
async fn listener_settings_data_dir_and_secrets_stay_read_only() {
    let fixture = Fixture::new_db(Access::Admin).await;
    let store = Arc::clone(fixture.database.as_ref().unwrap());
    let config = fixture.get(CONFIG).await;
    let main = source(&config, &fixture.originals["main.dae"]);
    let auth = config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|source| source["path"] == "auth.dae")
        .unwrap();
    let stored_auth = store
        .load(&HashMap::new(), &mut Vec::new())
        .unwrap()
        .sources
        .into_iter()
        .find(|source| source.path.ends_with("auth.dae"))
        .unwrap()
        .content;
    assert!(!stored_auth.contains(SECRET));
    let moved = fixture.originals["main.dae"].replace("/state'", "/moved'");
    assert_ne!(moved, fixture.originals["main.dae"]);
    for (target, content) in [
        (main, moved),
        (
            auth,
            stored_auth.replace("enabled: true", "enabled: true\n record_logs: false"),
        ),
        (
            auth,
            stored_auth.replace("enabled: true", "enabled: true\n secret: 'another-token'"),
        ),
    ] {
        let response = fixture.replace(target, &content).send().await.unwrap();
        error(response, StatusCode::FORBIDDEN, "permission_denied").await;
    }
    assert_eq!(store.head(), Ok(Some(1)));
    assert_eq!(fixture.reloads.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}
