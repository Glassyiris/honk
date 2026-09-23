use super::*;

fn member(name: &str) -> SelectorMember {
    SelectorMember::Group(name.to_owned())
}

#[test]
fn selector_and_clash_state_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    assert!(
        db.load_network_selector("proxy", SelectionNetwork::Tcp)
            .is_none()
    );
    db.save_network_selector("proxy", SelectionNetwork::Tcp, &member("a"));
    db.save_network_selector("proxy", SelectionNetwork::Udp, &member("b"));
    db.save_clash_mode("Global");
    db.save_clash_global("proxy");
    db.flush_pending().unwrap();
    drop(db);

    let db = CacheDb::in_dir(directory.path());
    for (network, expected) in [(SelectionNetwork::Tcp, "a"), (SelectionNetwork::Udp, "b")] {
        assert_eq!(
            db.load_network_selector("proxy", network).unwrap().unwrap(),
            member(expected)
        );
    }
    assert_eq!(db.load_clash_mode().as_deref(), Some("Global"));
    assert_eq!(db.load_clash_global().as_deref(), Some("proxy"));
}

#[test]
fn point_writes_are_latest_wins_without_blocking_readers() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(CacheDb::in_dir(directory.path()));
    let writer = Arc::clone(&db);
    let worker = std::thread::spawn(move || {
        for value in 0..10_000 {
            writer.save_clash_global(&value.to_string());
        }
    });
    for _ in 0..10_000 {
        let _ = db.load_clash_global();
    }
    worker.join().unwrap();
    assert_eq!(db.load_clash_global().as_deref(), Some("9999"));
}

#[test]
fn point_save_does_not_wait_for_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(CacheDb::in_dir(directory.path()));
    let writer_guard = db.lock_for_test();
    let (completed, completion) = mpsc::channel();
    let saving = Arc::clone(&db);
    let worker = std::thread::spawn(move || {
        saving.save_clash_global("node-a");
        completed.send(()).unwrap();
    });

    completion
        .recv_timeout(std::time::Duration::from_millis(100))
        .expect("point save must not wait for SQLite");
    assert_eq!(db.load_clash_global().as_deref(), Some("node-a"));
    drop(writer_guard);
    worker.join().unwrap();
    db.flush_pending().unwrap();
}

#[test]
fn periodic_flush_bounds_point_write_durability() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    db.save_clash_mode("Direct");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let stored = db
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT value FROM clash_state WHERE key = 'mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok();
        if stored.as_deref() == Some("Direct") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "periodic flush exceeded durability bound"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn delay_sample_save_load_and_age_out() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let now = 1_700_000_000u64;

    db.save_delay_samples(vec![
        ("node-a".into(), 123, now - 60),
        ("node-old".into(), 456, now - 25 * 3600),
    ]);
    db.flush_pending().unwrap();
    let barrier = |db: &CacheDb| db.request(Write::Barrier).unwrap();
    barrier(&db);

    let samples = db.load_delay_samples(now, 24 * 3600);
    assert_eq!(samples, [("node-a".to_string(), 123, now - 60)]);
    barrier(&db);
    let rows: i64 = db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM delay_sample", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 1, "the stale sample is deleted");
}

#[test]
fn dns_rows_write_load_and_flush_without_touching_other_tables() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    db.save_clash_global("proxy");
    db.write_dns(vec![("opaque".into(), 1_000, vec![0, 255, 1])])
        .unwrap();
    assert_eq!(db.load_dns().unwrap(), [("opaque".into(), vec![0, 255, 1])]);
    db.delete_dns_entries(&["other".into()]).unwrap();
    assert_eq!(db.load_dns().unwrap().len(), 1);

    db.flush_dns().unwrap();
    assert!(db.load_dns().unwrap().is_empty());
    assert_eq!(db.load_clash_global().as_deref(), Some("proxy"));
}

#[test]
fn sqlite_errors_carry_only_the_result_code() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let error = db
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO clash_state (key, value) VALUES ('secret-key', 'secret-value')",
            [],
        )
        .unwrap_err();
    let text = CacheDbError::from(error).to_string();
    assert!(
        text.contains(&rusqlite::ffi::SQLITE_CONSTRAINT_CHECK.to_string()),
        "{text}"
    );
    assert!(
        !text.contains("secret") && !text.contains("CHECK"),
        "{text}"
    );
}

#[test]
fn an_idle_cache_does_not_wake_the_flusher() {
    let directory = tempfile::tempdir().unwrap();
    let db = CacheDb::in_dir(directory.path());
    let wakeups = || db.flush.wakeups.load(std::sync::atomic::Ordering::Relaxed);
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(wakeups(), 0, "the flusher woke with nothing pending");

    db.save_clash_mode("Direct");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while db
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM clash_state", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
        == 0
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the write was not flushed"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(wakeups(), 1, "one write, one wakeup");
}
