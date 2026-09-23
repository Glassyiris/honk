use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn pbkdf2_sha256_matches_independent_vectors() {
    // RFC 6070 inputs with HMAC-SHA256 (the values published for PBKDF2-HMAC-SHA256 test suites).
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 1)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 2)),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
    assert_eq!(
        hex(&pbkdf2_sha256(b"password", b"salt", 4096)),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
    // A key longer than the SHA-256 block is hashed first by HMAC; the derivation must still agree.
    let long = [b'p'; 100];
    assert_ne!(
        pbkdf2_sha256(&long, b"salt", 2),
        pbkdf2_sha256(&long[..99], b"salt", 2)
    );
    assert_eq!(
        pbkdf2_sha256("密碼 pässwörd".as_bytes(), b"salt", 3),
        pbkdf2_sha256("密碼 pässwörd".as_bytes(), b"salt", 3)
    );
}

#[test]
fn record_round_trips_and_verifies_in_constant_shape() {
    let record = Record::create("admin", "correct horse battery").unwrap();
    assert!(record.verify("admin", "correct horse battery"));
    assert!(!record.verify("admin", "correct horse batterx"));
    assert!(!record.verify("admin2", "correct horse battery"));
    let json = record.to_json();
    assert_eq!(Record::from_json(&json).unwrap(), record);
    assert!(Record::create("bad name", "correct horse battery").is_none());
    assert!(Record::create("admin", "short").is_none());
}

#[test]
fn passwords_are_eight_to_128_characters() {
    assert!(!valid_password("7 chars"));
    assert!(valid_password("8 chars!"));
    assert!(valid_password(&"x".repeat(128)));
    assert!(!valid_password(&"x".repeat(129)));
    // Counted in Unicode scalar values, so eight CJK characters are enough.
    assert!(valid_password("八個字元的密碼好"));
}

#[test]
fn record_parsing_rejects_unknown_shapes() {
    let mut json: serde_json::Value = serde_json::from_slice(
        &Record::create("a", "correct horse battery")
            .unwrap()
            .to_json(),
    )
    .unwrap();
    let ok = json.clone();
    json["iterations"] = serde_json::json!(4096);
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["algorithm"] = serde_json::json!("argon2id");
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["extra"] = serde_json::json!(1);
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    let mut json = ok.clone();
    json["salt"] = serde_json::json!("AAAA");
    assert_eq!(
        Record::from_json(json.to_string().as_bytes()),
        Err(StoreError::Corrupt)
    );
    assert!(Record::from_json(ok.to_string().as_bytes()).is_ok());
}

fn temp_data_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn store_in(data: &Path) -> CredentialStore {
    CredentialStore::open(Arc::new(StateDb::open(data).unwrap()), data).unwrap()
}

fn admin_rows(data: &Path) -> i64 {
    StateDb::open(data)
        .unwrap()
        .strict()
        .query_row("SELECT count(*) FROM admin", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn setup_publishes_one_durable_account() {
    let data = temp_data_dir();
    let store = store_in(data.path());
    assert!(store.setup_required());
    assert!(!store.verify("admin", "correct horse battery"));
    store.setup("admin", "correct horse battery").unwrap();
    assert!(!store.setup_required());
    assert!(store.verify("admin", "correct horse battery"));
    assert_eq!(
        store.setup("other", "correct horse battery"),
        Err(SetupError::AlreadyCompleted)
    );
    assert_eq!(admin_rows(data.path()), 1);
    drop(store);
    // A fresh process reads the same account back.
    let reopened = store_in(data.path());
    assert!(!reopened.setup_required());
    assert!(reopened.verify("admin", "correct horse battery"));
}

#[test]
fn two_stores_racing_setup_yield_one_winner() {
    let data = temp_data_dir();
    let stores: Vec<_> = (0..2).map(|_| Arc::new(store_in(data.path()))).collect();
    let results: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(index, store)| {
            let store = Arc::clone(store);
            std::thread::spawn(move || {
                store.setup(&format!("admin{index}"), "correct horse battery")
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.contains(&Err(SetupError::AlreadyCompleted)));
    assert_eq!(admin_rows(data.path()), 1);
}

#[test]
fn a_failed_write_blocks_the_store() {
    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let store = CredentialStore::open(Arc::clone(&db), data.path()).unwrap();
    // The INSERT itself fails, after the transaction started.
    db.strict()
        .execute_batch(
            "CREATE TEMP TRIGGER refuse BEFORE INSERT ON admin BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::NotDurable)
    );
    db.strict().execute_batch("DROP TRIGGER refuse").unwrap();
    assert!(!store.verify("admin", "correct horse battery"));
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::AlreadyCompleted)
    );
}

fn legacy_record(data: &Path) -> std::path::PathBuf {
    let dir = data.join(LEGACY_DIR);
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join(LEGACY_RECORD);
    std::fs::write(
        &file,
        Record::create("legacy", "correct horse battery")
            .unwrap()
            .to_json(),
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    file
}

#[test]
fn a_legacy_record_is_imported_and_removed_only_by_the_credential_store() {
    let data = temp_data_dir();
    let file = legacy_record(data.path());
    // File mode without password_auth opens the state db and leaves it alone.
    drop(StateDb::open(data.path()).unwrap());
    assert!(file.exists());

    let store = store_in(data.path());
    assert!(store.verify("legacy", "correct horse battery"));
    assert!(!file.exists());
    assert!(!data.path().join(LEGACY_DIR).exists());
}

#[test]
fn an_unsafe_legacy_directory_or_record_fails_closed() {
    let data = temp_data_dir();
    let file = legacy_record(data.path());
    let dir = data.path().join(LEGACY_DIR);
    let open =
        || CredentialStore::open(Arc::new(StateDb::open(data.path()).unwrap()), data.path()).err();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(open(), Some(StoreError::Unsafe));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(open(), Some(StoreError::Unsafe));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&file, b"{}").unwrap();
    assert_eq!(open(), Some(StoreError::Corrupt));
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(data.path().join("elsewhere"), &file).unwrap();
    assert_eq!(open(), Some(StoreError::Unsafe));
    assert_eq!(admin_rows(data.path()), 0);
}

#[test]
fn reset_refuses_while_a_daemon_has_the_db_open() {
    let data = temp_data_dir();
    let db = Arc::new(StateDb::open(data.path()).unwrap());
    let store = CredentialStore::open(Arc::clone(&db), data.path()).unwrap();
    store.setup("admin", "correct horse battery").unwrap();
    assert_eq!(
        crate::state::reset_admin(data.path()),
        Err(crate::state::StateError::InUse)
    );
    drop(store);
    drop(db);
    assert_eq!(crate::state::reset_admin(data.path()), Ok(true));
    assert!(store_in(data.path()).setup_required());
}

#[test]
fn session_expiry_revocation_and_capacity() {
    let sessions = Sessions::default();
    let now = Instant::now();
    let issued = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    assert!(issued.token.starts_with(TOKEN_PREFIX));
    assert_eq!(issued.expires_at, SystemTime::UNIX_EPOCH + SESSION_LIFETIME);
    assert!(sessions.authenticate_at(&issued.token, now));
    assert!(sessions.authenticate_at(
        &issued.token,
        now + SESSION_LIFETIME - Duration::from_secs(1)
    ));
    assert!(!sessions.authenticate_at(&issued.token, now + SESSION_LIFETIME));
    assert!(!sessions.authenticate_at("hnk1_nope", now));
    assert!(!sessions.authenticate_at(&issued.token[1..], now));
    assert!(sessions.revoke(&issued.token));
    assert!(!sessions.revoke(&issued.token));
    assert!(!sessions.authenticate_at(&issued.token, now));
    let first = sessions.issue_at(now, SystemTime::UNIX_EPOCH);
    for i in 0..SESSION_LIMIT {
        sessions.issue_at(
            now + Duration::from_secs(i as u64 + 1),
            SystemTime::UNIX_EPOCH,
        );
    }
    assert_eq!(sessions.len(), SESSION_LIMIT);
    assert!(
        !sessions.authenticate_at(&first.token, now),
        "the oldest session is evicted"
    );
    let fresh = Sessions::default();
    assert!(
        !fresh.authenticate_at(&first.token, now),
        "a new process knows no session"
    );
}

#[test]
fn admission_bounds_attempts_per_peer_and_overall() {
    let rate = AuthRate::default();
    let now = Instant::now();
    let a: std::net::IpAddr = "10.0.0.2".parse().unwrap();
    let b: std::net::IpAddr = "10.0.0.3".parse().unwrap();
    for _ in 0..PEER_ATTEMPTS {
        assert_eq!(rate.admit_at(a, now), None);
    }
    assert!(rate.admit_at(a, now).is_some(), "the peer window closes");
    assert_eq!(
        rate.admit_at(b, now),
        None,
        "another peer has its own window"
    );
    // The global window closes after ten attempts however many peers there are.
    for i in 0..4 {
        let peer: std::net::IpAddr = format!("10.0.1.{i}").parse().unwrap();
        assert_eq!(rate.admit_at(peer, now), None);
    }
    let fresh: std::net::IpAddr = "10.0.2.1".parse().unwrap();
    assert!(
        rate.admit_at(fresh, now).is_some(),
        "the global window closes"
    );
    // Both windows reopen after a minute.
    assert_eq!(rate.admit_at(a, now + Duration::from_secs(61)), None);
}

#[test]
fn repeated_credential_failures_lock_logins_briefly() {
    let rate = AuthRate::default();
    let now = Instant::now();
    let peer: std::net::IpAddr = "192.168.1.5".parse().unwrap();
    for _ in 0..FAILURES_BEFORE_LOCK {
        rate.failed_at(now);
    }
    let wait = rate.admit_at(peer, now).expect("locked");
    assert!(wait <= LOCK.as_secs() as u32 && wait > 0);
    assert!(
        rate.admit_at(peer, now + LOCK).is_none(),
        "the lock expires"
    );
    rate.failed_at(now + LOCK);
    rate.succeeded();
    assert!(
        rate.admit_at(peer, now + LOCK).is_none(),
        "a success clears the count"
    );
}

#[test]
fn setup_peers_are_loopback_or_private_only() {
    use crate::native_api::{Peer, canonical_ip};
    let allow = [
        "127.0.0.1",
        "::1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.1.1",
        "fd00::1",
        "fe80::1",
    ];
    let deny = [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "100.64.0.1",
        "2001:db8::1",
        "fec0::1",
        "0.0.0.0",
        "224.0.0.1",
    ];
    for ip in allow {
        assert!(
            Peer(canonical_ip(ip.parse().unwrap())).may_set_up(),
            "{ip} may set up"
        );
    }
    for ip in deny {
        assert!(
            !Peer(canonical_ip(ip.parse().unwrap())).may_set_up(),
            "{ip} may not set up"
        );
    }
    // An IPv4-mapped peer is judged as the IPv4 address it carries.
    assert!(Peer(canonical_ip("::ffff:10.0.0.1".parse().unwrap())).may_set_up());
    assert!(!Peer(canonical_ip("::ffff:8.8.8.8".parse().unwrap())).may_set_up());
}

#[test]
fn reset_also_removes_a_legacy_record_never_imported() {
    let data = temp_data_dir();
    drop(StateDb::open(data.path()).unwrap());
    let file = legacy_record(data.path());
    assert_eq!(crate::state::reset_admin(data.path()), Ok(true));
    assert!(!file.exists());
    assert!(store_in(data.path()).setup_required());
}

#[test]
fn a_busy_db_leaves_setup_available() {
    let data = temp_data_dir();
    let store = store_in(data.path());
    let holder = StateDb::open(data.path()).unwrap();
    let mut connection = holder.strict();
    let busy = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(
        store.setup("admin", "correct horse battery"),
        Err(SetupError::Unavailable)
    );
    drop(busy);
    drop(connection);
    store.setup("admin", "correct horse battery").unwrap();
    assert!(store.verify("admin", "correct horse battery"));
}

#[test]
fn reset_removes_a_legacy_record_before_any_state_db_exists() {
    let data = temp_data_dir();
    let file = legacy_record(data.path());
    assert_eq!(crate::state::reset_admin(data.path()), Ok(true));
    assert!(!file.exists());
    assert!(!data.path().join(crate::state::STATE_DIR).exists());
    assert_eq!(crate::state::reset_admin(data.path()), Ok(false));
}

#[test]
fn reset_on_a_db_without_its_schema_still_removes_a_legacy_record() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let data = temp_data_dir();
    let state = data.path().join(crate::state::STATE_DIR);
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A first start that stopped between creating the file and its schema.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join(crate::state::DB_FILE))
        .unwrap();
    let file = legacy_record(data.path());
    assert_eq!(crate::state::reset_admin(data.path()), Ok(true));
    assert!(!file.exists());
}
