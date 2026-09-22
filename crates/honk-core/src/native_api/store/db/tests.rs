use std::fs;

use honk_config::parser::{SourceLimits, parse_dae_sources};

use super::*;

const MAIN: &str = "global { log_level: info }\nexperimental { native_api { enabled: true } }\n";

struct Fixture {
    _directory: tempfile::TempDir,
    data_dir: PathBuf,
    entry: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().join("data");
    fs::create_dir(&data_dir).unwrap();
    Fixture {
        entry: directory.path().join("etc/config.dae"),
        data_dir,
        _directory: directory,
    }
}

fn db_path(fixture: &Fixture) -> PathBuf {
    fixture.data_dir.join(CREDENTIAL_DIR).join(DB_FILE)
}

fn sources(entry: &Path, content: &str) -> Vec<SourceSnapshot> {
    parse_dae_sources(
        &[(entry.to_path_buf(), Arc::from(content))],
        SourceLimits::default(),
        &mut Vec::new(),
    )
    .unwrap()
    .sources
}

fn initialized(fixture: &Fixture) -> DbStore {
    let store = DbStore::open(&fixture.data_dir, &fixture.entry).unwrap();
    let main = sources(&fixture.entry, MAIN);
    let secrets = ListenerSecrets {
        native_api: "native-token".into(),
        clash_api: String::new(),
    };
    assert_eq!(
        store.initialize(&main, &MaskSet::new(&[], ""), &secrets, "startup"),
        Ok(1)
    );
    store
}

fn write(store: &DbStore, content: &str) -> Pending {
    let pin = store.pin(store.entry()).unwrap();
    let candidate = sources(store.entry(), content);
    store
        .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap()
}

#[test]
fn created_directory_and_file_are_private() {
    let fixture = fixture();
    let store = DbStore::open(&fixture.data_dir, &fixture.entry).unwrap();
    let directory = fs::metadata(fixture.data_dir.join(CREDENTIAL_DIR)).unwrap();
    let file = fs::symlink_metadata(db_path(&fixture)).unwrap();
    assert!(directory.is_dir() && file.is_file());
    assert_eq!(directory.permissions().mode() & 0o777, 0o700);
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    assert_eq!(store.head(), Ok(None));
    drop(store);

    let reopened = initialized(&fixture);
    drop(reopened);
    let store = DbStore::open(&fixture.data_dir, Path::new("/elsewhere/other.dae")).unwrap();
    assert_eq!(store.entry(), fixture.entry);
    let loaded = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.experimental.native_api.secret, "native-token");
    assert_eq!(loaded.config.global.log_level, "info");
}

#[test]
fn symlinked_database_is_refused() {
    let fixture = fixture();
    let directory = fixture.data_dir.join(CREDENTIAL_DIR);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let target = fixture.data_dir.join("target.db");
    fs::write(&target, b"").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, db_path(&fixture)).unwrap();
    assert_eq!(
        DbStore::open(&fixture.data_dir, &fixture.entry).err(),
        Some(StoreError::Unsafe)
    );
    assert_eq!(fs::read(&target).unwrap(), b"");
}

#[test]
fn group_readable_database_is_refused() {
    let fixture = fixture();
    drop(DbStore::open(&fixture.data_dir, &fixture.entry).unwrap());
    fs::set_permissions(db_path(&fixture), fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        DbStore::open(&fixture.data_dir, &fixture.entry).err(),
        Some(StoreError::Unsafe)
    );
}

#[test]
fn corrupt_database_is_refused_and_kept() {
    let fixture = fixture();
    drop(DbStore::open(&fixture.data_dir, &fixture.entry).unwrap());
    let garbage = vec![0x5a; 8192];
    fs::write(db_path(&fixture), &garbage).unwrap();
    assert_eq!(
        DbStore::open(&fixture.data_dir, &fixture.entry).err(),
        Some(StoreError::Corrupt)
    );
    assert_eq!(fs::read(db_path(&fixture)).unwrap(), garbage);
}

#[test]
fn foreign_or_newer_databases_are_refused() {
    for (application_id, version) in [(1, 0), (1, 1), (APPLICATION_ID, 2)] {
        let fixture = fixture();
        drop(DbStore::open(&fixture.data_dir, &fixture.entry).unwrap());
        fs::remove_file(db_path(&fixture)).unwrap();
        let connection = Connection::open(db_path(&fixture)).unwrap();
        connection
            .execute_batch(&format!(
                "CREATE TABLE other (x); PRAGMA application_id = {application_id}; PRAGMA user_version = {version};"
            ))
            .unwrap();
        drop(connection);
        fs::set_permissions(db_path(&fixture), fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            DbStore::open(&fixture.data_dir, &fixture.entry).err(),
            Some(StoreError::Unsupported),
            "{application_id} {version}"
        );
    }
}

#[test]
fn source_labels_resolve_lexically_inside_the_root() {
    let fixture = fixture();
    let store = DbStore::open(&fixture.data_dir, &fixture.entry).unwrap();
    let root = fixture.entry.parent().unwrap();
    assert_eq!(
        store.resolve("conf.d/a.dae").unwrap(),
        root.join("conf.d/a.dae")
    );
    assert_eq!(
        store.resolve(root.join("b.dae").to_str().unwrap()).unwrap(),
        root.join("b.dae")
    );
    assert_eq!(
        store.resolve("conf.d/./a.dae").unwrap(),
        root.join("conf.d/a.dae")
    );
    for label in [
        "../escape.dae",
        "/other/c.dae",
        "conf.d/../a.dae",
        "notes.txt",
        "",
    ] {
        assert!(store.resolve(label).is_err(), "{label}");
    }
}

#[test]
fn promote_on_a_moved_head_conflicts() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let first = write(&store, "global { log_level: debug }\n");
    let second = write(&store, "global { log_level: warn }\n");
    assert_eq!(store.promote(first), Ok(2));
    assert_eq!(store.promote(second), Err(WriteError::Conflict));
    assert_eq!(store.head(), Ok(Some(2)));

    let fixture = self::fixture();
    let store = initialized(&fixture);
    let pin = store.pin(store.entry()).unwrap();
    assert_eq!(store.promote(write(&store, "global {}\n")), Ok(2));
    let content = "global { log_level: error }\n";
    let candidate = sources(store.entry(), content);
    assert_eq!(
        store
            .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
            .err(),
        Some(WriteError::Conflict)
    );
}

#[test]
fn candidates_with_listener_secrets_are_not_recorded() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let pin = store.pin(store.entry()).unwrap();
    let content = "experimental { native_api { secret: 'leaked' } }\n";
    let candidate = sources(store.entry(), content);
    assert_eq!(
        store
            .commit(pin, content, &candidate, "control", Box::new(|| Ok(())))
            .err(),
        Some(WriteError::UnsafePath)
    );
}

#[test]
fn retention_keeps_fifty_revisions_and_the_active_one() {
    let fixture = fixture();
    let store = initialized(&fixture);
    for index in 0..55 {
        let number = store
            .promote(write(
                &store,
                &format!("global {{ tproxy_port: {} }}\n", 20000 + index),
            ))
            .unwrap();
        assert_eq!(number, index + 2);
    }
    let connection = store.connection.lock();
    let (count, oldest): (i64, i64) = connection
        .query_row("SELECT count(*), min(number) FROM revision", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!((count, oldest), (MAX_REVISIONS as i64, 7));
    let parent: Option<i64> = connection
        .query_row("SELECT parent FROM revision WHERE number = 7", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(parent, None);
    assert_eq!(head(&connection), Ok(Some(56)));
    drop(connection);
    let loaded = store.load(&HashMap::new(), &mut Vec::new()).unwrap();
    assert_eq!(loaded.config.global.tproxy_port, 20054);
}

#[test]
fn cli_export_restores_secrets_into_a_new_private_file() {
    let fixture = fixture();
    let store = initialized(&fixture);
    let out = fixture.data_dir.join("export.dae");
    export_to(&fixture.data_dir, &out, true).unwrap();
    assert_eq!(
        fs::symlink_metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(&out).unwrap();
    let exported = honk_config::parser::parse_dae_config(&text).unwrap();
    exported.validate().unwrap();
    assert_eq!(exported.experimental.native_api.secret, "native-token");
    assert_eq!(
        exported,
        store.load(&HashMap::new(), &mut Vec::new()).unwrap().config
    );

    let bare = fixture.data_dir.join("bare.dae");
    export_to(&fixture.data_dir, &bare, false).unwrap();
    let text = fs::read_to_string(&bare).unwrap();
    assert!(text.starts_with("# listener secrets omitted\n"));
    assert!(!text.contains("native-token"));

    fs::write(&out, "kept").unwrap();
    assert!(export_to(&fixture.data_dir, &out, true).is_err());
    assert_eq!(fs::read_to_string(&out).unwrap(), "kept");
    assert!(fs::read_dir(&fixture.data_dir).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    assert_eq!(store.head(), Ok(Some(1)));
}

#[test]
fn head_cache_and_existence_follow_promote() {
    let fixture = fixture();
    let store = initialized(&fixture);
    assert_eq!(store.cached_head(), Some((1, None)));
    let pending = write(&store, "global { log_level: debug }\n");
    assert_eq!(store.promote(pending), Ok(2));
    assert_eq!(store.cached_head(), Some((2, Some(1))));
    assert_eq!(store.revision_exists(1), Ok(true));
    assert_eq!(store.revision_exists(9), Ok(false));
}
