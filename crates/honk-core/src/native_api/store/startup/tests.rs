use std::fs;
use std::path::PathBuf;

use super::*;

fn tree(data_dir: &Path) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::write(
        root.join("config.dae"),
        format!(
            "include {{ 'auth.dae' }}\nglobal {{ data_dir: '{}' }}\nrouting {{ fallback: direct }}\n",
            data_dir.display()
        ),
    )
    .unwrap();
    fs::write(
        root.join("auth.dae"),
        "experimental { native_api { enabled: true\n secret: 'startup-token'\n config_write: true } }\n",
    )
    .unwrap();
    (directory, root.join("config.dae"))
}

#[test]
fn import_strips_secrets_and_a_later_start_reads_only_the_head() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (directory, entry) = tree(&data_dir);
    let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    assert!(
        startup
            .sources
            .sources
            .iter()
            .all(|source| !source.contains_api_secret && !source.content.contains("startup-token"))
    );
    assert_eq!(
        startup.config.experimental.native_api.secret,
        "startup-token"
    );
    startup.record().unwrap();
    let imported = startup.config.clone();
    drop(startup);
    drop(directory);

    let reopened = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    assert_eq!(reopened.config, imported);
    assert_eq!(reopened.store.head(), Ok(Some(1)));
}

#[test]
fn data_dir_mismatch_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir.join("elsewhere"));
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("mismatched data_dir must refuse startup");
    assert!(error.to_string().contains("--data-dir"), "{error}");
    let store = DbStore::open(&data_dir, &entry).unwrap();
    assert_eq!(store.head(), Ok(None));
}

#[test]
fn secret_copy_in_a_comment_refuses_import() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    let mut main = fs::read_to_string(&entry).unwrap();
    main.push_str("# old startup-token copied here\n");
    fs::write(&entry, main).unwrap();
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a secret copy must refuse the import");
    assert!(error.to_string().contains("copies"), "{error}");
}

#[test]
fn head_moved_before_the_instance_lock_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .unwrap()
        .record()
        .unwrap();
    let mut waiting = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
    let running = DbStore::open(&data_dir, &entry).unwrap();
    let pin = running.pin(running.entry()).unwrap();
    let mut candidate = waiting.sources.sources.clone();
    let content = format!("{}# edited\n", candidate[0].content);
    candidate[0].content = Arc::from(content.as_str());
    let pending = running
        .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap();
    assert_eq!(running.promote(pending), Ok(2));
    let error = waiting.record().expect_err("a moved head must refuse");
    assert!(error.to_string().contains("moved"), "{error}");
}

const CONTROLLER: &str = "clash_api { external_controller: '127.0.0.1:9090' }\n native_api {";

#[test]
fn clash_controller_refuses_the_import() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (directory, entry) = tree(&data_dir);
    let auth = directory.path().canonicalize().unwrap().join("auth.dae");
    let content = fs::read_to_string(&auth).unwrap();
    fs::write(&auth, content.replace("native_api {", CONTROLLER)).unwrap();
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a Clash controller must refuse the import");
    assert!(
        error.to_string().contains("without the Clash API"),
        "{error}"
    );
    let store = DbStore::open(&data_dir, &entry).unwrap();
    assert_eq!(store.head(), Ok(None));
}

#[test]
fn clash_controller_in_the_head_refuses_startup() {
    let state = tempfile::tempdir().unwrap();
    let data_dir = state.path().canonicalize().unwrap();
    let (_directory, entry) = tree(&data_dir);
    let startup = {
        let mut startup = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new()).unwrap();
        startup.record().unwrap();
        startup
    };
    let mut candidate = startup.sources.sources.clone();
    drop(startup);
    let store = DbStore::open(&data_dir, &entry).unwrap();
    let auth = candidate
        .iter_mut()
        .find(|source| source.path.ends_with("auth.dae"))
        .unwrap();
    let pin = store.pin(&auth.path).unwrap();
    let content = auth.content.replace("native_api {", CONTROLLER);
    auth.content = Arc::from(content.as_str());
    let pending = store
        .commit(pin, &content, &candidate, "control", Box::new(|| Ok(())))
        .unwrap();
    assert_eq!(store.promote(pending), Ok(2));
    drop(store);
    let error = DatabaseStartup::open(&entry, &data_dir, &mut Vec::new())
        .err()
        .expect("a head with a Clash controller must refuse startup");
    assert!(
        error.to_string().contains("without the Clash API"),
        "{error}"
    );
}
