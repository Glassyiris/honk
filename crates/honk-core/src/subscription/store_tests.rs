use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown, symlink};

use super::*;

#[tokio::test]
async fn store_keeps_opened_directory_after_path_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let retained = temp.path().join("retained");
    let store = SubscriptionStore::open(root.clone()).unwrap();
    let subscription = Subscription {
        url: "https://example.invalid/subscription".into(),
        ..Default::default()
    };
    store
        .store_content(&subscription, "socks5://127.0.0.1:1080#original".into())
        .await
        .unwrap();
    let filename = store
        .path_for(&subscription)
        .file_name()
        .unwrap()
        .to_owned();
    fs::rename(&root, &retained).unwrap();
    fs::create_dir(&root).unwrap();
    let injected = "socks5://127.0.0.1:1081#injected";
    fs::write(root.join(&filename), injected).unwrap();

    let nodes = store.load_nodes(&subscription).await.unwrap().unwrap();
    assert_eq!(nodes[0].name, "original");
    store
        .store_content(&subscription, "socks5://127.0.0.1:1082#updated".into())
        .await
        .unwrap();
    assert_eq!(fs::read_to_string(root.join(&filename)).unwrap(), injected);
    assert_eq!(
        fs::read_to_string(retained.join(&filename)).unwrap(),
        "socks5://127.0.0.1:1082#updated"
    );
}

#[tokio::test]
async fn store_rejects_cache_body_writable_by_other_users() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join("store")).unwrap();
    let subscription = Subscription::default();
    store
        .store_content(&subscription, "socks5://127.0.0.1:1080#untrusted".into())
        .await
        .unwrap();
    let path = store.path_for(&subscription);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

    assert!(store.load_nodes(&subscription).await.is_err());
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o666
    );
}

#[test]
fn store_rejects_symlink_directory() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let link = temp.path().join(SUBSCRIPTION_STORE_DIR);
    symlink(target, &link).unwrap();
    assert!(SubscriptionStore::open(link).is_err());
}

#[tokio::test]
async fn store_skips_writable_legacy_directory_without_chmod() {
    let temp = tempfile::tempdir().unwrap();
    let preferred = temp.path().join("preferred");
    let writable = temp.path().join("writable");
    let secure = temp.path().join("secure");
    let subscription = Subscription::default();
    let retained = SubscriptionStore::open(secure.clone()).unwrap();
    retained
        .store_content(&subscription, "socks5://127.0.0.1:1080#retained".into())
        .await
        .unwrap();
    fs::create_dir(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();

    let store =
        SubscriptionStore::open_with_legacy(preferred.clone(), [writable.clone(), secure.clone()])
            .unwrap();
    assert_eq!(
        store.load_nodes(&subscription).await.unwrap().unwrap()[0].name,
        "retained"
    );
    assert_eq!(store.root(), secure);
    assert_eq!(
        fs::metadata(writable).unwrap().permissions().mode() & 0o7777,
        0o777
    );
    assert!(!preferred.exists());
}

#[tokio::test]
async fn store_reads_private_cache_without_chmod() {
    let temp = tempfile::tempdir().unwrap();
    let store = SubscriptionStore::open(temp.path().join("store")).unwrap();
    let subscription = Subscription::default();
    store
        .store_content(&subscription, "socks5://127.0.0.1:1080#stored".into())
        .await
        .unwrap();
    let path = store.path_for(&subscription);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        store.load_nodes(&subscription).await.unwrap().unwrap()[0].name,
        "stored"
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o7777,
        0o400
    );
}

#[tokio::test]
#[ignore = "requires root to create foreign-owned fixtures"]
async fn store_rejects_foreign_owners_without_chmod() {
    // SAFETY: geteuid has no arguments or memory-safety preconditions.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "this ignored test requires root"
    );
    let temp = tempfile::tempdir().unwrap();

    let foreign_directory = temp.path().join("foreign-directory");
    fs::create_dir(&foreign_directory).unwrap();
    fs::set_permissions(&foreign_directory, fs::Permissions::from_mode(0o755)).unwrap();
    chown(&foreign_directory, Some(1), None).unwrap();
    assert!(SubscriptionStore::open(foreign_directory.clone()).is_err());
    let metadata = fs::metadata(&foreign_directory).unwrap();
    assert_eq!(metadata.uid(), 1);
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);

    let store = SubscriptionStore::open(temp.path().join("store")).unwrap();
    let subscription = Subscription::default();
    store
        .store_content(&subscription, "socks5://127.0.0.1:1080#foreign".into())
        .await
        .unwrap();
    let path = store.path_for(&subscription);
    chown(&path, Some(1), None).unwrap();
    assert!(store.load_nodes(&subscription).await.is_err());
    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.uid(), 1);
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
}
