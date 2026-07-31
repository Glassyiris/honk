use super::*;

#[tokio::test]
async fn set_forwarder_does_not_wait_for_resolve_and_notify_exchange() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 1],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    }));
    let controller = snapshot_controller(old);
    let query = crate::dns::forwarder::build_dns_query("example.com", 1);
    let running = {
        let controller = controller.clone();
        let query = query.clone();
        tokio::spawn(async move {
            controller
                .resolve_and_notify(&query, None, crate::dns::query::IngressProfile::Internal)
                .await
        })
    };
    entered.notified().await;
    let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [198, 51, 100, 2],
        calls: AtomicUsize::new(0),
        entered: None,
        release: None,
    }));

    let publication = tokio::time::timeout(
        Duration::from_millis(100),
        publish_snapshot_forwarder(&controller, new),
    )
    .await;
    if publication.is_err() {
        release.notify_waiters();
        let _ = running.await;
        panic!("set_forwarder waited for the old upstream exchange");
    }
    assert!(!running.is_finished(), "old query must remain paused");
    release.notify_waiters();
    let (old_response, _) = running.await.expect("old query task");
    let (new_response, _) = controller
        .resolve_and_notify(&query, None, crate::dns::query::IngressProfile::Internal)
        .await;

    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&old_response),
        ["192.0.2.1".parse::<std::net::IpAddr>().expect("old IP")]
    );
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&new_response),
        ["198.51.100.2".parse::<std::net::IpAddr>().expect("new IP")]
    );
}

#[tokio::test]
async fn resolve_domain_keeps_old_snapshot_without_blocking_publication() {
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let old = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [192, 0, 2, 3],
        calls: AtomicUsize::new(0),
        entered: Some(entered.clone()),
        release: Some(release.clone()),
    }));
    let controller = snapshot_controller(old);
    let running = {
        let controller = controller.clone();
        tokio::spawn(async move { controller.resolve_domain("example.com").await })
    };
    entered.notified().await;
    let new = snapshot_forwarder(Arc::new(SnapshotUpstream {
        ip: [198, 51, 100, 4],
        calls: AtomicUsize::new(0),
        entered: None,
        release: None,
    }));

    let publication = tokio::time::timeout(
        Duration::from_millis(100),
        publish_snapshot_forwarder(&controller, new),
    )
    .await;
    if publication.is_err() {
        release.notify_waiters();
        let _ = running.await;
        panic!("set_forwarder waited for resolve_domain");
    }
    assert!(!running.is_finished(), "old lookup must remain paused");
    release.notify_waiters();
    let old_ips = running.await.expect("old lookup task");
    let new_ips = controller.resolve_domain("example.com").await;

    assert_eq!(
        old_ips,
        ["192.0.2.3".parse::<std::net::IpAddr>().expect("old IP")]
    );
    assert_eq!(
        new_ips,
        ["198.51.100.4".parse::<std::net::IpAddr>().expect("new IP")]
    );
}
