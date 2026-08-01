use super::*;

#[tokio::test(start_paused = true)]
async fn same_generation_interleaving_converges_exact_mock_value() {
    for _ in 0..10 {
        let (projection, mut receiver, ebpf) = projection_for_test(snapshot(1, 1, 2));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30));
        projection.submit(
            snapshot(1, 1, 2),
            positive("a.test", &[ip], Duration::from_secs(30)),
        );
        receiver.try_recv().expect("initial wake");
        worker::flush_for_test_after_snapshot(&projection, &ebpf, || {
            projection.submit(
                snapshot(1, 1, 2),
                positive("b.test", &[ip], Duration::from_secs(30)),
            );
        })
        .await;
        receiver.try_recv().expect("new desired state wake");
        worker::flush_for_test(&projection, &ebpf).await;

        assert!(projection.state.lock().dirty_ips.is_empty());
        assert_eq!(
            ebpf.read().await.projection_map_snapshot()[0].1.bitmap,
            [3, 0, 0, 0, 0, 0, 0, 0]
        );
    }
    println!("INTERLEAVING_CONVERGED repetitions=10 bitmap=[3, 0, 0, 0] dirty=0");
}

#[tokio::test(start_paused = true)]
async fn stale_remove_is_repaired_by_new_same_generation_owner() {
    let now = tokio::time::Instant::now();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
    let mut state = DesiredState::new(snapshot(1, 1, 2), 10_000);
    let mut backend = MockEbpfBackend::new();
    let key = maps::cidr_to_lpm_key("203.0.113.31/32").expect("test IP");
    state.observe(positive("a.test", &[ip], Duration::from_secs(30)), now);
    let initial = state.batch(now);
    backend
        .set_domain_ip_bitmap(&key, &initial.sets[0].bitmap)
        .expect("initial write");
    assert!(state.commit_success(initial.generation, &initial.sets, &[]));

    state.observe(ProjectionObservation::Clear { domain: "a.test" }, now);
    let stale_remove = state.batch(now);
    state.observe(positive("b.test", &[ip], Duration::from_secs(30)), now);
    backend.remove_domain_ip_bitmap(&key).expect("stale remove");
    assert!(!state.commit_success(stale_remove.generation, &[], &stale_remove.removes));

    let repaired = state.batch(now);
    backend
        .set_domain_ip_bitmap(&key, &repaired.sets[0].bitmap)
        .expect("repair write");
    assert!(state.commit_success(repaired.generation, &repaired.sets, &repaired.removes));
    assert!(state.dirty_ips.is_empty());
    assert_eq!(
        backend.projection_map_snapshot()[0].1.bitmap,
        [2, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[tokio::test(start_paused = true)]
async fn wake_overflow_is_harmless_and_latest_state_converges() {
    let (projection, _receiver, ebpf) = projection_for_test(snapshot(1, 1, 2));
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    for _ in 0..32 {
        projection.submit(
            snapshot(1, 1, 2),
            positive("a.test", &[ip], Duration::from_secs(30)),
        );
    }
    assert!(projection.counters().wake_coalesced > 0);
    worker::flush_for_test(&projection, &ebpf).await;
    let map = ebpf.read().await.projection_map_snapshot();
    assert_eq!(map.len(), 1);
    assert_eq!(map[0].1.bitmap, [1, 0, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn set_and_map_full_failures_keep_dirty_until_retry() {
    let before = crate::stats::dns_snapshot();
    for map_full in [false, true] {
        let (projection, _receiver, ebpf) = projection_for_test(snapshot(1, 1, 2));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        ebpf.write()
            .await
            .inject_projection_fault(ProjectionMapOperation::Set, 1, map_full)
            .expect("fault injection");
        projection.submit(
            snapshot(1, 1, 2),
            positive("a.test", &[ip], Duration::from_secs(30)),
        );
        worker::flush_for_test(&projection, &ebpf).await;
        assert!(ebpf.read().await.projection_map_snapshot().is_empty());
        tokio::time::advance(Duration::from_millis(100)).await;
        worker::flush_for_test(&projection, &ebpf).await;
        assert_eq!(ebpf.read().await.projection_map_snapshot().len(), 1);
        assert_eq!(projection.counters().write_failures, 1);
        assert_eq!(projection.counters().map_full, u64::from(map_full));
    }
    let delta = crate::stats::dns_snapshot().delta(before);
    assert!(delta.projection_write_failure >= 2);
    assert!(delta.projection_retry >= 2);
    println!("TYPED_MAP_FULL_COUNTER generic=0 map_full=1");
}

#[tokio::test(start_paused = true)]
async fn changed_entry_is_written_before_obsolete_entry_is_deleted_and_delete_retries() {
    let (projection, _receiver, ebpf) = projection_for_test(snapshot(1, 1, 2));
    let old_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
    let new_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
    projection.submit(
        snapshot(1, 1, 2),
        positive("a.test", &[old_ip], Duration::from_secs(30)),
    );
    worker::flush_for_test(&projection, &ebpf).await;
    ebpf.write().await.clear_projection_write_log();
    ebpf.write()
        .await
        .inject_projection_fault(ProjectionMapOperation::Remove, 1, false)
        .expect("fault injection");
    projection.submit(
        snapshot(1, 1, 2),
        positive("a.test", &[new_ip], Duration::from_secs(30)),
    );
    worker::flush_for_test(&projection, &ebpf).await;
    assert_eq!(
        ebpf.read().await.projection_write_log(),
        vec![ProjectionMapOperation::Set, ProjectionMapOperation::Remove]
    );
    assert_eq!(ebpf.read().await.projection_map_snapshot().len(), 2);
    tokio::time::advance(Duration::from_millis(100)).await;
    worker::flush_for_test(&projection, &ebpf).await;
    let map = ebpf.read().await.projection_map_snapshot();
    assert_eq!(map.len(), 1);
    let expected = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("203.0.113.4/32").expect("test IP"));
    assert_eq!(map[0].0, expected);
}

#[tokio::test(start_paused = true)]
async fn spawned_worker_converges_mock_map_after_transient_failure() {
    let ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
        Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
    ebpf.write()
        .await
        .inject_projection_fault(ProjectionMapOperation::Set, 1, false)
        .expect("fault injection");
    let current = snapshot(7, 1, 2);
    let projection = RoutingProjection::spawn(Arc::clone(&ebpf), Arc::clone(&current));
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    projection.submit(current, positive("a.test", &[ip], Duration::from_secs(30)));
    tokio::task::yield_now().await;
    assert!(ebpf.read().await.projection_map_snapshot().is_empty());
    tokio::time::advance(Duration::from_millis(100)).await;
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let map = ebpf.read().await.projection_map_snapshot();
    assert_eq!(map.len(), 1);
    assert_eq!(map[0].1.bitmap, [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(projection.counters().write_failures, 1);
    println!(
        "MOCK_CONVERGED entries={} bitmap={:?} write_failures={}",
        map.len(),
        map[0].1.bitmap,
        projection.counters().write_failures
    );
    projection.shutdown().await;
}

#[tokio::test]
async fn shutdown_is_idempotent_and_awaits_worker_termination() {
    for _ in 0..10 {
        // Given
        let ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
        let projection = RoutingProjection::spawn(ebpf, snapshot(1, 1, 2));
        let termination = projection.termination_probe_for_test();

        // When
        tokio::join!(projection.shutdown(), projection.shutdown());

        // Then
        assert!(termination.is_terminated());
    }
}

#[tokio::test]
async fn drop_cancels_projection_worker() {
    for _ in 0..10 {
        // Given
        let ebpf: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
            Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
        let projection = RoutingProjection::spawn(ebpf, snapshot(1, 1, 2));
        let termination = projection.termination_probe_for_test();

        // When
        drop(projection);
        termination.wait().await;

        // Then
        assert!(termination.is_terminated());
    }
}
