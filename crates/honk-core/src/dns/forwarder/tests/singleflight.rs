#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_concurrent_queries_share_one_exchange_and_render_each_txid() {
    // Given
    const CALLERS: usize = 128;
    let upstream = Arc::new(GatedUpstream {
        response: make_a_response([192, 0, 2, 1], 300),
        call_count: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let cache = test_cache();
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        cache.clone(),
        test_router(),
    ));
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for txid in 1..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;
    upstream.entered.notified().await;
    let flights = cache.lock().await.singleflight();
    while flights.counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }

    // When
    upstream.release.notify_one();
    let mut txids = Vec::with_capacity(CALLERS);
    while let Some(joined) = tasks.join_next().await {
        let response = joined.expect("task").expect("resolve");
        txids.push(u16::from_be_bytes([response[0], response[1]]));
    }

    // Then
    txids.sort_unstable();
    assert_eq!(
        txids,
        (1..=u16::try_from(CALLERS).expect("count")).collect::<Vec<_>>()
    );
    assert_eq!(upstream.call_count.load(Ordering::SeqCst), 1);
    assert_eq!(flights.active_len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_leader_wakes_all_waiters_to_one_successor_operation() {
    const CALLERS: usize = 128;
    struct CancelUpstream {
        response: Vec<u8>,
        calls: AtomicUsize,
        first_entered: tokio::sync::Notify,
        successor_entered: tokio::sync::Notify,
        release_successor: tokio::sync::Notify,
    }
    #[async_trait]
    impl DnsUpstreamPool for CancelUpstream {
        async fn query(&self, _: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.first_entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.successor_entered.notify_one();
            self.release_successor.notified().await;
            Ok(self.response.clone())
        }
    }

    let upstream = Arc::new(CancelUpstream {
        response: make_a_response([192, 0, 2, 9], 300),
        calls: AtomicUsize::new(0),
        first_entered: tokio::sync::Notify::new(),
        successor_entered: tokio::sync::Notify::new(),
        release_successor: tokio::sync::Notify::new(),
    });
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let service = forwarder.cache_service().await;
    let mut leader_query = make_a_query();
    leader_query[0..2].copy_from_slice(&1_u16.to_be_bytes());
    let leader = {
        let forwarder = Arc::clone(&forwarder);
        tokio::spawn(async move { forwarder.resolve(&leader_query).await })
    };
    upstream.first_entered.notified().await;

    let start = Arc::new(tokio::sync::Barrier::new(CALLERS));
    let mut survivors = tokio::task::JoinSet::new();
    for txid in 2..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        survivors.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;
    while service.flight_counters().waiters < u64::try_from(CALLERS - 1).expect("count") {
        tokio::task::yield_now().await;
    }

    leader.abort();
    assert!(leader.await.expect_err("cancelled").is_cancelled());
    upstream.successor_entered.notified().await;
    while service.flight_counters().waiters
        < u64::try_from((CALLERS - 1) + (CALLERS - 2)).expect("count")
    {
        tokio::task::yield_now().await;
    }
    upstream.release_successor.notify_one();

    let mut completed = 0;
    while let Some(joined) = survivors.join_next().await {
        joined.expect("task").expect("resolve");
        completed += 1;
    }
    let counters = service.flight_counters();
    assert_eq!(completed, CALLERS - 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 2);
    assert_eq!(counters.leaders, 2);
    assert_eq!(counters.aborts, 1);
    assert_eq!(counters.retries, u64::try_from(CALLERS - 1).expect("count"));
    assert_eq!(service.active_flights(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_preflight_miss_does_not_open_a_second_exchange_after_cache_publish() {
    // Given
    const CALLERS: usize = 128;
    let upstream = Arc::new(MockUpstream::new(make_a_response([192, 0, 2, 1], 300)));
    let forwarder = Arc::new(DnsForwarder::new(
        upstream.clone(),
        test_cache(),
        test_router(),
    ));
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for txid in 1..=CALLERS {
        let forwarder = Arc::clone(&forwarder);
        let start = Arc::clone(&start);
        tasks.spawn(async move {
            let mut query = make_a_query();
            query[0..2].copy_from_slice(
                &u16::try_from(txid)
                    .expect("caller count fits u16")
                    .to_be_bytes(),
            );
            start.wait().await;
            forwarder.resolve(&query).await
        });
    }
    start.wait().await;

    // When
    while let Some(joined) = tasks.join_next().await {
        joined.expect("task").expect("resolve");
    }

    // Then
    assert_eq!(
        upstream.call_count.load(Ordering::SeqCst),
        1,
        "a caller delayed after its cache miss opened a second exchange"
    );
}
