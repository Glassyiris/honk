#[tokio::test]
async fn test_only_strategy_filters_at_request_time() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::Ipv4Only);

    let resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(answer_count(&resp), 0, "AAAA must be answered NODATA");
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        0,
        "filtered query must never reach upstream"
    );
}

#[tokio::test]
async fn test_prefer_ipv4_suppresses_aaaa_when_a_exists() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    // Prime the A cache with real answers.
    let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert!(answer_count(&a_resp) > 0);

    // AAAA is forwarded to upstream but suppressed at response time.
    let aaaa_resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(
        answer_count(&aaaa_resp),
        0,
        "AAAA must be suppressed when A answers exist"
    );
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "A + AAAA; the prefer check must hit the cache, not upstream"
    );
}

#[tokio::test]
async fn test_prefer_ipv4_returns_aaaa_when_no_a() {
    let mock = qtype_mock(
        nodata_response("example.com", 1),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    let resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(
        answer_count(&resp),
        1,
        "AAAA must be returned when no A answers exist"
    );
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "AAAA + sibling A probe"
    );

    // Cache-hit path: AAAA and the sibling's NODATA are both cached.
    let resp2 = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert_eq!(answer_count(&resp2), 1);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_prefer_ipv4_never_probes_for_a_queries() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv4);

    let resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert_eq!(answer_count(&resp), 1);
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "preferred qtype must not trigger a sibling probe"
    );
}

#[tokio::test]
async fn test_prefer_ipv6_suppresses_a_when_aaaa_exists() {
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        test_router(),
    )
    .with_strategy(DnsStrategy::PreferIpv6);

    // Prime the AAAA cache.
    let aaaa_resp = forwarder
        .resolve(&build_dns_query("example.com", 28))
        .await
        .unwrap();
    assert!(answer_count(&aaaa_resp) > 0);

    let a_resp = forwarder.resolve(&make_a_query()).await.unwrap();
    assert_eq!(
        answer_count(&a_resp),
        0,
        "A must be suppressed when AAAA answers exist"
    );
}

/// A cached NXDOMAIN must be answered as NXDOMAIN (rcode 3), never
/// upgraded to SERVFAIL — the two have opposite client semantics.
#[tokio::test]
async fn test_negative_cache_returns_nxdomain_not_servfail() {
    let mut nx = make_a_response([93, 184, 216, 34], 60);
    nx[3] = 0x83; // QR + RA + NXDOMAIN
    let mock = Arc::new(MockUpstream::new(nx));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());
    let query = make_a_query();

    let resp = forwarder.resolve(&query).await.expect("first nxdomain");
    assert_eq!(resp[3] & 0x0f, 3);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

    let resp2 = forwarder.resolve(&query).await.expect("cached nxdomain");
    assert_eq!(resp2[3] & 0x0f, 3, "cached negative must stay NXDOMAIN");
    assert_eq!(resp2[0..2], query[0..2], "txid must match the query");
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "negative hit must not re-query upstream"
    );
}

/// A cached SERVFAIL stays SERVFAIL (rcode 2) on later hits.
#[tokio::test]
async fn test_negative_cache_keeps_servfail_rcode() {
    let mut sf = make_a_response([93, 184, 216, 34], 1);
    sf[3] = 0x82; // QR + RA + SERVFAIL
    let mock = Arc::new(MockUpstream::new(sf));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(mock.clone(), cache, test_router());
    let query = make_a_query();

    let _ = forwarder.resolve(&query).await;
    // Second hit: still rcode 2, no extra upstream call.
    let resp2 = forwarder.resolve(&query).await.expect("cached servfail");
    assert_eq!(resp2[3] & 0x0f, 2);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}
