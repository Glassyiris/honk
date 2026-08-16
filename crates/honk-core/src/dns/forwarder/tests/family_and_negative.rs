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

#[tokio::test]
async fn cached_negative_keeps_source_aware_preferred_family_projection() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    };

    struct NegativePreferenceUpstream {
        rcode: u8,
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsUpstreamPool for NegativePreferenceUpstream {
        async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("calls")
                .push(upstream_name.to_string());
            Ok(match upstream_name {
                "negative" => {
                    let mut response = nodata_response("example.com", 28);
                    response[3] = 0x80 | self.rcode;
                    response
                }
                "has-a" => make_a_response([192, 0, 2, 1], 300),
                "no-a" => {
                    let query = crate::dns::query::QueryContext::parse(raw_query).expect("query");
                    make_empty_response(raw_query, &query)
                }
                _ => panic!("unexpected upstream {upstream_name}"),
            })
        }
    }

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![
                    DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        }],
                        action: DnsRequestAction::Upstream("negative".into()),
                    },
                    DnsRequestRule {
                        conditions: vec![
                            DnsCond::Sip {
                                not: false,
                                cidrs: vec!["192.0.2.0/24".into()],
                            },
                            DnsCond::Qtype {
                                not: false,
                                types: vec![1],
                            },
                        ],
                        action: DnsRequestAction::Upstream("has-a".into()),
                    },
                ],
                fallback: DnsRequestAction::Upstream("no-a".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let query = build_dns_query("example.com", 28);

    for rcode in [2, 3] {
        let upstream = Arc::new(NegativePreferenceUpstream {
            rcode,
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), Arc::clone(&router))
            .with_strategy(DnsStrategy::PreferIpv4);
        for _ in 0..2 {
            for (source, expected_rcode) in [("192.0.2.10", 0), ("198.51.100.10", rcode)] {
                let response = forwarder
                    .resolve_outcome_with_context(
                        &query,
                        DnsRequestMeta::new(Some(source.parse().expect("source")), None),
                    )
                    .await
                    .expect("negative response")
                    .into_rendered();
                assert_eq!(response[3] & 0x0f, expected_rcode);
                assert_eq!(answer_count(&response), 0);
            }
        }
        let mut calls = upstream.calls.lock().expect("calls").clone();
        calls.sort();
        assert_eq!(calls, ["has-a", "negative", "no-a"]);
    }
}

#[tokio::test]
async fn strict_preferred_family_asis_without_destination_does_not_fall_back() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    };

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![DnsRequestRule {
                    conditions: vec![DnsCond::Qtype {
                        not: false,
                        types: vec![1],
                    }],
                    action: DnsRequestAction::AsIs,
                }],
                fallback: DnsRequestAction::Upstream("default".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let mock = qtype_mock(
        make_a_response([10, 0, 0, 1], 300),
        make_aaaa_response(TEST_V6, 300),
    );
    let forwarder = DnsForwarder::new(mock.clone(), test_cache(), router)
        .with_strategy(DnsStrategy::PreferIpv4);

    let response = forwarder
        .resolve_outcome_with_context(
            &build_dns_query("example.com", 28),
            DnsRequestMeta::new(Some("192.0.2.10".parse().expect("source")), None),
        )
        .await
        .expect("strict response")
        .into_rendered();

    assert_eq!(answer_count(&response), 1);
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn preferred_family_sibling_keeps_client_source_routing() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    };

    struct PreferenceUpstream {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsUpstreamPool for PreferenceUpstream {
        async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(match upstream_name {
                "aaaa" => make_aaaa_response(TEST_V6, 300),
                "has-a" => make_a_response([192, 0, 2, 1], 300),
                "no-a" => {
                    let query = crate::dns::query::QueryContext::parse(raw_query).expect("query");
                    make_empty_response(raw_query, &query)
                }
                _ => panic!("unexpected upstream {upstream_name}"),
            })
        }
    }

    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![
                    DnsRequestRule {
                        conditions: vec![DnsCond::Qtype {
                            not: false,
                            types: vec![28],
                        }],
                        action: DnsRequestAction::Upstream("aaaa".into()),
                    },
                    DnsRequestRule {
                        conditions: vec![
                            DnsCond::Sip {
                                not: false,
                                cidrs: vec!["192.0.2.0/24".into()],
                            },
                            DnsCond::Qtype {
                                not: false,
                                types: vec![1],
                            },
                        ],
                        action: DnsRequestAction::Upstream("has-a".into()),
                    },
                ],
                fallback: DnsRequestAction::Upstream("no-a".into()),
            },
            ..Default::default()
        })
        .expect("router"),
    );
    let upstream = Arc::new(PreferenceUpstream {
        calls: AtomicUsize::new(0),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router)
        .with_strategy(DnsStrategy::PreferIpv4);
    let query = build_dns_query("example.com", 28);

    let inside = forwarder
        .resolve_outcome_with_context(
            &query,
            DnsRequestMeta::new(Some("192.0.2.10".parse().expect("source")), None),
        )
        .await
        .expect("inside response")
        .into_rendered();
    let outside = forwarder
        .resolve_outcome_with_context(
            &query,
            DnsRequestMeta::new(Some("198.51.100.10".parse().expect("source")), None),
        )
        .await
        .expect("outside response")
        .into_rendered();

    assert_eq!(answer_count(&inside), 0);
    assert_eq!(answer_count(&outside), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 3);
}
