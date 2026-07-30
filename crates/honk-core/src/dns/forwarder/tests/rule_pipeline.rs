#[tokio::test]
async fn test_optimistic_cache_ttl_overrides_answer_ttl() {
    // Upstream answers with TTL=30; forwarder configured for 600.
    let upstream_resp = make_a_response([9, 9, 9, 9], 30);
    let mock = Arc::new(MockUpstream::new(upstream_resp));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(
        mock as Arc<dyn DnsUpstreamPool>,
        cache.clone(),
        test_router(),
    )
    .with_cache_ttl(600);

    let query = make_a_query();
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(
        extract_min_ttl(&result),
        600,
        "client-visible wire TTL overridden"
    );

    {
        let guard = cache.lock().await;
        let entries = guard.positive_entries_for_test();
        let entry = entries.first().expect("cached");
        assert_eq!(entry.min_ttl, 600);
        assert_eq!(extract_min_ttl(&entry.response), 600);
        // Lifetime should be ~600s, not 30s.
        let remaining = entry.remaining_ttl_secs();
        assert!(
            (590..=600).contains(&remaining),
            "cache lifetime uses optimistic_cache_ttl, got {remaining}"
        );
    }
}

#[tokio::test]
async fn test_request_reject_skips_upstream() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    let mock = Arc::new(MockUpstream::new(make_a_response([1, 1, 1, 1], 60)));
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![DnsRequestRule {
                    conditions: vec![DnsCond::Qtype {
                        not: false,
                        types: vec![65], // HTTPS
                    }],
                    action: DnsRequestAction::Reject,
                }],
                fallback: DnsRequestAction::Upstream("default".into()),
            },
            ..Default::default()
        })
        .unwrap(),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    );

    let query = build_dns_query("example.com", 65);
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        0,
        "reject must not dial"
    );
    assert_eq!(
        u16::from_be_bytes([result[6], result[7]]),
        0,
        "empty ANCOUNT"
    );
}

#[tokio::test]
async fn test_qtype_routes_to_named_upstream() {
    use honk_config::dns::{DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule};

    struct NameMock {
        last: std::sync::Mutex<String>,
        a_resp: Vec<u8>,
        aaaa_resp: Vec<u8>,
    }
    #[async_trait]
    impl DnsUpstreamPool for NameMock {
        async fn query(&self, upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            *self.last.lock().unwrap() = upstream_name.to_string();
            if upstream_name == "v6dns" {
                Ok(self.aaaa_resp.clone())
            } else {
                Ok(self.a_resp.clone())
            }
        }
    }

    let mock = Arc::new(NameMock {
        last: std::sync::Mutex::new(String::new()),
        a_resp: make_a_response([1, 2, 3, 4], 60),
        aaaa_resp: make_a_response([9, 9, 9, 9], 60),
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![DnsRequestRule {
                    conditions: vec![DnsCond::Qtype {
                        not: false,
                        types: vec![28],
                    }],
                    action: DnsRequestAction::Upstream("v6dns".into()),
                }],
                fallback: DnsRequestAction::Upstream("default".into()),
            },
            ..Default::default()
        })
        .unwrap(),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    )
    .with_strategy(honk_config::dns::DnsStrategy::Both);

    let q_a = build_dns_query("example.com", 1);
    let _ = forwarder.resolve(&q_a).await.unwrap();
    assert_eq!(mock.last.lock().unwrap().as_str(), "default");

    let q_aaaa = build_dns_query("example.com", 28);
    let _ = forwarder.resolve(&q_aaaa).await.unwrap();
    assert_eq!(mock.last.lock().unwrap().as_str(), "v6dns");
}

#[tokio::test]
async fn test_response_requery_switches_upstream() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
        DnsResponseRule,
    };

    struct SeqMock {
        calls: AtomicUsize,
        polluted: Vec<u8>,
        clean: Vec<u8>,
    }
    #[async_trait]
    impl DnsUpstreamPool for SeqMock {
        async fn query(&self, upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if upstream_name == "googledns" {
                Ok(self.clean.clone())
            } else {
                Ok(self.polluted.clone())
            }
        }
    }

    let mock = Arc::new(SeqMock {
        calls: AtomicUsize::new(0),
        polluted: make_a_response([10, 0, 0, 1], 60), // private → trigger requery
        clean: make_a_response([8, 8, 8, 8], 60),
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![],
                fallback: DnsRequestAction::Upstream("alidns".into()),
            },
            response: DnsResponseRouting {
                rules: vec![DnsResponseRule {
                    conditions: vec![DnsCond::Ip {
                        not: false,
                        cidrs: vec!["10.0.0.0/8".into()],
                        geoip: vec![],
                    }],
                    action: DnsResponseAction::Upstream("googledns".into()),
                }],
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        })
        .unwrap(),
    );
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        test_cache(),
        router,
    );

    let query = make_a_query();
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2, "polluted then clean");
    assert_eq!(&result[result.len() - 4..], &[8, 8, 8, 8]);
}
