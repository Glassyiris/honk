#[tokio::test]
async fn typed_outcome_tracks_positive_requery_and_caller_rendering() {
    // Given
    let mut query = build_dns_query("example.com", 1);
    query[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
    let first = response(&query, [10, 0, 0, 1], 30);
    let second = response(&query, [8, 8, 8, 8], 30);
    let rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Ip {
            not: false,
            cidrs: vec!["10.0.0.0/8".to_owned()],
            geoip: Vec::new(),
        }],
        action: DnsResponseAction::Upstream("second".to_owned()),
    }];
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let forwarder = DnsForwarder::new(
        exchange(
            [("first", Ok(first)), ("second", Ok(second))],
            Some(cache.clone()),
        ),
        cache,
        router("first", rules, None),
    );

    // When
    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");

    // Then
    assert_eq!(outcome.status(), OutcomeStatus::Accepted);
    assert_eq!(outcome.response_class(), ResponseClass::Positive);
    assert_eq!(outcome.provenance(), Provenance::Upstream);
    assert_eq!(outcome.logical_upstream(), Some("first"));
    assert_eq!(outcome.final_upstream(), Some("second"));
    assert_eq!(outcome.requery_history(), &["first", "second"]);
    assert_eq!(&outcome.rendered()[0..2], &0x1234_u16.to_be_bytes());
    assert_eq!(
        &outcome.rendered()[outcome.rendered().len() - 4..],
        &[8, 8, 8, 8]
    );
}

#[tokio::test]
async fn typed_outcome_rejects_response_and_skips_exchange_for_request_reject() {
    // Given
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::Reject,
        },
        ..Default::default()
    };
    let forwarder = DnsForwarder::new(
        exchange([], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new(&routing).expect("router")),
    );

    // When
    let outcome = forwarder
        .resolve_outcome(&build_dns_query("example.com", 1))
        .await
        .expect("reject outcome");

    // Then
    assert_eq!(outcome.status(), OutcomeStatus::Rejected);
    assert_eq!(outcome.response_class(), ResponseClass::Nodata);
    assert_eq!(outcome.provenance(), Provenance::Fresh);
}

#[tokio::test]
async fn typed_outcome_reports_malformed_response_and_requery_cycle() {
    // Given
    let query = build_dns_query("example.com", 1);
    let cycle_rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["first".to_owned()],
        }],
        action: DnsResponseAction::Upstream("first".to_owned()),
    }];
    let malformed = DnsForwarder::new(
        exchange([("first", Ok(vec![0, 1, 2]))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    );
    let cyclic = DnsForwarder::new(
        exchange([("first", Ok(response(&query, [1, 1, 1, 1], 30)))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", cycle_rules, None),
    );

    // When
    let malformed_error = malformed
        .resolve_outcome(&query)
        .await
        .expect_err("malformed");
    let cycle_error = cyclic.resolve_outcome(&query).await.expect_err("cycle");

    // Then
    assert!(matches!(
        malformed_error,
        DnsForwardError::Engine(super::EngineError::Response(_))
    ));
    assert!(matches!(
        cycle_error,
        DnsForwardError::Engine(super::EngineError::Plan(PlanError::UpstreamCycle { .. }))
    ));
}

#[tokio::test]
async fn typed_outcome_reports_requery_depth_before_fourth_exchange() {
    // Given
    let query = build_dns_query("example.com", 1);
    let rules = [
        ("first", "second"),
        ("second", "third"),
        ("third", "fourth"),
    ]
    .into_iter()
    .map(|(from, to)| DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec![from.to_owned()],
        }],
        action: DnsResponseAction::Upstream(to.to_owned()),
    })
    .collect();
    let forwarder = DnsForwarder::new(
        exchange(
            [
                ("first", Ok(response(&query, [1, 1, 1, 1], 30))),
                ("second", Ok(response(&query, [2, 2, 2, 2], 30))),
                ("third", Ok(response(&query, [3, 3, 3, 3], 30))),
            ],
            None,
        ),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", rules, None),
    );

    // When
    let error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("depth error");

    // Then
    assert!(matches!(
        error,
        DnsForwardError::Engine(super::EngineError::Plan(PlanError::DepthExceeded {
            max: 3
        }))
    ));
}

#[tokio::test]
async fn stale_outcome_covers_upstream_error_and_servfail_without_sleeping() {
    // Given
    let query = build_dns_query("example.com", 1);
    let cached = response(&query, [9, 9, 9, 9], 30);
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let routing = router("first", Vec::new(), None);
    let engine = super::DnsEngine::from_router(&routing, None).expect("engine");
    let prepared = engine
        .prepare(&query, None, IngressProfile::Internal)
        .expect("prepared");
    let RequestPlan::Exchange(scope) = prepared.plan() else {
        panic!("exchange plan");
    };
    let cache_key = CacheKey::new(
        prepared.query(),
        None,
        scope.clone(),
        OperationKind::Resolve,
    );
    cache
        .lock()
        .await
        .service()
        .insert_expired_exact_for_test(cache_key, cached, 30);
    let error_forwarder = DnsForwarder::new(
        exchange([("first", Err(anyhow::anyhow!("offline")))], None),
        cache.clone(),
        routing.clone(),
    );
    let mut servfail = response(&query, [1, 1, 1, 1], 30);
    servfail[3] = 0x82;
    let servfail_forwarder =
        DnsForwarder::new(exchange([("first", Ok(servfail))], None), cache, routing);

    // When
    let on_error = error_forwarder
        .resolve_outcome(&query)
        .await
        .expect("stale");
    let on_servfail = servfail_forwarder
        .resolve_outcome(&query)
        .await
        .expect("stale");

    // Then
    assert_eq!(on_error.provenance(), Provenance::Stale);
    assert_eq!(on_servfail.provenance(), Provenance::Stale);
    assert_eq!(
        on_error.expiry().ttl(),
        std::time::Duration::from_secs(crate::dns::forwarder::SERVE_STALE_TTL_SECS.into())
    );
    assert_eq!(on_error.expiry(), on_servfail.expiry());
    assert_eq!(
        &on_error.rendered()[on_error.rendered().len() - 4..],
        &[9, 9, 9, 9]
    );
}
