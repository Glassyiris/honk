use super::{classify_response, effective_expiry};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use honk_config::dns::{
    DnsCond, DnsConfig, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
    DnsResponseRule, DnsRouting,
};
use tokio::sync::Mutex;

use crate::dns::cache::DnsCache;
use crate::dns::forwarder::{
    DnsForwardError, DnsForwarder, DnsUpstreamPool, DomainResolveNotifier, build_dns_query,
};
use crate::dns::outcome::{OutcomeStatus, Provenance, ResponseClass};
use crate::dns::planner::PlanError;
use crate::dns::routing::DnsRouter;

#[test]
fn classifies_positive_nodata_nxdomain_and_servfail_responses() {
    // Given
    let positive = [0_u8, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    let nodata = [0_u8, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    let nxdomain = [0_u8, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
    let servfail = [0_u8, 0, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0];

    // When / Then
    assert_eq!(classify_response(&positive), ResponseClass::Positive);
    assert_eq!(classify_response(&nodata), ResponseClass::Nodata);
    assert_eq!(classify_response(&nxdomain), ResponseClass::Nxdomain);
    assert_eq!(classify_response(&servfail), ResponseClass::Servfail);
}

#[test]
fn fixed_zero_disables_cache_instead_of_clamping_to_one() {
    // Given / When
    let expiry = effective_expiry(Some(0), 600, 30);

    // Then
    assert!(!expiry.is_cacheable());
}

struct SequenceExchange {
    replies: StdMutex<HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>>>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
    calls: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for SequenceExchange {
    async fn query(&self, upstream: &str, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(cache) = &self.cache_probe {
            assert!(
                cache.try_lock().is_ok(),
                "cache guard held at exchange await"
            );
        }
        self.replies
            .lock()
            .expect("reply lock")
            .get_mut(upstream)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| anyhow::bail!("missing reply for {upstream}"))
    }
}

fn response(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&[
        0xc0,
        0x0c,
        0,
        1,
        0,
        1,
        ttl.to_be_bytes()[0],
        ttl.to_be_bytes()[1],
        ttl.to_be_bytes()[2],
        ttl.to_be_bytes()[3],
        0,
        4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
    ]);
    wire
}

fn router(
    initial: &str,
    response_rules: Vec<DnsResponseRule>,
    fixed_ttl: Option<u32>,
) -> Arc<DnsRouter> {
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::Upstream(initial.to_owned()),
        },
        response: DnsResponseRouting {
            rules: response_rules,
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    };
    let fixed = fixed_ttl
        .map(|ttl| HashMap::from([("example.com".to_owned(), ttl)]))
        .unwrap_or_default();
    Arc::new(DnsRouter::new_with_fixed_ttl(&routing, &fixed).expect("router"))
}

fn exchange(
    replies: impl IntoIterator<Item = (&'static str, anyhow::Result<Vec<u8>>)>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
) -> Arc<SequenceExchange> {
    let mut by_upstream: HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>> = HashMap::new();
    for (upstream, reply) in replies {
        by_upstream
            .entry(upstream.to_owned())
            .or_default()
            .push_back(reply);
    }
    Arc::new(SequenceExchange {
        replies: StdMutex::new(by_upstream),
        cache_probe,
        calls: AtomicUsize::new(0),
    })
}

fn multi_question_query() -> Vec<u8> {
    let mut query = build_dns_query("example.com", 1);
    let second = build_dns_query("other.example", 28);
    query[4..6].copy_from_slice(&2_u16.to_be_bytes());
    query.extend_from_slice(&second[12..]);
    query
}

fn edns_query(version: u8, option: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut query = build_dns_query("example.com", 1);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, version, 0, 0]);
    let option_len = option
        .map(|(_, data)| 4_usize.saturating_add(data.len()))
        .unwrap_or_default();
    query.extend_from_slice(&(option_len as u16).to_be_bytes());
    if let Some((code, data)) = option {
        query.extend_from_slice(&code.to_be_bytes());
        query.extend_from_slice(&(data.len() as u16).to_be_bytes());
        query.extend_from_slice(data);
    }
    query
}

fn nodata_response(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire
}

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
    cache
        .lock()
        .await
        .insert_expired_for_test("example.com:1".to_owned(), cached, 30);
    let error_forwarder = DnsForwarder::new(
        exchange([("first", Err(anyhow::anyhow!("offline")))], None),
        cache.clone(),
        router("first", Vec::new(), None),
    );
    let mut servfail = response(&query, [1, 1, 1, 1], 30);
    servfail[3] = 0x82;
    let servfail_forwarder = DnsForwarder::new(
        exchange([("first", Ok(servfail))], None),
        cache,
        router("first", Vec::new(), None),
    );

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

struct OrderingNotifier {
    cache: Arc<Mutex<DnsCache>>,
    observed: StdMutex<Option<Vec<u8>>>,
}

impl DomainResolveNotifier for OrderingNotifier {
    fn on_domain_resolved(&self, _: &str, response: &[u8]) {
        assert!(
            self.cache.try_lock().is_ok(),
            "cache guard held at notifier"
        );
        self.observed
            .lock()
            .expect("notifier lock")
            .replace(response.to_vec());
    }
}

#[tokio::test]
async fn fixed_zero_and_notifier_order_are_visible_in_typed_outcome() {
    // Given
    let mut query = build_dns_query("example.com", 1);
    query[0..2].copy_from_slice(&0x5678_u16.to_be_bytes());
    let upstream = response(&query, [4, 3, 2, 1], 30);
    let cache = Arc::new(Mutex::new(DnsCache::new(8)));
    let notifier = Arc::new(OrderingNotifier {
        cache: cache.clone(),
        observed: StdMutex::new(None),
    });
    let forwarder = DnsForwarder::with_notifier(
        exchange([("first", Ok(upstream))], None),
        cache.clone(),
        router("first", Vec::new(), Some(0)),
        notifier.clone(),
    );

    // When
    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");

    // Then
    assert!(!outcome.expiry().is_cacheable());
    assert!(cache.lock().await.get("example.com:1").is_none());
    let notified = notifier
        .observed
        .lock()
        .expect("notifier lock")
        .clone()
        .expect("notified");
    assert_eq!(&notified[0..2], &[0, 0]);
    assert_eq!(&outcome.rendered()[0..2], &0x5678_u16.to_be_bytes());
}

#[tokio::test]
async fn strict_asis_without_destination_errors_but_raw_wrapper_uses_default() {
    let query = build_dns_query("example.com", 1);
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::AsIs,
        },
        ..Default::default()
    };
    let pool = exchange([("default", Ok(response(&query, [1, 2, 3, 4], 30)))], None);
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        Arc::new(DnsRouter::new(&routing).expect("router")),
    );

    let typed_error = forwarder
        .resolve_outcome(&query)
        .await
        .expect_err("typed AsIs(None) must fail");
    let raw = forwarder.resolve(&query).await.expect("legacy fallback");

    assert!(matches!(
        typed_error,
        DnsForwardError::Engine(super::EngineError::Plan(
            PlanError::MissingOriginalDestination
        ))
    ));
    assert_eq!(&raw[raw.len() - 4..], &[1, 2, 3, 4]);
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ineligible_queries_bypass_cache_while_eligible_queries_reuse_it() {
    let unusual_queries = [
        ("multi-question", multi_question_query()),
        ("EDNSv1", edns_query(1, None)),
        ("ECS", edns_query(0, Some((8, &[0, 1, 2, 3])))),
        ("COOKIE", edns_query(0, Some((10, &[1, 2, 3, 4])))),
    ];
    for (label, unusual) in unusual_queries {
        let pool = exchange(
            [
                ("first", Ok(nodata_response(&unusual))),
                ("first", Ok(nodata_response(&unusual))),
            ],
            None,
        );
        let forwarder = DnsForwarder::new(
            pool.clone(),
            Arc::new(Mutex::new(DnsCache::new(8))),
            router("first", Vec::new(), None),
        );

        let first = forwarder
            .resolve_outcome(&unusual)
            .await
            .unwrap_or_else(|error| panic!("{label} first exchange failed: {error}"));
        let second = forwarder
            .resolve_outcome(&unusual)
            .await
            .unwrap_or_else(|error| panic!("{label} second exchange failed: {error}"));

        assert_eq!(first.provenance(), Provenance::Upstream, "{label}");
        assert_eq!(second.provenance(), Provenance::Upstream, "{label}");
        assert_eq!(pool.calls.load(Ordering::SeqCst), 2, "{label}");
    }

    let eligible = build_dns_query("example.com", 1);
    let eligible_pool = exchange([("first", Ok(response(&eligible, [3, 3, 3, 3], 30)))], None);
    let eligible_forwarder = DnsForwarder::new(
        eligible_pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    );
    let _ = eligible_forwarder
        .resolve_outcome(&eligible)
        .await
        .expect("eligible miss");
    let hit = eligible_forwarder
        .resolve_outcome(&eligible)
        .await
        .expect("eligible hit");

    assert_eq!(hit.provenance(), Provenance::Cache);
    assert_eq!(eligible_pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn negative_outcome_expiry_matches_insert_and_cache_hit_lifetime() {
    let query = build_dns_query("example.com", 1);
    let mut nxdomain = query.clone();
    nxdomain[0..2].copy_from_slice(&[0, 0]);
    nxdomain[2] = 0x81;
    nxdomain[3] = 0x83;
    let pool = exchange([("first", Ok(nxdomain))], None);
    let forwarder = DnsForwarder::new(
        pool.clone(),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), Some(0)),
    )
    .with_cache_ttl(600);

    let inserted = forwarder
        .resolve_outcome(&query)
        .await
        .expect("negative miss");
    let hit = forwarder
        .resolve_outcome(&query)
        .await
        .expect("negative hit");

    assert_eq!(inserted.response_class(), ResponseClass::Nxdomain);
    assert_eq!(inserted.expiry().ttl(), std::time::Duration::from_secs(60));
    assert_eq!(hit.provenance(), Provenance::Cache);
    assert!(hit.expiry().is_cacheable());
    assert_eq!(hit.expiry().ttl(), std::time::Duration::from_secs(60));
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn config_backed_forwarder_populates_typed_policy_identity() {
    let query = build_dns_query("example.com", 1);
    let config = DnsConfig::default();
    let forwarder = DnsForwarder::new(
        exchange([("first", Ok(response(&query, [4, 4, 4, 4], 30)))], None),
        Arc::new(Mutex::new(DnsCache::new(8))),
        router("first", Vec::new(), None),
    )
    .with_policy_from_config(&config)
    .expect("config policy");

    let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");

    assert_eq!(
        outcome.policy_id().map(ToString::to_string),
        Some(
            crate::dns::policy::PolicyId::from_config(&config)
                .expect("expected policy")
                .to_string()
        )
    );
}
