use crate::dns::forwarder::build_dns_query;
use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

use super::*;

fn key(name: &str, kind: u16, ingress: IngressProfile, scope: &str) -> CacheKey {
    CacheKey::new(
        &QueryContext::parse_with_profile(&build_dns_query(name, kind), ingress).unwrap(),
        None,
        RequestScope::Upstream(UpstreamTag::new(scope).unwrap()),
        OperationKind::Resolve,
    )
}

#[tokio::test]
async fn exact_ids_follow_incarnations_not_keys_or_cache_instances() {
    let service = DnsCache::new(1).service();
    let key = key("example.com", 1, IngressProfile::Internal, "default");
    let response = make_test_response([192, 0, 2, 1], 300);
    let revision = service
        .put_exact_if_current(
            service.publication_epoch(),
            key.clone(),
            response.clone(),
            300,
            None,
        )
        .unwrap();
    let first = service.entry_id(&key).unwrap();
    assert_eq!(
        service.entry_id_for_revision(&key, revision).as_deref(),
        Some(first.as_str())
    );
    assert_eq!(service.inspect_exact(4096).unwrap()[0].id, first);
    service.put_exact(key.clone(), response.clone(), 300, None);
    let replacement = service.entry_id(&key).unwrap();
    assert_ne!(replacement, first);
    assert!(service.entry_id_for_revision(&key, revision).is_none());
    assert_eq!(
        service
            .invalidate(CacheInvalidation::Id(first))
            .await
            .unwrap()
            .deleted,
        0
    );
    assert_eq!(
        service.entry_id(&key).as_deref(),
        Some(replacement.as_str())
    );
    assert_eq!(
        service
            .invalidate(CacheInvalidation::Id(replacement.clone()))
            .await
            .unwrap()
            .deleted,
        1
    );
    assert_eq!(
        service
            .invalidate(CacheInvalidation::Id(replacement.clone()))
            .await
            .unwrap()
            .deleted,
        0
    );
    service.put_exact(key.clone(), response.clone(), 300, None);
    assert_ne!(service.entry_id(&key).unwrap(), replacement);
    let other = DnsCache::new(1).service();
    other.put_exact(key.clone(), response, 300, None);
    assert_ne!(service.entry_id(&key), other.entry_id(&key));
}

#[test]
fn bounded_inspection_retains_every_variant_without_touching_lru_or_counters() {
    let service = DnsCache::new(128).service();
    let base = key("example.com", 1, IngressProfile::Internal, "default");
    let other = key("example.com", 1, IngressProfile::Internal, "other");
    let profile = key("example.com", 1, IngressProfile::Tcp, "default");
    let policy = CacheKey::new(
        &QueryContext::parse(&build_dns_query("example.com", 1)).unwrap(),
        Some(PolicyId::from_config(&Default::default()).unwrap()),
        base.scope().clone(),
        OperationKind::Resolve,
    );
    for key in [&base, &other, &profile, &policy] {
        service.put_exact(
            key.clone(),
            make_test_response([192, 0, 2, 1], 300),
            300,
            None,
        );
    }
    let before = service.counters();
    let rows = service.inspect_exact(1024 * 1024).unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row.response.is_some()
        && row.expires_at > std::time::Instant::now()
        && row.stale_until.is_some_and(|until| until > row.expires_at)
        && row.negative.is_none()));
    for key in [&base, &other, &profile, &policy] {
        assert!(rows.iter().any(|row| &row.key == key));
    }
    let cost = rows.iter().map(|row| row.cost).sum();
    assert_eq!(service.inspect_exact(cost).unwrap().len(), 4);
    assert_eq!(
        service.inspect_exact(cost - 1).unwrap_err(),
        CacheInspectionError
    );
    assert_eq!(service.counters(), before);
    let lru = DnsCache::new(32).service();
    lru.put_exact(
        base.clone(),
        make_test_response([192, 0, 2, 1], 300),
        300,
        None,
    );
    lru.put_exact(
        other.clone(),
        make_test_response([192, 0, 2, 2], 300),
        300,
        None,
    );
    lru.inspect_exact(4096).unwrap();
    lru.entry_id(&base).unwrap();
    let third = key("example.com", 1, IngressProfile::Internal, "third");
    lru.put_exact(third, make_test_response([192, 0, 2, 3], 300), 300, None);
    assert!(lru.entry_id(&base).is_none());
    assert!(lru.entry_id(&other).is_some());
}

#[tokio::test]
async fn name_invalidation_fences_foreground_refresh_and_restore_across_variants() {
    let service = DnsCache::new(128).service();
    let first = key("Example.COM", 1, IngressProfile::Internal, "default");
    let second = key("example.com", 1, IngressProfile::Tcp, "other");
    let other_type = key("example.com", 28, IngressProfile::Internal, "default");
    let unrelated = key("other.example", 1, IngressProfile::Internal, "default");
    let old_epoch = service.publication_epoch();
    let response = make_test_response([192, 0, 2, 1], 300);
    for key in [&first, &second, &other_type, &unrelated] {
        service.put_exact(key.clone(), response.clone(), 300, None);
    }
    let revision = match service.lookup_exact(&first, true) {
        ExactLookup::Positive { revision, .. } => revision,
        _ => panic!("positive fixture"),
    };
    let result = service
        .invalidate(CacheInvalidation::Name {
            name: "EXAMPLE.com.".into(),
            types: vec![1],
        })
        .await
        .unwrap();
    assert_eq!(
        (result.matched, result.deleted, result.persistent),
        (2, 2, false)
    );
    assert!(service.entry_id(&first).is_none());
    assert!(service.entry_id(&second).is_none());
    assert!(service.entry_id(&other_type).is_some());
    assert!(service.entry_id(&unrelated).is_some());
    assert!(
        service
            .put_exact_if_current(old_epoch, first.clone(), response.clone(), 300, None)
            .is_none()
    );
    assert!(
        service
            .put_negative_if_current(old_epoch, first.clone(), 30, 3, Some(revision))
            .is_none()
    );
    assert!(!service.put_restored_exact_if_current(
        old_epoch,
        first.clone(),
        response.clone(),
        300
    ));
    assert!(
        service
            .put_exact_if_current(
                service.publication_epoch(),
                first.clone(),
                response,
                300,
                None
            )
            .is_some()
    );
    assert_eq!(
        service
            .invalidate(CacheInvalidation::All)
            .await
            .unwrap()
            .deleted,
        3
    );
    assert!(service.is_empty());
}
