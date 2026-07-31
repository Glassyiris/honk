use crate::dns::planner::{RequestScope, UpstreamTag};
use crate::dns::policy::PolicyId;
use crate::dns::query::{IngressProfile, QueryContext};

use super::{CacheKey, DnsCache, OperationKind};

#[test]
fn cache_key_canonical_bytes_have_stable_golden_identity() {
    let key = CacheKey::for_test(
        vec![0, 0, 1],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
        OperationKind::Resolve,
    );
    let canonical_hex = key
        .canonical_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(
        canonical_hex,
        "4844434b0101000000030000010213032004300000000764656661756c740540"
    );
    assert_eq!(
        key.storage_key(),
        concat!(
            "honk-dns-cache-key:v1:",
            "caae7e784d48452782f192a41b2899cafa9c3042336fa67ae5e857a258deac76:",
            "4844434b0101000000030000010213032004300000000764656661756c740540"
        )
    );
    assert_eq!(DnsCache::new(16).shard_index(&key.storage_key()), 7);
}

#[test]
fn cache_key_canonical_fields_are_separated_and_collision_checked() {
    let base = CacheKey::for_test(
        vec![0, 0, 1],
        IngressProfile::Internal,
        RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
        OperationKind::Resolve,
    );
    let variants = [
        CacheKey::for_test(
            vec![0, 0, 2],
            IngressProfile::Internal,
            base.scope().clone(),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Tcp,
            base.scope().clone(),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Internal,
            RequestScope::Upstream(UpstreamTag::new("other").expect("tag")),
            OperationKind::Resolve,
        ),
        CacheKey::for_test(
            vec![0, 0, 1],
            IngressProfile::Internal,
            base.scope().clone(),
            OperationKind::Refresh,
        ),
    ];

    for variant in variants {
        assert_ne!(base.canonical_bytes(), variant.canonical_bytes());
        assert_ne!(base.storage_key(), variant.storage_key());
    }
    let storage = base.storage_key();
    let (_, canonical_hex) = storage
        .rsplit_once(':')
        .expect("digest and collision material");
    assert_eq!(
        canonical_hex,
        base.canonical_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
}

#[test]
fn exact_key_separates_wire_profile_policy_scope_and_operation() {
    let base_wire = crate::dns::forwarder::build_dns_query("Example.com", 1);
    let base_query = QueryContext::parse(&base_wire).expect("base query");
    let scope = RequestScope::Upstream(UpstreamTag::new("default").expect("scope"));
    let base = CacheKey::new(&base_query, None, scope.clone(), OperationKind::Resolve);
    let mut variants = Vec::new();
    for mutate in [
        |wire: &mut Vec<u8>| wire[13] = b'e',
        |wire: &mut Vec<u8>| wire[2] ^= 0x10,
        |wire: &mut Vec<u8>| {
            let end = wire.len();
            wire[end - 1] = 3;
        },
    ] {
        let mut wire = base_wire.clone();
        mutate(&mut wire);
        variants.push(CacheKey::new(
            &QueryContext::parse(&wire).expect("wire variant"),
            None,
            scope.clone(),
            OperationKind::Resolve,
        ));
    }
    let mut edns_wire = base_wire.clone();
    edns_wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
    edns_wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    variants.push(CacheKey::new(
        &QueryContext::parse(&edns_wire).expect("edns"),
        None,
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &QueryContext::parse_with_profile(&base_wire, IngressProfile::Tcp).expect("profile"),
        None,
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        Some(PolicyId::from_config(&Default::default()).expect("policy")),
        scope.clone(),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        None,
        RequestScope::Upstream(UpstreamTag::new("other").expect("other scope")),
        OperationKind::Resolve,
    ));
    variants.push(CacheKey::new(
        &base_query,
        None,
        scope,
        OperationKind::Refresh,
    ));

    assert!(variants.iter().all(|variant| variant != &base));
    assert!(
        variants
            .iter()
            .all(|variant| variant.storage_key() != base.storage_key())
    );
}
