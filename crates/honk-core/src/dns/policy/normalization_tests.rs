use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule, DnsResponseAction,
    DnsResponseRule,
};

use super::PolicyId;
use crate::dns::routing::{DnsRequestDecision, DnsRouter};

#[test]
fn fixed_ttl_case_and_trailing_dot_follow_exact_runtime_keys() {
    // Given
    let lower = fixed_ttl_config("example.com");
    let upper = fixed_ttl_config("EXAMPLE.COM");
    let dotted = fixed_ttl_config("example.com.");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let dotted_id = PolicyId::from_config(&dotted).expect("dotted policy");
    let lower_router = DnsRouter::new_from_dns_config(&lower).expect("lower router");
    let upper_router = DnsRouter::new_from_dns_config(&upper).expect("upper router");
    let dotted_router = DnsRouter::new_from_dns_config(&dotted).expect("dotted router");

    // Then
    assert_ne!(lower_id, upper_id);
    assert_ne!(lower_id, dotted_id);
    assert_eq!(lower_router.fixed_ttl("example.com"), Some(42));
    assert_eq!(upper_router.fixed_ttl("example.com"), None);
    assert_eq!(dotted_router.fixed_ttl("example.com"), None);
}

#[test]
fn exact_runtime_tags_and_targets_do_not_share_policy_identity() {
    // Given
    let base = exact_material_config();
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.upstream[0].name = "dnsmain".into();
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].outbound = Some("proxy".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.request.fallback = DnsRequestAction::Upstream("dnsmain".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.rules[0].conditions = vec![DnsCond::Upstream {
        not: false,
        names: vec!["dnsmain".into()],
    }];
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.rules[0].action = DnsResponseAction::Upstream("secondary".into());
    variants.push(changed);

    // When
    let base_id = PolicyId::from_config(&base).expect("base policy");
    let variant_ids = variants
        .iter()
        .map(PolicyId::from_config)
        .collect::<Result<Vec<_>, _>>()
        .expect("variant policies");

    // Then
    assert!(variant_ids.iter().all(|id| id != &base_id));
}

#[test]
fn full_matcher_only_normalizes_case_that_router_also_normalizes() {
    // Given
    let lower = full_matcher_config("example.com");
    let upper = full_matcher_config("EXAMPLE.COM");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let lower_decision = DnsRouter::new_from_dns_config(&lower)
        .expect("lower router")
        .select_request("example.com", 1);
    let upper_decision = DnsRouter::new_from_dns_config(&upper)
        .expect("upper router")
        .select_request("example.com", 1);

    // Then
    assert_eq!(lower_id, upper_id);
    assert_eq!(lower_decision, DnsRequestDecision::Reject);
    assert_eq!(upper_decision, DnsRequestDecision::Reject);
}

#[test]
fn full_matcher_trailing_dot_changes_runtime_and_identity() {
    // Given
    let plain = full_matcher_config("example.com");
    let dotted = full_matcher_config("example.com.");

    // When
    let plain_id = PolicyId::from_config(&plain).expect("plain policy");
    let dotted_id = PolicyId::from_config(&dotted).expect("dotted policy");
    let plain_decision = DnsRouter::new_from_dns_config(&plain)
        .expect("plain router")
        .select_request("example.com", 1);
    let dotted_decision = DnsRouter::new_from_dns_config(&dotted)
        .expect("dotted router")
        .select_request("example.com", 1);

    // Then
    assert_ne!(plain_id, dotted_id);
    assert_eq!(plain_decision, DnsRequestDecision::Reject);
    assert_eq!(dotted_decision, DnsRequestDecision::AsIs);
}

#[test]
fn keyword_matcher_case_remains_exact_like_router_material() {
    // Given
    let lower = keyword_matcher_config("ads");
    let upper = keyword_matcher_config("ADS");

    // When
    let lower_id = PolicyId::from_config(&lower).expect("lower policy");
    let upper_id = PolicyId::from_config(&upper).expect("upper policy");
    let lower_decision = DnsRouter::new_from_dns_config(&lower)
        .expect("lower router")
        .select_request("ads.example", 1);
    let upper_decision = DnsRouter::new_from_dns_config(&upper)
        .expect("upper router")
        .select_request("ads.example", 1);

    // Then
    assert_ne!(lower_id, upper_id);
    assert_eq!(lower_decision, DnsRequestDecision::Reject);
    assert_eq!(upper_decision, DnsRequestDecision::AsIs);
}

fn fixed_ttl_config(key: &str) -> DnsConfig {
    let mut config = DnsConfig::default();
    config.fixed_domain_ttl.insert(key.into(), 42);
    config
}

fn exact_material_config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.upstream[0].name = "DNSMain".into();
    config.upstream[0].outbound = Some("Proxy".into());
    config.routing.request.fallback = DnsRequestAction::Upstream("DNSMain".into());
    config.routing.response.rules = vec![DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["DNSMain".into()],
        }],
        action: DnsResponseAction::Upstream("Secondary".into()),
    }];
    config
}

fn full_matcher_config(value: &str) -> DnsConfig {
    matcher_config(DnsDomainMatcher::Full(value.into()))
}

fn keyword_matcher_config(value: &str) -> DnsConfig {
    matcher_config(DnsDomainMatcher::Keyword(value.into()))
}

fn matcher_config(matcher: DnsDomainMatcher) -> DnsConfig {
    let mut config = DnsConfig::default();
    config.routing.request.rules = vec![DnsRequestRule {
        conditions: vec![DnsCond::Qname {
            not: false,
            matchers: vec![matcher],
        }],
        action: DnsRequestAction::Reject,
    }];
    config.routing.request.fallback = DnsRequestAction::AsIs;
    config
}
