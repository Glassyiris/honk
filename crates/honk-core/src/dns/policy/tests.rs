use honk_config::dns::{
    DnsCond, DnsConfig, DnsDomainMatcher, DnsRequestAction, DnsRequestRule, DnsResponseAction,
    DnsResponseRule,
};
use honk_config::types::DnsProtocol;

use super::*;

fn representative_config() -> DnsConfig {
    let mut config = DnsConfig::default();
    config.upstream[0].address = "DNS.Google".into();
    config.upstream[0].tls_server_name = Some("DNS.Google.".into());
    config.routing.request.rules = vec![DnsRequestRule {
        conditions: vec![
            DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Suffix(".Example.COM.".into())],
            },
            DnsCond::Qtype {
                not: false,
                types: vec![1, 28],
            },
        ],
        action: DnsRequestAction::Upstream("DEFAULT".into()),
    }];
    config.fixed_domain_ttl.insert("Example.COM.".into(), 42);
    config
}

#[test]
fn dns_v2_persistence_cache_identity_matches_external_golden_contract() {
    // Given
    // This externally versioned `dns:v2` byte vector is persisted and used as
    // cache identity; it intentionally does not derive expectations from the
    // encoder implementation under test.
    let first = representative_config();
    let second = representative_config();

    // When
    let first_id = PolicyId::from_config(&first).expect("valid policy");
    let second_id = PolicyId::from_config(&second).expect("valid policy");

    // Then
    assert_eq!(first_id, second_id);
    assert_eq!(
        first_id.digest_hex(),
        "28a5f74cae8c9867b3de9f69057a14b967e8d5679257f292f2b271006d5fc483"
    );
    assert_eq!(
        hex(first_id.canonical_bytes()),
        "020000000000000001000000000000000764656661756c7400000000000000000a646e732e676f6f676c6500350000000000000000000000000000000a646e732e676f6f676c6500000000000000000100000000000000020000000000000000000101000000000000000c6578616d706c652e636f6d2e010000000000000000020001001c02000000000000000744454641554c5402000000000000000764656661756c74000000000000000000040000000000000001000000000000000c4578616d706c652e434f4d2e0000002a01000000000000025800000000000027100000000000000e100000001e"
    );
}

#[test]
fn canonical_policy_normalizes_equivalent_endpoint_spellings() {
    // Given
    let first = representative_config();
    let mut second = representative_config();
    second.upstream[0].address = "dns.google:53".into();
    second.upstream[0].tls_server_name = Some("dns.google".into());

    // When
    let first_id = PolicyId::from_config(&first).expect("valid policy");
    let second_id = PolicyId::from_config(&second).expect("valid policy");

    // Then
    assert_eq!(first_id, second_id);
}

#[test]
fn semantic_policy_fields_change_identity() {
    // Given
    let base = representative_config();
    let base_id = PolicyId::from_config(&base).expect("valid policy");
    let mut variants = Vec::new();
    let mut changed = base.clone();
    changed.cache.enabled = false;
    variants.push(changed);
    let mut changed = base.clone();
    changed.cache.ttl += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.cache.max_size += 1;
    variants.push(changed);
    let mut changed = base.clone();
    changed.strategy = honk_config::dns::DnsStrategy::Ipv4Only;
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.request.rules[0].action = DnsRequestAction::Reject;
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].outbound = Some("proxy".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].address = "1.1.1.1".into();
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].protocol = DnsProtocol::Tcp;
    variants.push(changed);
    let mut changed = base.clone();
    changed.upstream[0].tls_server_name = Some("other.test".into());
    variants.push(changed);
    let mut changed = base.clone();
    changed.routing.response.fallback = DnsResponseAction::Reject;
    variants.push(changed);
    let mut changed = base.clone();
    changed.fixed_domain_ttl.insert("other.test".into(), 7);
    variants.push(changed);

    // When
    let ids = variants
        .iter()
        .map(PolicyId::from_config)
        .collect::<Result<Vec<_>, _>>()
        .expect("valid variants");

    // Then
    assert!(ids.iter().all(|id| id != &base_id));
}

#[test]
fn request_and_response_rule_order_change_identity() {
    // Given
    let mut base = representative_config();
    base.routing.request.rules.push(DnsRequestRule {
        conditions: vec![],
        action: DnsRequestAction::Reject,
    });
    base.routing.response.rules = vec![
        DnsResponseRule {
            conditions: vec![],
            action: DnsResponseAction::Accept,
        },
        DnsResponseRule {
            conditions: vec![],
            action: DnsResponseAction::Reject,
        },
    ];
    let mut request_swapped = base.clone();
    request_swapped.routing.request.rules.swap(0, 1);
    let mut response_swapped = base.clone();
    response_swapped.routing.response.rules.swap(0, 1);

    // When
    let base_id = PolicyId::from_config(&base).expect("base");
    let request_id = PolicyId::from_config(&request_swapped).expect("request");
    let response_id = PolicyId::from_config(&response_swapped).expect("response");

    // Then
    assert_ne!(base_id, request_id);
    assert_ne!(base_id, response_id);
}

#[test]
fn malformed_endpoint_is_rejected() {
    // Given
    let mut config = representative_config();
    config.upstream[0].address = "[invalid".into();

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidEndpoint { .. })));
}

#[test]
fn malformed_cidr_is_rejected() {
    // Given
    let mut config = representative_config();
    config.routing.request.rules[0]
        .conditions
        .push(DnsCond::Ip {
            not: false,
            cidrs: vec!["invalid".into()],
            geoip: vec![],
        });

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidCidr { .. })));
}

#[test]
fn malformed_regex_is_rejected() {
    // Given
    let mut config = representative_config();
    config.routing.request.rules[0]
        .conditions
        .push(DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Regex("(".into())],
        });

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::InvalidRegex { .. })));
}

#[test]
fn empty_fixed_ttl_domain_is_rejected() {
    // Given
    let mut config = representative_config();
    config.fixed_domain_ttl.insert(String::new(), 7);

    // When
    let result = PolicyId::from_config(&config);

    // Then
    assert!(matches!(result, Err(PolicyError::EmptyName { .. })));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
