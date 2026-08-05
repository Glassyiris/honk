use std::time::Duration;

use super::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};

#[test]
fn typed_outcome_exposes_projection_metadata_when_upstream_is_accepted() {
    // Given
    let expiry = EffectiveExpiry::cacheable(Duration::from_secs(42));

    // When
    let outcome = DnsOutcome::metadata_for_test(
        OutcomeStatus::Accepted,
        ResponseClass::Positive,
        Provenance::Upstream,
        expiry,
        "primary",
        "secondary",
        &["primary", "secondary"],
        vec!["192.0.2.1".parse().expect("IP")],
        vec![0x12, 0x34],
    );

    // Then
    assert_eq!(outcome.status(), OutcomeStatus::Accepted);
    assert_eq!(outcome.response_class(), ResponseClass::Positive);
    assert_eq!(outcome.provenance(), Provenance::Upstream);
    assert_eq!(outcome.expiry().ttl(), Duration::from_secs(42));
    assert_eq!(outcome.logical_upstream(), Some("primary"));
    assert_eq!(outcome.final_upstream(), Some("secondary"));
    assert_eq!(outcome.requery_history(), &["primary", "secondary"]);
    assert_eq!(outcome.domain(), "example.com");
    assert_eq!(
        outcome.answer_ips(),
        &["192.0.2.1".parse::<std::net::IpAddr>().expect("IP")]
    );
    assert_eq!(outcome.rendered(), &[0x12, 0x34]);
}

#[test]
fn fixed_zero_expiry_is_explicitly_not_cacheable() {
    // Given
    let expiry = EffectiveExpiry::do_not_cache();

    // When
    let cacheable = expiry.is_cacheable();

    // Then
    assert!(!cacheable);
    assert_eq!(expiry.ttl(), Duration::ZERO);
}
