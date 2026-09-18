use super::*;

#[test]
fn query_parameters_reject_semantic_duplicates_and_name_wire_overflow() {
    let id = RequestId("dns-test".into());
    for query in [
        "type=A&type=TYPE1",
        "type=1&type=A",
        "domain=a&domain=b",
        "type=A&unknown=x",
    ] {
        let uri: Uri = format!("/api/v1/dns/query?{query}").parse().unwrap();
        assert!(parameters(&uri, &["domain", "type"], &id).is_err());
    }
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert!(validate_name(&maximum));
    assert!(!validate_name(&format!("{maximum}x")));
    assert!(!validate_name(&format!("{}.example", "x".repeat(64))));
    assert!(!validate_name("example..com"));
    assert!(!validate_name("example.com.."));
    assert_eq!(canonical_name("EXAMPLE.Com.", &id).unwrap(), "example.com.");
    for name in [".", "example.com."] {
        let query = crate::dns::forwarder::build_dns_query(name, 1);
        assert!(crate::dns::query::QueryContext::parse(&query).is_ok());
    }
}
