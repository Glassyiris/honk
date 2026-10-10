use super::*;

#[test]
fn parse_pin_sha256_variants() {
    let hex = "a".repeat(64);
    assert!(parse_pin_sha256(&hex).is_some());
    let colon = (0..32).map(|_| "ab").collect::<Vec<_>>().join(":");
    assert!(parse_pin_sha256(&colon).is_some());
    assert_eq!(parse_pin_sha256(&colon).unwrap(), [0xab; 32]);
    assert!(parse_pin_sha256("zz").is_none());
    assert!(parse_pin_sha256("abcd").is_none());
    // Uppercase hex is valid.
    assert!(parse_pin_sha256(&"AB".repeat(32)).is_some());
}

/// P0: an unparseable pinSHA256 must fail closed — never silently
/// degrade to plain PKI.
#[test]
fn invalid_pin_fails_closed() {
    let mut node = Node {
        name: "pinned".into(),
        host: "example.com".into(),
        address: "example.com:443".into(),
        port: 443,
        outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
        ..Default::default()
    };
    node.tls_mut().unwrap().pin_sha256 = Some("not-a-pin".into());
    let err = build_connector(&node).unwrap_err();
    assert!(
        err.to_string().contains("invalid tls_pin_sha256"),
        "bad pin must be a hard error: {err}"
    );

    let node = Node::from_share_link("trojan://pw@example.com:443?pinSHA256=").unwrap();
    assert!(build_connector(&node).is_err());
}

#[test]
fn non_tls_node_connector_returns_error() {
    let node = Node {
        name: "direct".into(),
        outbound: honk_config::node::OutboundConfig::Direct,
        ..Default::default()
    };
    let error = build_connector(&node).unwrap_err();
    assert!(error.to_string().contains("has no TLS options"), "{error}");
}
