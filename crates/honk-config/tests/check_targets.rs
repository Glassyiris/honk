use honk_config::{Config, parser::parse_dae_config_with_detailed_diagnostics};

#[test]
fn malformed_udp_dns_targets_fail_located_admission() {
    for value in [
        "[::1",
        "[::1]junk",
        "resolver.test:PRIVATE",
        "resolver.test:0",
        "resolver.test:65536",
        ":53",
        "resolver.test:",
    ] {
        let mut config = Config::default();
        config.global.udp_check_dns = vec![value.into()];
        assert!(config.validate().is_err(), "{value}");
        let mut diagnostics = Vec::new();
        let error = parse_dae_config_with_detailed_diagnostics(
            &format!("global {{\n udp_check_dns: {value}\n}}"),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.code, "invalid-dns-check-target");
        assert_eq!(
            error.diagnostic.setting.to_string(),
            "global.udp_check_dns[1]"
        );
        assert_eq!(error.diagnostic.line, Some(2));
        assert!(!format!("{diagnostics:?}{error:?}").contains("PRIVATE"));
    }
}

#[test]
fn http_targets_preserve_caller_defaults_and_authority_boundaries() {
    use honk_config::check::{decode_health_http_target, decode_http_check_target};
    for (input, host, port, path) in [
        ("http://host,1.1.1.1,::1", "host", 80, "/"),
        ("host/generate_204", "host", 80, "/generate_204"),
        (
            "host/path?next=https://other/",
            "host",
            80,
            "/path?next=https://other/",
        ),
        (
            "http://u:PRIVATE@host:8080/path?q#fragment",
            "host",
            8080,
            "/path?q",
        ),
        ("https://host?q=1", "host", 443, "/?q=1"),
        (
            "http://host/a/../health?q=1",
            "host",
            80,
            "/a/../health?q=1",
        ),
        (
            "http://host/a/%2e%2e/health?q=1",
            "host",
            80,
            "/a/%2e%2e/health?q=1",
        ),
        ("[::1]:8080/path", "::1", 8080, "/path"),
        ("https://[::1]/", "::1", 443, "/"),
    ] {
        let target = decode_health_http_target(input).unwrap();
        assert_eq!(
            (target.host(), target.port(), target.request_target()),
            (host, port, path)
        );
    }
    for (input, expected) in [
        ("http://host", "host"),
        ("http://host:80", "host"),
        ("http://host:8080", "host:8080"),
        ("https://host:443", "host"),
        ("https://host:8443", "host:8443"),
        ("http://[::1]", "[::1]"),
        ("http://[::1]:8080", "[::1]:8080"),
    ] {
        assert_eq!(
            decode_health_http_target(input).unwrap().authority(),
            expected,
            "{input}"
        );
    }
    assert_eq!(
        decode_http_check_target("host/check", true).unwrap().port(),
        443
    );
    for input in ["", "https://", "http://[::1", "http://host:bad/"] {
        assert!(decode_health_http_target(input).is_err());
    }
}

#[test]
fn http_targets_reject_ambiguous_authorities_before_exposing_userinfo() {
    use honk_config::check::decode_http_check_target;
    for input in [
        "http:///user:PRIVATE@example.invalid/health",
        "https:////user:PRIVATE@example.invalid/health",
        r"http://\user:PRIVATE@example.invalid/health",
        "http://example.invalid/health\r\nX-Private: secret",
    ] {
        assert!(decode_http_check_target(input, false).is_err(), "{input:?}");
    }
}
