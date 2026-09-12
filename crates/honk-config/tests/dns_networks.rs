use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

#[test]
fn dns_network_admission_rejects_whole_rule_and_reports_host_bits() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics("dns {\n routing {\n response {\n ip(192.0.2.1, PRIVATE_INVALID) -> reject\n ip(192.0.2.17/24, 2001:db8::1, 192.0.2.1) -> reject\n }\n }\n}", &mut diagnostics).unwrap();
    assert_eq!(config.dns.routing.response.rules.len(), 1);
    assert!(diagnostics.iter().any(|d| d.code == "invalid-dns-network"
        && d.line == Some(4)
        && d.setting.to_string() == "dns.routing.response.rules[1]"));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "dns-network-host-bits" && d.line == Some(5))
    );
    assert!(!format!("{diagnostics:?}").contains("PRIVATE_INVALID"));
}
