use honk_config::parser::parse_dae_config_with_diagnostics;

#[test]
fn parser_returns_node_skip_and_legacy_nfqueue_warnings_as_safe_data() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        include_str!("fixtures/diagnostic_warnings.dae"),
        &mut diagnostics,
    )
    .unwrap();
    assert!(config.nodes.is_empty());
    assert!(!config.global.nfqueue_enable);
    assert_eq!(config.global.check_tolerance_ms, 50);
    assert_eq!(diagnostics.len(), 3, "{diagnostics:?}");
    assert!(!format!("{diagnostics:?}").contains("secret"));
}
#[test]
fn dns_unsupported_conditions_are_safe_data_on_success() {
    let input = include_str!("fixtures/dns_unsupported_condition.dae");

    let mut detailed = Vec::new();
    let config =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut detailed)
            .unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    assert_eq!(config.dns.routing.response.rules.len(), 1);

    let warnings = detailed
        .iter()
        .filter(|diagnostic| diagnostic.code == "unsupported-dns-condition")
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 2, "{detailed:?}");
    assert_eq!(
        warnings[0].setting.to_string(),
        "dns.routing.request.rules[1]"
    );
    assert_eq!(warnings[0].entry_index, Some(1));
    assert_eq!(warnings[0].line, Some(4));
    assert_eq!(
        warnings[1].setting.to_string(),
        "dns.routing.response.rules[1]"
    );
    assert_eq!(warnings[1].entry_index, Some(1));
    assert_eq!(warnings[1].line, Some(8));
    assert!(!format!("{detailed:?}").contains("PRIVATE_"));

    let mut legacy = Vec::new();
    honk_config::parser::parse_dae_config_with_diagnostics(input, &mut legacy).unwrap();
    assert_eq!(legacy.len(), 2, "{legacy:?}");
    assert!(legacy.iter().all(|diagnostic| {
        diagnostic.setting.ends_with(".rules[1]")
            && diagnostic.value == "1"
            && !diagnostic.message.contains("PRIVATE_")
    }));
    assert!(!format!("{legacy:?}").contains("PRIVATE_"));
}

#[test]
fn dns_unsupported_conditions_are_retained_before_failure() {
    let input = include_str!("fixtures/dns_unsupported_condition_failure.dae");

    let mut detailed = Vec::new();
    let error =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut detailed)
            .unwrap_err();
    assert!(detailed.iter().any(|diagnostic| {
        diagnostic.code == "unsupported-dns-condition"
            && diagnostic.setting.to_string() == "dns.routing.request.rules[1]"
    }));
    assert!(detailed.iter().any(|diagnostic| {
        diagnostic.code == "unsupported-dns-condition"
            && diagnostic.setting.to_string() == "dns.routing.response.rules[1]"
    }));
    assert!(detailed.iter().any(|diagnostic| diagnostic.terminal));
    assert!(!format!("{detailed:?}").contains("PRIVATE_"));
    assert!(!format!("{error:?}").contains("PRIVATE_"));

    let mut legacy = Vec::new();
    let error =
        honk_config::parser::parse_dae_config_with_diagnostics(input, &mut legacy).unwrap_err();
    assert_eq!(
        legacy
            .iter()
            .filter(|diagnostic| diagnostic.setting.ends_with(".rules[1]"))
            .count(),
        2
    );
    assert!(!format!("{legacy:?}").contains("PRIVATE_"));
    assert!(!format!("{error:?}").contains("PRIVATE_"));
}

#[test]
fn removed_settings_retain_safe_migration_causes() {
    for (input, path, code, replacement) in [
        (
            include_str!("fixtures/removed_node_mux.dae"),
            "nodes.mux",
            "unsupported-node-mux",
            "vless_mode",
        ),
        (
            include_str!("fixtures/removed_dns_hosts_file.dae"),
            "dns.hosts_file",
            "removed-dns-hosts-file",
            "use_host",
        ),
    ] {
        let mut diagnostics = Vec::new();
        let error = honk_config::parser::parse_dae_config_with_detailed_diagnostics(
            input,
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.code, code);
        assert_eq!(error.diagnostic.setting.to_string(), path);
        assert!(error.diagnostic.message.contains(replacement));
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        assert!(error.into_legacy().to_string().contains(replacement));
    }
}
