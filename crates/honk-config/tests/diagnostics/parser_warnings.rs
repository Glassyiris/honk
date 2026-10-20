use honk_config::parser::parse_dae_config_with_diagnostics;

#[test]
fn parser_returns_node_skip_and_legacy_nfqueue_warnings_as_safe_data() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_diagnostics(
        include_str!("../fixtures/diagnostic_warnings.dae"),
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
    let input = include_str!("../fixtures/dns_unsupported_condition.dae");

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
    let input = include_str!("../fixtures/dns_unsupported_condition_failure.dae");

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
fn misplaced_experimental_keys_are_named_by_schema_name_only() {
    let native = "native API setting belongs inside native_api { }";
    let unknown = "unknown experimental setting";
    let nfqueue = "unknown NFQUEUE setting; only enabled is supported";
    for (input, code, setting, message) in [
        (
            "experimental {\n config_write: true\n}\n",
            "unknown-experimental-setting",
            "experimental.config_write",
            native,
        ),
        (
            "experimental {\n record_logs: false\n}\n",
            "unknown-experimental-setting",
            "experimental.record_logs",
            native,
        ),
        (
            "experimental {\n external_ui: PRIVATE_UI\n}\n",
            "unknown-experimental-setting",
            "experimental.external_ui",
            "clash API setting belongs inside clash_api { }",
        ),
        (
            "experimental {\n store_dns: true\n}\n",
            "unknown-experimental-setting",
            "experimental.store_dns",
            "cache file setting belongs inside cache_file { }",
        ),
        (
            "experimental {\n secret: PRIVATE_SECRET\n}\n",
            "unknown-experimental-setting",
            "experimental.secret",
            unknown,
        ),
        (
            "experimental {\n enabled: true\n}\n",
            "unknown-experimental-setting",
            "experimental.enabled",
            unknown,
        ),
        (
            "experimental {\n nfqueue_enable: true\n}\n",
            "unknown-experimental-setting",
            "experimental.nfqueue_enable",
            unknown,
        ),
        (
            "experimental {\n PRIVATE_KEY: true\n}\n",
            "unknown-experimental-setting",
            "experimental",
            unknown,
        ),
        (
            "experimental {\n PRIVATE_BLOCK {\n }\n}\n",
            "unknown-experimental-setting",
            "experimental",
            unknown,
        ),
        (
            "experimental {\n native_api {\n external_ui: PRIVATE_UI\n }\n}\n",
            "unknown-native-api-setting",
            "experimental.native_api.external_ui",
            "unknown native API setting",
        ),
        (
            "experimental {\n native_api {\n PRIVATE_KEY: true\n }\n}\n",
            "unknown-native-api-setting",
            "experimental.native_api",
            "unknown native API setting",
        ),
        (
            "experimental {\n udp_nfqueue {\n nfqueue_enable: true\n }\n}\n",
            "unknown-nfqueue-setting",
            "experimental.udp_nfqueue.nfqueue_enable",
            nfqueue,
        ),
        (
            "experimental {\n udp_nfqueue {\n PRIVATE_KEY: true\n }\n}\n",
            "unknown-nfqueue-setting",
            "experimental.udp_nfqueue",
            nfqueue,
        ),
    ] {
        let mut detailed = Vec::new();
        let error =
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut detailed)
                .unwrap_err();
        assert_eq!(
            (
                error.diagnostic.code,
                error.diagnostic.setting.to_string().as_str(),
                error.diagnostic.message,
            ),
            (code, setting, message),
            "{input}"
        );
        assert!(!format!("{error:?} {detailed:?}").contains("PRIVATE_"));
    }
}

#[test]
fn removed_settings_retain_safe_migration_causes() {
    for (input, path, code, replacement) in [
        (
            include_str!("../fixtures/removed_node_mux.dae"),
            "nodes.mux",
            "unsupported-node-mux",
            "mux",
        ),
        (
            include_str!("../fixtures/removed_dns_hosts_file.dae"),
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
#[test]
fn removed_vless_mode_is_terminal_at_the_dae_entry() {
    let input = "node {\n edge: 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?vless_mode=#PRIVATE'\n}";
    let mut diagnostics = Vec::new();
    let error =
        honk_config::parser::parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics)
            .unwrap_err();
    assert_eq!(error.diagnostic.code, "removed-vless-mode");
    assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].vless_mode");
    assert_eq!(error.diagnostic.entry_index, Some(1));
    assert!(!format!("{error:?} {diagnostics:?}").contains("PRIVATE"));
}

#[test]
fn recoverable_vless_rejections_keep_reasons_and_entry_sources() {
    use honk_config::diagnostic::{SafeValue, Severity};

    let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@private.example:443?pbk=PRIVATE_KEY";
    let input = format!(
        "node {{\n keep: 'socks5://127.0.0.1:1080'\n PRIVATE_ALIAS: '{uri}&allowInsecure=yes&packet-encoding=PRIVATE_VALUE#PRIVATE_NAME'\n PRIVATE_TUNING: '{uri}&mux=xray&concurrency=PRIVATE_VALUE'\n PRIVATE_VISION: '{uri}&flow=xtls-rprx-vision&mux=h2mux'\n PRIVATE_DUPLICATE: '{uri}&mux=off&mux=off'\n malformed: 'PRIVATE_SYNTAX'\n}}\n"
    );
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.dae");
    let child = dir.path().join("child.dae");
    std::fs::write(&root, "include { child.dae }\n").unwrap();
    std::fs::write(&child, &input).unwrap();

    for included in [false, true] {
        let mut diagnostics = Vec::new();
        let config = if included {
            honk_config::Config::from_file_with_detailed_diagnostics(
                root.to_str().unwrap(),
                &mut diagnostics,
            )
        } else {
            honk_config::parser::parse_dae_config_with_detailed_diagnostics(
                &input,
                &mut diagnostics,
            )
        }
        .unwrap();
        assert_eq!(
            config
                .nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["keep"]
        );
        assert_eq!(diagnostics.len(), 6, "{diagnostics:?}");
        for (diagnostic, (code, field, ordinal, reason)) in diagnostics.iter().zip([
            (
                "legacy-config-warning",
                "nodes[2].skip_cert_verify",
                2,
                "verification",
            ),
            (
                "unsupported-vless-parameter",
                "nodes[2].packet_encoding",
                2,
                "packetEncoding",
            ),
            (
                "invalid-config-value",
                "nodes[3].multiplex.tcp",
                3,
                "integer",
            ),
            ("invalid-config-value", "nodes[4].flow", 4, "path"),
            ("duplicate-vless-parameter", "nodes[5].multiplex", 5, "once"),
            ("invalid-node-entry", "nodes[6]", 6, "ignored"),
        ]) {
            assert_eq!(diagnostic.code, code);
            assert_eq!(diagnostic.setting.to_string(), field);
            assert!(diagnostic.message.contains(reason), "{diagnostic:?}");
            assert_eq!(diagnostic.entry_index, Some(ordinal));
            assert_eq!(diagnostic.line, Some(ordinal + 1));
            assert_eq!(diagnostic.byte_column, Some(2));
            assert_eq!(diagnostic.severity, Severity::Warning);
            assert!(!diagnostic.terminal);
            assert_eq!(diagnostic.value, SafeValue::Redacted);
            assert_eq!(
                &input[diagnostic.span.clone().unwrap()],
                input.lines().nth(ordinal).unwrap().trim(),
            );
            let source = &diagnostic.source;
            assert_eq!(
                source.sources().metadata()[source.index()].path.as_ref(),
                included.then_some(&child),
            );
            assert!(source.same_source(&diagnostics[0].source));
            let rendered = format!("{diagnostic:?} {:?}", diagnostic.to_legacy());
            for secret in [
                "PRIVATE_",
                "private.example",
                "b831381d-6324-4d53-ad4f-8cda48b30811",
            ] {
                assert!(!rendered.contains(secret));
            }
        }
    }
}
