use honk_config::Config;

#[test]
fn tolerated_prefixes_do_not_hide_dae_semantic_failures() {
    for prefix in ["", "ignored_top_level_statement\n", "}\n"] {
        for extension in ["", ".dae"] {
            let file = tempfile::Builder::new()
                .suffix(extension)
                .tempfile()
                .unwrap();
            std::fs::write(
                file.path(),
                format!("{prefix}global {{\n nfqueue_enable: invalid\n}}\n"),
            )
            .unwrap();
            let mut diagnostics = Vec::new();
            Config::from_file_with_detailed_diagnostics(
                file.path().to_str().unwrap(),
                &mut diagnostics,
            )
            .unwrap_err();
            assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.code == "invalid-structured-config")
            );
        }
    }
}

#[test]
fn inline_dae_semantic_failure_is_not_a_yaml_mapping() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        include_str!("fixtures/invalid_nfqueue_inline.dae"),
    )
    .unwrap();
    let mut diagnostics = Vec::new();
    Config::from_file_with_detailed_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
        .unwrap_err();
    assert_eq!(diagnostics.len(), 1);
}

#[test]
fn quoted_scalar_keeps_structured_fallback() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), include_str!("fixtures/quoted_dae_scalar.yaml")).unwrap();
    let mut diagnostics = Vec::new();
    let config = Config::from_file_with_detailed_diagnostics(
        file.path().to_str().unwrap(),
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(config.global.check_tolerance_ms, 75);
    assert!(diagnostics.is_empty());
}

#[test]
fn flow_sequence_scalar_keeps_structured_fallback_and_caller_prefix() {
    let mut prefix = Vec::new();
    honk_config::parser::parse_dae_config_with_diagnostics(
        "global {\n sniffing_timeout: 2h\n}",
        &mut prefix,
    )
    .unwrap();
    let mut configs = Vec::new();
    for extension in [".yaml", ".dae"] {
        let file = tempfile::Builder::new()
            .suffix(extension)
            .tempfile()
            .unwrap();
        std::fs::write(
            file.path(),
            include_str!("fixtures/flow_sequence_dae_scalar.yaml"),
        )
        .unwrap();
        let mut diagnostics = prefix.clone();
        let config =
            Config::from_file_with_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
                .unwrap();
        assert_eq!(config.global.check_tolerance_ms, 75);
        assert_eq!(diagnostics, prefix);
        configs.push(config);
    }
    assert_eq!(configs[0], configs[1]);
}
