use honk_config::diagnostic::SafeValue;
use honk_config::{Config, ConfigDiagnostic};

fn node_fixture() -> serde_json::Value {
    let mut node: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/node_incompatible.json")).unwrap();
    node.as_object_mut().unwrap().remove("tls_alpn");
    node
}

#[test]
fn structured_loaders_preserve_prefix_and_return_node_warnings() {
    let root = serde_json::json!({"nodes": [node_fixture()]});
    let formats = [
        ("json", serde_json::to_string(&root).unwrap()),
        ("yaml", serde_yaml::to_string(&root).unwrap()),
        ("toml", toml::to_string(&root).unwrap()),
        ("dae", serde_json::to_string(&root).unwrap()),
    ];
    for (extension, text) in formats {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), text).unwrap();
        let prefix = ConfigDiagnostic {
            setting: "caller".into(),
            value: "prefix".into(),
            message: "keep".into(),
        };
        let mut diagnostics = vec![prefix.clone()];
        let config =
            Config::from_file_with_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
                .unwrap();
        assert_eq!(config.nodes[0].host, "secret-endpoint");
        assert_eq!(diagnostics[0], prefix);
        assert_eq!(diagnostics.len(), 2, "{extension}: {diagnostics:?}");
        assert!(!format!("{:?}", &diagnostics[1..]).contains("secret"));
    }
}

#[test]
fn failed_fallback_retains_attempts_and_only_one_terminal() {
    let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    std::fs::write(
        file.path(),
        include_str!("fixtures/config_failed_second_port.json"),
    )
    .unwrap();
    let mut diagnostics = Vec::new();
    Config::from_file_with_detailed_diagnostics(file.path().to_str().unwrap(), &mut diagnostics)
        .unwrap_err();
    assert_eq!(
        diagnostics.iter().map(|d| d.code).collect::<Vec<_>>(),
        [
            "incompatible-node-fields",
            "invalid-structured-config",
            "invalid-structured-config",
            "incompatible-node-fields",
            "invalid-structured-config",
        ]
    );
    assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
    assert!(diagnostics.last().unwrap().terminal);
    let terminal = diagnostics.last().unwrap();
    assert_eq!(terminal.setting.to_string(), "nodes[2].port");
    assert_eq!(terminal.entry_index, Some(2));
    assert!(terminal.line.is_some());
    assert!(terminal.byte_column.is_some());
    assert_eq!(terminal.value, SafeValue::Redacted);
    assert!(diagnostics[0].source.same_table(&diagnostics[1].source));
    assert!(!diagnostics[1].source.same_table(&diagnostics[2].source));
    assert!(!format!("{diagnostics:?}").contains("private-port"));
}

#[test]
fn failed_fallback_keeps_the_indexed_cause_over_later_syntax_errors() {
    let root: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/config_failed_second_port.json")).unwrap();
    for (extension, text) in [
        ("yaml", serde_yaml::to_string(&root).unwrap()),
        ("toml", toml::to_string(&root).unwrap()),
    ] {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), text).unwrap();
        let mut diagnostics = Vec::new();
        let error = Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[2].port");
        assert_eq!(error.diagnostic.entry_index, Some(2));
        assert!(error.diagnostic.line.is_some());
        let causes = diagnostics
            .iter()
            .filter(|d| d.code == "invalid-structured-config")
            .collect::<Vec<_>>();
        assert_eq!(causes.len(), 3, "{extension}: {diagnostics:?}");
        for (index, cause) in causes.iter().enumerate() {
            assert!(
                causes[..index]
                    .iter()
                    .all(|earlier| !earlier.source.same_table(&cause.source)),
                "{extension}: each attempted format must contribute one cause"
            );
        }
        assert_eq!(causes.iter().filter(|cause| cause.terminal).count(), 1);
        let terminal = causes
            .iter()
            .find(|diagnostic| diagnostic.terminal)
            .expect("selected format cause is terminal");
        assert_eq!(
            causes
                .iter()
                .filter(|diagnostic| diagnostic.setting == terminal.setting)
                .count(),
            1,
            "{extension}: selected terminal cause must render once"
        );
        assert!(!format!("{diagnostics:?}").contains("private-port"));
    }
}

#[test]
fn structured_group_failure_retains_original_index_in_map_and_sequence_forms() {
    let input = include_str!("fixtures/config_failed_group.json");
    let mut sequence = serde_json::to_value(Config::default()).unwrap();
    sequence["groups"] =
        serde_json::from_str::<serde_json::Value>(input).unwrap()["groups"].clone();
    let sequence = [
        "global",
        "dns",
        "routing",
        "nodes",
        "groups",
        "subscriptions",
        "experimental",
    ]
    .map(|field| sequence[field].take());
    for text in [input.to_owned(), serde_json::to_string(&sequence).unwrap()] {
        let mut diagnostics = Vec::new();
        let error =
            Config::from_json_str_with_detailed_diagnostics(&text, &mut diagnostics).unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), "groups[1]");
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert!(error.diagnostic.line.is_some());
        assert_eq!(diagnostics.iter().filter(|d| d.terminal).count(), 1);
        assert!(!format!("{error:?} {diagnostics:?}").contains("PRIVATE_GROUP_VALUE"));
    }
}
