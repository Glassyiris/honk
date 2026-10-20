use honk_config::diagnostic::SafeValue;
use honk_config::{Config, ConfigDiagnostic};

fn node_fixture() -> serde_json::Value {
    let mut node: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/node_incompatible.json")).unwrap();
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
fn structured_loaders_ignore_removed_native_destination_keys_with_warnings() {
    let root = serde_json::json!({"experimental": {"native_api": {
        "record_flows": false,
        "probe_allowed_cidrs": {"PRIVATE": false},
        "probe_allowed_ports": [0, 65536, "PRIVATE"]
    }}});
    for (extension, text) in [
        ("json", serde_json::to_string(&root).unwrap()),
        ("yaml", serde_yaml::to_string(&root).unwrap()),
        ("toml", toml::to_string(&root).unwrap()),
        ("dae", serde_json::to_string(&root).unwrap()),
    ] {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), text).unwrap();
        let mut diagnostics = Vec::new();
        let config = Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut diagnostics,
        )
        .unwrap();
        assert!(!config.experimental.native_api.record_flows);
        assert_eq!(diagnostics.len(), 2, "{extension}: {diagnostics:?}");
        for key in ["probe_allowed_cidrs", "probe_allowed_ports"] {
            let notice = diagnostics
                .iter()
                .find(|notice| {
                    notice.setting.to_string() == format!("experimental.native_api.{key}")
                })
                .unwrap();
            assert_eq!(notice.code, "legacy-config-warning");
            assert_eq!(notice.severity, honk_config::diagnostic::Severity::Warning);
            assert!(
                notice.message.contains("removed") && notice.message.contains("can be deleted")
            );
            assert!(!serde_json::to_string(&config).unwrap().contains(key));
        }
        assert!(!format!("{diagnostics:?}").contains("PRIVATE"));
    }
    let invalid = r#"{"experimental":{"native_api":{"record_flows":"PRIVATE"}}}"#;
    let error =
        Config::from_json_str_with_detailed_diagnostics(invalid, &mut Vec::new()).unwrap_err();
    assert_eq!(error.diagnostic.setting.to_string(), "experimental");
    let input = r#"{"experimental":{"native_api":{"probe_allowed_cidrs":null,"probe_allowed_ports":null}}}"#;
    let mut diagnostics = Vec::new();
    Config::from_json_str_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
    assert_eq!(diagnostics.len(), 2);
    assert!(
        Config::from_json_str(r#"{"experimental":{"native_api":{"probe_allowed_port":[]}}}"#)
            .is_err()
    );
}

#[test]
fn structured_loaders_record_explicit_group_option_presence() {
    let root = serde_json::json!({"groups": [
        {"name": "set", "policy": "urltest", "tolerance": 7, "interrupt_connections": true},
        {"name": "unset", "policy": "urltest"}
    ]});
    for (extension, text) in [
        ("json", serde_json::to_string(&root).unwrap()),
        ("yaml", serde_yaml::to_string(&root).unwrap()),
        ("toml", toml::to_string(&root).unwrap()),
    ] {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), text).unwrap();
        let config = Config::from_file(file.path().to_str().unwrap()).unwrap();
        let own = |index: usize| config.groups[index].own;
        assert_eq!(config.groups[0].tolerance, 7, "{extension}");
        assert!(
            own(0).tolerance && own(0).interrupt_connections,
            "{extension}"
        );
        assert!(
            !own(1).tolerance && !own(1).interrupt_connections,
            "{extension}"
        );
    }
    let config = Config::from_json_str(&serde_json::to_string(&root).unwrap()).unwrap();
    assert!(config.groups[0].own.tolerance && !config.groups[1].own.tolerance);
}

#[test]
fn structured_group_field_failure_names_the_field() {
    let root = serde_json::json!({"groups": [
        {"name": "fine"},
        {"name": "bad", "policy": "PRIVATE_POLICY"}
    ]});
    for (extension, text) in [
        ("json", serde_json::to_string(&root).unwrap()),
        ("yaml", serde_yaml::to_string(&root).unwrap()),
        ("toml", toml::to_string(&root).unwrap()),
    ] {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        std::fs::write(file.path(), text).unwrap();
        let error = Config::from_file_with_detailed_diagnostics(
            file.path().to_str().unwrap(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(
            error.diagnostic.setting.to_string(),
            "groups[2].policy",
            "{extension}"
        );
        assert!(!format!("{error:?}").contains("PRIVATE_POLICY"));
    }
}

#[test]
fn rewriting_a_structured_config_keeps_unset_group_options_unset() {
    let root = serde_json::json!({"groups": [
        {"name": "set", "policy": "urltest", "tolerance": 7, "interrupt_connections": false},
        {"name": "unset", "policy": "urltest"}
    ]});
    for extension in ["json", "yaml", "toml"] {
        let file = tempfile::Builder::new()
            .suffix(&format!(".{extension}"))
            .tempfile()
            .unwrap();
        let path = file.path().to_str().unwrap();
        let source = Config::from_json_str(&root.to_string()).unwrap();
        source.to_file(path).unwrap();
        let config = Config::from_file(path).unwrap();
        let own = |index: usize| config.groups[index].own;
        assert!(
            own(0).tolerance && own(0).interrupt_connections,
            "{extension}"
        );
        assert!(
            !own(1).tolerance && !own(1).interrupt_connections,
            "{extension}"
        );
        assert_eq!(config.groups[0].tolerance, 7, "{extension}");
        assert!(!config.groups[0].interrupt_connections, "{extension}");
    }
}

#[test]
fn legacy_cache_file_keys_warn_in_dae_and_structured_input() {
    let dae = "experimental { cache_file { enabled: true\n path: 'cache.db' }\n cache_file { cache_id: 'gw' } }\n";
    let mut diagnostics = Vec::new();
    honk_config::parser::parse_dae_config_with_detailed_diagnostics(dae, &mut diagnostics).unwrap();
    let warned = |diagnostics: &[honk_config::diagnostic::DetailedDiagnostic]| {
        diagnostics
            .iter()
            .filter(|d| d.code == "legacy-cache-file")
            .map(|d| d.setting.to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        warned(&diagnostics),
        [
            "experimental.cache_file.path",
            "experimental.cache_file.cache_id"
        ]
    );

    let file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
    std::fs::write(
        file.path(),
        "[experimental.cache_file]\nenabled = true\npath = \"cache.db\"\ncache_id = \"gw\"\n",
    )
    .unwrap();
    let mut diagnostics = Vec::new();
    let config = Config::from_file_with_detailed_diagnostics(
        file.path().to_str().unwrap(),
        &mut diagnostics,
    )
    .unwrap();
    assert_eq!(
        warned(&diagnostics),
        [
            "experimental.cache_file.path",
            "experimental.cache_file.cache_id"
        ]
    );
    assert_eq!(
        config.experimental.cache_file.legacy_cache_file(),
        (Some("cache.db"), Some("gw"))
    );
    let serialized = serde_json::to_value(&config.experimental.cache_file).unwrap();
    assert_eq!(
        serialized,
        serde_json::json!({"enabled": true, "store_dns": false})
    );
}

#[test]
fn failed_fallback_retains_attempts_and_only_one_terminal() {
    let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    std::fs::write(
        file.path(),
        include_str!("../fixtures/config_failed_second_port.json"),
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
        serde_json::from_str(include_str!("../fixtures/config_failed_second_port.json")).unwrap();
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
    let input = include_str!("../fixtures/config_failed_group.json");
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
#[test]
fn removed_vless_mode_preserves_indexed_safe_diagnostics() {
    for removed in [serde_json::json!("legacy"), serde_json::Value::Null] {
        let input = serde_json::json!({
            "nodes": [{
                "name": "vless",
                "protocol": "vless",
                "address": "private.example:443",
                "host": "private.example",
                "port": 443,
                "password": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "vless_mode": removed,
            }]
        });
        let mut diagnostics = Vec::new();
        let error =
            Config::from_json_str_with_detailed_diagnostics(&input.to_string(), &mut diagnostics)
                .unwrap_err();
        assert_eq!(error.diagnostic.setting.to_string(), "nodes[1].vless_mode");
        assert_eq!(error.diagnostic.entry_index, Some(1));
        assert_eq!(error.diagnostic.value, SafeValue::Redacted);
        assert!(!format!("{error:?} {diagnostics:?}").contains("private.example"));
    }
}
