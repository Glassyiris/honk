use honk_config::{
    Config,
    config::ConfigSeed,
    diagnostic::{DiagnosticSources, SafeValue},
};
use serde::de::DeserializeSeed;

#[test]
fn ineffective_group_option_is_safe_data_for_structured_formats() {
    let mut config = Config::default();
    config.groups.push(honk_config::node::Group {
        name: "PRIVATE_GROUP".into(),
        interrupt_connections: true,
        ..Default::default()
    });
    let mut constructed = Vec::new();
    let source = DiagnosticSources::new(None).root();
    config.append_diagnostics(source.clone(), &mut constructed);
    config.append_diagnostics(source, &mut constructed);
    assert_eq!(constructed.len(), 1);
    assert_eq!(constructed[0].code, "ineffective-option");
    for (extension, body) in [
        ("json", serde_json::to_string(&config).unwrap()),
        ("yaml", serde_yaml::to_string(&config).unwrap()),
        ("toml", toml::to_string(&config).unwrap()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("config.{extension}"));
        std::fs::write(&path, body).unwrap();
        let mut diagnostics = Vec::new();
        Config::from_file_with_detailed_diagnostics(path.to_str().unwrap(), &mut diagnostics)
            .unwrap();
        let warning = diagnostics
            .iter()
            .find(|d| d.code == "ineffective-option")
            .unwrap();
        assert_eq!(
            warning.setting.to_string(),
            "groups[1].interrupt_connections"
        );
        assert_eq!(warning.entry_index, Some(1));
        assert!(!format!("{diagnostics:?}").contains("PRIVATE_GROUP"));
    }
}

#[test]
fn api_exposure_warning_covers_custom_binds_without_values() {
    for (bind, secret, expected) in [
        ("", "", false),
        ("127.0.0.1:9090", "", false),
        ("[::1]:9090", "", false),
        (":9090", "", true),
        ("192.0.2.221:9090", "", true),
        ("[2001:db8::221]:9090", "", true),
        ("0.0.0.0:9090", "PRIVATE_SECRET", false),
    ] {
        let body = serde_json::json!({"experimental": {"clash_api": {"external_controller": bind, "secret": secret}}}).to_string();
        let mut diagnostics = Vec::new();
        ConfigSeed {
            diagnostics: &mut diagnostics,
            source: DiagnosticSources::new(None).root(),
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&body))
        .unwrap();
        assert_eq!(
            diagnostics
                .iter()
                .filter(|d| d.code == "unsafe-api-bind")
                .count(),
            usize::from(expected)
        );
        if expected {
            assert_eq!(
                diagnostics[0].setting.to_string(),
                "experimental.clash_api.external_controller"
            );
        }
        let text = format!("{diagnostics:?}");
        assert!(
            !text.contains("PRIVATE_SECRET")
                && !text.contains("9090")
                && !text.contains("192.0.2")
                && !text.contains("2001:db8")
        );
    }
}

#[test]
fn included_api_warning_keeps_the_winning_field_source() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.dae");
    let child = dir.path().join("api.dae");
    std::fs::write(
        &root,
        "include {\n api.dae\n}\nexperimental {\n cache_file {\n enabled: false\n }\n}\n",
    )
    .unwrap();
    std::fs::write(
        &child,
        "experimental {\n clash_api {\n external_controller: '192.0.2.221:9090'\n }\n}\n",
    )
    .unwrap();
    let mut diagnostics = Vec::new();
    Config::from_file_with_detailed_diagnostics(root.to_str().unwrap(), &mut diagnostics).unwrap();
    let warning = diagnostics
        .iter()
        .find(|d| d.code == "unsafe-api-bind")
        .unwrap();

    let sources = warning.source.sources().metadata();
    assert_eq!(sources[warning.source.index()].path.as_ref(), Some(&child));
    assert_eq!(warning.line, Some(3));
}

fn assert_warning_precedes_terminal(
    diagnostics: &[honk_config::diagnostic::DetailedDiagnostic],
    code: &str,
) {
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.terminal)
            .count(),
        1
    );
    assert_eq!(diagnostics[0].code, code);
    assert!(!diagnostics[0].terminal);
    assert!(matches!(&diagnostics[0].value, SafeValue::Redacted));
    assert!(diagnostics[1].terminal);
}

#[test]
fn group_warning_survives_later_structured_node_failure() {
    let input = r#"{
        "groups": [
            {
                "name": "g",
                "interrupt_connections": true
            }
        ],
        "nodes": [{}]
    }"#;
    let mut diagnostics = Vec::new();
    assert!(Config::from_json_str_with_detailed_diagnostics(input, &mut diagnostics).is_err());
    assert_warning_precedes_terminal(&diagnostics, "ineffective-option");
    assert_eq!(
        diagnostics[0].setting.to_string(),
        "groups[1].interrupt_connections"
    );
    assert_eq!(diagnostics[0].entry_index, Some(1));
}

#[test]
fn api_warning_survives_later_structured_node_failure() {
    let input = r#"{
        "experimental": {
            "clash_api": {
                "external_controller": "0.0.0.0:9090"
            }
        },
        "nodes": [{}]
    }"#;
    let mut diagnostics = Vec::new();
    assert!(Config::from_json_str_with_detailed_diagnostics(input, &mut diagnostics).is_err());
    assert_warning_precedes_terminal(&diagnostics, "unsafe-api-bind");
    assert_eq!(
        diagnostics[0].setting.to_string(),
        "experimental.clash_api.external_controller"
    );
    let rendered = format!("{diagnostics:?}");
    assert!(!rendered.contains("0.0.0.0:9090"));
}

#[test]
fn group_warning_survives_later_sequence_subscription_failure() {
    let input = serde_json::json!([
        {},
        {},
        {},
        [],
        [{"name": "g", "interrupt_connections": true}],
        [{}],
        {}
    ])
    .to_string();
    let mut diagnostics = Vec::new();
    assert!(Config::from_json_str_with_detailed_diagnostics(&input, &mut diagnostics).is_err());
    assert_warning_precedes_terminal(&diagnostics, "ineffective-option");
}
