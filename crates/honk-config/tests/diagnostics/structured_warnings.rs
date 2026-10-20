use honk_config::{
    Config,
    config::ConfigSeed,
    diagnostic::{DiagnosticSources, SafeValue},
};
use serde::de::DeserializeSeed;

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
