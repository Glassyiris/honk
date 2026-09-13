//! Keep emitting tests in this binary: scoped-subscriber callsite interest is resolved through
//! the registering thread's default (`Rebuilder::JustOne`). No-subscriber diagnostic suites stay in
//! separate binaries so they cannot cache these callsites as never-interested.
use honk_config::parser::parse_dae_config;
use parking_lot::Mutex;
use serde::de::DeserializeSeed;
use std::sync::Arc;

#[derive(Clone, Default)]
struct Writer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_millisecond_duration_compat_entry_logs_warning() {
    let output = Writer::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        parse_dae_config("global {\n    check_tolerance: abc\n}").unwrap();
    });
    let bytes = output.0.lock();
    let log = String::from_utf8_lossy(&bytes);
    assert!(log.contains("global.check_tolerance"), "{log}");
}

#[test]
fn standalone_serde_reports_once_and_redacts_success_and_failure() {
    let output = Writer::default();
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/node_incompatible.json")).unwrap();
        for valid in [true, false] {
            output.0.lock().clear();
            let mut input = fixture.clone();
            if valid {
                input.as_object_mut().unwrap().remove("tls_alpn");
            }
            let result = serde_json::from_value::<honk_config::node::Node>(input.clone());
            assert_eq!(result.is_ok(), valid);
            let log = String::from_utf8(output.0.lock().clone()).unwrap();
            assert_eq!(log.lines().count(), 1, "{log}");
            assert!(!log.contains("secret"), "{log}");
            if let Err(error) = result {
                assert!(!error.to_string().contains("secret"));
            }
            output.0.lock().clear();
            let mut diagnostics = Vec::new();
            let result = honk_config::node::NodeSeed {
                diagnostics: &mut diagnostics,
                source: honk_config::diagnostic::DiagnosticSources::new(None).root(),
                setting: honk_config::diagnostic::SettingPath::new("nodes").index(1),
            }
            .deserialize(input);
            assert_eq!(result.is_ok(), valid);
            assert!(output.0.lock().is_empty());
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(
                diagnostics[0].value,
                honk_config::diagnostic::SafeValue::Fields(vec!["sni"])
            );
            assert!(!format!("{diagnostics:?}").contains("secret"));
        }
    });
}
