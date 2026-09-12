use honk_config::diagnostic::{DiagnosticSources, SafeValue, SettingPath};
use honk_config::node::Node;
use honk_config::node::NodeSeed;
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
            let result = serde_json::from_value::<Node>(input.clone());
            assert_eq!(result.is_ok(), valid);
            let log = String::from_utf8(output.0.lock().clone()).unwrap();
            assert_eq!(log.lines().count(), 1, "{log}");
            assert!(!log.contains("secret"), "{log}");
            if let Err(error) = result {
                assert!(!error.to_string().contains("secret"));
            }
            output.0.lock().clear();
            let mut diagnostics = Vec::new();
            let result = NodeSeed {
                diagnostics: &mut diagnostics,
                source: DiagnosticSources::new(None).root(),
                setting: SettingPath::new("nodes").index(1),
            }
            .deserialize(input);
            assert_eq!(result.is_ok(), valid);
            assert!(output.0.lock().is_empty());
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].value, SafeValue::Fields(vec!["sni"]));
            assert!(!format!("{diagnostics:?}").contains("secret"));
        }
    });
}
