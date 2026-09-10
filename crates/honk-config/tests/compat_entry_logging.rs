//! Keep this test alone in its binary: scoped-subscriber callsite interest is resolved through
//! the registering thread's default (`Rebuilder::JustOne`). Another test reaching
//! `report_diagnostics` first under `NoSubscriber` caches the callsite as never-interested.
use honk_config::parser::parse_dae_config;

#[test]
fn test_millisecond_duration_compat_entry_logs_warning() {
    #[derive(Clone)]
    struct Writer(std::sync::Arc<parking_lot::Mutex<Vec<u8>>>);

    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let output = Writer(Default::default());
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
