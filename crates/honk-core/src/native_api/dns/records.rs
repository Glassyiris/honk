pub(crate) use crate::dns::response::native::{
    DnsAnswer, DnsQuestion, MAX_JSON_BYTES, ProjectionError, parse_type, project, question,
    record_type, status,
};

pub(super) fn json_size(value: &impl serde::Serialize) -> Result<usize, serde_json::Error> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
