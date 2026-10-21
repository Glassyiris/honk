use super::write_sniff_prefix;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn native_prefix_partial_failure_keeps_only_written_bytes() {
    let connection = AtomicU64::new(0);
    let outbound = AtomicU64::new(7);
    let (mut writer, mut reader) = tokio::io::duplex(3);
    let (result, received) = tokio::join!(
        write_sniff_prefix(&mut writer, b"abcdef", |bytes| {
            connection.fetch_add(bytes as u64, Ordering::Relaxed);
            outbound.fetch_add(bytes as u64, Ordering::Relaxed);
        }),
        async move {
            let mut received = [0; 3];
            reader.read_exact(&mut received).await.unwrap();
            drop(reader);
            received
        }
    );
    assert_eq!(&received, b"abc");
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(connection.load(Ordering::Relaxed), 3);
    assert_eq!(outbound.load(Ordering::Relaxed), 10);
}
