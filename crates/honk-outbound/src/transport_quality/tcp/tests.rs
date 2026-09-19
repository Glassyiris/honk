use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn truncated_kernel_fields_remain_unknown_instead_of_zero_measurements() {
    // SAFETY: the Linux TCP_INFO ABI consists entirely of integer fields.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    info.tcpi_state = 1;
    info.tcpi_rtt = 40_000;
    info.tcpi_bytes_acked = 16384;
    info.tcpi_data_segs_out = 64;
    info.tcpi_total_retrans = 4;
    info.tcpi_bytes_retrans = 4096;
    info.tcpi_bytes_sent = 65536;
    info.tcpi_bytes_received = 8192;
    let now = Instant::now();
    let short = sample_from_info(
        &info,
        std::mem::offset_of!(libc::tcp_info, tcpi_bytes_acked) + 7,
        now,
    );
    assert_eq!(short.rtt, Some(Duration::from_millis(40)));
    assert_eq!(short.lost, Some(4));
    assert!(short.acknowledged.is_none());
    assert!(short.transmitted.is_none());
    assert!(short.tx_bytes.is_none());
    assert!(short.lost_bytes.is_none());
    let tail = sample_from_info(
        &info,
        std::mem::offset_of!(libc::tcp_info, tcpi_bytes_retrans) + 7,
        now,
    );
    assert_eq!(tail.tx_bytes, Some(65536));
    assert!(tail.lost_bytes.is_none());
    info.tcpi_state = 7;
    let closed = sample_from_info(&info, std::mem::size_of_val(&info), now);
    assert!(closed.acknowledged.is_none());
    assert!(closed.rtt.is_none());
}

#[tokio::test]
async fn observed_tcp_loopback_preserves_cancelled_reads_payload_and_half_close() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let quality = Arc::new(TransportQuality::default());
        quality.enable();
        let mut observed = quality
            .clone()
            .scope(async { ObservedTcp::new(socket) })
            .await;
        observed.activate();
        let mut output = [0u8; 8192];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), observed.read_exact(&mut output))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1001)).await;
        peer.write_all(&[42; 8192]).await.unwrap();
        observed.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [42; 8192]);
        observed.write_all(&[17; 8192]).await.unwrap();
        observed.flush().await.unwrap();
        peer.read_exact(&mut output).await.unwrap();
        assert_eq!(output, [17; 8192]);
        let sample = read_sample(&observed.inner, Instant::now());
        assert!(sample.rtt.is_some_and(|rtt| !rtt.is_zero()));
        assert!(sample.rx_bytes.is_none_or(|bytes| bytes >= 8192));
        assert!(sample.tx_bytes.is_none_or(|bytes| bytes >= 8192));
        assert!(quality.snapshot().iter().all(Option::is_none));
        observed.shutdown().await.unwrap();
        assert_eq!(peer.read(&mut output).await.unwrap(), 0);
        peer.write_all(b"after-half-close").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut remaining = Vec::new();
        observed.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"after-half-close");
    })
    .await
    .unwrap();
}
