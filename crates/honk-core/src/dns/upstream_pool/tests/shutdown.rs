use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::dns::forwarder::DnsUpstreamPool;

#[tokio::test]
async fn close_waits_for_query_admitted_before_transport_publication() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).await.expect("query");
        let transaction_id = u16::from_be_bytes([query[0], query[1]]);
        let response = mock_dns_response(transaction_id);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        stream.write_all(&response).await.expect("response");
    });
    let pool = Arc::new(
        UpstreamPool::new(
            &[make_upstream(
                "default",
                &address.to_string(),
                DnsProtocol::Tcp,
            )],
            make_router(),
        )
        .expect("pool"),
    );
    let pause = pool.arm_admission_pause_for_test();
    let query_pool = Arc::clone(&pool);
    let query =
        tokio::spawn(async move { query_pool.query("default", &mock_dns_query(0x1234)).await });
    pause.entered.notified().await;
    let close_pool = Arc::clone(&pool);
    let mut close = tokio::spawn(async move { close_pool.close().await });

    // When
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut close)
            .await
            .is_err(),
        "close returned while an admitted query could still publish a transport"
    );
    pause.release.notify_one();
    query
        .await
        .expect("query task")
        .expect("query response after release");
    close.await.expect("close task");
    server.await.expect("server task");

    // Then
    let slot_count = pool
        .entries
        .values()
        .map(|entry| entry.transports.lock().len())
        .sum::<usize>();
    assert_eq!(slot_count, 1);
    assert_eq!(
        pool.lifecycle_stats(),
        TransportLifecycleStats {
            init_count: 1,
            close_count: 1,
            tasks: 0,
        }
    );
}
