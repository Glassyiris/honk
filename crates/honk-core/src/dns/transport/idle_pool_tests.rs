use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::{IdlePoolState, close_idle_pool, idle_pool_exchange};

async fn assert_close_excludes_inflight_return() {
    // Given
    let lifecycle = Arc::new(tokio::sync::RwLock::new(IdlePoolState::Open));
    let idle = Arc::new(Mutex::new(Vec::<DuplexStream>::new()));
    let (client, mut server) = tokio::io::duplex(256);
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let mut length = [0_u8; 2];
        server.read_exact(&mut length).await.expect("query length");
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        server.read_exact(&mut query).await.expect("query");
        let _ = request_tx.send(());
        let _ = response_rx.await;
        let response = [0_u8; 12];
        server
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .expect("response length");
        server.write_all(&response).await.expect("response");
    });
    let exchange_lifecycle = Arc::clone(&lifecycle);
    let exchange_idle = Arc::clone(&idle);
    let exchange = tokio::spawn(async move {
        idle_pool_exchange(
            &exchange_lifecycle,
            &exchange_idle,
            || async { Ok::<_, anyhow::Error>(client) },
            &[0_u8; 12],
            Duration::from_secs(1),
            None,
        )
        .await
    });
    request_rx.await.expect("exchange in flight");
    let close_lifecycle = Arc::clone(&lifecycle);
    let close_idle = Arc::clone(&idle);
    let mut close = tokio::spawn(async move {
        close_idle_pool(&close_lifecycle, &close_idle, Duration::from_secs(1)).await;
    });

    // When
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut close)
            .await
            .is_err(),
        "close returned before the exchange lease"
    );
    response_tx.send(()).expect("release response");
    exchange
        .await
        .expect("exchange task")
        .expect("exchange response");
    close.await.expect("close task");
    server_task.await.expect("server task");

    // Then
    assert_eq!(idle.lock().len(), 0);
    let error = idle_pool_exchange(
        &lifecycle,
        &idle,
        || async { Ok::<_, anyhow::Error>(tokio::io::duplex(64).0) },
        &[0_u8; 12],
        Duration::from_secs(1),
        None,
    )
    .await
    .expect_err("closed pool rejects exchange");
    assert!(error.to_string().contains("closed"));
}

#[tokio::test]
async fn tcp_inflight_stream_cannot_return_after_close() {
    assert_close_excludes_inflight_return().await;
}

#[tokio::test]
async fn dot_inflight_stream_cannot_return_after_close() {
    assert_close_excludes_inflight_return().await;
}
