use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

#[tokio::test]
async fn acquisition_initializes_once_when_128_callers_race() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let initializations = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Barrier::new(128));
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let initializations = Arc::clone(&initializations);
        let gate = Arc::clone(&gate);
        callers.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async {
                initializations.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok::<_, anyhow::Error>(7_u8)
            })
            .await
        });
    }

    // When
    while let Some(result) = callers.join_next().await {
        assert_eq!(*result.expect("caller task").expect("acquire"), 7);
    }

    // Then
    assert_eq!(initializations.load(Ordering::SeqCst), 1);
    assert_eq!(slot.init_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Ready);
}

#[tokio::test]
async fn builder_abort_wakes_waiters_and_allows_recovery() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let leader_slot = Arc::clone(&slot);
    let leader = tokio::spawn(async move {
        leader_slot
            .acquire(|| async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                Ok::<_, anyhow::Error>(1_u8)
            })
            .await
    });
    started_rx.await.expect("builder started");
    let gate = Arc::new(tokio::sync::Barrier::new(129));
    let mut waiters = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let gate = Arc::clone(&gate);
        waiters.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async { Ok::<_, anyhow::Error>(2_u8) })
                .await
        });
    }
    gate.wait().await;
    tokio::task::yield_now().await;

    // When
    leader.abort();
    let _ = leader.await;

    // Then
    while let Some(result) = waiters.join_next().await {
        let error = result
            .expect("waiter task")
            .expect_err("cancelled generation fails");
        assert!(error.to_string().contains("cancelled"));
    }
    let recovered = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(3_u8) })
        .await
        .expect("retry succeeds");
    assert_eq!(*recovered, 3);
    assert_eq!(slot.init_count(), 2);
}

#[tokio::test]
async fn builder_error_is_fanned_out_to_waiters() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let leader_slot = Arc::clone(&slot);
    let leader = tokio::spawn(async move {
        leader_slot
            .acquire(|| async move {
                let _ = started_tx.send(());
                let _ = release_rx.await;
                anyhow::bail!("malformed handshake")
            })
            .await
    });
    started_rx.await.expect("builder started");
    let gate = Arc::new(tokio::sync::Barrier::new(129));
    let mut waiters = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let slot = Arc::clone(&slot);
        let gate = Arc::clone(&gate);
        waiters.spawn(async move {
            gate.wait().await;
            slot.acquire(|| async { Ok::<_, anyhow::Error>(9_u8) })
                .await
        });
    }
    gate.wait().await;
    tokio::task::yield_now().await;

    // When
    release_tx.send(()).expect("release builder");

    // Then
    assert!(
        leader
            .await
            .expect("leader task")
            .expect_err("builder fails")
            .to_string()
            .contains("malformed handshake")
    );
    while let Some(result) = waiters.join_next().await {
        assert!(
            result
                .expect("waiter task")
                .expect_err("same generation fails")
                .to_string()
                .contains("malformed handshake")
        );
    }
}

#[tokio::test]
async fn close_is_idempotent() {
    // Given
    let slot = LifecycleSlot::new();
    let closes = AtomicUsize::new(0);
    slot.acquire(|| async { Ok::<_, anyhow::Error>(5_u8) })
        .await
        .expect("resource");

    // When
    slot.close(|_| async {
        closes.fetch_add(1, Ordering::SeqCst);
    })
    .await;
    slot.close(|_| async {
        closes.fetch_add(1, Ordering::SeqCst);
    })
    .await;

    // Then
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Closed);
}

#[tokio::test]
async fn repeated_builder_interruption_never_leaves_a_stale_slot() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());

    // When
    for _ in 0..3 {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let slot_for_builder = Arc::clone(&slot);
        let builder = tokio::spawn(async move {
            slot_for_builder
                .acquire(|| async move {
                    let _ = started_tx.send(());
                    std::future::pending::<anyhow::Result<u8>>().await
                })
                .await
        });
        started_rx.await.expect("builder started");
        builder.abort();
        let _ = builder.await;
        assert_eq!(slot.state(), LifecycleState::Closed);
    }
    let value = slot
        .acquire(|| async { Ok::<_, anyhow::Error>(11_u8) })
        .await
        .expect("recovered resource");

    // Then
    assert_eq!(*value, 11);
    assert_eq!(slot.init_count(), 4);
}

#[tokio::test]
async fn cancelled_close_owner_allows_waiting_close_to_finish() {
    // Given
    let slot = Arc::new(LifecycleSlot::new());
    slot.acquire(|| async { Ok::<_, anyhow::Error>(17_u8) })
        .await
        .expect("resource");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let slot_for_owner = Arc::clone(&slot);
    let owner = tokio::spawn(async move {
        slot_for_owner
            .close(|_| async move {
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
            .await;
    });
    started_rx.await.expect("close owner started");
    let closes = Arc::new(AtomicUsize::new(0));
    let slot_for_waiter = Arc::clone(&slot);
    let closes_for_waiter = Arc::clone(&closes);
    let waiter = tokio::spawn(async move {
        slot_for_waiter
            .close(|_| async move {
                closes_for_waiter.fetch_add(1, Ordering::SeqCst);
            })
            .await;
    });

    // When
    owner.abort();
    let _ = owner.await;
    tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("waiting close resumed")
        .expect("waiting close task");

    // Then
    assert_eq!(closes.load(Ordering::SeqCst), 1);
    assert_eq!(slot.close_count(), 1);
    assert_eq!(slot.state(), LifecycleState::Closed);
}
