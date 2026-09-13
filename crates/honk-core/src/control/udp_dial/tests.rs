use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn candidate(name: &str) -> Node {
    let mut node = Node {
        name: name.into(),
        address: format!("{name}.example"),
        port: 9,
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_drains_pending_candidate() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let acquired = Arc::new(tokio::sync::Notify::new());
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<()> = {
        let permits = Arc::clone(&permits);
        let acquired = Arc::clone(&acquired);
        Arc::new(move |_, _| {
            let permits = Arc::clone(&permits);
            let acquired = Arc::clone(&acquired);
            Box::pin(async move {
                let _permit = permits.acquire_owned().await.unwrap();
                acquired.notify_one();
                std::future::pending::<anyhow::Result<()>>().await
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_| {
                errors.fetch_add(1, Ordering::Relaxed);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::Authoritative,
        vec![candidate("pending")],
        deadline,
        prepare,
        callbacks,
    ));

    acquired.notified().await;
    assert_eq!(
        permits.available_permits(),
        0,
        "preparation acquired its permit"
    );
    tokio::time::advance(Duration::from_millis(10)).await;
    let result = tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("UDP preparation must enforce its own deadline")
        .expect("preparation task must not panic");
    assert!(result.is_none());
    assert_eq!(permits.available_permits(), 1);
    assert_eq!(errors.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_prevents_future_stagger_start() {
    let starts = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<()> = {
        let starts = Arc::clone(&starts);
        Arc::new(move |_, _| {
            starts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(anyhow::anyhow!("scripted dial error")) })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = Arc::clone(&errors);
            Arc::new(move |_| {
                errors.fetch_add(1, Ordering::SeqCst);
            })
        },
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![candidate("first"), candidate("after-deadline")],
        deadline,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_millis(20)).await;
    assert!(task.await.unwrap().is_none());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(errors.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn udp_preparation_deadline_drains_three_pending_candidates() {
    let permits = Arc::new(tokio::sync::Semaphore::new(3));
    let starts = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let prepare: UdpPrepare<()> = {
        let permits = Arc::clone(&permits);
        let starts = Arc::clone(&starts);
        Arc::new(move |_, _| {
            let permits = Arc::clone(&permits);
            let starts = Arc::clone(&starts);
            Box::pin(async move {
                let _permit = permits.acquire_owned().await.unwrap();
                starts.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<anyhow::Result<()>>().await
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_| panic!("cancellation is health-neutral")),
        on_attempt: Arc::new(|| {}),
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = Arc::clone(&cancellations);
            Arc::new(move || {
                cancellations.fetch_add(1, Ordering::SeqCst);
            })
        },
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    let task = tokio::spawn(prepare_udp_plan(
        SelectionPlanMode::ColdUrlTest,
        vec![
            candidate("first"),
            candidate("second"),
            candidate("third"),
            candidate("never-started"),
        ],
        deadline,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert_eq!(permits.available_permits(), 0);
    tokio::time::advance(Duration::from_millis(20)).await;

    assert!(
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("all pending preparations must stop at the deadline")
            .unwrap()
            .is_none()
    );
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert_eq!(permits.available_permits(), 3);
    assert_eq!(cancellations.load(Ordering::SeqCst), 3);
}
