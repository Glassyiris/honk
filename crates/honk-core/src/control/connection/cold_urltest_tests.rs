use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test(start_paused = true)]
async fn cold_urltest_releases_candidates_progressively_and_cancels_waiters() {
    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..3 {
        let started = Arc::clone(&started);
        tasks.spawn(async move {
            wait_for_cold_urltest_release(index).await;
            started.fetch_add(1, Ordering::AcqRel);
        });
    }
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        1,
        "only the first candidate is immediate"
    );
    tokio::time::advance(COLD_URLTEST_STAGGER).await;
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        2,
        "the second candidate releases after one delay"
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    tokio::time::advance(COLD_URLTEST_STAGGER * 2).await;
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(Ordering::Acquire),
        2,
        "cancelled unreleased candidate must not start"
    );
}
