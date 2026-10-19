use super::*;
use std::sync::atomic::{AtomicU32, Ordering};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn blocking_commit_leaves_the_worker_free_for_other_tasks() {
    const COMMIT: Duration = Duration::from_millis(300);
    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.commit_delay = Some(COMMIT);
    let DecisionFixture {
        pending,
        lease,
        identity,
        ..
    } = pending_fixture_with(31, mock);
    let pending = Arc::new(pending);
    let ticks = Arc::new(AtomicU32::new(0));
    let ticker = tokio::spawn({
        let ticks = Arc::clone(&ticks);
        async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                ticks.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let commit = tokio::spawn(async move {
        pending
            .activate_proxy(identity, &lease, 4, 0x3400)
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), commit)
        .await
        .expect("commit must finish")
        .unwrap();
    ticker.abort();

    assert!(
        ticks.load(Ordering::Relaxed) >= 10,
        "a 300 ms commit starved the only worker: {} ticks",
        ticks.load(Ordering::Relaxed)
    );
}
