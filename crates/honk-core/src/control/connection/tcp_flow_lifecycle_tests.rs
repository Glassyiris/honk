use super::*;

use crate::connection_tracker::ConnectionEntry;
use crate::control::retirement_worker::{RetirementPort, RetirementWorker};
use crate::ebpf::{TcpPin, mock::MockEbpfBackend};
use honk_ebpf_common::RedirectTuple;
use honk_ebpf_common::conn::{ConnState, TcpState};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::AsyncReadExt;

fn forward_tuple() -> TuplesKey {
    build_tuples_key(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        443,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        50_000,
        6,
    )
}

fn reverse_tuple() -> TuplesKey {
    build_tuples_key(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        50_000,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        443,
        6,
    )
}

fn backend() -> Arc<RwLock<Box<dyn EbpfBackend>>> {
    Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())))
}

fn removal_worker(
    backend: &Arc<RwLock<Box<dyn EbpfBackend>>>,
    pins: &Arc<TcpFlowPins>,
    tracker: &Arc<ConnectionTracker>,
) -> (
    Arc<UdpEndpointPool>,
    Arc<RetirementPort>,
    RetirementWorker,
    mpsc::UnboundedReceiver<anyhow::Error>,
) {
    let pool = Arc::new(UdpEndpointPool::new());
    let port = Arc::new(RetirementPort::default());
    let (fatal_tx, fatal_rx) = mpsc::unbounded_channel();
    let task = spawn_retirement_worker(
        Arc::clone(&pool),
        Arc::clone(backend),
        Arc::clone(tracker),
        fatal_tx,
        Arc::clone(pins),
        Arc::clone(&port),
    );
    (pool, port, task, fatal_rx)
}

async fn stop_removals(
    pool: Arc<UdpEndpointPool>,
    port: &RetirementPort,
    worker: RetirementWorker,
    mut fatal: mpsc::UnboundedReceiver<anyhow::Error>,
) -> anyhow::Result<()> {
    pool.shutdown().await;
    port.sink.lock().take();
    worker.await?;
    assert!(fatal.try_recv().is_err());
    Ok(())
}

fn tracked_entry(id: &str) -> ConnectionEntry {
    ConnectionEntry {
        id: id.to_string(),
        source: "192.0.2.1:50000".to_string(),
        destination: "203.0.113.2:443".to_string(),
        proxy: "direct".to_string(),
        #[cfg(feature = "native-api")]
        routed_outbound: None,
        #[cfg(feature = "native-api")]
        native_flow_id: None,
        rule: "Fallback".to_string(),
        rule_payload: String::new(),
        chains: vec!["direct".to_string()],
        upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        start_time: std::time::Instant::now(),
        domain: None,
        network: "tcp".to_string(),
        process: None,
        process_path: None,
    }
}

async fn tcp_pair() -> anyhow::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let connect = TcpStream::connect(addr);
    let (accepted, peer) = tokio::join!(listener.accept(), connect);
    Ok((accepted?.0, peer?))
}

#[test]
fn directional_key_ignores_padding_and_refcounts_owners() {
    let mut first = forward_tuple();
    let mut second = forward_tuple();
    first.padding = [1, 2, 3];
    second.padding = [4, 5, 6];
    let key = TcpFlowKey::from_tuples(&first);

    assert_eq!(key, TcpFlowKey::from_tuples(&second));
    assert_eq!(
        key,
        TcpFlowKey::from_redirect(&RedirectTuple::from_tuples(&first))
    );
    let reverse = TcpFlowKey::from_tuples(&reverse_tuple());
    assert_ne!(key, reverse);

    let pins = TcpFlowPins::default();
    pins.retain(key);
    pins.retain(key);
    pins.retain(reverse);
    assert_eq!(pins.snapshot().len(), 2);
    assert_eq!(pins.release(key), Some(false));
    assert!(pins.snapshot().contains(&key));
    assert_eq!(pins.release(key), Some(true));
    assert!(!pins.snapshot().contains(&key));
    assert!(pins.snapshot().contains(&reverse));
    assert_eq!(pins.release(key), None);
    assert_eq!(pins.release(reverse), Some(true));
    assert!(pins.snapshot().is_empty());
}

#[tokio::test]
async fn tcp_flow_guard_abort_releases_pin_tracker_and_socket() -> anyhow::Result<()> {
    let (stream, mut peer) = tcp_pair().await?;
    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let mut flow = TcpFlowGuard::new(
        stream,
        forward_tuple(),
        1,
        Arc::clone(&pins),
        Arc::clone(&tracker),
        Arc::new(RetirementPort::default()),
        TcpPin::Model,
    );
    flow.track(tracked_entry("abort"));
    assert_eq!(pins.snapshot().len(), 1);
    assert_eq!(tracker.snapshot().len(), 1);

    let task = tokio::spawn(async move {
        let _flow = flow;
        std::future::pending::<()>().await;
    });
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(pins.snapshot().is_empty());
    assert!(tracker.snapshot().is_empty());

    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
        0
    );
    Ok(())
}

#[tokio::test]
async fn tcp_retire_waits_for_final_owner() -> anyhow::Result<()> {
    let tuple = forward_tuple();
    let backend = backend();
    backend.write().await.tcp_conn_state_store(
        &tuple,
        &ConnState {
            state: TcpState::TcpStateActive as u8,
            incarnation: 1,
            last_seen_ns: 0,
            ..Default::default()
        },
    )?;
    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let (pool, port, worker, fatal) = removal_worker(&backend, &pins, &tracker);
    let (first_stream, _first_peer) = tcp_pair().await?;
    let (second_stream, _second_peer) = tcp_pair().await?;
    let first = TcpFlowGuard::new(
        first_stream,
        tuple,
        1,
        Arc::clone(&pins),
        Arc::clone(&tracker),
        Arc::clone(&port),
        TcpPin::Model,
    );
    let second = TcpFlowGuard::new(
        second_stream,
        tuple,
        1,
        Arc::clone(&pins),
        tracker,
        Arc::clone(&port),
        TcpPin::Model,
    );

    assert!(first.retire(Default::default()).await);
    assert!(backend.read().await.conn_state_lookup(&tuple)?.is_some());
    assert!(pins.snapshot().contains(&TcpFlowKey::from_tuples(&tuple)));

    assert!(second.retire(Default::default()).await);
    assert!(backend.read().await.conn_state_lookup(&tuple)?.is_none());
    assert!(pins.snapshot().is_empty());
    stop_removals(pool, &port, worker, fatal).await?;
    Ok(())
}

#[tokio::test]
async fn tcp_retire_preserves_newer_incarnation() -> anyhow::Result<()> {
    let tuple = forward_tuple();
    let reverse = reverse_tuple();
    let old = ConnState {
        state: TcpState::TcpStateActive as u8,
        incarnation: 1,
        last_seen_ns: 0,
        ..Default::default()
    };
    let backend = backend();
    {
        let mut backend = backend.write().await;
        backend.tcp_conn_state_store(&tuple, &old)?;
        backend.tcp_conn_state_store(&reverse, &old)?;
    }

    let pins = Arc::new(TcpFlowPins::default());
    let tracker = Arc::new(ConnectionTracker::new());
    let (pool, port, worker, fatal) = removal_worker(&backend, &pins, &tracker);
    let (stream, mut peer) = tcp_pair().await?;
    let mut flow = TcpFlowGuard::new(
        stream,
        tuple,
        old.incarnation,
        Arc::clone(&pins),
        Arc::clone(&tracker),
        Arc::clone(&port),
        TcpPin::Model,
    );
    flow.track(tracked_entry("replacement"));

    let mut backend_guard = backend.write().await;
    let retire = tokio::spawn(flow.retire(Default::default()));
    tokio::task::yield_now().await;
    assert_eq!(
        tracker.snapshot().len(),
        1,
        "retirement retains its ID until backend cleanup completes"
    );
    backend_guard.tcp_conn_state_store(
        &tuple,
        &ConnState {
            incarnation: 2,
            last_seen_ns: 0,
            ..old
        },
    )?;
    drop(backend_guard);
    assert!(retire.await?);

    let backend = backend.read().await;
    assert_eq!(
        backend
            .conn_state_lookup(&tuple)?
            .expect("replacement state")
            .incarnation,
        2,
        "an old guard must never retire a newer SYN even when it reads that state at teardown"
    );
    assert!(backend.conn_state_lookup(&reverse)?.is_some());
    drop(backend);
    assert!(pins.snapshot().is_empty());
    assert!(tracker.snapshot().is_empty());
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
        0
    );
    stop_removals(pool, &port, worker, fatal).await?;
    Ok(())
}
