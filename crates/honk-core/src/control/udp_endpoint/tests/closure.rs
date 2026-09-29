use super::*;
use crate::connection_tracker::{CloseOutcome, ConnectionEntry, ConnectionTracker};
use crate::ebpf::{EbpfBackend, mock::MockEbpfBackend};
use honk_ebpf_common::{
    RedirectEntry, RedirectTuple,
    conn::{ConnState, UdpDecisionState},
};

pub(in crate::control::udp_endpoint) fn tracked_entry(
    id: &str,
    client: SocketAddr,
    dst: SocketAddr,
) -> ConnectionEntry {
    ConnectionEntry {
        id: id.to_owned(),
        source: client.to_string(),
        destination: dst.to_string(),
        proxy: "direct".into(),
        #[cfg(feature = "native-api")]
        routed_outbound: None,
        #[cfg(feature = "native-api")]
        native_flow_id: None,
        rule: String::new(),
        rule_payload: String::new(),
        chains: Vec::new(),
        upload: Arc::new(AtomicU64::new(0)),
        download: Arc::new(AtomicU64::new(0)),
        start_time: Instant::now(),
        domain: None,
        network: "udp".into(),
        process: None,
        process_path: None,
    }
}

#[tokio::test]
async fn udp_close_waits_for_driver_and_exact_backend_ack() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for mismatch in [false, true] {
            let pool = Arc::new(UdpEndpointPool::new());
            let stats = Arc::new(StatsManager::new());
            let tracker = Arc::new(ConnectionTracker::new());
            tracker.enable();
            let backend: Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>> =
                Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
            let (fatal, mut failures) = mpsc::unbounded_channel();
            let worker = crate::control::udp_removal::spawn_udp_removal_worker(
                Arc::clone(&pool),
                Arc::clone(&backend),
                Arc::clone(&tracker),
                fatal,
            );
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = upstream.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let source = client.local_addr().unwrap();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            socket.connect(destination).await.unwrap();
            let local_transport = socket.local_addr().unwrap();
            let endpoint = Arc::new(UdpEndpoint::new(
                transport(socket, destination),
                destination,
                uuid::Uuid::new_v4(),
            ));
            endpoint.record_pending_reply_peer(destination);
            let weak = Arc::downgrade(&endpoint);
            let mut lease = match pool.reserve_owned_or_enqueue(
                source,
                destination,
                Bytes::from_static(b"live"),
                101,
                None,
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                &stats,
            ) {
                EndpointReservation::Initializing(lease) => lease,
                _ => panic!("fresh owned endpoint"),
            };
            let generation = lease.generation();
            let key = crate::control::connection::build_tuples_key(
                destination.ip(),
                destination.port(),
                source.ip(),
                source.port(),
                17,
            );
            backend
                .write()
                .await
                .udp_conn_state_store(
                    &key,
                    &ConnState {
                        decision_token: 101,
                        state: UdpDecisionState::Proxy as u8,
                        ..Default::default()
                    },
                )
                .unwrap();
            let queue = lease.take_queue_receiver().unwrap();
            let mut driver = pool.spawn_driver(
                source,
                destination,
                generation,
                101,
                Arc::clone(&endpoint),
                queue,
                test_reply_socket().await,
                Arc::new(honk_outbound::alive::AliveDialerSet::new()),
                Arc::clone(&stats),
                stats.outbound_tracker("direct", crate::stats::OutboundKind::Builtin),
            );
            driver.wait_ready().await.unwrap();
            assert!(lease.commit_ready(Arc::clone(&endpoint)));
            let id = pool
                .register_ready_tracker(
                    source,
                    destination,
                    101,
                    generation,
                    &endpoint,
                    &tracker,
                    vec!["captured-parent".into()],
                    || tracked_entry("owned-udp", source, destination),
                )
                .unwrap()
                .unwrap();
            driver.start(lease.take_first().unwrap()).unwrap();
            driver.wait_first_ack().await.unwrap();
            drop(lease);
            drop(endpoint);
            let mut bytes = [0; 4];
            upstream.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"live");
            let selected = tracker
                .snapshot_group("captured-parent", Some("udp"))
                .pop()
                .unwrap();
            let mut locked = backend.write().await;
            if mismatch {
                locked
                    .redirect_track_store(
                        &RedirectTuple::from_tuples(&key),
                        &RedirectEntry {
                            decision_token: 202,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            let pending = tracker.start_close(selected);
            assert_eq!(tracker.close_id(&id).await, CloseOutcome::Gone);
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
            let socket_released = UdpSocket::bind(local_transport).await.unwrap();
            drop(socket_released);
            let mut pending = Box::pin(pending.wait());
            assert!(futures::poll!(&mut pending).is_pending());
            assert!(locked.udp_conn_state_lookup(&key).unwrap().is_some());
            drop(locked);
            if mismatch {
                assert_eq!(pending.await, CloseOutcome::Failed);
                assert!(failures.recv().await.is_some());
                assert!(matches!(
                    pool.endpoints
                        .get(&EndpointKey::new(source, destination))
                        .unwrap()
                        .value(),
                    EndpointEntry::Retiring { .. }
                ));
                assert_eq!(
                    backend
                        .read()
                        .await
                        .udp_conn_state_lookup(&key)
                        .unwrap()
                        .unwrap()
                        .decision_token,
                    101
                );
            } else {
                assert_eq!(pending.await, CloseOutcome::Closed);
                assert!(tracker.snapshot().is_empty());
                assert!(
                    backend
                        .read()
                        .await
                        .udp_conn_state_lookup(&key)
                        .unwrap()
                        .is_none()
                );
                let replacement = match pool.reserve_owned_or_enqueue(
                    source,
                    destination,
                    Bytes::from_static(b"new"),
                    202,
                    None,
                    Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                    &stats,
                ) {
                    EndpointReservation::Initializing(lease) => lease,
                    _ => panic!("acknowledged retirement permits tuple reuse"),
                };
                assert!(!pool.close_exact(source, destination, 101, generation));
                assert!(replacement.still_initializing());
                drop(replacement);
                assert!(pool.shutdown().await.joined);
                assert!(failures.try_recv().is_err());
            }
            pool.remove_sink.lock().take();
            worker.await.unwrap();
        }
    })
    .await
    .unwrap();
}
