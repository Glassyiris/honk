use super::*;
use honk_config::group::{Group, GroupPolicy};
use honk_config::node::Node;
use honk_outbound::group::{GroupManager, ScoreSelectionContext, SelectionNetwork};

#[tokio::test]
async fn accepted_udp_progress_changes_selection_before_endpoint_finishes() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let outbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let outbound_addr = outbound.local_addr().unwrap();
    let nodes = [
        Node {
            name: "control".into(),
            id: OTHER_NODE_ID,
            ..Default::default()
        },
        Node {
            name: "live".into(),
            id: TEST_NODE_ID,
            ..Default::default()
        },
    ];
    let manager = GroupManager::new(
        &[Group {
            name: "score".into(),
            policy: GroupPolicy::Score,
            nodes: nodes.iter().map(|node| node.id).collect(),
            ..Default::default()
        }],
        &nodes,
    );
    let context = ScoreSelectionContext {
        network: SelectionNetwork::Udp,
        probe_domain: honk_outbound::alive::ProbeDomain::DataUdp,
        target_family: Some(honk_outbound::alive::IpVersion::V4),
        health_family: honk_outbound::alive::IpVersion::V4,
        target: Some(target.into()),
    };
    let histories: Vec<Vec<_>> = nodes
        .iter()
        .map(|node| {
            (0..8)
                .map(|_| {
                    let reporter = manager
                        .feedback_for_node(node.id, context.clone())
                        .unwrap()
                        .start();
                    reporter.setup_succeeded();
                    reporter
                })
                .collect()
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for history in histories {
        for reporter in history {
            reporter.first_response();
            reporter.tx(1);
            reporter.rx(1);
            reporter.finish(ScoreOutcome::Success);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let control = manager
        .feedback_for_node(OTHER_NODE_ID, context.clone())
        .unwrap()
        .start();
    control.setup_succeeded();
    let reporter = manager
        .feedback_for_node(TEST_NODE_ID, context)
        .unwrap()
        .start();
    reporter.setup_succeeded();
    let endpoint = Arc::new(UdpEndpoint::new_scored(
        transport(outbound, target),
        target,
        false,
        TEST_NODE_ID,
        honk_outbound::alive::IpVersion::V4,
        Some(reporter),
    ));
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let payload = vec![0x5a; 32 * 1024];
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let mut lease = match pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("live flow must reserve a fresh endpoint"),
    };
    let mut driver = pool.spawn_driver(
        client_addr,
        target,
        lease.generation(),
        lease.decision_token(),
        Arc::clone(&endpoint),
        lease.take_queue_receiver().unwrap(),
        test_reply_socket().await,
        Arc::new(honk_outbound::alive::AliveDialerSet::new()),
        Arc::clone(&stats),
        stats.outbound_tracker("live", crate::stats::OutboundKind::Node),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    drop(lease);
    driver.wait_first_ack().await.unwrap();
    let mut buf = vec![0; payload.len()];
    for index in 0..4 {
        if index != 0 {
            let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
            assert!(matches!(
                pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats),
                EndpointReservation::Enqueued
            ));
        }
        let (len, peer) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, outbound_addr);
        assert_eq!(&buf[..len], payload);
    }
    server.send_to(b"r", outbound_addr).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"r");
    control.first_response();
    control.tx(64 * 1024);
    control.rx(1);

    for window in 0..4 {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        control.tx(1);
        if window == 0 {
            assert_eq!(
                manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
                Some("control".into()),
            );
        }
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(client_addr, target, b"!", permit, &stats),
            EndpointReservation::Enqueued
        ));
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"!");
        if window < 3 {
            control.tx(64 * 1024);
            for _ in 0..4 {
                let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
                assert!(matches!(
                    pool.reserve_or_enqueue(client_addr, target, &payload, permit, &stats),
                    EndpointReservation::Enqueued
                ));
                let (len, _) =
                    tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&buf[..len], payload);
            }
        }
    }
    assert_eq!(endpoint.upload.load(Ordering::Relaxed), 4 * 128 * 1024 + 4);
    assert_eq!(endpoint.download.load(Ordering::Relaxed), 1);
    assert_eq!(pool.driver_count(), 1);
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
        Some("live".into()),
        "accepted upload and delivered reply must publish before terminal settlement",
    );

    endpoint.finish_score(ScoreOutcome::Success);
    endpoint.finish_score(ScoreOutcome::Io(io::ErrorKind::ConnectionReset));
    assert_eq!(
        manager.get_score_selection_for_network("score", SelectionNetwork::Udp),
        Some("live".into()),
    );
    control.finish(ScoreOutcome::Cancelled);
    assert!(pool.shutdown().await.joined);
}
