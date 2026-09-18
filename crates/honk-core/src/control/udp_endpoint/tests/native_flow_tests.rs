use super::*;
use crate::control::tests::support::NativeFlowApi;

#[tokio::test]
async fn native_udp_terminal_evidence_survives_retirement_and_tuple_reuse() {
    let api = NativeFlowApi::new().await;
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = client_socket.local_addr().unwrap();
    let dst = make_addr("127.0.0.1", 15353);
    let (removed_tx, mut removed_rx) = mpsc::channel(8);
    pool.set_remove_sink(removed_tx);
    let mut records = Vec::new();

    for (reason, state, reply) in [
        ("timeout_before_reply", "failed", false),
        ("reply_idle", "closed", true),
        ("transport_error", "failed", false),
        ("driver_cancelled", "failed", false),
        ("intentional_retirement", "closed", false),
        ("shutdown", "closed", false),
    ] {
        let flow = Arc::new(api.flows.begin("udp", client, dst));
        let id = flow.id().to_owned();
        let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
        let mut lease = match pool.reserve_or_enqueue(client, dst, b"first", permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("retired tuple must allow a new initializer"),
        };
        lease.set_connection_guard(
            stats.track_connection("test-node", crate::stats::OutboundKind::Node),
        );
        let transport = Arc::new(ScriptedPacketTransport::with_receive_actions(
            dst,
            [if reason == "transport_error" {
                DriverSendAction::Error
            } else {
                DriverSendAction::Ok
            }],
            if reply {
                vec![DriverReceiveAction::Packet {
                    data: b"reply".to_vec(),
                    source: dst,
                }]
            } else {
                Vec::new()
            },
        ));
        let mut endpoint = UdpEndpoint::new(transport, dst, TEST_NODE_ID);
        endpoint.set_native_flow(Some(flow), &pool);
        let endpoint = Arc::new(endpoint);
        let alive = Arc::new(honk_outbound::alive::AliveDialerSet::new());
        let death_called = Arc::new(AtomicBool::new(false));
        if reason == "transport_error" {
            let callback_pool = Arc::clone(&pool);
            let death_called = Arc::clone(&death_called);
            alive.set_death_callback(Some(Box::new(move |node, _| {
                death_called.store(true, Ordering::Relaxed);
                callback_pool.remove_by_node(node);
            })));
            for _ in 0..49 {
                alive.report_unavailable_traffic(
                    TEST_NODE_ID,
                    honk_outbound::alive::ProbeDomain::DataUdp,
                    honk_outbound::alive::IpVersion::V4,
                );
            }
        }
        let queue = lease.take_queue_receiver().unwrap();
        let mut driver = pool.spawn_driver(
            client,
            dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue,
            test_reply_socket().await,
            alive,
            Arc::clone(&stats),
            stats.outbound_tracker("test-node", crate::stats::OutboundKind::Node),
        );
        driver.wait_ready().await.unwrap();
        assert!(lease.commit_ready(Arc::clone(&endpoint)));
        driver.start(lease.take_first().unwrap()).unwrap();
        drop(lease);
        let first = driver.wait_first_ack().await;
        if reason == "transport_error" {
            assert!(first.is_err());
            assert!(death_called.load(Ordering::Relaxed));
        } else {
            first.unwrap();
        }
        if reply {
            let mut bytes = [0; 16];
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(1), client_socket.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&bytes[..length], b"reply");
            tokio::time::timeout(Duration::from_secs(1), async {
                while !endpoint.has_reply() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            endpoint.mark_reply();
        }
        match reason {
            "timeout_before_reply" | "reply_idle" => {
                tokio::task::yield_now().await;
                tokio::time::pause();
                tokio::time::advance(REPLY_IDLE_TIMEOUT).await;
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
                tokio::time::resume();
            }
            "driver_cancelled" => {
                driver.abort();
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
            "intentional_retirement" => {
                pool.remove(client, dst);
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
            "shutdown" => {
                let shutting_pool = Arc::clone(&pool);
                let shutdown = tokio::spawn(async move { shutting_pool.shutdown().await });
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
                assert!(shutdown.await.unwrap().joined);
            }
            _ => {
                recv_and_ack(&pool, &mut removed_rx).await.unwrap();
            }
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while endpoint.ref_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(pool.is_empty());
        assert_eq!(stats.snapshot()["test-node"].active_conns, 0);
        let (upload, download) = endpoint.byte_counters();
        assert_eq!(
            upload.load(Ordering::Relaxed),
            if reason == "transport_error" { 0 } else { 5 }
        );
        assert_eq!(download.load(Ordering::Relaxed), if reply { 5 } else { 0 });
        records.push((id, reason, state, reply));
    }

    for (id, reason, state, reply) in records {
        let detail = api.detail(&id).await;
        assert_eq!(detail["state"], state);
        assert!(detail["ended_at"].is_string());
        let steps = detail["trace"]["steps"].as_array().unwrap();
        let terminal: Vec<_> = steps
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["data"]["reason"], reason);
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["data"]["milestone"] == "first_reply")
                .count(),
            usize::from(reply)
        );
    }
    api.shutdown().await;
}

#[tokio::test]
async fn native_udp_block_loser_does_not_close_direct_winner_with_sniffed_domain() {
    assert_native_udp_builtin_plan(false).await;
}

#[tokio::test]
async fn native_udp_selector_block_records_authoritative_terminal() {
    assert_native_udp_builtin_plan(true).await;
}

async fn assert_native_udp_builtin_plan(selector_block: bool) {
    use crate::control::tests::support::{UdpTestReplySocketFactory, test_dns_forwarder};
    use crate::native_api::{NativeServer, NativeState};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = upstream.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.global.store_subscribe = false;
    config.global.dial_mode = "domain+".into();
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.listen = api_addr.to_string();
    config.experimental.native_api.secret = "native-race-test".into();
    config.ensure_builtin_nodes();
    let block = config
        .nodes
        .iter()
        .find(|node| node.name == "block")
        .unwrap()
        .id;
    let direct = config
        .nodes
        .iter()
        .find(|node| node.name == "direct")
        .unwrap()
        .id;
    config.groups.push(honk_config::group::Group {
        name: "cold".into(),
        policy: if selector_block {
            honk_config::group::GroupPolicy::Selector
        } else {
            honk_config::group::GroupPolicy::URLTest
        },
        nodes: if selector_block {
            vec![block]
        } else {
            vec![block, direct]
        },
        ..Default::default()
    });
    config.routing.default_outbound = "cold".into();
    let router =
        crate::routing::Router::new(&config.routing.rules, &config.routing.default_outbound)
            .unwrap();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        test_dns_forwarder(),
    )
    .unwrap();
    control.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        2,
        Arc::new(UdpTestReplySocketFactory),
    ));
    let state = Arc::new(
        NativeState::new(
            &mut control,
            api_addr,
            std::time::SystemTime::now(),
            Instant::now(),
        )
        .await
        .unwrap(),
    );
    let server = NativeServer::start(listener, state);
    let handle = control.spawn_handle();
    let hello = crate::control::quic::test_utils::build_client_hello(Some("original-target.test"));
    let packet = crate::control::quic::test_utils::protect_initial_packet(
        b"dcid1234",
        b"",
        1,
        0,
        1,
        &crate::control::quic::test_utils::wrap_crypto_frame(0, &hello),
    );
    let permit = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let lease = match handle.udp_pool.reserve_or_enqueue(
        client_addr,
        destination,
        &packet,
        permit,
        &handle.stats,
    ) {
        EndpointReservation::Initializing(lease) => lease,
        _ => panic!("cold route must own a new initializer"),
    };
    tokio::time::timeout(Duration::from_secs(5), handle.serve_udp_connection(lease))
        .await
        .unwrap()
        .unwrap();
    let mut received = vec![0; packet.len() + 1];
    if !selector_block {
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut received))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..length], packet.as_slice());
        let endpoint = handle.udp_pool.get(client_addr, destination).unwrap();
        assert_eq!(
            endpoint.byte_counters().0.load(Ordering::Relaxed),
            packet.len() as u64
        );
    } else {
        assert!(handle.udp_pool.is_empty());
        assert_eq!(
            upstream.try_recv_from(&mut received).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(handle.stats.snapshot()["cold"].active_conns, 0);
        assert_eq!(handle.stats.snapshot()["cold"].errors, 0);
    }
    let flows: serde_json::Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{api_addr}/api/v1/flows"))
        .bearer_auth("native-race-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(flows["flows"].as_array().unwrap().len(), 1);
    let flow_id = flows["flows"][0]["id"].as_str().unwrap();
    let detail: serde_json::Value = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{api_addr}/api/v1/flows/{flow_id}"))
        .bearer_auth("native-race-test")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["state"],
        if selector_block { "blocked" } else { "active" }
    );
    if selector_block {
        assert!(detail["ended_at"].is_string());
    } else {
        assert_eq!(detail["ended_at"], serde_json::Value::Null);
    }
    assert_eq!(detail["input"]["domain"], "original-target.test");
    let steps = detail["trace"]["steps"].as_array().unwrap();
    let failed_block = steps
        .iter()
        .find(|step| {
            step["stage"] == "outbound"
                && step["data"]["leaf_node_id"] == block.to_string()
                && step["data"]["status"] == "failed"
        })
        .unwrap();
    assert_eq!(failed_block["data"]["target_kind"], "none");
    assert_eq!(failed_block["data"]["target"], serde_json::Value::Null);
    if selector_block {
        let terminal: Vec<_> = steps
            .iter()
            .filter(|step| step["data"]["milestone"] == "terminal")
            .collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0]["data"]["state"], "blocked");
        assert_eq!(terminal[0]["data"]["reason"], "policy_block");
        assert!(handle.udp_pool.shutdown().await.joined);
        server.shutdown().await;
        return;
    }
    let won_direct = steps
        .iter()
        .find(|step| {
            step["stage"] == "outbound"
                && step["data"]["leaf_node_id"] == direct.to_string()
                && step["data"]["status"] == "succeeded"
        })
        .unwrap();
    assert_eq!(won_direct["data"]["target_kind"], "ip");
    assert_eq!(won_direct["data"]["target"], destination.to_string());
    assert_eq!(
        steps
            .iter()
            .rfind(|step| step["stage"] == "dial_mode")
            .unwrap()["data"]["effective_target"],
        "ip"
    );
    assert!(
        !steps
            .iter()
            .any(|step| step["data"]["milestone"] == "terminal")
    );
    assert!(handle.udp_pool.shutdown().await.joined);
    server.shutdown().await;
}
