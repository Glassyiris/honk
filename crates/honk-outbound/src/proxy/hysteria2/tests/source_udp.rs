use super::*;

async fn udp_wire_peer(
    target: SocketAddr,
    domain: Option<&str>,
) -> (Endpoint, Arc<dyn PacketTransport>, quinn::Connection, u32) {
    let (endpoint, address) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    let server = endpoint.clone();
    let peer = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (send, recv) = conn.accept_bi().await.unwrap();
        handle_server_stream(
            send,
            recv,
            Arc::new(AtomicBool::new(false)),
            TEST_PASSWORD,
            Duration::ZERO,
            0,
            true,
        )
        .await;
        let first = conn.read_datagram().await.unwrap();
        assert!(first.len() >= 9);
        let session = u32::from_be_bytes(first[..4].try_into().unwrap());
        (conn, session)
    });
    let transport = Hysteria2Handler::new()
        .dial_udp_transport(
            &test_node(address.port(), TEST_PASSWORD),
            target,
            domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    transport.send_packet(b"prime").await.unwrap();
    let (conn, session) = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    (endpoint, transport, conn, session)
}

fn reply_frame(
    session: u32,
    packet: u16,
    fragment: u8,
    total: u8,
    peer: &str,
    payload: &[u8],
) -> Bytes {
    // Independent short-vstring wire vector, not the production encoder.
    assert!(peer.len() < 64);
    let mut frame = session.to_be_bytes().to_vec();
    frame.extend_from_slice(&packet.to_be_bytes());
    frame.extend_from_slice(&[fragment, total, peer.len() as u8]);
    frame.extend_from_slice(peer.as_bytes());
    frame.extend_from_slice(payload);
    frame.into()
}

#[tokio::test]
async fn udp_reply_source_survives_reassembly() {
    for (target, peer, expected_peer) in [
        ("192.0.2.1:53", "192.0.2.99:5353", "192.0.2.99:5353"),
        (
            "192.0.2.1:53",
            "[::ffff:192.0.2.99]:5353",
            "192.0.2.99:5353",
        ),
        (
            "[2001:db8::1]:53",
            "[2001:db8::99]:5353",
            "[2001:db8::99]:5353",
        ),
    ] {
        let target = target.parse().unwrap();
        let (_endpoint, transport, conn, session) = udp_wire_peer(target, None).await;
        assert!(transport.allows_full_cone_replies());
        for (packet, frames, expected) in [
            (1, vec![(0, 1, b"single".as_slice())], b"single".as_slice()),
            (
                2,
                vec![(1, 2, b"tail".as_slice()), (0, 2, b"head".as_slice())],
                b"headtail".as_slice(),
            ),
        ] {
            for (fragment, total, payload) in frames {
                let peer = if total > 1 && fragment == 0 {
                    expected_peer
                } else {
                    peer
                };
                conn.send_datagram_wait(reply_frame(
                    session, packet, fragment, total, peer, payload,
                ))
                .await
                .unwrap();
            }
            let mut buf = [0; 32];
            let (n, source) =
                tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(
                (source, &buf[..n]),
                (expected_peer.parse().unwrap(), expected)
            );
            assert_eq!(transport.relay_addr(), target);
        }
    }
}

#[tokio::test]
async fn udp_fragments_reject_conflicting_sources() {
    let target = "192.0.2.1:53".parse().unwrap();
    let (_endpoint, transport, conn, session) = udp_wire_peer(target, None).await;
    for (fragment, peer, payload) in [
        (1, "192.0.2.99:5353", b"tail".as_slice()),
        (1, "192.0.2.88:5353", b"duplicate".as_slice()),
        (0, "192.0.2.88:5353", b"wrong".as_slice()),
        (0, "192.0.2.99:5353", b"head".as_slice()),
    ] {
        conn.send_datagram_wait(reply_frame(session, 1, fragment, 2, peer, payload))
            .await
            .unwrap();
    }
    let mut buf = [0; 32];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (peer, &buf[..n]),
        ("192.0.2.99:5353".parse().unwrap(), b"headtail".as_slice())
    );
    conn.send_datagram_wait(reply_frame(session, 2, 0, 1, "192.0.2.88:5353", b"next"))
        .await
        .unwrap();
    let (n, peer) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (peer, &buf[..n]),
        ("192.0.2.88:5353".parse().unwrap(), b"next".as_slice())
    );
}

#[tokio::test]
async fn udp_domain_reply_requires_exact_captured_target() {
    let target = "192.0.2.1:53".parse().unwrap();
    for (domain, reply_domain) in [
        (None, "requested.invalid:53"),
        (None, "ReQuEsTeD.InVaLiD:53"),
        (Some("requested.invalid"), "requested.invalid:53"),
        (Some("requested.invalid"), "ReQuEsTeD.InVaLiD:53"),
    ] {
        let (_endpoint, transport, conn, session) = udp_wire_peer(target, domain).await;
        for (packet, peer, payload) in [
            (1, "FoReIgN.InVaLiD:53", b"foreign".as_slice()),
            (2, "ReQuEsTeD.InVaLiD:54", b"wrong port".as_slice()),
            (3, reply_domain, b"domain".as_slice()),
            (4, "192.0.2.1:53", b"numeric".as_slice()),
        ] {
            conn.send_datagram_wait(reply_frame(session, packet, 0, 1, peer, payload))
                .await
                .unwrap();
        }
        let mut buf = [0; 32];
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, target);
        assert_eq!(
            &buf[..n],
            if domain.is_some() {
                b"domain".as_slice()
            } else {
                b"numeric".as_slice()
            }
        );
    }
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn udp_request_observation_follows_each_source_view() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver, Milestone};

    for speculative in [Some(false), Some(true), None] {
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let [a, b, failed] = std::array::from_fn::<_, 3, _>(|_| {
            let events = Arc::clone(&events);
            FlowObserver::new(
                FlowContext {
                    flow_id: uuid::Uuid::new_v4(),
                    generation: 1,
                    attempt_id: None,
                    lookup_id: None,
                    dns_purpose: "proxy_server",
                },
                Arc::new(move |context, event| {
                    if matches!(
                        event,
                        FlowEvent::Milestone {
                            milestone: Milestone::TargetRequestSent
                        }
                    ) {
                        events.lock().push(context.flow_id);
                    }
                }),
            )
        });
        let address = start_server(TEST_PASSWORD).await;
        let mut node = test_node(address.port(), TEST_PASSWORD);
        node.id = node.derive_id();
        let mut runtime = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
        let handler = Hysteria2Handler::new();
        let target = "192.0.2.1:53".parse().unwrap();
        let other = "192.0.2.2:5353".parse().unwrap();
        let transport = {
            let prepare = async {
                if let Some(speculative) = speculative {
                    handler
                        .prepare_udp_source(
                            runtime.runtime(),
                            target,
                            None,
                            Duration::from_secs(5),
                            speculative,
                        )
                        .await
                        .unwrap()
                        .commit()
                        .await
                        .unwrap()
                } else {
                    let client = handler.build_client(&node, None).await.unwrap();
                    handler
                        .udp_transport_via_client(client, target, None, Duration::from_secs(5))
                        .await
                        .unwrap()
                }
            };
            tokio::pin!(prepare);
            a.scope(&mut prepare).await
        };
        assert_eq!(transport.server_addr(), address);
        assert!(events.lock().is_empty());
        assert!(
            b.scope(transport.send_to(other, None, &vec![0; MAX_UDP_SIZE + 1], None))
                .await
                .is_err()
        );
        assert!(events.lock().is_empty());
        transport
            .send_to(other, None, b"unobserved", None)
            .await
            .unwrap();
        let mut buf = [0; 32];
        let (n, peer) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!((peer, &buf[..n]), (other, b"unobserved".as_slice()));
        if speculative.is_some() {
            assert!(events.lock().is_empty());
        } else {
            assert_eq!(events.lock().as_slice(), &[a.context().flow_id]);
        }
        for (observer, peer) in [(&b, other), (&b, other), (&a, target), (&a, target)] {
            observer
                .scope(transport.send_to(peer, None, b"observed", None))
                .await
                .unwrap();
            let (n, source) =
                tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!((source, &buf[..n]), (peer, b"observed".as_slice()));
        }
        let expected = if speculative.is_some() {
            [b.context().flow_id, a.context().flow_id]
        } else {
            [a.context().flow_id, b.context().flow_id]
        };
        assert_eq!(events.lock().as_slice(), &expected);
        transport.state.conn.close(0u32.into(), b"test closed");
        assert!(
            failed
                .scope(transport.send_to(other, None, b"failed", None))
                .await
                .is_err()
        );
        assert_eq!(events.lock().as_slice(), &expected);
        drop(transport);
        runtime.close().await.unwrap();
    }
}

#[tokio::test]
async fn udp_source_send_to_tracks_physical_admission() {
    let address = start_server(TEST_PASSWORD).await;
    let handler = Hysteria2Handler::new();
    let client = handler
        .build_client(&test_node(address.port(), TEST_PASSWORD), None)
        .await
        .unwrap();
    let target = "192.0.2.1:53".parse().unwrap();
    let other = "192.0.2.2:5353".parse().unwrap();
    let transport = handler
        .udp_transport_via_client(client, target, None, Duration::from_secs(5))
        .await
        .unwrap();
    let admitted = AtomicBool::new(false);
    assert!(
        transport
            .send_to(other, None, &[0; MAX_UDP_SIZE + 1], Some(&admitted))
            .await
            .is_err()
    );
    assert!(!admitted.load(Ordering::Acquire));
    transport
        .send_to(other, None, b"", Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));
    admitted.store(false, Ordering::Release);
    transport
        .send_to(other, None, b"other target", Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));
    let mut buf = [0; 32];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((source, &buf[..n]), (other, b"other target".as_slice()));
    assert_eq!(transport.relay_addr(), target);
    admitted.store(false, Ordering::Release);
    transport.state.conn.close(0u32.into(), b"test closed");
    assert!(
        transport
            .send_to(other, None, b"next", Some(&admitted))
            .await
            .is_err()
    );
    assert!(!admitted.load(Ordering::Acquire));
}
