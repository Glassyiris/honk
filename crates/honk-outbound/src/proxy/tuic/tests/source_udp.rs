use super::*;

async fn udp_wire_peer(
    datagrams: bool,
    target: SocketAddr,
    domain: Option<&str>,
) -> (
    quinn::Endpoint,
    Arc<dyn PacketTransport>,
    quinn::Connection,
    u16,
) {
    let (endpoint, address) = testutil::server_endpoint(&[b"tuic"], datagrams).unwrap();
    let server = endpoint.clone();
    let peer = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut auth = conn.accept_uni().await.unwrap();
        let mut bytes = [0; 50];
        read_exact(&mut auth, &mut bytes).await.unwrap();
        assert_eq!(&bytes[..2], &[5, 0]);
        let mut token = [0; 32];
        conn.export_keying_material(&mut token, &bytes[2..18], TEST_PASSWORD.as_bytes())
            .unwrap();
        assert_eq!(token, bytes[18..]);
        let first = if datagrams {
            conn.read_datagram().await.unwrap().to_vec()
        } else {
            conn.accept_uni()
                .await
                .unwrap()
                .read_to_end(65536)
                .await
                .unwrap()
        };
        assert_eq!(&first[..2], &[5, 2]);
        assert_eq!(
            &first[8..10],
            &[0, 0],
            "first zero-length datagram must reach the wire"
        );
        let session = u16::from_be_bytes(first[2..4].try_into().unwrap());
        (conn, session)
    });
    let transport = TuicHandler::new()
        .dial_udp_transport(
            &test_node(address.port(), TEST_PASSWORD),
            target,
            domain,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    transport.send_packet(b"").await.unwrap();
    let (conn, session) = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    (endpoint, transport, conn, session)
}

fn reply_frame(
    session: u16,
    packet: u16,
    fragment: u8,
    total: u8,
    peer: Option<SocketAddr>,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![5, 2];
    frame.extend_from_slice(&session.to_be_bytes());
    frame.extend_from_slice(&packet.to_be_bytes());
    frame.extend_from_slice(&[total, fragment]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    match peer {
        Some(SocketAddr::V4(peer)) => {
            frame.push(1);
            frame.extend_from_slice(&peer.ip().octets());
            frame.extend_from_slice(&peer.port().to_be_bytes());
        }
        Some(SocketAddr::V6(peer)) => {
            frame.push(2);
            frame.extend_from_slice(&peer.ip().octets());
            frame.extend_from_slice(&peer.port().to_be_bytes());
        }
        None => frame.push(255),
    }
    frame.extend_from_slice(payload);
    frame
}

async fn send_reply(conn: &quinn::Connection, datagrams: bool, frame: Vec<u8>) {
    if datagrams {
        conn.send_datagram_wait(frame.into()).await.unwrap();
    } else {
        let mut send = conn.open_uni().await.unwrap();
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
    }
}

#[tokio::test]
async fn udp_reply_source_survives_datagram_and_stream() {
    for datagrams in [true, false] {
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
            let peer = peer.parse().unwrap();
            let expected_peer: SocketAddr = expected_peer.parse().unwrap();
            let (_endpoint, transport, conn, session) =
                udp_wire_peer(datagrams, target, None).await;
            for (packet, payload) in [
                (1, b"".as_slice()),
                (2, b"foreign".as_slice()),
                (3, b"".as_slice()),
            ] {
                send_reply(
                    &conn,
                    datagrams,
                    reply_frame(session, packet, 0, 1, Some(peer), payload),
                )
                .await;
                let mut buf = [0; 32];
                let (n, source) =
                    tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!((source, &buf[..n]), (expected_peer, payload));
            }
            assert!(transport.allows_full_cone_replies());
            assert_eq!(transport.relay_addr(), target);
            send_reply(
                &conn,
                datagrams,
                reply_frame(session, 4, 0, 1, Some(peer), b"too long"),
            )
            .await;
            let err =
                tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut [0; 2]))
                    .await
                    .unwrap()
                    .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            transport.send_packet(b"").await.unwrap();
            let later = if datagrams {
                conn.read_datagram().await.unwrap().to_vec()
            } else {
                conn.accept_uni()
                    .await
                    .unwrap()
                    .read_to_end(65536)
                    .await
                    .unwrap()
            };
            assert_eq!(&later[8..10], &[0, 0]);
            assert_eq!(u16::from_be_bytes(later[2..4].try_into().unwrap()), session);
        }
    }
}

#[tokio::test]
async fn udp_reply_fragment_zero_last_preserves_source() {
    for datagrams in [true, false] {
        let target = "192.0.2.1:53".parse().unwrap();
        let peer = "192.0.2.99:5353".parse().unwrap();
        let mapped = "[::ffff:192.0.2.99]:5353".parse().unwrap();
        let other = "192.0.2.88:5353".parse().unwrap();
        let (_endpoint, transport, conn, session) = udp_wire_peer(datagrams, target, None).await;
        for (packet, fragment, total, address, payload) in [
            (1, 0, 1, None, b"missing peer".as_slice()),
            (2, 1, 3, None, b"middle".as_slice()),
            (2, 1, 3, Some(other), b"duplicate".as_slice()),
            (2, 2, 3, None, b"tail".as_slice()),
            (2, 0, 3, Some(mapped), b"head".as_slice()),
        ] {
            send_reply(
                &conn,
                datagrams,
                reply_frame(session, packet, fragment, total, address, payload),
            )
            .await;
            if packet != 2 || fragment != 0 {
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        transport.recv_packet(&mut [0; 32])
                    )
                    .await
                    .is_err()
                );
            }
        }
        let mut buf = [0; 32];
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!((source, &buf[..n]), (peer, b"headmiddletail".as_slice()));
        for (fragment, address, payload) in [
            (0, peer, b"good".as_slice()),
            (1, other, b"wrong".as_slice()),
            (1, mapped, b"tail".as_slice()),
        ] {
            send_reply(
                &conn,
                datagrams,
                reply_frame(session, 3, fragment, 2, Some(address), payload),
            )
            .await;
            if fragment == 0 || address == other {
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        transport.recv_packet(&mut buf)
                    )
                    .await
                    .is_err()
                );
            }
        }
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!((source, &buf[..n]), (peer, b"goodtail".as_slice()));
    }
}

#[tokio::test]
async fn udp_domain_reply_requires_exact_captured_target() {
    for datagrams in [true, false] {
        for (domain, reply_domain) in [
            (None, "requested.invalid"),
            (None, "ReQuEsTeD.InVaLiD"),
            (Some("requested.invalid"), "requested.invalid"),
            (Some("requested.invalid"), "ReQuEsTeD.InVaLiD"),
        ] {
            let target = "192.0.2.1:53".parse().unwrap();
            let (_endpoint, transport, conn, session) =
                udp_wire_peer(datagrams, target, domain).await;
            for (packet, name, port, payload) in [
                (1, "FoReIgN.InVaLiD", 53u16, b"foreign".as_slice()),
                (2, "ReQuEsTeD.InVaLiD", 54, b"wrong port".as_slice()),
                (3, reply_domain, 53, b"domain".as_slice()),
            ] {
                let mut frame = reply_frame(session, packet, 0, 1, None, payload);
                frame.truncate(10);
                frame.extend_from_slice(&[0, name.len() as u8]);
                frame.extend_from_slice(name.as_bytes());
                frame.extend_from_slice(&port.to_be_bytes());
                frame.extend_from_slice(payload);
                send_reply(&conn, datagrams, frame).await;
                let mut buf = [0; 32];
                if packet == 3 && domain.is_some() {
                    let (n, source) = tokio::time::timeout(
                        Duration::from_secs(5),
                        transport.recv_packet(&mut buf),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!((source, &buf[..n]), (target, b"domain".as_slice()));
                } else {
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(20),
                            transport.recv_packet(&mut buf)
                        )
                        .await
                        .is_err()
                    );
                }
            }
            send_reply(
                &conn,
                datagrams,
                reply_frame(session, 4, 0, 1, Some(target), b"numeric"),
            )
            .await;
            let mut buf = [0; 32];
            let (n, source) =
                tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(source, target);
            assert_eq!(&buf[..n], b"numeric");
        }
    }
}

#[tokio::test]
async fn udp_stream_partial_write_marks_admission_without_replay() {
    let mut config = testutil::server_config(&[b"tuic"], false).unwrap();
    let mut limits = quinn::TransportConfig::default();
    limits.stream_receive_window(64u32.into());
    limits.datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(limits));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server = endpoint.clone();
    let peer = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut auth = conn.accept_uni().await.unwrap();
        let mut bytes = [0; 50];
        read_exact(&mut auth, &mut bytes).await.unwrap();
        (conn, auth)
    });
    let handler = TuicHandler::new();
    let node = test_node(endpoint.local_addr().unwrap().port(), TEST_PASSWORD);
    let client = handler.build_client(&node, None).await.unwrap();
    let target = "192.0.2.1:53".parse().unwrap();
    let transport = handler
        .udp_transport_via_client(client, target, None, Duration::from_secs(5))
        .await
        .unwrap();
    let (conn, _auth) = tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .unwrap()
        .unwrap();
    let admitted = AtomicBool::new(false);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.send_to(target, None, &[7; 1024], Some(&admitted))
        )
        .await
        .is_err()
    );
    assert!(
        admitted.load(Ordering::Acquire),
        "accepted stream prefix is irreversible"
    );
    let mut packet = conn.accept_uni().await.unwrap();
    let mut prefix = [0; 64];
    tokio::time::timeout(Duration::from_secs(5), read_exact(&mut packet, &mut prefix))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&prefix[..2], &[5, 2]);
    assert_eq!(&prefix[8..10], &1024u16.to_be_bytes());
    assert_eq!(&prefix[17..], &[7; 47]);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), conn.accept_uni())
            .await
            .is_err(),
        "partial packet must not be replayed"
    );
    admitted.store(false, Ordering::Release);
    transport.state.conn.close(0u32.into(), b"test closed");
    assert!(
        transport
            .send_to(target, None, b"next", Some(&admitted))
            .await
            .is_err()
    );
    assert!(
        !admitted.load(Ordering::Acquire),
        "failed stream open is not admission"
    );
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn udp_request_observation_follows_each_source_view() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver, Milestone};

    for datagrams in [true, false] {
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
            let address = start_server(datagrams, TEST_PASSWORD).await;
            let mut node = test_node(address.port(), TEST_PASSWORD);
            node.id = node.derive_id();
            let mut runtime = crate::runtime::NodeRuntime::try_ephemeral_guarded(&node).unwrap();
            let handler = TuicHandler::new();
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
                b.scope(transport.send_to(other, None, &vec![0; u16::MAX as usize + 1], None))
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
}

#[tokio::test]
async fn udp_source_send_to_tracks_physical_admission() {
    for datagrams in [true, false] {
        let address = start_server(datagrams, TEST_PASSWORD).await;
        let handler = TuicHandler::new();
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
                .send_to(
                    other,
                    None,
                    &vec![0; u16::MAX as usize + 1],
                    Some(&admitted)
                )
                .await
                .is_err()
        );
        assert!(!admitted.load(Ordering::Acquire));
        for payload in [b"".as_slice(), b"other target".as_slice()] {
            admitted.store(false, Ordering::Release);
            transport
                .send_to(other, None, payload, Some(&admitted))
                .await
                .unwrap();
            assert!(admitted.load(Ordering::Acquire));
            let mut buf = [0; 32];
            let (n, source) =
                tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!((source, &buf[..n]), (other, payload));
        }
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
}
