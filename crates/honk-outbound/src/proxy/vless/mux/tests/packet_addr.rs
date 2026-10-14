use super::*;

// An independent sing-mux PacketAddr peer. Every address is spelled out from
// the wire spec: flags UDP|Addr = 3, SOCKS5 ATYPs (IPv4=1, domain=3, IPv6=4),
// then `[address][port][u16 length][payload]` both ways.
const PA_A: &str = "198.51.100.10:5301";
const PA_A_ADDR: [u8; 5] = [1, 198, 51, 100, 10];
const PA_B_ADDR: [u8; 5] = [1, 203, 0, 113, 20];
const PA_C_ADDR: [u8; 5] = [1, 192, 0, 2, 30];

fn pa_frame(address: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = address.to_vec();
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn pa_domain(domain: &str) -> Vec<u8> {
    let mut address = vec![3, domain.len() as u8];
    address.extend_from_slice(domain.as_bytes());
    address
}

async fn serve_with<F, Fut>(wire: tokio::io::DuplexStream, handler: F)
where
    F: Fn(http::Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let io = server_carrier(wire, false).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    while let Some(request) = connection.accept().await {
        let (request, respond) = request.unwrap();
        tokio::spawn(handler(request, respond));
    }
}

async fn pa_open(
    session: &Arc<VlessMuxSession>,
    target: &str,
    domain: Option<&str>,
) -> Arc<VlessMuxUdpTransport> {
    let permit = session.try_reserve().unwrap();
    Arc::clone(session)
        .open_packet(permit, target.parse().unwrap(), domain)
        .await
        .unwrap_or_else(|_| panic!("PacketAddr stream must open"))
}

async fn pa_recv(udp: &VlessMuxUdpTransport) -> (Vec<u8>, std::net::SocketAddr) {
    let mut buffer = vec![0; crate::proxy::uot::MAX_PACKET_SIZE];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        udp.recv_packet(&mut buffer),
    )
    .await
    .expect("PacketAddr datagram stalled")
    .unwrap();
    buffer.truncate(size);
    (buffer, peer)
}

#[test]
fn packet_addr_request_flags_and_first_destination() {
    assert_eq!(FLAG_UDP | FLAG_ADDR, 3);
    assert_eq!(
        stream_request(3, PA_A.parse().unwrap(), None)
            .unwrap()
            .as_ref(),
        [0, 3, 1, 198, 51, 100, 10, 0x14, 0xb5]
    );
}

#[tokio::test]
async fn consecutive_address_frames_both_directions() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let domain = "target.example";
    let uplink = [
        // Request (flags, then the captured name as a SOCKS domain), then the first datagram.
        [
            &[0, 3][..],
            &pa_domain(domain)[..],
            &5301u16.to_be_bytes()[..],
        ]
        .concat(),
        pa_frame(&pa_domain(domain), 5301, b"one"),
        pa_frame(&PA_B_ADDR, 5302, b"two"),
        // A name other than the dialed one goes out numerically.
        pa_frame(&PA_C_ADDR, 5303, b""),
        pa_frame(
            &[
                4, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30,
            ],
            5304,
            b"six",
        ),
    ]
    .concat();
    let expected_uplink = uplink.clone();
    let reply = [
        pa_frame(&PA_A_ADDR, 5301, b"a-reply"),
        pa_frame(&pa_domain("TARGET.Example"), 5301, b"projected"),
        pa_frame(&PA_C_ADDR, 5303, b"unsolicited"),
        pa_frame(&pa_domain("other.example"), 5301, b"stranger"),
        pa_frame(&pa_domain("target.example"), 1, b"wrong-port"),
        pa_frame(&PA_B_ADDR, 5302, b""),
    ]
    .concat();
    let server = tokio::spawn(serve_with(server, move |request, mut respond| {
        let expected = expected_uplink.clone();
        let reply = reply.clone();
        async move {
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let mut recv = request.into_body();
            let mut body = BytesMut::new();
            receive_at_least(&mut recv, &mut body, expected.len()).await;
            assert_eq!(&body[..], &expected[..]);
            // Split mid-frame to exercise reassembly across DATA frames.
            let mut wire = vec![0];
            wire.extend_from_slice(&reply);
            let cut = 13;
            let tail = wire.split_off(cut);
            send_owned(&mut send, &CarrierFailure::default(), Bytes::from(wire))
                .await
                .unwrap();
            send_owned(&mut send, &CarrierFailure::default(), Bytes::from(tail))
                .await
                .unwrap();
            while recv.data().await.is_some_and(|data| data.is_ok()) {}
        }
    }));
    let session = connect(Box::new(client), false).await.unwrap();
    let udp = pa_open(&session, PA_A, Some(domain)).await;
    udp.send_packet_confirmed(b"one").await.unwrap();
    udp.send_to(
        "203.0.113.20:5302".parse().unwrap(),
        None,
        b"two",
        false,
        None,
    )
    .await
    .unwrap();
    udp.send_to(
        "192.0.2.30:5303".parse().unwrap(),
        Some("c.example"),
        b"",
        false,
        None,
    )
    .await
    .unwrap();
    udp.send_to(
        "[2001:db8::30]:5304".parse().unwrap(),
        None,
        b"six",
        false,
        None,
    )
    .await
    .unwrap();

    for (payload, peer) in [
        (&b"a-reply"[..], PA_A),
        (b"projected", PA_A),
        (b"unsolicited", "192.0.2.30:5303"),
        (b"", "203.0.113.20:5302"),
    ] {
        assert_eq!(
            pa_recv(&udp).await,
            (payload.to_vec(), peer.parse().unwrap())
        );
    }
    drop(udp);
    session.close();
    server.abort();
}

#[tokio::test]
async fn uplink_boundaries_and_unknown_reply_atyp() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_with(server, |request, mut respond| async move {
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let mut recv = request.into_body();
        let mut body = BytesMut::new();
        receive_at_least(&mut recv, &mut body, 9 + 5 + 4 + 65535).await;
        // 9-byte request, then B's maximum datagram is the first frame.
        assert_eq!(&body[..9], &[0, 3, 1, 198, 51, 100, 10, 0x14, 0xb5]);
        assert_eq!(
            &body[9..9 + 5 + 4],
            &[1, 203, 0, 113, 20, 0x14, 0xb6, 0xff, 0xff]
        );
        // ATYP 0 is not SOCKS5: the stream has no derivable length after it.
        send_owned(
            &mut send,
            &CarrierFailure::default(),
            Bytes::from_static(&[0, 0, 1, 2, 3, 4]),
        )
        .await
        .unwrap();
        while recv.data().await.is_some_and(|data| data.is_ok()) {}
    }));
    let session = connect(Box::new(client), false).await.unwrap();
    let udp = pa_open(&session, PA_A, None).await;
    let oversized = vec![0; crate::proxy::uot::MAX_PACKET_SIZE + 1];
    let error = udp
        .send_to(
            "203.0.113.20:5302".parse().unwrap(),
            None,
            &oversized,
            false,
            None,
        )
        .await
        .unwrap_err();
    assert!(crate::proxy::is_packet_rejection(&anyhow::Error::new(
        error
    )));
    // Local rejection kept the pending request and the stream.
    let maximum = vec![0x77; crate::proxy::uot::MAX_PACKET_SIZE];
    udp.send_to(
        "203.0.113.20:5302".parse().unwrap(),
        None,
        &maximum,
        true,
        None,
    )
    .await
    .unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        udp.recv_packet(&mut [0; 8]),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    drop(udp);
    session.close();
    server.abort();
}

/// A write cancelled while the peer's window is closed leaves the shared
/// stream poisoned; a sibling destination must fail instead of appending.
#[tokio::test]
async fn cancelled_write_poisons_the_shared_stream() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_with(server, |request, mut respond| async move {
        let _send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        // Never reading the body keeps the default 64 KiB window closed.
        let _recv = request.into_body();
        std::future::pending::<()>().await;
    }));
    let session = connect(Box::new(client), false).await.unwrap();
    let udp = pa_open(&session, PA_A, None).await;
    let maximum = vec![0x77; crate::proxy::uot::MAX_PACKET_SIZE];
    let stalled = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        udp.send_to(
            "203.0.113.20:5302".parse().unwrap(),
            None,
            &maximum,
            false,
            None,
        ),
    )
    .await;
    assert!(stalled.is_err(), "the closed window must stall the write");
    assert!(udp.frame_stream_torn());
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        udp.send_to(PA_A.parse().unwrap(), None, b"x", false, None),
    )
    .await
    .expect("a poisoned stream refuses the next frame instead of queueing it")
    .unwrap_err();
    assert!(crate::proxy::is_frame_interrupted(&error));
    drop(udp);
    session.close();
    server.abort();
}

/// Dropped (foreign-domain) frames must return their H2 credit: this server
/// sends ~10 MB of them, far above any receive window, before one real frame.
#[tokio::test]
async fn dropped_domain_frames_release_their_h2_credit() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_with(server, |request, mut respond| async move {
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let mut recv = request.into_body();
        let carrier = CarrierFailure::default();
        send_owned(&mut send, &carrier, Bytes::from_static(&[0]))
            .await
            .unwrap();
        let junk = Bytes::from(pa_frame(
            &pa_domain("stranger.example"),
            5301,
            &[0xee; 60_000],
        ));
        for _ in 0..170 {
            send_owned(&mut send, &carrier, junk.clone()).await.unwrap();
        }
        send_owned(
            &mut send,
            &carrier,
            Bytes::from(pa_frame(&PA_B_ADDR, 5302, b"survivor")),
        )
        .await
        .unwrap();
        while recv.data().await.is_some_and(|data| data.is_ok()) {}
    }));
    let session = connect(Box::new(client), false).await.unwrap();
    let udp = pa_open(&session, PA_A, Some("target.example")).await;
    assert_eq!(
        pa_recv(&udp).await,
        (b"survivor".to_vec(), "203.0.113.20:5302".parse().unwrap())
    );
    drop(udp);
    session.close();
    server.abort();
}

/// With every slot holding an unread maximum frame (widest domain address, full
/// payload) the connection window must still admit each frame whole.
#[tokio::test]
async fn full_slot_maximum_frames_all_arrive_before_any_read() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let domain = "x".repeat(255);
    let sent = Arc::new(tokio::sync::Semaphore::new(0));
    let server = {
        let sent = Arc::clone(&sent);
        let domain = domain.clone();
        tokio::spawn(serve_with(server, move |_request, mut respond| {
            let sent = Arc::clone(&sent);
            let frame = {
                let mut wire = vec![0];
                wire.extend(pa_frame(
                    &pa_domain(&domain),
                    5301,
                    &vec![0x5a; crate::proxy::uot::MAX_PACKET_SIZE],
                ));
                Bytes::from(wire)
            };
            async move {
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                send_owned(&mut send, &CarrierFailure::default(), frame)
                    .await
                    .unwrap();
                sent.add_permits(1);
                // Keep the stream alive until the client has read it.
                std::future::pending::<()>().await;
            }
        }))
    };
    let session = connect(Box::new(client), false).await.unwrap();
    let mut streams = Vec::new();
    for _ in 0..MAX_STREAMS_PER_SESSION {
        streams.push(pa_open(&session, PA_A, Some(&domain)).await);
    }
    let all = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        sent.acquire_many(MAX_STREAMS_PER_SESSION as u32),
    )
    .await
    .expect("maximum frames exhausted the connection window before any read")
    .unwrap();
    drop(all);
    for udp in &streams {
        let (payload, peer) = pa_recv(udp).await;
        assert_eq!(payload.len(), crate::proxy::uot::MAX_PACKET_SIZE);
        assert_eq!(peer, PA_A.parse().unwrap());
    }
    drop(streams);
    session.close();
    server.abort();
}

/// Both directions move several times the receive window while the reader
/// keeps pace: a credit leak of even a few bytes per frame would stall it.
#[tokio::test]
async fn long_mixed_streams_do_not_stall() {
    const FRAMES: usize = 4000;
    const PAYLOAD: usize = 1200;
    let (client, server) = tokio::io::duplex(1 << 20);
    let uplink = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server = tokio::spawn(serve_with(server, {
        let uplink = Arc::clone(&uplink);
        move |request, mut respond| {
            let uplink = Arc::clone(&uplink);
            async move {
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut recv = request.into_body();
                let carrier = CarrierFailure::default();
                let writer = async {
                    send_owned(&mut send, &carrier, Bytes::from_static(&[0]))
                        .await
                        .unwrap();
                    for index in 0..FRAMES {
                        let frame = match index % 4 {
                            0 => pa_frame(&PA_A_ADDR, 5301, &[index as u8; PAYLOAD]),
                            1 => pa_frame(&PA_B_ADDR, 5302, &[index as u8; PAYLOAD]),
                            2 => pa_frame(&PA_C_ADDR, 5303, &[index as u8; PAYLOAD]),
                            _ => pa_frame(
                                &pa_domain("Target.Example"),
                                5301,
                                &[index as u8; PAYLOAD],
                            ),
                        };
                        send_owned(&mut send, &carrier, Bytes::from(frame))
                            .await
                            .unwrap();
                    }
                };
                let reader = async {
                    while let Some(Ok(data)) = recv.data().await {
                        uplink.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                        recv.flow_control().release_capacity(data.len()).unwrap();
                    }
                };
                tokio::join!(writer, reader);
            }
        }
    }));
    let session = connect(Box::new(client), false).await.unwrap();
    let udp = pa_open(&session, PA_A, Some("target.example")).await;
    let sender = {
        let udp = Arc::clone(&udp);
        tokio::spawn(async move {
            for index in 0..FRAMES {
                let (peer, domain) = match index % 3 {
                    0 => ("198.51.100.10:5301", None),
                    1 => ("203.0.113.20:5302", None),
                    _ => ("192.0.2.30:5303", Some("c.example")),
                };
                udp.send_to(
                    peer.parse().unwrap(),
                    domain,
                    &[index as u8; PAYLOAD],
                    false,
                    None,
                )
                .await
                .unwrap();
            }
        })
    };
    for index in 0..FRAMES {
        let (payload, peer) = pa_recv(&udp).await;
        assert_eq!(payload, vec![index as u8; PAYLOAD]);
        let expected = match index % 4 {
            0 | 3 => PA_A,
            1 => "203.0.113.20:5302",
            _ => "192.0.2.30:5303",
        };
        assert_eq!(peer, expected.parse().unwrap(), "frame {index}");
    }
    tokio::time::timeout(std::time::Duration::from_secs(20), sender)
        .await
        .expect("uplink stalled")
        .unwrap();
    let required = FRAMES * (9 + PAYLOAD);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while uplink.load(std::sync::atomic::Ordering::Relaxed) < required {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server received fewer uplink bytes than were sent");
    drop(udp);
    session.close();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
}
