use super::padding::{H2MUX_BACKEND, PADDED_RECORDS};
use super::*;
use crate::session::SpeculativeCheckout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn receive_windows_cover_every_maximum_udp_frame() {
    // Status byte, domain address (ATYP + length + 255 + port), u16 length, payload.
    let maximum_response_frame = 1 + (1 + 1 + 255 + 2) + 2 + 65535;
    assert!(H2_STREAM_RECV_WINDOW as usize >= maximum_response_frame);
    assert_eq!(
        H2_CONNECTION_RECV_WINDOW as usize,
        maximum_response_frame * MAX_STREAMS_PER_SESSION
    );
}

#[test]
fn physical_preface_matches_sing_mux() {
    assert_eq!(&mux_preface(false)[..], &[0, H2MUX_BACKEND]);
    let padded = mux_preface(true);
    assert_eq!(&padded[..3], &[1, H2MUX_BACKEND, 1]);
    let length = u16::from_be_bytes([padded[3], padded[4]]) as usize;
    assert!((256..768).contains(&length));
    assert_eq!(padded.len(), 5 + length);
}

#[test]
fn stream_request_rejects_overlong_domains() {
    let domain = "x".repeat(256);
    assert_eq!(
        stream_request(0, "127.0.0.1:443".parse().unwrap(), Some(&domain))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[tokio::test]
async fn padding_frames_first_sixteen_records_per_direction() {
    let (client, mut wire) = tokio::io::duplex(1 << 20);
    let mut padded = PaddingStream::new(client, true);
    for value in 0..PADDED_RECORDS {
        padded.write_all(&[value]).await.unwrap();
        padded.flush().await.unwrap();
        let mut header = [0; 4];
        wire.read_exact(&mut header).await.unwrap();
        assert_eq!(u16::from_be_bytes([header[0], header[1]]), 1);
        let padding = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut body = vec![0; 1 + padding];
        wire.read_exact(&mut body).await.unwrap();
        assert_eq!(body[0], value);
    }
    padded.write_all(b"raw").await.unwrap();
    padded.flush().await.unwrap();
    let mut raw = [0; 3];
    wire.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw, b"raw");

    for value in 0..PADDED_RECORDS {
        let padding = 256usize;
        wire.write_all(&[0, 1, 1, 0, value]).await.unwrap();
        wire.write_all(&vec![0; padding]).await.unwrap();
        let mut output = [0];
        padded.read_exact(&mut output).await.unwrap();
        assert_eq!(output[0], value);
    }
    wire.write_all(b"raw").await.unwrap();
    let mut raw = [0; 3];
    padded.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw, b"raw");
}

async fn receive_at_least(recv: &mut h2::RecvStream, body: &mut BytesMut, minimum: usize) -> bool {
    while body.len() < minimum {
        let Some(Ok(data)) = recv.data().await else {
            return false;
        };
        let size = data.len();
        body.extend_from_slice(&data);
        if recv.flow_control().release_capacity(size).is_err() {
            return false;
        }
    }
    true
}

async fn serve_logical_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
    let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
        return;
    };
    let mut recv = request.into_body();
    let mut body = BytesMut::new();
    if !receive_at_least(&mut recv, &mut body, 9).await {
        return;
    }
    match u16::from_be_bytes([body[0], body[1]]) {
        0 => {
            assert_eq!(&body[2..9], &[1, 93, 184, 216, 34, 1, 187]);
            if send
                .send_data(Bytes::from_static(b"\0hello"), false)
                .is_err()
                || !receive_at_least(&mut recv, &mut body, 13).await
            {
                return;
            }
            assert_eq!(&body[9..13], b"ping");
            if send.send_data(Bytes::from_static(b"pong"), false).is_err() {
                return;
            }
            while let Some(Ok(data)) = recv.data().await {
                let size = data.len();
                let _ = recv.flow_control().release_capacity(size);
            }
            let _ = send.send_data(Bytes::new(), true);
        }
        flags if flags == FLAG_UDP | FLAG_ADDR => {
            let address = body[2..9].to_vec();
            assert!(matches!(
                address.as_slice(),
                [1, 8, 8, 8, 8, 0, 53] | [1, 1, 1, 1, 1, 0, 53]
            ));
            let maximum = address[1] == 1;
            if !receive_at_least(&mut recv, &mut body, 21).await {
                return;
            }
            assert_eq!(&body[9..21], &[&address[..], b"\0\x03dns"].concat());
            let answer = if maximum {
                vec![0x5a; crate::proxy::uot::MAX_PACKET_SIZE]
            } else {
                b"answer".to_vec()
            };
            let mut response = BytesMut::with_capacity(1 + 7 + 2 + answer.len());
            response.extend_from_slice(&[0]);
            response.extend_from_slice(&address);
            response.extend_from_slice(&(answer.len() as u16).to_be_bytes());
            response.extend_from_slice(&answer);
            let _ = send.send_data(response.freeze(), true);
        }
        flags => panic!("unexpected mux flags {flags}"),
    }
}
async fn server_carrier(
    mut wire: tokio::io::DuplexStream,
    padded: bool,
) -> PaddingStream<tokio::io::DuplexStream> {
    if padded {
        let mut request = [0; 5];
        wire.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[1, H2MUX_BACKEND, 1]);
        let padding = u16::from_be_bytes([request[3], request[4]]) as usize;
        let mut ignored = vec![0; padding];
        wire.read_exact(&mut ignored).await.unwrap();
    } else {
        let mut request = [0; 2];
        wire.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [0, H2MUX_BACKEND]);
    }
    PaddingStream::new(wire, padded)
}

async fn serve_h2mux(
    wire: tokio::io::DuplexStream,
    padded: bool,
    goaway_after_first: bool,
) -> usize {
    let io = server_carrier(wire, padded).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut requests = 0;
    while let Some(request) = connection.accept().await {
        let (request, respond) = request.unwrap();
        requests += 1;
        tokio::spawn(serve_logical_stream(request, respond));
        if goaway_after_first && requests == 1 {
            connection.graceful_shutdown();
        }
    }
    requests
}

async fn exercise_h2mux(padded: bool) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_h2mux(server, padded, false));
    let session = connect(Box::new(client), padded).await.unwrap();

    let tcp_permit = session.try_reserve().unwrap();
    let mut tcp = Arc::clone(&session)
        .open_stream(tcp_permit, "93.184.216.34:443".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("TCP logical stream must open"));
    let mut greeting = [0; 5];
    tcp.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    tcp.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    tcp.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");

    let udp_permit = session.try_reserve().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(udp_permit, "8.8.8.8:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("UDP logical stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();
    assert_eq!(session.active_streams(), 2);
    assert_eq!(
        udp.recv_packet(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let mut answer = [0; 16];
    assert_eq!(
        udp.recv_packet(&mut answer).await.unwrap(),
        (6, "8.8.8.8:53".parse().unwrap())
    );
    assert_eq!(&answer[..6], b"answer");

    drop(udp);
    tcp.shutdown().await.unwrap();
    drop(tcp);
    assert_eq!(session.active_streams(), 0);
    session.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn tcp_and_udp_share_plain_and_padded_h2mux_carriers() {
    exercise_h2mux(false).await;
    exercise_h2mux(true).await;
}

#[tokio::test]
async fn maximum_udp_frame_cannot_exhaust_the_h2_receive_window() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_h2mux(server, false, false));
    let session = connect(Box::new(client), false).await.unwrap();
    let permit = session.try_reserve().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(permit, "1.1.1.1:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("maximum-frame UDP stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();

    let mut packet = vec![0; crate::proxy::uot::MAX_PACKET_SIZE];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        udp.recv_packet(&mut packet),
    )
    .await
    .expect("maximum UoT frame deadlocked HTTP/2 flow control")
    .unwrap();
    assert_eq!(size, crate::proxy::uot::MAX_PACKET_SIZE);
    assert_eq!(peer, "1.1.1.1:53".parse().unwrap());
    assert!(packet.iter().all(|byte| *byte == 0x5a));

    drop(udp);
    session.close();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn tcp_receive_window_admits_one_megabyte_before_reads() {
    const PAYLOAD_SIZE: usize = 1024 * 1024;

    let (client, server) = tokio::io::duplex(2 * PAYLOAD_SIZE);
    let (sent, sent_done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let writer = tokio::spawn(async move {
            let mut response = BytesMut::with_capacity(PAYLOAD_SIZE + 1);
            response.extend_from_slice(&[0]);
            response.resize(PAYLOAD_SIZE + 1, 0x5a);
            send_owned(&mut send, &Default::default(), response.freeze())
                .await
                .unwrap();
            send.send_data(Bytes::new(), true).unwrap();
            let _ = sent.send(());
        });
        while connection.accept().await.is_some() {}
        writer.await.unwrap();
    });

    let session = connect(Box::new(client), false).await.unwrap();
    let permit = session.try_reserve().unwrap();
    let mut tcp = Arc::clone(&session)
        .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("large-response TCP stream must open"));
    tokio::time::timeout(std::time::Duration::from_secs(2), sent_done)
        .await
        .expect("one-megabyte response stalled behind the initial H2 stream window")
        .unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert_eq!(response.len(), PAYLOAD_SIZE);
    assert!(response.iter().all(|byte| *byte == 0x5a));

    drop(tcp);
    session.close();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_tcp_stream_leaves_connection_credit_for_udp() {
    let capacity = H2_CONNECTION_RECV_WINDOW as usize + 1024 * 1024;
    let (client, server) = tokio::io::duplex(capacity);
    let (filled, filled_done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut filled = Some(filled);
        let mut writers = Vec::new();
        while let Some(request) = connection.accept().await {
            let (request, mut respond) = request.unwrap();
            if let Some(filled) = filled.take() {
                writers.push(tokio::spawn(async move {
                    let mut recv = request.into_body();
                    let mut request_body = BytesMut::new();
                    assert!(receive_at_least(&mut recv, &mut request_body, 9).await);
                    let mut send = respond
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    let mut response = BytesMut::with_capacity(H2_STREAM_RECV_WINDOW as usize);
                    response.extend_from_slice(&[0]);
                    response.resize(H2_STREAM_RECV_WINDOW as usize, 0x5a);
                    send_owned(&mut send, &Default::default(), response.freeze())
                        .await
                        .unwrap();
                    send.send_data(Bytes::new(), true).unwrap();
                    let _ = filled.send(());
                }));
            } else {
                writers.push(tokio::spawn(serve_logical_stream(request, respond)));
            }
        }
        for writer in writers {
            writer.await.unwrap();
        }
    });

    let session = connect(Box::new(client), false).await.unwrap();
    let tcp = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|error| match error {
            OpenError::Session(error) | OpenError::Draining(error) | OpenError::Refused(error) => {
                panic!("stalled TCP stream must open: {error:#}")
            }
        });
    tokio::time::timeout(std::time::Duration::from_secs(2), filled_done)
        .await
        .expect("peer could not fill one TCP stream window")
        .unwrap();

    let udp_target = "8.8.8.8:53".parse().unwrap();
    let udp = Arc::clone(&session)
        .open_packet(session.try_reserve().unwrap(), udp_target, None)
        .await
        .unwrap_or_else(|_| panic!("sibling UDP stream must open"));
    udp.send_packet_confirmed(b"dns").await.unwrap();
    let mut answer = [0; 16];
    let (size, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        udp.recv_packet(&mut answer),
    )
    .await
    .expect("stalled TCP stream consumed all H2 connection credit")
    .unwrap();
    assert_eq!(peer, udp_target);
    assert_eq!(&answer[..size], b"answer");

    drop(udp);
    drop(tcp);
    session.close();
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn goaway_rolls_over_without_cutting_the_live_stream() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let servers = Arc::new(Mutex::new(Vec::new()));
    let dial = {
        let dials = Arc::clone(&dials);
        let sessions = Arc::clone(&sessions);
        let servers = Arc::clone(&servers);
        move || {
            let dials = Arc::clone(&dials);
            let sessions = Arc::clone(&sessions);
            let servers = Arc::clone(&servers);
            async move {
                let index = dials.fetch_add(1, Ordering::AcqRel);
                let (client, server) = tokio::io::duplex(1 << 20);
                servers
                    .lock()
                    .push(tokio::spawn(serve_h2mux(server, false, index == 0)));
                let session = connect(Box::new(client), false).await?;
                sessions.lock().push(Arc::clone(&session));
                Ok(session)
            }
        }
    };
    let open = |session: Arc<VlessMuxSession>, permit: SessionPermit<VlessMuxSession>| async move {
        session
            .open_stream(permit, "93.184.216.34:443".parse().unwrap(), None)
            .await
    };

    let mut first = pool.open_with(dial.clone(), open).await.unwrap();
    let mut greeting = [0; 5];
    first.read_exact(&mut greeting).await.unwrap();
    first.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    first.read_exact(&mut pong).await.unwrap();

    let first_session = Arc::clone(&sessions.lock()[0]);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if matches!(
                Arc::clone(&first_session).check_ready().await,
                Err(OpenError::Draining(_))
            ) {
                first_session.begin_drain();
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut second = pool.open_with(dial, open).await.unwrap();
    second.read_exact(&mut greeting).await.unwrap();
    assert_eq!(dials.load(Ordering::Acquire), 2);
    assert_eq!(first_session.state(), SessionState::Draining);
    assert!(!first_session.is_closed());

    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    drop(first);
    drop(second);
    assert!(first_session.is_closed());
    pool.shutdown();
    let servers = std::mem::take(&mut *servers.lock());
    for server in servers {
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap(),
            1
        );
    }
}
async fn serve_idle_h2mux(wire: tokio::io::DuplexStream) -> usize {
    let io = server_carrier(wire, false).await;
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut streams = Vec::new();
    while let Some(stream) = connection.accept().await {
        streams.push(stream.unwrap());
    }
    streams.len()
}

#[tokio::test]
async fn saturated_carrier_opens_the_second_pool_slot() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (first_client, first_server) = tokio::io::duplex(1 << 20);
    let first_server = tokio::spawn(serve_idle_h2mux(first_server));
    let first = connect(Box::new(first_client), false).await.unwrap();
    pool.insert(&first);
    let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
        .map(|_| first.try_reserve().unwrap())
        .collect();
    assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);

    let (second_client, second_server) = tokio::io::duplex(1 << 20);
    let second_server = tokio::spawn(serve_idle_h2mux(second_server));
    let second = pool
        .offer(move || async move { connect(Box::new(second_client), false).await })
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(pool.metrics().sessions, 2);

    drop(permits);
    pool.shutdown();
    assert_eq!(first_server.await.unwrap(), 0);
    assert_eq!(second_server.await.unwrap(), 0);
}

#[tokio::test]
async fn carrier_death_wakes_full_pool_waiters_with_child_permits_held() {
    enum Publication {
        Ordinary,
        Detached,
        Inserted,
    }
    for publication in [
        Publication::Ordinary,
        Publication::Detached,
        Publication::Inserted,
    ] {
        let pool = Arc::new(SessionPool::new(session_pool_config()));
        let (first_client, first_server) = tokio::io::duplex(1 << 20);
        let first_server = tokio::spawn(serve_idle_h2mux(first_server));
        let mut permits = Vec::new();
        let first = match publication {
            Publication::Ordinary => pool
                .offer(move || async move { connect(Box::new(first_client), false).await })
                .await
                .unwrap(),
            Publication::Detached => {
                let SpeculativeCheckout::Detached(mut reservation) =
                    pool.checkout_speculative().await.unwrap()
                else {
                    panic!("empty pool must reserve a detached dial");
                };
                let session = connect(Box::new(first_client), false).await.unwrap();
                permits.push(reservation.attach(&session).unwrap());
                reservation.commit().unwrap()
            }
            Publication::Inserted => {
                let session = connect(Box::new(first_client), false).await.unwrap();
                pool.insert(&session);
                session
            }
        };
        permits
            .extend((permits.len()..MAX_STREAMS_PER_SESSION).map(|_| first.try_reserve().unwrap()));
        let (second_client, second_server) = tokio::io::duplex(1 << 20);
        let second_server = tokio::spawn(serve_idle_h2mux(second_server));
        let second = pool
            .offer(move || async move { connect(Box::new(second_client), false).await })
            .await
            .unwrap();
        permits.extend((0..MAX_STREAMS_PER_SESSION).map(|_| second.try_reserve().unwrap()));

        let (replacement_client, replacement_server) = tokio::io::duplex(1 << 20);
        let replacement_server = tokio::spawn(serve_idle_h2mux(replacement_server));
        let mut normal = std::pin::pin!(
            pool.offer(move || async move { connect(Box::new(replacement_client), false).await })
        );
        let mut speculative = std::pin::pin!(pool.checkout_speculative());
        assert!(futures_util::poll!(normal.as_mut()).is_pending());
        assert!(futures_util::poll!(speculative.as_mut()).is_pending());

        first_server.abort();
        let _ = first_server.await;
        let SpeculativeCheckout::Detached(reservation) =
            tokio::time::timeout(std::time::Duration::from_secs(1), speculative)
                .await
                .expect("carrier death stranded the speculative checkout")
                .unwrap()
        else {
            panic!("the surviving carrier is still full");
        };
        let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), normal)
            .await
            .expect("carrier death stranded the replacement dial")
            .unwrap();
        assert!(first.is_closed());
        assert_eq!(first.active_streams(), MAX_STREAMS_PER_SESSION);
        assert_eq!(second.active_streams(), MAX_STREAMS_PER_SESSION);
        assert_eq!(second.state(), SessionState::Active);
        assert!(!Arc::ptr_eq(&replacement, &first));
        assert!(!Arc::ptr_eq(&replacement, &second));

        drop(reservation);
        pool.shutdown();
        drop(permits);
        second_server.await.unwrap();
        replacement_server.await.unwrap();
    }
}

async fn prepare_detached(
    pool: &Arc<VlessMuxPool>,
) -> (
    crate::proxy::PreparedUdpTransport,
    Arc<VlessMuxSession>,
    tokio::task::JoinHandle<usize>,
) {
    let SpeculativeCheckout::Detached(mut reservation) = pool.checkout_speculative().await.unwrap()
    else {
        panic!("empty pool must reserve a detached dial");
    };
    let (client, server) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_idle_h2mux(server));
    let session = connect(Box::new(client), false).await.unwrap();
    let permit = reservation.attach(&session).unwrap();
    let transport = Arc::clone(&session)
        .open_packet(permit, "8.8.8.8:53".parse().unwrap(), None)
        .await
        .unwrap_or_else(|_| panic!("detached UDP stream must open"));
    let transport: Arc<dyn PacketTransport> = transport;
    (
        crate::proxy::PreparedUdpTransport::new(async move {
            reservation.commit()?;
            Ok(transport)
        }),
        session,
        server,
    )
}

#[tokio::test]
async fn detached_session_publishes_only_on_commit() {
    let pool = Arc::new(SessionPool::new(session_pool_config()));
    let (loser, loser_session, loser_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    drop(loser);
    assert!(loser_session.is_closed());
    assert!(loser_server.await.unwrap() <= 1);

    let (winner, winner_session, winner_server) = prepare_detached(&pool).await;
    assert_eq!(pool.live_session_count(), 0);
    let transport = winner.commit().await.unwrap();
    assert_eq!(pool.live_session_count(), 1);
    assert!(!winner_session.is_closed());
    drop(transport);
    pool.shutdown();
    assert!(winner_session.is_closed());
    assert!(winner_server.await.unwrap() <= 1);
}

#[tokio::test]
async fn carrier_failure_fans_out_and_stream_capacity_is_bounded() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let mut streams = Vec::new();
        for _ in 0..2 {
            streams.push(connection.accept().await.unwrap().unwrap());
        }
        accepted_tx.send(()).unwrap();
        drop_rx.await.unwrap();
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let permits: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
        .map(|_| session.try_reserve().unwrap())
        .collect();
    assert!(session.try_reserve().is_none());
    drop(permits);

    let mut first = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("first stream must open"));
    let mut second = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("second stream must open"));
    accepted_rx.await.unwrap();
    drop_tx.send(()).unwrap();
    server.await.unwrap();
    let mut byte = [0];
    let mut outcomes = Vec::new();
    for stream in [&mut first, &mut second] {
        let error = stream.read_exact(&mut byte).await.unwrap_err();
        outcomes.push(crate::group::ScoreOutcome::from_io_error(&error));
    }
    assert!(matches!(
        outcomes[0],
        crate::group::ScoreOutcome::SharedNodeFailure(_)
    ));
    assert_eq!(
        outcomes[0], outcomes[1],
        "one carrier failure is one episode"
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_logical_stream_sends_cancel_reset() {
    let (client, server) = tokio::io::duplex(1 << 20);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        ready_tx.send(()).unwrap();
        tokio::select! {
            reset = std::future::poll_fn(|cx| send.poll_reset(cx)) => reset.unwrap(),
            request = connection.accept() => {
                panic!("unexpected H2 event while awaiting reset: {request:?}");
            }
        }
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("logical stream must open"));
    ready_rx.await.unwrap();
    drop(stream);
    let reset = tokio::time::timeout(std::time::Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reset, h2::Reason::CANCEL);
    session.close();
}

#[tokio::test]
async fn remote_no_error_close_keeps_half_close_failure_stream_scoped() {
    for end_stream in [false, true] {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            send.send_data(Bytes::from_static(b"\0payload"), end_stream)
                .unwrap();
            tokio::select! {
                result = reset_rx => result.unwrap(),
                request = connection.accept() => {
                    panic!("unexpected H2 event while awaiting reset: {request:?}");
                }
            }
            // Go's HTTP/2 server resets an unfinished request with NO_ERROR
            // after its handler has sent a complete response.
            send.send_reset(h2::Reason::NO_ERROR);
            while let Some(request) = connection.accept().await {
                let (request, respond) = request.unwrap();
                tokio::spawn(serve_logical_stream(request, respond));
            }
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let mut stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("logical stream must open"));
        let mut payload = [0; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        reset_tx.send(()).unwrap();
        let reason = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            std::future::poll_fn(|cx| stream.send.inner.poll_reset(cx)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reason, h2::Reason::NO_ERROR);
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        let error = stream.shutdown().await.unwrap_err();
        assert_eq!(
            crate::group::ScoreOutcome::from_io_error(&error),
            crate::group::ScoreOutcome::Io(io::ErrorKind::ConnectionReset)
        );
        let mut sibling = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("remote stream closure must keep its carrier usable"));
        sibling.read_exact(&mut [0; 5]).await.unwrap();
        sibling.write_all(b"ping").await.unwrap();
        let mut pong = [0; 4];
        sibling.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        drop((stream, sibling));
        session.close();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn mux_refusal_distinguishes_target_status_from_http_envelope() {
    for envelope in [false, true] {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut response = http::Response::new(());
            if envelope {
                *response.status_mut() = http::StatusCode::FORBIDDEN;
            }
            let mut send = respond.send_response(response, envelope).unwrap();
            if !envelope {
                send.send_data(Bytes::from_static(&[1, 3, b'b', b'a', b'd']), true)
                    .unwrap();
            }
            while connection.accept().await.is_some() {}
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let mut stream = Arc::clone(&session)
            .open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            )
            .await
            .unwrap_or_else(|_| panic!("logical stream must open before lazy rejection"));
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let outcome = crate::group::ScoreOutcome::from_io_error(&error);
        if envelope {
            assert!(outcome.is_node_failure(), "{outcome:?}");
        } else {
            assert_eq!(outcome, crate::group::ScoreOutcome::TargetFailure);
        }
        let repeated = stream.read_u8().await.unwrap_err();
        assert_eq!(
            crate::group::ScoreOutcome::from_io_error(&repeated),
            outcome,
            "a replayed refusal is the same event"
        );
        drop(stream);
        session.close();
        server.await.unwrap();
    }
}

#[cfg(feature = "flow-observation")]
#[tokio::test]
async fn target_evidence_requires_mux_body_status_not_http_success() {
    use crate::runtime::flow_observation::{FlowContext, FlowEvent, FlowObserver};
    for status in [0, 1] {
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let observer = FlowObserver::new(
            FlowContext {
                flow_id: uuid::Uuid::new_v4(),
                generation: 1,
                attempt_id: None,
                lookup_id: None,
                dns_purpose: "proxy_server",
            },
            {
                let events = Arc::clone(&events);
                Arc::new(move |_, event| {
                    if let FlowEvent::Milestone { milestone } = event {
                        events.lock().push(milestone.as_str());
                    }
                })
            },
        );
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(async move {
            let io = server_carrier(server, false).await;
            let mut connection = h2::server::handshake(io).await.unwrap();
            let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let response = if status == 0 {
                Bytes::from_static(b"\0x")
            } else {
                Bytes::from_static(b"\x01\x01x")
            };
            send.send_data(response, true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let session = connect(Box::new(client), false).await.unwrap();
        let mut stream = observer
            .scope(Arc::clone(&session).open_stream(
                session.try_reserve().unwrap(),
                "93.184.216.34:443".parse().unwrap(),
                None,
            ))
            .await
            .unwrap_or_else(|_| panic!("logical stream failed to open"));
        assert_eq!(&*events.lock(), &["target_request_sent"]);
        let result = stream.read_u8().await;
        if status == 0 {
            assert_eq!(result.unwrap(), b'x');
            assert_eq!(
                &*events.lock(),
                &["target_request_sent", "target_confirmed"]
            );
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(&*events.lock(), &["target_request_sent"]);
        }
        drop(stream);
        session.close();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn logical_writes_wait_for_h2_flow_control() {
    const PAYLOAD_SIZE: usize = 4 * 1024 * 1024;
    let (client, server) = tokio::io::duplex(1 << 20);
    let release = Arc::new(tokio::sync::Notify::new());
    let server_release = Arc::clone(&release);
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let io = server_carrier(server, false).await;
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(&[0]), false).unwrap();
        accepted_tx.send(()).unwrap();
        let handler = tokio::spawn(async move {
            let mut recv = request.into_body();
            server_release.notified().await;
            let mut received = 0;
            while let Some(data) = recv.data().await {
                let data = data.unwrap();
                received += data.len();
                recv.flow_control().release_capacity(data.len()).unwrap();
            }
            let _ = send.send_data(Bytes::new(), true);
            drained_tx.send(received).unwrap();
        });
        while connection.accept().await.is_some() {}
        handler.await.unwrap();
    });
    let session = connect(Box::new(client), false).await.unwrap();
    let stream = Arc::clone(&session)
        .open_stream(
            session.try_reserve().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("flow-control stream must open"));
    accepted_rx.await.unwrap();
    let mut writer = tokio::spawn(async move {
        let mut stream = stream;
        stream.write_all(&vec![0x5a; PAYLOAD_SIZE]).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(stream)
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut writer)
            .await
            .is_err(),
        "writer must stop at the peer's H2 receive window"
    );
    release.notify_one();
    let stream = writer.await.unwrap().unwrap();
    drop(stream);
    assert!(drained_rx.await.unwrap() >= PAYLOAD_SIZE);
    session.close();
    server.await.unwrap();
}

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
