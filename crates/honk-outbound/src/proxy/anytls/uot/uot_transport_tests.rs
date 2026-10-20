use super::*;

const TEST_AUTH: &[u8] = b"test-auth";
const TEST_SETTINGS: &[u8] = b"test-settings";

// An independent UoT peer: every address and packet below is spelled out
// from the wire spec (non-connect v2 request, v1 packets with ATYP
// IPv4=0 / IPv6=1 / domain=2), not produced by the codec under test.
const A: &str = "198.51.100.10:5301";
const B: &str = "203.0.113.20:5302";
const C: &str = "192.0.2.30:5303";
const C6: &str = "[2001:db8::30]:5304";
const A_REQUEST: [u8; 8] = [0x00, 0x01, 198, 51, 100, 10, 0x14, 0xb5];
const A_ADDR: [u8; 5] = [0x00, 198, 51, 100, 10];
const B_ADDR: [u8; 5] = [0x00, 203, 0, 113, 20];
const C_ADDR: [u8; 5] = [0x00, 192, 0, 2, 30];
const C6_ADDR: [u8; 17] = [
    0x01, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x30,
];

fn packet(address: &[u8], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = address.to_vec();
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn domain_address(domain: &str) -> Vec<u8> {
    let mut address = vec![0x02, domain.len() as u8];
    address.extend_from_slice(domain.as_bytes());
    address
}

fn sock(address: &str) -> SocketAddr {
    address.parse().unwrap()
}

/// Open a UoT stream on an in-memory test session; returns the
/// transport and the server end of the session transport.
async fn uot_test_transport(
    target: SocketAddr,
) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
    uot_test_transport_with(target, None, 1 << 20, INBOUND_PAYLOAD_BUDGET).await
}

async fn uot_test_transport_with_capacity(
    target: SocketAddr,
    capacity: usize,
) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
    uot_test_transport_with(target, None, capacity, INBOUND_PAYLOAD_BUDGET).await
}

async fn uot_test_transport_with(
    target: SocketAddr,
    domain: Option<&str>,
    capacity: usize,
    inbound_budget: usize,
) -> (Arc<AnyTlsUotTransport>, tokio::io::DuplexStream) {
    let addr = "127.0.0.1:2443";
    let (client_end, mut server_end) = tokio::io::duplex(capacity);
    let (read, write) = tokio::io::split(client_end);
    let padding_state = Arc::new(PaddingState {
        current: parking_lot::RwLock::new(Arc::new(PaddingScheme::parse(b"stop=0").unwrap())),
    });
    let session = AnyTlsSession::establish(
        addr,
        Box::new(read),
        Box::new(write),
        TEST_AUTH,
        bytes::Bytes::from_static(TEST_SETTINGS),
        padding_state,
        InboundPayloadBudget::new(inbound_budget),
    )
    .await
    .unwrap();
    session.flush_initial_settings_for_test().unwrap();

    let mut auth = vec![0u8; TEST_AUTH.len()];
    server_end.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, TEST_AUTH);
    let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
    assert_eq!(cmd, CMD_SETTINGS);
    let transport = Arc::clone(&session)
        .open_packet(session.try_reserve().unwrap(), target, domain)
        .await
        .unwrap_or_else(|_| panic!("UoT transport must open"));

    let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
    assert_eq!(cmd, CMD_SYN);
    let (cmd, _, _) = read_frame(&mut server_end).await.unwrap();
    assert_eq!(cmd, CMD_PSH);
    (transport, server_end)
}

async fn recv(transport: &AnyTlsUotTransport) -> (Vec<u8>, SocketAddr) {
    let mut buf = vec![0u8; u16::MAX as usize];
    let (n, source) = tokio::time::timeout(Duration::from_secs(1), transport.recv_packet(&mut buf))
        .await
        .expect("UoT datagram must arrive")
        .unwrap();
    buf.truncate(n);
    (buf, source)
}

#[tokio::test]
async fn uot_magic_refusal_is_not_a_target_failure() {
    let (transport, mut server) = uot_test_transport(sock("192.0.2.1:53")).await;
    write_frame(&mut server, CMD_SYNACK, transport.sid, b"UoT unsupported")
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), transport.recv_packet(&mut [0; 1]))
        .await
        .unwrap()
        .unwrap_err();
    assert!(crate::group::ScoreOutcome::from_io_error(&error).is_node_failure());
    assert!(!transport.session.is_closed());
}

/// Non-connect request (mode byte 0 + SOCKS5 address, ATYP 1) and the
/// first packet share one PSH; every packet, first or not, carries its
/// own UoT-numbered address (ATYP 0).
#[tokio::test]
async fn uot_request_and_packets_carry_addresses() {
    let (transport, mut server) = uot_test_transport(sock(A)).await;

    transport.send_packet(b"dns-packet").await.unwrap();
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
    let expected = [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"dns-packet")].concat();
    assert_eq!(data, expected);
    assert_eq!(
        &data[..24],
        [
            0x00, 0x01, 198, 51, 100, 10, 0x14, 0xb5, 0x00, 198, 51, 100, 10, 0x14, 0xb5, 0x00,
            0x0a, b'd', b'n', b's', b'-', b'p', b'a', b'c'
        ]
    );

    transport.send_packet(b"next").await.unwrap();
    let (cmd, next_sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, next_sid), (CMD_PSH, sid));
    assert_eq!(data, packet(&A_ADDR, 5301, b"next"));
}

#[tokio::test]
async fn uot_domain_and_ipv6_targets_use_uot_atyps() {
    let (transport, mut server) = uot_test_transport_with(
        sock("[2001:db8::30]:5304"),
        Some("dns.example"),
        1 << 20,
        INBOUND_PAYLOAD_BUDGET,
    )
    .await;
    transport.send_packet(b"by-name").await.unwrap();
    let (_, _, data) = read_frame(&mut server).await.unwrap();
    // Request: SOCKS5 domain ATYP 3; packet: UoT domain ATYP 2.
    let mut request = vec![0x00, 0x03, 11];
    request.extend_from_slice(b"dns.example");
    request.extend_from_slice(&5304u16.to_be_bytes());
    let expected = [
        request,
        packet(&domain_address("dns.example"), 5304, b"by-name"),
    ]
    .concat();
    assert_eq!(data, expected);

    transport
        .send_to(sock(C6), None, b"v6", false, None)
        .await
        .unwrap();
    let (_, _, data) = read_frame(&mut server).await.unwrap();
    assert_eq!(data, packet(&C6_ADDR, 5304, b"v6"));

    // A name other than the dialed one never reaches the wire.
    transport
        .send_to(
            sock("[2001:db8::30]:5304"),
            Some("other.example"),
            b"x",
            false,
            None,
        )
        .await
        .unwrap();
    let (_, _, data) = read_frame(&mut server).await.unwrap();
    assert_eq!(data, packet(&C6_ADDR, 5304, b"x"));
}

/// A and B share one stream; each destination is addressed per packet.
/// Replies from A, B and a never-contacted C (IPv4 and IPv6) keep their
/// exact sources, including when coalesced into one PSH.
#[tokio::test]
async fn uot_one_stream_carries_many_destinations_and_unsolicited_sources() {
    let (transport, mut server) = uot_test_transport(sock(A)).await;
    assert!(transport.allows_full_cone_replies());
    let admitted = AtomicBool::new(false);
    transport
        .send_to(sock(A), None, b"to-a", false, Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
    assert_eq!(
        data,
        [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"to-a")].concat()
    );

    transport
        .send_to(sock(B), None, b"to-b", false, None)
        .await
        .unwrap();
    let (cmd, b_sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, b_sid), (CMD_PSH, sid));
    assert_eq!(data, packet(&B_ADDR, 5302, b"to-b"));

    let replies = [
        packet(&C_ADDR, 5303, b"from-c"),
        packet(&A_ADDR, 5301, b"from-a"),
        packet(&C6_ADDR, 5304, b"from-c6"),
        packet(&B_ADDR, 5302, b""),
    ]
    .concat();
    write_frame(&mut server, CMD_PSH, sid, &replies)
        .await
        .unwrap();
    for (payload, source) in [
        (&b"from-c"[..], C),
        (b"from-a", A),
        (b"from-c6", C6),
        (b"", B),
    ] {
        assert_eq!(recv(&transport).await, (payload.to_vec(), sock(source)));
    }
}

#[tokio::test]
async fn uot_ipv4_mapped_source_is_canonicalized() {
    let (transport, mut server) = uot_test_transport(sock(A)).await;
    let mapped = [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 30,
    ];
    write_frame(
        &mut server,
        CMD_PSH,
        transport.sid,
        &packet(&mapped, 5303, b"m"),
    )
    .await
    .unwrap();
    assert_eq!(recv(&transport).await, (b"m".to_vec(), sock(C)));
}

/// Every split of an addressed frame across AnyTLS PSH frames decodes.
#[tokio::test]
async fn uot_reassembles_addressed_frame_at_every_split() {
    let (transport, mut server) = uot_test_transport_with(
        sock(A),
        Some("dns.example"),
        1 << 20,
        INBOUND_PAYLOAD_BUDGET,
    )
    .await;
    let frames = [
        (packet(&C_ADDR, 5303, b"quic-initial"), sock(C)),
        (packet(&C6_ADDR, 5304, b"quic-initial"), sock(C6)),
        (
            packet(&domain_address("dns.example"), 5301, b"quic-initial"),
            sock(A),
        ),
    ];
    for (frame, source) in frames {
        for split in 1..frame.len() {
            write_frame(&mut server, CMD_PSH, transport.sid, &frame[..split])
                .await
                .unwrap();
            write_frame(&mut server, CMD_PSH, transport.sid, &frame[split..])
                .await
                .unwrap();
            assert_eq!(
                recv(&transport).await,
                (b"quic-initial".to_vec(), source),
                "split at {split}"
            );
        }
    }
}

/// Captured domain + port projects to the captured target (ASCII
/// case-insensitive); any other domain frame is consumed whole and the
/// next frame still decodes.
#[tokio::test]
async fn uot_domain_source_projects_captured_target_and_drops_others() {
    let target = sock(A);
    let (transport, mut server) =
        uot_test_transport_with(target, Some("dns.example"), 1 << 20, INBOUND_PAYLOAD_BUDGET).await;
    let frames = [
        packet(&domain_address("evil.example"), 5301, b"unknown"),
        packet(&domain_address("dns.example"), 5999, b"wrong-port"),
        packet(&domain_address(""), 5301, b"empty-name"),
        packet(&domain_address("DNS.Example"), 5301, b"projected"),
        packet(&B_ADDR, 5302, b"after"),
    ]
    .concat();
    write_frame(&mut server, CMD_PSH, transport.sid, &frames)
        .await
        .unwrap();
    assert_eq!(recv(&transport).await, (b"projected".to_vec(), target));
    assert_eq!(recv(&transport).await, (b"after".to_vec(), sock(B)));
}

/// Dropped domain frames return their whole header and payload to the
/// pool credit: with a budget of exactly one frame (a full budget retires
/// the stream), the next frame can only arrive if the dropped one was
/// fully released.
#[tokio::test]
async fn uot_dropped_domain_frame_releases_header_and_payload_credit() {
    let dropped = packet(&domain_address("x.y"), 5301, b"abc");
    let kept = packet(&A_ADDR, 5301, b"xyz");
    assert_eq!(dropped.len(), kept.len());
    let (transport, mut server) =
        uot_test_transport_with(sock(A), Some("dns.example"), 1 << 20, dropped.len()).await;
    for _ in 0..2 {
        write_frame(&mut server, CMD_PSH, transport.sid, &dropped)
            .await
            .unwrap();
        let (received, _) = tokio::join!(recv(&transport), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            write_frame(&mut server, CMD_PSH, transport.sid, &kept)
                .await
                .unwrap();
        });
        assert_eq!(received, (b"xyz".to_vec(), sock(A)));
    }
}

#[tokio::test]
async fn uot_unknown_atyp_is_terminal() {
    let (transport, mut server) = uot_test_transport(sock(A)).await;
    write_frame(
        &mut server,
        CMD_PSH,
        transport.sid,
        &[0x03, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .await
    .unwrap();
    let error = transport.recv_packet(&mut [0; 8]).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn uot_read_releases_pool_payload_credit() {
    let first = packet(&A_ADDR, 5301, b"first!");
    let second = packet(&A_ADDR, 5301, b"second");
    let (transport, mut server) =
        uot_test_transport_with(sock(A), None, 1 << 20, first.len()).await;
    for (frame, payload) in [(first, b"first!"), (second, b"second")] {
        write_frame(&mut server, CMD_PSH, transport.sid, &frame)
            .await
            .unwrap();
        assert_eq!(recv(&transport).await, (payload.to_vec(), sock(A)));
    }
}

#[tokio::test]
async fn confirmed_uot_send_waits_for_physical_flush() {
    let (transport, mut server) =
        uot_test_transport_with_capacity(sock("93.184.216.34:443"), 64).await;
    let payload = vec![0x5a; 256];
    let send = transport.send_packet_confirmed(&payload);
    tokio::pin!(send);

    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut send)
            .await
            .is_err(),
        "confirmation must wait while the physical writer is blocked"
    );
    let (sent, frame) = tokio::join!(&mut send, read_frame(&mut server));
    sent.unwrap();
    let (cmd, sid, data) = frame.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
    let request = [0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb];
    let address = [0x00, 93, 184, 216, 34];
    assert_eq!(
        data,
        [&request[..], &packet(&address, 443, &payload)].concat()
    );
}

/// Source sends: the first flow's confirmed send keeps waiting for the
/// physical flush while the writer is blocked, but the frame is already
/// admitted; steady sends enqueue only and never wait for a flush.
#[tokio::test]
async fn source_send_confirmation_waits_for_flush_and_steady_sends_do_not() {
    let (transport, mut server) = uot_test_transport_with_capacity(sock(A), 64).await;
    let payload = vec![0x5a; 256];
    let admitted = AtomicBool::new(false);
    let first = transport.send_to(sock(A), None, &payload, true, Some(&admitted));
    tokio::pin!(first);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut first)
            .await
            .is_err(),
        "first send confirmation must wait while the physical writer is blocked"
    );
    assert!(admitted.load(Ordering::Acquire), "queued frame is admitted");

    let steady_admitted = AtomicBool::new(false);
    tokio::time::timeout(
        Duration::from_millis(500),
        transport.send_to(sock(B), None, b"steady", false, Some(&steady_admitted)),
    )
    .await
    .expect("an unconfirmed send must not wait for the physical flush")
    .unwrap();
    assert!(steady_admitted.load(Ordering::Acquire));

    let (sent, frame) = tokio::join!(&mut first, read_frame(&mut server));
    sent.unwrap();
    assert_eq!(
        frame.unwrap().2,
        [&A_REQUEST[..], &packet(&A_ADDR, 5301, &payload)].concat()
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap().2,
        packet(&B_ADDR, 5302, b"steady")
    );
}

#[tokio::test]
async fn uot_send_enforces_anytls_go_packet_limit_without_poisoning_stream() {
    use crate::proxy::{
        PacketErrorClass, PacketRejection, io_packet_rejection, packet_error_class,
    };

    let (transport, mut server) = uot_test_transport(sock(A)).await;
    let payload = vec![0x5a; UOT_MAX_PACKET_SIZE];
    let oversized = vec![0; UOT_MAX_PACKET_SIZE + 1];
    let error = futures_util::FutureExt::now_or_never(transport.send_packet_confirmed(&oversized))
        .expect("local refusal must not wait for I/O")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        io_packet_rejection(&error),
        Some(PacketRejection::InvalidSize)
    );
    assert_eq!(packet_error_class(&error), PacketErrorClass::Rejected);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
            .await
            .is_err(),
        "rejected first datagram must not consume setup or emit a PSH"
    );

    transport.send_packet(&payload).await.unwrap();
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
    assert_eq!(
        data,
        [&A_REQUEST[..], &packet(&A_ADDR, 5301, &payload)].concat()
    );

    let error = transport.send_packet(&oversized).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        io_packet_rejection(&error),
        Some(PacketRejection::InvalidSize)
    );
    assert_eq!(packet_error_class(&error), PacketErrorClass::Rejected);

    // An empty datagram is representable and keeps the stream usable.
    transport.send_packet(b"").await.unwrap();
    assert_eq!(
        read_frame(&mut server).await.unwrap().2,
        packet(&A_ADDR, 5301, b"")
    );
    transport.send_packet(b"kept").await.unwrap();
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!(
        (cmd, sid, data),
        (CMD_PSH, transport.sid, packet(&A_ADDR, 5301, b"kept"))
    );
}

/// A send cancelled while waiting for writer-queue capacity queued
/// nothing: it is not admitted and the lazy setup stays for the next one.
#[tokio::test]
async fn cancelled_pre_enqueue_send_keeps_setup_and_is_not_admitted() {
    let (transport, mut server) = uot_test_transport(sock(A)).await;
    let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
    let held = Arc::clone(&transport.session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();

    let admitted = AtomicBool::new(false);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            transport.send_to(sock(A), None, b"cancelled", true, Some(&admitted)),
        )
        .await
        .is_err()
    );
    assert!(!admitted.load(Ordering::Acquire));
    drop(held);

    transport.send_packet_confirmed(b"kept").await.unwrap();
    let (cmd, sid, data) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, sid), (CMD_PSH, transport.sid));
    assert_eq!(
        data,
        [&A_REQUEST[..], &packet(&A_ADDR, 5301, b"kept")].concat()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
            .await
            .is_err(),
        "the cancelled datagram must not be queued"
    );

    // Steady state: a cancelled waiter is neither admitted nor sent.
    let held = Arc::clone(&transport.session.writer_q.data_permits)
        .acquire_many_owned(capacity)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            transport.send_to(sock(B), None, b"cancelled", false, Some(&admitted)),
        )
        .await
        .is_err()
    );
    assert!(!admitted.load(Ordering::Acquire));
    drop(held);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
            .await
            .is_err()
    );
}

/// Once the frame is owned by the session writer, cancelling the
/// confirmation wait neither loses nor replays it, and the setup is gone.
#[tokio::test]
async fn cancelled_post_enqueue_send_is_admitted_and_never_replayed() {
    let (transport, mut server) = uot_test_transport_with_capacity(sock(A), 64).await;
    let payload = vec![0x5a; 256];
    let admitted = AtomicBool::new(false);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            transport.send_to(sock(A), None, &payload, true, Some(&admitted)),
        )
        .await
        .is_err(),
        "the blocked physical writer must keep the confirmation pending"
    );
    assert!(admitted.load(Ordering::Acquire));

    transport
        .send_to(sock(B), None, b"next", false, None)
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut server).await.unwrap().2,
        [&A_REQUEST[..], &packet(&A_ADDR, 5301, &payload)].concat(),
        "the cancelled first frame is delivered once, with its request"
    );
    assert_eq!(
        read_frame(&mut server).await.unwrap().2,
        packet(&B_ADDR, 5302, b"next"),
        "the setup was consumed by the queued frame"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn retired_uot_waiter_never_queues_payload_after_fin() {
    for confirmed in [false, true] {
        let (transport, mut server) = uot_test_transport(sock("93.184.216.34:443")).await;
        let sid = transport.sid;
        transport.send_packet(b"initial").await.unwrap();
        assert_eq!(read_frame(&mut server).await.unwrap().0, CMD_PSH);

        let capacity = (WRITER_QUEUE_CAP - WRITER_CONTROL_RESERVED) as u32;
        let held = Arc::clone(&transport.session.writer_q.data_permits)
            .acquire_many_owned(capacity)
            .await
            .unwrap();
        let send = async {
            if confirmed {
                transport.send_packet_confirmed(b"retired").await
            } else {
                transport.send_packet(b"retired").await
            }
        };
        tokio::pin!(send);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut send)
                .await
                .is_err()
        );

        transport.session.end_uot_stream(sid, true);
        let (cmd, fin_sid, _) = read_frame(&mut server).await.unwrap();
        assert_eq!((cmd, fin_sid), (CMD_FIN, sid));
        drop(held);

        let error = tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .expect("retired send must resume")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_frame(&mut server))
                .await
                .is_err(),
            "no PSH may follow the stream FIN"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn blocked_data_writer_backpressures_without_killing_session() {
    let (transport, mut server) =
        uot_test_transport_with_capacity(sock("93.184.216.34:443"), 64).await;
    let session = Arc::clone(&transport.session);
    let send = tokio::spawn(async move { transport.send_packet_confirmed(&vec![0x5a; 256]).await });
    tokio::task::yield_now().await;
    tokio::time::advance(WRITER_IO_TIMEOUT * 10).await;
    tokio::task::yield_now().await;
    assert!(!session.is_closed());

    let mut sink = vec![0u8; 4096];
    while !send.is_finished() {
        tokio::task::yield_now().await;
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut sink)
            .await
            .unwrap();
        assert!(n > 0);
    }
    send.await.unwrap().unwrap();
    assert!(!session.is_closed());
}

#[tokio::test(start_paused = true)]
async fn blocked_control_write_becomes_terminal() {
    let (transport, _server) =
        uot_test_transport_with_capacity(sock("93.184.216.34:443"), 64).await;
    let session = Arc::clone(&transport.session);
    session
        .enqueue_control(CMD_SETTINGS, 0, bytes::Bytes::from(vec![0u8; 4096]))
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(WRITER_IO_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(session.is_closed());
}

#[tokio::test]
async fn uot_v1_max_domain_frame_survives_valid_chunking() {
    let target = sock("93.184.216.34:443");
    let domain = "d".repeat(u8::MAX as usize);
    let (transport, mut server) =
        uot_test_transport_with(target, Some(&domain), 1 << 20, INBOUND_PAYLOAD_BUDGET).await;
    let sid = transport.sid;

    let mut stream = packet(
        &domain_address(&domain),
        target.port(),
        &[0x5a; u16::MAX as usize],
    );
    let first_frame_end = stream.len();
    stream.extend(std::iter::repeat_n(0, u16::MAX as usize - 1));
    assert_eq!(stream.len(), UOT_MAX_BUFFERED_BYTES);

    for chunk in [
        &stream[..32_768],
        &stream[32_768..first_frame_end - 1],
        &stream[first_frame_end - 1..],
    ] {
        write_frame(&mut server, CMD_PSH, sid, chunk).await.unwrap();
    }

    let (payload, source) = recv(&transport).await;
    assert_eq!(payload.len(), u16::MAX as usize);
    assert!(payload.iter().all(|byte| *byte == 0x5a));
    assert_eq!(source, target);
}

/// A stalled UoT consumer retires its sid instead of silently dropping a
/// chunk from the length-delimited receive stream.
#[tokio::test]
async fn uot_transport_saturation_retires_stream() {
    let (transport, mut server) = uot_test_transport(sock("93.184.216.34:53")).await;
    let sid = transport.sid;

    let frame = packet(&[0x00, 93, 184, 216, 34], 53, b"flood");
    for _ in 0..(UOT_DRAIN_QUEUE_CAP * 4) {
        write_frame(&mut server, CMD_PSH, sid, &frame)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while transport.session.streams.lock().unwrap().contains_key(&sid) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("saturated UoT sid must retire");
    assert!(!transport.session.is_closed());
    let error = transport.send_packet(b"ping").await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    let (cmd, fin_sid, _) = read_frame(&mut server).await.unwrap();
    assert_eq!((cmd, fin_sid), (CMD_FIN, sid));
}
