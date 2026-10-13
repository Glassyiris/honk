use super::*;
use honk_config::types::NodeProtocol;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A peer that accepts and then stays silent must not park the caller: the
/// TCP path bounds the same exchange, and only the connect before this one
/// is bounded by the caller.
#[tokio::test(start_paused = true)]
async fn udp_associate_gives_up_on_a_silent_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _accepted = listener.accept().await;
        std::future::pending::<()>().await;
    });

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        Socks5Handler::udp_associate(&mut stream, None, None),
    )
    .await;

    let inner = outcome.expect("udp_associate outlived its own deadline");
    assert!(
        inner
            .unwrap_err()
            .to_string()
            .contains("negotiation timed out"),
        "expected the negotiation deadline to fire"
    );
}

#[tokio::test]
async fn udp_associate_gives_up_after_greeting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    let client = tokio::spawn(async move {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            Socks5Handler::udp_associate(&mut stream, None, None),
        )
        .await
    });
    let mut greeting = [0; 3];
    server.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [SOCKS5_VERSION, 1, METHOD_NO_AUTH]);
    server
        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
        .await
        .unwrap();
    let mut request = [0; 10];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(request[1], CMD_UDP_ASSOCIATE);

    // Pause only after real socket I/O completes, so time cannot skip the greeting.
    tokio::time::pause();
    let outcome = client.await.unwrap();
    let error = outcome
        .expect("UDP ASSOCIATE outlived its own deadline after greeting")
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("SOCKS5 UDP: associate timed out")
    );
}

#[test]
fn socks5_rfc1929_auth_request_rejects_oversized_credentials() {
    let oversized = "x".repeat(u8::MAX as usize + 1);
    assert!(Socks5Handler::username_password_auth_request(&oversized, "ok").is_err());
    assert!(Socks5Handler::username_password_auth_request("ok", &oversized).is_err());
}

#[test]
fn socks5_rfc1929_auth_request_encodes_checked_lengths() {
    assert_eq!(
        Socks5Handler::username_password_auth_request("user", "pass").unwrap(),
        b"\x01\x04user\x04pass"
    );
}

#[tokio::test]
async fn socks5_tcp_connect_rejects_oversized_domain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        stream
            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
            .await
            .unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let oversized = "x".repeat(u8::MAX as usize + 1);
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let result = Socks5Handler::handshake(&mut client, target, Some(&oversized), None, None).await;
    server.await.unwrap();
    let error = result.expect_err("oversized domain must fail the handshake");
    assert!(error.to_string().contains("255"));
}

struct UdpAssociateTestServer {
    proxy_addr: SocketAddr,
    relay: tokio::net::UdpSocket,
    control_closed: oneshot::Receiver<()>,
    close_control: Option<oneshot::Sender<()>>,
}

impl UdpAssociateTestServer {
    fn close_control(&mut self) {
        self.close_control
            .take()
            .expect("control close signal may only be sent once")
            .send(())
            .expect("SOCKS5 test control task is still running");
    }
}

fn socks5_udp_associate_reply(relay_addr: SocketAddr) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00];
    match relay_addr {
        SocketAddr::V4(addr) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&addr.ip().octets());
        }
    }
    reply.extend_from_slice(&relay_addr.port().to_be_bytes());
    reply
}

fn socks5_udp_associate_domain_reply(domain: &str, port: u16) -> Vec<u8> {
    assert!(domain.len() <= u8::MAX as usize);
    let mut reply = vec![
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,
        ATYP_DOMAIN,
        domain.len() as u8,
    ];
    reply.extend_from_slice(domain.as_bytes());
    reply.extend_from_slice(&port.to_be_bytes());
    reply
}

async fn run_udp_associate_test_server(mut reply: Vec<u8>) -> UdpAssociateTestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    if reply.ends_with(&[0x00, 0x00]) {
        let port = relay.local_addr().unwrap().port().to_be_bytes();
        let reply_len = reply.len();
        reply[reply_len - 2..].copy_from_slice(&port);
    }
    let (control_closed_tx, control_closed) = oneshot::channel();
    let (close_control, mut close_control_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [SOCKS5_VERSION, 1]);
        let mut methods = vec![0u8; greeting[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods, [METHOD_NO_AUTH]);
        stream
            .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
            .await
            .unwrap();

        let mut request = [0u8; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(
            request,
            [
                SOCKS5_VERSION,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ]
        );
        stream.write_all(&reply).await.unwrap();

        let mut probe = [0u8; 1];
        tokio::select! {
            _ = &mut close_control_rx => {}
            result = stream.read(&mut probe) => {
                assert_eq!(result.unwrap(), 0, "control channel must only close");
            }
        }
        drop(stream);
        let _ = control_closed_tx.send(());
    });

    UdpAssociateTestServer {
        proxy_addr,
        relay,
        control_closed,
        close_control: Some(close_control),
    }
}

fn socks5_test_node(proxy_addr: SocketAddr) -> Node {
    Node {
        name: "test".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: proxy_addr.ip().to_string(),
        host: String::new(),
        port: proxy_addr.port(),
        ..Default::default()
    }
}

async fn dial_udp_test_transport(
    server: &UdpAssociateTestServer,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Arc<dyn super::super::PacketTransport> {
    Socks5Handler::new()
        .dial_udp_transport(
            &socks5_test_node(server.proxy_addr),
            target,
            target_domain,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap()
}

fn expected_socks5_udp_datagram(
    target: SocketAddr,
    target_domain: Option<&str>,
    frag: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut datagram = vec![0x00, 0x00, frag];
    match (target_domain, target) {
        (Some(domain), _) => {
            assert!(domain.len() <= u8::MAX as usize);
            datagram.push(ATYP_DOMAIN);
            datagram.push(domain.len() as u8);
            datagram.extend_from_slice(domain.as_bytes());
        }
        (None, SocketAddr::V4(addr)) => {
            datagram.push(ATYP_IPV4);
            datagram.extend_from_slice(&addr.ip().octets());
        }
        (None, SocketAddr::V6(addr)) => {
            datagram.push(ATYP_IPV6);
            datagram.extend_from_slice(&addr.ip().octets());
        }
    }
    datagram.extend_from_slice(&target.port().to_be_bytes());
    datagram.extend_from_slice(payload);
    datagram
}

async fn transport_client_addr(
    server: &UdpAssociateTestServer,
    transport: &Arc<dyn super::super::PacketTransport>,
) -> SocketAddr {
    transport.send_packet(b"probe").await.unwrap();
    let mut packet = [0u8; 1024];
    let (_, addr) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server.relay.recv_from(&mut packet),
    )
    .await
    .expect("transport should send a UDP datagram")
    .unwrap();
    addr
}

async fn assert_udp_transport_request_frame(target: SocketAddr, target_domain: Option<&str>) {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let transport = dial_udp_test_transport(&server, target, target_domain).await;
    let payload = b"request payload";

    transport.send_packet(payload).await.unwrap();
    let mut received = [0u8; 1024];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server.relay.recv_from(&mut received),
    )
    .await
    .expect("relay should receive a request")
    .unwrap();

    assert_eq!(
        &received[..n],
        expected_socks5_udp_datagram(target, target_domain, 0, payload)
    );
}

async fn assert_udp_transport_invalid_data(datagram: &[u8]) {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let transport =
        dial_udp_test_transport(&server, "198.51.100.9:53".parse().unwrap(), None).await;
    let client_addr = transport_client_addr(&server, &transport).await;
    server.relay.send_to(datagram, client_addr).await.unwrap();

    let mut received = [0u8; 1024];
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut received),
    )
    .await
    .expect("malformed SOCKS5 UDP frame should complete with an error")
    .expect_err("malformed SOCKS5 UDP frame should fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn socks5_udp_transport_frames_ipv4_request() {
    assert_udp_transport_request_frame("198.51.100.7:53".parse().unwrap(), None).await;
}

#[tokio::test]
async fn socks5_udp_transport_frames_ipv6_request() {
    assert_udp_transport_request_frame("[2001:db8::7]:53".parse().unwrap(), None).await;
}

#[tokio::test]
async fn socks5_udp_transport_frames_domain_request() {
    assert_udp_transport_request_frame(
        "198.51.100.7:53".parse().unwrap(),
        Some("dns.example.test"),
    )
    .await;
}

#[tokio::test]
async fn socks5_udp_transport_reports_reply_source_from_wire() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.9:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    assert!(transport.allows_full_cone_replies());
    let client_addr = transport_client_addr(&server, &transport).await;
    server
        .relay
        .send_to(
            &expected_socks5_udp_datagram(target, None, 0, b"reply payload"),
            client_addr,
        )
        .await
        .unwrap();

    let mut received = [0u8; 1024];
    let (n, source) = transport.recv_packet(&mut received).await.unwrap();
    assert_eq!(&received[..n], b"reply payload");
    assert_eq!(source, target);
}

#[tokio::test]
async fn socks5_udp_transport_returns_the_real_numeric_wire_source() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.9:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    let client_addr = transport_client_addr(&server, &transport).await;

    // A peer that was never contacted, an IPv6 one, and an IPv4-mapped one
    // that must read back as plain IPv4.
    let mapped: SocketAddr = "[::ffff:198.51.100.77]:7000".parse().unwrap();
    let cases: [(SocketAddr, SocketAddr); 3] = [
        (
            "198.51.100.50:5353".parse().unwrap(),
            "198.51.100.50:5353".parse().unwrap(),
        ),
        (
            "[2001:db8::50]:5354".parse().unwrap(),
            "[2001:db8::50]:5354".parse().unwrap(),
        ),
        (mapped, "198.51.100.77:7000".parse().unwrap()),
    ];
    for (wire, expected) in cases {
        assert_ne!(wire, target);
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(wire, None, 0, b"from-wire"),
                client_addr,
            )
            .await
            .unwrap();
        let mut received = [0u8; 1024];
        let (n, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.recv_packet(&mut received),
        )
        .await
        .expect("recv_packet should complete without network I/O")
        .expect("valid RFC1928 frame must be accepted");
        assert_eq!(&received[..n], b"from-wire");
        assert_eq!(source, expected);
    }
}

#[tokio::test]
async fn socks5_udp_transport_projects_only_the_dialed_domain_without_dns() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.11:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, Some("Peer.Example.Test")).await;
    let client_addr = transport_client_addr(&server, &transport).await;

    // Other names, and the dialed name on another port, are dropped; the
    // frame after them is still decoded. The dialed name matches
    // case-insensitively and projects to the captured target.
    let datagrams = [
        expected_socks5_udp_datagram(target, Some("other.invalid.test"), 0, b"foreign-name"),
        expected_socks5_udp_datagram(
            "203.0.113.11:5354".parse().unwrap(),
            Some("Peer.Example.Test"),
            0,
            b"wrong-port",
        ),
        expected_socks5_udp_datagram(target, Some("peer.example.test"), 0, b"projected"),
    ];
    for datagram in &datagrams {
        server.relay.send_to(datagram, client_addr).await.unwrap();
    }

    let mut received = [0u8; 1024];
    let (n, source) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut received),
    )
    .await
    .expect("domain wire source must not block on DNS")
    .expect("a dropped domain frame must not fail the transport");
    assert_eq!(&received[..n], b"projected");
    assert_eq!(source, target);
}

#[tokio::test]
async fn socks5_udp_transport_drops_a_domain_source_when_dialed_by_address() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.11:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    let client_addr = transport_client_addr(&server, &transport).await;
    for datagram in [
        expected_socks5_udp_datagram(target, Some("peer.example.test"), 0, b"dropped"),
        expected_socks5_udp_datagram(target, None, 0, b"numeric"),
    ] {
        server.relay.send_to(&datagram, client_addr).await.unwrap();
    }

    let mut received = [0u8; 1024];
    let (n, _) = transport.recv_packet(&mut received).await.unwrap();
    assert_eq!(&received[..n], b"numeric");
}

#[tokio::test]
async fn socks5_udp_transport_carries_empty_and_maximum_payloads() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.12:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    // IPv4 UDP payload limit 65507 minus the 10-byte SOCKS5 header.
    let largest = vec![0x5a; 65_507 - 10];
    let mut relay_buf = vec![0u8; 65_535];
    let mut client_addr = None;
    for payload in [&[][..], &largest[..]] {
        transport.send_packet(payload).await.unwrap();
        let (n, client) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut relay_buf),
        )
        .await
        .expect("relay should receive the request")
        .unwrap();
        assert_eq!(
            &relay_buf[..n],
            expected_socks5_udp_datagram(target, None, 0, payload)
        );
        client_addr = Some(client);
    }
    let client_addr = client_addr.unwrap();

    let mut received = vec![0u8; 65_535];
    for payload in [&[][..], &largest[..]] {
        server
            .relay
            .send_to(
                &expected_socks5_udp_datagram(target, None, 0, payload),
                client_addr,
            )
            .await
            .unwrap();
        let (n, source) = transport.recv_packet(&mut received).await.unwrap();
        assert_eq!(&received[..n], payload);
        assert_eq!(source, target);
    }
}

#[tokio::test]
async fn socks5_udp_transport_rejects_invalid_domain_encoding() {
    assert_udp_transport_invalid_data(&[
        0x00,
        0x00,
        0x00,
        ATYP_DOMAIN,
        4,
        0xff,
        0xfe,
        0xfd,
        0xfc,
        0x00,
        53,
    ])
    .await;
}

#[tokio::test]
async fn socks5_udp_transport_ignores_malformed_non_relay_datagrams() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.10:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    let client_addr = transport_client_addr(&server, &transport).await;
    let attacker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    attacker
        .send_to(
            &[0x01, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 53],
            client_addr,
        )
        .await
        .unwrap();
    server
        .relay
        .send_to(
            &expected_socks5_udp_datagram(target, None, 0, b"accepted"),
            client_addr,
        )
        .await
        .unwrap();

    let mut received = [0u8; 1024];
    let (n, source) = transport.recv_packet(&mut received).await.unwrap();
    assert_eq!(&received[..n], b"accepted");
    assert_eq!(source, target);
}

#[tokio::test]
async fn socks5_udp_transport_skips_fragmented_datagrams() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let target: SocketAddr = "203.0.113.10:5353".parse().unwrap();
    let transport = dial_udp_test_transport(&server, target, None).await;
    let client_addr = transport_client_addr(&server, &transport).await;
    server
        .relay
        .send_to(
            &expected_socks5_udp_datagram(target, None, 1, b"fragment"),
            client_addr,
        )
        .await
        .unwrap();
    server
        .relay
        .send_to(
            &expected_socks5_udp_datagram(target, None, 0, b"accepted"),
            client_addr,
        )
        .await
        .unwrap();

    let mut received = [0u8; 1024];
    let (n, source) = transport.recv_packet(&mut received).await.unwrap();
    assert_eq!(&received[..n], b"accepted");
    assert_eq!(source, target);
}

#[tokio::test]
async fn socks5_udp_transport_rejects_nonzero_rsv() {
    assert_udp_transport_invalid_data(&[0x01, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 53]).await;
}

#[tokio::test]
async fn socks5_udp_transport_rejects_unknown_atyp() {
    assert_udp_transport_invalid_data(&[0x00, 0x00, 0x00, 0x7f]).await;
}

#[tokio::test]
async fn socks5_udp_transport_rejects_truncated_frame() {
    assert_udp_transport_invalid_data(&[0x00, 0x00, 0x00, ATYP_IPV4, 127, 0]).await;
}

#[tokio::test]
async fn socks5_udp_transport_keeps_control_open_until_drop() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let transport =
        dial_udp_test_transport(&server, "198.51.100.11:53".parse().unwrap(), None).await;

    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            &mut server.control_closed,
        )
        .await
        .is_err(),
        "UDP transport must retain the control stream"
    );

    drop(transport);
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        &mut server.control_closed,
    )
    .await
    .expect("control stream should close when transport drops")
    .expect("SOCKS5 server should observe the control stream closing");
}

#[tokio::test]
async fn socks5_udp_transport_reports_control_eof() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let transport =
        dial_udp_test_transport(&server, "198.51.100.12:53".parse().unwrap(), None).await;
    server.close_control();

    let mut received = [0u8; 1024];
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut received),
    )
    .await
    .expect("control EOF should wake recv_packet")
    .expect_err("control EOF should fail recv_packet");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn socks5_udp_association_uses_control_peer_for_unspecified_bnd_addr() {
    let server = run_udp_associate_test_server(socks5_udp_associate_reply(SocketAddr::new(
        "0.0.0.0".parse().unwrap(),
        0,
    )))
    .await;
    let relay_port = server.relay.local_addr().unwrap().port();
    let (_socket, relay_addr, _control) = Socks5Handler::udp_association(
        &socks5_test_node(server.proxy_addr),
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert_eq!(
        relay_addr,
        SocketAddr::new(server.proxy_addr.ip(), relay_port)
    );
}

#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn socks5_udp_transport_resolves_domain_bnd_addr() {
    let _lock = crate::bootstrap::GLOBAL_TEST_LOCK.lock().unwrap();
    let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let (query_tx, query_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut query_tx = Some(query_tx);
        for _ in 0..2 {
            let mut buf = [0u8; 512];
            let (n, peer) = resolver.recv_from(&mut buf).await.unwrap();
            if let Some(query_tx) = query_tx.take() {
                query_tx.send(buf[..n].to_vec()).unwrap();
            }

            let mut response = buf[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = 1;
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[127, 0, 0, 1]);
            resolver.send_to(&response, peer).await.unwrap();
        }
    });

    crate::bootstrap::set_global(crate::bootstrap::BootstrapResolver::parse(&format!(
        "udp://{resolver_addr}"
    )));
    let server =
        run_udp_associate_test_server(socks5_udp_associate_domain_reply("socks-relay.test", 0))
            .await;
    let result = Socks5Handler::new()
        .dial_udp_transport(
            &socks5_test_node(server.proxy_addr),
            "198.51.100.14:53".parse().unwrap(),
            None,
            std::time::Duration::from_secs(1),
        )
        .await;
    crate::bootstrap::set_global(None);
    let transport = result.unwrap();

    let query = query_rx.await.unwrap();
    assert!(
        query
            .windows(b"\x0bsocks-relay\x04test".len())
            .any(|window| window == b"\x0bsocks-relay\x04test")
    );
    transport_client_addr(&server, &transport).await;
}

#[tokio::test]
async fn socks5_udp_transport_rejects_long_domain() {
    let server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let long_domain = "a".repeat(u8::MAX as usize + 1);
    let result = Socks5Handler::new()
        .dial_udp_transport(
            &socks5_test_node(server.proxy_addr),
            "198.51.100.15:53".parse().unwrap(),
            Some(&long_domain),
            std::time::Duration::from_secs(1),
        )
        .await;

    assert!(result.is_err(), "domains longer than 255 bytes must fail");
}

#[tokio::test]
async fn target_refusals_are_scoped_only_to_valid_connect_replies() {
    for (command, method, header, target_failure) in [
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 1, 0, 1], false),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 2, 0, 1], true),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 3, 0, 1], true),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 4, 0, 1], true),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 5, 0, 1], true),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 6, 0, 1], true),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 7, 0, 1], false),
        (CMD_CONNECT, METHOD_NO_AUTH, [4, 5, 0, 1], false),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 5, 1, 1], false),
        (CMD_CONNECT, METHOD_NO_AUTH, [5, 5, 0, 0xff], false),
        (CMD_CONNECT, METHOD_NO_ACCEPTABLE, [5, 5, 0, 1], false),
        (CMD_UDP_ASSOCIATE, METHOD_NO_AUTH, [5, 5, 0, 1], false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[SOCKS5_VERSION, method]).await.unwrap();
            if method == METHOD_NO_ACCEPTABLE {
                return;
            }
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request[1], command);
            let mut reply = [0; 10];
            reply[..4].copy_from_slice(&header);
            stream.write_all(&reply).await.unwrap();
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let error = if command == CMD_CONNECT {
            Socks5Handler::handshake(
                &mut stream,
                "192.0.2.1:80".parse().unwrap(),
                None,
                None,
                None,
            )
            .await
            .unwrap_err()
        } else {
            Socks5Handler::udp_associate(&mut stream, None, None)
                .await
                .unwrap_err()
        };
        peer.await.unwrap();
        let error = anyhow::Error::new(io::Error::other(crate::SharedError::new(
            error.context("dial"),
        )));
        assert_eq!(crate::proxy::target_failure(&error), target_failure);
        let outcome = crate::group::ScoreOutcome::from_error(&error);
        assert_eq!(
            outcome == crate::group::ScoreOutcome::TargetFailure,
            target_failure
        );
        assert_ne!(outcome, crate::group::ScoreOutcome::Success);
    }
}

async fn run_test_socks5_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Simple SOCKS5 server: no auth, always succeed
                    let mut buf = [0u8; 256];

                    // Read greeting
                    let _ = stream.read(&mut buf).await.unwrap();
                    assert!(buf[0] == SOCKS5_VERSION);

                    // Reply: no auth
                    stream
                        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                        .await
                        .unwrap();

                    // Read request
                    let _ = stream.read(&mut buf).await.unwrap();
                    assert!(buf[0] == SOCKS5_VERSION);
                    assert!(buf[1] == CMD_CONNECT);

                    // Reply: success, bind to 0.0.0.0:0
                    let reply = [
                        SOCKS5_VERSION,
                        REP_SUCCESS,
                        0x00, // RSV
                        ATYP_IPV4,
                        0,
                        0,
                        0,
                        0, // 0.0.0.0
                        0,
                        0, // port 0
                    ];
                    stream.write_all(&reply).await.unwrap();

                    // Keep connection alive briefly for test
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                });
            }
        }
    });

    addr
}

#[tokio::test]
async fn test_socks5_handshake_no_auth() {
    let server_addr = run_test_socks5_server().await;

    let node = Node {
        name: "test".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
        address: server_addr.ip().to_string(),
        host: String::new(),
        port: server_addr.port(),
        ..Default::default()
    };

    let handler = Socks5Handler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let result = handler
        .dial(
            &node,
            target,
            Some("example.com"),
            std::time::Duration::from_secs(3),
        )
        .await;
    assert!(result.is_ok());
}

/// SOCKS5 server that, like Dante with `udp.connectdst: no` or a Xray
/// freedom outbound, forwards every destination of one client through one
/// unconnected socket and relays whatever that socket receives back with its
/// real source in the header.
struct FullConeSocks5Server {
    proxy_addr: SocketAddr,
    /// The server's single outbound socket, the source every peer sees.
    egress_addr: SocketAddr,
    associates: Arc<std::sync::atomic::AtomicUsize>,
    released: Arc<std::sync::atomic::AtomicUsize>,
    close_controls: tokio::sync::watch::Sender<bool>,
}

async fn run_full_cone_socks5_server() -> FullConeSocks5Server {
    use std::sync::atomic::AtomicUsize;
    use tokio::net::UdpSocket;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let egress = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let egress_addr = egress.local_addr().unwrap();
    let relay_reply = socks5_udp_associate_reply(relay.local_addr().unwrap());
    let associates = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let (close_controls, close_rx) = tokio::sync::watch::channel(false);

    tokio::spawn({
        let associates = Arc::clone(&associates);
        let released = Arc::clone(&released);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                associates.fetch_add(1, Ordering::SeqCst);
                let reply = relay_reply.clone();
                let released = Arc::clone(&released);
                let mut close_rx = close_rx.clone();
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    stream
                        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                        .await
                        .unwrap();
                    let mut request = [0u8; 10];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(request[1], CMD_UDP_ASSOCIATE);
                    stream.write_all(&reply).await.unwrap();
                    let mut probe = [0u8; 1];
                    tokio::select! {
                        _ = close_rx.wait_for(|closed| *closed) => {}
                        _ = stream.read(&mut probe) => {}
                    }
                    drop(stream);
                    released.fetch_add(1, Ordering::SeqCst);
                });
            }
        }
    });

    tokio::spawn(async move {
        let mut client = None;
        let mut from_client = vec![0u8; 65_535];
        let mut from_peer = vec![0u8; 65_535];
        loop {
            tokio::select! {
                received = relay.recv_from(&mut from_client) => {
                    let (n, peer) = received.unwrap();
                    client = Some(peer);
                    // IPv4 requests only: RSV(2) FRAG ATYP=1 addr(4) port(2) data.
                    let packet = &from_client[..n];
                    assert_eq!(packet[..4], [0, 0, 0, ATYP_IPV4]);
                    let destination = SocketAddr::from((
                        [packet[4], packet[5], packet[6], packet[7]],
                        u16::from_be_bytes([packet[8], packet[9]]),
                    ));
                    egress.send_to(&packet[10..], destination).await.unwrap();
                }
                received = egress.recv_from(&mut from_peer) => {
                    let (n, source) = received.unwrap();
                    if let Some(client) = client {
                        relay
                            .send_to(
                                &expected_socks5_udp_datagram(source, None, 0, &from_peer[..n]),
                                client,
                            )
                            .await
                            .unwrap();
                    }
                }
            }
        }
    });

    FullConeSocks5Server {
        proxy_addr,
        egress_addr,
        associates,
        released,
        close_controls,
    }
}

/// The production dispatch path: runtime-pinned preparation, then commit.
async fn prepare_shared_test_transport(
    proxy_addr: SocketAddr,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Arc<dyn super::super::MultiTargetTransport> {
    let mut node = socks5_test_node(proxy_addr);
    node.id = node.derive_id();
    let runtime = crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap();
    super::super::ProxyRegistry::default_resolver()
        .unwrap()
        .prepare_shared_source(
            runtime,
            target,
            target_domain,
            std::time::Duration::from_secs(1),
            true,
        )
        .await
        .unwrap()
        .commit()
        .await
        .unwrap()
}

async fn recv_within(
    transport: &Arc<dyn super::super::MultiTargetTransport>,
) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 1024];
    let (n, source) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("reply should arrive")
    .unwrap();
    (buf[..n].to_vec(), source)
}

async fn peer_recv(socket: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 1024];
    let (n, from) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        socket.recv_from(&mut buf),
    )
    .await
    .expect("peer should receive the datagram")
    .unwrap();
    (buf[..n].to_vec(), from)
}

#[test]
fn socks5_is_a_shared_source_protocol() {
    assert!(
        super::super::ProxyRegistry::default_resolver()
            .unwrap()
            .has_shared_source(NodeProtocol::Socks5)
    );
}

#[tokio::test]
async fn socks5_one_association_serves_every_destination_and_unsolicited_peers() {
    let server = run_full_cone_socks5_server().await;
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr, c_addr) = (
        a.local_addr().unwrap(),
        b.local_addr().unwrap(),
        c.local_addr().unwrap(),
    );
    let transport = prepare_shared_test_transport(server.proxy_addr, a_addr, None).await;

    let admitted = AtomicBool::new(false);
    transport.send_packet(b"to-a").await.unwrap();
    transport
        .send_to(b_addr, None, b"to-b", false, Some(&admitted))
        .await
        .unwrap();
    assert!(admitted.load(Ordering::Acquire));

    // Both destinations see the one server-side mapping.
    assert_eq!(peer_recv(&a).await, (b"to-a".to_vec(), server.egress_addr));
    assert_eq!(peer_recv(&b).await, (b"to-b".to_vec(), server.egress_addr));
    assert_eq!(
        server.associates.load(Ordering::SeqCst),
        1,
        "two destinations must share one ASSOCIATE"
    );

    // A peer the client never contacted reaches the mapping and is named.
    c.send_to(b"c-first", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"c-first".to_vec(), c_addr));
    // Later replies keep their own real sources.
    b.send_to(b"b-reply", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"b-reply".to_vec(), b_addr));
    a.send_to(b"a-reply", server.egress_addr).await.unwrap();
    assert_eq!(recv_within(&transport).await, (b"a-reply".to_vec(), a_addr));

    // Dropping the transport releases the one control stream.
    drop(transport);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while server.released.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("control stream should close with the association");
}

#[tokio::test]
async fn socks5_shared_association_ends_with_its_control_stream() {
    let server = run_full_cone_socks5_server().await;
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport =
        prepare_shared_test_transport(server.proxy_addr, peer.local_addr().unwrap(), None).await;
    server.close_controls.send(true).unwrap();

    let mut buf = [0u8; 16];
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        transport.recv_packet(&mut buf),
    )
    .await
    .expect("control EOF should wake recv_packet")
    .expect_err("control EOF should end the association");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn socks5_send_to_encodes_each_destination_in_its_own_header() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let default: SocketAddr = "203.0.113.1:53".parse().unwrap();
    let transport = prepare_shared_test_transport(server.proxy_addr, default, None).await;

    let v6: SocketAddr = "[2001:db8::7]:5353".parse().unwrap();
    let v4: SocketAddr = "198.51.100.8:443".parse().unwrap();
    let named: SocketAddr = "192.0.2.9:8443".parse().unwrap();
    transport
        .send_to(v6, None, b"six", true, None)
        .await
        .unwrap();
    transport.send_to(v4, None, b"", false, None).await.unwrap();
    transport
        .send_to(named, Some("named.example.test"), b"name", false, None)
        .await
        .unwrap();
    transport.send_packet(b"default").await.unwrap();
    let expected = [
        expected_socks5_udp_datagram(v6, None, 0, b"six"),
        expected_socks5_udp_datagram(v4, None, 0, b""),
        // Not the dialed name: a real server pins its outbound form by the
        // first destination, so the address goes out numerically.
        expected_socks5_udp_datagram(named, None, 0, b"name"),
        expected_socks5_udp_datagram(default, None, 0, b"default"),
    ];
    for expected in expected {
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut buf),
        )
        .await
        .expect("relay should receive the datagram")
        .unwrap();
        assert_eq!(&buf[..n], expected);
    }

    // Even an unencodable foreign name cannot fail the packet: only the dialed
    // name reaches the wire.
    let long = "a".repeat(usize::from(u8::MAX) + 1);
    transport
        .send_to(named, Some(&long), b"long", false, None)
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        server.relay.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        &buf[..n],
        expected_socks5_udp_datagram(named, None, 0, b"long")
    );
    server.close_control();
}

#[tokio::test]
async fn socks5_send_to_names_only_the_dialed_destination() {
    let mut server =
        run_udp_associate_test_server(socks5_udp_associate_reply("127.0.0.1:0".parse().unwrap()))
            .await;
    let dialed: SocketAddr = "203.0.113.1:443".parse().unwrap();
    let transport =
        prepare_shared_test_transport(server.proxy_addr, dialed, Some("dialed.example.test")).await;

    transport
        .send_to(dialed, Some("dialed.example.test"), b"dialed", false, None)
        .await
        .unwrap();
    transport
        .send_to(dialed, Some("other.example.test"), b"other", false, None)
        .await
        .unwrap();
    for expected in [
        expected_socks5_udp_datagram(dialed, Some("dialed.example.test"), 0, b"dialed"),
        expected_socks5_udp_datagram(dialed, None, 0, b"other"),
    ] {
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.relay.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf[..n], expected);
    }
    server.close_control();
}
