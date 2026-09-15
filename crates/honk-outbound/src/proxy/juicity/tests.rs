use super::*;
use crate::quic::testutil;
use quinn::VarInt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// AUTHENTICATE command byte (the shared `exporter_auth` writes it
/// inline; only the test server decodes it).
const CMD_AUTHENTICATE: u8 = 0x00;

const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const TEST_PASSWORD: &str = "juicity-test-password";

fn test_node(port: u16, password: &str) -> Node {
    Node {
        name: "juicity-test".to_string(),
        host: "127.0.0.1".to_string(),
        address: format!("127.0.0.1:{port}"),
        port,
        outbound: honk_config::node::OutboundConfig::Juicity(honk_config::node::JuicityConfig {
            uuid: Some(TEST_UUID.to_string()),
            password: Some(password.to_string()),
            quic: honk_config::node::QuicOptions {
                tls: honk_config::node::TlsOptions {
                    skip_cert_verify: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        }),
        ..Default::default()
    }
}

/// Minimal in-process Juicity server: verifies the AUTHENTICATE token
/// with the same TLS exporter, echoes TCP streams back, and echoes UDP
/// stream frames (`[metadata][len][payload]`) back verbatim.
async fn start_server(password: &'static str) -> SocketAddr {
    let (endpoint, addr) = testutil::server_endpoint(&[b"h3"], true).unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                handle_connection(conn, password).await;
            });
        }
    });
    addr
}

async fn handle_connection(conn: quinn::Connection, password: &'static str) {
    // Uni stream: authenticate (stays open; only the first 50 bytes are
    // the auth frame).
    let uni_conn = conn.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut recv) = uni_conn.accept_uni().await else {
                break;
            };
            let conn = uni_conn.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                if read_exact(&mut recv, &mut head).await.is_err() {
                    return;
                }
                if head != [JUICITY_VERSION, CMD_AUTHENTICATE] {
                    return;
                }
                let mut rest = [0u8; 48];
                if read_exact(&mut recv, &mut rest).await.is_err() {
                    return;
                }
                let uuid: &[u8; 16] = rest[..16].try_into().unwrap();
                let mut token = [0u8; 32];
                if conn
                    .export_keying_material(&mut token, uuid, password.as_bytes())
                    .is_err()
                {
                    return;
                }
                if token != rest[16..] {
                    conn.close(VarInt::from_u32(0xfffffff1), b"authentication failed");
                }
            });
        }
    });
    // Bi streams: TCP echo / UDP frame echo.
    loop {
        let Ok((mut send, mut recv)) = conn.accept_bi().await else {
            break;
        };
        tokio::spawn(async move {
            let mut network = [0u8; 1];
            if read_exact(&mut recv, &mut network).await.is_err() {
                return;
            }
            match network[0] {
                NETWORK_TCP => {
                    if JuiceAddr::read_from_stream(&mut recv).await.is_err() {
                        return;
                    }
                    let mut buf = [0u8; 8192];
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        }
                    }
                }
                NETWORK_UDP => {
                    if JuiceAddr::read_from_stream(&mut recv).await.is_err() {
                        return;
                    }
                    let mut payload = vec![0u8; u16::MAX as usize];
                    loop {
                        let Ok((addr, payload_len)) = read_udp_frame(&mut recv, &mut payload).await
                        else {
                            return;
                        };
                        let mut frame = Vec::with_capacity(addr.encoded_len() + 2 + payload_len);
                        addr.encode(&mut frame);
                        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
                        frame.extend_from_slice(&payload[..payload_len]);
                        if send.write_all(&frame).await.is_err() {
                            return;
                        }
                    }
                }
                _ => {}
            }
        });
    }
}

#[tokio::test]
async fn test_dial_tcp_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    let mut stream = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial should succeed");
    stream.stream.write_all(b"hello juicity").await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello juicity");
}

#[tokio::test]
async fn test_wrong_password_rejected() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), "wrong-password");
    let handler = JuicityHandler::new();
    let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

    // Optimistic auth (zero grace, tuic parity): the rejection surfaces
    // ~1 RTT later when the server closes the connection; the
    // connectivity probe (which waits for it) must say no.
    let _ = handler
        .dial(&node, target, None, Duration::from_secs(5))
        .await;
    assert!(!handler.test_connectivity(&node).await);
}

#[tokio::test]
async fn test_udp_transport_echo() {
    let server_addr = start_server(TEST_PASSWORD).await;
    let node = test_node(server_addr.port(), TEST_PASSWORD);
    let handler = JuicityHandler::new();
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

    let transport = handler
        .dial_udp_transport(&node, target, None, Duration::from_secs(5))
        .await
        .expect("dial_udp_transport should succeed");
    assert_eq!(transport.relay_addr(), target);
    transport.send_packet(b"dns-query").await.unwrap();
    let mut small = [0u8; 4];
    let error = transport.recv_packet(&mut small).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let mut buf = [0u8; 256];
    transport.send_packet(b"dns-query").await.unwrap();
    let (n, src) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(src, target);
    assert_eq!(&buf[..n], b"dns-query");

    // A second datagram on the same session must work too.
    transport.send_packet(b"second").await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), transport.recv_packet(&mut buf))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"second");
}
