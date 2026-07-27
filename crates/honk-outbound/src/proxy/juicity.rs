//! Juicity proxy handler (QUIC), implemented against the daeuniverse
//! reference client (`outbound/protocol/juicity`):
//!
//! - QUIC with TLS ALPN `h3` (`dialer/juicity/juicity.go:49-54`).
//! - Authentication reuses the TUIC frame on a uni stream:
//!   `[version = 0x00, command = 0x00, uuid(16), token(32)]` with
//!   `token = TLS ExportKeyingMaterial(label = uuid bytes, context = password,
//!   len = 32)` (`juice.go`, `client.go:122-157`, `protocol/tuic/
//!   protocol.go:146-154`). The stream is kept open for the connection
//!   lifetime; the reference client multiplexes per-underlay UDP auth
//!   messages on it (not implemented here — that exotic port-0 raw-UDP mode
//!   is never used by normal proxying).
//! - TCP: one bi stream per connection, `[network = 0x01][metadata]` followed
//!   by raw payload (`stream_conn.go:29-36`).
//! - UDP: one bi stream per session, `[network = 0x03][metadata]` followed by
//!   frames of `[metadata][len u16][payload]` in both directions
//!   (`stream_packet_conn.go`, `SealUDP`).
//! - Metadata (trojanc wire format): type 0x01 = IPv4 (4B + port),
//!   0x03 = domain (len byte + bytes + port), 0x04 = IPv6 (16B + port)
//!   (`protocol/trojanc/addr.go:89-111`).
//! - Keep-alive: QUIC keep-alive every 5s (`dialer.go:58`); there is no
//!   application-level heartbeat command.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use tracing::debug;

use crate::quic::{
    ClientCache, QuicClient, QuicConnState, now_secs, recv_read_exact as read_exact,
};

use super::addr::SocksAddr as JuiceAddr;
use super::{ProxyHandler, ProxyStream, UdpProxySocket};

const JUICITY_VERSION: u8 = 0x00;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x03;

/// daeuniverse juicity client keep-alive (`dialer.go:58`).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// Close the shared QUIC connection after this long without any open stream.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period after sending AUTHENTICATE for the server to reject bad
/// credentials by closing the connection.
const AUTH_GRACE: Duration = Duration::from_millis(150);
/// Tear down a UDP session bridge after this long without traffic.
const UDP_BRIDGE_IDLE: Duration = Duration::from_secs(90);

/// Read one inbound UDP frame (`[metadata][len u16][payload]`); the address
/// is returned alongside the payload for completeness but relayed sessions
/// are keyed by target, so callers currently ignore it.
async fn read_udp_frame(recv: &mut quinn::RecvStream) -> io::Result<(JuiceAddr, Vec<u8>)> {
    let addr = JuiceAddr::read_from_stream(recv).await?;
    let mut len = [0u8; 2];
    read_exact(recv, &mut len).await?;
    let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
    read_exact(recv, &mut payload).await?;
    Ok((addr, payload))
}

/// Per-QUIC-connection protocol state.
struct JuicityConnState {
    #[allow(dead_code)] // kept to own the connection handle
    conn: quinn::Connection,
    /// Kept open for the connection lifetime — dropping it would send FIN on
    /// the authenticate stream (see module docs).
    _auth_stream: quinn::SendStream,
    /// Number of open TCP streams + UDP bridges on this connection.
    open: Arc<AtomicUsize>,
    /// Last activity (unix seconds) for the idle-connection reaper.
    last_activity: Arc<AtomicU64>,
}

impl QuicConnState for JuicityConnState {
    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn open_counter(&self) -> &Arc<AtomicUsize> {
        &self.open
    }
}

impl JuicityConnState {
    fn new(conn: quinn::Connection, auth_stream: quinn::SendStream) -> Self {
        let state = Self {
            conn: conn.clone(),
            _auth_stream: auth_stream,
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
        };
        crate::quic::spawn_conn_reaper(
            conn,
            Arc::downgrade(&state.open),
            Arc::downgrade(&state.last_activity),
            KEEP_ALIVE_INTERVAL,
            CONN_IDLE_TIMEOUT,
            None,
        );
        state
    }
}

struct JuicityClient {
    quic: QuicClient<JuicityConnState>,
    uuid: [u8; 16],
    password: String,
}

impl JuicityClient {
    async fn connection(
        &self,
        connect_timeout: Duration,
    ) -> anyhow::Result<(quinn::Connection, Arc<JuicityConnState>)> {
        let uuid = self.uuid;
        let password = self.password.clone();
        self.quic
            .connection_with(connect_timeout, move |conn| async move {
                let auth_stream = crate::quic::exporter_auth(
                    &conn,
                    &uuid,
                    &password,
                    JUICITY_VERSION,
                    false,
                    AUTH_GRACE,
                )
                .await?;
                Ok(JuicityConnState::new(conn, auth_stream))
            })
            .await
    }
}

/// Juicity proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct JuicityHandler;

/// Shared Juicity clients keyed by server + credentials (anytls pool parity).
static CLIENTS: ClientCache<JuicityClient> =
    ClientCache::new(|| parking_lot::Mutex::new(HashMap::new()));

impl JuicityHandler {
    pub fn new() -> Self {
        Self
    }

    async fn client_for(node: &Node) -> anyhow::Result<Arc<JuicityClient>> {
        let uuid_str = node
            .juicity_uuid
            .as_deref()
            .or(node.username.as_deref())
            .ok_or_else(|| anyhow!("Juicity node '{}': missing juicity_uuid", node.name))?;
        let uuid = uuid::Uuid::parse_str(uuid_str)
            .with_context(|| format!("Juicity node '{}': invalid uuid", node.name))?;
        let password = node
            .juicity_password
            .as_deref()
            .or(node.password.as_deref())
            .unwrap_or("")
            .to_string();
        let key = format!(
            "{}|{}|{}|{}|{}|{}",
            node.host(),
            node.port,
            uuid_str,
            password,
            node.sni.as_deref().unwrap_or(""),
            node.skip_cert_verify
        );
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        crate::quic::cached_client(&CLIENTS, key, || async move {
            // Upstream juicity (Go and juicity-rs) defaults to BBR on the client
            // when no congestion_control is configured.
            let config = crate::quic::client_config(
                node,
                &[b"h3"],
                crate::quic::QuicClientOptions {
                    keep_alive: Some(KEEP_ALIVE_INTERVAL),
                    ..crate::quic::QuicClientOptions::with_congestion(Some("bbr"))
                },
            )
            .await?;
            Ok(Arc::new(JuicityClient {
                quic: QuicClient::new(node.host().to_string(), node.port, server_name, config),
                uuid: *uuid.as_bytes(),
                password,
            }))
        })
        .await
    }

    /// Open a bi stream and write the juicity request header
    /// (`[network][metadata]`, `stream_conn.go:29-36`).
    async fn open_stream(
        conn: &quinn::Connection,
        network: u8,
        addr: &JuiceAddr,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = conn.open_bi().await.context("Juicity: open stream")?;
        let mut header = Vec::with_capacity(1 + addr.encoded_len());
        header.push(network);
        addr.encode(&mut header);
        send.write_all(&header)
            .await
            .context("Juicity: send request header")?;
        Ok((send, recv))
    }
}

#[async_trait]
impl ProxyHandler for JuicityHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::Juicity
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        let client = Self::client_for(node).await?;
        let addr = JuiceAddr::new(target, target_domain);
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = addr.clone();
                async move { Self::open_stream(&conn, NETWORK_TCP, &addr).await }
            },
            |_| true,
            "Juicity",
        )
        .await?;
        Ok(ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        let client = Self::client_for(node).await?;
        let target_addr = JuiceAddr::new(target, target_domain);
        // Same retry skeleton as TCP dials: a dead cached connection must not
        // fail the UDP session outright (it would otherwise surface as a
        // one-shot stream-open error on the half-dead connection).
        let stream_addr = target_addr.clone();
        let stream = crate::quic::dial_quic_stream(
            &client.quic,
            |timeout| {
                let client = Arc::clone(&client);
                async move { client.connection(timeout).await }
            },
            connect_timeout,
            move |conn| {
                let addr = stream_addr.clone();
                async move { Self::open_stream(&conn, NETWORK_UDP, &addr).await }
            },
            |_| true,
            "Juicity",
        )
        .await?;
        // The guard carries the connection's open-stream accounting; it must
        // live as long as the bridge.
        let (mut send, mut recv, guard) = stream.into_parts();

        // Bridge the QUIC stream to a local UDP socket pair: the relay sends
        // raw payloads to `relay_addr` on the returned socket and receives
        // replies from the same address (see UdpProxySocket users).
        let (external, internal, external_addr, relay_addr) =
            crate::util::udp_loopback_pair().await?;
        let internal = Arc::new(internal);

        tokio::spawn(async move {
            let _guard = guard;
            let writer = {
                let internal = Arc::clone(&internal);
                let target_addr = target_addr.clone();
                async move {
                    let mut buf = vec![0u8; 65536];
                    loop {
                        let Ok((n, src)) = internal.recv_from(&mut buf).await else {
                            break;
                        };
                        if src != external_addr {
                            continue;
                        }
                        // SealUDP: `[metadata][len u16][payload]`
                        // (`stream_packet_conn.go:83-90`).
                        let mut frame = Vec::with_capacity(target_addr.encoded_len() + 2 + n);
                        target_addr.encode(&mut frame);
                        frame.extend_from_slice(&(n as u16).to_be_bytes());
                        frame.extend_from_slice(&buf[..n]);
                        if send.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                }
            };
            let reader = async move {
                loop {
                    let Ok((_addr, payload)) = read_udp_frame(&mut recv).await else {
                        break;
                    };
                    if internal.send_to(&payload, external_addr).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = writer => {},
                _ = reader => {},
                _ = tokio::time::sleep(UDP_BRIDGE_IDLE) => {},
            }
        });

        Ok(UdpProxySocket {
            socket: Arc::new(external),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
            _control: None,
        })
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _tcp: tokio::net::TcpStream,
        _connect_timeout: Duration,
    ) -> anyhow::Result<ProxyStream> {
        anyhow::bail!("Juicity runs over QUIC; a bare TCP connection cannot be reused")
    }

    async fn test_connectivity(&self, node: &Node) -> bool {
        match Self::client_for(node).await {
            Ok(client) => client.connection(Duration::from_secs(5)).await.is_ok(),
            Err(e) => {
                debug!("Juicity connectivity test failed for {}: {}", node.name, e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::testutil;
    use quinn::VarInt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// AUTHENTICATE command byte (the shared `exporter_auth` writes it
    /// inline; only the test server decodes it).
    const CMD_AUTHENTICATE: u8 = 0x00;

    const TEST_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const TEST_PASSWORD: &str = "juicity-test-password";

    fn test_node(port: u16, password: &str) -> Node {
        Node {
            name: "juicity-test".to_string(),
            protocol: NodeProtocol::Juicity,
            host: "127.0.0.1".to_string(),
            address: format!("127.0.0.1:{port}"),
            port,
            juicity_uuid: Some(TEST_UUID.to_string()),
            juicity_password: Some(password.to_string()),
            skip_cert_verify: true,
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
                        loop {
                            let Ok((addr, payload)) = read_udp_frame(&mut recv).await else {
                                return;
                            };
                            let mut frame =
                                Vec::with_capacity(addr.encoded_len() + 2 + payload.len());
                            addr.encode(&mut frame);
                            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                            frame.extend_from_slice(&payload);
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

        let result = handler
            .dial(&node, target, None, Duration::from_secs(5))
            .await;
        assert!(result.is_err(), "bad password must fail the dial");
        assert!(!handler.test_connectivity(&node).await);
    }

    #[tokio::test]
    async fn test_udp_echo() {
        let server_addr = start_server(TEST_PASSWORD).await;
        let node = test_node(server_addr.port(), TEST_PASSWORD);
        let handler = JuicityHandler::new();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let udp = handler
            .dial_udp(&node, target, None, Duration::from_secs(5))
            .await
            .expect("dial_udp should succeed");
        udp.socket
            .send_to(b"dns-query", udp.relay_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let (n, src) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
            .await
            .expect("reply timed out")
            .unwrap();
        assert_eq!(src, udp.relay_addr);
        assert_eq!(&buf[..n], b"dns-query");

        // A second datagram on the same session must work too.
        udp.socket.send_to(b"second", udp.relay_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.socket.recv_from(&mut buf))
            .await
            .expect("reply timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"second");
    }

    #[test]
    fn test_metadata_codec() {
        let mut buf = Vec::new();
        JuiceAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80)).encode(&mut buf);
        assert_eq!(
            buf,
            vec![crate::proxy::addr::ATYP_IPV4, 93, 184, 216, 34, 0x00, 0x50]
        );

        let mut buf = Vec::new();
        JuiceAddr::Domain("example.com".to_string(), 443).encode(&mut buf);
        assert_eq!(buf[0], crate::proxy::addr::ATYP_DOMAIN);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xbb]);

        let mut buf = Vec::new();
        JuiceAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)).encode(&mut buf);
        assert_eq!(buf.len(), 19);
        assert_eq!(buf[0], crate::proxy::addr::ATYP_IPV6);
        assert_eq!(&buf[17..19], &[0x1f, 0x90]);
    }
}
