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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use parking_lot::Mutex;
use tracing::debug;

use crate::quic::{QuicBiStream, QuicClient};

use super::{ProxyHandler, ProxyStream, UdpProxySocket};

const JUICITY_VERSION: u8 = 0x00;
const CMD_AUTHENTICATE: u8 = 0x00;

const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// daeuniverse juicity client keep-alive (`dialer.go:58`).
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// Close the shared QUIC connection after this long without any open stream.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period after sending AUTHENTICATE for the server to reject bad
/// credentials by closing the connection.
const AUTH_GRACE: Duration = Duration::from_millis(150);
/// Tear down a UDP session bridge after this long without traffic.
const UDP_BRIDGE_IDLE: Duration = Duration::from_secs(90);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Juicity address (trojanc metadata wire format).
#[derive(Debug, Clone, PartialEq, Eq)]
enum JuiceAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

impl JuiceAddr {
    fn new(target: SocketAddr, target_domain: Option<&str>) -> Self {
        if let Some(domain) = target_domain {
            return JuiceAddr::Domain(domain.to_string(), target.port());
        }
        match target {
            SocketAddr::V4(v4) => JuiceAddr::V4(v4),
            SocketAddr::V6(v6) => JuiceAddr::V6(v6),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            JuiceAddr::V4(_) => 1 + 4 + 2,
            JuiceAddr::V6(_) => 1 + 16 + 2,
            JuiceAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
        }
    }

    /// trojanc `Metadata.PackTo` (`addr.go:89-111`).
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            JuiceAddr::V4(v4) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            JuiceAddr::V6(v6) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
            JuiceAddr::Domain(domain, port) => {
                out.push(ATYP_DOMAIN);
                out.push(domain.len().min(u8::MAX as usize) as u8);
                out.extend_from_slice(domain.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    /// trojanc `Metadata.Unpack` (`addr.go:113-148`) from a QUIC stream.
    async fn read_from_stream(recv: &mut quinn::RecvStream) -> io::Result<JuiceAddr> {
        let mut atyp = [0u8; 1];
        read_exact(recv, &mut atyp).await?;
        match atyp[0] {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2];
                read_exact(recv, &mut buf).await?;
                let ip: [u8; 4] = buf[..4].try_into().expect("array length");
                let port = u16::from_be_bytes(buf[4..].try_into().expect("array length"));
                Ok(JuiceAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2];
                read_exact(recv, &mut buf).await?;
                let ip: [u8; 16] = buf[..16].try_into().expect("array length");
                let port = u16::from_be_bytes(buf[16..].try_into().expect("array length"));
                Ok(JuiceAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                read_exact(recv, &mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                read_exact(recv, &mut domain).await?;
                let mut port = [0u8; 2];
                read_exact(recv, &mut port).await?;
                let domain = String::from_utf8(domain)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(JuiceAddr::Domain(domain, u16::from_be_bytes(port)))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown metadata type {other:#x}"),
            )),
        }
    }
}

async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> io::Result<()> {
    recv.read_exact(buf)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))
}

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

impl JuicityConnState {
    fn new(conn: quinn::Connection, auth_stream: quinn::SendStream) -> Self {
        let state = Self {
            conn: conn.clone(),
            _auth_stream: auth_stream,
            open: Arc::new(AtomicUsize::new(0)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
        };
        let open = Arc::downgrade(&state.open);
        let last_activity = Arc::downgrade(&state.last_activity);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(KEEP_ALIVE_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                if conn.close_reason().is_some() {
                    break;
                }
                let (Some(open), Some(last)) = (open.upgrade(), last_activity.upgrade()) else {
                    conn.close(quinn::VarInt::from_u32(0), b"state dropped");
                    break;
                };
                let idle = now_secs().saturating_sub(last.load(Ordering::Relaxed));
                if open.load(Ordering::Relaxed) == 0 && idle > CONN_IDLE_TIMEOUT.as_secs() {
                    conn.close(quinn::VarInt::from_u32(0), b"idle");
                    break;
                }
            }
        });
        state
    }

    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
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
                let auth_stream = authenticate(&conn, &uuid, &password).await?;
                Ok(JuicityConnState::new(conn, auth_stream))
            })
            .await
    }
}

/// Juicity authenticate: same TUIC exporter token, version byte 0x00
/// (`client.go:122-141`). Returns the still-open auth stream.
async fn authenticate(
    conn: &quinn::Connection,
    uuid: &[u8; 16],
    password: &str,
) -> anyhow::Result<quinn::SendStream> {
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| anyhow!("Juicity: TLS keying material export failed: {e:?}"))?;
    let mut auth = Vec::with_capacity(2 + 16 + 32);
    auth.push(JUICITY_VERSION);
    auth.push(CMD_AUTHENTICATE);
    auth.extend_from_slice(uuid);
    auth.extend_from_slice(&token);
    let mut stream = conn
        .open_uni()
        .await
        .context("Juicity: open authenticate stream")?;
    stream
        .write_all(&auth)
        .await
        .context("Juicity: send authenticate")?;
    // Bad credentials are signalled by the server closing the connection;
    // give it a brief grace period to do so (no protocol-level auth ack).
    tokio::select! {
        e = conn.closed() => Err(anyhow!("Juicity: connection closed during authentication: {e}")),
        _ = tokio::time::sleep(AUTH_GRACE) => Ok(stream),
    }
}

/// Juicity proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct JuicityHandler;

/// Shared Juicity clients keyed by server + credentials (anytls pool parity).
static CLIENTS: LazyLock<Mutex<HashMap<String, Arc<JuicityClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

impl JuicityHandler {
    pub fn new() -> Self {
        Self
    }

    fn client_for(node: &Node) -> anyhow::Result<Arc<JuicityClient>> {
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
        let mut clients = CLIENTS.lock();
        if let Some(client) = clients.get(&key) {
            return Ok(Arc::clone(client));
        }
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        let config = crate::quic::client_config(
            node.skip_cert_verify,
            &[b"h3"],
            None,
            Some(KEEP_ALIVE_INTERVAL),
        )?;
        let client = Arc::new(JuicityClient {
            quic: QuicClient::new(node.host().to_string(), node.port, server_name, config),
            uuid: *uuid.as_bytes(),
            password,
        });
        clients.insert(key, Arc::clone(&client));
        Ok(client)
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
        let client = Self::client_for(node)?;
        let addr = JuiceAddr::new(target, target_domain);
        let mut last_err: Option<anyhow::Error> = None;
        // Retry once with a fresh connection when the stream open fails on a
        // half-dead cached connection.
        for attempt in 0..2 {
            let (conn, state) = client.connection(connect_timeout).await?;
            state.touch();
            match Self::open_stream(&conn, NETWORK_TCP, &addr).await {
                Ok((send, recv)) => {
                    state.open.fetch_add(1, Ordering::Relaxed);
                    let open = Arc::clone(&state.open);
                    let stream = QuicBiStream::new(send, recv).with_on_drop(move || {
                        open.fetch_sub(1, Ordering::Relaxed);
                    });
                    return Ok(ProxyStream {
                        stream: Box::new(stream),
                        target_addr: target,
                        target_domain: target_domain.map(str::to_string),
                    });
                }
                Err(e) => {
                    debug!("Juicity: stream open failed (attempt {attempt}): {e}");
                    client.quic.invalidate(&conn).await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.expect("loop runs at least once"))
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        let client = Self::client_for(node)?;
        let (conn, state) = client.connection(connect_timeout).await?;
        state.touch();
        let target_addr = JuiceAddr::new(target, target_domain);
        let (mut send, mut recv) = Self::open_stream(&conn, NETWORK_UDP, &target_addr).await?;

        // Bridge the QUIC stream to a local UDP socket pair: the relay sends
        // raw payloads to `relay_addr` on the returned socket and receives
        // replies from the same address (see UdpProxySocket users).
        let external = crate::util::udp_loopback_bind().await?;
        let internal = crate::util::udp_loopback_bind().await?;
        let external_addr = external.local_addr()?;
        let relay_addr = internal.local_addr()?;
        let internal = Arc::new(internal);

        state.open.fetch_add(1, Ordering::Relaxed);
        let bridge_state = Arc::clone(&state);
        tokio::spawn(async move {
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
            bridge_state.open.fetch_sub(1, Ordering::Relaxed);
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
        match Self::client_for(node) {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        assert_eq!(buf, vec![ATYP_IPV4, 93, 184, 216, 34, 0x00, 0x50]);

        let mut buf = Vec::new();
        JuiceAddr::Domain("example.com".to_string(), 443).encode(&mut buf);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xbb]);

        let mut buf = Vec::new();
        JuiceAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)).encode(&mut buf);
        assert_eq!(buf.len(), 19);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(&buf[17..19], &[0x1f, 0x90]);
    }
}
