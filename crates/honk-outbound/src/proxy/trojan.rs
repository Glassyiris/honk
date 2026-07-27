//! Trojan proxy handler.
//!
//! Implements the Trojan-GFW protocol over a plain TCP, TLS-wrapped,
//! WebSocket, or gRPC connection. The protocol header consists of:
//!
//! ```text
//! SHA224(password) as 56 hex bytes | CRLF | cmd(1) | address | CRLF
//! ```
//!
//! Address encoding follows the SOCKS5-style format used by Trojan:
//! - IPv4:  `0x01` + 4 octets + 2-byte port
//! - IPv6:  `0x04` + 16 octets + 2-byte port
//! - Domain: `0x03` + 1-byte length + domain + 2-byte port
//!
//! Command bytes: `0x01` for TCP, `0x03` for UDP.
//!
//! ### Transport wrapping
//!
//! When `node.transport` is set to `"ws"` or `"grpc"`, the underlying
//! TCP (or TLS) connection is wrapped before the Trojan handshake. The
//! transport layer itself (WebSocket upgrade via tokio-tungstenite,
//! minimal HTTP/2 + gRPC-Length-Prefixed framing) lives in
//! [`super::transport`], shared with the VMess/VLESS handlers.
//!
//! Reference: <https://trojan-gfw.github.io/trojan/protocol>

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time;

use super::addr;
use super::{ProxyHandler, ProxyStream, UdpProxySocket};

const CRLF: &[u8] = b"\r\n";
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

/// Trojan proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct TrojanHandler;

impl TrojanHandler {
    pub fn new() -> Self {
        Self
    }

    /// Format: `hex(sha224(password)) CRLF cmd address CRLF`.
    fn build_request_header(
        password: &str,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_TCP);
        header.extend_from_slice(&addr::encode_address(target, target_domain));
        header.extend_from_slice(CRLF);
        header
    }

    /// Connect to the server and optionally wrap with WebSocket or gRPC
    /// transport based on `node.transport`. TLS is applied before the
    /// transport wrapping when `node.tls` is true.
    async fn connect_server(
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn super::AsyncReadWrite>> {
        super::transport::connect_transport(node, connect_timeout).await
    }

    async fn maybe_tls_wrap(
        node: &Node,
        stream: TcpStream,
    ) -> anyhow::Result<Box<dyn super::AsyncReadWrite>> {
        super::transport::maybe_tls_wrap(node, stream).await
    }
}

#[async_trait]
impl ProxyHandler for TrojanHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::Trojan
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain);
        let mut stream = Self::connect_server(node, connect_timeout).await?;
        stream.write_all(&header).await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        _connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain);
        let mut stream = Self::maybe_tls_wrap(node, tcp).await?;
        stream.write_all(&header).await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_udp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<UdpProxySocket> {
        // UDP relay is only available when the node's network list explicitly
        // includes "udp" (or is unset); fail loudly otherwise instead of
        // silently dropping datagrams.
        if let Some(network) = node.network.as_deref() {
            let supports_udp = network
                .split(',')
                .any(|n| n.trim().eq_ignore_ascii_case("udp"));
            if !supports_udp {
                anyhow::bail!(
                    "Trojan UDP: node network '{}' does not include \"udp\"",
                    network
                );
            }
        }

        let password = node.password.as_deref().unwrap_or("");
        let addr = format!("{}:{}", node.host(), node.port);
        tracing::debug!("Trojan UDP: opening associate channel to {}", addr);

        // The associate channel needs the same TLS / transport wrapping as
        // TCP dials — writing the header onto bare TCP gets dropped by any
        // TLS-terminated Trojan server before the request is even read.
        let mut control = Self::connect_server(node, connect_timeout).await?;

        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_UDP);
        header.extend_from_slice(&addr::encode_address(target, target_domain));
        header.extend_from_slice(CRLF);

        control.write_all(&header).await?;

        // Bridge a loopback UDP socket pair to Trojan-framed packets on the
        // associate stream: the relay talks raw payloads to `relay_addr`,
        // the bridge frames them onto the tunnel and unframes replies back.
        // (Sending datagrams directly to `target` here used to bypass the
        // proxy entirely — and made UDP health probes measure the gateway's
        // own egress instead of the tunnel.)
        let external = crate::util::udp_loopback_bind().await?;
        let internal = crate::util::udp_loopback_bind().await?;
        let external_addr = external.local_addr()?;
        let relay_addr = internal.local_addr()?;
        tokio::spawn(trojan_udp_bridge(
            control,
            internal,
            external_addr,
            addr::encode_address(target, target_domain),
        ));

        Ok(UdpProxySocket {
            socket: Arc::new(external),
            relay_addr,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
            _control: None,
        })
    }

    /// Poolable only on the plain TCP transport: `dial()` completes the
    /// TLS handshake (if enabled) and writes the one-shot request header;
    /// Trojan defines no server handshake reply, so the stream is then a
    /// target-bound data channel. WebSocket/gRPC transports add a bridge
    /// task / HTTP/2 framing state whose idle liveness cannot be probed at
    /// the fd level, so they stay on bare-TCP pooling.
    fn pool_ready_streams(&self, node: &Node) -> bool {
        matches!(node.transport.as_str(), "" | "tcp")
    }
}

/// Idle timeout for the UDP associate bridge (mirrors the AnyTLS UoT bridge).
const UDP_BRIDGE_IDLE_SECS: u64 = 90;

/// Bridge task for UDP associate: frames loopback datagrams as Trojan UDP
/// packets (`addr | u16 len | CRLF | payload`) on the associate stream and
/// delivers inbound packets back to the loopback peer. Ends on error, EOF,
/// or after [`UDP_BRIDGE_IDLE_SECS`] without activity.
async fn trojan_udp_bridge(
    stream: Box<dyn super::AsyncReadWrite>,
    internal: tokio::net::UdpSocket,
    external_addr: SocketAddr,
    addr_header: Vec<u8>,
) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader = tokio::spawn(async move {
        loop {
            // The address is parsed (and bounds-checked) but discarded: the
            // bridge replies to the fixed loopback peer regardless.
            if addr::SocksAddr::read_from_stream(&mut rd).await.is_err() {
                break;
            }
            let mut len_buf = [0u8; 2];
            if rd.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut crlf = [0u8; 2];
            if rd.read_exact(&mut crlf).await.is_err() {
                break;
            }
            let mut data = vec![0u8; len];
            if rd.read_exact(&mut data).await.is_err() {
                break;
            }
            if tx.send(data).is_err() {
                break;
            }
        }
    });

    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            result = internal.recv_from(&mut buf) => {
                match result {
                    Ok((n, src)) => {
                        if src != external_addr {
                            continue;
                        }
                        let mut pkt = Vec::with_capacity(addr_header.len() + 4 + n);
                        pkt.extend_from_slice(&addr_header);
                        pkt.extend_from_slice(&(n as u16).to_be_bytes());
                        pkt.extend_from_slice(CRLF);
                        pkt.extend_from_slice(&buf[..n]);
                        if wr.write_all(&pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if internal.send_to(&data, external_addr).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = time::sleep(Duration::from_secs(UDP_BRIDGE_IDLE_SECS)) => break,
        }
    }
    reader.abort();
}

/// Compute the lowercase hex encoding of SHA224(password).
fn hex_sha224(password: &str) -> String {
    let hash = Sha224::digest(password.as_bytes());
    let mut out = String::with_capacity(hash.len() * 2);
    for byte in hash {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_request_header_encoding() {
        let password = "password123";
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header = TrojanHandler::build_request_header(password, target, None);

        // First 56 bytes are the hex-encoded SHA224(password).
        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_TCP);
        assert_eq!(header[59], addr::ATYP_IPV4);
        assert_eq!(&header[60..64], &[93, 184, 216, 34]);
        assert_eq!(&header[64..66], &[0x00, 0x50]); // port 80
        assert_eq!(&header[66..68], CRLF);
    }

    #[test]
    fn test_trojan_domain_header_encoding() {
        let password = "secret";
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let domain = "example.com";

        let header = TrojanHandler::build_request_header(password, target, Some(domain));

        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_TCP);
        assert_eq!(header[59], addr::ATYP_DOMAIN);
        assert_eq!(header[60], domain.len() as u8);
        assert_eq!(&header[61..72], domain.as_bytes());
        assert_eq!(&header[72..74], &[0x01, 0xbb]); // port 443
        assert_eq!(&header[74..76], CRLF);
    }

    #[test]
    fn test_hex_sha224_known_value() {
        // SHA224("") is a known constant.
        let hash = hex_sha224("");
        assert_eq!(
            hash,
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_pool_ready_streams_transport_gating() {
        let handler = TrojanHandler::new();
        let mut node = Node {
            name: "t".into(),
            protocol: NodeProtocol::Trojan,
            address: "127.0.0.1".into(),
            port: 443,
            ..Default::default()
        };
        node.transport = String::new();
        assert!(handler.pool_ready_streams(&node));
        node.transport = "tcp".into();
        assert!(handler.pool_ready_streams(&node));
        node.transport = "ws".into();
        assert!(!handler.pool_ready_streams(&node));
        node.transport = "grpc".into();
        assert!(!handler.pool_ready_streams(&node));
    }

    /// The bridge frames loopback payloads as Trojan UDP packets
    /// (`addr | u16 len | CRLF | payload`) and delivers inbound packets
    /// back to the loopback peer.
    #[tokio::test]
    async fn test_trojan_udp_bridge_roundtrip() {
        let (client_half, mut server_half) = tokio::io::duplex(65536);
        let boxed: Box<dyn crate::proxy::AsyncReadWrite> = Box::new(client_half);
        let external = crate::util::udp_loopback_bind().await.unwrap();
        let internal = crate::util::udp_loopback_bind().await.unwrap();
        let external_addr = external.local_addr().unwrap();
        let relay_addr = internal.local_addr().unwrap();
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let addr_header = addr::encode_address(target, None);
        tokio::spawn(trojan_udp_bridge(
            boxed,
            internal,
            external_addr,
            addr_header,
        ));

        // Outbound: payload from the loopback peer becomes a framed packet.
        external.send_to(b"ping", relay_addr).await.unwrap();
        let mut head = [0u8; 7]; // 0x01 + 4 octets + 2 port
        server_half.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [0x01, 8, 8, 8, 8, 0, 53]);
        let mut len_buf = [0u8; 2];
        server_half.read_exact(&mut len_buf).await.unwrap();
        assert_eq!(u16::from_be_bytes(len_buf), 4);
        let mut crlf = [0u8; 2];
        server_half.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0u8; 4];
        server_half.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");

        // Inbound: a framed packet from the stream is delivered to the peer.
        let mut inbound = vec![0x01, 8, 8, 8, 8, 0, 53, 0, 4];
        inbound.extend_from_slice(b"\r\n");
        inbound.extend_from_slice(b"pong");
        server_half.write_all(&inbound).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = external.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from, relay_addr);
    }
}
