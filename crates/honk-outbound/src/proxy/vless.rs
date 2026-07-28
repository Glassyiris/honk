//! VLESS proxy handler.
//!
//! VLESS is Xray's simplified protocol — NO encryption, relies entirely
//! on outer TLS for security. The handshake is a single request header
//! followed by a 1-byte response.
//!
//! Protocol flow:
//! 1. Connect to the server via the shared transport layer
//!    (`super::transport`): TCP, optionally TLS-wrapped (`node.tls`),
//!    optionally carried over WebSocket (`node.transport = "ws"`) or
//!    gRPC (`"grpc"`).
//! 2. Send the VLESS request header:
//!    ```text
//!    ver(1) | uuid(16) | addon_len(1) | [addon(addon_len)] | cmd(1) | port(2) | atyp(1) | addr(var)
//!    ```
//!    - `ver`: 0x00
//!    - `uuid`: 16 raw bytes parsed from `node.password` (UUID string)
//!    - `addon_len`: 0 (no addons for simplicity)
//!    - `cmd`: 0x01 TCP, 0x02 UDP
//!    - `port`: big-endian u16
//!    - `atyp`: 0x01 IPv4, 0x02 Domain, 0x03 IPv6
//!    - `addr`: 4 bytes (IPv4) / 1+len bytes (Domain) / 16 bytes (IPv6)
//! 3. Read 1-byte response (0x00 = success, non-zero = error).
//! 4. If success, the stream is transparently connected to the target.
//!
//! Reference: <https://xtls.github.io/en/development/protocols/vless.html>

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::{AsyncReadWrite, ProxyHandler, ProxyStream};

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
#[allow(dead_code)]
const CMD_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// VLESS proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct VLessHandler;

impl VLessHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a UUID string into a 16-byte array.
    fn parse_uuid(uuid_str: &str) -> anyhow::Result<[u8; 16]> {
        let uuid = uuid::Uuid::parse_str(uuid_str)?;
        Ok(*uuid.as_bytes())
    }

    /// Build the VLESS request header.
    ///
    /// Layout: `ver(1) | uuid(16) | addon_len(1) | cmd(1) | port(2) | atyp(1) | addr(var)`
    fn build_request_header(
        uuid_bytes: &[u8; 16],
        cmd: u8,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Vec<u8> {
        let max_addr = if target_domain.is_some() {
            1 + 255
        } else if target.is_ipv6() {
            16
        } else {
            4
        };
        let mut buf = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + max_addr);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(uuid_bytes);
        buf.push(0x00); // addon_len = 0 (no addons)
        buf.push(cmd);

        buf.extend_from_slice(&target.port().to_be_bytes());

        if let Some(domain) = target_domain {
            buf.push(ATYP_DOMAIN);
            let domain_bytes = domain.as_bytes();
            buf.push(domain_bytes.len().min(u8::MAX as usize) as u8);
            buf.extend_from_slice(domain_bytes);
        } else {
            match target {
                SocketAddr::V4(v4) => {
                    buf.push(ATYP_IPV4);
                    buf.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    buf.push(ATYP_IPV6);
                    buf.extend_from_slice(&v6.ip().octets());
                }
            }
        }

        buf
    }

    /// Connect to the server, optionally wrapping in TLS and then the
    /// `node.transport` WS/gRPC layer (via `super::transport`).
    async fn connect_server(
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        super::transport::connect_transport(node, connect_timeout).await
    }

    /// Wrap an already-connected TCP stream with TLS (when `node.tls`) and
    /// then the `node.transport` WS/gRPC layer (the `dial_with_tcp` path).
    async fn wrap_transport(
        node: &Node,
        tcp: TcpStream,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        super::transport::wrap_transport(node, tcp).await
    }
}

impl VLessHandler {
    /// Read and validate the VLESS response header:
    /// `[version(1)][addon_len(1)][addon(addon_len)]`. Reading only the
    /// version byte would leave any addon bytes to corrupt the stream.
    async fn read_response_header(stream: &mut Box<dyn AsyncReadWrite>) -> anyhow::Result<()> {
        use tokio::io::AsyncReadExt;
        let mut head = [0u8; 2];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x00 {
            anyhow::bail!("VLESS: server rejected request (code 0x{:02x})", head[0]);
        }
        let addon_len = head[1] as usize;
        if addon_len > 0 {
            // Protobuf addon is informational; consume it so it does not
            // leak into the relayed stream.
            let mut addon = vec![0u8; addon_len];
            stream.read_exact(&mut addon).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyHandler for VLessHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::VLess
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid_str = node.password.as_deref().unwrap_or("");
        let uuid_bytes = Self::parse_uuid(uuid_str)?;

        let header = Self::build_request_header(&uuid_bytes, CMD_TCP, target, target_domain);
        let mut stream = Self::connect_server(node, connect_timeout).await?;
        stream.write_all(&header).await?;

        Self::read_response_header(&mut stream).await?;

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
        let uuid_str = node.password.as_deref().unwrap_or("");
        let uuid_bytes = Self::parse_uuid(uuid_str)?;

        let header = Self::build_request_header(&uuid_bytes, CMD_TCP, target, target_domain);
        let mut stream = Self::wrap_transport(node, tcp).await?;
        stream.write_all(&header).await?;

        Self::read_response_header(&mut stream).await?;

        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_header_ipv4() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, None);

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(4)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 4);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x00, 0x50]); // port 80
        assert_eq!(header[21], ATYP_IPV4);
        assert_eq!(&header[22..26], &[93, 184, 216, 34]);
    }

    #[test]
    fn test_vless_header_domain() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let domain = "example.com";

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, Some(domain));

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + domain_len(1) + domain(11)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 1 + domain.len());
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x01, 0xbb]); // port 443
        assert_eq!(header[21], ATYP_DOMAIN);
        assert_eq!(header[22], domain.len() as u8);
        assert_eq!(&header[23..34], domain.as_bytes());
    }

    #[test]
    fn test_vless_header_ipv6() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "[::1]:1080".parse().unwrap();

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, None);

        // ver(1) + uuid(16) + addon_len(1) + cmd(1) + port(2) + atyp(1) + addr(16)
        assert_eq!(header.len(), 1 + 16 + 1 + 1 + 2 + 1 + 16);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 0x00); // addon_len
        assert_eq!(header[18], CMD_TCP);
        assert_eq!(&header[19..21], &[0x04, 0x38]); // port 1080
        assert_eq!(header[21], ATYP_IPV6);
        // IPv6 ::1 = 15 bytes of 0x00 then 0x01
        assert_eq!(&header[22..37], &[0u8; 15]);
        assert_eq!(header[37], 0x01);
    }

    #[test]
    fn test_vless_header_udp() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_UDP, target, None);

        assert_eq!(header[18], CMD_UDP);
        assert_eq!(&header[19..21], &[0x27, 0x0f]); // port 9999
    }

    #[test]
    fn test_parse_uuid_valid() {
        let result = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_parse_uuid_invalid() {
        let result = VLessHandler::parse_uuid("not-a-uuid");
        assert!(result.is_err());
    }

    /// End-to-end over the WebSocket transport: a mock WS server receives
    /// the VLESS request header as the first binary message, replies with
    /// the 1-byte acceptance, and then sees relayed payload.
    #[tokio::test]
    async fn test_vless_dial_over_ws() {
        use futures_util::{SinkExt, StreamExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            // First binary message is the VLESS request header.
            let msg = ws.next().await.unwrap().unwrap();
            let header = msg.into_data();
            assert_eq!(header[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&header[1..17], &uuid_bytes);
            assert_eq!(header[18], CMD_TCP);

            // Accept with the 2-byte response header (version + addon_len=0),
            // then expect relayed payload.
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![0x00, 0x00].into(),
            ))
            .await
            .unwrap();
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(&msg.into_data()[..], b"ping");
        });

        let node = Node {
            name: "vless-ws".into(),
            protocol: NodeProtocol::VLess,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            password: Some(uuid_str.into()),
            transport: "ws".into(),
            ws_path: Some("/vless".into()),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = VLessHandler::new()
            .dial(&node, target, None, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
