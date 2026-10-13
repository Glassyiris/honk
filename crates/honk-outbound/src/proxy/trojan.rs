//! Trojan proxy handler.
//! https://github.com/trojan-gfw/trojan

use async_trait::async_trait;
use honk_config::node::Node;
use sha2::{Digest, Sha224};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::addr;
use super::{
    AsyncReadWrite, MultiTargetTransport, PacketOutbound, PacketTransport, PreparedUdpTransport,
    ProbeableOutbound, ProxyStream, SharedSourceOutbound, TcpOutbound, WarmRequirement,
    WarmableOutbound,
};

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
    ) -> std::io::Result<Vec<u8>> {
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_TCP);
        header.extend_from_slice(&addr::encode_address(target, target_domain)?);
        header.extend_from_slice(CRLF);
        Ok(header)
    }

    async fn dial_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let header = Self::build_request_header(password, target, target_domain)?;
        let (mut stream, preparation) =
            Self::prepare_transport(node, runtime, tcp, connect_timeout).await?;
        preparation.commit()?;
        super::transport::write_request(&mut stream, &header).await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::prepare_udp_stream(node, runtime, target, target_domain, connect_timeout)
            .await?
            .commit()
            .await
    }

    async fn prepare_transport(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        tcp: Option<TcpStream>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Box<dyn AsyncReadWrite>,
        super::transport::TransportPreparation,
    )> {
        match runtime {
            Some(runtime) => {
                super::transport::prepare_transport_runtime(runtime, tcp, timeout).await
            }
            None => Ok((
                super::transport::wrap_transport(node, tcp, timeout).await?,
                super::transport::TransportPreparation::none(),
            )),
        }
    }

    async fn prepare_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let (transport, preparation) =
            Self::open_udp_stream(node, runtime, target, domain, timeout).await?;
        Ok(Self::commit_udp_stream(
            transport as Arc<dyn PacketTransport>,
            preparation,
        ))
    }

    /// One association for a whole client source scope: `target` and
    /// `domain` only name the UDP-associate request; every frame carries its
    /// own destination.
    pub(crate) async fn prepare_udp_source(
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let (transport, preparation) =
            Self::open_udp_stream(&runtime.node, Some(runtime), target, domain, timeout).await?;
        Ok(Self::commit_udp_stream(
            transport as Arc<dyn MultiTargetTransport>,
            preparation,
        ))
    }

    async fn open_udp_stream(
        node: &Node,
        runtime: Option<&Arc<crate::runtime::NodeRuntime>>,
        target: SocketAddr,
        domain: Option<&str>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Arc<TrojanUdpTransport>,
        super::transport::TransportPreparation,
    )> {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!(
                "Trojan UDP: node network {:?} does not include \"udp\"",
                node.network()
            );
        }
        let (control, preparation) = Self::prepare_transport(node, runtime, None, timeout).await?;
        let transport = Self::finish_udp_stream(node, target, domain, control).await?;
        Ok((transport, preparation))
    }

    fn commit_udp_stream<T: ?Sized + Send + Sync + 'static>(
        transport: Arc<T>,
        preparation: super::transport::TransportPreparation,
    ) -> PreparedUdpTransport<T> {
        PreparedUdpTransport::new(async move {
            preparation.commit()?;
            Ok(transport)
        })
    }

    async fn finish_udp_stream(
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        mut control: Box<dyn AsyncReadWrite>,
    ) -> anyhow::Result<Arc<TrojanUdpTransport>> {
        let password = node.trojan().unwrap().password.as_deref().unwrap_or("");
        let addr_header = addr::encode_address(target, target_domain)?;
        let mut header = Vec::with_capacity(56 + 2 + 1 + 19 + 2);
        header.extend_from_slice(hex_sha224(password).as_bytes());
        header.extend_from_slice(CRLF);
        header.push(CMD_UDP);
        header.extend_from_slice(&addr_header);
        header.extend_from_slice(CRLF);
        super::transport::write_request(&mut control, &header).await?;

        let (rd, wr) = tokio::io::split(control);
        Ok(Arc::new(TrojanUdpTransport {
            writer: tokio::sync::Mutex::new(wr),
            write_interrupted: std::sync::atomic::AtomicBool::new(false),
            reader: tokio::sync::Mutex::new(rd),
            addr_header,
            domain: target_domain.map(Box::from),
            relay_addr: target,
        }))
    }
}

#[async_trait]
impl TcpOutbound for TrojanHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_stream(node, None, target, target_domain, None, connect_timeout).await
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_stream(
            node,
            None,
            target,
            target_domain,
            Some(tcp),
            connect_timeout,
        )
        .await
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        Self::dial_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            None,
            connect_timeout,
        )
        .await
    }
}

#[async_trait]
impl SharedSourceOutbound for TrojanHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        let _ = speculative;
        Self::prepare_udp_source(&runtime, target, target_domain, connect_timeout).await
    }
}

#[async_trait]
impl PacketOutbound for TrojanHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(node, None, target, target_domain, connect_timeout).await
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        Self::dial_udp_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<super::PreparedUdpTransport> {
        Self::prepare_udp_stream(
            &runtime.node,
            Some(&runtime),
            target,
            target_domain,
            connect_timeout,
        )
        .await
    }
}

#[async_trait]
impl WarmableOutbound for TrojanHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        super::transport::xhttp::XhttpRuntime::warm(&runtime, connect_timeout).await
    }
}

#[async_trait]
impl ProbeableOutbound for TrojanHandler {}

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
    use honk_config::types::NodeProtocol;

    #[test]
    fn test_trojan_request_header_encoding() {
        let password = "password123";
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header = TrojanHandler::build_request_header(password, target, None).unwrap();

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

        let header = TrojanHandler::build_request_header(password, target, Some(domain)).unwrap();

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
        let pool_ready_streams =
            crate::descriptor::descriptor(NodeProtocol::Trojan).pool_ready_streams;
        let mut node = Node {
            name: "t".into(),
            address: "127.0.0.1".into(),
            port: 443,
            outbound: honk_config::node::OutboundConfig::Trojan(Default::default()),
            ..Default::default()
        };
        node.transport_mut().unwrap().transport.clear();
        assert!(pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "tcp".into();
        assert!(pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "ws".into();
        assert!(!pool_ready_streams(&node));
        node.transport_mut().unwrap().transport = "grpc".into();
        assert!(!pool_ready_streams(&node));
    }

    /// A pooled bare server socket must complete and flush the configured
    /// gRPC transport before returning the target-bound Trojan stream.
    #[tokio::test]
    async fn bare_tcp_grpc_flushes_trojan_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let password = "pooled-secret";
        let expected = TrojanHandler::build_request_header(password, target, None).unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(tcp).await.unwrap();
            let (request, _respond) = connection
                .accept()
                .await
                .expect("gRPC request must arrive")
                .expect("gRPC headers must be valid");
            assert_eq!(request.uri().path(), "/pooled/Tun");
            let mut body = request.into_body();
            let driver = tokio::spawn(async move {
                while let Some(request) = connection.accept().await {
                    request.expect("subsequent gRPC request must be valid");
                }
            });

            let mut received = Vec::new();
            loop {
                let data = tokio::time::timeout(std::time::Duration::from_secs(5), body.data())
                    .await
                    .expect("flushed Trojan header must arrive")
                    .expect("gRPC request body must remain open")
                    .expect("gRPC DATA must be valid");
                received.extend_from_slice(&data);
                if received.len() >= 5 {
                    let message_len =
                        u32::from_be_bytes(received[1..5].try_into().unwrap()) as usize;
                    if received.len() >= 5 + message_len {
                        break;
                    }
                }
            }
            driver.abort();

            assert_eq!(received[0], 0, "gRPC message must be uncompressed");
            assert_eq!(
                u32::from_be_bytes(received[1..5].try_into().unwrap()) as usize,
                expected.len() + 2
            );
            assert_eq!(received[5], 0x0a, "protobuf payload must be bytes field 1");
            assert_eq!(received[6] as usize, expected.len());
            assert_eq!(&received[7..], expected.as_slice());
        });

        let mut node = Node {
            name: "trojan-grpc".into(),
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                password: Some(password.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let transport = node.transport_mut().unwrap();
        transport.transport = "grpc".into();
        transport.grpc_service = Some("pooled".into());

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let _stream = TrojanHandler::new()
            .dial_with_tcp(&node, target, None, tcp, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        server.await.unwrap();
    }
}

/// Framed UDP-associate transport over the Trojan control stream: packets
/// are framed directly onto the associate stream
/// (`addr | u16 len | CRLF | payload`), each frame naming its own peer.
struct TrojanUdpTransport {
    writer: tokio::sync::Mutex<WriteHalf<Box<dyn AsyncReadWrite>>>,
    /// Set while a frame is being written, cleared once it is flushed: a write
    /// cancelled halfway leaves it set, so no sibling destination can append a
    /// frame to a torn one.
    write_interrupted: std::sync::atomic::AtomicBool,
    reader: tokio::sync::Mutex<ReadHalf<Box<dyn AsyncReadWrite>>>,
    /// Encoded `relay_addr`/`domain`: the destination of `send_packet`.
    addr_header: Vec<u8>,
    domain: Option<Box<str>>,
    relay_addr: SocketAddr,
}

impl std::fmt::Debug for TrojanUdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanUdpTransport")
            .field("relay_addr", &self.relay_addr)
            .finish()
    }
}

impl TrojanUdpTransport {
    async fn send_frame(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "trojan udp frame too large",
            ));
        }
        // The endpoint driver drops this packet on `WouldBlock` without
        // treating writer contention as a dead tunnel.
        let Ok(mut writer) = self.writer.try_lock() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "trojan UDP writer is busy",
            ));
        };
        if self
            .write_interrupted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "trojan UDP frame write was interrupted",
            ));
        }
        let mut frame;
        if target == self.relay_addr && domain == self.domain.as_deref() {
            frame = Vec::with_capacity(self.addr_header.len() + 4 + data.len());
            frame.extend_from_slice(&self.addr_header);
        } else {
            let address = addr::SocksAddr::new(target, domain)?;
            frame = Vec::with_capacity(address.encoded_len() + 4 + data.len());
            address.encode(&mut frame);
        }
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(CRLF);
        frame.extend_from_slice(data);
        // From here a deadline can leave a partial frame on the shared
        // stream; the next sender must fail instead of extending it.
        if let Some(admitted) = admitted {
            admitted.store(true, std::sync::atomic::Ordering::Release);
        }
        self.write_interrupted
            .store(true, std::sync::atomic::Ordering::Release);
        writer.write_all(&frame).await?;
        writer.flush().await?;
        self.write_interrupted
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}

#[async_trait]
impl PacketTransport for TrojanUdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_frame(self.relay_addr, self.domain.as_deref(), data, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut rd = self.reader.lock().await;
        loop {
            // An unknown ATYP has no derivable length, so the parser's error
            // stays terminal for the whole stream.
            let peer = match addr::SocksAddr::read_from_stream(&mut *rd).await? {
                addr::SocksAddr::V4(peer) => Some(SocketAddr::V4(peer)),
                addr::SocksAddr::V6(peer) => {
                    Some(SocketAddr::new(peer.ip().to_canonical(), peer.port()))
                }
                addr::SocksAddr::Domain(domain, port)
                    if port == self.relay_addr.port()
                        && self
                            .domain
                            .as_deref()
                            .is_some_and(|expected| domain.eq_ignore_ascii_case(expected)) =>
                {
                    Some(self.relay_addr)
                }
                // Never resolve an unrecognised name or invent its address.
                addr::SocksAddr::Domain(..) => None,
            };
            let mut head = [0u8; 4];
            rd.read_exact(&mut head).await?;
            let len = u16::from_be_bytes([head[0], head[1]]) as usize;
            if let Some(peer) = peer {
                if len > buf.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "trojan udp frame exceeds buffer",
                    ));
                }
                rd.read_exact(&mut buf[..len]).await?;
                return Ok((len, peer));
            }
            // The dropped frame must be consumed so the next one decodes.
            let mut left = len;
            while left > 0 {
                let chunk = left.min(buf.len());
                if chunk == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "trojan udp frame exceeds buffer",
                    ));
                }
                rd.read_exact(&mut buf[..chunk]).await?;
                left -= chunk;
            }
        }
    }
}

#[async_trait]
impl MultiTargetTransport for TrojanUdpTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        _confirmed: bool,
        admitted: Option<&std::sync::atomic::AtomicBool>,
    ) -> std::io::Result<()> {
        let domain = addr::dialed_name(self.domain.as_deref(), domain);
        self.send_frame(target, domain, data, admitted).await
    }
}

#[cfg(test)]
mod udp_transport_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Independent peer-side codec: addresses are spelled out byte by byte so
    /// the production encoder and decoder are not what verifies each other.
    fn wire_addr(peer: SocketAddr) -> Vec<u8> {
        let mut out = Vec::new();
        match peer {
            SocketAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.ip().octets());
            }
        }
        out.extend_from_slice(&peer.port().to_be_bytes());
        out
    }

    fn wire_domain(domain: &str, port: u16) -> Vec<u8> {
        let mut out = vec![0x03, domain.len() as u8];
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    fn frame(address: Vec<u8>, payload: &[u8]) -> Vec<u8> {
        let mut out = address;
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(payload);
        out
    }

    /// Read one frame as the server would: SOCKS5 address, length, CRLF, payload.
    async fn read_frame<R: AsyncReadExt + Unpin>(server: &mut R) -> (SocketAddr, Vec<u8>) {
        let mut atyp = [0u8; 1];
        server.read_exact(&mut atyp).await.unwrap();
        let peer = match atyp[0] {
            0x01 => {
                let mut ip = [0u8; 4];
                server.read_exact(&mut ip).await.unwrap();
                let mut port = [0u8; 2];
                server.read_exact(&mut port).await.unwrap();
                SocketAddr::new(Ipv4Addr::from(ip).into(), u16::from_be_bytes(port))
            }
            0x04 => {
                let mut ip = [0u8; 16];
                server.read_exact(&mut ip).await.unwrap();
                let mut port = [0u8; 2];
                server.read_exact(&mut port).await.unwrap();
                SocketAddr::new(Ipv6Addr::from(ip).into(), u16::from_be_bytes(port))
            }
            other => panic!("unexpected ATYP {other:#x}"),
        };
        let mut head = [0u8; 4];
        server.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[2..], b"\r\n");
        let mut payload = vec![0u8; u16::from_be_bytes([head[0], head[1]]) as usize];
        server.read_exact(&mut payload).await.unwrap();
        (peer, payload)
    }

    fn transport_over<S: AsyncReadWrite + 'static>(
        stream: S,
        target: SocketAddr,
        domain: Option<&str>,
    ) -> TrojanUdpTransport {
        let (rd, wr) = tokio::io::split(Box::new(stream) as Box<dyn AsyncReadWrite>);
        TrojanUdpTransport {
            writer: tokio::sync::Mutex::new(wr),
            write_interrupted: AtomicBool::new(false),
            reader: tokio::sync::Mutex::new(rd),
            addr_header: addr::encode_address(target, domain).unwrap(),
            domain: domain.map(Box::from),
            relay_addr: target,
        }
    }

    /// send_packet frames `addr|len|CRLF|payload`; recv_packet unframes the
    /// same shape back. Round-tripped over a duplex pair.
    #[tokio::test]
    async fn trojan_udp_transport_frame_roundtrip() {
        let (client, mut server) = tokio::io::duplex(8192);
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let transport = transport_over(client, target, None);

        transport.send_packet(b"hello-trojan-udp").await.unwrap();
        assert_eq!(
            read_frame(&mut server).await,
            (target, b"hello-trojan-udp".to_vec())
        );

        server
            .write_all(&frame(wire_addr(target), b"pong!"))
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong!");
        assert_eq!(src, target);
    }

    /// Two destinations share one stream; a never-contacted peer may answer
    /// first; every reply keeps its own real source.
    #[tokio::test]
    async fn shared_stream_carries_each_destination_and_returns_real_sources() {
        let (client, mut server) = tokio::io::duplex(1 << 17);
        let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let c: SocketAddr = "198.51.100.9:3478".parse().unwrap();
        let mapped_c: SocketAddr = "[::ffff:198.51.100.9]:3478".parse().unwrap();
        let transport = transport_over(client, a, None);

        transport
            .send_to(a, None, b"to-a", false, None)
            .await
            .unwrap();
        transport
            .send_to(b, None, b"to-b", true, None)
            .await
            .unwrap();
        transport.send_to(b, None, b"", false, None).await.unwrap();
        let max = vec![0x5a; u16::MAX as usize];
        transport.send_to(a, None, &max, false, None).await.unwrap();
        assert_eq!(read_frame(&mut server).await, (a, b"to-a".to_vec()));
        assert_eq!(read_frame(&mut server).await, (b, b"to-b".to_vec()));
        assert_eq!(read_frame(&mut server).await, (b, Vec::new()));
        assert_eq!(read_frame(&mut server).await, (a, max));
        let too_big = vec![0u8; u16::MAX as usize + 1];
        let error = transport
            .send_to(a, None, &too_big, false, None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        let mut buf = vec![0u8; 65536];
        for (source, wire, payload) in [
            (c, wire_addr(c), &b"unsolicited"[..]),
            (c, wire_addr(mapped_c), &b"mapped"[..]),
            (a, wire_addr(a), &b"from-a"[..]),
            (b, wire_addr(b), &b""[..]),
        ] {
            server.write_all(&frame(wire, payload)).await.unwrap();
            let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
            assert_eq!((peer, &buf[..n]), (source, payload));
        }
    }

    /// Only the dialed name goes on the wire: a real server pins its outbound
    /// form by the first destination, so any other name is sent numerically.
    #[tokio::test]
    async fn per_packet_domain_is_only_the_dialed_one() {
        let (client, mut server) = tokio::io::duplex(8192);
        let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let transport = transport_over(client, a, Some("example.com"));

        transport
            .send_to(a, Some("example.com"), b"dialed", false, None)
            .await
            .unwrap();
        let expected = frame(wire_domain("example.com", 53), b"dialed");
        let mut wire = vec![0u8; expected.len()];
        server.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire, expected);

        transport
            .send_to(a, Some("other.example"), b"other", false, None)
            .await
            .unwrap();
        assert_eq!(read_frame(&mut server).await, (a, b"other".to_vec()));
        transport
            .send_to(a, None, b"numeric", false, None)
            .await
            .unwrap();
        assert_eq!(read_frame(&mut server).await, (a, b"numeric".to_vec()));
    }

    /// A frame named by a domain other than the captured one is consumed whole
    /// (even when its payload exceeds the receive buffer) and the stream stays
    /// aligned for the next frame.
    #[tokio::test]
    async fn unrecognised_domain_frames_are_consumed_and_the_next_decodes() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let transport = transport_over(client, target, Some("Example.com"));
        let numeric: SocketAddr = "203.0.113.5:9".parse().unwrap();

        let big = vec![0xee; 100];
        let mut wire = frame(wire_domain("other.example", 443), &big);
        wire.extend(frame(wire_domain("example.com", 444), b"wrong-port"));
        wire.extend(frame(wire_domain("EXAMPLE.COM", 443), b"mine"));
        wire.extend(frame(wire_domain("other.example", 443), b""));
        wire.extend(frame(wire_addr(numeric), b"next"));
        server.write_all(&wire).await.unwrap();

        // An 8-byte buffer forces the discard path to chunk the 100 bytes.
        let mut buf = [0u8; 8];
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (target, &b"mine"[..]));
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (numeric, &b"next"[..]));
    }

    /// Without a captured domain no domain-named frame can be projected.
    #[tokio::test]
    async fn domain_frame_without_captured_domain_is_dropped() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let transport = transport_over(client, target, None);
        let mut wire = frame(wire_domain("example.com", 443), b"dropped");
        wire.extend(frame(wire_addr(target), b"kept"));
        server.write_all(&wire).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (target, &b"kept"[..]));
    }

    /// An unknown ATYP has no derivable length: the stream cannot be realigned.
    #[tokio::test]
    async fn unknown_atyp_is_terminal() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let transport = transport_over(client, target, None);
        server
            .write_all(&frame(vec![0x09, 1, 2, 3, 4, 0, 53], b"x"))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let error = transport.recv_packet(&mut buf).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Writes that stall mid-frame are never packet-local: the datagram is
    /// admitted before the first byte is written and a deadline is not
    /// congestion.
    #[tokio::test]
    async fn stalled_partial_write_is_admitted_and_not_congestion() {
        let (client, server) = tokio::io::duplex(16);
        let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let transport = transport_over(client, a, None);
        assert!(!transport.send_timeout_is_congestion());

        let admitted = AtomicBool::new(false);
        let payload = vec![7u8; 4096];
        let stalled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            transport.send_to(a, None, &payload, false, Some(&admitted)),
        )
        .await;
        assert!(stalled.is_err(), "the unread stream must stall the write");
        assert!(admitted.load(Ordering::Acquire));
        drop(server);
    }

    /// A concurrent sender is refused instead of interleaving: the frame
    /// boundary belongs to whoever holds the writer lock.
    #[tokio::test]
    async fn concurrent_sender_is_refused_while_a_frame_is_mid_write() {
        let (client, server) = tokio::io::duplex(16);
        let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let transport = transport_over(client, a, None);

        let payload = vec![7u8; 4096];
        let mut first = std::pin::pin!(transport.send_to(a, None, &payload, false, None));
        assert!(
            futures_util::poll!(first.as_mut()).is_pending(),
            "writer must be pending on the full stream"
        );
        let busy_admitted = AtomicBool::new(false);
        let error = transport
            .send_to(b, None, b"b", false, Some(&busy_admitted))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(!busy_admitted.load(Ordering::Acquire));
        drop(server);
    }

    /// A write cancelled halfway leaves a torn frame on the shared stream;
    /// a sibling destination must fail rather than append to it, even when
    /// the peer is draining again.
    #[tokio::test]
    async fn cancelled_partial_write_poisons_the_shared_stream() {
        let (client, mut server) = tokio::io::duplex(16);
        let a: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let b: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let transport = transport_over(client, a, None);
        let payload = vec![7u8; 4096];
        let stalled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            transport.send_to(a, None, &payload, false, None),
        )
        .await;
        assert!(stalled.is_err(), "the unread stream must stall the write");
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut server, &mut tokio::io::sink()).await;
        });
        let error = transport
            .send_to(b, None, b"b", false, None)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// Dropping the transport closes the logical stream.
    #[tokio::test]
    async fn drop_releases_the_stream() {
        let (client, mut server) = tokio::io::duplex(4096);
        let target: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let transport = Arc::new(transport_over(client, target, None));
        drop(transport);
        let mut byte = [0u8; 1];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }

    /// Real loopback TCP through the production preparation: the associate
    /// request names the first destination, later frames name their own, and
    /// a third peer can answer first.
    #[tokio::test]
    async fn plain_tcp_association_serves_every_destination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let first: SocketAddr = "93.184.216.34:53".parse().unwrap();
        let second: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let stranger: SocketAddr = "198.51.100.9:3478".parse().unwrap();
        let password = "udp-secret";
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 56 + 2 + 1 + 7 + 2];
            tcp.read_exact(&mut request).await.unwrap();
            let mut expected = hex_sha224(password).into_bytes();
            expected.extend_from_slice(b"\r\n\x03");
            expected.extend(wire_addr(first));
            expected.extend_from_slice(b"\r\n");
            assert_eq!(request, expected);
            assert_eq!(read_frame(&mut tcp).await, (first, b"one".to_vec()));
            assert_eq!(read_frame(&mut tcp).await, (second, b"two".to_vec()));
            let mut replies = frame(wire_addr(stranger), b"hi");
            replies.extend(frame(wire_addr(second), b"re-two"));
            tcp.write_all(&replies).await.unwrap();
            let mut eof = [0u8; 1];
            assert_eq!(tcp.read(&mut eof).await.unwrap(), 0);
        });

        let mut node = Node {
            name: "trojan-udp".into(),
            address: server_addr.ip().to_string(),
            host: server_addr.ip().to_string(),
            port: server_addr.port(),
            outbound: honk_config::node::OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                password: Some(password.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        node.tls_mut().unwrap().enabled = false;
        let (transport, preparation) = TrojanHandler::open_udp_stream(
            &node,
            None,
            first,
            None,
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        preparation.commit().unwrap();
        let transport: Arc<dyn MultiTargetTransport> = transport;
        transport
            .send_to(first, None, b"one", true, None)
            .await
            .unwrap();
        transport
            .send_to(second, None, b"two", false, None)
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (stranger, &b"hi"[..]));
        let (n, peer) = transport.recv_packet(&mut buf).await.unwrap();
        assert_eq!((peer, &buf[..n]), (second, &b"re-two"[..]));
        drop(transport);
        server.await.unwrap();
    }
}
