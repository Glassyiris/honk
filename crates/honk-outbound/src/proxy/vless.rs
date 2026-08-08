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
//!    - `addon_len` / `addon`: Xray `encoding.Addons` protobuf carrying
//!      the flow (`node.flow`, e.g. `xtls-rprx-vision`); empty otherwise
//!    - `cmd`: 0x01 TCP, 0x02 UDP
//!    - `port`: big-endian u16
//!    - `atyp`: 0x01 IPv4, 0x02 Domain, 0x03 IPv6
//!    - `addr`: 4 bytes (IPv4) / 1+len bytes (Domain) / 16 bytes (IPv6)
//! 3. The response header (`ver(1) | addon_len(1) | [addon]`) is stripped
//!    lazily on the first read: real servers piggyback it on the target's
//!    first downstream bytes, so awaiting it in dial would deadlock with
//!    target-speaks-first protocols like TLS.
//! 4. The stream is then transparently connected to the target (with XTLS
//!    Vision unpadding on the read path when `flow = xtls-rprx-vision`).
//!
//! Reference: <https://xtls.github.io/en/development/protocols/vless.html>

use async_trait::async_trait;
use honk_config::node::Node;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{AsyncReadWrite, ProbeableOutbound, ProxyStream, TcpOutbound};

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
#[cfg(test)]
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

    /// Xray `encoding.Addons` protobuf (`string Flow = 1`) for the addon
    /// block: tag 0x0A (field 1, length-delimited) plus the length-prefixed
    /// flow name. The flow only selects server-side behavior (e.g.
    /// xtls-rprx-vision splice); the VLESS layer itself stays unencrypted
    /// either way.
    fn flow_addons(flow: Option<&str>) -> Vec<u8> {
        let Some(flow) = flow.filter(|f| !f.is_empty()) else {
            return Vec::new();
        };
        let mut addons = Vec::with_capacity(2 + flow.len());
        addons.push(0x0a);
        addons.push(flow.len() as u8);
        addons.extend_from_slice(flow.as_bytes());
        addons
    }

    /// Build the VLESS request header.
    ///
    /// Layout: `ver(1) | uuid(16) | addon_len(1) | addon(addon_len) | cmd(1) | port(2) | atyp(1) | addr(var)`
    fn build_request_header(
        uuid_bytes: &[u8; 16],
        cmd: u8,
        target: SocketAddr,
        target_domain: Option<&str>,
        flow: Option<&str>,
    ) -> Vec<u8> {
        let addons = Self::flow_addons(flow);
        let max_addr = if target_domain.is_some() {
            1 + 255
        } else if target.is_ipv6() {
            16
        } else {
            4
        };
        let mut buf = Vec::with_capacity(1 + 16 + 1 + addons.len() + 1 + 2 + 1 + max_addr);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(uuid_bytes);
        buf.push(addons.len() as u8);
        buf.extend_from_slice(&addons);
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
}

impl VLessHandler {
    /// Build the post-connect stream for a dial. Vision over raw TCP/TLS
    /// keeps the concrete stream type so the direct-copy read switch can
    /// reach the socket; every other case goes through the shared
    /// transport wrapping and erases it.
    async fn dial_stream(
        node: &Node,
        uuid: [u8; 16],
        tcp: TcpStream,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        if node.flow.as_deref() == Some("xtls-rprx-vision")
            && matches!(node.transport.as_str(), "" | "tcp")
        {
            let stream: Box<dyn AsyncReadWrite> =
                match super::transport::maybe_tls_wrap_concrete(node, tcp).await? {
                    super::transport::MaybeTls::Tls(tls) => {
                        Box::new(VisionStream::new(ResponseHeaderStrip::new(tls), uuid))
                    }
                    super::transport::MaybeTls::Plain(tcp) => {
                        Box::new(VisionStream::new(ResponseHeaderStrip::new(tcp), uuid))
                    }
                };
            return Ok(stream);
        }
        let stream = super::transport::wrap_transport(node, tcp).await?;
        Ok(Self::wrap_response_stream(node, uuid, stream))
    }

    /// Wrap the post-handshake stream: strip the response header lazily on
    /// first read, then unpad vision frames when the flow requires it.
    fn wrap_response_stream(
        node: &Node,
        uuid: [u8; 16],
        stream: Box<dyn AsyncReadWrite>,
    ) -> Box<dyn AsyncReadWrite> {
        let stripped = ResponseHeaderStrip::new(stream);
        if node.flow.as_deref() == Some("xtls-rprx-vision") {
            Box::new(VisionStream::new(stripped, uuid))
        } else {
            Box::new(stripped)
        }
    }
}

/// Lazy VLESS response-header stripper.
///
/// Real servers do not send the response header `[version][addon_len]
/// [addon]` on request acceptance — it is piggybacked on the first
/// downstream data from the target (sing-vmess serverConn.Write, Xray
/// alike). Reading it eagerly in dial() would deadlock whenever the target
/// speaks first (e.g. TLS), so the header is consumed on the first read,
/// exactly like the reference clients' `responseRead` flag. A non-zero
/// version surfaces as a read error rather than a dial error.
#[derive(Debug)]
struct ResponseHeaderStrip<S> {
    inner: S,
    state: StripState,
}

#[derive(Debug)]
enum StripState {
    /// Accumulating the 2-byte `[version][addon_len]` header.
    Header {
        filled: usize,
        buf: [u8; 2],
    },
    /// Discarding `remaining` addon bytes.
    Addon {
        remaining: usize,
    },
    Body,
}

impl<S: AsyncRead + Unpin> ResponseHeaderStrip<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            state: StripState::Header {
                filled: 0,
                buf: [0; 2],
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseHeaderStrip<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let Self { inner, state, .. } = &mut *self;
        loop {
            match state {
                StripState::Header { filled, buf: hdr } => {
                    while *filled < 2 {
                        let mut rb = tokio::io::ReadBuf::new(&mut hdr[*filled..]);
                        match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                            std::task::Poll::Pending => return std::task::Poll::Pending,
                            std::task::Poll::Ready(Err(e)) => {
                                return std::task::Poll::Ready(Err(e));
                            }
                            std::task::Poll::Ready(Ok(())) => {
                                if rb.filled().is_empty() {
                                    return std::task::Poll::Ready(Ok(())); // EOF before header
                                }
                                *filled += rb.filled().len();
                            }
                        }
                    }
                    let [version, addon_len] = *hdr;
                    if version != 0 {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("VLESS: server rejected request (code 0x{version:02x})"),
                        )));
                    }
                    *state = if addon_len > 0 {
                        StripState::Addon {
                            remaining: addon_len as usize,
                        }
                    } else {
                        StripState::Body
                    };
                }
                StripState::Addon { remaining } => {
                    let mut scratch = [0u8; 256];
                    let n = (*remaining).min(scratch.len());
                    let mut rb = tokio::io::ReadBuf::new(&mut scratch[..n]);
                    match std::pin::Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                return std::task::Poll::Ready(Ok(())); // EOF in addon
                            }
                            *remaining -= rb.filled().len();
                            if *remaining == 0 {
                                *state = StripState::Body;
                            }
                        }
                    }
                }
                StripState::Body => {
                    return std::pin::Pin::new(&mut *inner).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseHeaderStrip<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// XTLS Vision response-side unpadding (flow `xtls-rprx-vision`).
///
/// The vision server frames the response body as a 16-byte user UUID
/// followed by `[command u8][content_len u16][padding_len u16][content]
/// [padding]` blocks (Xray-core proxy/vless encoding semantics, mirrored
/// from sing-vmess vision.go whose frame layout the lab emits). `command`
/// 1 (End) stops framing but keeps the outer TLS session; `command` 2
/// (Direct) is the XTLS direct copy: the server abandons the outer TLS
/// session and exchanges plaintext inner-TLS records on the raw socket
/// (sing-vmess `directWrite`/`netConn`, Xray `WriterSwitchToDirectCopy`),
/// so the read side must switch to the raw TCP conn or the next record
/// dies in the abandoned TLS session (observed as BAD_DECRYPT). The write
/// side stays on the outer stream: both servers only switch their uplink
/// to raw when the client pads its upload with a Direct command, and a
/// raw (unpadded) upload keeps the server reading the TLS uplink.
///
/// The upload direction needs no padding: the server passes raw upload
/// through unless it begins with the user UUID itself, and padding is
/// traffic shaping, not framing.
#[derive(Debug)]
struct VisionStream<S> {
    inner: S,
    uuid: [u8; 16],
    /// Bytes pulled from `inner` but not yet parsed.
    inbox: Vec<u8>,
    /// Decoded payload ready for delivery.
    outbox: std::collections::VecDeque<u8>,
    state: VisionState,
    inner_eof: bool,
}

/// Reach the raw TCP socket under a (TLS) stream for the vision direct
/// copy read switch. Streams that cannot unwrap (WS/gRPC bridges) get the
/// default `None` and degrade to framed passthrough.
pub(crate) trait RawTcp {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        None
    }
}

impl RawTcp for TcpStream {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        Some(self)
    }
}

impl RawTcp for tokio_boring::SslStream<TcpStream> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        Some(self.get_mut())
    }
}

impl RawTcp for Box<dyn AsyncReadWrite> {}

impl<T: RawTcp + ?Sized> RawTcp for Box<T> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        (**self).raw_tcp()
    }
}

impl<S: RawTcp> RawTcp for ResponseHeaderStrip<S> {
    fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
        self.inner.raw_tcp()
    }
}

#[derive(Debug)]
enum VisionState {
    /// The server's first write is at least uuid(16) + header(5) bytes;
    /// fewer cannot prove framed vs raw, so keep buffering.
    Detect,
    Framed {
        content_remaining: usize,
        padding_remaining: usize,
        command: u8,
    },
    /// Outer-session passthrough (after End, or never framed).
    Raw,
    /// Raw-socket read after the Direct command (write side unaffected).
    DirectRaw,
    Failed,
}

const VISION_COMMAND_END: u8 = 1;
const VISION_COMMAND_DIRECT: u8 = 2;

impl<S> VisionStream<S> {
    fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            uuid,
            inbox: Vec::new(),
            outbox: std::collections::VecDeque::new(),
            state: VisionState::Detect,
            inner_eof: false,
        }
    }
}

impl<S: AsyncRead + RawTcp + Unpin> VisionStream<S> {
    fn parse(&mut self) {
        if matches!(self.state, VisionState::Detect) {
            if self.inbox.len() < 21 && !self.inner_eof {
                return;
            }
            self.state = if self.inbox.len() >= 21 && self.inbox[..16] == self.uuid {
                self.inbox.drain(..16);
                VisionState::Framed {
                    content_remaining: 0,
                    padding_remaining: 0,
                    command: 0,
                }
            } else {
                VisionState::Raw
            };
        }
        loop {
            match self.state {
                VisionState::Framed {
                    ref mut content_remaining,
                    ref mut padding_remaining,
                    command,
                } => {
                    if *content_remaining > 0 {
                        let n = (*content_remaining).min(self.inbox.len());
                        self.outbox.extend(self.inbox.drain(..n));
                        *content_remaining -= n;
                        // An incomplete frame waits for more input; a just
                        // completed frame must fall through to the command
                        // dispatch — End/Direct change the read channel and
                        // cannot wait for the next one.
                        if *content_remaining > 0 {
                            break;
                        }
                        continue;
                    }
                    if *padding_remaining > 0 {
                        let n = (*padding_remaining).min(self.inbox.len());
                        self.inbox.drain(..n);
                        *padding_remaining -= n;
                        if *padding_remaining > 0 {
                            break;
                        }
                        continue;
                    }
                    match command {
                        VISION_COMMAND_END => {
                            self.state = VisionState::Raw;
                        }
                        VISION_COMMAND_DIRECT => {
                            // Anything already pulled through the TLS layer
                            // is valid framed data (bare TCP) or nothing at
                            // all (TLS — plaintext would never decrypt), so
                            // it is safe to deliver before going raw.
                            self.outbox.extend(self.inbox.drain(..));
                            self.state = if self.inner.raw_tcp().is_some() {
                                VisionState::DirectRaw
                            } else {
                                VisionState::Raw
                            };
                        }
                        0 => {
                            if self.inbox.len() < 5 {
                                break;
                            }
                            let next = self.inbox[0];
                            let content =
                                u16::from_be_bytes([self.inbox[1], self.inbox[2]]) as usize;
                            let padding =
                                u16::from_be_bytes([self.inbox[3], self.inbox[4]]) as usize;
                            self.inbox.drain(..5);
                            self.state = VisionState::Framed {
                                content_remaining: content,
                                padding_remaining: padding,
                                command: next,
                            };
                        }
                        _ => {
                            self.state = VisionState::Failed;
                        }
                    }
                }
                VisionState::Raw => {
                    self.outbox.extend(self.inbox.drain(..));
                    break;
                }
                _ => break,
            }
        }
    }
}

impl<S: AsyncRead + RawTcp + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            if !self.outbox.is_empty() {
                let n = self.outbox.len().min(buf.remaining());
                let (front, _) = self.outbox.as_slices();
                buf.put_slice(&front[..n]);
                self.outbox.drain(..n);
                return std::task::Poll::Ready(Ok(()));
            }
            match self.state {
                VisionState::Raw => {
                    return std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
                }
                VisionState::DirectRaw => {
                    let tcp = self.inner.raw_tcp().expect("checked at transition");
                    return std::pin::Pin::new(tcp).poll_read(cx, buf);
                }
                VisionState::Failed => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "vision: unknown padding command",
                    )));
                }
                _ => {}
            }
            if self.inner_eof {
                return std::task::Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 8192];
            let mut chunk_buf = tokio::io::ReadBuf::new(&mut chunk);
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut chunk_buf) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(())) => {
                    if chunk_buf.filled().is_empty() {
                        self.inner_eof = true;
                    } else {
                        self.inbox.extend_from_slice(chunk_buf.filled());
                    }
                    self.parse();
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl TcpOutbound for VLessHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid_str = node.password.as_deref().unwrap_or("");
        let uuid_bytes = Self::parse_uuid(uuid_str)?;

        let header = Self::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            target,
            target_domain,
            node.flow.as_deref(),
        );
        let addr = format!("{}:{}", node.host(), node.port);
        let tcp = crate::util::connect_outbound(&addr, connect_timeout).await?;
        let mut stream = Self::dial_stream(node, uuid_bytes, tcp).await?;
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
        let uuid_str = node.password.as_deref().unwrap_or("");
        let uuid_bytes = Self::parse_uuid(uuid_str)?;

        let header = Self::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            target,
            target_domain,
            node.flow.as_deref(),
        );
        let mut stream = Self::dial_stream(node, uuid_bytes, tcp).await?;
        stream.write_all(&header).await?;

        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

#[async_trait]
impl ProbeableOutbound for VLessHandler {}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;
    use tokio::io::AsyncReadExt;

    /// AsyncRead yielding at most `chunk` bytes per poll, to force frame
    /// headers and UUID detection across read boundaries.
    struct ChunkedReader {
        data: std::collections::VecDeque<u8>,
        chunk: usize,
    }

    impl tokio::io::AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = self.chunk.min(buf.remaining()).min(self.data.len());
            let (front, _) = self.data.as_slices();
            buf.put_slice(&front[..n]);
            self.data.drain(..n);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for ChunkedReader {}

    fn vision_frame(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
        let mut frame = vec![
            command,
            (content.len() >> 8) as u8,
            content.len() as u8,
            (padding >> 8) as u8,
            padding as u8,
        ];
        frame.extend_from_slice(content);
        frame.extend(std::iter::repeat_n(0u8, padding));
        frame
    }

    async fn unpad_all(uuid: [u8; 16], data: &[u8], chunk: usize) -> Vec<u8> {
        let reader = ChunkedReader {
            data: data.iter().copied().collect(),
            chunk,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn vision_unpad_frames_then_raw_tail() {
        let uuid = [7u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"hello", 3));
        data.extend(vision_frame(0, b"world", 0));
        data.extend(vision_frame(VISION_COMMAND_END, b"!", 2));
        data.extend_from_slice(b"RAW-TAIL");
        for chunk in [1usize, 3, 7, 1024] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                b"helloworld!RAW-TAIL",
                "chunk={chunk}"
            );
        }
    }

    #[tokio::test]
    async fn vision_unpad_direct_command_switches_to_raw() {
        let uuid = [9u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(VISION_COMMAND_DIRECT, b"abc", 1));
        data.extend_from_slice(b"rest-is-raw");
        for chunk in [2usize, 1024] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                b"abcrest-is-raw",
                "chunk={chunk}"
            );
        }
    }

    /// After a Direct command the server abandons the outer TLS session
    /// and writes plaintext on the raw socket: a loopback TLS server sends
    /// vision frames over TLS, then switches to raw TCP writes; the client
    /// must deliver both phases (write side stays on TLS).
    #[tokio::test]
    async fn vision_direct_raw_read_switch_over_tls() {
        use boring::pkey::PKey;
        use boring::ssl::{SslAcceptor, SslMethod};
        use boring::x509::X509;

        let uuid = [5u8; 16];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor
                .set_certificate(&X509::from_pem(cert_pem.as_bytes()).unwrap())
                .unwrap();
            acceptor
                .set_private_key(&PKey::private_key_from_pem(key_pem.as_bytes()).unwrap())
                .unwrap();
            let acceptor = acceptor.build();
            let (stream, _) = listener.accept().unwrap();
            let mut tls = acceptor.accept(stream).unwrap();
            let mut frame = uuid.to_vec();
            frame.extend(vision_frame(0, b"hel", 2));
            frame.extend(vision_frame(VISION_COMMAND_DIRECT, b"lo", 0));
            tls.write_all(&frame).unwrap();
            tls.flush().unwrap();
            // Direct: abandon TLS, write plaintext on the raw transport.
            let mut raw = tls.into_inner();
            raw.write_all(b" world").unwrap();
            raw.shutdown(std::net::Shutdown::Both).ok();
        });

        let node = Node {
            skip_cert_verify: true,
            ..Default::default()
        };
        let connector = crate::tls::build_connector(&node).unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut tls = connector.connect("localhost", tcp).await.unwrap();
        assert!(
            RawTcp::raw_tcp(&mut tls).is_some(),
            "TLS stream must unwrap"
        );
        let mut stream = VisionStream::new(tls, uuid);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
        server.join().unwrap();
    }

    #[tokio::test]
    async fn vision_passthrough_without_uuid_prefix() {
        let uuid = [7u8; 16];
        let data = b"plain stream, not vision framed".to_vec();
        for chunk in [4usize, 1024] {
            assert_eq!(unpad_all(uuid, &data, chunk).await, data, "chunk={chunk}");
        }
    }

    #[tokio::test]
    async fn vision_detect_short_stream_below_probe_size() {
        // Fewer than uuid(16)+header(5) bytes can never prove framing;
        // even a UUID-looking prefix passes through raw at EOF.
        let uuid = [7u8; 16];
        let data = uuid[..10].to_vec();
        assert_eq!(unpad_all(uuid, &data, 2).await, data);
    }

    #[tokio::test]
    async fn vision_unpad_lab_frame_sequence() {
        // Mirrored from a live sing-box vision downlink trace: big content
        // frames with long padding, then a Direct switch to raw.
        let uuid = [7u8; 16];
        let mk = |command: u8, content: usize, padding: usize, fill: u8| {
            let mut frame = vec![
                command,
                (content >> 8) as u8,
                content as u8,
                (padding >> 8) as u8,
                padding as u8,
            ];
            frame.extend(std::iter::repeat_n(fill, content));
            frame.extend(std::iter::repeat_n(0u8, padding));
            frame
        };
        let mut data = uuid.to_vec();
        data.extend(mk(0, 146, 135, b'a'));
        data.extend(mk(0, 5219, 180, b'b'));
        data.extend(mk(VISION_COMMAND_DIRECT, 647, 262, b'c'));
        data.extend_from_slice(b"RAW-TAIL");

        let mut expected = Vec::new();
        expected.extend(std::iter::repeat_n(b'a', 146));
        expected.extend(std::iter::repeat_n(b'b', 5219));
        expected.extend(std::iter::repeat_n(b'c', 647));
        expected.extend_from_slice(b"RAW-TAIL");

        for chunk in [7usize, 1400, 8192, 65536] {
            assert_eq!(
                unpad_all(uuid, &data, chunk).await,
                expected,
                "chunk={chunk}"
            );
        }
    }

    #[tokio::test]
    async fn vision_unknown_command_fails() {
        let uuid = [7u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0x42, b"x", 0));
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 1024,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn response_strip_header_and_addon() {
        let mut data = vec![0x00, 0x03, 0xaa, 0xbb, 0xcc];
        data.extend_from_slice(b"payload-bytes");
        for chunk in [1usize, 2, 5, 1024] {
            let reader = ChunkedReader {
                data: data.iter().copied().collect(),
                chunk,
            };
            let mut stream = ResponseHeaderStrip::new(reader);
            let mut out = Vec::new();
            stream.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"payload-bytes", "chunk={chunk}");
        }
    }

    #[tokio::test]
    async fn response_strip_rejects_nonzero_version() {
        let data = vec![0x01, 0x00, 0xff];
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 1024,
        };
        let mut stream = ResponseHeaderStrip::new(reader);
        let mut out = Vec::new();
        let err = stream.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Real servers piggyback the response header on the target's first
    /// downstream bytes: dial must return without it, and the header must
    /// not leak into the relayed stream.
    #[tokio::test]
    async fn test_vless_dial_lazy_response_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 19];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[18], CMD_TCP);
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            // Response header only after the client spoke first.
            stream.write_all(b"\x00\x00pong").await.unwrap();
        });

        let node = Node {
            name: "vless-lazy".into(),
            protocol: NodeProtocol::VLess,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            password: Some(uuid_str.into()),
            ..Default::default()
        };
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let mut ps = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            VLessHandler::new().dial(&node, target, None, std::time::Duration::from_secs(3)),
        )
        .await
        .expect("dial must not wait for the response header")
        .unwrap();
        ps.stream.write_all(b"ping").await.unwrap();
        ps.stream.flush().await.unwrap();
        let mut out = [0u8; 4];
        ps.stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");

        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn test_vless_header_ipv4() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, None, None);

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

        let header =
            VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, Some(domain), None);

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

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_TCP, target, None, None);

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

        let header = VLessHandler::build_request_header(&uuid_bytes, CMD_UDP, target, None, None);

        assert_eq!(header[18], CMD_UDP);
        assert_eq!(&header[19..21], &[0x27, 0x0f]); // port 9999
    }

    #[test]
    fn test_vless_header_vision_flow() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let header = VLessHandler::build_request_header(
            &uuid_bytes,
            CMD_TCP,
            target,
            None,
            Some("xtls-rprx-vision"),
        );

        // ver(1) + uuid(16) + addon_len(1) + addon(18) + cmd(1) + port(2) + atyp(1) + addr(4)
        assert_eq!(header.len(), 1 + 16 + 1 + 18 + 1 + 2 + 1 + 4);
        assert_eq!(header[0], VLESS_VERSION);
        assert_eq!(&header[1..17], &uuid_bytes);
        assert_eq!(header[17], 18); // addon_len: 0x0A + len + 16-byte flow
        // Xray encoding.Addons protobuf: field 1 (Flow) = tag 0x0A, length 0x10
        assert_eq!(&header[18..36], b"\x0a\x10xtls-rprx-vision");
        assert_eq!(header[36], CMD_TCP);
        assert_eq!(&header[37..39], &[0x01, 0xbb]); // port 443
        assert_eq!(header[39], ATYP_IPV4);
        assert_eq!(&header[40..44], &[93, 184, 216, 34]);
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

            // First binary message carries the VLESS request header,
            // possibly coalesced with the first payload bytes (nothing
            // forces a read between the two writes anymore).
            let msg = ws.next().await.unwrap().unwrap();
            let data = msg.into_data();
            assert_eq!(data[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&data[1..17], &uuid_bytes);
            assert_eq!(data[18], CMD_TCP);

            // Accept with the 2-byte response header (version + addon_len=0),
            // then expect relayed payload.
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                vec![0x00, 0x00].into(),
            ))
            .await
            .unwrap();
            const HEADER_LEN: usize = 1 + 16 + 1 + 1 + 2 + 1 + 4;
            if data.len() > HEADER_LEN {
                assert_eq!(&data[HEADER_LEN..], b"ping");
            } else {
                let msg = ws.next().await.unwrap().unwrap();
                assert_eq!(&msg.into_data()[..], b"ping");
            }
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

    /// Bare VLESS over raw TCP (`security=none`): `node.tls` false and an
    /// empty transport must not be TLS-wrapped. The lazy response stripper
    /// still wraps the stream (bare servers piggyback the response header
    /// too), so it no longer downcasts to a plain TcpStream.
    #[tokio::test]
    async fn test_vless_dial_bare_tcp() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 19];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&head[1..17], &uuid_bytes);
            assert_eq!(head[17], 0x00); // addon_len
            assert_eq!(head[18], CMD_TCP);
            // Skip port(2) + atyp(1) + ipv4(4), accept, expect payload.
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        });

        let node = Node {
            name: "vless-bare".into(),
            protocol: NodeProtocol::VLess,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            password: Some(uuid_str.into()),
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

    /// xtls-rprx-vision over raw TCP: the mock server asserts the full
    /// request header including the protobuf flow addon.
    #[tokio::test]
    async fn test_vless_dial_vision_flow() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // ver(1) + uuid(16) + addon_len(1) + addon(18) + cmd(1)
            let mut head = [0u8; 37];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0], VLESS_VERSION);
            let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
            assert_eq!(&head[1..17], &uuid_bytes);
            assert_eq!(head[17], 18);
            assert_eq!(&head[18..36], b"\x0a\x10xtls-rprx-vision");
            assert_eq!(head[36], CMD_TCP);
            let mut addr = [0u8; 7];
            stream.read_exact(&mut addr).await.unwrap();
            stream.write_all(&[0x00, 0x00]).await.unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
        });

        let node = Node {
            name: "vless-vision".into(),
            protocol: NodeProtocol::VLess,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            password: Some(uuid_str.into()),
            flow: Some("xtls-rprx-vision".into()),
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
