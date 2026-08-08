//! VLESS proxy handler.
//!
//! VLESS itself is unencrypted. Deployments normally use TLS or REALITY,
//! although cleartext is explicitly configurable. The handshake is one
//! request header followed by a two-byte response prefix and optional addons.
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
//!    - `cmd`: 0x01 TCP
//!    - `port`: big-endian u16
//!    - `atyp`: 0x01 IPv4, 0x02 Domain, 0x03 IPv6
//!    - `addr`: 4 bytes (IPv4) / 1+len bytes (Domain) / 16 bytes (IPv6)
//! 3. The response prefix (`ver(1) | addon_len(1) | [addon]`) is stripped
//!    lazily on the first read. Real servers emit it with the target's first
//!    downstream bytes; awaiting it during dial deadlocks when target output
//!    depends on client bytes, including the target TLS handshake.
//! 4. The stream is then transparently connected to the target (with XTLS
//!    Vision unpadding on the read path when `flow = xtls-rprx-vision`).
//!
//! Reference: <https://xtls.github.io/en/development/protocols/vless.html>

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use honk_config::node::Node;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{AsyncReadWrite, ProbeableOutbound, ProxyStream, TcpOutbound};

const VLESS_VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

#[derive(Debug, Default, Clone, Copy)]
pub struct VLessHandler;

impl VLessHandler {
    pub fn new() -> Self {
        Self
    }

    fn parse_uuid(uuid_str: &str) -> anyhow::Result<[u8; 16]> {
        let uuid = uuid::Uuid::parse_str(uuid_str)?;
        Ok(*uuid.as_bytes())
    }

    fn build_request_header(
        uuid_bytes: &[u8; 16],
        target: SocketAddr,
        target_domain: Option<&str>,
        flow: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let flow = match flow.filter(|flow| !flow.is_empty()) {
            None => None,
            Some("xtls-rprx-vision") => Some("xtls-rprx-vision"),
            Some(_) => anyhow::bail!("VLESS: unsupported flow"),
        };
        let addon_len = flow.map_or(0, |flow| 2 + flow.len());
        let encoded_address_len = match target_domain {
            Some(domain) => {
                anyhow::ensure!(
                    domain.len() <= u8::MAX as usize,
                    "VLESS: target domain exceeds 255 bytes"
                );
                1 + 1 + domain.len()
            }
            None if target.is_ipv6() => 1 + 16,
            None => 1 + 4,
        };
        let mut buf = Vec::with_capacity(1 + 16 + 1 + addon_len + 1 + 2 + encoded_address_len);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(uuid_bytes);
        buf.push(addon_len as u8);
        if let Some(flow) = flow {
            buf.push(0x0a);
            buf.push(flow.len() as u8);
            buf.extend_from_slice(flow.as_bytes());
        }
        buf.push(CMD_TCP);
        buf.extend_from_slice(&target.port().to_be_bytes());

        if let Some(domain) = target_domain {
            buf.push(ATYP_DOMAIN);
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        } else {
            match target {
                SocketAddr::V4(address) => {
                    buf.push(ATYP_IPV4);
                    buf.extend_from_slice(&address.ip().octets());
                }
                SocketAddr::V6(address) => {
                    buf.push(ATYP_IPV6);
                    buf.extend_from_slice(&address.ip().octets());
                }
            }
        }
        Ok(buf)
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

/// Real servers do not send the two-byte `[version][addon_len]` prefix and
/// optional addons on request acceptance. They emit them with the target's
/// first downstream data (sing-vmess `serverConn.Write`, Xray alike). Reading
/// eagerly during dial deadlocks when the target needs client bytes before it
/// responds, so the prefix is consumed on the first read. A non-zero version
/// surfaces as a read error rather than a dial error.
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
    inbox: BytesMut,
    state: VisionState,
    inner_eof: bool,
}

/// Reach the raw TCP socket for the Vision direct-copy read switch. WS/gRPC
/// streams cannot unwrap and fall back to outer-stream raw passthrough.
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
            inbox: BytesMut::new(),
            state: VisionState::Detect,
            inner_eof: false,
        }
    }
}

impl<S: AsyncRead + RawTcp + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let initial_filled = buf.filled().len();

        loop {
            let needs_inner_read = {
                let this = &mut *self;
                let state = std::mem::replace(&mut this.state, VisionState::Failed);
                match state {
                    VisionState::Detect => {
                        if this.inbox.len() < 21 {
                            if this.inner_eof {
                                this.state = VisionState::Raw;
                                continue;
                            }
                            this.state = VisionState::Detect;
                            true
                        } else if this.inbox[..16] == this.uuid {
                            this.inbox.advance(16);
                            this.state = VisionState::Framed {
                                content_remaining: 0,
                                padding_remaining: 0,
                                command: 0,
                            };
                            continue;
                        } else {
                            this.state = VisionState::Raw;
                            continue;
                        }
                    }
                    VisionState::Framed {
                        mut content_remaining,
                        mut padding_remaining,
                        command,
                    } => {
                        if content_remaining > 0 {
                            let count =
                                content_remaining.min(this.inbox.len()).min(buf.remaining());
                            if count > 0 {
                                buf.put_slice(&this.inbox[..count]);
                                this.inbox.advance(count);
                                content_remaining -= count;
                            }
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if buf.remaining() == 0 {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            if content_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            true
                        } else if padding_remaining > 0 {
                            let count = padding_remaining.min(this.inbox.len());
                            this.inbox.advance(count);
                            padding_remaining -= count;
                            this.state = VisionState::Framed {
                                content_remaining,
                                padding_remaining,
                                command,
                            };
                            if padding_remaining == 0 {
                                continue;
                            }
                            if this.inner_eof || buf.filled().len() > initial_filled {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            true
                        } else {
                            match command {
                                VISION_COMMAND_END => {
                                    this.state = VisionState::Raw;
                                    continue;
                                }
                                VISION_COMMAND_DIRECT => {
                                    // Drain bytes already read through the outer TLS stream
                                    // before switching the read side to the raw socket.
                                    this.state = if this.inner.raw_tcp().is_some() {
                                        VisionState::DirectRaw
                                    } else {
                                        VisionState::Raw
                                    };
                                    continue;
                                }
                                0 => {
                                    if this.inbox.len() < 5 {
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        if this.inner_eof || buf.filled().len() > initial_filled {
                                            return std::task::Poll::Ready(Ok(()));
                                        }
                                        true
                                    } else {
                                        let command = this.inbox[0];
                                        let content_remaining =
                                            u16::from_be_bytes([this.inbox[1], this.inbox[2]])
                                                as usize;
                                        let padding_remaining =
                                            u16::from_be_bytes([this.inbox[3], this.inbox[4]])
                                                as usize;
                                        this.inbox.advance(5);
                                        this.state = VisionState::Framed {
                                            content_remaining,
                                            padding_remaining,
                                            command,
                                        };
                                        continue;
                                    }
                                }
                                _ => {
                                    this.state = VisionState::Failed;
                                    if buf.filled().len() > initial_filled {
                                        return std::task::Poll::Ready(Ok(()));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    VisionState::Raw => {
                        this.state = VisionState::Raw;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        return std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
                    }
                    VisionState::DirectRaw => {
                        this.state = VisionState::DirectRaw;
                        if !this.inbox.is_empty() {
                            let count = this.inbox.len().min(buf.remaining());
                            buf.put_slice(&this.inbox[..count]);
                            this.inbox.advance(count);
                            return std::task::Poll::Ready(Ok(()));
                        }
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        let tcp = this.inner.raw_tcp().expect("checked at transition");
                        return std::pin::Pin::new(tcp).poll_read(cx, buf);
                    }
                    VisionState::Failed => {
                        this.state = VisionState::Failed;
                        if buf.filled().len() > initial_filled {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "vision: unknown padding command",
                        )));
                    }
                }
            };

            debug_assert!(needs_inner_read);
            let this = &mut *self;
            let old_len = this.inbox.len();
            this.inbox.resize(old_len + 8192, 0);
            let (poll, filled) = {
                let mut read_buf = tokio::io::ReadBuf::new(&mut this.inbox[old_len..]);
                let poll = std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf);
                let filled = read_buf.filled().len();
                (poll, filled)
            };
            match poll {
                std::task::Poll::Pending => {
                    this.inbox.truncate(old_len);
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Err(error)) => {
                    this.inbox.truncate(old_len);
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Ready(Ok(())) => {
                    this.inbox.truncate(old_len + filled);
                    if filled == 0 {
                        this.inner_eof = true;
                    }
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

        let header =
            Self::build_request_header(&uuid_bytes, target, target_domain, node.flow.as_deref())?;
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

        let header =
            Self::build_request_header(&uuid_bytes, target, target_domain, node.flow.as_deref())?;
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

    struct SegmentedReader {
        segments: std::collections::VecDeque<std::collections::VecDeque<u8>>,
    }

    impl tokio::io::AsyncRead for SegmentedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            while self
                .segments
                .front()
                .is_some_and(|segment| segment.is_empty())
            {
                self.segments.pop_front();
            }
            let Some(segment) = self.segments.front_mut() else {
                return std::task::Poll::Ready(Ok(()));
            };
            let count = segment.len().min(buf.remaining());
            let (front, _) = segment.as_slices();
            buf.put_slice(&front[..count]);
            segment.drain(..count);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for SegmentedReader {}

    struct DirectSwitchIo {
        prefix: std::collections::VecDeque<u8>,
        raw: TcpStream,
        outer_writes: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for DirectSwitchIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.prefix.is_empty() {
                return std::pin::Pin::new(&mut self.raw).poll_read(cx, buf);
            }
            let count = self.prefix.len().min(buf.remaining());
            let (front, _) = self.prefix.as_slices();
            buf.put_slice(&front[..count]);
            self.prefix.drain(..count);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for DirectSwitchIo {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.outer_writes.lock().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl RawTcp for DirectSwitchIo {
        fn raw_tcp(&mut self) -> Option<&mut TcpStream> {
            Some(&mut self.raw)
        }
    }

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

    #[tokio::test]
    async fn vision_one_byte_destination_buffers_preserve_payload() {
        let uuid = [3_u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"first", 4));
        data.extend(vision_frame(0, b"", 0));
        data.extend(vision_frame(VISION_COMMAND_END, b"second", 2));
        data.extend_from_slice(b"-raw");
        let reader = ChunkedReader {
            data: data.into(),
            chunk: 8192,
        };
        let mut stream = VisionStream::new(reader, uuid);
        let mut output = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let size = stream.read(&mut byte).await.unwrap();
            if size == 0 {
                break;
            }
            assert_eq!(size, 1);
            output.push(byte[0]);
        }
        assert_eq!(output, b"firstsecond-raw");
    }

    #[tokio::test]
    async fn vision_accepts_every_source_frame_boundary() {
        let uuid = [4_u8; 16];
        let mut data = uuid.to_vec();
        data.extend(vision_frame(0, b"alpha", 3));
        data.extend(vision_frame(0, b"", 2));
        data.extend(vision_frame(VISION_COMMAND_END, b"omega", 0));
        data.extend_from_slice(b"-tail");

        for boundary in 0..=data.len() {
            let reader = SegmentedReader {
                segments: vec![
                    data[..boundary].iter().copied().collect(),
                    data[boundary..].iter().copied().collect(),
                ]
                .into(),
            };
            let mut stream = VisionStream::new(reader, uuid);
            let mut output = Vec::new();
            stream.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, b"alphaomega-tail", "boundary={boundary}");
        }
    }

    #[tokio::test]
    async fn vision_truncated_detected_frame_ends_cleanly() {
        let uuid = [5_u8; 16];
        let mut truncated_content = uuid.to_vec();
        truncated_content.extend_from_slice(&[0, 0, 5, 0, 0]);
        truncated_content.extend_from_slice(b"ab");
        assert_eq!(unpad_all(uuid, &truncated_content, 2).await, b"ab");

        let mut truncated_padding = uuid.to_vec();
        truncated_padding.extend_from_slice(&[0, 0, 3, 0, 5]);
        truncated_padding.extend_from_slice(b"abc\0\0");
        assert_eq!(unpad_all(uuid, &truncated_padding, 3).await, b"abc");
    }

    #[tokio::test]
    async fn vision_sub_probe_size_streams_pass_through_raw() {
        let uuid = [6_u8; 16];
        let mut source = uuid.to_vec();
        source.extend_from_slice(&[0, 0, 0, 0]);
        for length in 0..21 {
            assert_eq!(
                unpad_all(uuid, &source[..length], 1).await,
                source[..length],
                "length={length}"
            );
        }
    }

    #[tokio::test]
    async fn vision_direct_drains_buffered_tail_and_keeps_outer_writes() {
        let uuid = [8_u8; 16];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"raw-tail").await.unwrap();
        });
        let raw = TcpStream::connect(address).await.unwrap();
        let mut prefix = uuid.to_vec();
        prefix.extend(vision_frame(VISION_COMMAND_DIRECT, b"framed-", 1));
        prefix.extend_from_slice(b"buffered-");
        let outer_writes = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let io = DirectSwitchIo {
            prefix: prefix.into(),
            raw,
            outer_writes: std::sync::Arc::clone(&outer_writes),
        };
        let mut stream = VisionStream::new(io, uuid);
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"framed-buffered-raw-tail");

        stream.write_all(b"outer-uplink").await.unwrap();
        assert_eq!(&*outer_writes.lock(), b"outer-uplink");
        server.await.unwrap();
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

        let header = VLessHandler::build_request_header(&uuid_bytes, target, None, None).unwrap();

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
            VLessHandler::build_request_header(&uuid_bytes, target, Some(domain), None).unwrap();

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

        let header = VLessHandler::build_request_header(&uuid_bytes, target, None, None).unwrap();

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
    fn test_vless_header_vision_flow() {
        let uuid_str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
        let uuid_bytes = VLessHandler::parse_uuid(uuid_str).unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let header =
            VLessHandler::build_request_header(&uuid_bytes, target, None, Some("xtls-rprx-vision"))
                .unwrap();

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
    fn test_vless_header_rejects_unsupported_flow_and_long_domain() {
        let uuid_bytes = VLessHandler::parse_uuid("b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3").unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        let flow_error =
            VLessHandler::build_request_header(&uuid_bytes, target, None, Some("unsupported"))
                .unwrap_err();
        assert_eq!(flow_error.to_string(), "VLESS: unsupported flow");

        let long_domain = "a".repeat(256);
        let domain_error =
            VLessHandler::build_request_header(&uuid_bytes, target, Some(&long_domain), None)
                .unwrap_err();
        assert_eq!(
            domain_error.to_string(),
            "VLESS: target domain exceeds 255 bytes"
        );

        let empty_flow =
            VLessHandler::build_request_header(&uuid_bytes, target, None, Some("")).unwrap();
        assert_eq!(empty_flow[17], 0);
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
