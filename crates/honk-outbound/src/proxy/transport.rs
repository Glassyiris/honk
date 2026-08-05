//! Shared stream-transport helpers for proxy handlers.
//!
//! Trojan, VMess and VLESS all wrap their connections in the same order:
//!
//! ```text
//! TCP -> (TLS) -> (WebSocket | gRPC) -> protocol header
//! ```
//!
//! This module provides the reusable pieces so each handler only implements
//! its own protocol handshake:
//!
//! - [`connect_transport`]: TCP connect + optional TLS + optional WS/gRPC
//!   wrapping, driven by `node.transport` / `node.tls`.
//! - [`wrap_transport`]: the same TLS + WS/gRPC wrapping for an
//!   already-connected `TcpStream` (the `dial_with_tcp` pooling path).
//! - [`maybe_tls_wrap`]: just the TLS step (used by handlers that keep the
//!   pooled-TCP path on the raw transport).
//! - [`GrpcStream`]: minimal gRPC-over-HTTP/2 framing client.

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::AsyncReadWrite;

/// Connect to the node server and optionally wrap with TLS and then a
/// WebSocket or gRPC transport based on `node.transport`.
pub(crate) async fn connect_transport(
    node: &Node,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let addr = format!("{}:{}", node.host(), node.port);
    let tcp = crate::util::connect_outbound(&addr, connect_timeout).await?;
    wrap_transport(node, tcp).await
}

/// Apply TLS (when `node.tls`) and then the `node.transport` wrapping to an
/// already-connected TCP stream.
pub(crate) async fn wrap_transport(
    node: &Node,
    tcp: TcpStream,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let stream = maybe_tls_wrap(node, tcp).await?;
    match node.transport.as_str() {
        "" | "tcp" => Ok(stream), // raw TCP/TLS
        "ws" => wrap_ws(node, stream).await,
        "grpc" => wrap_grpc(node, stream).await,
        // Unknown transport must not silently degrade to raw TCP — a
        // mistyped transport means a different protocol than intended.
        other => anyhow::bail!(
            "node '{}': unsupported transport '{}' (expected tcp/ws/grpc)",
            node.name,
            other
        ),
    }
}

/// Wrap the stream in TLS when `node.tls` is set, using `node.sni` (or the
/// server host) as the SNI. A node with REALITY parameters takes the
/// REALITY handshake instead of plain TLS (`security=reality` sets both).
pub(crate) async fn maybe_tls_wrap(
    node: &Node,
    stream: TcpStream,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    match maybe_tls_wrap_concrete(node, stream).await? {
        MaybeTls::Tls(stream) => Ok(Box::new(crate::tls::BatchRead::new(*stream))),
        MaybeTls::Plain(stream) => Ok(Box::new(stream)),
    }
}

/// [`maybe_tls_wrap`] without erasing the concrete stream type: the XTLS
/// Vision direct-copy switch must reach the raw TCP socket under the TLS
/// stream once the server abandons the outer TLS session.
pub(crate) enum MaybeTls {
    Tls(Box<crate::tls::TlsStream<TcpStream>>),
    Plain(TcpStream),
}

pub(crate) async fn maybe_tls_wrap_concrete(
    node: &Node,
    tcp: TcpStream,
) -> anyhow::Result<MaybeTls> {
    if let Some(reality) = crate::reality::parse_reality_config(node)? {
        let tls_stream =
            crate::reality::reality_connect(tcp, &reality, crate::tls::chrome_mode()).await?;
        return Ok(MaybeTls::Tls(Box::new(tls_stream)));
    }
    if node.tls {
        let connector = crate::tls::build_connector(node)?;
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        let tls_stream = connector.connect(&server_name, tcp).await?;
        return Ok(MaybeTls::Tls(Box::new(tls_stream)));
    }
    Ok(MaybeTls::Plain(tcp))
}

/// Upgrade an already-connected (optionally TLS-wrapped) stream to
/// WebSocket, then bridge through a duplex so the caller gets a
/// plain `AsyncRead + AsyncWrite` handle.
async fn wrap_ws(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let ws_path = node.ws_path.as_deref().unwrap_or("/");
    let ws_host = node.ws_host.as_deref().unwrap_or(node.host()).to_string();

    // Build the request from the URI so tungstenite generates the full
    // handshake header set (Sec-WebSocket-Key, Upgrade, ...); a bare
    // `http::Request` passed to `client_async` is sent as-is and real
    // servers reject the missing key.
    let uri = format!("ws://{}:{}{}", node.host(), node.port, ws_path);
    let mut request = uri
        .into_client_request()
        .map_err(|e| anyhow::anyhow!("WebSocket request build failed: {}", e))?;
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::HOST,
        ws_host
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid WebSocket host header: {}", e))?,
    );

    let (ws_stream, _response) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(|e| anyhow::anyhow!("WebSocket upgrade failed: {}", e))?;

    let (client_half, server_half) = tokio::io::duplex(65536);

    tokio::spawn(ws_bridge_relay(ws_stream, server_half));

    Ok(Box::new(client_half))
}

/// Background task that bridges a WebSocket stream to a duplex half.
/// Reads binary/text messages from the WebSocket and writes them to
/// the duplex; reads from the duplex and sends as binary WebSocket
/// messages.
async fn ws_bridge_relay(
    ws: tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>,
    server: tokio::io::DuplexStream,
) {
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    // server → ws
    let s2w = async {
        let mut buf = vec![0u8; 65536];
        loop {
            use tokio::io::AsyncReadExt;
            let n = server_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge server read: {}", e))?;
            if n == 0 {
                break;
            }
            ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    buf[..n].to_vec().into(),
                ))
                .await
                .map_err(|e| anyhow::anyhow!("ws bridge send: {}", e))?;
        }
        let _ = ws_sink.close().await;
        Ok::<_, anyhow::Error>(())
    };

    // ws → server
    let w2s = async {
        loop {
            let msg = ws_stream.next().await;
            match msg {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(&data).await?;
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(data))) => {
                    use tokio::io::AsyncWriteExt;
                    server_write.write_all(data.as_bytes()).await?;
                }
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Close(_)
                    | tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => {}
                Some(Ok(tokio_tungstenite::tungstenite::Message::Frame(_))) => {}
                Some(Err(e)) => {
                    tracing::debug!("ws bridge recv error: {}", e);
                    break;
                }
                None => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = s2w => { let _ = r; },
        r = w2s => { let _ = r; },
    }
}

/// Wrap an already-connected stream with minimal gRPC-over-HTTP/2
/// framing. On first read/write the HTTP/2 preface + SETTINGS +
/// HEADERS are sent, then all data is tunnelled through gRPC
/// length-prefixed DATA frames.
async fn wrap_grpc(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let service = node.grpc_service.as_deref().unwrap_or("GunService");
    let path = format!("/{}/Tun", service);
    let authority = node.host().to_string();
    // gRPC servers (sing-box) reject :scheme http over a TLS connection.
    let scheme = if node.tls { "https" } else { "http" };

    Ok(Box::new(
        GrpcStream::new(stream, &path, &authority, scheme).await?,
    ))
}

/// Minimal gRPC client that wraps a TCP/TLS stream with HTTP/2
/// framing and gRPC message framing.
///
/// On construction sends: HTTP/2 preface + SETTINGS + HEADERS frame
/// to open a gRPC stream. Every read/write payload is one gRPC message:
/// HTTP/2 DATA frames carry a length-prefixed block
/// (`[1 byte compressed] [4 bytes BE length] [message]`), and the message
/// itself is the protobuf single-bytes-field envelope (`0x0a` tag + varint
/// length + content) that gun-style transports (sing-box, Xray) put
/// inside it — verified byte-for-byte against a sing-box client capture.
struct GrpcStream {
    inner: Box<dyn AsyncReadWrite>,
    stream_id: u32,
    /// Decoded payload not yet consumed by the reader.
    read_buf: Vec<u8>,
    /// Raw undecoded bytes from `inner` awaiting frame parsing; short
    /// reads land here instead of corrupting frame alignment.
    undecoded: Vec<u8>,
    /// DATA-frame payloads awaiting message parsing; a message may span
    /// multiple DATA frames.
    msg_buf: Vec<u8>,
    /// Outbound bytes not yet fully written; short writes keep the rest
    /// queued instead of losing half a frame.
    write_queue: std::collections::VecDeque<u8>,
}

impl std::fmt::Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_SETTINGS: u8 = 0x4;

const H2_FLAG_END_HEADERS: u8 = 0x04;

impl GrpcStream {
    async fn new(
        inner: Box<dyn AsyncReadWrite>,
        path: &str,
        authority: &str,
        scheme: &str,
    ) -> anyhow::Result<Self> {
        let mut s = Self {
            inner,
            stream_id: 1,
            read_buf: Vec::new(),
            undecoded: Vec::new(),
            msg_buf: Vec::new(),
            write_queue: std::collections::VecDeque::new(),
        };
        s.send_preface().await?;
        s.send_settings().await?;
        s.send_headers_frame(path, authority, scheme).await?;
        Ok(s)
    }

    /// Send the HTTP/2 connection preface.
    async fn send_preface(&mut self) -> anyhow::Result<()> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        self.inner.write_all(PREFACE).await?;
        Ok(())
    }

    /// Send an empty SETTINGS frame (stream 0).
    async fn send_settings(&mut self) -> anyhow::Result<()> {
        let frame: [u8; 9] = [
            0x00,
            0x00,
            0x00,        // length = 0
            H2_SETTINGS, // type
            0x00,        // flags = none
            0x00,
            0x00,
            0x00,
            0x00, // stream_id = 0
        ];
        self.inner.write_all(&frame).await?;
        Ok(())
    }

    /// Send a HEADERS frame to open stream 1 with gRPC pseudo-headers.
    async fn send_headers_frame(
        &mut self,
        path: &str,
        authority: &str,
        scheme: &str,
    ) -> anyhow::Result<()> {
        let mut hpack = Vec::with_capacity(128);

        // :method: POST — literal header field with incremental indexing
        // 0x40 | 0x03 = 0x43 (indexed name, ref static table idx 3 = ":method")
        // value: "POST" = 4 bytes, huffman not used
        hpack.push(0x43);
        hpack.push(0x04);
        hpack.extend_from_slice(b"POST");

        // :scheme — same pattern, static idx 6 = ":scheme"
        hpack.push(0x46);
        hpack.push(scheme.len() as u8);
        hpack.extend_from_slice(scheme.as_bytes());

        // :path: <path> — static idx 4 = ":path"
        hpack.push(0x44);
        hpack.push(path.len() as u8);
        hpack.extend_from_slice(path.as_bytes());

        // :authority: <authority> — static idx 1 = ":authority"
        hpack.push(0x41);
        hpack.push(authority.len() as u8);
        hpack.extend_from_slice(authority.as_bytes());

        // content-type: application/grpc — static idx 31 = "content-type"
        hpack.push(0x5f); // 0x40 | 31
        hpack.push(16); // "application/grpc" len
        hpack.extend_from_slice(b"application/grpc");

        // te: trailers — "te" is not in the HPACK static table (55 is
        // set-cookie), so encode it as a literal name without indexing.
        hpack.push(0x00);
        hpack.push(2);
        hpack.extend_from_slice(b"te");
        hpack.push(8); // "trailers" len
        hpack.extend_from_slice(b"trailers");

        // user-agent: honk — static idx 58 for the name
        hpack.push(0x40 | 58);
        hpack.push(4); // "honk" len
        hpack.extend_from_slice(b"honk");

        let payload_len = hpack.len() as u32;
        let frame_header: [u8; 9] = [
            (payload_len >> 16) as u8,
            (payload_len >> 8) as u8,
            payload_len as u8,
            H2_HEADERS,
            // gRPC is bidirectional streaming: DATA frames follow, so the
            // HEADERS frame must NOT carry END_STREAM (servers reject
            // writes on a client-closed stream with 400).
            H2_FLAG_END_HEADERS,
            ((self.stream_id >> 24) & 0x7F) as u8,
            (self.stream_id >> 16) as u8,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
        ];

        self.inner.write_all(&frame_header).await?;
        self.inner.write_all(&hpack).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let drain = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..drain]);
                self.read_buf.drain(..drain);
                return Poll::Ready(Ok(()));
            }
            while self.try_parse_message() {}
            if !self.read_buf.is_empty() {
                continue;
            }
            if let Some(frame) = self.try_parse_frame() {
                match frame {
                    ParsedFrame::Data(payload) => {
                        self.msg_buf.extend_from_slice(&payload);
                    }
                    ParsedFrame::Skipped => {}
                }
                continue;
            }

            // Need more bytes from the inner stream.
            let mut chunk = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        // EOF: an empty read is the AsyncRead EOF signal.
                        return Poll::Ready(Ok(()));
                    }
                    self.undecoded.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

enum ParsedFrame {
    Data(Vec<u8>),
    Skipped,
}

impl GrpcStream {
    /// Parse one complete HTTP/2 frame out of `self.undecoded` if fully
    /// present. DATA frames yield their raw payload; every other frame
    /// type (SETTINGS, WINDOW_UPDATE, PING, trailers HEADERS, ...) is
    /// consumed and skipped.
    fn try_parse_frame(&mut self) -> Option<ParsedFrame> {
        if self.undecoded.len() < 9 {
            return None;
        }
        let payload_len = ((self.undecoded[0] as usize) << 16)
            | ((self.undecoded[1] as usize) << 8)
            | self.undecoded[2] as usize;
        let frame_type = self.undecoded[3];
        let total = 9 + payload_len;
        if self.undecoded.len() < total {
            return None;
        }
        let payload = self.undecoded[9..total].to_vec();
        self.undecoded.drain(..total);
        if frame_type == H2_DATA {
            Some(ParsedFrame::Data(payload))
        } else {
            Some(ParsedFrame::Skipped)
        }
    }

    /// Parse one complete gRPC message out of `self.msg_buf`, appending
    /// its content to `self.read_buf`. The message envelope is the
    /// protobuf bytes field (`0x0a` + varint length) inside the
    /// length-prefixed block; anything else passes through raw so a
    /// non-gun framing still delivers its bytes.
    fn try_parse_message(&mut self) -> bool {
        if self.msg_buf.len() < 5 {
            return false;
        }
        let compressed = self.msg_buf[0];
        let msg_len = u32::from_be_bytes([
            self.msg_buf[1],
            self.msg_buf[2],
            self.msg_buf[3],
            self.msg_buf[4],
        ]) as usize;
        if self.msg_buf.len() < 5 + msg_len {
            return false;
        }
        let msg = &self.msg_buf[5..5 + msg_len];
        let content = if compressed == 0 && msg.first() == Some(&0x0a) {
            match parse_varint(&msg[1..]) {
                Some((len, used)) if 1 + used + len == msg.len() => &msg[1 + used..],
                _ => msg,
            }
        } else {
            msg
        };
        self.read_buf.extend_from_slice(content);
        self.msg_buf.drain(..5 + msg_len);
        true
    }
}

fn parse_varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    for (i, &b) in bytes.iter().enumerate().take(10) {
        value |= ((b & 0x7f) as usize) << (7 * i);
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

fn push_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

impl GrpcStream {
    /// Write as much of the queued frame as possible; Pending keeps the
    /// remainder queued for the next call.
    fn drain_write_queue(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.write_queue.is_empty() {
            let n = {
                let contiguous = self.write_queue.make_contiguous();
                match Pin::new(&mut self.inner).poll_write(cx, contiguous) {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            };
            self.write_queue.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Only one gRPC frame is queued at a time: if a previous frame is
        // still draining, wait for it (callers write sequentially anyway).
        if self.write_queue.is_empty() {
            // Message: [1B uncompressed] [4B BE length] [protobuf envelope]:
            // field 1 bytes content (0x0a tag + varint length + payload).
            let mut msg = Vec::with_capacity(5 + buf.len());
            msg.push(0x0a);
            push_varint(&mut msg, buf.len());
            msg.extend_from_slice(buf);
            let h2_len = 5 + msg.len();
            let mut frame = Vec::with_capacity(9 + h2_len);
            frame.extend_from_slice(&[
                (h2_len >> 16) as u8,
                (h2_len >> 8) as u8,
                h2_len as u8,
                H2_DATA,
                0x00, // flags
                ((self.stream_id >> 24) & 0x7F) as u8,
                ((self.stream_id >> 16) & 0x7F) as u8,
                ((self.stream_id >> 8) & 0x7F) as u8,
                self.stream_id as u8,
            ]);
            frame.push(0x00); // uncompressed
            frame.extend_from_slice(&(msg.len() as u32).to_be_bytes());
            frame.extend_from_slice(&msg);
            self.write_queue.extend(frame);
        }
        match self.drain_write_queue(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.drain_write_queue(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn transport_node(port: u16) -> Node {
        Node {
            name: "transport-node".into(),
            // The protocol is irrelevant to the transport layer.
            protocol: NodeProtocol::Trojan,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        }
    }

    /// An inner stream that yields at most one byte per poll_read and
    /// accepts at most one byte per poll_write — the short-IO regression
    /// case for gRPC framing.
    #[derive(Debug)]
    struct DribbleStream {
        reader: std::collections::VecDeque<u8>,
        written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl tokio::io::AsyncRead for DribbleStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(b) = self.reader.pop_front() {
                buf.put_slice(&[b]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for DribbleStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.written.lock().unwrap().push(buf[0]);
            Poll::Ready(Ok(1))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_grpc_stream_tolerates_short_reads_and_writes() {
        // One gRPC DATA frame on stream 1: [9B h2 hdr][5B length prefix]
        // [protobuf envelope: 0a <len> "pong"].
        let mut wire = Vec::new();
        wire.extend_from_slice(&[0, 0, 11, H2_DATA, 0, 0, 0, 0, 1]);
        wire.extend_from_slice(&[0, 0, 0, 0, 6, 0x0a, 0x04]);
        wire.extend_from_slice(b"pong");
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = DribbleStream {
            reader: wire.into(),
            written: written.clone(),
        };
        let mut stream = GrpcStream {
            inner: Box::new(inner),
            stream_id: 1,
            read_buf: Vec::new(),
            undecoded: Vec::new(),
            msg_buf: Vec::new(),
            write_queue: std::collections::VecDeque::new(),
        };

        // Read: the frame arrives one byte at a time but must decode whole.
        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
            .await
            .unwrap();
        assert_eq!(&out, b"pong");

        // Write: the frame leaves one byte at a time but must be complete.
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();
        let got = written.lock().unwrap().clone();
        let mut want = Vec::new();
        want.extend_from_slice(&[0, 0, 11, H2_DATA, 0, 0, 0, 0, 1]);
        want.extend_from_slice(&[0, 0, 0, 0, 6, 0x0a, 0x04]);
        want.extend_from_slice(b"ping");
        assert_eq!(got, want);
    }

    /// WebSocket transport: the mock server verifies the upgrade request
    /// (path + Host header) and echoes one binary message.
    // The accept callback's Result type (and its large Err variant) is
    // dictated by tungstenite's `Callback` trait.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn test_ws_transport_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (stream, _) = listener.accept().await.unwrap();
            let mut seen_tx = Some(seen_tx);
            let callback = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                            resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send((req.uri().path().to_string(), host));
                }
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, callback)
                .await
                .unwrap();
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(&msg.into_data()[..], b"ping");
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                b"pong".to_vec().into(),
            ))
            .await
            .unwrap();
        });

        let mut node = transport_node(port);
        node.transport = "ws".into();
        node.ws_path = Some("/ws-path".into());
        node.ws_host = Some("cdn.example.com".into());

        let mut stream = connect_transport(&node, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf, b"pong");

        let (path, host) = seen_rx.await.unwrap();
        assert_eq!(path, "/ws-path");
        assert_eq!(host.as_deref(), Some("cdn.example.com"));

        server.await.unwrap();
    }

    /// gRPC transport: the mock server verifies the HTTP/2 preface, the
    /// client SETTINGS frame, the HEADERS frame (path, content-type,
    /// authority) and the DATA+gRPC-LP framing in both directions.
    #[tokio::test]
    async fn test_grpc_transport_roundtrip() {
        const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            // HTTP/2 connection preface.
            let mut preface = [0u8; 24];
            stream.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, H2_PREFACE);

            // Client SETTINGS frame: len 0, stream 0.
            let (len, ty, sid) = read_h2_header(&mut stream).await;
            assert_eq!((len, ty, sid), (0, H2_SETTINGS, 0));

            // HEADERS frame opening stream 1.
            let (len, ty, sid) = read_h2_header(&mut stream).await;
            assert_eq!(ty, H2_HEADERS);
            assert_eq!(sid, 1);
            let mut payload = vec![0u8; len as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let payload = String::from_utf8_lossy(&payload);
            assert!(payload.contains("/testSvc/Tun"));
            assert!(payload.contains("application/grpc"));
            assert!(payload.contains("127.0.0.1"));

            // DATA frame carrying one gRPC message "hello".
            let (len, ty, sid) = read_h2_header(&mut stream).await;
            assert_eq!(ty, H2_DATA);
            assert_eq!(sid, 1);
            assert_eq!(len, 5 + 7);
            let mut frame = vec![0u8; len as usize];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame[0], 0x00); // uncompressed
            assert_eq!(&frame[1..5], &[0, 0, 0, 7]);
            assert_eq!(&frame[5..7], &[0x0a, 0x05]); // protobuf bytes field
            assert_eq!(&frame[7..], b"hello");

            // Reply with one DATA frame carrying a gRPC message "world",
            // coalesced into a single write so the client's single-poll
            // reads observe complete frames.
            let h2_len: u32 = 5 + 7;
            let mut reply = Vec::new();
            reply.extend_from_slice(&[
                (h2_len >> 16) as u8,
                (h2_len >> 8) as u8,
                h2_len as u8,
                H2_DATA,
                0x00,
                0,
                0,
                0,
                1,
            ]);
            reply.push(0x00); // uncompressed
            reply.extend_from_slice(&7u32.to_be_bytes());
            reply.extend_from_slice(&[0x0a, 0x05]);
            reply.extend_from_slice(b"world");
            stream.write_all(&reply).await.unwrap();
        });

        let mut node = transport_node(port);
        node.transport = "grpc".into();
        node.grpc_service = Some("testSvc".into());

        let mut stream = connect_transport(&node, std::time::Duration::from_secs(3))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }

    /// Read one HTTP/2 frame header: returns (payload_len, type, stream_id).
    async fn read_h2_header(stream: &mut tokio::net::TcpStream) -> (u32, u8, u32) {
        let mut hdr = [0u8; 9];
        stream.read_exact(&mut hdr).await.unwrap();
        let len = ((hdr[0] as u32) << 16) | ((hdr[1] as u32) << 8) | hdr[2] as u32;
        let ty = hdr[3];
        let sid = u32::from_be_bytes([hdr[5] & 0x7F, hdr[6], hdr[7], hdr[8]]);
        (len, ty, sid)
    }
}
