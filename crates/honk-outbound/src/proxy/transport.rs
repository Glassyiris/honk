//! Shared stream-transport helpers for proxy handlers.
//!
//! Trojan, VMess and VLESS all wrap their connections in the same order:
//!
//! ```text
//! TCP -> (TLS) -> (h2mux | WebSocket | gRPC) -> protocol header
//! ```
//!
//! This module provides the reusable pieces so each handler only implements
//! its own protocol handshake:
//!
//! - [`connect_transport`]: TCP connect + optional TLS + optional h2mux or
//!   WS/gRPC wrapping, driven by `node.mux` / `node.transport` / `node.tls`.
//! - [`wrap_transport`]: the same TLS + h2mux/WS/gRPC wrapping for an
//!   already-connected `TcpStream` (the `dial_with_tcp` pooling path).
//! - [`maybe_tls_wrap`]: just the TLS step (used by handlers that keep the
//!   pooled-TCP path on the raw transport).
//! - [`GrpcStream`]: minimal gRPC-over-HTTP/2 framing client.
//!
//! When `node.mux` is set the dial goes through [`super::mux`] instead of
//! the WS/gRPC transports: the TCP (+TLS) connection is upgraded to a
//! shared HTTP/2 session and the returned stream is one multiplexed h2
//! stream (sing-box semantics — multiplex and transport are mutually
//! exclusive, so a configured `node.transport` is ignored with a debug
//! log). The protocol header the handler writes afterwards is unchanged.

use futures_util::{SinkExt, StreamExt};
use honk_config::node::Node;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::AsyncReadWrite;

/// Connect to the node server and optionally wrap with TLS and then a
/// WebSocket or gRPC transport based on `node.transport`.
///
/// When `node.mux` is set this returns a multiplexed h2 stream from the
/// shared h2mux session instead (see [`super::mux`]); the WS/gRPC
/// transports are mutually exclusive with mux and are skipped.
pub(crate) async fn connect_transport(
    node: &Node,
    connect_timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    if node.mux {
        debug_mux_transport_conflict(node);
        return super::mux::open_stream(node, connect_timeout).await;
    }
    let addr = format!("{}:{}", node.host(), node.port);
    let tcp = crate::util::connect_outbound(&addr, connect_timeout).await?;
    wrap_transport(node, tcp).await
}

/// Apply TLS (when `node.tls`) and then the `node.transport` wrapping to an
/// already-connected TCP stream. With `node.mux` the TLS stream is upgraded
/// to an h2mux session instead and one multiplexed stream is returned.
pub(crate) async fn wrap_transport(
    node: &Node,
    tcp: TcpStream,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let stream = maybe_tls_wrap(node, tcp).await?;
    if node.mux {
        debug_mux_transport_conflict(node);
        return super::mux::open_stream_on(node, stream).await;
    }
    match node.transport.as_str() {
        "ws" => wrap_ws(node, stream).await,
        "grpc" => wrap_grpc(node, stream).await,
        _ => Ok(stream), // "tcp" or unknown: raw TCP/TLS
    }
}

/// sing-box semantics: multiplex and the WS/gRPC transports are mutually
/// exclusive — mux wins, so warn (at debug level) when a transport is
/// configured but will be ignored.
fn debug_mux_transport_conflict(node: &Node) {
    if !matches!(node.transport.as_str(), "" | "tcp") {
        tracing::debug!(
            node = %node.name,
            transport = %node.transport,
            "node.mux is enabled: multiplex and transport are mutually exclusive; \
             ignoring the configured WS/gRPC transport"
        );
    }
}

/// Wrap the stream in TLS when `node.tls` is set, using `node.sni` (or the
/// server host) as the SNI.
pub(crate) async fn maybe_tls_wrap(
    node: &Node,
    stream: TcpStream,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    if node.tls {
        let connector = crate::tls::build_connector(node)?;
        let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
        let tls_stream = connector.connect(&server_name, stream).await?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
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

    Ok(Box::new(GrpcStream::new(stream, &path, &authority).await?))
}

/// Minimal gRPC client that wraps a TCP/TLS stream with HTTP/2
/// framing and gRPC-Length-Prefixed message framing.
///
/// On construction sends: HTTP/2 preface + SETTINGS + HEADERS frame
/// to open a gRPC stream. Subsequent reads/writes are wrapped in
/// gRPC-LP frames (`[1 byte compressed] [4 bytes BE length] [payload]`)
/// packed inside HTTP/2 DATA frames.
struct GrpcStream {
    inner: Box<dyn AsyncReadWrite>,
    stream_id: u32,
    read_buf: Vec<u8>,
    #[allow(dead_code)]
    wrote_preface: bool,
    #[allow(dead_code)]
    wrote_headers: bool,
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
const H2_FLAG_END_STREAM: u8 = 0x01;

impl GrpcStream {
    async fn new(
        inner: Box<dyn AsyncReadWrite>,
        path: &str,
        authority: &str,
    ) -> anyhow::Result<Self> {
        let mut s = Self {
            inner,
            stream_id: 1,
            read_buf: Vec::new(),
            wrote_preface: false,
            wrote_headers: false,
        };
        s.send_preface().await?;
        s.send_settings().await?;
        s.send_headers_frame(path, authority).await?;
        Ok(s)
    }

    /// Send the HTTP/2 connection preface.
    async fn send_preface(&mut self) -> anyhow::Result<()> {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        self.inner.write_all(PREFACE).await?;
        self.wrote_preface = true;
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
    async fn send_headers_frame(&mut self, path: &str, authority: &str) -> anyhow::Result<()> {
        let mut hpack = Vec::with_capacity(128);

        // :method: POST — literal header field with incremental indexing
        // 0x40 | 0x03 = 0x43 (indexed name, ref static table idx 3 = ":method")
        // value: "POST" = 4 bytes, huffman not used
        hpack.push(0x43);
        hpack.push(0x04);
        hpack.extend_from_slice(b"POST");

        // :scheme: http — same pattern, static idx 6 = ":scheme"
        hpack.push(0x46);
        hpack.push(0x04);
        hpack.extend_from_slice(b"http");

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

        // te: trailers — static idx 55 = "te"
        hpack.push(0x77); // 0x40 | 55
        hpack.push(8); // "trailers" len
        hpack.extend_from_slice(b"trailers");

        // user-agent: honk
        hpack.push(0x40 | 58); // static idx 58 = "user-agent", literal
        hpack.push(7); // "honk" len
        hpack.extend_from_slice(b"honk");

        let payload_len = hpack.len() as u32;
        let frame_header: [u8; 9] = [
            (payload_len >> 16) as u8,
            (payload_len >> 8) as u8,
            payload_len as u8,
            H2_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM,
            ((self.stream_id >> 24) & 0x7F) as u8,
            (self.stream_id >> 16) as u8,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
        ];

        self.inner.write_all(&frame_header).await?;
        self.inner.write_all(&hpack).await?;
        self.inner.flush().await?;
        self.wrote_headers = true;
        Ok(())
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let drain = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..drain]);
            self.read_buf.drain(..drain);
            return Poll::Ready(Ok(()));
        }

        // Read a gRPC-LP frame from inner stream, unwrapping HTTP/2
        // DATA frames. Each gRPC frame: [1B compressed] [4B BE len] [payload].
        let mut frame_header = [0u8; 9];
        match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut frame_header)) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        let _payload_len = ((frame_header[0] as u32) << 16)
            | ((frame_header[1] as u32) << 8)
            | (frame_header[2] as u32);
        let frame_type = frame_header[3];

        if frame_type == H2_DATA {
            let mut grpc_hdr = [0u8; 5];
            match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut grpc_hdr)) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let compressed = grpc_hdr[0];
            if compressed != 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "gRPC: compressed frames not supported",
                )));
            }
            let grpc_len = u32::from_be_bytes([grpc_hdr[1], grpc_hdr[2], grpc_hdr[3], grpc_hdr[4]]);

            if grpc_len > 0 {
                let mut payload = vec![0u8; grpc_len as usize];
                match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut payload)) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                let drain = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..drain]);
                if drain < payload.len() {
                    self.read_buf.extend_from_slice(&payload[drain..]);
                }
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Ok(()))
            }
        } else if frame_type == H2_SETTINGS {
            Poll::Ready(Ok(()))
        } else {
            // Skip other frame types — just try again
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Build a gRPC-LP frame: [1B uncompressed] [4B BE length] [payload]
        let payload_len = buf.len() as u32;
        let mut frame = Vec::with_capacity(5 + buf.len());
        frame.push(0x00); // uncompressed
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(buf);

        let h2_payload_len = frame.len() as u32;
        let h2_header: [u8; 9] = [
            (h2_payload_len >> 16) as u8,
            (h2_payload_len >> 8) as u8,
            h2_payload_len as u8,
            H2_DATA,
            0x00, // flags
            ((self.stream_id >> 24) & 0x7F) as u8,
            (self.stream_id >> 16) as u8,
            (self.stream_id >> 8) as u8,
            self.stream_id as u8,
        ];

        match Pin::new(&mut self.inner).poll_write(cx, &h2_header) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut self.inner).poll_write(cx, &frame) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
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

            // DATA frame carrying one gRPC-LP message "hello".
            let (len, ty, sid) = read_h2_header(&mut stream).await;
            assert_eq!(ty, H2_DATA);
            assert_eq!(sid, 1);
            assert_eq!(len, 5 + 5);
            let mut frame = vec![0u8; len as usize];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(frame[0], 0x00); // uncompressed
            assert_eq!(&frame[1..5], &[0, 0, 0, 5]);
            assert_eq!(&frame[5..], b"hello");

            // Reply with one DATA frame carrying gRPC-LP "world", coalesced
            // into a single write so the client's single-poll reads observe
            // complete frames.
            let h2_len: u32 = 5 + 5;
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
            reply.extend_from_slice(&5u32.to_be_bytes());
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
