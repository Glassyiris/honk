//! h2mux stream multiplexing for the stream-transport layer —
//! **honk h2 carrier**, not sing-mux compatible.
//!
//! When `node.mux` is set, the trojan/VMess/VLESS dial path upgrades its
//! TCP (+TLS) connection to a shared HTTP/2 session and each dial opens a
//! lightweight h2 stream on it instead of a new TCP connection, mirroring
//! sing-mux's `h2mux` protocol (`mux = true` means h2mux; smux/yamux are
//! not implemented).
//!
//! # Compatibility (4B decision gate)
//!
//! honk writes the proxy handshake onto each h2 stream, while sing-mux
//! wraps streams in its own outer handshake + per-stream `StreamRequest`.
//! An interop gate test against an official sing-box multiplex inbound
//! (`trojan_mux_against_sing_box`, run with `--ignored`) fails with
//! "stream closed because of a broken pipe" — **official sing-mux
//! inbounds reject this implementation**. Use it only with servers that
//! follow the same honk h2-carrier convention.
//!
//! # Wire format
//!
//! - **Session header**: before the HTTP/2 client preface the client writes
//!   the sing-mux session request `version(1) | protocol(1)` = `0x00 0x02`
//!   (Version0 + ProtocolH2Mux, no padding) — sing-mux `protocol.go`
//!   (`EncodeRequest`) and `protocol_conn.go` (prepended on first write).
//! - **Streams**: each proxied connection is one h2 stream opened with a
//!   plain CONNECT request — `:method: CONNECT`, `:authority: localhost`,
//!   no `:path`/`:scheme` (Go's `x/net/http2` omits them for non-extended
//!   CONNECT, and so does the `h2` crate) — sing-mux `h2mux.go` `Open`
//!   builds `&http.Request{Method: CONNECT, URL: https://localhost}`.
//!   The server must answer `200 OK`; the request/response bodies are the
//!   upload/download byte pipes (DATA frames both ways).
//! - **Half-close**: `shutdown()` on the write side sends an empty DATA
//!   frame with END_STREAM (Go: closing the request body pipe); a peer
//!   END_STREAM surfaces as read EOF. Dropping a stream that was not shut
//!   down resets it (Go: request-context cancel → RST_STREAM).
//! - **Limits**: the least-loaded session is reused while it carries fewer
//!   than 8 active streams (sing-mux `client.go` `offer` with the default
//!   `min_streams = 8`), otherwise a new session is dialed; a stale session
//!   (GOAWAY, I/O error) is invalidated and redialed once, like sing-mux
//!   `openStream`'s two attempts. A session with no active streams for 60s
//!   is gracefully closed.
//!
//! # Divergence from sing-box
//!
//! sing-box runs the proxy protocol handshake (e.g. trojan) on the *outer*
//! connection with the dummy destination `sp.mux.sing-box.arpa:444` and
//! prepends a per-stream `StreamRequest` header (`flags(2) | addr`) with the
//! real destination, so stream payloads are raw bytes. honk instead
//! hands each h2 stream to the proxy handler, which writes its normal
//! per-connection handshake (carrying the real target) onto the stream —
//! the transport layer never sees the target address, so the sing-mux
//! `StreamRequest` layer cannot be emitted here. Interop with official
//! sing-box multiplex inbounds is therefore **not** established; the h2
//! framing layer itself (session header, pseudo-headers, DATA flow,
//! END_STREAM semantics) follows sing-mux exactly.
//!
//! Sessions are cached per `(host, port, tls, sni)` — the TLS identity of
//! the server. Nodes that differ only in credentials share a session, the
//! same way sing-mux sessions are destination-agnostic.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Reason, RecvStream, SendStream};
use honk_config::node::Node;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Notify, watch};

use super::AsyncReadWrite;

/// sing-mux session request version: Version0 (no padding) — `protocol.go`.
const SESSION_REQUEST_VERSION: u8 = 0;
/// sing-mux protocol identifier for h2mux — `protocol.go` ProtocolH2Mux.
const SESSION_REQUEST_PROTOCOL_H2MUX: u8 = 2;
/// Soft per-session stream cap: sing-mux defaults to `min_streams = 8` when
/// neither `max_streams` nor `max_connections` is configured (`client.go`
/// `NewClient`); `offer` reuses the least-loaded session below this count
/// and dials a new one at/above it.
const SOFT_MAX_STREAMS_PER_SESSION: usize = 8;
/// Close a session that has carried no streams for this long.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout for the h2 handshake on a caller-provided stream (sing-mux
/// `TCPTimeout` parity); session dials use the caller's connect timeout.
const SESSION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Pool key for a node: `host:port` plus the auth/TLS fingerprint, so two
/// nodes sharing an endpoint but differing in password/SNI/verify never
/// share a session (anytls `pool_key` parity).
fn pool_key(node: &Node) -> String {
    let password = node.password.as_deref().unwrap_or("");
    let pw_hash = &blake3::hash(password.as_bytes()).to_hex().as_str()[..8].to_string();
    format!(
        "{}:{}|{}|{}|{}|{}",
        node.host(),
        node.port,
        node.tls,
        node.sni.as_deref().unwrap_or(""),
        pw_hash,
        node.skip_cert_verify,
    )
}

/// Shared per-session state, referenced by every open stream.
struct SessionShared {
    /// Number of currently open h2 streams on this session.
    active_streams: AtomicUsize,
    /// Broadcasts the active-stream count on every change; the idle watcher
    /// sleeps until the count has stayed 0 for [`SESSION_IDLE_TIMEOUT`].
    active_watch: watch::Sender<usize>,
    /// Set once the h2 connection driver has finished (peer GOAWAY/close,
    /// I/O error) or the manager invalidated the session — it must not be
    /// offered again.
    closed: AtomicBool,
    /// Wakes the connection driver for a graceful shutdown (idle close /
    /// invalidation).
    close_notify: Notify,
}

/// A cached h2mux session (one HTTP/2 client connection).
struct MuxSession {
    send_request: SendRequest<Bytes>,
    shared: Arc<SessionShared>,
}

impl crate::session::ManagedSession for MuxSession {
    fn active_streams(&self) -> usize {
        self.shared.active_streams.load(Ordering::Acquire)
    }
    fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
    fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.close_notify.notify_one();
    }
}

/// Process-wide h2mux session pool ([`SessionPool`] — hard session cap,
/// least-loaded scheduling, dial single-flight + backoff; the idle watcher
/// below keeps the precise 60s zero-stream close).
static POOL: LazyLock<crate::session::SessionPool<MuxSession>> = LazyLock::new(|| {
    crate::session::SessionPool::new(crate::session::SessionPoolConfig {
        max_streams_per_session: SOFT_MAX_STREAMS_PER_SESSION,
        ..Default::default()
    })
});

/// Open a multiplexed stream for `node` on a shared h2mux session, dialing
/// a session on demand. This is the `connect_transport` mux branch.
pub(crate) async fn open_stream(
    node: &Node,
    connect_timeout: Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let key = pool_key(node);
    let mut last_err: Option<anyhow::Error> = None;
    for _attempt in 0..2 {
        let dial_node = node.clone();
        let dial_key = key.clone();
        let session = match POOL
            .offer(&key, move || async move {
                dial_session(&dial_node, &dial_key, connect_timeout).await
            })
            .await
        {
            Ok(session) => session,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        match session.open_stream().await {
            Ok(stream) => return Ok(Box::new(stream)),
            Err(e) => {
                POOL.invalidate(&key, &session);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("open_stream attempts always record an error"))
}

/// Build a shared h2mux session on an already-connected (TLS-wrapped)
/// stream — the `wrap_transport` pooled-TCP path — and open a stream on it.
pub(crate) async fn open_stream_on(
    node: &Node,
    stream: Box<dyn AsyncReadWrite>,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let key = pool_key(node);
    let session = build_session(stream, SESSION_HANDSHAKE_TIMEOUT, &key).await?;
    POOL.insert(&key, &session);
    match session.open_stream().await {
        Ok(stream) => Ok(Box::new(stream)),
        Err(e) => {
            // The session is brand new; a failed first stream means it is
            // broken — do not leave it in the cache.
            POOL.invalidate(&key, &session);
            Err(e)
        }
    }
}

/// Dial a fresh session: TCP (+TLS) to the node server, then the h2
/// handshake.
async fn dial_session(
    node: &Node,
    key: &str,
    connect_timeout: Duration,
) -> anyhow::Result<Arc<MuxSession>> {
    let addr = format!("{}:{}", node.host(), node.port);
    let tcp = crate::util::connect_outbound(&addr, connect_timeout).await?;
    let stream = super::transport::maybe_tls_wrap(node, tcp).await?;
    build_session(stream, connect_timeout, key).await
}

/// Write the sing-mux session header, run the h2 client handshake, and
/// spawn the connection driver + idle watcher.
async fn build_session(
    mut stream: Box<dyn AsyncReadWrite>,
    handshake_timeout: Duration,
    key: &str,
) -> anyhow::Result<Arc<MuxSession>> {
    // sing-mux session request header, prepended to the first write
    // (the h2 client preface follows) — `protocol_conn.go` Write.
    stream
        .write_all(&[SESSION_REQUEST_VERSION, SESSION_REQUEST_PROTOCOL_H2MUX])
        .await?;
    stream.flush().await?;
    let (send_request, connection) =
        tokio::time::timeout(handshake_timeout, h2::client::handshake(stream))
            .await
            .map_err(|_| anyhow::anyhow!("h2mux: HTTP/2 handshake timed out"))??;
    let shared = Arc::new(SessionShared {
        active_streams: AtomicUsize::new(0),
        active_watch: watch::channel(0).0,
        closed: AtomicBool::new(false),
        close_notify: Notify::new(),
    });
    let session = Arc::new(MuxSession {
        send_request,
        shared,
    });
    spawn_connection_driver(connection, Arc::clone(&session.shared));
    spawn_idle_watcher(key, Arc::downgrade(&session));
    Ok(session)
}

impl MuxSession {
    /// Open one h2 stream: CONNECT request, 200 OK expected, then the
    /// request/response bodies are the byte pipe (sing-mux `h2mux.go` Open).
    async fn open_stream(&self) -> anyhow::Result<MuxStream> {
        if self.shared.closed.load(Ordering::Acquire) {
            anyhow::bail!("h2mux session is closed");
        }
        let mut send_request = self
            .send_request
            .clone()
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("h2mux session not ready: {}", e))?;
        // Plain CONNECT: the `h2` crate (like Go's http2) omits :scheme and
        // :path for non-extended CONNECT, emitting exactly `:method:
        // CONNECT` + `:authority: localhost`.
        let request = http::Request::builder()
            .version(http::Version::HTTP_2)
            .method(http::Method::CONNECT)
            .uri("https://localhost")
            .body(())
            .expect("static h2mux CONNECT request must build");
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(|e| anyhow::anyhow!("h2mux stream open failed: {}", e))?;
        // sing-mux cancels the request if it has not completed within
        // TCPTimeout (h2mux.go Open): the 200 OK is written by the server
        // as soon as the stream is accepted, so a long wait means the
        // session is broken, not slow.
        let response = tokio::time::timeout(SESSION_HANDSHAKE_TIMEOUT, response)
            .await
            .map_err(|_| anyhow::anyhow!("h2mux stream response timed out"))?
            .map_err(|e| anyhow::anyhow!("h2mux stream response failed: {}", e))?;
        if response.status() != http::StatusCode::OK {
            anyhow::bail!("h2mux: unexpected status: {}", response.status());
        }
        let active = self.shared.active_streams.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.shared.active_watch.send(active);
        Ok(MuxStream {
            send,
            recv: response.into_body(),
            read_buf: Bytes::new(),
            write_closed: false,
            shared: Arc::clone(&self.shared),
        })
    }
}

/// Drive the h2 connection until it ends (peer GOAWAY/close, I/O error, or
/// a manager-requested shutdown), then mark the session closed so
/// [`MuxManager::offer`] stops handing it out.
///
/// The h2 client `Connection` has no shutdown method of its own — it closes
/// once the last `SendRequest` handle is gone — so a requested shutdown
/// simply drops the connection, closing the socket. Shutdown is only
/// requested when the session is idle (no streams) or broken, so nothing
/// in flight is hurt.
fn spawn_connection_driver(
    mut connection: h2::client::Connection<Box<dyn AsyncReadWrite>, Bytes>,
    shared: Arc<SessionShared>,
) {
    tokio::spawn(async move {
        tokio::select! {
            result = &mut connection => {
                if let Err(e) = result {
                    tracing::debug!(error = %e, "h2mux session connection error");
                }
            }
            _ = shared.close_notify.notified() => {}
        }
        drop(connection);
        shared.closed.store(true, Ordering::Release);
    });
}

/// Gracefully close the session once its stream count has stayed at zero
/// for [`SESSION_IDLE_TIMEOUT`]; exits when the session is gone.
fn spawn_idle_watcher(key: &str, session: Weak<MuxSession>) {
    let key = key.to_string();
    tokio::spawn(async move {
        let Some(strong) = session.upgrade() else {
            return;
        };
        // The receiver alone does not keep the sender alive: when the
        // session and all its streams are dropped, `changed` errors out.
        let mut rx = strong.shared.active_watch.subscribe();
        drop(strong);
        loop {
            while *rx.borrow_and_update() != 0 {
                if rx.changed().await.is_err() {
                    return;
                }
            }
            // Zero streams: any change restarts the idle clock; no change
            // for SESSION_IDLE_TIMEOUT closes the session.
            if tokio::time::timeout(SESSION_IDLE_TIMEOUT, rx.changed())
                .await
                .is_err()
            {
                if let Some(strong) = session.upgrade() {
                    POOL.invalidate(&key, &strong);
                }
                return;
            }
        }
    });
}

/// One multiplexed h2 stream exposed as an `AsyncRead + AsyncWrite` byte
/// pipe. Dropping the stream before a clean shutdown resets it (h2 sends
/// RST_STREAM), mirroring Go's request-context cancellation.
pub(crate) struct MuxStream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Unconsumed remainder of the last DATA chunk.
    read_buf: Bytes,
    /// END_STREAM already sent (poll_shutdown) — no reset needed on drop.
    write_closed: bool,
    shared: Arc<SessionShared>,
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream")
            .field(
                "active_streams",
                &self.shared.active_streams.load(Ordering::Relaxed),
            )
            .field("write_closed", &self.write_closed)
            .finish_non_exhaustive()
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let active = self.shared.active_streams.fetch_sub(1, Ordering::AcqRel) - 1;
        let _ = self.shared.active_watch.send(active);
        if !self.write_closed {
            // Go cancels the request context on close, which resets a
            // mid-flight stream; do the same when the send side was never
            // closed cleanly.
            self.send.send_reset(Reason::CANCEL);
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                // Return the consumed window to the connection so the peer
                // is not throttled (h2 does not auto-release capacity).
                let _ = self.recv.flow_control().release_capacity(chunk.len());
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.read_buf = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
            // Stream error (e.g. RST_STREAM) → I/O error.
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            // Peer END_STREAM → clean EOF.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2mux stream write side is closed",
            )));
        }
        self.send.reserve_capacity(buf.len());
        match self.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let n = capacity.min(buf.len());
                self.send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(std::io::Error::other)?;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            // The stream or connection is gone.
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "h2mux stream is closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Data is handed to the h2 connection driver, which flushes it to
        // the socket on its own poll cycle; there is no per-stream buffer.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        self.write_closed = true;
        // Empty DATA frame with END_STREAM — Go closes the request body
        // pipe, which ends the upload side the same way.
        self.send
            .send_data(Bytes::new(), true)
            .map_err(std::io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::types::NodeProtocol;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn mux_node(port: u16) -> Node {
        Node {
            name: "mux-node".into(),
            // The protocol is irrelevant to the transport layer.
            protocol: NodeProtocol::Trojan,
            address: format!("127.0.0.1:{}", port),
            host: "127.0.0.1".into(),
            port,
            mux: true,
            ..Default::default()
        }
    }

    #[derive(Clone, Copy)]
    enum ServerMode {
        /// Echo every stream until the peer goes away.
        Echo,
        /// Echo the first stream to completion, then GOAWAY and close.
        GoAwayAfterFirstStream,
    }

    /// Serve one accepted connection: verify the sing-mux session header,
    /// run the h2 server handshake and handle streams per `mode`.
    async fn serve_conn(mut socket: TcpStream, mode: ServerMode) -> anyhow::Result<()> {
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await?;
        anyhow::ensure!(
            header == [SESSION_REQUEST_VERSION, SESSION_REQUEST_PROTOCOL_H2MUX],
            "bad sing-mux session header: {header:02x?}"
        );
        let mut conn = h2::server::handshake(socket).await?;
        match mode {
            ServerMode::Echo => {
                while let Some(next) = conn.accept().await {
                    let (request, respond) = next?;
                    tokio::spawn(async move {
                        let _ = echo_stream(request, respond).await;
                    });
                }
            }
            ServerMode::GoAwayAfterFirstStream => {
                let Some(next) = conn.accept().await else {
                    anyhow::bail!("connection closed before the first stream");
                };
                let (request, respond) = next?;
                // The server connection only makes I/O progress while it is
                // polled, so echo in a task and keep driving `conn` (via the
                // next `accept`) until the first stream is done.
                let mut echo = tokio::spawn(echo_stream(request, respond));
                tokio::select! {
                    result = &mut echo => { result??; }
                    _ = conn.accept() => {
                        anyhow::bail!("unexpected second stream or connection error");
                    }
                }
                conn.graceful_shutdown();
                // Drive the connection to a clean close.
                while conn.accept().await.is_some() {}
            }
        }
        Ok(())
    }

    /// Verify the sing-mux pseudo-headers, answer 200 and echo DATA frames
    /// until the request body ends (END_STREAM), then end the response —
    /// half-close propagation in both directions.
    async fn echo_stream(
        request: http::Request<RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> anyhow::Result<()> {
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.uri().authority().map(|a| a.as_str()),
            Some("localhost"),
            "sing-mux streams CONNECT to authority localhost"
        );
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        let mut recv = request.into_body();
        while let Some(chunk) = recv.data().await {
            let chunk = chunk?;
            recv.flow_control().release_capacity(chunk.len())?;
            send.send_data(chunk, false)?;
        }
        // Request END_STREAM: half-close the response side.
        send.send_data(Bytes::new(), true)?;
        Ok(())
    }

    /// Bind a listener and spawn a task serving exactly `n_connections`
    /// sequentially in `mode`; returns (port, join handle, accepted-count).
    async fn spawn_server(
        mode: ServerMode,
        n_connections: usize,
    ) -> (u16, tokio::task::JoinHandle<()>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted2 = Arc::clone(&accepted);
        let handle = tokio::spawn(async move {
            for _ in 0..n_connections {
                let (socket, _) = listener.accept().await.unwrap();
                accepted2.fetch_add(1, Ordering::AcqRel);
                serve_conn(socket, mode).await.unwrap();
            }
        });
        (port, handle, accepted)
    }

    /// Write `payload`, read back its full echo, then half-close and expect
    /// EOF (server ends the response on request END_STREAM).
    async fn echo_roundtrip(stream: &mut Box<dyn AsyncReadWrite>, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echo = vec![0u8; payload.len()];
        tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut echo))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo, payload);
        stream.shutdown().await.unwrap();
        // Peer END_STREAM must surface as read EOF.
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "expected EOF after peer END_STREAM");
    }

    /// One mux session carries 3 concurrent streams over a single TCP
    /// connection, each with its own payload.
    #[tokio::test]
    async fn test_mux_concurrent_streams_single_connection() {
        let (port, server, accepted) = spawn_server(ServerMode::Echo, 1).await;
        let node = mux_node(port);

        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(
                open_stream(&node, TEST_TIMEOUT)
                    .await
                    .expect("open mux stream"),
            );
        }

        // Interleave writes before reads so the streams are genuinely
        // concurrent on the wire.
        let payloads: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                format!("stream-{i}-")
                    .into_bytes()
                    .into_iter()
                    .cycle()
                    .take(8192)
                    .collect()
            })
            .collect();
        for (stream, payload) in streams.iter_mut().zip(&payloads) {
            stream.write_all(payload).await.unwrap();
        }
        for (stream, payload) in streams.iter_mut().zip(&payloads) {
            let mut echo = vec![0u8; payload.len()];
            tokio::time::timeout(TEST_TIMEOUT, stream.read_exact(&mut echo))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&echo, payload);
        }
        drop(streams);

        assert_eq!(accepted.load(Ordering::Acquire), 1);
        // The echo server runs until the connection dies; do not join it.
        drop(server);
    }

    /// The `wrap_transport` pooled-TCP path: an already-connected raw TCP
    /// stream is upgraded to a shared h2mux session and one stream on it.
    #[tokio::test]
    async fn test_mux_wrap_transport_on_connected_tcp() {
        let (port, server, _accepted) = spawn_server(ServerMode::Echo, 1).await;
        let node = mux_node(port);

        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut stream = super::super::transport::wrap_transport(&node, tcp)
            .await
            .expect("wrap_transport with mux");
        echo_roundtrip(&mut stream, b"pooled").await;
        drop(stream);
        drop(server);
    }

    /// Write-side shutdown sends END_STREAM; the server's response
    /// END_STREAM propagates back as read EOF.
    #[tokio::test]
    async fn test_mux_half_close_propagation() {
        let (port, server, _accepted) = spawn_server(ServerMode::Echo, 1).await;
        let node = mux_node(port);

        let mut stream = open_stream(&node, TEST_TIMEOUT)
            .await
            .expect("open mux stream");
        echo_roundtrip(&mut stream, b"ping").await;
        drop(stream);
        drop(server);
    }

    /// After the server sends GOAWAY and closes, the next stream is opened
    /// on a freshly dialed session (new TCP connection).
    #[tokio::test]
    async fn test_mux_goaway_redial() {
        let (port, server, accepted) = spawn_server(ServerMode::GoAwayAfterFirstStream, 2).await;
        let node = mux_node(port);

        // First stream: full echo + half-close, then the server GOAWAYs.
        let mut stream = open_stream(&node, TEST_TIMEOUT)
            .await
            .expect("open first mux stream");
        echo_roundtrip(&mut stream, b"first").await;
        drop(stream);

        // Let the GOAWAY/EOF reach the connection driver.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Second stream must transparently redial a new session.
        let mut stream = open_stream(&node, TEST_TIMEOUT)
            .await
            .expect("open mux stream after GOAWAY");
        echo_roundtrip(&mut stream, b"second").await;
        drop(stream);

        tokio::time::timeout(TEST_TIMEOUT, server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.load(Ordering::Acquire), 2);
    }

    /// mux wins over a configured WS/gRPC transport (sing-box: multiplex
    /// and transport are mutually exclusive) — the server must see the
    /// sing-mux session header, not a WebSocket upgrade.
    #[tokio::test]
    async fn test_mux_ignores_ws_transport() {
        let (port, server, _accepted) = spawn_server(ServerMode::Echo, 1).await;
        let mut node = mux_node(port);
        node.transport = "ws".into();
        node.ws_path = Some("/ignored".into());

        let mut stream = super::super::transport::connect_transport(&node, TEST_TIMEOUT)
            .await
            .expect("connect_transport with mux + ws");
        echo_roundtrip(&mut stream, b"via-mux").await;
        drop(stream);
        drop(server);
    }

    /// mux=false keeps the raw-TCP path byte-identical (the returned stream
    /// is a plain `TcpStream`, no session header is written).
    #[tokio::test]
    async fn test_mux_disabled_raw_tcp_unchanged() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // First two bytes must be the application payload, not the
            // sing-mux session header.
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            socket.write_all(b"pong").await.unwrap();
        });

        let mut node = mux_node(port);
        node.mux = false;
        let stream = super::super::transport::connect_transport(&node, TEST_TIMEOUT)
            .await
            .expect("connect_transport without mux");
        assert!(
            // `(*stream).as_any()` — vtable dispatch past the Box, see
            // `ProxyStream::into_tcp_stream`.
            (*stream).as_any().is::<TcpStream>(),
            "mux=false must return the raw TcpStream"
        );

        let mut stream = stream;
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        server.await.unwrap();
    }

    /// 4B decision gate: honk's h2mux against an **official sing-box
    /// multiplex inbound**. honk writes the proxy handshake onto each h2
    /// stream instead of sing-mux's outer handshake + per-stream
    /// StreamRequest, so this tells us whether the two are compatible.
    /// Run with:
    ///   sing-box run -c /tmp/lab-bin/sb-mux-h2.json   # trojan+multiplex on :2448
    ///   cargo test -p honk-outbound --lib trojan_mux_against_sing_box -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a sing-box multiplex server on 127.0.0.1:2448"]
    async fn trojan_mux_against_sing_box() {
        let node = Node {
            name: "trojan-mux".into(),
            protocol: NodeProtocol::Trojan,
            address: "127.0.0.1:2448".into(),
            host: "127.0.0.1".into(),
            port: 2448,
            password: Some("testpass123".into()),
            tls: true,
            skip_cert_verify: true,
            mux: true,
            ..Default::default()
        };
        let handler = crate::proxy::trojan::TrojanHandler::new();
        let target: SocketAddr = "127.0.0.1:8000".parse().unwrap();
        let stream = crate::proxy::ProxyHandler::dial(&handler, &node, target, None, TEST_TIMEOUT)
            .await
            .expect("mux dial failed");
        let mut stream = stream.stream;
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 512];
        let n = stream.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.contains(" 200") || resp.contains(" 301") || resp.contains(" 404"),
            "mux request did not get an HTTP status: {}",
            &resp[..resp.len().min(160)]
        );
    }
}
