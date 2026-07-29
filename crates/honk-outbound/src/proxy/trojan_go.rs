//! Trojan-Go proxy handler with mux support.
//!
//! Trojan-Go extends Trojan-GFW with connection multiplexing: a single
//! TCP connection carries multiple logical streams identified by a
//! 2-byte stream ID. The `CommandMux` byte (`0x7f`) replaces the
//! standard `CMD_TCP`/`CMD_UDP` bytes.
//!
//! ## Protocol
//!
//! **Stream open** (first frame on a new stream):
//! ```text
//! SHA224(password) hex 56B | CRLF | 0x7f | stream_id(2B BE) | address | CRLF
//! ```
//!
//! **Data frames** (after stream is open):
//! ```text
//! stream_id(2B BE) | length(2B BE) | payload(length)
//! ```
//!
//! ## Architecture
//!
//! Each unique `host:port` pair gets a single reusable mux connection.
//! Per-stream proxy data is bridged through internal channels:
//!
//! - A global demux task reads from the TCP connection and routes
//!   incoming frames to the correct per-stream channel.
//! - A per-stream bridge task reads from the stream's write channel
//!   and writes framed data to the shared TCP connection.
//!
//! Reference: <https://p4gefau1t.github.io/trojan-go/developer/protocol/>

use async_trait::async_trait;
use honk_config::node::Node;
use honk_config::types::NodeProtocol;
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::addr::encode_address;
use super::{AsyncReadWrite, ProxyHandler, ProxyStream};

const CRLF: &[u8] = b"\r\n";
const CMD_MUX: u8 = 0x7f;

/// Trojan-Go proxy handler with multiplexing.
pub struct TrojanGoHandler {
    /// Connection pool: `host:port|fingerprint` → mux connections
    /// (SessionPool: hard cap, dial single-flight + backoff).
    pool: crate::session::SessionPool<MuxConnection>,
}

impl Default for TrojanGoHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl TrojanGoHandler {
    pub fn new() -> Self {
        Self {
            pool: crate::session::SessionPool::new(crate::session::SessionPoolConfig {
                // One mux connection per key is the norm; scheduling is
                // least-loaded without a stream cap.
                max_streams_per_session: usize::MAX,
                ..Default::default()
            }),
        }
    }

    fn build_tls_connector(node: &Node) -> anyhow::Result<crate::tls::TlsConnector> {
        crate::tls::build_connector(node)
    }

    async fn connect_server(
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let addr = format!("{}:{}", node.host(), node.port);
        let stream = crate::util::connect_outbound(&addr, connect_timeout).await?;
        let stream: Box<dyn AsyncReadWrite> = if node.tls {
            let connector = Self::build_tls_connector(node)?;
            let server_name = node.sni.clone().unwrap_or_else(|| node.host().to_string());
            Box::new(crate::tls::BatchRead::new(
                connector.connect(&server_name, stream).await?,
            ))
        } else {
            Box::new(stream)
        };
        Ok(stream)
    }

    /// Get or create a mux connection for the given node.
    async fn get_mux(
        &self,
        node: &Node,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Arc<MuxConnection>> {
        // Pool key = host:port + auth/TLS fingerprint, so nodes sharing an
        // endpoint but differing in password/SNI/verify never share a mux
        // connection (and a reload changing those can't reuse a stale one).
        let host_key = {
            let pw_hash = &blake3::hash(node.password.as_deref().unwrap_or("").as_bytes())
                .to_hex()
                .as_str()[..8]
                .to_string();
            format!(
                "{}:{}|{}|{}|{}|{}",
                node.host(),
                node.port,
                pw_hash,
                node.sni.as_deref().unwrap_or(""),
                node.skip_cert_verify,
                node.tls
            )
        };
        let dial_node = node.clone();
        let dial_host_key = host_key.clone();
        self.pool
            .offer(&host_key, move || async move {
                let stream = Self::connect_server(&dial_node, connect_timeout).await?;
                let (mux, read_half) = MuxConnection::new(dial_host_key.clone(), stream);
                let mux = Arc::new(mux);
                mux.spawn_demux_task(read_half);
                Ok(mux)
            })
            .await
    }
}

/// A single multiplexed connection to a Trojan-Go server.
///
/// The connection is split at setup: the demux task owns the read half
/// (no lock), writers share the write half under a mutex. Previously one
/// mutex covered both, so the demux task held it across `read().await`
/// and every writer starved until data arrived (P0 audit, trojan_go.rs).
struct MuxConnection {
    #[allow(dead_code)]
    host_key: String,
    writer: Arc<tokio::sync::Mutex<WriteHalf<Box<dyn AsyncReadWrite>>>>,
    readers: Arc<Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>,
    next_id: AtomicU16,
    closed: AtomicBool,
    /// First close reason wins; kept for diagnostics (later failures do
    /// not overwrite it).
    close_reason: Mutex<Option<String>>,
}

impl std::fmt::Debug for MuxConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxConnection")
            .field("host_key", &self.host_key)
            .field("next_id", &self.next_id)
            .field("closed", &self.closed)
            .field("close_reason", &self.close_reason)
            .finish_non_exhaustive()
    }
}

impl MuxConnection {
    fn new(
        host_key: String,
        conn: Box<dyn AsyncReadWrite>,
    ) -> (Self, ReadHalf<Box<dyn AsyncReadWrite>>) {
        let (read_half, write_half) = tokio::io::split(conn);
        (
            Self {
                host_key,
                writer: Arc::new(tokio::sync::Mutex::new(write_half)),
                readers: Arc::new(Mutex::new(HashMap::new())),
                next_id: AtomicU16::new(0),
                closed: AtomicBool::new(false),
                close_reason: Mutex::new(None),
            },
            read_half,
        )
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Close the connection: flag it, EOF every stream (their senders
    /// drop), and shut the write half down. Idempotent.
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.readers.lock().unwrap().clear();
        let writer = Arc::clone(&self.writer);
        tokio::spawn(async move {
            let _ = writer.lock().await.shutdown().await;
        });
    }

    /// Fail the connection once: record the first close reason, then
    /// close (every logical stream EOFs, no new streams are served).
    /// The pool prunes on the next offer pass — the session does not
    /// back-reference the pool.
    fn fail_session(&self, reason: impl Into<String>) {
        {
            let mut slot = self.close_reason.lock().unwrap();
            if slot.is_none() {
                *slot = Some(reason.into());
            }
        }
        self.close();
    }

    fn alloc_stream_id(&self) -> u16 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    /// Spawn a background task that reads from the TCP connection,
    /// demuxes frames by stream_id, and routes payloads to the
    /// appropriate per-stream channel.
    fn spawn_demux_task(self: &Arc<Self>, mut read_half: ReadHalf<Box<dyn AsyncReadWrite>>) {
        let readers = Arc::clone(&self.readers);
        let this = Arc::clone(self);

        self.closed.store(false, Ordering::Release);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut carry = Vec::new();
            loop {
                let n = match read_half.read(&mut buf).await {
                    Ok(0) => {
                        this.fail_session("demux read EOF");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!("TrojanGo mux read error: {}", e);
                        this.fail_session(format!("demux read error: {e}"));
                        break;
                    }
                };
                let read_data = &buf[..n];

                let mut data = carry;
                data.extend_from_slice(read_data);
                carry = Vec::new();

                let mut offset = 0;
                while offset + 4 <= data.len() {
                    let stream_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                    offset += 4;

                    if offset + len > data.len() {
                        // Partial frame — carry over to next read
                        carry = data[offset - 4..].to_vec();
                        break;
                    }
                    let payload = data[offset..offset + len].to_vec();
                    offset += len;

                    let tx = readers.lock().unwrap().get(&stream_id).cloned();
                    if let Some(tx) = tx {
                        // Bounded per-stream queue with backpressure (TCP
                        // data must not be dropped).
                        let _ = tx.send(payload).await;
                    }
                }
            }
        });
    }
}

impl crate::session::ManagedSession for MuxConnection {
    fn active_streams(&self) -> usize {
        self.readers.lock().unwrap().len()
    }
    fn is_closed(&self) -> bool {
        self.is_closed()
    }
    fn close(&self) {
        MuxConnection::close(self)
    }
}

#[async_trait]
impl ProxyHandler for TrojanGoHandler {
    fn protocol(&self) -> NodeProtocol {
        NodeProtocol::TrojanGo
    }

    /// Multiplexed (own smux-style mux on SessionPool): bare-TCP pooling
    /// would force a new mux session per flow — see AnyTlsHandler.
    fn pool_bare_tcp(&self, _node: &Node) -> bool {
        false
    }

    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let password = node.password.as_deref().unwrap_or("");
        let mux = self.get_mux(node, connect_timeout).await?;
        if mux.is_closed() {
            anyhow::bail!("Trojan-Go mux connection is closed");
        }
        let stream_id = mux.alloc_stream_id();

        let header = build_mux_header(password, stream_id, target, target_domain);

        // Inbound (demux → stream): bounded frames with demux backpressure.
        let (read_tx, read_rx) = mpsc::channel(64);
        // Outbound (stream → conn): a bounded duplex (64 KiB) so a slow
        // connection backpressures the writer instead of growing a queue.
        let (client_write, mut stream_read) = tokio::io::duplex(64 * 1024);

        {
            let mut readers = mux.readers.lock().unwrap();
            readers.insert(stream_id, read_tx);
        }

        {
            let mut w = mux.writer.lock().await;
            w.write_all(&header).await?;
        }

        let writer = Arc::clone(&mux.writer);
        let mux_for_fail = Arc::clone(&mux);
        let sid = stream_id;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match stream_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut frame = Vec::with_capacity(4 + n);
                        frame.extend_from_slice(&sid.to_be_bytes());
                        frame.extend_from_slice(&(n as u16).to_be_bytes());
                        frame.extend_from_slice(&buf[..n]);
                        let mut w = writer.lock().await;
                        if w.write_all(&frame).await.is_err() {
                            // A failed frame write breaks the session's
                            // framing: propagate to every logical stream.
                            mux_for_fail.fail_session("frame write error");
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let proxy_stream =
            MuxProxyStream::new(stream_id, read_rx, client_write, Arc::clone(&mux.readers));

        Ok(ProxyStream {
            stream: Box::new(proxy_stream),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }

    async fn dial_with_tcp(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        // dial_with_tcp with connection pooling isn't meaningful for
        // TrojanGo since it already multiplexes. Delegate to dial.
        self.dial(_node, target, target_domain, connect_timeout)
            .await
    }
}

/// Build the Trojan-Go mux request header.
///
/// Format: `hex_sha224(password) + CRLF + CMD_MUX + stream_id(2) + address + CRLF`
fn build_mux_header(
    password: &str,
    stream_id: u16,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Vec<u8> {
    let hash = hex_sha224(password);
    let addr = encode_address(target, target_domain);
    let mut header = Vec::with_capacity(56 + 2 + 1 + 2 + addr.len() + 2);
    header.extend_from_slice(hash.as_bytes());
    header.extend_from_slice(CRLF);
    header.push(CMD_MUX);
    header.extend_from_slice(&stream_id.to_be_bytes());
    header.extend_from_slice(&addr);
    header.extend_from_slice(CRLF);
    header
}

struct MuxProxyStream {
    stream_id: u16,
    read_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    write_half: tokio::io::DuplexStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    readers: Arc<Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>,
}

impl std::fmt::Debug for MuxProxyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxProxyStream")
            .field("stream_id", &self.stream_id)
            .field("read_buf_len", &self.read_buf.len())
            .field("read_pos", &self.read_pos)
            .finish_non_exhaustive()
    }
}

impl MuxProxyStream {
    fn new(
        stream_id: u16,
        read_rx: mpsc::Receiver<Vec<u8>>,
        write_half: tokio::io::DuplexStream,
        readers: Arc<Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>,
    ) -> Self {
        Self {
            stream_id,
            read_rx: Mutex::new(read_rx),
            write_half,
            read_buf: Vec::new(),
            read_pos: 0,
            readers,
        }
    }
}

impl Drop for MuxProxyStream {
    fn drop(&mut self) {
        let mut readers = self.readers.lock().unwrap();
        readers.remove(&self.stream_id);
    }
}

impl AsyncRead for MuxProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        let available = this.read_buf.len() - this.read_pos;
        if available > 0 {
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        let msg = {
            let mut rx = this.read_rx.lock().unwrap();
            match rx.poll_recv(cx) {
                Poll::Ready(Some(msg)) => msg,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        };

        this.read_buf = msg;
        this.read_pos = 0;
        let to_copy = this.read_buf.len().min(buf.remaining());
        buf.put_slice(&this.read_buf[..to_copy]);
        this.read_pos = to_copy;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Bounded duplex: a full buffer backpressures here (Pending) until
        // the forward task drains it into the connection.
        Pin::new(&mut self.get_mut().write_half).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().write_half).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().write_half).poll_shutdown(cx)
    }
}

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

    /// 0.5.3: a physical EOF on the demux read half must propagate —
    /// the session closes and every logical stream's receiver EOFs
    /// (previously only the closed flag was set and streams hung).
    #[tokio::test]
    async fn test_demux_eof_fails_session_and_streams() {
        let (client_end, server_end) = tokio::io::duplex(4096);
        let (conn, read_half) = MuxConnection::new("test:443".into(), Box::new(client_end));
        let conn = Arc::new(conn);
        conn.spawn_demux_task(read_half);

        let (tx, mut rx) = mpsc::channel(8);
        conn.readers.lock().unwrap().insert(1, tx);

        drop(server_end); // physical EOF
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("stream never EOFed after physical EOF");
        assert!(conn.is_closed());
        assert_eq!(
            conn.close_reason.lock().unwrap().as_deref(),
            Some("demux read EOF")
        );
        // First close reason wins.
        conn.fail_session("later failure");
        assert_eq!(
            conn.close_reason.lock().unwrap().as_deref(),
            Some("demux read EOF")
        );
    }

    #[test]
    fn test_mux_header_basic() {
        let password = "test";
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let stream_id = 42u16;

        let header = build_mux_header(password, stream_id, target, None);
        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_MUX);
        assert_eq!(&header[59..61], &stream_id.to_be_bytes());
        assert_eq!(header[61], crate::proxy::addr::ATYP_IPV4);
        assert_eq!(&header[62..66], &[93, 184, 216, 34]);
        assert_eq!(&header[66..68], &[0x00, 0x50]);
        assert_eq!(&header[68..70], CRLF);
    }

    #[test]
    fn test_mux_header_domain() {
        let password = "pw";
        let target: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let stream_id = 256u16;
        let domain = "example.org";

        let header = build_mux_header(password, stream_id, target, Some(domain));
        let expected_hash = hex_sha224(password);
        assert_eq!(&header[..56], expected_hash.as_bytes());
        assert_eq!(&header[56..58], CRLF);
        assert_eq!(header[58], CMD_MUX);
        assert_eq!(&header[59..61], &stream_id.to_be_bytes());
        assert_eq!(header[61], crate::proxy::addr::ATYP_DOMAIN);
        assert_eq!(header[62], domain.len() as u8);
        assert_eq!(&header[63..74], domain.as_bytes());
        assert_eq!(&header[74..76], &[0x01, 0xbb]);
    }

    #[test]
    fn test_stream_id_alloc_skips_zero() {
        let (conn, _rd) =
            MuxConnection::new("test:443".into(), Box::new(tokio::io::duplex(1024).0));
        let id = conn.alloc_stream_id();
        assert_ne!(id, 0);
        let id2 = conn.alloc_stream_id();
        assert_ne!(id, id2);
        assert_ne!(id2, 0);
    }
}
