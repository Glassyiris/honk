//! TCP connection pool for proxy dials.
//!
//! Two entry kinds, both capped at 8 per key and 300s max age:
//!
//! - **Bare** — a pre-handshake `TcpStream` to the proxy server (60s idle
//!   TTL), keyed by the server's `"host:port"` and reused via
//!   `ProxyHandler::dial_with_tcp`. Saves the TCP connect RTT only.
//! - **Ready** — a fully-dialed `ProxyStream` whose protocol handshake is
//!   complete (SOCKS5 CONNECT done, Trojan TLS + request header written),
//!   reused *directly* as the data channel with no handshake at all.
//!   Idle TTL is shorter (30s): a target-bound tunnel holds more
//!   server-side state than a bare TCP connection and servers reap idle
//!   tunnels sooner.
//!
//! Ready keys are namespaced (`ready|<node_addr>|<target>`) so they can
//! never collide with bare `"host:port"` keys (`|` cannot appear in a
//! host:port pair). The key binds BOTH the proxy node and the target
//! because the completed handshake already committed the stream to that
//! exact pair — lookup by the same pair is the only correct reuse.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, trace};

use honk_outbound::proxy::ProxyStream;

const MAX_PER_HOST: usize = 8;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle TTL for Ready (handshake-completed) entries — shorter than Bare
/// because a target-bound tunnel holds more server-side state and servers
/// typically reap idle tunnels sooner.
const READY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);

/// A pooled connection. Each key's list holds exactly one kind: the key
/// namespaces (`"host:port"` vs `ready|...`) make mixing impossible.
enum PooledStream {
    /// Pre-handshake TCP to the proxy server; reused via `dial_with_tcp`.
    Bare(TcpStream),
    /// Fully-dialed, target-bound data channel; reused as-is.
    Ready(ProxyStream),
}

struct TimedStream {
    stream: PooledStream,
    created: Instant,
    last_used: Instant,
}

pub(crate) struct ConnectionPool {
    entries: DashMap<String, Arc<Mutex<Vec<TimedStream>>>>,
    total_entries: AtomicU64,
    idle_timeout: Duration,
    ready_idle_timeout: Duration,
    max_age: Duration,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            total_entries: AtomicU64::new(0),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            ready_idle_timeout: READY_IDLE_TIMEOUT,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    #[cfg(test)]
    fn set_ready_idle_timeout(&mut self, timeout: Duration) {
        self.ready_idle_timeout = timeout;
    }

    /// Pool key for a Ready entry. The completed handshake bound the
    /// stream to (proxy node, target), so the key contains both; with
    /// domain routing the CONNECT request carries the domain, making
    /// `domain:port` — not the resolved IP — the destination identity.
    pub(crate) fn ready_key(
        node_addr: &str,
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> String {
        match target_domain {
            Some(domain) => format!("ready|{}|{}:{}", node_addr, domain, target.port()),
            None => format!("ready|{}|{}", node_addr, target),
        }
    }

    pub(crate) async fn acquire_tcp(&self, addr: &str) -> Option<TcpStream> {
        match self.acquire_entry(addr, false).await {
            Some(PooledStream::Bare(tcp)) => Some(tcp),
            _ => None,
        }
    }

    /// Take a Ready stream for `key`, if one is pooled, unexpired, and
    /// alive. The entry is removed from the pool: a ready stream serves
    /// exactly one connection and is never returned after use.
    pub(crate) async fn acquire_ready(&self, key: &str) -> Option<ProxyStream> {
        match self.acquire_entry(key, true).await {
            Some(PooledStream::Ready(stream)) => Some(stream),
            _ => None,
        }
    }

    async fn acquire_entry(&self, addr: &str, want_ready: bool) -> Option<PooledStream> {
        // Clone the Arc from DashMap, releasing the shard lock immediately.
        let arc = Arc::clone(&*self.entries.get(addr)?);
        let mut list = arc.lock().unwrap();

        let now = Instant::now();
        let mut found_idx: Option<usize> = None;
        for (i, entry) in list.iter().rev().enumerate() {
            let idx = list.len() - 1 - i;
            if !Self::entry_matches(entry, want_ready) {
                continue;
            }
            if self.entry_expired(entry, now) {
                continue;
            }
            if Self::is_entry_alive(entry) {
                found_idx = Some(idx);
                break;
            }
        }

        match found_idx {
            Some(idx) => {
                let entry = list.swap_remove(idx);
                self.total_entries.fetch_sub(1, Ordering::Relaxed);
                trace!(
                    "Pool hit ({}): {} ({} idle remaining)",
                    if want_ready { "ready" } else { "bare" },
                    addr,
                    list.len()
                );
                if list.is_empty() {
                    drop(list);
                    self.entries.remove(addr);
                }
                Some(entry.stream)
            }
            None => {
                let before = list.len();
                list.retain(|e| !self.entry_expired(e, now) && Self::is_entry_alive(e));
                let removed = before - list.len();
                if removed > 0 {
                    self.total_entries
                        .fetch_sub(removed as u64, Ordering::Relaxed);
                }
                if list.is_empty() {
                    drop(list);
                    self.entries.remove(addr);
                }
                None
            }
        }
    }

    pub(crate) async fn deposit_tcp(&self, addr: &str, stream: TcpStream) {
        self.deposit_entry(addr, PooledStream::Bare(stream)).await;
    }

    /// Deposit a fully-dialed stream under `key` (see [`ready_key`]).
    /// The stream must come straight out of `ProxyHandler::dial()` with no
    /// application reads performed, so its userspace TLS buffer (if any)
    /// is empty and the fd-level liveness probe stays accurate.
    pub(crate) async fn deposit_ready(&self, key: &str, stream: ProxyStream) {
        self.deposit_entry(key, PooledStream::Ready(stream)).await;
    }

    async fn deposit_entry(&self, addr: &str, stream: PooledStream) {
        let arc = {
            let entry = self
                .entries
                .entry(addr.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
            Arc::clone(&*entry)
        };
        let mut list = arc.lock().unwrap();
        if list.len() >= MAX_PER_HOST {
            debug!("Pool cap reached for {} (max={})", addr, MAX_PER_HOST);
            return;
        }
        let now = Instant::now();
        self.total_entries.fetch_add(1, Ordering::Relaxed);
        let kind = match &stream {
            PooledStream::Bare(_) => "bare",
            PooledStream::Ready(_) => "ready",
        };
        list.push(TimedStream {
            stream,
            created: now,
            last_used: now,
        });
        debug!(
            "Pool deposit ({}): {} ({} total pooled)",
            kind,
            addr,
            self.total_entries.load(Ordering::Relaxed)
        );
    }

    /// Drop every pooled connection tied to a proxy node: the bare
    /// `"host:port"` key plus all `ready|<node_addr>|…` entries. Called
    /// when the node flips alive→dead — a pooled-but-doomed stream must
    /// never be handed out (idle/max-age expiry would otherwise keep
    /// serving it for up to 60s).
    pub(crate) fn purge_node(&self, node_addr: &str) {
        let ready_prefix = format!("ready|{}|", node_addr);
        let mut removed = 0u64;
        self.entries.retain(|key, arc| {
            if key == node_addr || key.starts_with(&ready_prefix) {
                removed += arc.lock().unwrap().len() as u64;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.total_entries.fetch_sub(removed, Ordering::Relaxed);
            debug!(
                "Purged {} pooled connections for dead node {}",
                removed, node_addr
            );
        }
    }

    pub(crate) async fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut total_removed = 0usize;
        let total_remaining = AtomicU64::new(0);

        self.entries.retain(|_addr, arc| {
            let mut list = arc.lock().unwrap();
            list.retain(|e| {
                if self.entry_expired(e, now) || !Self::is_entry_alive(e) {
                    total_removed += 1;
                    false
                } else {
                    true
                }
            });
            total_remaining.fetch_add(list.len() as u64, Ordering::Relaxed);
            !list.is_empty()
        });

        let remaining = total_remaining.load(Ordering::Relaxed);
        self.total_entries.store(remaining, Ordering::Relaxed);
        debug!(
            "Pruned {} expired pooled connections ({} remaining)",
            total_removed, remaining
        );
        total_removed
    }

    pub(crate) fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                pool.prune_expired().await;
            }
        })
    }

    fn entry_matches(entry: &TimedStream, want_ready: bool) -> bool {
        matches!(
            (&entry.stream, want_ready),
            (PooledStream::Bare(_), false) | (PooledStream::Ready(_), true)
        )
    }

    fn idle_ttl(&self, entry: &TimedStream) -> Duration {
        match &entry.stream {
            PooledStream::Bare(_) => self.idle_timeout,
            PooledStream::Ready(_) => self.ready_idle_timeout,
        }
    }

    fn entry_expired(&self, entry: &TimedStream, now: Instant) -> bool {
        now.duration_since(entry.last_used) > self.idle_ttl(entry)
            || now.duration_since(entry.created) > self.max_age
    }

    fn is_entry_alive(entry: &TimedStream) -> bool {
        match &entry.stream {
            PooledStream::Bare(tcp) => Self::is_stream_alive(tcp),
            PooledStream::Ready(stream) => Self::is_ready_stream_alive(stream),
        }
    }

    fn is_stream_alive(stream: &TcpStream) -> bool {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut err: libc::c_int = 0;
        let mut err_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut _ as *mut libc::c_void,
                &mut err_len,
            )
        };
        ret == 0 && err == 0
    }

    /// Liveness probe for Ready streams: `MSG_PEEK | MSG_DONTWAIT` on the
    /// underlying fd.
    ///
    /// - returns 0: the peer performed an orderly shutdown (FIN) — the
    ///   tunnel is dead; drop it and fall back to a normal dial.
    /// - returns >0: bytes are pending in the kernel receive buffer —
    ///   alive. For TLS streams this is ciphertext (a `close_notify` alert
    ///   counts as alive here — a false positive, but the first real read
    ///   then surfaces EOF, bounding the waste to one checkout).
    /// - `EAGAIN`/`EWOULDBLOCK`: nothing pending, connection open — alive.
    /// - `ECONNRESET`/`ENOTCONN`: dead.
    /// - any other error, or no extractable fd (non-TCP stream such as a
    ///   duplex bridge): conservatively treated as alive.
    ///
    /// Limitation: this peeks the SOCKET, not any userspace TLS buffer.
    /// rustls buffers decrypted plaintext once reads start, so bytes
    /// already pulled into rustls would be invisible here — and a peer FIN
    /// arriving after them would look like a dead connection even though
    /// buffered data remains. Pooled Ready streams are deposited straight
    /// out of `dial()` before any application read, so their rustls read
    /// buffer is empty by construction and fd-level peek is accurate.
    /// Never deposit a stream that has already been read from.
    fn is_ready_stream_alive(stream: &ProxyStream) -> bool {
        let Some(fd) = stream.raw_fd() else {
            // No probe possible (not a plain TCP/TLS stream) — conservatively alive.
            return true;
        };
        let mut buf = [0u8; 1];
        let ret = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if ret == 0 {
            return false; // orderly FIN from the peer
        }
        if ret > 0 {
            return true; // pending bytes (TLS ciphertext counts as alive)
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ECONNRESET) | Some(libc::ENOTCONN) => false,
            // EAGAIN/EWOULDBLOCK (nothing to read) and anything unexpected:
            // conservatively alive.
            _ => true,
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::node::Node;
    use honk_config::types::NodeProtocol;
    use honk_outbound::proxy::ProxyHandler;
    use honk_outbound::proxy::socks5::Socks5Handler;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_ready_stream(tcp: TcpStream, target: SocketAddr) -> ProxyStream {
        ProxyStream {
            stream: Box::new(tcp),
            target_addr: target,
            target_domain: None,
        }
    }

    /// Accept one connection and hold it open (no data, no close) so the
    /// peer's liveness probes keep reporting "alive".
    async fn spawn_hold_open_listener() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = s.read(&mut buf).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_pool_acquire_deposit() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await.to_string();

        assert!(pool.acquire_tcp(&addr).await.is_none());

        let stream = TcpStream::connect(&addr).await.unwrap();
        pool.deposit_tcp(&addr, stream).await;

        let acquired = pool.acquire_tcp(&addr).await;
        assert!(acquired.is_some());
    }

    #[tokio::test]
    async fn test_pool_per_host_cap() {
        let pool = ConnectionPool::new();
        let addr = spawn_hold_open_listener().await.to_string();

        for _ in 0..MAX_PER_HOST + 3 {
            if let Ok(s) = TcpStream::connect(&addr).await {
                pool.deposit_tcp(&addr, s).await;
            }
        }
        // Only MAX_PER_HOST entries are retained; the rest can be acquired
        // and then the pool is empty.
        for _ in 0..MAX_PER_HOST {
            assert!(pool.acquire_tcp(&addr).await.is_some());
        }
        assert!(pool.acquire_tcp(&addr).await.is_none());
    }

    #[tokio::test]
    async fn test_pool_ready_roundtrip() {
        let pool = ConnectionPool::new();
        let server_addr = spawn_hold_open_listener().await;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);

        assert!(pool.acquire_ready(&key).await.is_none());

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(&key, make_ready_stream(tcp, target))
            .await;

        let ready = pool.acquire_ready(&key).await.expect("ready entry");
        assert_eq!(ready.target_addr, target);
        // A checkout removes the entry: a second acquire must miss.
        assert!(pool.acquire_ready(&key).await.is_none());
        drop(ready);
    }

    #[tokio::test]
    async fn test_pool_ready_key_namespacing() {
        // Ready keys live in a namespace disjoint from bare "host:port"
        // keys, and bind both node and target (domain-aware).
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let k1 = ConnectionPool::ready_key("proxy.example:1080", target, None);
        let k2 = ConnectionPool::ready_key("proxy.example:1080", target, Some("example.com"));
        let k3 = ConnectionPool::ready_key("other.example:1080", target, None);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, "proxy.example:1080");
        assert!(k1.contains('|'));
    }

    #[tokio::test]
    async fn test_pool_ready_idle_ttl() {
        let mut pool = ConnectionPool::new();
        pool.set_ready_idle_timeout(Duration::from_millis(50));
        let server_addr = spawn_hold_open_listener().await;
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        // Ready entry expires after the short TTL.
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);
        let tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_ready(&key, make_ready_stream(tcp, target))
            .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(pool.acquire_ready(&key).await.is_none());

        // Bare entries still use the default 60s TTL and survive.
        let bare_tcp = TcpStream::connect(server_addr).await.unwrap();
        pool.deposit_tcp("server:1080", bare_tcp).await;
        assert!(pool.acquire_tcp("server:1080").await.is_some());
    }

    #[tokio::test]
    async fn test_pool_ready_dead_fin_evicted() {
        let pool = ConnectionPool::new();
        // Server accepts and immediately closes → client receives FIN.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((s, _)) = listener.accept().await {
                drop(s); // orderly FIN
            }
        });

        let tcp = TcpStream::connect(server_addr).await.unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let stream = make_ready_stream(tcp, target);

        // Wait until the FIN reaches the client kernel and the probe sees it.
        let mut saw_fin = false;
        for _ in 0..100 {
            if !ConnectionPool::is_ready_stream_alive(&stream) {
                saw_fin = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(saw_fin, "MSG_PEEK never observed the peer FIN");

        // A dead ready entry must not be handed out.
        let key = ConnectionPool::ready_key("proxy.example:1080", target, None);
        pool.deposit_ready(&key, stream).await;
        assert!(pool.acquire_ready(&key).await.is_none());
    }

    /// End-to-end: a SOCKS5 stream pooled after a full dial is reused
    /// without repeating the greeting/CONNECT handshake.
    #[tokio::test]
    async fn test_socks5_ready_reuse_skips_handshake() {
        // Mock SOCKS5 server: counts TCP connections; per connection it
        // answers greeting + CONNECT, then requires the next 4 bytes to be
        // exactly b"PING" (any re-handshake would fail this) before
        // replying b"PONG".
        let conn_count = Arc::new(AtomicU64::new(0));
        let payload_ok = Arc::new(AtomicU64::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        {
            let conn_count = Arc::clone(&conn_count);
            let payload_ok = Arc::clone(&payload_ok);
            tokio::spawn(async move {
                loop {
                    let (mut s, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    conn_count.fetch_add(1, Ordering::Relaxed);
                    let payload_ok = Arc::clone(&payload_ok);
                    tokio::spawn(async move {
                        // Greeting: VER NMETHODS METHODS...
                        let mut hdr = [0u8; 2];
                        s.read_exact(&mut hdr).await.unwrap();
                        assert_eq!(hdr[0], 0x05);
                        let mut methods = vec![0u8; hdr[1] as usize];
                        s.read_exact(&mut methods).await.unwrap();
                        s.write_all(&[0x05, 0x00]).await.unwrap();
                        // Request: VER CMD RSV ATYP ... ADDR PORT
                        let mut req = [0u8; 4];
                        s.read_exact(&mut req).await.unwrap();
                        assert_eq!(req[0], 0x05);
                        assert_eq!(req[1], 0x01); // CONNECT
                        let skip = match req[3] {
                            0x01 => 4 + 2,
                            0x04 => 16 + 2,
                            0x03 => {
                                let mut l = [0u8; 1];
                                s.read_exact(&mut l).await.unwrap();
                                l[0] as usize + 2
                            }
                            a => panic!("bad ATYP {a}"),
                        };
                        let mut rest = vec![0u8; skip];
                        s.read_exact(&mut rest).await.unwrap();
                        // Success reply: VER REP RSV ATYP=IPv4 0.0.0.0:0
                        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .unwrap();
                        // Data phase: the next bytes must be the payload
                        // itself, not a repeated greeting.
                        let mut data = [0u8; 4];
                        match s.read_exact(&mut data).await {
                            Ok(_) if &data == b"PING" => {
                                payload_ok.fetch_add(1, Ordering::Relaxed);
                                s.write_all(b"PONG").await.unwrap();
                            }
                            _ => return, // wrong bytes: close, client assert fails
                        }
                        // Hold the tunnel open until the client hangs up.
                        let mut sink = [0u8; 64];
                        let _ = s.read(&mut sink).await;
                    });
                }
            });
        }

        let node = Node {
            name: "test".into(),
            protocol: NodeProtocol::Socks5,
            address: server_addr.ip().to_string(),
            host: String::new(),
            port: server_addr.port(),
            ..Default::default()
        };
        let handler = Socks5Handler::new();
        assert!(handler.pool_ready_streams(&node));
        let target: SocketAddr = "93.184.216.34:80".parse().unwrap();

        // Full dial (TCP + greeting + CONNECT), then pool the result.
        let stream = handler
            .dial(&node, target, None, Duration::from_secs(3))
            .await
            .unwrap();
        let pool = ConnectionPool::new();
        let node_addr = format!("{}:{}", node.host(), node.port);
        let key = ConnectionPool::ready_key(&node_addr, target, None);
        pool.deposit_ready(&key, stream).await;

        // Checkout: payload goes straight through, no handshake bytes.
        let mut reused = pool.acquire_ready(&key).await.expect("ready stream");
        reused.stream.write_all(b"PING").await.unwrap();
        let mut buf = [0u8; 4];
        reused.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");

        // Exactly one TCP connection total, and its data phase saw the raw
        // payload — proving no greeting/CONNECT was sent on reuse.
        assert_eq!(conn_count.load(Ordering::Relaxed), 1);
        assert_eq!(payload_ok.load(Ordering::Relaxed), 1);
    }

    /// A dead node's bare AND ready entries must all be purged; other
    /// nodes' entries stay.
    #[tokio::test]
    async fn test_purge_node_removes_bare_and_ready() {
        let pool = ConnectionPool::new();
        let server = spawn_hold_open_listener().await;
        let dead_addr = "dead.example:1080";
        let other_addr = "other.example:1080";
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();

        for addr in [dead_addr, other_addr] {
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_tcp(addr, tcp).await;
            let key = ConnectionPool::ready_key(addr, target, None);
            let tcp = TcpStream::connect(server).await.unwrap();
            pool.deposit_ready(&key, make_ready_stream(tcp, target))
                .await;
        }
        pool.purge_node(dead_addr);
        assert!(pool.acquire_tcp(dead_addr).await.is_none());
        assert!(
            pool.acquire_ready(&ConnectionPool::ready_key(dead_addr, target, None))
                .await
                .is_none()
        );
        // Other node untouched.
        assert!(pool.acquire_tcp(other_addr).await.is_some());
        assert!(
            pool.acquire_ready(&ConnectionPool::ready_key(other_addr, target, None))
                .await
                .is_some()
        );
    }
}
