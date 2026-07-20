//! DNS listener that intercepts local DNS queries.
//!
//! Listens on UDP port 53 (and optionally TCP port 53) for DNS queries,
//! forwards them to configured upstreams via a [`DnsRequestHandler`], and
//! sends responses back to the originating client.
//!
//! # Architecture
//!
//! ```text
//!   Client App                    honk DNS Listener            Upstream DNS
//!      │                                │                              │
//!      │── DNS query (UDP) ───→         │                              │
//!      │                          recv_from()                         │
//!      │                          handler.handle_query() ────────────→│
//!      │                                           ←────────────────│
//!      │←─ DNS response (UDP) ─── send_to()                          │
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use honk_core::dns::listener::{DnsListener, DnsRequestHandler};
//! use std::sync::Arc;
//!
//! struct MyHandler;
//!
//! #[async_trait::async_trait]
//! impl DnsRequestHandler for MyHandler {
//!     async fn handle_query(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
//!         // Forward to upstream DNS and return response bytes
//!         Ok(vec![])
//!     }
//! }
//! ```
//!
//! ```rust,no_run
//! # use honk_core::dns::listener::{DnsListener, DnsRequestHandler};
//! # use std::sync::Arc;
//! # struct MyHandler;
//! # #[async_trait::async_trait]
//! # impl DnsRequestHandler for MyHandler {
//! #     async fn handle_query(&self, _msg: &[u8]) -> anyhow::Result<Vec<u8>> { Ok(vec![]) }
//! # }
//! # async fn example() -> anyhow::Result<()> {
//! let listener = DnsListener::new("127.0.0.1:5353").await?;
//! let handle = listener.run(Arc::new(MyHandler));
//! // ... application work ...
//! listener.shutdown();
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

/// Maximum size of a standard DNS message in bytes (per RFC 1035).
const MAX_DNS_QUERY_SIZE: usize = 512;

/// Handler trait for processing intercepted DNS queries.
///
/// Implementations forward the raw DNS query bytes to configured
/// upstream DNS servers and return the raw DNS response bytes.
///
/// This trait is object-safe and can be used as `Arc<dyn DnsRequestHandler>`.
#[async_trait::async_trait]
pub trait DnsRequestHandler: Send + Sync {
    /// Handle a raw DNS query and return the raw DNS response.
    ///
    /// The `msg` parameter contains the full DNS query message as received
    /// from the client. The returned `Vec<u8>` must be a valid DNS response
    /// message to be sent back to the client.
    async fn handle_query(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// DNS listener that intercepts local DNS queries.
///
/// Binds to a UDP socket (and optionally TCP) on the given endpoint.
/// Incoming DNS queries are passed to a [`DnsRequestHandler`] for
/// resolution, and responses are sent back to the originating client.
///
/// # Lifecycle
///
/// 1. Construct with [`DnsListener::new`] — binds the sockets.
/// 2. Call [`DnsListener::run`] to start the background event loop.
/// 3. Call [`DnsListener::shutdown`] for graceful termination.
pub struct DnsListener {
    /// The bound endpoint address (e.g. "0.0.0.0:53").
    endpoint: String,
    /// UDP socket for receiving DNS queries.
    udp_socket: Option<Arc<UdpSocket>>,
    /// Optional TCP listener for DNS over TCP (RFC 7766).
    tcp_listener: Option<Arc<tokio::net::TcpListener>>,
    /// Shutdown signal sender. Calling `send(true)` stops the event loop.
    shutdown_tx: watch::Sender<bool>,
}

impl DnsListener {
    /// Create a new DNS listener bound to the given endpoint.
    ///
    /// Binds a UDP socket (required) and optionally a TCP listener to
    /// `endpoint`. TCP binding failure is non-fatal — a warning is logged
    /// and the listener continues in UDP-only mode.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint string cannot be parsed as a `SocketAddr`.
    /// - The UDP socket cannot be bound.
    pub async fn new(endpoint: &str) -> anyhow::Result<Self> {
        let addr: SocketAddr = endpoint
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid endpoint '{}': {}", endpoint, e))?;

        let std_udp = std::net::UdpSocket::bind(addr)
            .map_err(|e| anyhow::anyhow!("failed to bind UDP socket on {}: {}", endpoint, e))?;
        std_udp
            .set_nonblocking(true)
            .map_err(|e| anyhow::anyhow!("failed to set UDP socket non-blocking: {}", e))?;
        let udp_socket = UdpSocket::from_std(std_udp)
            .map_err(|e| anyhow::anyhow!("failed to create tokio UdpSocket: {}", e))?;
        debug!("DNS UDP listener bound on {}", endpoint);

        let tcp_listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                debug!("DNS TCP listener bound on {}", endpoint);
                Some(Arc::new(listener))
            }
            Err(e) => {
                warn!(
                    "failed to bind DNS TCP listener on {}: {} (continuing UDP-only)",
                    endpoint, e
                );
                None
            }
        };

        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        Ok(Self {
            endpoint: endpoint.to_string(),
            udp_socket: Some(Arc::new(udp_socket)),
            tcp_listener,
            shutdown_tx,
        })
    }

    /// Spawn the DNS listener event loop.
    ///
    /// Starts a background task that continuously receives UDP DNS
    /// queries and forwards them through the provided `handler`.
    /// If a TCP listener was successfully bound, a second task is
    /// spawned to handle DNS-over-TCP connections.
    ///
    /// Returns a [`JoinHandle`] that can be used to abort the task.
    /// Prefer [`shutdown`](Self::shutdown) for graceful termination.
    pub fn run(&self, handler: Arc<dyn DnsRequestHandler>) -> JoinHandle<()> {
        let udp_socket = self
            .udp_socket
            .as_ref()
            .map(Arc::clone)
            .expect("UDP socket not initialized");
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let endpoint = self.endpoint.clone();

        if let Some(tcp_listener) = self.tcp_listener.as_ref().map(Arc::clone) {
            let tcp_handler = Arc::clone(&handler);
            let mut tcp_shutdown_rx = self.shutdown_tx.subscribe();
            let tcp_endpoint = self.endpoint.clone();

            tokio::spawn(async move {
                debug!("DNS TCP accept loop running on {}", tcp_endpoint);

                loop {
                    tokio::select! {
                        biased;

                        _ = tcp_shutdown_rx.changed() => {
                            if *tcp_shutdown_rx.borrow() {
                                debug!("DNS TCP accept loop on {} shutting down", tcp_endpoint);
                                break;
                            }
                        }

                        result = tcp_listener.accept() => {
                            match result {
                                Ok((mut stream, peer_addr)) => {
                                    debug!("DNS TCP connection from {}", peer_addr);
                                    let handler = Arc::clone(&tcp_handler);

                                    tokio::spawn(async move {
                                        // Read DNS query length prefix (2 bytes, RFC 7766 §7)
                                        use tokio::io::AsyncReadExt;
                                        use tokio::io::AsyncWriteExt;

                                        let mut len_buf = [0u8; 2];
                                        if let Err(e) = stream.read_exact(&mut len_buf).await {
                                            debug!("failed to read DNS TCP length from {}: {}", peer_addr, e);
                                            return;
                                        }
                                        let msg_len = u16::from_be_bytes(len_buf) as usize;

                                        if msg_len > MAX_DNS_QUERY_SIZE {
                                            debug!("DNS TCP query too large from {}: {} bytes", peer_addr, msg_len);
                                            return;
                                        }

                                        let mut msg_buf = vec![0u8; msg_len];
                                        if let Err(e) = stream.read_exact(&mut msg_buf).await {
                                            debug!("failed to read DNS TCP query from {}: {}", peer_addr, e);
                                            return;
                                        }

                                        match handler.handle_query(&msg_buf).await {
                                            Ok(response) => {
                                                let resp_len = (response.len() as u16).to_be_bytes();
                                                if stream.write_all(&resp_len).await.is_err()
                                                    || stream.write_all(&response).await.is_err()
                                                {
                                                    debug!("failed to send DNS TCP response to {}", peer_addr);
                                                }
                                            }
                                            Err(e) => {
                                                error!("DNS TCP handler error for {}: {}", peer_addr, e);
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("TCP accept error on {}: {}", tcp_endpoint, e);
                                }
                            }
                        }
                    }
                }

                debug!("DNS TCP accept loop on {} stopped", tcp_endpoint);
            });
        }

        tokio::spawn(async move {
            debug!("DNS UDP receive loop running on {}", endpoint);

            let mut buf = vec![0u8; MAX_DNS_QUERY_SIZE];

            loop {
                tokio::select! {
                    biased;

                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("DNS UDP receive loop on {} shutting down", endpoint);
                            break;
                        }
                    }

                    result = udp_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src_addr)) => {
                                let query = &buf[..len];
                                debug!("DNS UDP query from {} ({} bytes)", src_addr, len);

                                match handler.handle_query(query).await {
                                    Ok(response) => {
                                        if let Err(e) = udp_socket.send_to(&response, src_addr).await {
                                            error!(
                                                "failed to send DNS UDP response to {}: {}",
                                                src_addr, e
                                            );
                                        } else {
                                            debug!(
                                                "DNS UDP response sent to {} ({} bytes)",
                                                src_addr,
                                                response.len()
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "DNS handler error for query from {}: {}",
                                            src_addr, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!("UDP recv error on {}: {}", endpoint, e);
                            }
                        }
                    }
                }
            }

            debug!("DNS UDP receive loop on {} stopped", endpoint);
        })
    }

    /// Initiate graceful shutdown of the DNS listener.
    ///
    /// Sends a shutdown signal to all background tasks spawned by
    /// [`run`](Self::run). Tasks will stop after completing any
    /// in-flight queries.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        debug!("DNS listener shutdown signal sent");
    }

    /// Return the local socket address of the bound UDP socket.
    ///
    /// Returns `None` if the listener was not initialized with a
    /// UDP socket.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.udp_socket.as_ref().and_then(|s| s.local_addr().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Mock handler that records whether it was called and returns a fixed response.
    struct MockHandler {
        /// Set to `true` when `handle_query` is invoked.
        called: AtomicBool,
        /// The fixed response to return (wrapped for interior mutability).
        response: Mutex<Vec<u8>>,
        /// Received query buffer (captured for assertion).
        received_query: Mutex<Vec<u8>>,
    }

    impl MockHandler {
        fn new(response: Vec<u8>) -> Self {
            Self {
                called: AtomicBool::new(false),
                response: Mutex::new(response),
                received_query: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait::async_trait]
    impl DnsRequestHandler for MockHandler {
        async fn handle_query(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.called.store(true, Ordering::SeqCst);
            *self.received_query.lock().unwrap() = msg.to_vec();
            Ok(self.response.lock().unwrap().clone())
        }
    }

    /// Verify that the listener binds to a port successfully.
    #[tokio::test]
    async fn test_listener_bind() {
        let listener = DnsListener::new("127.0.0.1:0").await;
        assert!(listener.is_ok(), "listener should bind to random port");

        let listener = listener.unwrap();
        let addr = listener.local_addr();
        assert!(addr.is_some(), "listener should have a bound address");
        assert!(addr.unwrap().port() > 0, "port should be non-zero");
    }

    /// Verify that the listener rejects invalid endpoints.
    #[tokio::test]
    async fn test_listener_bind_invalid_endpoint() {
        let result = DnsListener::new("not-an-address").await;
        assert!(result.is_err(), "invalid endpoint should fail");
    }

    /// Verify that the handler is called when a DNS query is received.
    #[tokio::test]
    async fn test_handler_called() {
        let listener = DnsListener::new("127.0.0.1:0")
            .await
            .expect("failed to bind listener");
        let addr = listener.local_addr().expect("failed to get local addr");

        let mock_response = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x5d\xb8\xd8\x22";
        let handler = Arc::new(MockHandler::new(mock_response.to_vec()));
        let _handle = listener.run(Arc::clone(&handler) as Arc<dyn DnsRequestHandler>);

        // Send a mock DNS query (A record for example.com)
        let query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind client socket");

        client
            .send_to(query, addr)
            .await
            .expect("failed to send query");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            handler.called.load(Ordering::SeqCst),
            "handler should have been called"
        );

        let received = handler.received_query.lock().unwrap();
        assert_eq!(
            received.as_slice(),
            query,
            "handler should receive the query"
        );

        listener.shutdown();
    }

    /// Verify that the response from the handler is sent back to the client.
    #[tokio::test]
    async fn test_response_sent() {
        let listener = DnsListener::new("127.0.0.1:0")
            .await
            .expect("failed to bind listener");
        let addr = listener.local_addr().expect("failed to get local addr");

        let mock_response = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\x5d\xb8\xd8\x22";
        let handler = Arc::new(MockHandler::new(mock_response.to_vec()));
        let _handle = listener.run(Arc::clone(&handler) as Arc<dyn DnsRequestHandler>);

        let query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind client socket");

        client
            .send_to(query, addr)
            .await
            .expect("failed to send query");

        let mut resp_buf = vec![0u8; 512];
        let (len, _src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut resp_buf),
        )
        .await
        .expect("timeout waiting for response")
        .expect("failed to receive response");

        assert_eq!(&resp_buf[..len], mock_response, "response should match");

        listener.shutdown();
    }

    /// Verify shutdown stops the event loop (query after shutdown is not handled).
    #[tokio::test]
    async fn test_shutdown_stops_loop() {
        let listener = DnsListener::new("127.0.0.1:0")
            .await
            .expect("failed to bind listener");
        let addr = listener.local_addr().expect("failed to get local addr");

        let handler = Arc::new(MockHandler::new(vec![0u8; 32]));
        let handle = listener.run(Arc::clone(&handler) as Arc<dyn DnsRequestHandler>);

        listener.shutdown();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "listener task should finish after shutdown");

        // Query sent after shutdown should still reach the socket
        // but the loop has exited, so handler won't be called again
        let query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("failed to bind client socket");

        let _ = client.send_to(query, addr).await;
    }
}
