//! UDP endpoint pool — NAT mapping and connection tracking for UDP relay.
//!
//! Each UDP "connection" (identified by client address + destination address)
//! gets a pooled endpoint that handles bidirectional forwarding and
//! NAT timeout management. Mirrors the Go `udp_endpoint_pool.go`.
//!
//! The pool is a [`DashMap`] so that per-packet lookups on the UDP fast path
//! only contend on a single shard instead of one global mutex.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

const DEFAULT_NAT_TIMEOUT: Duration = Duration::from_secs(30);
const JANITOR_INTERVAL: Duration = Duration::from_secs(5);
/// How long the reply handler waits for proxy data before giving up.
const REPLY_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// TTL for the per-endpoint UDP routing result cache.
const ROUTING_CACHE_TTL: Duration = Duration::from_secs(30);

/// A pooled UDP endpoint representing one NAT mapping.
pub struct UdpEndpoint {
    /// The proxy-side UDP socket (connected to upstream).
    pub proxy_socket: Arc<UdpSocket>,
    /// The relay target address (upstream proxy).
    pub relay_addr: SocketAddr,
    /// Name of the proxy node this endpoint dials through — used to report
    /// UDP liveness when a reply actually arrives (see spawn_reply_handler).
    node_name: String,
    /// When this endpoint expires (monotonic nanos).
    expires_at: AtomicI64,
    /// Whether the endpoint has received at least one reply.
    has_reply: AtomicBool,
    /// Whether at least one client packet has been forwarded.
    has_sent: AtomicBool,
    /// Reference count for active operations.
    ref_count: AtomicI64,
    /// Set when the endpoint is being destroyed.
    dead: AtomicBool,
    /// Packed destination address for routing cache validation.
    routing_cache_dst: AtomicU64,
    /// Cached outbound index.
    routing_cache_outbound: AtomicU8,
    /// Monotonic nanos when the cache entry was stored.
    routing_cache_at: AtomicI64,
    /// Whether a valid routing cache entry exists.
    has_routing_cache: AtomicBool,
    /// Cached Anyfrom socket for sending responses back to the client.
    /// Avoids repeated bind syscalls in the hot reply path.
    response_conn: Mutex<Option<Arc<UdpSocket>>>,
    /// Tiny LRU ring for full-cone reply reinjection sockets keyed by bind_addr.
    full_cone_resp_cache: Mutex<[(SocketAddr, Option<Arc<UdpSocket>>); 4]>,
    /// Next slot to evict in the full_cone_resp_cache ring.
    full_cone_resp_next: Mutex<usize>,
    /// Ring buffer of peers we've sent packets to (for reply validation).
    pending_reply_peers: Mutex<[(SocketAddr, bool); 8]>,
    /// Number of entries in the pending_reply_peers ring.
    pending_reply_count: AtomicU64,
    /// Next ring position to write.
    pending_reply_next: AtomicU64,
    /// Live byte counters shared with the clash-API tracker entry (plain
    /// atomics — the per-packet path must not take a lock).
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    /// Clash-API tracker connection id; set once at registration, taken at
    /// removal.  Not touched on the per-packet path.
    tracker_id: Mutex<Option<String>>,
}

impl UdpEndpoint {
    pub fn new(proxy_socket: Arc<UdpSocket>, relay_addr: SocketAddr, node_name: String) -> Self {
        let now = monotonic_nanos();
        Self {
            proxy_socket,
            relay_addr,
            node_name,
            expires_at: AtomicI64::new(now + nanos_from_dur(DEFAULT_NAT_TIMEOUT)),
            has_reply: AtomicBool::new(false),
            has_sent: AtomicBool::new(false),
            ref_count: AtomicI64::new(1),
            dead: AtomicBool::new(false),
            routing_cache_dst: AtomicU64::new(0),
            routing_cache_outbound: AtomicU8::new(0),
            routing_cache_at: AtomicI64::new(0),
            has_routing_cache: AtomicBool::new(false),
            response_conn: Mutex::new(None),
            full_cone_resp_cache: Mutex::new(std::array::from_fn(|_| {
                (
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    None,
                )
            })),
            full_cone_resp_next: Mutex::new(0),
            pending_reply_peers: Mutex::new(
                [(
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                    false,
                ); 8],
            ),
            pending_reply_count: AtomicU64::new(0),
            pending_reply_next: AtomicU64::new(0),
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            tracker_id: Mutex::new(None),
        }
    }

    /// Bind the clash-API tracker entry to this endpoint: the entry shares
    /// the endpoint's atomic counters, and `conn_id` is stored for removal.
    pub fn set_tracker(&self, conn_id: String) {
        *self.tracker_id.lock().unwrap() = Some(conn_id);
    }

    /// Counter clones for the tracker entry.
    pub fn byte_counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (self.upload.clone(), self.download.clone())
    }

    /// Count client→proxy bytes (lock-free).
    pub fn tracker_upload(&self, n: u64) {
        self.upload.fetch_add(n, Ordering::Relaxed);
    }

    /// Count proxy→client bytes (lock-free).
    pub fn tracker_download(&self, n: u64) {
        self.download.fetch_add(n, Ordering::Relaxed);
    }

    /// Take the tracker connection id (on endpoint removal).
    pub fn take_tracker_id(&self) -> Option<String> {
        self.tracker_id.lock().unwrap().take()
    }

    pub fn is_expired(&self) -> bool {
        monotonic_nanos() > self.expires_at.load(Ordering::Relaxed)
    }

    pub fn refresh(&self) {
        self.expires_at.store(
            monotonic_nanos() + nanos_from_dur(DEFAULT_NAT_TIMEOUT),
            Ordering::Relaxed,
        );
    }

    pub fn mark_reply(&self) {
        self.has_reply.store(true, Ordering::Relaxed);
        self.refresh();
    }

    pub fn mark_sent(&self) {
        self.has_sent.store(true, Ordering::Relaxed);
    }

    /// Cache the routing result for this endpoint.
    ///
    /// Stores the destination and outbound index with a TTL so that
    /// subsequent UDP packets on the same endpoint can skip eBPF
    /// handoff lookup and Router evaluation.
    pub fn cache_routing_result(&self, dst: SocketAddr, outbound: u8) {
        let packed = pack_socket_addr(dst);
        self.routing_cache_dst.store(packed, Ordering::Relaxed);
        self.routing_cache_outbound
            .store(outbound, Ordering::Relaxed);
        self.routing_cache_at
            .store(monotonic_nanos(), Ordering::Relaxed);
        self.has_routing_cache.store(true, Ordering::Relaxed);
    }

    /// Retrieve a cached routing result for this endpoint.
    ///
    /// Returns `Some(outbound)` if the cache is valid for the given
    /// destination and the TTL has not expired. Returns `None` otherwise.
    pub fn get_cached_routing(&self, dst: SocketAddr) -> Option<u8> {
        if !self.has_routing_cache.load(Ordering::Relaxed) {
            return None;
        }
        let packed = pack_socket_addr(dst);
        if self.routing_cache_dst.load(Ordering::Relaxed) != packed {
            return None;
        }
        let now = monotonic_nanos();
        let cached_at = self.routing_cache_at.load(Ordering::Relaxed);
        if now - cached_at > nanos_from_dur(ROUTING_CACHE_TTL) {
            self.has_routing_cache.store(false, Ordering::Relaxed);
            return None;
        }
        Some(self.routing_cache_outbound.load(Ordering::Relaxed))
    }

    pub fn has_reply(&self) -> bool {
        self.has_reply.load(Ordering::Relaxed)
    }

    pub fn release(&self) {
        self.ref_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn kill(&self) {
        self.dead.store(true, Ordering::Release);
    }

    pub fn ref_count(&self) -> i64 {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Get a cached response connection for the given bind address.
    ///
    /// First checks the primary `response_conn`, then the LRU ring
    /// `full_cone_resp_cache`. Returns `None` if no cached socket
    /// matches the bind address.
    pub fn cached_response_conn(&self, bind_addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        if let Some(ref conn) = *self.response_conn.lock().unwrap()
            && let Ok(local) = conn.local_addr()
            && local == bind_addr
        {
            return Some(Arc::clone(conn));
        }
        let cache = self.full_cone_resp_cache.lock().unwrap();
        for (addr, conn) in cache.iter() {
            if *addr == bind_addr
                && let Some(conn) = conn
            {
                return Some(Arc::clone(conn));
            }
        }
        None
    }

    /// Store a response connection in the cache.
    ///
    /// If the primary `response_conn` slot is empty, stores it there.
    /// Otherwise, stores in the LRU ring `full_cone_resp_cache` using
    /// a simple round-robin eviction strategy.
    pub fn store_response_conn(&self, bind_addr: SocketAddr, conn: Arc<UdpSocket>) {
        let mut resp = self.response_conn.lock().unwrap();
        if resp.is_none() {
            *resp = Some(conn);
            return;
        }
        drop(resp);

        let mut cache = self.full_cone_resp_cache.lock().unwrap();
        let mut next = self.full_cone_resp_next.lock().unwrap();
        let slot = *next;
        *next = (slot + 1) % 4;
        cache[slot] = (bind_addr, Some(conn));
    }

    /// Record a peer we've sent a packet to (for reply validation).
    ///
    /// Stores the peer address in a ring buffer. During the probing phase
    /// (before the first reply is received), only replies from recorded
    /// peers are accepted.
    pub fn record_pending_reply_peer(&self, peer: SocketAddr) {
        let mut ring = self.pending_reply_peers.lock().unwrap();
        let next = self.pending_reply_next.fetch_add(1, Ordering::Relaxed) as usize % 8;
        ring[next] = (peer, true);
        self.pending_reply_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Validate that a reply peer is expected.
    ///
    /// Returns `true` if the reply should be accepted:
    /// - After `has_reply` is true: always accept (established state).
    /// - During probing: only accept if the peer was recorded via
    ///   `record_pending_reply_peer`.
    pub fn validate_reply_peer(&self, peer: SocketAddr) -> bool {
        if self.has_reply.load(Ordering::Relaxed) {
            return true;
        }
        let ring = self.pending_reply_peers.lock().unwrap();
        for (addr, valid) in ring.iter() {
            if *valid && *addr == peer {
                return true;
            }
        }
        false
    }
}

/// Key for the endpoint pool: (client address, destination address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    client_ip: [u8; 16],
    client_port: u16,
    dst_ip: [u8; 16],
    dst_port: u16,
}

impl EndpointKey {
    fn new(client: SocketAddr, dst: SocketAddr) -> Self {
        let mut cip = [0u8; 16];
        let mut dip = [0u8; 16];
        match client.ip() {
            std::net::IpAddr::V4(ip) => {
                cip[10] = 0xff;
                cip[11] = 0xff;
                cip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => cip.copy_from_slice(&ip.octets()),
        }
        match dst.ip() {
            std::net::IpAddr::V4(ip) => {
                dip[10] = 0xff;
                dip[11] = 0xff;
                dip[12..16].copy_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => dip.copy_from_slice(&ip.octets()),
        }
        Self {
            client_ip: cip,
            client_port: client.port(),
            dst_ip: dip,
            dst_port: dst.port(),
        }
    }

    /// Convert a stored 16-byte address back to `IpAddr`, unwrapping the
    /// v4-mapped form written by `new()`.
    fn ip_addr(bytes: &[u8; 16]) -> std::net::IpAddr {
        if bytes[0..10].iter().all(|&b| b == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[12], bytes[13], bytes[14], bytes[15],
            ))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
        }
    }

    fn client_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.client_ip)
    }

    fn dst_ip(&self) -> std::net::IpAddr {
        Self::ip_addr(&self.dst_ip)
    }
}

/// Message sent to the endpoint-removal sink: `(client, dst, conn_id)`.
type EndpointRemoval = (SocketAddr, SocketAddr, Option<String>);

/// Pool of UDP endpoints with LRU-like eviction.
pub struct UdpEndpointPool {
    endpoints: DashMap<EndpointKey, Arc<UdpEndpoint>>,
    /// Sink notified whenever an endpoint is removed; the control plane uses
    /// it to retire the flow's conntrack entries promptly instead of waiting
    /// for the datapath/janitor timeouts, and to drop the flow from the
    /// clash-API tracker.
    remove_sink: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<EndpointRemoval>>>,
}

impl UdpEndpointPool {
    pub fn new() -> Self {
        Self {
            endpoints: DashMap::new(),
            remove_sink: std::sync::Mutex::new(None),
        }
    }

    /// Register the endpoint-removal sink (called once at control-plane
    /// startup).
    pub fn set_remove_sink(&self, tx: tokio::sync::mpsc::UnboundedSender<EndpointRemoval>) {
        *self.remove_sink.lock().unwrap() = Some(tx);
    }

    fn notify_removed(&self, client: SocketAddr, dst: SocketAddr, conn_id: Option<String>) {
        if let Some(tx) = &*self.remove_sink.lock().unwrap() {
            let _ = tx.send((client, dst, conn_id));
        }
    }

    /// Look up an existing endpoint without creating one.
    pub fn get(&self, client: SocketAddr, dst: SocketAddr) -> Option<Arc<UdpEndpoint>> {
        let key = EndpointKey::new(client, dst);
        // The shard guard is held only for the atomic check + Arc clone and
        // is released before returning — no map re-entry while holding it.
        let ep = self.endpoints.get(&key)?;
        if ep.dead.load(Ordering::Acquire) {
            return None;
        }
        Some(Arc::clone(ep.value()))
    }

    /// Get or create an endpoint for the given client→dst mapping.
    /// Returns (endpoint, is_new) where is_new indicates whether this was just created.
    pub fn get_or_create(
        &self,
        client: SocketAddr,
        dst: SocketAddr,
        proxy_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
        node_name: String,
    ) -> (Arc<UdpEndpoint>, bool) {
        let key = EndpointKey::new(client, dst);
        // entry() holds the shard lock across the whole check-and-insert,
        // preserving the old global-mutex semantics (no duplicate endpoint
        // can be created for the same key by a racing task).
        match self.endpoints.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                let existing = occ.get();
                if !existing.dead.load(Ordering::Acquire) {
                    // NB: no acquire() here — the endpoint's single ref is
                    // owned by its reply handler (released when the handler
                    // exits after REPLY_IDLE_TIMEOUT). Acquiring per packet
                    // without a matching release pinned every reused
                    // endpoint in the pool forever (the UDP socket leak).
                    existing.refresh();
                    return (Arc::clone(existing), false);
                }
                // Dead endpoint: replace it atomically (equivalent to the
                // old remove-then-insert under the global lock).
                let ep = Arc::new(UdpEndpoint::new(proxy_socket, relay_addr, node_name));
                occ.insert(Arc::clone(&ep));
                (ep, true)
            }
            dashmap::mapref::entry::Entry::Vacant(vac) => {
                let ep = Arc::new(UdpEndpoint::new(proxy_socket, relay_addr, node_name));
                vac.insert(Arc::clone(&ep));
                (ep, true)
            }
        }
    }

    /// Remove an endpoint from the pool.
    pub fn remove(&self, client: SocketAddr, dst: SocketAddr) {
        let key = EndpointKey::new(client, dst);
        if let Some((_, ep)) = self.endpoints.remove(&key) {
            ep.kill();
            self.notify_removed(client, dst, ep.take_tracker_id());
        }
    }

    /// Remove every endpoint dialing through `node_name` — called when the
    /// node flips alive→dead so its UDP flows stop immediately instead of
    /// lingering until the NAT/reply idle timeouts reap them.
    pub fn remove_by_node(&self, node_name: &str) {
        let keys: Vec<(SocketAddr, SocketAddr)> = self
            .endpoints
            .iter()
            .filter(|ep| ep.node_name == node_name)
            .map(|ep| {
                let key = ep.key();
                (
                    SocketAddr::new(key.client_ip(), key.client_port),
                    SocketAddr::new(key.dst_ip(), key.dst_port),
                )
            })
            .collect();
        let removed = keys.len();
        for (client, dst) in keys {
            self.remove(client, dst);
        }
        if removed > 0 {
            debug!(
                "Removed {} UDP endpoints bound to dead node '{}'",
                removed, node_name
            );
        }
    }

    /// Run a janitor cycle: remove expired endpoints.
    pub fn janitor_cycle(&self) -> usize {
        let expired: Vec<(SocketAddr, SocketAddr)> = self
            .endpoints
            .iter()
            .filter(|ep| ep.ref_count() <= 0 && ep.is_expired())
            .map(|ep| {
                let key = ep.key();
                (
                    SocketAddr::new(key.client_ip(), key.client_port),
                    SocketAddr::new(key.dst_ip(), key.dst_port),
                )
            })
            .collect();
        let removed = expired.len();
        for (client, dst) in expired {
            self.remove(client, dst);
        }
        if removed > 0 {
            debug!("UDP endpoint janitor removed {} expired endpoints", removed);
        }
        removed
    }

    /// Spawn a background janitor that periodically cleans up expired endpoints.
    pub fn spawn_janitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JANITOR_INTERVAL).await;
                pool.janitor_cycle();
            }
        })
    }

    /// Spawn a background reply handler for a new endpoint.
    /// Listens for datagrams from the proxy and forwards them back to the client.
    pub fn spawn_reply_handler(
        endpoint: Arc<UdpEndpoint>,
        client_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        client_dst: SocketAddr,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Replies must reach the client with the ORIGINAL DESTINATION as
            // source (e.g. 8.8.8.8:443 → client); anything else is dropped by
            // the client's stack (4-tuple mismatch) — and a reply sourced
            // from the TPROXY listener (169.254.0.11:12345) never survives
            // the host dae0 path. Go dae "anyfrom" parity: a transparent
            // socket bound to the original destination (created in daens),
            // cached per endpoint for the endpoint's lifetime.
            let reply_socket = match endpoint.cached_response_conn(client_dst) {
                Some(sock) => sock,
                None => match super::new_udp_reply_socket(client_dst) {
                    Ok(sock) => {
                        let sock = Arc::new(sock);
                        endpoint.store_response_conn(client_dst, Arc::clone(&sock));
                        debug!("UDP reply handler using anyfrom socket for {}", client_dst);
                        sock
                    }
                    Err(e) => {
                        debug!(
                            "UDP reply handler: anyfrom socket for {} failed ({}); falling back to listener",
                            client_dst, e
                        );
                        client_socket.clone()
                    }
                },
            };
            let ipver = if client_dst.is_ipv4() {
                honk_outbound::alive::IpVersion::V4
            } else {
                honk_outbound::alive::IpVersion::V6
            };

            let mut buf = [0u8; 65536];
            loop {
                if endpoint.dead.load(Ordering::Acquire) {
                    break;
                }
                match tokio::time::timeout(
                    REPLY_IDLE_TIMEOUT,
                    endpoint.proxy_socket.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, src))) => {
                        // Only accept datagrams from our relay
                        if src != endpoint.relay_addr && !endpoint.validate_reply_peer(src) {
                            debug!("UDP reply handler: rejecting unexpected peer {}", src);
                            continue;
                        }
                        endpoint.mark_reply();
                        endpoint.tracker_download(n as u64);
                        // A reply is the only proof a UDP path actually works
                        // (a UoT-blackhole server accepts sends but never
                        // answers); report liveness on receipt, not on send.
                        alive_set.report_available_traffic(
                            &endpoint.node_name,
                            honk_outbound::alive::ProbeDomain::DataUdp,
                            ipver,
                        );
                        if let Err(e) = reply_socket.send_to(&buf[..n], client_addr).await {
                            warn!(
                                "UDP reply handler: failed to send to client {}: {}",
                                client_addr, e
                            );
                            break;
                        }
                        debug!(
                            "UDP reply: {} bytes proxy->client ({} -> {})",
                            n, client_dst, client_addr
                        );
                    }
                    Ok(Err(e)) => {
                        warn!("UDP reply handler recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!(
                            "UDP reply handler idle timeout for {} -> {}",
                            client_addr, client_dst
                        );
                        break;
                    }
                }
            }
            endpoint.release();
        })
    }

    /// Get the current endpoint count.
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

impl Default for UdpEndpointPool {
    fn default() -> Self {
        Self::new()
    }
}

fn monotonic_nanos() -> i64 {
    // Use std Instant as monotonic clock (handles suspend correctly).
    // We only need relative comparisons, so offset from a fixed epoch is fine.
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

fn nanos_from_dur(d: Duration) -> i64 {
    d.as_nanos() as i64
}

/// Pack a SocketAddr into a u64 for fast atomic comparisons.
///
/// IPv4: `(octets as u32) as u64) << 16 | port`
/// IPv6: XOR of address bytes with port for collision resistance.
fn pack_socket_addr(addr: SocketAddr) -> u64 {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            ((octets[0] as u64) << 24
                | (octets[1] as u64) << 16
                | (octets[2] as u64) << 8
                | octets[3] as u64)
                << 16
                | (addr.port() as u64)
        }
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            let lo = u64::from_be_bytes([
                octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14],
                octets[15],
            ]);
            lo ^ ((addr.port() as u64) << 48)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(ip: &str, port: u16) -> SocketAddr {
        format!("{}:{}", ip, port).parse().unwrap()
    }

    #[test]
    fn test_endpoint_key() {
        // Key is (client, dst) not (client, relay)
        let a = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
        let b = EndpointKey::new(make_addr("1.2.3.4", 80), make_addr("5.6.7.8", 443));
        let c = EndpointKey::new(make_addr("1.2.3.5", 80), make_addr("5.6.7.8", 443));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_endpoint_key_ipv6() {
        let a = EndpointKey::new(
            make_addr("[2001:db8::1]", 8080),
            make_addr("[2001:db8::2]", 9090),
        );
        let b = EndpointKey::new(
            make_addr("[2001:db8::1]", 8080),
            make_addr("[2001:db8::2]", 9090),
        );
        assert_eq!(a, b);
    }

    #[test]
    fn test_pool_empty_operations() {
        let pool = UdpEndpointPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.janitor_cycle(), 0);
    }

    #[test]
    fn test_pool_get() {
        let pool = UdpEndpointPool::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        assert!(pool.get(client, dst).is_none());
    }

    #[test]
    fn test_get_or_create_returns_is_new() {
        let pool = UdpEndpointPool::new();
        let client = make_addr("10.0.0.1", 12345);
        let dst = make_addr("8.8.8.8", 53);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let relay = make_addr("192.168.1.1", 1080);

        let (_ep, is_new) =
            pool.get_or_create(client, dst, proxy.clone(), relay, "test-node".to_string());
        assert!(is_new, "first call should be new");

        let (_ep2, is_new2) =
            pool.get_or_create(client, dst, proxy, relay, "test-node".to_string());
        assert!(!is_new2, "second call should return existing");
    }

    #[test]
    fn test_routing_cache_hit() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let relay = make_addr("192.168.1.1", 1080);
        let ep = UdpEndpoint::new(proxy, relay, "test-node".to_string());
        let dst = make_addr("8.8.8.8", 53);

        assert!(ep.get_cached_routing(dst).is_none());

        ep.cache_routing_result(dst, 5);
        assert_eq!(ep.get_cached_routing(dst), Some(5));
    }

    #[test]
    fn test_routing_cache_different_dst_miss() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let ep = UdpEndpoint::new(
            proxy,
            make_addr("192.168.1.1", 1080),
            "test-node".to_string(),
        );

        ep.cache_routing_result(make_addr("8.8.8.8", 53), 3);
        assert!(ep.get_cached_routing(make_addr("1.1.1.1", 53)).is_none());
    }

    #[test]
    fn test_routing_cache_expiry() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let ep = UdpEndpoint::new(
            proxy,
            make_addr("192.168.1.1", 1080),
            "test-node".to_string(),
        );
        let dst = make_addr("8.8.8.8", 53);

        ep.cache_routing_result(dst, 7);
        assert_eq!(ep.get_cached_routing(dst), Some(7));

        // Force expiry by backdating the timestamp past the TTL.
        ep.routing_cache_at.store(
            monotonic_nanos()
                - nanos_from_dur(ROUTING_CACHE_TTL)
                - nanos_from_dur(Duration::from_secs(1)),
            Ordering::Relaxed,
        );
        assert!(ep.get_cached_routing(dst).is_none());
    }

    #[test]
    fn test_remove_by_node() {
        let pool = UdpEndpointPool::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = Arc::new(
            rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
                .unwrap(),
        );
        let relay = make_addr("192.168.1.1", 1080);
        let dst = make_addr("8.8.8.8", 53);
        pool.get_or_create(
            make_addr("10.0.0.1", 12345),
            dst,
            proxy.clone(),
            relay,
            "dead-node".to_string(),
        );
        pool.get_or_create(
            make_addr("10.0.0.2", 12345),
            dst,
            proxy.clone(),
            relay,
            "other-node".to_string(),
        );
        assert_eq!(pool.len(), 2);

        pool.remove_by_node("dead-node");
        assert_eq!(pool.len(), 1);
        assert!(pool.get(make_addr("10.0.0.1", 12345), dst).is_none());
        assert!(pool.get(make_addr("10.0.0.2", 12345), dst).is_some());
    }
}
