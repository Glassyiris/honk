//! Per-upstream DNS query management with connection reuse.
//!
//! Plain UDP stays datagram-per-query (with bypass mark). TCP/DoT use idle
//! stream pools; DoH multiplexes over one H2 session; DoQ/DoH3 reuse one
//! QUIC connection. Hostnames resolve through the bootstrap resolver so
//! encrypted upstreams never depend on the intercepted DNS path.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use honk_config::dns::DnsUpstream;
use honk_config::node::{Group, Node};
use honk_config::types::DnsProtocol;
use honk_ebpf_common::DAE_BYPASS_MARK;
use honk_outbound::alive::{IpVersion, ProbeDomain};
use honk_outbound::group::SharedGroupManager;
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{debug, warn};

use super::endpoint::DnsEndpoint;
use super::forwarder::DnsUpstreamPool;
use super::routing::DnsRouter;
use super::transport::{
    DialContext, Doh3Client, DohClient, DoqClient, DotPool, ProxyDial, TcpPool,
};
use crate::proxy::ProxyRegistry;
use crate::routing::{ConnectionInfo, Router};

/// Runtime handle for one named upstream.
struct UpstreamEntry {
    protocol: DnsProtocol,
    endpoint: DnsEndpoint,
    /// Original address string (kept for logs / UDP SocketAddr fast path).
    address: String,
    outbound: Option<String>,
    /// Pooled transports keyed by leaf node name.
    ///
    /// - `""` (empty key): direct dial (no `outbound:` / `direct`)
    /// - node name: session pinned to that leaf so URLTest/Selector switches
    ///   open a fresh tunnel instead of reusing another node's H2/TLS pool.
    transports: tokio::sync::Mutex<HashMap<String, Arc<PooledTransport>>>,
}

enum PooledTransport {
    Tcp(Arc<TcpPool>),
    Dot(Arc<DotPool>),
    Doh(Arc<DohClient>),
    Doq(Arc<DoqClient>),
    Doh3(Arc<Doh3Client>),
}

pub struct UpstreamPool {
    entries: HashMap<String, UpstreamEntry>,
    router: Arc<DnsRouter>,
    proxy_registry: Option<Arc<ProxyRegistry>>,
    /// Fallback node list when no [`SharedGroupManager`] is installed (tests).
    nodes: Vec<Node>,
    /// Fallback group list for legacy first-member pick without GroupManager.
    groups: Vec<Group>,
    /// Live group policy cell — same handle the control plane / clash API use.
    /// When set, `name: 'uri' -> <group>` uses authoritative selection (URLTest /
    /// Selector / Fallback / nested groups), matching traffic dial semantics.
    ///
    /// Interior mutability so the control plane can attach the shared cell
    /// after construction without wrapping the whole pool.
    group_manager: parking_lot::RwLock<Option<SharedGroupManager>>,
    /// Traffic router cell (same as control plane). Used when an upstream has
    /// **no** explicit `-> outbound` — dae semantics: dial the DNS server IP
    /// through normal `routing { }` + group selection.
    traffic_router: parking_lot::RwLock<Option<Arc<AsyncRwLock<Router>>>>,
    dns_query_timeout: Duration,
    dns_dial_timeout: Duration,
}

impl UpstreamPool {
    pub fn new(upstreams: &[DnsUpstream], router: Arc<DnsRouter>) -> anyhow::Result<Self> {
        Self::new_with_proxy(upstreams, router, None, Vec::new(), Vec::new())
    }

    pub fn new_with_proxy(
        upstreams: &[DnsUpstream],
        router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
    ) -> anyhow::Result<Self> {
        let mut entries = HashMap::new();
        for upstream in upstreams {
            let endpoint = DnsEndpoint::parse(
                &upstream.address,
                upstream.protocol,
                upstream.tls_server_name.as_deref(),
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "invalid upstream '{}' address '{}': {e}",
                    upstream.name,
                    upstream.address
                )
            })?;
            entries.insert(
                upstream.name.clone(),
                UpstreamEntry {
                    protocol: upstream.protocol,
                    endpoint,
                    address: upstream.address.clone(),
                    outbound: upstream.outbound.clone(),
                    transports: tokio::sync::Mutex::new(HashMap::new()),
                },
            );
        }
        Ok(Self {
            entries,
            router,
            proxy_registry,
            nodes,
            groups,
            group_manager: parking_lot::RwLock::new(None),
            traffic_router: parking_lot::RwLock::new(None),
            dns_query_timeout: Duration::from_secs(3),
            dns_dial_timeout: Duration::from_secs(10),
        })
    }

    pub fn with_timeouts(
        mut self,
        dns_query_timeout: Duration,
        dns_dial_timeout: Duration,
    ) -> Self {
        self.dns_query_timeout = dns_query_timeout;
        self.dns_dial_timeout = dns_dial_timeout;
        self
    }

    /// Install the shared group manager used for `-> <group>` selection.
    ///
    /// Must be the same [`SharedGroupManager`] cell the control plane holds so
    /// Selector choices / URLTest winners stay consistent with traffic dials.
    pub fn set_group_manager(&self, gm: Option<SharedGroupManager>) {
        *self.group_manager.write() = gm;
    }

    /// Builder-style install (consumes `self`).
    pub fn with_group_manager(self, gm: SharedGroupManager) -> Self {
        *self.group_manager.write() = Some(gm);
        self
    }

    /// Install the traffic router used for **implicit** DNS-upstream dial
    /// selection (dae: Route the DNS server IP through `routing { }`).
    pub fn set_traffic_router(&self, router: Option<Arc<AsyncRwLock<Router>>>) {
        *self.traffic_router.write() = router;
    }

    /// Builder-style install of the traffic router.
    pub fn with_traffic_router(self, router: Arc<AsyncRwLock<Router>>) -> Self {
        *self.traffic_router.write() = Some(router);
        self
    }

    /// Resolve `outbound:` to a concrete leaf node — same precedence as traffic:
    ///
    /// 1. `direct` / `block` → no proxy (`None`)
    /// 2. With [`SharedGroupManager`]: group name → authoritative policy pick
    ///    (`select_nodes_in_order_for_domain`, TCP/IPv4 then IPv4-fallback path
    ///    matching `resolve_outbound_nodes`); plain node name → that node
    /// 3. Without GM (tests): node by name, else first member of static group
    fn resolve_outbound_leaf(&self, outbound: &str) -> Option<Node> {
        if outbound.eq_ignore_ascii_case("direct") || outbound.eq_ignore_ascii_case("block") {
            return None;
        }

        {
            let cell = self.group_manager.read();
            if let Some(cell) = cell.as_ref() {
                let gm = cell.read();
                // Group? → policy pick (URLTest / Selector / Fallback / nested).
                if gm.get_group_policy(outbound).is_some() {
                    let mut picked = gm.select_nodes_in_order_for_domain(
                        outbound,
                        ProbeDomain::Tcp,
                        IpVersion::V4,
                    );
                    if picked.is_empty() {
                        // Mirror traffic: try V6 domain if V4 empty.
                        picked = gm.select_nodes_in_order_for_domain(
                            outbound,
                            ProbeDomain::Tcp,
                            IpVersion::V6,
                        );
                    }
                    if let Some(n) = picked.into_iter().next() {
                        return Some(n.clone());
                    }
                    warn!(
                        "DNS outbound group '{}' has no available node (GroupManager)",
                        outbound
                    );
                    return None;
                }
                // Not a group — fall through to node lookup.
            }
        }

        if let Some(node) = self.nodes.iter().find(|n| n.name == outbound) {
            return Some(node.clone());
        }

        // No GM or unknown group name: legacy first-member fallback for tests.
        if self.group_manager.read().is_none()
            && let Some(group) = self.groups.iter().find(|g| g.name == outbound)
        {
            for node_id in &group.nodes {
                if let Some(node) = self.nodes.iter().find(|n| &n.id == node_id) {
                    return Some(node.clone());
                }
            }
        }

        warn!("DNS outbound '{}' resolved to no node", outbound);
        None
    }

    /// Choose the proxy leaf for dialing one DNS upstream (dae-aligned).
    ///
    /// 1. **Explicit** `name: 'uri' -> tag` → always resolve `tag` via
    ///    [`Self::resolve_outbound_leaf`] (forced node/group).
    /// 2. **Implicit** (no `->`): resolve the upstream server address, run the
    ///    traffic [`Router`] on that 5-tuple (+ hostname when not an IP), then
    ///    map the resulting outbound name through GroupManager — same as dae's
    ///    `chooseBestDnsDialer` → `Route(dnsServerIp)`.
    /// 3. No traffic router installed → direct dial (`None`).
    async fn resolve_dial_leaf(&self, entry: &UpstreamEntry) -> anyhow::Result<Option<Node>> {
        // 1) Forced binding wins.
        if let Some(tag) = entry.outbound.as_deref() {
            let leaf = self.resolve_outbound_leaf(tag);
            if leaf.is_none()
                && !tag.eq_ignore_ascii_case("direct")
                && !tag.eq_ignore_ascii_case("block")
            {
                anyhow::bail!("DNS upstream outbound '{tag}' has no available node");
            }
            debug!(
                "DNS dial leaf (forced -> {}): {:?}",
                tag,
                leaf.as_ref().map(|n| n.name.as_str())
            );
            return Ok(leaf);
        }

        // 2) Implicit: traffic-route the DNS server endpoint.
        let router_cell = self.traffic_router.read().clone();
        let Some(router_arc) = router_cell else {
            debug!("DNS dial leaf (no traffic router): direct");
            return Ok(None);
        };

        let target = match Self::resolve_udp_addr(entry).await {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    "DNS dial route: failed to resolve upstream host '{}': {e}; dialing direct",
                    entry.endpoint.host
                );
                return Ok(None);
            }
        };

        let host_is_ip = entry.endpoint.host.parse::<IpAddr>().is_ok();
        let l4 = match entry.protocol {
            DnsProtocol::Udp => "udp",
            _ => "tcp", // TCP / DoT / DoH / DoQ / DoH3 all dial stream/QUIC over IP
        };
        let conn = ConnectionInfo {
            domain: if host_is_ip {
                None
            } else {
                Some(entry.endpoint.host.clone())
            },
            dst_ip: target.ip(),
            dst_port: target.port(),
            src_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            protocol: l4,
            process_name: None,
            mac: None,
            dscp: None,
        };

        let outbound_name = {
            let router = router_arc.read().await;
            router.route(&conn).to_string()
        };

        debug!(
            "DNS dial route: {} {}:{} (host={}) l4={} → outbound '{}'",
            entry.endpoint.host,
            target.ip(),
            target.port(),
            entry.endpoint.host,
            l4,
            outbound_name
        );

        if outbound_name.eq_ignore_ascii_case("direct")
            || outbound_name.eq_ignore_ascii_case("block")
        {
            return Ok(None);
        }

        let leaf = self.resolve_outbound_leaf(&outbound_name);
        if leaf.is_none() {
            // Traffic said "proxy" but group is empty — surface the failure
            // instead of silently falling back to direct (would leak DNS).
            anyhow::bail!(
                "DNS dial route selected outbound '{outbound_name}' but no leaf node is available"
            );
        }
        debug!(
            "DNS dial leaf (routed via {}): {:?}",
            outbound_name,
            leaf.as_ref().map(|n| n.name.as_str())
        );
        Ok(leaf)
    }

    pub fn selector(&self, domain: &str) -> &str {
        self.router.select_upstream(domain)
    }

    pub fn upstream_count(&self) -> usize {
        self.entries.len()
    }

    fn dial_context(&self, entry: &UpstreamEntry, proxy_node: Option<&Node>) -> DialContext {
        let proxy = match (proxy_node, self.proxy_registry.as_ref()) {
            (Some(node), Some(registry)) => Some(ProxyDial {
                registry: registry.clone(),
                node: node.clone(),
            }),
            _ => None,
        };
        DialContext {
            endpoint: entry.endpoint.clone(),
            query_timeout: self.dns_query_timeout,
            dial_timeout: self.dns_dial_timeout,
            proxy,
        }
    }

    fn build_transport(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&Node>,
    ) -> anyhow::Result<PooledTransport> {
        let protocol = entry.protocol;
        let endpoint = entry.endpoint.clone();
        let dial = self.dial_context(entry, proxy_node);
        let query_timeout = self.dns_query_timeout;
        Ok(match protocol {
            DnsProtocol::Tcp => PooledTransport::Tcp(TcpPool::new(dial)),
            DnsProtocol::Tls => PooledTransport::Dot(DotPool::new(dial)?),
            DnsProtocol::Https => PooledTransport::Doh(DohClient::new(dial)?),
            DnsProtocol::Quic => PooledTransport::Doq(DoqClient::new(endpoint, query_timeout)?),
            DnsProtocol::H3 => PooledTransport::Doh3(Doh3Client::new(endpoint, query_timeout)?),
            DnsProtocol::Udp => anyhow::bail!("internal: UDP has no pooled transport"),
        })
    }

    /// Get or create a pooled transport for this upstream + leaf node.
    async fn get_transport(
        &self,
        entry: &UpstreamEntry,
        proxy_node: Option<&Node>,
    ) -> anyhow::Result<Arc<PooledTransport>> {
        let key = proxy_node.map(|n| n.name.clone()).unwrap_or_default();
        {
            let guard = entry.transports.lock().await;
            if let Some(t) = guard.get(&key) {
                return Ok(t.clone());
            }
        }
        let built = Arc::new(self.build_transport(entry, proxy_node)?);
        let mut guard = entry.transports.lock().await;
        // Another task may have won the race — reuse theirs.
        if let Some(t) = guard.get(&key) {
            return Ok(t.clone());
        }
        guard.insert(key, built.clone());
        Ok(built)
    }

    async fn query_udp(
        addr: SocketAddr,
        raw_query: &[u8],
        dns_query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let sock2 = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        sock2.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        {
            sock2.set_mark(DAE_BYPASS_MARK)?;
        }
        sock2.bind(
            &SocketAddr::new(
                if addr.is_ipv4() {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                },
                0,
            )
            .into(),
        )?;
        let socket = tokio::net::UdpSocket::from_std(sock2.into())?;
        socket.connect(addr).await?;

        let resp = tokio::time::timeout(dns_query_timeout, async {
            socket.send(raw_query).await?;
            let mut buf = vec![0u8; 4096];
            let n = socket.recv(&mut buf).await?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("UDP DNS query to {addr} timed out after {dns_query_timeout:?}")
        })??;
        Ok(resp)
    }

    async fn resolve_udp_addr(entry: &UpstreamEntry) -> anyhow::Result<SocketAddr> {
        // Fast path: address already a SocketAddr (common for LAN resolvers).
        if let Ok(addr) = entry.address.parse::<SocketAddr>() {
            return Ok(addr);
        }
        entry.endpoint.resolve_addr().await
    }
}

#[async_trait::async_trait]
impl DnsUpstreamPool for UpstreamPool {
    async fn query(&self, upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        debug!(
            "UpstreamPool::query called for '{}' ({} bytes)",
            upstream_name,
            raw_query.len()
        );
        let entry = self
            .entries
            .get(upstream_name)
            .ok_or_else(|| anyhow::anyhow!("unknown upstream: {}", upstream_name))?;

        // Dial leaf: explicit `-> tag` OR dae-style traffic Route(dnsServer).
        let proxy_node = self
            .resolve_dial_leaf(entry)
            .await
            .map_err(|e| anyhow::anyhow!("DNS upstream '{upstream_name}': {e}"))?;
        debug!(
            "DNS upstream '{}' dial leaf={:?} (forced={})",
            upstream_name,
            proxy_node.as_ref().map(|n| n.name.as_str()),
            entry.outbound.is_some()
        );

        // UDP stays connectionless; with outbound we tunnel as TCP DNS over proxy
        // (SOCKS5 UDP associate is not wired for DNS yet).
        if entry.protocol == DnsProtocol::Udp {
            if proxy_node.is_none() {
                let addr = Self::resolve_udp_addr(entry).await?;
                let response = Self::query_udp(addr, raw_query, self.dns_query_timeout).await?;
                debug!(
                    "DNS upstream '{}' (udp {}) returned {} bytes",
                    upstream_name,
                    addr,
                    response.len()
                );
                return Ok(response);
            }
            let dial = self.dial_context(entry, proxy_node.as_ref());
            let pool = TcpPool::new(dial);
            let response = pool.exchange(raw_query).await?;
            debug!(
                "DNS upstream '{}' (udp via proxy {}) returned {} bytes",
                upstream_name,
                proxy_node.as_ref().map(|n| n.name.as_str()).unwrap_or("?"),
                response.len()
            );
            return Ok(response);
        }

        // DoQ/DoH3 cannot currently ride a TCP proxy tunnel; require direct path.
        if matches!(entry.protocol, DnsProtocol::Quic | DnsProtocol::H3) && proxy_node.is_some() {
            anyhow::bail!(
                "DNS upstream '{}' protocol {:?} does not support outbound proxy yet",
                upstream_name,
                entry.protocol
            );
        }

        let transport = self.get_transport(entry, proxy_node.as_ref()).await?;
        let response = match transport.as_ref() {
            PooledTransport::Tcp(p) => p.exchange(raw_query).await?,
            PooledTransport::Dot(p) => p.exchange(raw_query).await?,
            PooledTransport::Doh(p) => p.exchange(raw_query).await?,
            PooledTransport::Doq(p) => p.exchange(raw_query).await?,
            PooledTransport::Doh3(p) => p.exchange(raw_query).await?,
        };
        debug!(
            "DNS upstream '{}' ({:?} {} via {:?}) returned {} bytes",
            upstream_name,
            entry.protocol,
            entry.endpoint.host,
            proxy_node
                .as_ref()
                .map(|n| n.name.as_str())
                .unwrap_or("direct"),
            response.len()
        );
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_router() -> Arc<DnsRouter> {
        Arc::new(
            DnsRouter::new(&honk_config::dns::DnsRouting {
                rules: vec![],
                fallback: "default".into(),
                ..Default::default()
            })
            .unwrap(),
        )
    }

    fn make_upstream(name: &str, addr: &str, protocol: DnsProtocol) -> DnsUpstream {
        DnsUpstream {
            name: name.to_string(),
            address: addr.to_string(),
            protocol,
            tls_server_name: None,
            outbound: None,
        }
    }

    fn mock_dns_response(txid: u16) -> Vec<u8> {
        vec![
            (txid >> 8) as u8,
            txid as u8,
            0x81,
            0x80,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x07,
            b'e',
            b'x',
            b'a',
            b'm',
            b'p',
            b'l',
            b'e',
            0x03,
            b'c',
            b'o',
            b'm',
            0x00,
            0x00,
            0x01,
            0x00,
            0x01,
            0xc0,
            0x0c,
            0x00,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x3c,
            0x00,
            0x04,
            0x7f,
            0x00,
            0x00,
            0x01,
        ]
    }

    fn mock_dns_query(txid: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&txid.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00]);
        query.extend_from_slice(&[0x00, 0x01]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.extend_from_slice(&[0x00, 0x00]);
        query.push(0x07);
        query.extend_from_slice(b"example");
        query.push(0x03);
        query.extend_from_slice(b"com");
        query.push(0x00);
        query.extend_from_slice(&[0x00, 0x01]);
        query.extend_from_slice(&[0x00, 0x01]);
        query
    }

    #[tokio::test]
    async fn test_udp_query() {
        let response = mock_dns_response(0x1234);
        let response_clone = response.clone();

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, src) = server.recv_from(&mut buf).await.unwrap();
            assert!(n > 0);
            server.send_to(&response_clone, src).await.unwrap();
        });

        let upstream = make_upstream("test-udp", &server_addr.to_string(), DnsProtocol::Udp);
        let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
        let result = pool
            .query("test-udp", &mock_dns_query(0x1234))
            .await
            .expect("UDP query should succeed");

        assert_eq!(result, response);
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_query_pooled() {
        let response = mock_dns_response(0x5678);
        let response_clone = response.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Serve two queries on the same connection (pool reuse).
            for _ in 0..2 {
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await.unwrap();
                let query_len = u16::from_be_bytes(len_buf) as usize;
                let mut query_buf = vec![0u8; query_len];
                stream.read_exact(&mut query_buf).await.unwrap();
                assert!(!query_buf.is_empty());

                let resp_len = response_clone.len() as u16;
                stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
                stream.write_all(&response_clone).await.unwrap();
            }
        });

        let upstream = make_upstream("test-tcp", &server_addr.to_string(), DnsProtocol::Tcp);
        let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
        let q = mock_dns_query(0x5678);
        let r1 = pool.query("test-tcp", &q).await.expect("TCP query 1");
        let r2 = pool.query("test-tcp", &q).await.expect("TCP query 2");
        assert_eq!(r1, response);
        assert_eq!(r2, response);
        server_handle.await.unwrap();
    }

    #[test]
    fn parses_encrypted_upstream_at_construction() {
        let ups = [
            make_upstream("dot", "dns.google", DnsProtocol::Tls),
            make_upstream("doh", "cloudflare-dns.com/dns-query", DnsProtocol::Https),
            make_upstream("doq", "dns.adguard.com", DnsProtocol::Quic),
            make_upstream("h3", "cloudflare-dns.com/dns-query", DnsProtocol::H3),
        ];
        let pool = UpstreamPool::new(&ups, make_router()).unwrap();
        assert_eq!(pool.upstream_count(), 4);
    }

    fn test_node(name: &str) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..Default::default()
        }
    }

    fn test_group(
        name: &str,
        policy: honk_config::group::GroupPolicy,
        ids: Vec<uuid::Uuid>,
    ) -> Group {
        use chrono::Utc;
        Group {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            policy,
            nodes: ids,
            filters: vec![],
            groups: vec![],
            default: None,
            final_outbound: None,
            check_url: None,
            check_interval: None,
            tolerance: 50,
            idle_timeout: None,
            interrupt_connections: false,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn resolve_outbound_leaf_node_by_name() {
        let a = test_node("hk-1");
        let pool = UpstreamPool::new_with_proxy(&[], make_router(), None, vec![a.clone()], vec![])
            .unwrap();
        let leaf = pool.resolve_outbound_leaf("hk-1").unwrap();
        assert_eq!(leaf.name, "hk-1");
        assert!(pool.resolve_outbound_leaf("direct").is_none());
        assert!(pool.resolve_outbound_leaf("missing").is_none());
    }

    #[test]
    fn resolve_outbound_group_uses_group_manager_selector() {
        use honk_config::group::GroupPolicy;
        use honk_outbound::group::GroupManager;

        let a = test_node("alpha");
        let b = test_node("beta");
        let mut g = test_group("proxy", GroupPolicy::Selector, vec![a.id, b.id]);
        g.default = Some("beta".into());
        let gm = GroupManager::new(&[g], &[a.clone(), b.clone()]);
        // Runtime Selector override must win (same as traffic).
        gm.set_selector_choice("proxy", "alpha");
        let shared = gm.into_shared();

        let mut google = make_upstream("google", "dns.google/dns-query", DnsProtocol::Https);
        google.outbound = Some("proxy".into());

        let pool = UpstreamPool::new_with_proxy(&[google], make_router(), None, vec![a, b], vec![])
            .unwrap()
            .with_group_manager(shared);

        let leaf = pool.resolve_outbound_leaf("proxy").unwrap();
        assert_eq!(
            leaf.name, "alpha",
            "DNS outbound must honor Selector choice like traffic"
        );

        // Switch selector — next DNS query must pick the new leaf.
        pool.group_manager
            .read()
            .as_ref()
            .unwrap()
            .read()
            .set_selector_choice("proxy", "beta");
        let leaf2 = pool.resolve_outbound_leaf("proxy").unwrap();
        assert_eq!(leaf2.name, "beta");
    }

    #[test]
    fn resolve_outbound_group_without_gm_uses_first_member() {
        use honk_config::group::GroupPolicy;

        let a = test_node("first");
        let b = test_node("second");
        let g = test_group("proxy", GroupPolicy::URLTest, vec![a.id, b.id]);
        let pool =
            UpstreamPool::new_with_proxy(&[], make_router(), None, vec![a, b], vec![g]).unwrap();
        // No GroupManager: legacy first-member fallback for unit tests.
        assert_eq!(pool.resolve_outbound_leaf("proxy").unwrap().name, "first");
    }

    #[tokio::test]
    async fn resolve_dial_leaf_forced_arrow_bypasses_traffic_router() {
        use crate::routing::Router;
        use honk_config::group::GroupPolicy;
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        use honk_outbound::group::GroupManager;

        let a = test_node("forced-node");
        let b = test_node("routed-node");
        let g_force = test_group("force_g", GroupPolicy::Selector, vec![a.id]);
        let g_route = test_group("route_g", GroupPolicy::Selector, vec![b.id]);
        let gm = GroupManager::new(&[g_force, g_route], &[a.clone(), b.clone()]).into_shared();

        // Traffic router would send 8.8.8.8 → route_g, but forced -> force_g wins.
        let rules = vec![RoutingRule {
            name: "dns-google".into(),
            condition: RoutingCondition {
                ip: vec!["8.8.8.8/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("route_g".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let traffic = Arc::new(AsyncRwLock::new(Router::new(&rules, "direct").unwrap()));

        let mut up = make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp);
        up.outbound = Some("force_g".into()); // explicit `-> force_g`

        let pool = UpstreamPool::new_with_proxy(&[up], make_router(), None, vec![a, b], vec![])
            .unwrap()
            .with_group_manager(gm)
            .with_traffic_router(traffic);

        let entry = pool.entries.get("google").unwrap();
        let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
        assert_eq!(leaf.name, "forced-node");
    }

    #[tokio::test]
    async fn resolve_dial_leaf_implicit_uses_traffic_router() {
        use crate::routing::Router;
        use honk_config::group::GroupPolicy;
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
        use honk_outbound::group::GroupManager;

        let a = test_node("proxy-leaf");
        let g = test_group("proxy", GroupPolicy::Selector, vec![a.id]);
        let gm = GroupManager::new(&[g], std::slice::from_ref(&a)).into_shared();

        // No explicit -> on upstream; 8.8.8.8 → proxy via traffic routing.
        let rules = vec![RoutingRule {
            name: "to-proxy".into(),
            condition: RoutingCondition {
                ip: vec!["8.8.8.8/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("proxy".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let traffic = Arc::new(AsyncRwLock::new(Router::new(&rules, "direct").unwrap()));

        let up = make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp); // no outbound

        let pool = UpstreamPool::new_with_proxy(&[up], make_router(), None, vec![a], vec![])
            .unwrap()
            .with_group_manager(gm)
            .with_traffic_router(traffic);

        let entry = pool.entries.get("google").unwrap();
        let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
        assert_eq!(
            leaf.name, "proxy-leaf",
            "implicit dial must follow traffic Route"
        );
    }

    #[tokio::test]
    async fn resolve_dial_leaf_implicit_direct_when_route_is_direct() {
        use crate::routing::Router;
        use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};

        // 223.5.5.5 → direct
        let rules = vec![RoutingRule {
            name: "cn-dns".into(),
            condition: RoutingCondition {
                ip: vec!["223.5.5.5/32".into()],
                ..Default::default()
            },
            outbound: RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        }];
        let traffic = Arc::new(AsyncRwLock::new(Router::new(&rules, "proxy").unwrap()));

        let up = make_upstream("alidns", "223.5.5.5:53", DnsProtocol::Udp);
        let pool = UpstreamPool::new_with_proxy(&[up], make_router(), None, vec![], vec![])
            .unwrap()
            .with_traffic_router(traffic);

        let entry = pool.entries.get("alidns").unwrap();
        let leaf = pool.resolve_dial_leaf(entry).await.unwrap();
        assert!(
            leaf.is_none(),
            "geoip/cn-style direct route → no proxy leaf"
        );
    }

    #[tokio::test]
    async fn resolve_dial_leaf_implicit_default_fallback() {
        use crate::routing::Router;

        // Empty rules, default outbound = direct
        let traffic = Arc::new(AsyncRwLock::new(Router::new(&[], "direct").unwrap()));
        let up = make_upstream("any", "1.1.1.1:53", DnsProtocol::Udp);
        let pool = UpstreamPool::new_with_proxy(&[up], make_router(), None, vec![], vec![])
            .unwrap()
            .with_traffic_router(traffic);

        let entry = pool.entries.get("any").unwrap();
        assert!(pool.resolve_dial_leaf(entry).await.unwrap().is_none());
    }
}
