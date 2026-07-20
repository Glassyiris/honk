use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use honk_ebpf_common::DAE_BYPASS_MARK;
use honk_outbound::util::connect_marked_addr;

use super::forwarder::DnsUpstreamPool;
use super::routing::DnsRouter;
use crate::proxy::ProxyRegistry;
use honk_config::dns::DnsUpstream;
use honk_config::node::{Group, Node};
use honk_config::types::DnsProtocol;
use tokio::time::timeout;

/// Per-upstream state kept by the pool.
struct UpstreamEntry {
    protocol: DnsProtocol,
    /// For UDP/TCP this is `ip:port`.  For TLS/HTTPS it is the URL/host
    /// fragment as it appeared in the config (e.g. `8.8.8.8:853`).
    address: String,
    /// Optional outbound node/group name to route this upstream through.
    outbound: Option<String>,
}

pub struct UpstreamPool {
    entries: HashMap<String, UpstreamEntry>,
    router: Arc<DnsRouter>,
    /// Proxy registry used when an upstream specifies an outbound.
    proxy_registry: Option<Arc<ProxyRegistry>>,
    /// Nodes available for proxy outbound selection.
    nodes: Vec<Node>,
    /// Groups available for resolving group outbound names.
    groups: Vec<Group>,
    /// Timeout for DNS query send/receive (UDP/TCP).
    dns_query_timeout: Duration,
    /// Timeout for dialing proxy when DNS upstream uses an outbound.
    dns_dial_timeout: Duration,
}

impl UpstreamPool {
    pub fn new(upstreams: &[DnsUpstream], router: Arc<DnsRouter>) -> anyhow::Result<Self> {
        Self::new_with_proxy(upstreams, router, None, Vec::new(), Vec::new())
    }

    /// Create an upstream pool that can route queries through proxy nodes.
    pub fn new_with_proxy(
        upstreams: &[DnsUpstream],
        router: Arc<DnsRouter>,
        proxy_registry: Option<Arc<ProxyRegistry>>,
        nodes: Vec<Node>,
        groups: Vec<Group>,
    ) -> anyhow::Result<Self> {
        let mut entries = HashMap::new();
        for upstream in upstreams {
            // Validate early for plain UDP/TCP so a bad address fails at startup.
            match upstream.protocol {
                DnsProtocol::Udp | DnsProtocol::Tcp => {
                    upstream.address.parse::<SocketAddr>().map_err(|e| {
                        anyhow::anyhow!(
                            "invalid upstream address '{}' for {:?}: {}",
                            upstream.address,
                            upstream.protocol,
                            e
                        )
                    })?;
                }
                DnsProtocol::Tls | DnsProtocol::Https | DnsProtocol::Quic => {
                    // Accept as-is; parsed when the connection is opened.
                }
            }
            entries.insert(
                upstream.name.clone(),
                UpstreamEntry {
                    protocol: upstream.protocol,
                    address: upstream.address.clone(),
                    outbound: upstream.outbound.clone(),
                },
            );
        }
        Ok(Self {
            entries,
            router,
            proxy_registry,
            nodes,
            groups,
            dns_query_timeout: Duration::from_secs(3),
            dns_dial_timeout: Duration::from_secs(10),
        })
    }

    /// Override the DNS query and proxy dial timeouts from configuration.
    pub fn with_timeouts(
        mut self,
        dns_query_timeout: Duration,
        dns_dial_timeout: Duration,
    ) -> Self {
        self.dns_query_timeout = dns_query_timeout;
        self.dns_dial_timeout = dns_dial_timeout;
        self
    }

    /// Resolve an outbound name to a concrete node.
    ///
    /// Supports both node names and group names. For groups, the first node
    /// belonging to the group is returned.
    fn resolve_outbound_node(&self, outbound: &str) -> Option<&Node> {
        // Direct / block are not proxy outbounds.
        if outbound.eq_ignore_ascii_case("direct") || outbound.eq_ignore_ascii_case("block") {
            return None;
        }
        if let Some(node) = self.nodes.iter().find(|n| n.name == outbound) {
            return Some(node);
        }
        if let Some(group) = self.groups.iter().find(|g| g.name == outbound) {
            for node_id in &group.nodes {
                if let Some(node) = self.nodes.iter().find(|n| &n.id == node_id) {
                    return Some(node);
                }
            }
        }
        None
    }

    pub fn selector(&self, domain: &str) -> &str {
        self.router.select_upstream(domain)
    }

    pub fn upstream_count(&self) -> usize {
        self.entries.len()
    }

    /// Send a DNS query over UDP.
    async fn query_udp(
        addr: &SocketAddr,
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
            sock2.set_mark(honk_ebpf_common::DAE_BYPASS_MARK)?;
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
        socket.connect(*addr).await?;

        let resp = timeout(dns_query_timeout, async {
            socket.send(raw_query).await?;
            let mut buf = vec![0u8; 4096];
            let n = socket.recv(&mut buf).await?;
            buf.truncate(n);
            Ok::<_, std::io::Error>(buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("UDP DNS query timed out after 3s"))?;
        Ok(resp?)
    }

    /// Send a DNS query over DNS-over-TCP (RFC 7766 §7).
    async fn query_tcp(
        addr: &SocketAddr,
        raw_query: &[u8],
        dns_query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let stream = timeout(
            dns_query_timeout,
            connect_marked_addr(*addr, Some(DAE_BYPASS_MARK), dns_query_timeout),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TCP DNS connect timed out after 3s"))??;
        Self::query_tcp_stream(stream, raw_query, dns_query_timeout).await
    }

    /// Send a DNS query over an already-established TCP stream.
    async fn query_tcp_stream(
        mut stream: TcpStream,
        raw_query: &[u8],
        dns_query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        // Length-prefixed DNS message.
        let len = raw_query.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(raw_query).await?;
        stream.flush().await?;

        let mut len_buf = [0u8; 2];
        timeout(dns_query_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP DNS read length timed out after 3s"))??;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; resp_len];
        timeout(dns_query_timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP DNS read body timed out after 3s"))??;

        Ok(buf)
    }

    /// Send a DNS query over TCP through a proxy node.
    async fn query_tcp_via_proxy(
        proxy_registry: &ProxyRegistry,
        node: &Node,
        addr: &SocketAddr,
        raw_query: &[u8],
        dns_dial_timeout: Duration,
        dns_query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let proxy_stream = proxy_registry
            .dial(node, *addr, None, dns_dial_timeout)
            .await
            .map_err(|e| anyhow::anyhow!("proxy dial failed for DNS upstream: {}", e))?;
        // The proxy handler has already completed the protocol handshake and
        // the returned stream is connected to the upstream DNS server.
        Self::query_tcp_boxed_stream(proxy_stream.stream, raw_query, dns_query_timeout).await
    }

    /// Send a length-prefixed DNS message through a boxed async stream.
    async fn query_tcp_boxed_stream(
        mut stream: Box<dyn crate::proxy::AsyncReadWrite>,
        raw_query: &[u8],
        dns_query_timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let len = raw_query.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(raw_query).await?;
        stream.flush().await?;

        let mut len_buf = [0u8; 2];
        timeout(dns_query_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP DNS proxy read length timed out"))??;

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; resp_len];
        timeout(dns_query_timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("TCP DNS proxy read body timed out"))??;
        Ok(buf)
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

        // If an outbound is configured, route the upstream connection through
        // the proxy to avoid DNS hijacking/pollution. UDP is tunneled as TCP
        // DNS over the proxy because SOCKS5 UDP association is not yet wired.
        let proxy_node = entry
            .outbound
            .as_deref()
            .and_then(|outbound| self.resolve_outbound_node(outbound));
        if entry.outbound.is_some() {
            debug!(
                "DNS upstream '{}' outbound='{:?}' resolved proxy_node='{:?}'",
                upstream_name,
                entry.outbound,
                proxy_node.map(|n| &n.name)
            );
        }

        match entry.protocol {
            DnsProtocol::Udp if proxy_node.is_none() => {
                let addr: SocketAddr = entry.address.parse().map_err(|e| {
                    anyhow::anyhow!("invalid UDP upstream address '{}': {}", entry.address, e)
                })?;
                let response = Self::query_udp(&addr, raw_query, self.dns_query_timeout).await?;
                debug!(
                    "DNS upstream '{}' (udp {}) returned {} bytes",
                    upstream_name,
                    addr,
                    response.len()
                );
                Ok(response)
            }
            DnsProtocol::Udp => {
                let addr: SocketAddr = entry.address.parse().map_err(|e| {
                    anyhow::anyhow!("invalid UDP upstream address '{}': {}", entry.address, e)
                })?;
                let node = proxy_node.unwrap();
                let registry = self
                    .proxy_registry
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("proxy registry not available"))?;
                let response = Self::query_tcp_via_proxy(
                    registry,
                    node,
                    &addr,
                    raw_query,
                    self.dns_dial_timeout,
                    self.dns_query_timeout,
                )
                .await?;
                debug!(
                    "DNS upstream '{}' (udp {} via proxy {}) returned {} bytes",
                    upstream_name,
                    addr,
                    node.name,
                    response.len()
                );
                Ok(response)
            }
            DnsProtocol::Tcp if proxy_node.is_none() => {
                let addr: SocketAddr = entry.address.parse().map_err(|e| {
                    anyhow::anyhow!("invalid TCP upstream address '{}': {}", entry.address, e)
                })?;
                let response = Self::query_tcp(&addr, raw_query, self.dns_query_timeout).await?;
                debug!(
                    "DNS upstream '{}' (tcp {}) returned {} bytes",
                    upstream_name,
                    addr,
                    response.len()
                );
                Ok(response)
            }
            DnsProtocol::Tcp => {
                let addr: SocketAddr = entry.address.parse().map_err(|e| {
                    anyhow::anyhow!("invalid TCP upstream address '{}': {}", entry.address, e)
                })?;
                let node = proxy_node.unwrap();
                let registry = self
                    .proxy_registry
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("proxy registry not available"))?;
                let response = Self::query_tcp_via_proxy(
                    registry,
                    node,
                    &addr,
                    raw_query,
                    self.dns_dial_timeout,
                    self.dns_query_timeout,
                )
                .await?;
                debug!(
                    "DNS upstream '{}' (tcp {} via proxy {}) returned {} bytes",
                    upstream_name,
                    addr,
                    node.name,
                    response.len()
                );
                Ok(response)
            }
            DnsProtocol::Tls | DnsProtocol::Https | DnsProtocol::Quic => {
                // Best-effort fallback to plain TCP on the configured address.
                // This lets `tcp://` or `udp+tcp://` work while a proper TLS/HTTPS
                // implementation is being added.
                warn!(
                    "DNS upstream '{}' uses {:?}; falling back to TCP on '{}'",
                    upstream_name, entry.protocol, entry.address
                );
                let addr: SocketAddr = entry.address.parse().map_err(|e| {
                    anyhow::anyhow!(
                        "invalid fallback TCP upstream address '{}': {}",
                        entry.address,
                        e
                    )
                })?;
                if let Some(node) = proxy_node {
                    let registry = self
                        .proxy_registry
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("proxy registry not available"))?;
                    Self::query_tcp_via_proxy(
                        registry,
                        node,
                        &addr,
                        raw_query,
                        self.dns_dial_timeout,
                        self.dns_query_timeout,
                    )
                    .await
                } else {
                    Self::query_tcp(&addr, raw_query, self.dns_query_timeout).await
                }
            }
        }
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
            bootstrap: None,
            outbound: None,
            tags: vec![],
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
        query.extend_from_slice(&(txid).to_be_bytes());
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
    async fn test_tcp_query() {
        let response = mock_dns_response(0x5678);
        let response_clone = response.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let query_len = u16::from_be_bytes(len_buf) as usize;
            let mut query_buf = vec![0u8; query_len];
            stream.read_exact(&mut query_buf).await.unwrap();
            assert!(!query_buf.is_empty());

            let resp_len = response_clone.len() as u16;
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&response_clone).await.unwrap();
        });

        let upstream = make_upstream("test-tcp", &server_addr.to_string(), DnsProtocol::Tcp);
        let pool = UpstreamPool::new(&[upstream], make_router()).unwrap();
        let result = pool
            .query("test-tcp", &mock_dns_query(0x5678))
            .await
            .expect("TCP query should succeed");

        assert_eq!(result, response);
        server_handle.await.unwrap();
    }
}
