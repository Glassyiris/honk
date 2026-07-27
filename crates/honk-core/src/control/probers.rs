use super::*;

/// HTTP-based health check prober that routes requests through proxy nodes.
///
/// Implements `HttpProber` for `AliveDialerSet`, matching Go's `Dialer.HttpCheck`.
/// Resolves the check URL's hostname, dials through the proxy node via the
/// `ProxyRegistry`, sends a raw HTTP request, and validates the status code.
pub(super) struct ProxyHttpProber {
    config: Arc<RwLock<Config>>,
    proxy_registry: Arc<ProxyRegistry>,
    check_method: String,
}

impl ProxyHttpProber {
    pub(super) fn new(
        config: Arc<RwLock<Config>>,
        proxy_registry: Arc<ProxyRegistry>,
        check_method: String,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            check_method,
        }
    }

    /// Find a node by name in the current config.
    fn find_node(&self, node_name: &str) -> Option<Node> {
        self.config
            .try_read()
            .ok()?
            .nodes
            .iter()
            .find(|n| n.name == node_name)
            .cloned()
    }
}

impl honk_outbound::alive::HttpProber for ProxyHttpProber {
    fn probe_http(
        &self,
        node_name: &str,
        addr: SocketAddr,
        url: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<std::time::Duration, String>> + Send + 'static>,
    > {
        let node = self.find_node(node_name);
        let node_name_owned = node_name.to_string();
        let registry = self.proxy_registry.clone();
        let check_url = url.to_string();
        let check_method = self.check_method.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let node = node.ok_or_else(|| format!("node '{}' not found", node_name_owned))?;
            let handler = registry
                .find(node.protocol)
                .ok_or_else(|| format!("no handler for protocol {:?}", node.protocol))?;

            let start = std::time::Instant::now();
            let connect_timeout = {
                let config = config
                    .try_read()
                    .map_err(|_| "config lock busy".to_string())?;
                std::time::Duration::from_millis(config.global.connect_timeout_ms)
            };
            let proxy = handler
                .dial(&node, addr, None, connect_timeout)
                .await
                .map_err(|e| format!("dial failed: {}", e))?;

            let elapsed = start.elapsed();

            // Send HTTP request over the proxy connection.
            Self::http_check(proxy.stream, &check_url, &check_method).await?;

            Ok(elapsed)
        })
    }
}

impl ProxyHttpProber {
    /// Perform an HTTP health check over an already-established connection.
    ///
    /// Sends a minimal HTTP request, reads the response status line, and
    /// validates the status code.  Status codes 200-399 are considered healthy.
    async fn http_check(
        mut stream: Box<dyn crate::proxy::AsyncReadWrite>,
        url: &str,
        method: &str,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (host, path) =
            extract_url_host_path(url).ok_or_else(|| format!("invalid check URL: {}", url))?;
        let method = if method.is_empty() { "GET" } else { method };

        // Build minimal HTTP/1.1 request
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: honk-health/1.0\r\nConnection: close\r\n\r\n",
            method, path, host
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("HTTP write failed: {}", e))?;

        // Read response until we have the status line
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .map_err(|_| "HTTP read timeout".to_string())?
            .map_err(|e| format!("HTTP read failed: {}", e))?;

        if n == 0 {
            return Err("empty HTTP response".to_string());
        }

        let response = String::from_utf8_lossy(&buf[..n]);
        let status_line = response.lines().next().unwrap_or("");

        // Parse status code: "HTTP/1.1 200 OK" → 200
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!("malformed HTTP status: {}", status_line));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| format!("invalid status code: {}", parts[1]))?;

        // Go: 200-499 = success, 5xx = failure
        if !(200..500).contains(&status_code) {
            return Err(format!("bad status code: {}", status_code));
        }

        Ok(())
    }
}

/// Default DNS target for UDP health checks when `udp_check_dns` is unset
/// or unresolvable (dae semantics: plain `8.8.8.8:53`).
const DEFAULT_UDP_CHECK_DNS: &str = "8.8.8.8:53";

/// UDP health check prober that routes a minimal DNS query through the
/// proxy node's UDP data path.
///
/// Implements `UdpProber` for `AliveDialerSet` (Go: `Dialer.UdpCheck`):
/// resolves the node, opens its UDP channel via the handler's `dial_udp`
/// (real UDP, UoT, QUIC datagrams — whatever the protocol provides),
/// sends one DNS query to the configured check DNS server, and awaits the
/// answer. Nodes whose server or protocol cannot carry UDP (e.g. an
/// AnyTLS server without UoT support) fail here even while their TCP
/// probe succeeds — exactly the signal the UDP alive domains need.
pub(super) struct ProxyUdpProber {
    config: Arc<RwLock<Config>>,
    proxy_registry: Arc<ProxyRegistry>,
    dns_target: SocketAddr,
}

impl ProxyUdpProber {
    pub(super) fn new(
        config: Arc<RwLock<Config>>,
        proxy_registry: Arc<ProxyRegistry>,
        dns_target: SocketAddr,
    ) -> Self {
        Self {
            config,
            proxy_registry,
            dns_target,
        }
    }

    /// Find a node by name in the current config.
    fn find_node(&self, node_name: &str) -> Option<Node> {
        self.config
            .try_read()
            .ok()?
            .nodes
            .iter()
            .find(|n| n.name == node_name)
            .cloned()
    }
}

impl honk_outbound::alive::UdpProber for ProxyUdpProber {
    fn probe_udp(
        &self,
        node_name: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<std::time::Duration, String>> + Send + 'static>,
    > {
        let node = self.find_node(node_name);
        let node_name_owned = node_name.to_string();
        let registry = self.proxy_registry.clone();
        let config = self.config.clone();
        let dns_target = self.dns_target;

        Box::pin(async move {
            let node = node.ok_or_else(|| format!("node '{}' not found", node_name_owned))?;
            let handler = registry
                .find(node.protocol)
                .ok_or_else(|| format!("no handler for protocol {:?}", node.protocol))?;
            let connect_timeout = {
                let config = config
                    .try_read()
                    .map_err(|_| "config lock busy".to_string())?;
                std::time::Duration::from_millis(config.global.connect_timeout_ms)
            };

            let start = std::time::Instant::now();
            let proxy = handler
                .dial_udp(&node, dns_target, None, connect_timeout)
                .await
                .map_err(|e| format!("UDP dial failed: {}", e))?;

            // One minimal DNS query; any well-formed answer proves the
            // node's UDP path round-trips end to end.
            let query = build_dns_probe_query();
            proxy
                .socket
                .send_to(&query, proxy.relay_addr)
                .await
                .map_err(|e| format!("UDP probe send failed: {}", e))?;

            let mut buf = [0u8; 512];
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                proxy.socket.recv(&mut buf),
            )
            .await
            .map_err(|_| "UDP probe recv timeout".to_string())?
            .map_err(|e| format!("UDP probe recv failed: {}", e))?;

            // Validate the DNS header: matching id + QR (response) bit.
            if n < 12 || buf[0] != query[0] || buf[1] != query[1] || buf[2] & 0x80 == 0 {
                return Err("malformed DNS probe response".to_string());
            }

            Ok(start.elapsed())
        })
    }
}

/// Build the minimal DNS query used by the UDP health probe: a single
/// A-record question for google.com with a fixed id (0x1234). The id is
/// echoed back by the resolver and validated in the response.
pub(super) fn build_dns_probe_query() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(&[
        6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    q
}

/// Resolve the UDP health check target from `global.udp_check_dns`
/// (dae semantics: `host[:port]` list, default port 53).
///
/// IP literals in the list are preferred over domain entries: the system
/// resolver can return DNS-poisoned answers for popular check domains
/// (e.g. dns.google), which would send every probe to a black hole.
/// Falls back to [`DEFAULT_UDP_CHECK_DNS`] when the list is empty or no
/// entry resolves.
pub(super) async fn resolve_udp_check_target(raws: &[String]) -> SocketAddr {
    let fallback: SocketAddr = DEFAULT_UDP_CHECK_DNS
        .parse()
        .expect("hardcoded default UDP check DNS address");
    let entries: Vec<&str> = raws
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    // First pass: literal IPs (full socket addr or bare IP with default port).
    for raw in &entries {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            return addr;
        }
        if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            return SocketAddr::new(ip, 53);
        }
    }
    // Second pass: first domain entry, resolved via system DNS.
    if let Some(raw) = entries.first() {
        let (host, port) = match raw.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h, port),
                Err(_) => (*raw, 53),
            },
            None => (*raw, 53),
        };
        match tokio::net::lookup_host((host, port)).await {
            Ok(mut addrs) => return addrs.next().unwrap_or(fallback),
            Err(e) => {
                warn!(
                    "Failed to resolve udp_check_dns '{}': {}; using {}",
                    raw, e, fallback
                );
            }
        }
    }
    fallback
}

/// Returns true if `ip` belongs to honk's own dae0 veth subnets.
///
/// The subnet constants (`crate::DAE0_IPV6_PREFIX_HI`, `crate::DAE0_IPV4_NET`)
/// live in the crate root next to the `DAENS_*` address strings used by the
/// netns setup, so this datapath check and the interface configuration
/// cannot drift apart.
pub(super) fn is_honk_internal_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            let hi = u64::from_be_bytes(octets[..8].try_into().unwrap());
            hi == crate::DAE0_IPV6_PREFIX_HI // fd00:686f:6e6b::/64
        }
        std::net::IpAddr::V4(v4) => {
            let addr: u32 = u32::from(*v4);
            (addr & 0xFFFF0000) == crate::DAE0_IPV4_NET // 169.254.0.0/16
        }
    }
}

/// Returns true for broadcast/multicast addresses that should not be
/// proxied (mDNS, SSDP, LLMNR local discovery traffic).
pub(super) fn is_broadcast_or_multicast(ip: &std::net::IpAddr) -> bool {
    if ip.is_multicast() {
        return true;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets == [255, 255, 255, 255] || octets[3] == 255
        }
        std::net::IpAddr::V6(_) => false,
    }
}

/// Extract hostname from a URL like "http://cp.cloudflare.com".
/// Extract `(host, request_path)` from a health-check URL.
///
/// The scheme is optional; with dae's comma-separated fallback list
/// (`http://host,ip4,ip6`) only the first segment contributes. The path
/// defaults to `/` when the URL has none. The port is stripped (bracketed
/// IPv6 literals are kept intact).
pub(super) fn extract_url_host_path(url: &str) -> Option<(&str, &str)> {
    let s = url.trim();
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s);
    let s = s.split(',').next().unwrap_or(s).trim();
    let (authority, path) = match s.find('/') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "/"),
    };
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(authority)
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some((host, path))
    }
}
