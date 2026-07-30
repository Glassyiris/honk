use super::*;

#[test]
fn test_build_dns_probe_query() {
    let q = build_dns_probe_query();
    assert_eq!(&q[..2], &[0x12, 0x34]); // fixed id, validated on the response
    assert_eq!(q[2], 0x01); // RD (recursion desired)
    assert_eq!(q[5], 1); // QDCOUNT = 1
    assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]); // QTYPE A / QCLASS IN
}

#[tokio::test]
async fn test_resolve_udp_check_target() {
    let fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
    assert_eq!(resolve_udp_check_target(&[], None).await, fallback);
    assert_eq!(
        resolve_udp_check_target(&["   ".into()], None).await,
        fallback
    );
    // Bare IP literals get the default DNS port.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1".into()], None).await,
        "1.1.1.1:53".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["2001:4860:4860::8888".into()], None).await,
        "[2001:4860:4860::8888]:53".parse().unwrap()
    );
    // Full socket addresses (v4 or bracketed v6) are kept as-is.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1:5353".into()], None).await,
        "1.1.1.1:5353".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["[2606:4700:4700::1111]:53".into()], None).await,
        "[2606:4700:4700::1111]:53".parse().unwrap()
    );
    // Literals win over domain entries anywhere in the list (poison-proof).
    assert_eq!(
        resolve_udp_check_target(&["dns.google".into(), "8.8.8.8".into()], None).await,
        "8.8.8.8:53".parse().unwrap()
    );
    // host:port resolves via the system resolver ("localhost" needs no
    // external network).
    let addr = resolve_udp_check_target(&["localhost:5353".into()], None).await;
    assert_eq!(addr.port(), 5353);
    assert!(addr.ip().is_loopback());

    // A domain entry is resolved through the installed hook when present.
    let hook: crate::outbound::ResolveHook = std::sync::Arc::new(|host, port| {
        Box::pin(async move {
            assert_eq!(host, "dns.example");
            vec![std::net::SocketAddr::new(
                std::net::IpAddr::from([10, 9, 8, 7]),
                port,
            )]
        })
    });
    assert_eq!(
        resolve_udp_check_target(&["dns.example".into()], Some(hook)).await,
        "10.9.8.7:53".parse().unwrap()
    );
}

#[test]
fn extract_url_host_path_parses_all_forms() {
    // Regression: path must not leak into the Host header / DNS name.
    assert_eq!(
        extract_url_host_path("http://www.google-analytics.com/generate_204"),
        Some(("www.google-analytics.com", "/generate_204"))
    );
    assert_eq!(
        extract_url_host_path("www.google-analytics.com/generate_204"),
        Some(("www.google-analytics.com", "/generate_204"))
    );
    assert_eq!(
        extract_url_host_path("https://cp.cloudflare.com/"),
        Some(("cp.cloudflare.com", "/"))
    );
    assert_eq!(
        extract_url_host_path("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111"),
        Some(("cp.cloudflare.com", "/"))
    );
    assert_eq!(
        extract_url_host_path("http://example.com:8080/check?q=1"),
        Some(("example.com", "/check?q=1"))
    );
    assert_eq!(
        extract_url_host_path("http://[2606:4700:4700::1111]:443/"),
        Some(("2606:4700:4700::1111", "/"))
    );
    assert_eq!(extract_url_host_path(""), None);
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A minimal DNS query payload for "a.com" (A record).
fn dns_query_payload() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(&[
        0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]);
    q
}

#[test]
fn might_be_dns_query_matches_controller_condition() {
    // Real query: consumed by the DNS controller.
    assert!(might_be_dns_query(&dns_query_payload()));
    // QR bit set (response): not a query.
    let mut resp = dns_query_payload();
    resp[2] |= 0x80;
    assert!(!might_be_dns_query(&resp));
    // Too short / garbage: not a query.
    assert!(!might_be_dns_query(b"hello"));
    assert!(!might_be_dns_query(&[0u8; 20])); // qdcount == 0
}

#[tokio::test]
async fn udp_fast_path_miss_goes_slow() {
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    assert!(!udp_fast_path(&pool, &stats, b"hello", client, dst).await);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_misses, 1);
    assert_eq!(udp.endpoint_hits, 0);
}

#[tokio::test]
async fn udp_fast_path_hit_forwards_inline() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy.local_addr().unwrap();
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    let (_ep, is_new) = pool
        .get_or_create(
            client,
            dst,
            std::sync::Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
                proxy, echo_addr,
            )),
            echo_addr,
            "test-node".to_string(),
        )
        .unwrap();
    assert!(is_new);

    assert!(udp_fast_path(&pool, &stats, b"hello", client, dst).await);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 1);
    assert_eq!(udp.endpoint_misses, 0);

    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, proxy_addr);
}

#[tokio::test]
async fn udp_fast_path_dns_goes_slow_even_with_endpoint() {
    // A real DNS query must reach the DNS controller even when an
    // endpoint exists for (client, dst) — today's order is DNS first.
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (_ep, is_new) = pool
        .get_or_create(
            client,
            dst,
            std::sync::Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
                proxy,
                addr("127.0.0.1:9"),
            )),
            addr("127.0.0.1:9"),
            "test-node".to_string(),
        )
        .unwrap();
    assert!(is_new);

    assert!(!udp_fast_path(&pool, &stats, &dns_query_payload(), client, dst).await);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 0);
    assert_eq!(udp.endpoint_misses, 0);
}

#[tokio::test]
async fn udp_fast_path_non_dns_port53_forwards() {
    // Garbage to port 53 is not a DNS query: the endpoint forwards it,
    // exactly like the slow path does after handle_udp_dns declines.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let (_ep, is_new) = pool
        .get_or_create(
            client,
            dst,
            std::sync::Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
                proxy, echo_addr,
            )),
            echo_addr,
            "test-node".to_string(),
        )
        .unwrap();
    assert!(is_new);

    let garbage = [0u8; 20]; // QR=0 but qdcount=0 — not a DNS query
    assert!(udp_fast_path(&pool, &stats, &garbage, client, dst).await);
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], &garbage[..]);
}

#[tokio::test]
async fn udp_fast_path_drops_internal_and_broadcast() {
    let pool = UdpEndpointPool::new();
    let stats = StatsManager::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    // honk-internal subnets (v4 + v6), either direction.  The v6 check
    // must match the real dae0 addresses (fd00:686f:6e6b::1/2, see the
    // DAENS_* constants in the crate root).
    assert!(udp_fast_path(&pool, &stats, b"hello", client, addr("169.254.0.11:8080")).await);
    assert!(udp_fast_path(&pool, &stats, b"hello", addr("169.254.0.1:1234"), dst).await);
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("[fd00:686f:6e6b::1]:8080")
        )
        .await
    );
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            addr("[fd00:686f:6e6b::2]:1234"),
            dst
        )
        .await
    );
    // Broadcast / multicast destinations.
    assert!(udp_fast_path(&pool, &stats, b"hello", client, addr("255.255.255.255:67")).await);
    assert!(udp_fast_path(&pool, &stats, b"hello", client, addr("192.168.1.255:67")).await);
    assert!(
        udp_fast_path(
            &pool,
            &stats,
            b"hello",
            client,
            addr("239.255.255.250:1900")
        )
        .await
    );
    // Drops do not count as endpoint misses and nothing is pooled.
    assert!(pool.is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 0);
    assert_eq!(udp.endpoint_misses, 0);
}

#[test]
fn dae0_internal_addr_covers_real_dae0_addresses() {
    // The internal-addr check must match the actual dae0/dae0peer
    // addresses assigned by the netns setup; both sides share the
    // DAENS_*/DAE0_* constants in the crate root so they cannot drift.
    for s in [
        crate::DAENS_HOST_IPV6,
        crate::DAENS_PEER_IPV6,
        crate::DAENS_HOST_IP,
        crate::DAENS_PEER_IP,
    ] {
        let ip: std::net::IpAddr = s.parse().unwrap();
        assert!(
            is_honk_internal_addr(&ip),
            "{} must be classified as honk-internal",
            s
        );
    }
    // Other hosts inside the same subnets.
    assert!(is_honk_internal_addr(
        &"fd00:686f:6e6b::beef".parse().unwrap()
    ));
    assert!(is_honk_internal_addr(&"169.254.0.200".parse().unwrap()));
    // Outside the subnets — including fd00:dae:d000::/64, the value of
    // the old wrong DAE0_IPV6_PREFIX_HI constant that never matched the
    // real dae0 addresses.
    assert!(!is_honk_internal_addr(&"fd00:dae:d000::1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"fd00:daec::1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"192.168.0.1".parse().unwrap()));
    assert!(!is_honk_internal_addr(&"10.0.0.1".parse().unwrap()));
}

#[test]
fn subscription_merge_replaces_only_that_subscription() {
    fn node(name: &str, sub: Option<uuid::Uuid>) -> Node {
        Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            address: "127.0.0.1:1".into(),
            host: "127.0.0.1".into(),
            port: 1,
            subscription_id: sub,
            ..Default::default()
        }
    }

    let sub_a = uuid::Uuid::new_v4();
    let sub_b = uuid::Uuid::new_v4();
    let static_node = node("static", None);
    let old_a1 = node("a-old-1", Some(sub_a));
    let old_a2 = node("a-old-2", Some(sub_a));
    let b_node = node("b-1", Some(sub_b));

    let mut current = Config {
        nodes: vec![
            static_node.clone(),
            old_a1.clone(),
            old_a2.clone(),
            b_node.clone(),
        ],
        groups: vec![honk_config::node::Group {
            name: "proxy".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    // Resolve initial membership exactly like startup does; the
    // filter-less group swallows every node.
    honk_config::parser::resolve_group_filters(&mut current.groups, &current.nodes);
    assert_eq!(current.groups[0].nodes.len(), 4);

    let new_a1 = node("a-new-1", Some(sub_a));
    let merged = config_with_subscription_nodes(&current, sub_a, vec![new_a1.clone()]);

    // Old sub-A nodes are gone; static and other-subscription nodes stay.
    let names: Vec<&str> = merged.nodes.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec!["static", "b-1", "a-new-1"]);
    // Group membership was pruned of dangling IDs and re-resolved:
    // exactly the three live nodes, no stale UUIDs.
    assert_eq!(merged.groups[0].nodes.len(), 3);
    for id in &merged.groups[0].nodes {
        assert!(merged.nodes.iter().any(|n| n.id == *id));
    }
    assert!(!merged.groups[0].nodes.contains(&old_a1.id));
    assert!(!merged.groups[0].nodes.contains(&old_a2.id));

    // Re-merging the same subscription replaces instead of duplicating.
    let new_a1b = node("a-new-1", Some(sub_a));
    let remerged = config_with_subscription_nodes(&merged, sub_a, vec![new_a1b.clone()]);
    assert_eq!(remerged.nodes.len(), 3);
    assert_eq!(remerged.groups[0].nodes.len(), 3);
    assert_eq!(remerged.nodes[2].id, new_a1b.id);
}

#[test]
fn domain_reality_exact_match_same_family() {
    let v4: std::net::IpAddr = "104.20.22.25".parse().unwrap();
    let v6: std::net::IpAddr = "2606:4700:10::6814:1619".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(v4, &[v4], &[]),
        RealityOutcome::ExactMatch
    );
    assert_eq!(
        domain_reality_outcome(v6, &[], &[v6]),
        RealityOutcome::ExactMatch
    );
}

#[test]
fn domain_reality_ipv6_conn_ipv4_only_answers_trusts_sni() {
    // tracker.m-team.cc on CF IPv6 while resolver only has A (Ipv4Only).
    let conn_v6: std::net::IpAddr = "2606:4700:10::6814:1619".parse().unwrap();
    let a1: std::net::IpAddr = "172.66.165.79".parse().unwrap();
    let a2: std::net::IpAddr = "104.20.22.25".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(conn_v6, &[a1, a2], &[]),
        RealityOutcome::OtherFamilyOnly
    );
}

#[test]
fn domain_reality_same_family_wrong_ip_is_mismatch() {
    let conn: std::net::IpAddr = "1.2.3.4".parse().unwrap();
    let other: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(
        domain_reality_outcome(conn, &[other], &[]),
        RealityOutcome::Mismatch
    );
    // Empty both families → mismatch (resolve returned nothing useful).
    assert_eq!(
        domain_reality_outcome(conn, &[], &[]),
        RealityOutcome::Mismatch
    );
}

#[derive(Debug, Clone)]
enum UdpTestMode {
    DialError,
    SendError,
    Success,
    Hold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
}

#[derive(Debug)]
struct UdpTestTransport {
    mode: UdpTestMode,
    relay: SocketAddr,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for UdpTestTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        match self.mode {
            UdpTestMode::SendError => Err(std::io::Error::other("first UDP send failed")),
            _ => Ok(()),
        }
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

#[derive(Debug)]
struct UdpTestHandler {
    mode: UdpTestMode,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::ProxyHandler for UdpTestHandler {
    fn protocol(&self) -> honk_config::types::NodeProtocol {
        honk_config::types::NodeProtocol::HTTP
    }

    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        Err(anyhow::anyhow!(
            "TCP dial is not used by the UDP lifecycle tests"
        ))
    }

    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        if let UdpTestMode::Hold { entered, release } = &self.mode {
            entered.notify_one();
            release.notified().await;
        }
        match self.mode {
            UdpTestMode::DialError => Err(anyhow::anyhow!("UDP dial failed")),
            _ => Ok(Arc::new(UdpTestTransport {
                mode: self.mode.clone(),
                relay: target,
            })),
        }
    }
}

fn udp_test_forwarder() -> Arc<crate::dns::forwarder::DnsForwarder> {
    let router = Arc::new(
        crate::dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(crate::dns::upstream_pool::UpstreamPool::new(&[], router.clone()).unwrap()),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false),
    )
}

fn udp_test_config(default_outbound: &str, nodes: Vec<Node>, groups: Vec<Group>) -> Config {
    let mut config = Config::default();
    config.nodes = nodes;
    config.groups = groups;
    config.routing.default_outbound = default_outbound.into();
    config
}

fn udp_test_node() -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: "udp-test".into(),
        protocol: honk_config::types::NodeProtocol::HTTP,
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    }
}

fn udp_test_handle(config: Config, mode: UdpTestMode, capacity: usize) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    registry.register(Box::new(UdpTestHandler { mode }));
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_capacity_limit(capacity));
    control_plane.spawn_handle()
}

async fn serve_test_udp(handle: &ControlPlaneHandle) -> anyhow::Result<()> {
    handle
        .serve_udp_connection(
            Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            bytes::Bytes::from_static(b"UDP test packet"),
            addr("10.0.0.2:53000"),
            addr("203.0.113.2:443"),
        )
        .await
}

fn assert_udp_outbound(
    stats: &Arc<StatsManager>,
    outbound: &str,
    total_connections: u32,
    active_connections: u32,
    errors: u32,
) {
    let snapshot = stats.snapshot();
    let actual = snapshot
        .get(outbound)
        .unwrap_or_else(|| panic!("missing outbound stats for {outbound}"));
    assert_eq!(actual.total_conns, total_connections);
    assert_eq!(actual.active_conns, active_connections);
    assert_eq!(actual.errors, errors);
}

#[tokio::test]
async fn udp_stats_lifecycle_no_candidate_closes_guard_and_records_error() {
    let config = udp_test_config(
        "empty",
        vec![],
        vec![Group {
            name: "empty".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            ..Default::default()
        }],
    );
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert_udp_outbound(&stats, "empty", 1, 0, 1);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.route_latency.count, 1);
    assert_eq!(udp.dial_latency.count, 0);
}

#[tokio::test]
async fn udp_stats_lifecycle_dial_error_closes_guard_and_samples_dial() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::DialError, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert_udp_outbound(&stats, "udp-test", 1, 0, 1);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.route_latency.count, 1);
    assert_eq!(udp.dial_latency.count, 1);
}

#[tokio::test]
async fn udp_stats_lifecycle_capacity_after_send_closes_guard() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::Success, 0);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert_udp_outbound(&stats, "udp-test", 1, 0, 0);
}

#[tokio::test]
async fn udp_stats_lifecycle_first_send_error_closes_guard_and_records_error() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::SendError, 1);
    let stats = handle.stats.clone();

    assert!(serve_test_udp(&handle).await.is_err());

    assert_udp_outbound(&stats, "udp-test", 1, 0, 1);
}

#[tokio::test]
async fn udp_stats_lifecycle_slow_future_cancellation_drops_guard_without_error() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::Hold {
            entered: entered.clone(),
            release,
        },
        1,
    );
    let stats = handle.stats.clone();
    let task = tokio::spawn(async move { serve_test_udp(&handle).await });

    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production slow path did not reach the injected dialer");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    assert_udp_outbound(&stats, "udp-test", 1, 0, 0);
}

#[tokio::test]
async fn udp_stats_lifecycle_success_and_reply_eof_close_guard() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();
    tokio::task::yield_now().await;

    assert_udp_outbound(&stats, "udp-test", 1, 0, 0);
}

#[tokio::test]
async fn udp_stats_lifecycle_slow_permit_full_rejects_without_outbound_total() {
    // Exercise the production admission helper used by the accept-loop slow
    // path. A full semaphore must bump only udp.slowPermit.rejected and must
    // never open an outbound connection counter.
    let stats = Arc::new(StatsManager::new());
    let full = Arc::new(tokio::sync::Semaphore::new(0));

    assert!(super::try_admit_udp_slow_path(&stats, &full).is_none());

    assert!(stats.snapshot().is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_rejected, 1);
    assert_eq!(udp.slow_permit_accepted, 0);
    assert_eq!(udp.slow_permit_closed, 0);
    assert_eq!(udp.queue_accepted, 0);
    assert_eq!(udp.queue_full, 0);
    assert_eq!(udp.queue_closed, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = super::try_admit_udp_slow_path(&stats, &open).expect("slow path should admit");
    drop(permit);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(udp.slow_permit_rejected, 1);
    assert!(stats.snapshot().is_empty());
}
