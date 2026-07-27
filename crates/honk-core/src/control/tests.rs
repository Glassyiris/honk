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
    assert_eq!(resolve_udp_check_target(&[]).await, fallback);
    assert_eq!(resolve_udp_check_target(&["   ".into()]).await, fallback);
    // Bare IP literals get the default DNS port.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1".into()]).await,
        "1.1.1.1:53".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["2001:4860:4860::8888".into()]).await,
        "[2001:4860:4860::8888]:53".parse().unwrap()
    );
    // Full socket addresses (v4 or bracketed v6) are kept as-is.
    assert_eq!(
        resolve_udp_check_target(&["1.1.1.1:5353".into()]).await,
        "1.1.1.1:5353".parse().unwrap()
    );
    assert_eq!(
        resolve_udp_check_target(&["[2606:4700:4700::1111]:53".into()]).await,
        "[2606:4700:4700::1111]:53".parse().unwrap()
    );
    // Literals win over domain entries anywhere in the list (poison-proof).
    assert_eq!(
        resolve_udp_check_target(&["dns.google".into(), "8.8.8.8".into()]).await,
        "8.8.8.8:53".parse().unwrap()
    );
    // host:port resolves via the system resolver ("localhost" needs no
    // external network).
    let addr = resolve_udp_check_target(&["localhost:5353".into()]).await;
    assert_eq!(addr.port(), 5353);
    assert!(addr.ip().is_loopback());
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
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    assert!(!udp_fast_path(&pool, b"hello", client, dst).await);
}

#[tokio::test]
async fn udp_fast_path_hit_forwards_inline() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy.local_addr().unwrap();
    let pool = UdpEndpointPool::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    let (_ep, is_new) = pool.get_or_create(client, dst, proxy, echo_addr, "test-node".to_string());
    assert!(is_new);

    assert!(udp_fast_path(&pool, b"hello", client, dst).await);

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
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (_ep, is_new) = pool.get_or_create(
        client,
        dst,
        proxy,
        addr("127.0.0.1:9"),
        "test-node".to_string(),
    );
    assert!(is_new);

    assert!(!udp_fast_path(&pool, &dns_query_payload(), client, dst).await);
}

#[tokio::test]
async fn udp_fast_path_non_dns_port53_forwards() {
    // Garbage to port 53 is not a DNS query: the endpoint forwards it,
    // exactly like the slow path does after handle_udp_dns declines.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = UdpEndpointPool::new();
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let (_ep, is_new) = pool.get_or_create(client, dst, proxy, echo_addr, "test-node".to_string());
    assert!(is_new);

    let garbage = [0u8; 20]; // QR=0 but qdcount=0 — not a DNS query
    assert!(udp_fast_path(&pool, &garbage, client, dst).await);

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
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    // honk-internal subnets (v4 + v6), either direction.  The v6 check
    // must match the real dae0 addresses (fd00:686f:6e6b::1/2, see the
    // DAENS_* constants in the crate root).
    assert!(udp_fast_path(&pool, b"hello", client, addr("169.254.0.11:8080")).await);
    assert!(udp_fast_path(&pool, b"hello", addr("169.254.0.1:1234"), dst).await);
    assert!(udp_fast_path(&pool, b"hello", client, addr("[fd00:686f:6e6b::1]:8080")).await);
    assert!(udp_fast_path(&pool, b"hello", addr("[fd00:686f:6e6b::2]:1234"), dst).await);
    // Broadcast / multicast destinations.
    assert!(udp_fast_path(&pool, b"hello", client, addr("255.255.255.255:67")).await);
    assert!(udp_fast_path(&pool, b"hello", client, addr("192.168.1.255:67")).await);
    assert!(udp_fast_path(&pool, b"hello", client, addr("239.255.255.250:1900")).await);
    // Nothing was proxied or pooled.
    assert!(pool.is_empty());
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
