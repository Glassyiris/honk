use super::*;

#[test]
fn test_parse_resolver() {
    let r = BootstrapResolver::parse("udp://8.8.8.8:53").unwrap();
    assert_eq!(r.server, "8.8.8.8:53".parse().unwrap());
    assert!(!r.use_tcp);
    let r = BootstrapResolver::parse("tcp://1.1.1.1:53").unwrap();
    assert!(r.use_tcp);
    let r = BootstrapResolver::parse("9.9.9.9:53").unwrap();
    assert!(!r.use_tcp);
    assert!(BootstrapResolver::parse("").is_none());
    assert!(BootstrapResolver::parse("not-an-addr").is_none());
}

#[test]
fn test_build_and_parse_roundtrip() {
    let query = build_query("example.com", 1);
    let mut resp = query.clone();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1; // ancount = 1
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    resp.extend_from_slice(&1u16.to_be_bytes()); // A
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
    resp.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    resp.extend_from_slice(&[93, 184, 216, 34]);
    let ips = parse_answers(&resp, 1).unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
}

#[tokio::test]
async fn test_resolve_literal_ip_skips_lookup() {
    let ips = resolve("1.2.3.4").await.unwrap();
    assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
}

/// End-to-end: a stub UDP DNS server on loopback answering A records,
/// installed as the global bootstrap resolver.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_resolve_via_bootstrap_udp() {
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let mut resp = buf[..n].to_vec();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0;
        resp[7] = 1;
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[10, 9, 8, 7]);
        server.send_to(&resp, peer).await.unwrap();
    });

    set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
    let ips = resolve("node.example.com").await.unwrap();
    set_global(None);
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7))]);
}

/// Build a DNS response carrying one HTTPS (65) answer for the query's
/// question, with the given priority and `ech` SvcParam (or none).
fn make_https_response(query: &[u8], priority: u16, ech: Option<&[u8]>, ttl: u32) -> Vec<u8> {
    let mut resp = query.to_vec();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1; // ancount = 1
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer to question
    resp.extend_from_slice(&65u16.to_be_bytes()); // TYPE HTTPS
    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
    resp.extend_from_slice(&ttl.to_be_bytes());
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.push(0); // target name = root
    if let Some(ech) = ech {
        rdata.extend_from_slice(&5u16.to_be_bytes()); // SvcParam key ech
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(ech);
    }
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(&rdata);
    resp
}

#[test]
fn test_parse_https_rr_ech() {
    let query = build_query("example.com", 65);
    let ech = b"\x00\x01fake-ech-config";
    // ServiceMode (priority >= 1) with an ech param.
    let resp = make_https_response(&query, 1, Some(ech), 300);
    assert_eq!(
        parse_https_rr_ech(&resp),
        Some((ech.to_vec(), 300)),
        "ServiceMode HTTPS RR with ech param"
    );

    // AliasMode (priority 0) carries no SvcParams — skipped even when
    // bytes shaped like params follow (they are part of the TargetName).
    let resp = make_https_response(&query, 0, Some(ech), 300);
    assert_eq!(parse_https_rr_ech(&resp), None);

    // ServiceMode without an ech param.
    let resp = make_https_response(&query, 1, None, 300);
    assert_eq!(parse_https_rr_ech(&resp), None);
}

/// End-to-end: stub UDP DNS server answering HTTPS records with an ech
/// SvcParam, installed as the global bootstrap resolver.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn test_query_ech_config_via_bootstrap_udp() {
    let _lock = GLOBAL_TEST_LOCK.lock().unwrap();
    let ech = b"\x00\x02real-ech-bytes";
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let resp = make_https_response(&buf[..n], 1, Some(ech), 120);
        server.send_to(&resp, peer).await.unwrap();
    });

    set_global(BootstrapResolver::parse(&format!("udp://{}", server_addr)));
    let got = query_ech_config("node.example.com").await.unwrap();
    set_global(None);
    assert_eq!(got, Some((ech.to_vec(), 120)));

    // IP literals never hit the network.
    assert_eq!(query_ech_config("1.2.3.4").await.unwrap(), None);
}
