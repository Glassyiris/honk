use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::UdpEndpoint;
use crate::dns::query::is_exact_dns_query;

#[test]
fn test_build_dns_probe_query() {
    let q = build_dns_probe_query();
    assert_eq!(&q[..2], &[0x12, 0x34]); // fixed id, validated on the response
    assert_eq!(q[2], 0x01); // RD (recursion desired)
    assert_eq!(q[5], 1); // QDCOUNT = 1
    assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]); // QTYPE A / QCLASS IN
}

#[cfg(target_os = "linux")]
#[test]
fn udp_listener_enables_reuse_port_before_bind() {
    use std::os::fd::AsRawFd;

    let first = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    let mut enabled = 0i32;
    let mut enabled_len = std::mem::size_of_val(&enabled) as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            first.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            (&mut enabled as *mut i32).cast(),
            &mut enabled_len,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(enabled, 1);

    first
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    let addr = first.local_addr().unwrap();
    let second = sockets::new_udp_listener_socket(socket2::Domain::IPV4, true).unwrap();
    second.bind(&addr).unwrap();
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

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value` and has its exact layout size.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

/// Test storage has the same `cmsghdr` alignment required by `recvmsg`.
#[repr(C)]
struct AlignedTestCmsgStorage {
    _alignment: [libc::cmsghdr; 0],
    bytes: [u8; 256],
}

impl AlignedTestCmsgStorage {
    fn new() -> Self {
        // SAFETY: all-zero bytes are a valid initial representation for this
        // test-only raw control-message storage.
        unsafe { std::mem::zeroed() }
    }
}

fn cmsg_len(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_LEN as the platform ABI macro wrapper.
    unsafe { libc::CMSG_LEN(data_len as _) as usize }
}

fn cmsg_space(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_SPACE as the platform ABI macro wrapper.
    unsafe { libc::CMSG_SPACE(data_len as _) as usize }
}

fn append_cmsg(
    storage: &mut AlignedTestCmsgStorage,
    used: &mut usize,
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: &[u8],
) {
    let space = cmsg_space(data.len());
    assert!(*used + space <= storage.bytes.len());
    // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
    let mut header: libc::cmsghdr = unsafe { std::mem::zeroed::<libc::cmsghdr>() };
    header.cmsg_len = cmsg_len(data.len()) as _;
    header.cmsg_level = cmsg_level;
    header.cmsg_type = cmsg_type;
    // SAFETY: `AlignedTestCmsgStorage` is explicitly cmsghdr-aligned, the
    // checked range fits storage, and the header is initialized before use.
    unsafe {
        let ptr = storage
            .bytes
            .as_mut_ptr()
            .add(*used)
            .cast::<libc::cmsghdr>();
        assert_eq!(
            ptr as usize % std::mem::align_of::<libc::cmsghdr>(),
            0,
            "test cmsg header must be naturally aligned"
        );
        std::ptr::write(ptr, header);
    }
    let data_start = *used + cmsg_len(0);
    storage.bytes[data_start..data_start + data.len()].copy_from_slice(data);
    *used += space;
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv4_multi_cmsg() {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = 4444u16.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(203, 0, 113, 10)).to_be(),
    };
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(packet_ifindex, Some(0));
}

#[test]
fn udp_original_dst_cmsg_parser_walks_aligned_ipv6_multi_cmsg() {
    let expected_original: std::net::Ipv6Addr = "2001:db8::4444".parse().unwrap();
    let expected_packet: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let mut original: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    original.sin6_family = libc::AF_INET6 as _;
    original.sin6_port = 4444u16.to_be();
    original.sin6_addr = libc::in6_addr {
        s6_addr: expected_original.octets(),
    };
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_packet.octets(),
        },
        ipi6_ifindex: 7,
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IPV6,
        libc::IPV6_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("[2001:db8::4444]:4444")));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V6(expected_packet)));
    assert_eq!(packet_ifindex, Some(7));
}

#[test]
fn udp_original_dst_cmsg_parser_uses_only_returned_control_length() {
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(198, 51, 100, 53)).to_be(),
        },
    };
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let returned_control_len = used;
    // Bytes beyond msg_controllen are not kernel-returned control data; make
    // them malformed to prove they cannot influence the parser.
    unsafe {
        // SAFETY: all-zero is a valid initial representation for a raw test cmsg header.
        let mut malformed_header: libc::cmsghdr = std::mem::zeroed::<libc::cmsghdr>();
        malformed_header.cmsg_len = 0;
        malformed_header.cmsg_level = libc::IPPROTO_IP;
        malformed_header.cmsg_type = libc::IP_PKTINFO;
        std::ptr::write(
            storage.bytes.as_mut_ptr().add(used).cast::<libc::cmsghdr>(),
            malformed_header,
        );
    }
    let malformed_len = used + cmsg_len(0);

    assert!(parse_cmsg_control(&storage.bytes[..returned_control_len], 0).is_ok());
    let error = parse_cmsg_control(&storage.bytes[..malformed_len], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_fails_closed_on_truncation_or_ctrunc() {
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &[0; 1],
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let error = parse_cmsg_control(&storage.bytes[..used], libc::MSG_CTRUNC).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_storage_has_space_for_ipv6_origdst_and_pktinfo() {
    assert!(cmsg_control_capacity_is_sufficient());
}

#[test]
fn udp_original_dst_unspecified_origdst_is_authoritative_and_fails_closed() {
    let meta = UdpRecvMeta {
        original_dst_cmsg: Some(addr("0.0.0.0:53")),
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("192.0.2.20:5353"),
    };

    assert_eq!(udp_original_dst(&meta, &dns_query_payload()), None);
}

fn ipv4_origdst(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    let mut original: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    original.sin_family = libc::AF_INET as _;
    original.sin_port = port.to_be();
    original.sin_addr = libc::in_addr {
        s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
    };
    original
}

fn ipv4_pktinfo(ip: [u8; 4]) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be(),
        },
    }
}

#[test]
fn udp_original_dst_cmsg_parser_requires_exact_recognized_payload_length() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut oversized = bytes_of(&original).to_vec();
    oversized.push(0xab);

    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        &oversized,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut oversized_pkt = bytes_of(&pktinfo).to_vec();
    oversized_pkt.extend_from_slice(&[0xde, 0xad]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &oversized_pkt,
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_rejects_duplicate_recognized_records() {
    // Equal ORIGDST values are still ambiguous provenance.
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Conflicting ORIGDST values fail closed.
    let other = ipv4_origdst([198, 51, 100, 10], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&other),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Unspecified followed by a valid ORIGDST is still a duplicate.
    let unspecified = ipv4_origdst([0, 0, 0, 0], 53);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&unspecified),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    // Duplicate PKTINFO (equal values) is also rejected.
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );
    let error = parse_cmsg_control(&storage.bytes[..used], 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn udp_original_dst_cmsg_parser_skips_unknown_cmsg_with_padding() {
    let original = ipv4_origdst([203, 0, 113, 10], 4444);
    let pktinfo = ipv4_pktinfo([198, 51, 100, 53]);
    let mut storage = AlignedTestCmsgStorage::new();
    let mut used = 0;
    // Unknown record with a non-aligned-looking payload still consumes CMSG_SPACE.
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7fff, // not a recognized ORIGDST/PKTINFO type
        &[0x11, 0x22, 0x33],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_ORIGDSTADDR,
        bytes_of(&original),
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        0x7ffe,
        &[0xaa, 0xbb],
    );
    append_cmsg(
        &mut storage,
        &mut used,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        bytes_of(&pktinfo),
    );

    let (original_dst, packet_dst_ip, packet_ifindex) =
        parse_cmsg_control(&storage.bytes[..used], 0).unwrap();
    assert_eq!(original_dst, Some(addr("203.0.113.10:4444")));
    assert_eq!(
        packet_dst_ip,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            198, 51, 100, 53
        )))
    );
    assert_eq!(packet_ifindex, Some(0));
}

async fn ready_udp_endpoint(
    pool: &Arc<UdpEndpointPool>,
    stats: &Arc<StatsManager>,
    client: SocketAddr,
    dst: SocketAddr,
    transport: Arc<dyn honk_outbound::proxy::PacketTransport>,
    relay: SocketAddr,
) -> Arc<UdpEndpoint> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let mut lease = match pool.reserve_or_enqueue(client, dst, b"bootstrap", slow_permit, stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("test endpoint must reserve a fresh lease"),
    };
    let endpoint = Arc::new(UdpEndpoint::new(transport, relay, udp_test_node().id));
    let queue_rx = lease.take_queue_receiver().unwrap();
    let reply_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut driver = pool.spawn_driver(
        client,
        dst,
        lease.generation(),
        Arc::clone(&endpoint),
        queue_rx,
        reply_socket,
        Arc::new(crate::outbound::AliveDialerSet::new()),
        stats.clone(),
        "test-node".into(),
    );
    driver.wait_ready().await.unwrap();
    assert!(lease.commit_ready(Arc::clone(&endpoint)));
    driver.start(lease.take_first().unwrap()).unwrap();
    driver.wait_first_ack().await.unwrap();
    endpoint
}

#[test]
fn udp_original_dst_exact_dns_predicate_matches_controller_condition() {
    // Real query: consumed by the DNS controller.
    assert!(is_exact_dns_query(&dns_query_payload()));
    // QR bit set (response): not a query.
    let mut resp = dns_query_payload();
    resp[2] |= 0x80;
    assert!(!is_exact_dns_query(&resp));
    // Too short / garbage: not a query.
    assert!(!is_exact_dns_query(b"hello"));
    assert!(!is_exact_dns_query(&[0u8; 20])); // qdcount == 0
}

#[test]
fn strict_dns_query_accepts_complete_query_and_edns_only() {
    let query = dns_query_payload();
    assert!(is_exact_dns_query(&query));

    // A legal EDNS OPT pseudo-RR is still an exact DNS query.
    let mut edns = query.clone();
    edns[10..12].copy_from_slice(&1u16.to_be_bytes());
    edns.extend_from_slice(&[
        0x00, // root NAME
        0x00, 0x29, // TYPE OPT
        0x10, 0x00, // UDP payload size
        0x00, 0x00, 0x00, 0x00, // extended RCODE/version/flags
        0x00, 0x00, // RDLENGTH
    ]);
    assert!(is_exact_dns_query(&edns));

    // A forged QDCOUNT cannot claim a second question that is not encoded.
    let mut forged_question_count = query.clone();
    forged_question_count[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(!is_exact_dns_query(&forged_question_count));

    // Header record counts require a complete NAME + fixed RR + RDATA.
    let mut truncated_rr = query.clone();
    truncated_rr[6..8].copy_from_slice(&1u16.to_be_bytes());
    truncated_rr.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01]);
    assert!(!is_exact_dns_query(&truncated_rr));
    let mut short_rdata = query.clone();
    short_rdata[6..8].copy_from_slice(&1u16.to_be_bytes());
    short_rdata.extend_from_slice(&[
        0xc0, 0x0c, // NAME pointer to question
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, // only half the claimed RDATA
    ]);
    assert!(!is_exact_dns_query(&short_rdata));

    let mut invalid_label = query.clone();
    invalid_label[12] = 0x40;
    assert!(!is_exact_dns_query(&invalid_label));
    let mut invalid_pointer = query.clone();
    invalid_pointer.truncate(12);
    invalid_pointer.extend_from_slice(&[0xc0, 0xff, 0x00, 0x01, 0x00, 0x01]);
    assert!(!is_exact_dns_query(&invalid_pointer));

    let mut trailing_junk = query;
    trailing_junk.push(0xde);
    assert!(!is_exact_dns_query(&trailing_junk));
}

fn dns_query_with_qname(qname: &[u8]) -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(qname);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A / QCLASS IN
    q
}

#[test]
fn strict_dns_query_enforces_expanded_name_limit_and_label_boundaries() {
    // Four 63-byte labels + root expand to 257 octets (>255) and must fail.
    let mut overlong_name = Vec::new();
    for _ in 0..4 {
        overlong_name.push(63);
        overlong_name.extend(std::iter::repeat_n(b'a', 63));
    }
    overlong_name.push(0);
    let overlong = dns_query_with_qname(&overlong_name);
    assert_eq!(overlong_name.len(), 257);
    assert!(!is_exact_dns_query(&overlong));

    // Pointer into the middle of a label is not a prior label boundary.
    // a.com qname occupies offsets 12..19 with boundaries at 12,14,18.
    let mut pointer_into_label = dns_query_payload();
    pointer_into_label[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
    pointer_into_label.extend_from_slice(&[
        0xc0, 0x0d, // pointer to offset 13 (the 'a' payload byte)
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ]);
    assert!(!is_exact_dns_query(&pointer_into_label));

    // Valid suffix compression: answer owner points at the "com" label boundary.
    let mut suffix = dns_query_payload();
    suffix[6..8].copy_from_slice(&1u16.to_be_bytes());
    suffix.extend_from_slice(&[
        0xc0, 0x0e, // pointer to offset 14 (start of "com")
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        192, 0, 2, 1,
    ]);
    assert!(is_exact_dns_query(&suffix));

    // Full-name compression onto the question owner remains accepted.
    let mut full = dns_query_payload();
    full[6..8].copy_from_slice(&1u16.to_be_bytes());
    full.extend_from_slice(&[
        0xc0, 0x0c, // pointer to question name
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
    ]);
    assert!(is_exact_dns_query(&full));
}

#[test]
fn strict_dns_query_requires_forwarder_parseable_question() {
    // Root qname is wire-valid but parse_dns_question rejects empty labels.
    let root = dns_query_with_qname(&[0x00]);
    assert!(crate::dns::forwarder::parse_dns_question(&root).is_none());
    assert!(!is_exact_dns_query(&root));

    // Non-UTF8 / binary label is wire-shaped but not consumer-parseable.
    let binary = dns_query_with_qname(&[0x01, 0xff, 0x00]);
    assert!(crate::dns::forwarder::parse_dns_question(&binary).is_none());
    assert!(!is_exact_dns_query(&binary));

    // Ordinary UTF-8 name remains accepted by both.
    let ok = dns_query_payload();
    assert!(crate::dns::forwarder::parse_dns_question(&ok).is_some());
    assert!(is_exact_dns_query(&ok));
}

#[tokio::test]
async fn udp_dns_controller_declines_root_and_binary_questions() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let controller = production_dns_controller(calls.clone(), dns_response_payload());
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = addr("127.0.0.1:34567");
    let dst = addr("203.0.113.53:53");

    let root = dns_query_with_qname(&[0x00]);
    assert!(
        !controller
            .handle_udp_dns(&sock, &root, client, dst)
            .await
            .unwrap(),
        "root qname must fall back to ordinary UDP"
    );

    let binary = dns_query_with_qname(&[0x01, 0xff, 0x00]);
    assert!(
        !controller
            .handle_udp_dns(&sock, &binary, client, dst)
            .await
            .unwrap(),
        "binary qname must fall back to ordinary UDP"
    );

    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn udp_slow_path_only_forces_strict_dns_to_port_53() {
    let client = addr("10.0.0.1:12345");
    let data = dns_query_payload();

    let dns_pool = Arc::new(UdpEndpointPool::new());
    let dns_stats = Arc::new(StatsManager::new());
    let dns_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let dns_work = begin_udp_slow_path(
        &dns_pool,
        &dns_stats,
        &dns_limit,
        client,
        addr("203.0.113.53:53"),
        &data,
    );
    assert!(matches!(
        dns_work,
        UdpSlowPathWork::DnsThenMaybeInitialize { .. }
    ));

    let ordinary_pool = Arc::new(UdpEndpointPool::new());
    let ordinary_stats = Arc::new(StatsManager::new());
    let ordinary_limit = Arc::new(tokio::sync::Semaphore::new(1));
    let ordinary_work = begin_udp_slow_path(
        &ordinary_pool,
        &ordinary_stats,
        &ordinary_limit,
        client,
        addr("203.0.113.53:5353"),
        &data,
    );
    assert!(matches!(ordinary_work, UdpSlowPathWork::Initialize(_)));
}

#[test]
fn udp_original_dst_cmsg_takes_precedence_over_other_metadata() {
    let meta = UdpRecvMeta {
        original_dst_cmsg: Some(addr("203.0.113.10:4444")),
        packet_dst_ip: Some("198.51.100.10".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("192.0.2.10:5353"),
    };

    assert_eq!(
        udp_original_dst(&meta, b"not a DNS query"),
        Some(addr("203.0.113.10:4444"))
    );
}

#[test]
fn udp_original_dst_uses_ipv4_pktinfo_for_exact_dns_query() {
    let expected_ip = std::net::Ipv4Addr::new(198, 51, 100, 53);
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr {
            s_addr: u32::from(expected_ip).to_be(),
        },
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IP, libc::IP_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V4(expected_ip)));

    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    assert_eq!(
        udp_original_dst(&meta, &dns_query_payload()),
        Some(addr("198.51.100.53:53"))
    );
}

#[test]
fn udp_original_dst_uses_ipv6_pktinfo_for_exact_dns_query() {
    let expected_ip: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: expected_ip.octets(),
        },
        ipi6_ifindex: 0,
    };
    let packet_dst_ip =
        packet_dst_ip_from_cmsg(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, bytes_of(&pktinfo));
    assert_eq!(packet_dst_ip, Some(std::net::IpAddr::V6(expected_ip)));

    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip,
        packet_ifindex: None,
        local_addr: addr("[::]:15000"),
    };
    assert_eq!(
        udp_original_dst(&meta, &dns_query_payload()),
        Some(addr("[2001:db8::53]:53"))
    );
}

#[test]
fn udp_original_dst_uses_non_wildcard_local_fallback() {
    let local_addr = addr("192.0.2.20:5353");
    let meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        local_addr,
    };

    assert_eq!(udp_original_dst(&meta, b"opaque UDP"), Some(local_addr));
}

#[test]
fn udp_original_dst_fails_closed_for_wildcard_local_without_metadata() {
    for local_addr in [addr("0.0.0.0:15000"), addr("[::]:15000")] {
        let meta = UdpRecvMeta {
            original_dst_cmsg: None,
            packet_dst_ip: None,
            packet_ifindex: None,
            local_addr,
        };
        assert_eq!(udp_original_dst(&meta, b"opaque UDP"), None);
    }
}

#[test]
fn udp_original_dst_does_not_rewrite_non_exact_dns_payloads() {
    let packet_meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: Some("198.51.100.53".parse().unwrap()),
        packet_ifindex: None,
        local_addr: addr("0.0.0.0:15000"),
    };
    let local_fallback = addr("192.0.2.20:5353");
    let fallback_meta = UdpRecvMeta {
        original_dst_cmsg: None,
        packet_dst_ip: None,
        packet_ifindex: None,
        local_addr: local_fallback,
    };
    let mut dns_response = dns_query_payload();
    dns_response[2] |= 0x80;

    for payload in [
        dns_response.as_slice(),
        b"short".as_slice(),
        &[0u8; 20][..],
        b"random non-53 UDP payload".as_slice(),
    ] {
        assert!(!is_exact_dns_query(payload));
        assert_eq!(udp_original_dst(&packet_meta, payload), None);
        assert_eq!(
            udp_original_dst(&fallback_meta, payload),
            Some(local_fallback)
        );
    }
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
async fn udp_fast_path_hit_enqueues_for_the_endpoint_driver() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy.local_addr().unwrap();
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:443");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    // First packet was delivered through the driver start barrier.
    echo.recv_from(&mut buf).await.unwrap();
    assert!(!udp_fast_path(&pool, &stats, b"wrong-client", addr("10.0.0.2:12345"), dst,).await);
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-destination",
            client,
            addr("203.0.113.2:443"),
        )
        .await
    );
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-client-port",
            addr("10.0.0.1:12346"),
            dst,
        )
        .await
    );
    assert!(
        !udp_fast_path(
            &pool,
            &stats,
            b"wrong-destination-port",
            client,
            addr("203.0.113.1:444"),
        )
        .await
    );
    assert!(udp_fast_path(&pool, &stats, b"hello", client, dst).await);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 1);
    assert_eq!(udp.endpoint_misses, 4);

    let (n, from) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, proxy_addr);
}

#[tokio::test]
async fn udp_fast_path_dns_goes_slow_even_with_endpoint() {
    // A real DNS query must reach the DNS controller even when an endpoint
    // driver already owns this tuple.
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy,
            addr("127.0.0.1:9"),
        )),
        addr("127.0.0.1:9"),
    )
    .await;

    assert!(!udp_fast_path(&pool, &stats, &dns_query_payload(), client, dst).await);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.endpoint_hits, 0);
    assert_eq!(udp.endpoint_misses, 0);
}

#[tokio::test]
async fn udp_fast_path_dns_shaped_non53_forwards() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.53:5353");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();
    let query = dns_query_payload();
    assert!(udp_fast_path(&pool, &stats, &query, client, dst).await);
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), echo.recv_from(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], &query);
}

#[tokio::test]
async fn udp_fast_path_non_dns_port53_forwards() {
    // Garbage to port 53 is not a DNS query: the endpoint driver forwards it,
    // exactly like the slow path does after handle_udp_dns declines.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;

    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();
    let garbage = [0u8; 20]; // QR=0 but qdcount=0 — not a DNS query
    assert!(udp_fast_path(&pool, &stats, &garbage, client, dst).await);
    assert_eq!(stats.udp_snapshot().endpoint_hits, 1);

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
    honk_config::parser::resolve_group_filters(
        &mut current.groups,
        &current.nodes,
        &current.subscriptions,
    );
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
    /// Records real application-send attempts made by the production
    /// PacketTransport call path.
    CountSends(Arc<std::sync::atomic::AtomicUsize>),
    /// Counts dial and send attempts while making the first application send
    /// ambiguous. A later candidate must never be tried after that send.
    CountFirstSendError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialAndSend {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    Success,
    TcpHold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    Hold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    HoldAndCount {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    HoldAndCountDialAndSend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
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
        match &self.mode {
            UdpTestMode::SendError => Err(std::io::Error::other("first UDP send failed")),
            UdpTestMode::CountSends(sends) => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            UdpTestMode::CountFirstSendError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::other("ambiguous first UDP send failure"))
            }
            UdpTestMode::CountDialAndSend { sends, .. }
            | UdpTestMode::HoldAndCountDialAndSend { sends, .. }
            | UdpTestMode::PreparedCommitError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

#[derive(Debug)]
struct UdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for UdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

#[derive(Debug)]
struct FailingUdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for FailingUdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        Err(std::io::Error::other("scripted anyfrom setup failure"))
    }
}

#[derive(Debug)]
struct UdpTestHandler {
    mode: UdpTestMode,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for UdpTestHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        let UdpTestMode::TcpHold { entered, release } = &self.mode else {
            return Err(anyhow::anyhow!(
                "TCP dial is not used by the UDP lifecycle tests"
            ));
        };
        entered.notify_one();
        release.notified().await;
        let stream = TcpStream::connect(target).await?;
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for UdpTestHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        match &self.mode {
            UdpTestMode::Hold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::HoldAndCount {
                entered,
                release,
                dials,
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::CountFirstSendError { dials, .. }
            | UdpTestMode::CountDialAndSend { dials, .. }
            | UdpTestMode::CountDialError { dials }
            | UdpTestMode::PreparedCommitError { dials, .. } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            UdpTestMode::HoldAndCountDialAndSend {
                entered,
                release,
                dials,
                ..
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            _ => {}
        }
        match &self.mode {
            UdpTestMode::DialError | UdpTestMode::CountDialError { .. } => {
                Err(anyhow::anyhow!("UDP dial failed"))
            }
            _ => Ok(Arc::new(UdpTestTransport {
                mode: self.mode.clone(),
                relay: target,
            })),
        }
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::PreparedUdpTransport> {
        let transport = self
            .dial_udp_transport(
                runtime.node.as_ref(),
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
        if let UdpTestMode::PreparedCommitError { commits, .. } = &self.mode {
            let commits = Arc::clone(commits);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                transport,
                move || async move {
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(anyhow::anyhow!(
                        "scripted prepared transport commit failure"
                    ))
                },
            ));
        }
        Ok(honk_outbound::proxy::PreparedUdpTransport::ready(transport))
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

#[tokio::test]
async fn tcp_idle_relay_survives_conn_state_sweep() -> anyhow::Result<()> {
    use honk_ebpf_common::conn::{ConnState, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    let redirect_key = RedirectTuple::from_tuples(&tuples);
    let stale_timestamp = 1;
    let stale_state = ConnState {
        state: TcpState::TcpStateActive as u8,
        last_seen_ns: stale_timestamp,
        ..Default::default()
    };
    let stale_redirect = RedirectEntry {
        last_seen_ns: stale_timestamp,
        ..Default::default()
    };
    let handoff = RoutingHandoffEntry {
        last_seen_ns: stale_timestamp,
        result: RoutingResult {
            outbound: OutboundIndex::Direct as u8,
            mark: 0,
            ..Default::default()
        },
    };

    let mut mock = crate::ebpf::mock::MockEbpfBackend::new();
    mock.tcp_conn_state_store(&tuples, &stale_state)?;
    mock.redirect_track_store(&redirect_key, &stale_redirect)?;
    let raw_tuples: [u8; 40] = bytes_of(&tuples).try_into().expect("40-byte tuple key");
    mock.routing_handoffs
        .lock()
        .unwrap()
        .insert(raw_tuples, handoff);

    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".to_string();
    config.routing.default_outbound = "direct".to_string();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound)?;
    let plane = ControlPlane::new(
        config,
        Box::new(mock),
        router,
        Arc::new(ProxyRegistry::default_resolver()?),
        DnsResolver::new(&honk_config::dns::DnsConfig::default())?,
        udp_test_forwarder(),
    )?;
    let handle = plane.spawn_handle();
    let handler_handle = handle.clone();
    let handler =
        tokio::spawn(async move { handler_handle.serve_connection(accepted, client_addr).await });
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;

    let tracked_before = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = handle.connection_tracker.snapshot();
            if snapshot.len() == 1 {
                break snapshot.into_iter().next().unwrap();
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let synthetic_now = TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + stale_timestamp + 1;
    let janitor = BpfJanitor::new(handle.ebpf.clone(), handle.tcp_flow_pins.clone());
    assert_eq!(
        janitor.cleanup_conn_state_for_test(synthetic_now).await,
        (0, 1)
    );
    assert_eq!(
        janitor.cleanup_redirect_track_for_test(synthetic_now).await,
        (0, 1)
    );
    {
        let backend = handle.ebpf.read().await;
        assert!(backend.tcp_conn_state_lookup(&tuples)?.is_some());
        assert!(backend.redirect_track_lookup(&redirect_key)?.is_some());
    }

    upstream.write_all(b"S").await?;
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"S");

    client.write_all(b"C").await?;
    upstream.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"C");
    upstream.write_all(b"R").await?;
    client.read_exact(&mut byte).await?;
    assert_eq!(&byte, b"R");

    let tracked_after = handle.connection_tracker.snapshot();
    assert_eq!(tracked_after.len(), 1);
    assert_eq!(tracked_after[0].id, tracked_before.id);
    assert_eq!(tracked_after[0].proxy, tracked_before.proxy);
    assert_eq!(tracked_after[0].chains, tracked_before.chains);

    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);
    let handler_result = tokio::time::timeout(Duration::from_secs(5), handler).await?;
    handler_result??;

    {
        let backend = handle.ebpf.read().await;
        assert!(backend.tcp_conn_state_lookup(&tuples)?.is_none());
        assert!(backend.redirect_track_lookup(&redirect_key)?.is_some());
    }
    assert!(handle.tcp_flow_pins.snapshot().is_empty());
    assert!(handle.connection_tracker.snapshot().is_empty());
    assert_eq!(
        janitor.cleanup_redirect_track_for_test(synthetic_now).await,
        (1, 1)
    );
    assert!(
        handle
            .ebpf
            .read()
            .await
            .redirect_track_lookup(&redirect_key)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn tcp_tracker_keeps_the_dial_selection_snapshot() -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut hk = Node {
        name: "hk-140".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    hk.id = hk.derive_id();
    let mut us = Node {
        name: "us-163".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 163,
        ..Default::default()
    };
    us.id = us.derive_id();
    let mut config = udp_test_config(
        "devops",
        vec![hk.clone(), us.clone()],
        vec![Group {
            name: "devops".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![hk.id, us.id],
            default: Some(hk.name.clone()),
            ..Default::default()
        }],
    );
    config.ensure_builtin_nodes();
    config.global.dial_mode = "ip".into();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handle = udp_test_handle(
        config,
        UdpTestMode::TcpHold {
            entered: entered.clone(),
            release: release.clone(),
        },
        1,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let original_dst = listener.local_addr()?;
    let mut client = TcpStream::connect(original_dst).await?;
    let (accepted, client_addr) = listener.accept().await?;
    let tuples = build_tuples_key(
        original_dst.ip(),
        original_dst.port(),
        client_addr.ip(),
        client_addr.port(),
        6,
    );
    handle.ebpf.write().await.tcp_conn_state_store(
        &tuples,
        &honk_ebpf_common::conn::ConnState {
            state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
            last_seen_ns: 1,
            ..Default::default()
        },
    )?;
    let task_handle = handle.clone();
    let mut task =
        tokio::spawn(async move { task_handle.serve_connection(accepted, client_addr).await });

    tokio::select! {
        _ = entered.notified() => {}
        result = &mut task => panic!("TCP handler exited before dial: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("TCP dial did not reach the injected handler")
        }
    }
    assert_eq!(
        handle.group_manager.read().selection_chain("devops"),
        vec!["devops", "hk-140"]
    );
    handle
        .group_manager
        .read()
        .set_selector_choice("devops", "us-163");
    assert_eq!(
        handle.group_manager.read().selection_chain("devops"),
        vec!["devops", "us-163"]
    );

    release.notify_one();
    let (mut upstream, _) =
        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    let tracked = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(entry) = handle.connection_tracker.snapshot().into_iter().next() {
                break entry;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(tracked.proxy, "hk-140");
    assert_eq!(tracked.chains, vec!["hk-140", "devops"]);

    client.shutdown().await?;
    upstream.shutdown().await?;
    drop(client);
    drop(upstream);
    tokio::time::timeout(Duration::from_secs(5), task).await???;
    Ok(())
}

#[tokio::test]
async fn udp_tracker_uses_the_udp_selection_snapshot() -> anyhow::Result<()> {
    let mut tcp_node = Node {
        name: "tcp-node".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 140,
        ..Default::default()
    };
    tcp_node.id = tcp_node.derive_id();
    let mut udp_node = Node {
        name: "udp-node".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 163,
        ..Default::default()
    };
    udp_node.id = udp_node.derive_id();
    let config = udp_test_config(
        "traffic",
        vec![tcp_node.clone(), udp_node.clone()],
        vec![Group {
            name: "traffic".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![tcp_node.id, udp_node.id],
            ..Default::default()
        }],
    );
    let handle = udp_test_handle(config, UdpTestMode::Success, 1);
    handle.alive_set.record_probe_latency(
        tcp_node.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    handle.alive_set.record_probe_latency(
        udp_node.id,
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    handle.alive_set.record_probe_latency(
        tcp_node.id,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(100),
    );
    handle.alive_set.record_probe_latency(
        udp_node.id,
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(10),
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .select_node_for_domain("traffic", ProbeDomain::Tcp, IpVersion::V4)
            .expect("TCP selection")
            .name,
        "tcp-node"
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .select_node_for_domain("traffic", ProbeDomain::DataUdp, IpVersion::V4)
            .expect("UDP selection")
            .name,
        "udp-node"
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .selection_chain_for_network("traffic", crate::group::SelectionNetwork::Tcp),
        vec!["traffic", "tcp-node"]
    );
    assert_eq!(
        handle
            .group_manager
            .read()
            .selection_chain_for_network("traffic", crate::group::SelectionNetwork::Udp),
        vec!["traffic", "udp-node"]
    );

    serve_test_udp(&handle).await?;
    let tracked = handle
        .connection_tracker
        .snapshot()
        .into_iter()
        .next()
        .expect("ready UDP endpoint must be tracked");
    assert_eq!(tracked.proxy, "udp-node");
    assert_eq!(tracked.chains, vec!["udp-node", "traffic"]);
    handle
        .udp_pool
        .remove(addr("10.0.0.2:53000"), addr("203.0.113.2:443"));
    Ok(())
}

fn udp_test_config(default_outbound: &str, nodes: Vec<Node>, groups: Vec<Group>) -> Config {
    let mut config = Config {
        nodes,
        groups,
        ..Default::default()
    };
    config.routing.default_outbound = default_outbound.into();
    config
}

fn udp_test_node() -> Node {
    let mut node = Node {
        name: "udp-test".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

fn udp_test_handle(config: Config, mode: UdpTestMode, capacity: usize) -> ControlPlaneHandle {
    udp_test_handle_with_reply_factory(config, mode, capacity, Arc::new(UdpTestReplySocketFactory))
}

/// Uses ControlPlane's production endpoint pool unchanged. The blocked-dial
/// death test needs this so the callback installed during ControlPlane::new
/// owns the same pool that contains the real Initializing reservation.
fn udp_test_handle_with_default_pool(config: Config, mode: UdpTestMode) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle()
}

fn udp_test_handle_with_reply_factory(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
    reply_socket_factory: Arc<dyn crate::control::udp_endpoint::UdpReplySocketFactory>,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        capacity,
        reply_socket_factory,
    ));
    control_plane.spawn_handle()
}

async fn serve_test_udp(handle: &ControlPlaneHandle) -> anyhow::Result<()> {
    serve_test_udp_to(
        handle,
        addr("10.0.0.2:53000"),
        addr("203.0.113.2:443"),
        b"UDP test packet",
    )
    .await
}

async fn serve_test_udp_to(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let reservation =
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, payload, slow_permit, &handle.stats);
    match reservation {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => {
            handle
                .serve_udp_connection(
                    lease,
                    Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                )
                .await
        }
        crate::control::udp_endpoint::EndpointReservation::Enqueued
        | crate::control::udp_endpoint::EndpointReservation::CapacityRejected
        | crate::control::udp_endpoint::EndpointReservation::QueueFull
        | crate::control::udp_endpoint::EndpointReservation::QueueClosed => Ok(()),
    }
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
async fn udp_init_lease_capacity_rejection_happens_before_route_or_send() {
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::Success, 0);
    let stats = handle.stats.clone();

    serve_test_udp(&handle).await.unwrap();

    assert!(stats.snapshot().is_empty());
    let udp = stats.udp_snapshot();
    assert_eq!(udp.capacity_rejections, 1);
    assert_eq!(udp.route_latency.count, 0);
}

#[tokio::test]
async fn udp_init_lease_capacity_rejection_sends_zero() {
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(config, UdpTestMode::CountSends(sends.clone()), 0);

    serve_test_udp(&handle).await.unwrap();

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "endpoint reservation must reject at capacity before application send"
    );
}

#[tokio::test]
async fn udp_init_lease_reply_factory_failure_sends_zero() {
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle_with_reply_factory(
        config,
        UdpTestMode::CountSends(sends.clone()),
        1,
        Arc::new(FailingUdpTestReplySocketFactory),
    );

    assert!(serve_test_udp(&handle).await.is_err());

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "anyfrom setup failure must happen before the first application send"
    );
    assert!(handle.udp_pool.is_empty());
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
async fn udp_first_send_failure_does_not_replay_to_another_candidate() {
    let first = udp_test_node();
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "udp-test-second".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    let config = udp_test_config(
        "udp-group",
        vec![first.clone(), second.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![first.id, second.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountFirstSendError {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        2,
    );

    assert!(serve_test_udp(&handle).await.is_err());

    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the selected transport receives exactly one application-send attempt"
    );
    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "an ambiguous first-send failure must not dial a later candidate"
    );
}

#[tokio::test]
async fn udp_cold_urltest_commit_failure_sends_nothing_and_fails_closed() {
    let node = udp_test_node();
    let config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::URLTest,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitError {
            dials: Arc::clone(&dials),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
        },
        1,
    );

    assert!(serve_test_udp(&handle).await.is_err());
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(handle.udp_pool.is_empty());
}

#[tokio::test]
async fn udp_authoritative_plan_bypasses_speculative_commit_hook() {
    let node = udp_test_node();
    let config = udp_test_config(
        "udp-group",
        vec![node.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![node.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let commits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::PreparedCommitError {
            dials: Arc::clone(&dials),
            commits: Arc::clone(&commits),
            sends: Arc::clone(&sends),
        },
        1,
    );

    serve_test_udp(&handle).await.unwrap();
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 1);
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
async fn udp_init_lease_concurrent_first_packets_make_one_reservation_and_one_dial() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::HoldAndCount {
            entered: entered.clone(),
            release: release.clone(),
            dials: dials.clone(),
        },
        1,
    );
    let first_handle = handle.clone();
    let first = tokio::spawn(async move { serve_test_udp(&first_handle).await });

    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("first packet did not reach the injected dialer");
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);

    serve_test_udp(&handle)
        .await
        .expect("concurrent follower must enqueue behind the reservation");
    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "concurrent first packets must not create a second initializer"
    );

    release.notify_one();
    first.await.unwrap().unwrap();
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_node_dead_before_production_dial_has_zero_dials_and_sends() {
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialAndSend {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        1,
    );

    for domain in [
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::ProbeDomain::DnsUdp,
    ] {
        handle.alive_set.report_unavailable_forced(
            udp_test_node().id,
            domain,
            crate::outbound::IpVersion::V4,
        );
    }
    serve_test_udp(&handle).await.unwrap();

    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn udp_dns_udp_liveness_keeps_explicit_node_selectable_in_production() {
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialAndSend {
            dials: dials.clone(),
            sends: sends.clone(),
        },
        1,
    );

    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::IpVersion::V4,
    );
    serve_test_udp(&handle).await.unwrap();

    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(sends.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn udp_authoritative_selection_stops_after_single_candidate_dial_failure() {
    let first = udp_test_node();
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "udp-test-second".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    let config = udp_test_config(
        "udp-group",
        vec![first.clone(), second.clone()],
        vec![Group {
            name: "udp-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![first.id, second.id],
            ..Default::default()
        }],
    );
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = udp_test_handle(
        config,
        UdpTestMode::CountDialError {
            dials: dials.clone(),
        },
        2,
    );

    serve_test_udp(&handle).await.unwrap();

    assert_eq!(
        dials.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Selector is authoritative: pre-send failure does not invent a second candidate"
    );
}

#[tokio::test]
async fn udp_production_death_during_unbound_preparation_prevents_send() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let target = udp_test_node();
    let unrelated = Node {
        id: uuid::Uuid::new_v4(),
        name: "health-registered-other".into(),
        protocol: honk_config::types::NodeProtocol::Socks5,
        address: "127.0.0.1".into(),
        port: 10,
        ..Default::default()
    };
    // Keep the selected direct node out of the health-check registration so
    // the public death transition is not hidden by the startup grace period.
    let config = udp_test_config(
        "udp-test",
        vec![target, unrelated.clone()],
        vec![Group {
            name: "unrelated-health-group".into(),
            policy: honk_config::group::GroupPolicy::Selector,
            nodes: vec![unrelated.id],
            ..Default::default()
        }],
    );
    let handle = udp_test_handle_with_default_pool(
        config,
        UdpTestMode::HoldAndCountDialAndSend {
            entered: entered.clone(),
            release: release.clone(),
            dials: dials.clone(),
            sends: sends.clone(),
        },
    );
    let task_handle = handle.clone();
    let task = tokio::spawn(async move { serve_test_udp(&task_handle).await });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production ProxyRegistry transport preparation must block");

    // TCP death triggers the production removal callback; both UDP domains
    // becoming unavailable ensure the scheduler's completion recheck rejects
    // the transport before it can become a winner.
    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DataUdp,
        crate::outbound::IpVersion::V4,
    );
    handle.alive_set.report_unavailable_forced(
        udp_test_node().id,
        crate::outbound::ProbeDomain::DnsUdp,
        crate::outbound::IpVersion::V4,
    );
    handle.alive_set.mark_dead(udp_test_node().id);
    assert!(
        !handle.udp_pool.is_empty(),
        "speculative transport preparation must not bind its lease before a winner exists"
    );
    release.notify_one();
    let result = task.await.unwrap();
    assert!(result.is_ok(), "unexpected initializer result: {result:?}");
    assert!(
        handle.udp_pool.is_empty(),
        "the stale unbound initializer must retire after eligibility rejects its prepared transport"
    );
    assert_eq!(dials.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        sends.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "death during the production blocked dial must prevent application send"
    );
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

// --- UDP post-decision kernel offload -------------------------------------

#[test]
fn udp_offload_predicate_mode_and_outbound_matrix() {
    let rule = crate::mode::ModeState::new("rule", "proxy");
    let direct = crate::mode::ModeState::new("direct", "proxy");
    let global = crate::mode::ModeState::new("global", "direct");
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let allow = super::connection::udp_post_decision_offload_allowed;

    // Rule (and clash-API-disabled, where no override ever applies) offload
    // a converged direct decision.
    assert!(allow(Some(&rule), "direct", false, client, dst));
    assert!(allow(None, "direct", false, client, dst));
    // Direct normalizes every non-must/block decision to direct.
    assert!(allow(Some(&direct), "direct", false, client, dst));
    // A proxied or blocked decision is never offloaded, in any mode.
    assert!(!allow(Some(&rule), "proxy", false, client, dst));
    assert!(!allow(Some(&direct), "proxy", false, client, dst));
    assert!(!allow(None, "block", false, client, dst));
    // Global keeps non-must flows in userspace, even when the GLOBAL
    // selection itself resolves to direct.
    assert!(!allow(Some(&global), "direct", false, client, dst));
    // must-direct finals offload in every mode.
    assert!(allow(Some(&global), "direct", true, client, dst));
    assert!(allow(Some(&rule), "direct", true, client, dst));
    // Port 53 is never offloaded, in either direction: the DNS hijack
    // depends on the DnsController seeing every packet.
    assert!(!allow(
        None,
        "direct",
        false,
        client,
        addr("203.0.113.2:53")
    ));
    assert!(!allow(None, "direct", true, client, addr("203.0.113.2:53")));
    assert!(!allow(None, "direct", false, addr("10.0.0.2:53"), dst));
}

/// A transport whose receive side never completes, so the endpoint driver
/// stays alive and the Ready endpoint remains observable in the pool.
#[derive(Debug)]
struct UdpOffloadTestTransport {
    relay: SocketAddr,
    sends: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for UdpOffloadTestTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        self.sends
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn recv_packet(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

/// Counts dials/sends so offload tests can prove the userspace datapath was
/// never used for an offloaded flow.
#[derive(Debug, Clone, Default)]
struct UdpOffloadTestHandler {
    dials: Arc<std::sync::atomic::AtomicUsize>,
    sends: Arc<std::sync::atomic::AtomicUsize>,
}

impl UdpOffloadTestHandler {
    fn dial_count(&self) -> usize {
        self.dials.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn send_count(&self) -> usize {
        self.sends.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for UdpOffloadTestHandler {
    async fn dial(
        &self,
        _node: &Node,
        _target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        Err(anyhow::anyhow!(
            "TCP dial is not used by the UDP offload tests"
        ))
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for UdpOffloadTestHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        _target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        self.dials
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Arc::new(UdpOffloadTestTransport {
            relay: target,
            sends: self.sends.clone(),
        }))
    }
}

/// Registers the offload test handler for both the Socks5 (proxy leaf) and
/// Direct (built-in) protocols, and optionally installs a clash mode state.
fn udp_offload_test_handle(
    config: Config,
    clash: Option<crate::mode::ModeState>,
) -> (ControlPlaneHandle, UdpOffloadTestHandler) {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = UdpOffloadTestHandler::default();
    let handler_arc = Arc::new(handler.clone());
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler_arc.clone(),
        )
        .with_packet(handler_arc.clone()),
    );
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Direct,
            handler_arc.clone(),
        )
        .with_packet(handler_arc),
    );
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        8,
        Arc::new(UdpTestReplySocketFactory),
    ));
    if let Some(state) = clash {
        control_plane.set_mode_state(Arc::new(parking_lot::RwLock::new(state)));
    }
    control_plane.udp_post_decision_offload = true;
    (control_plane.spawn_handle(), handler)
}

fn udp_offload_test_config(default_outbound: &str, nodes: Vec<Node>) -> Config {
    let mut config = udp_test_config(default_outbound, nodes, vec![]);
    config.ensure_builtin_nodes();
    config
}

/// A genuine QUIC v1 client Initial whose ClientHello carries `sni`, built
/// with the sniffer's own test utils (the encryption-side mirror of the
/// decryption pipeline).
fn quic_initial_payload(sni: Option<&str>) -> Vec<u8> {
    use super::quic::test_utils;
    test_utils::protect_initial_packet(
        b"dcid1234",
        b"",
        super::quic::QUIC_VERSION_1,
        0,
        1,
        &test_utils::wrap_crypto_frame(0, &test_utils::build_client_hello(sni)),
    )
}

/// Mirror of the kernel's `build_routing_meta` bit encoding.
fn seeded_meta_raw(outbound: u8, mark: u32, must: u8) -> u64 {
    (outbound as u64)
        | ((mark as u64) << 8)
        | ((must as u64) << 40)
        | honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED
}

async fn seed_udp_conn_state(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    raw: u64,
) -> TuplesKey {
    let key =
        super::connection::build_tuples_key(dst.ip(), dst.port(), client.ip(), client.port(), 17);
    let state = ConnState {
        last_seen_ns: 1,
        meta: RoutingMeta { raw },
        ..Default::default()
    };
    handle
        .ebpf
        .write()
        .await
        .udp_conn_state_store(&key, &state)
        .unwrap();
    key
}

async fn udp_conn_meta_raw(handle: &ControlPlaneHandle, key: &TuplesKey) -> Option<u64> {
    handle
        .ebpf
        .read()
        .await
        .udp_conn_state_lookup(key)
        .unwrap()
        .map(|state| unsafe { state.meta.raw })
}

#[tokio::test]
async fn udp_offload_converged_direct_marks_conn_state() {
    for (client, dst) in [
        (addr("10.0.0.2:53000"), addr("203.0.113.2:443")),
        (addr("[2001:db8::2]:53000"), addr("[2001:db8::3]:443")),
    ] {
        let config = udp_offload_test_config("direct", vec![]);
        let (handle, handler) = udp_offload_test_handle(config, None);
        let key = seed_udp_conn_state(
            &handle,
            client,
            dst,
            seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
        )
        .await;
        let initial = quic_initial_payload(Some("quic.example.org"));

        serve_test_udp_to(&handle, client, dst, &initial)
            .await
            .unwrap();

        let raw = udp_conn_meta_raw(&handle, &key)
            .await
            .expect("conn state kept");
        assert_ne!(
            raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD,
            0,
            "converged direct QUIC flow must be offloaded ({client} -> {dst})"
        );
        assert_ne!(raw & honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED, 0);
        // Drop-and-reinject: no endpoint, no tracker entry, no stats
        // connection, and not a single userspace dial — nothing is left
        // frozen behind the offloaded flow.
        assert!(handle.udp_pool.get(client, dst).is_none());
        assert!(handle.connection_tracker.snapshot().is_empty());
        assert!(!handle.stats.snapshot().contains_key("direct"));
        assert_eq!(handler.dial_count(), 0);
    }
}

#[tokio::test]
async fn udp_offload_direct_mode_normalizes_proxy_decision() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("udp-test", vec![udp_test_node()]);
    let (handle, handler) =
        udp_offload_test_handle(config, Some(crate::mode::ModeState::new("direct", "proxy")));
    // The kernel cached a proxy decision for this flow (e.g. it was routed
    // before the mode switch); the userspace override re-decides it to
    // direct, so the cached meta must be normalized along with the offload
    // bit.
    let key = seed_udp_conn_state(
        &handle,
        client,
        dst,
        seeded_meta_raw(
            honk_ebpf_common::OutboundIndex::UserBase as u8,
            honk_ebpf_common::TPROXY_MARK,
            0,
        ),
    )
    .await;
    let initial = quic_initial_payload(Some("quic.example.org"));

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    let raw = udp_conn_meta_raw(&handle, &key)
        .await
        .expect("conn state kept");
    assert_ne!(raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD, 0);
    assert_eq!(
        raw & 0xFF,
        honk_ebpf_common::OutboundIndex::Direct as u64,
        "cached outbound normalized to direct"
    );
    assert_eq!(
        (raw >> 8) & 0xFFFF_FFFF,
        0,
        "tproxy mark must be cleared or policy routing loops the flow back into daens"
    );
    assert_eq!(handler.dial_count(), 0);
}

#[tokio::test]
async fn udp_offload_rule_mode_keeps_proxy_decision_in_userspace() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("udp-test", vec![udp_test_node()]);
    let (handle, handler) = udp_offload_test_handle(config, None);
    let proxied = seeded_meta_raw(
        honk_ebpf_common::OutboundIndex::UserBase as u8,
        honk_ebpf_common::TPROXY_MARK,
        0,
    );
    let key = seed_udp_conn_state(&handle, client, dst, proxied).await;
    let initial = quic_initial_payload(Some("quic.example.org"));

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    assert_eq!(
        udp_conn_meta_raw(&handle, &key).await,
        Some(proxied),
        "a converged proxy decision must never be offloaded"
    );
    // Zero impact: the flow is relayed in userspace exactly as before.
    assert!(handle.udp_pool.get(client, dst).is_some());
    assert_eq!(handler.dial_count(), 1);
    assert_eq!(handler.send_count(), 1);
}

#[tokio::test]
async fn udp_offload_global_mode_keeps_direct_decision_in_userspace() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("direct", vec![]);
    // GLOBAL selection resolves to direct: the decision converges to direct,
    // but Global mode offloads only must-direct finals.
    let (handle, handler) = udp_offload_test_handle(
        config,
        Some(crate::mode::ModeState::new("global", "direct")),
    );
    let direct = seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0);
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;
    let initial = quic_initial_payload(Some("quic.example.org"));

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    assert_eq!(udp_conn_meta_raw(&handle, &key).await, Some(direct));
    assert!(handle.udp_pool.get(client, dst).is_some());
    assert_eq!(handler.dial_count(), 1);
}

/// Same offloadable conditions (direct decision, Rule semantics), but the
/// first datagram is not a QUIC Initial: the flow must stay on the full
/// userspace relay — no offload, and its packet is relayed, never dropped.
#[tokio::test]
async fn udp_offload_non_quic_flow_stays_in_userspace() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("direct", vec![]);
    let (handle, handler) = udp_offload_test_handle(config, None);
    let direct = seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0);
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;

    serve_test_udp_to(&handle, client, dst, b"plain udp payload")
        .await
        .unwrap();

    assert_eq!(
        udp_conn_meta_raw(&handle, &key).await,
        Some(direct),
        "a non-QUIC flow must never be offloaded (no retransmission guarantee)"
    );
    assert!(handle.udp_pool.get(client, dst).is_some());
    assert_eq!(handler.dial_count(), 1);
    assert_eq!(
        handler.send_count(),
        1,
        "the packet must be relayed, not dropped"
    );
}

/// A decrypted Initial whose ClientHello carries no SNI is still confirmed
/// QUIC, so a converged-direct decision may offload it.
#[tokio::test]
async fn udp_offload_quic_initial_without_sni_is_confirmed() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("direct", vec![]);
    let (handle, handler) = udp_offload_test_handle(config, None);
    let key = seed_udp_conn_state(
        &handle,
        client,
        dst,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    let initial = quic_initial_payload(None);

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    let raw = udp_conn_meta_raw(&handle, &key)
        .await
        .expect("conn state kept");
    assert_ne!(raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD, 0);
    assert_eq!(handler.dial_count(), 0);
}

#[tokio::test]
async fn udp_offload_uncommitted_initializer_never_marks_conn_state() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("direct", vec![]);
    let (handle, _handler) = udp_offload_test_handle(config, None);
    let direct = seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0);
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;
    // Retire the initializer mid-flight: no decision ever converges, so no
    // offload write may happen.
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let crate::control::udp_endpoint::EndpointReservation::Initializing(lease) = handle
        .udp_pool
        .reserve_or_enqueue(client, dst, b"UDP test packet", slow_permit, &handle.stats)
    else {
        panic!("fresh flow must reserve an initializer");
    };
    drop(lease);

    assert_eq!(
        udp_conn_meta_raw(&handle, &key).await,
        Some(direct),
        "an uncommitted initializer must never offload"
    );
}

#[tokio::test]
async fn udp_offload_repeats_after_conn_state_sweep_without_leaking() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let config = udp_offload_test_config("direct", vec![]);
    let (handle, handler) = udp_offload_test_handle(config, None);
    let direct = seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0);
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;
    let initial = quic_initial_payload(Some("quic.example.org"));

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();
    assert_ne!(
        udp_conn_meta_raw(&handle, &key).await.unwrap()
            & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD,
        0
    );

    // The flow goes silent and the datapath sweeps its conn_state after
    // 120s; the next Initial repeats the decide-drop-reinject cycle.
    // Nothing userspace-side exists that could leak: this path never
    // creates an endpoint.
    handle
        .ebpf
        .write()
        .await
        .udp_conn_state_remove(&key)
        .unwrap();
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;

    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    assert_ne!(
        udp_conn_meta_raw(&handle, &key).await.unwrap()
            & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD,
        0,
        "re-created flow must be offloaded again"
    );
    assert!(handle.udp_pool.is_empty(), "no endpoint was ever created");
    assert_eq!(handler.dial_count(), 0);
}

/// Config carrying one domain-class rule (unique name/suffix) pointing at
/// `direct`, so a sniffed `quic-offload.example` flow converges to direct
/// through a domain rule and gets a DOMAIN_ROUTING_MAP writeback.
fn udp_offload_domain_rule_config() -> Config {
    let mut config = udp_offload_test_config("direct", vec![udp_test_node()]);
    let mut rule = domain_rule("direct");
    rule.name = "udp-offload-domain".into();
    rule.condition.domain_suffix = vec!["quic-offload.example".into()];
    config.routing.rules = vec![rule];
    // domain++: sniff and re-route without the reality check (the test DNS
    // forwarder cannot resolve the made-up domain).
    config.global.dial_mode = "domain++".into();
    config
}

/// Install a recognizable bitmap for the test domain rule.  Test control
/// planes never run `activate_projection` (that happens at engine start),
/// so the process-global DOMAIN_BITMAPS is populated directly — this also
/// shields the serve from a concurrent test replacing the global.
fn repin_offload_domain_bitmap() -> Vec<DomainRouting> {
    let mut bitmap = DomainRouting::default();
    bitmap.bitmap[0] = 0x5A00_0001;
    bitmap.bitmap[2] = 0x0000_0042;
    let expected = vec![bitmap];
    crate::control::routing_matcher::DOMAIN_BITMAPS
        .write()
        .insert("udp-offload-domain".into(), expected.clone());
    expected
}

/// The mock's DOMAIN_ROUTING_MAP entry for `dst`, keyed like the map.
async fn domain_route_bitmap(
    handle: &ControlPlaneHandle,
    dst: SocketAddr,
) -> Option<DomainRouting> {
    let prefix_len = if dst.is_ipv4() { 32 } else { 128 };
    let lpm_key =
        crate::ebpf::maps::cidr_to_lpm_key(&format!("{}/{prefix_len}", dst.ip())).unwrap();
    let key_bytes = crate::ebpf::maps::lpm_key_bytes(&lpm_key);
    handle
        .ebpf
        .read()
        .await
        .projection_map_snapshot()
        .into_iter()
        .find(|(key, _)| *key == key_bytes)
        .map(|(_, bitmap)| bitmap)
}

#[tokio::test]
async fn udp_offload_writes_domain_bitmap_for_sniffed_direct_flow() {
    for (client, dst) in [
        (addr("10.0.0.2:53000"), addr("203.0.113.2:443")),
        (addr("[2001:db8::2]:53000"), addr("[2001:db8::3]:443")),
    ] {
        let (handle, handler) = udp_offload_test_handle(udp_offload_domain_rule_config(), None);
        let expected = repin_offload_domain_bitmap();
        let key = seed_udp_conn_state(
            &handle,
            client,
            dst,
            seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
        )
        .await;
        let initial = quic_initial_payload(Some("quic-offload.example"));

        serve_test_udp_to(&handle, client, dst, &initial)
            .await
            .unwrap();

        let raw = udp_conn_meta_raw(&handle, &key)
            .await
            .expect("conn state kept");
        assert_ne!(raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD, 0);
        assert_eq!(handler.dial_count(), 0);
        // The sniffed domain's rule bitmap was written back for the dst IP,
        // transformed into the active routing generation exactly like a
        // DNS-learned route.
        let generation = handle
            .ebpf
            .read()
            .await
            .active_routing_generation()
            .unwrap();
        let mut merged = DomainRouting::default();
        for bm in &expected {
            for (word, value) in merged.bitmap.iter_mut().zip(bm.bitmap) {
                *word |= value;
            }
        }
        let expected_stored = merged.for_generation(generation);
        let stored = domain_route_bitmap(&handle, dst).await;
        assert_eq!(
            stored.map(|bitmap| bitmap.bitmap),
            Some(expected_stored.bitmap),
            "DOMAIN_ROUTING_MAP must carry the sniffed rule bitmap ({client} -> {dst})"
        );
    }
}

#[tokio::test]
async fn udp_offload_domain_bitmap_survives_conn_state_sweep() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let (handle, handler) = udp_offload_test_handle(udp_offload_domain_rule_config(), None);
    let _expected = repin_offload_domain_bitmap();
    let key = seed_udp_conn_state(
        &handle,
        client,
        dst,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    let initial = quic_initial_payload(Some("quic-offload.example"));
    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();
    assert!(domain_route_bitmap(&handle, dst).await.is_some());

    // The flow goes silent and the datapath sweeps the conn_state (120s).
    handle
        .ebpf
        .write()
        .await
        .udp_conn_state_remove(&key)
        .unwrap();

    // The learned domain route lives in DOMAIN_ROUTING_MAP, not the
    // conn_state, so it survives the sweep: a mid-session packet is not an
    // Initial and cannot be re-sniffed, but the route-time re-decision finds
    // the bitmap (DomainKnown → direct → kernel route-time offload — the
    // unchanged main path) and never re-enters userspace.  Assert the state
    // that evaluation consumes and that nothing userspace-side exists.
    assert!(
        domain_route_bitmap(&handle, dst).await.is_some(),
        "the learned domain route must survive the conn_state sweep"
    );
    assert!(handle.udp_pool.is_empty());
    assert!(handle.connection_tracker.snapshot().is_empty());
    assert_eq!(handler.dial_count(), 0);
}

#[tokio::test]
async fn udp_offload_domain_bitmap_write_failure_is_not_fatal() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let (handle, handler) = udp_offload_test_handle(udp_offload_domain_rule_config(), None);
    let _expected = repin_offload_domain_bitmap();
    let key = seed_udp_conn_state(
        &handle,
        client,
        dst,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    handle
        .ebpf
        .write()
        .await
        .inject_domain_bitmap_add_fault(1)
        .unwrap();
    let initial = quic_initial_payload(Some("quic-offload.example"));

    // The writeback failure must not fail the flow or the offload.
    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();

    let raw = udp_conn_meta_raw(&handle, &key)
        .await
        .expect("conn state kept");
    assert_ne!(
        raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD,
        0,
        "offload stands even when the bitmap writeback fails"
    );
    assert!(domain_route_bitmap(&handle, dst).await.is_none());
    assert_eq!(handler.dial_count(), 0);
}

/// A genuine QUIC v1 client Initial whose ClientHello SNI is split across
/// two CRYPTO fragments (two Initial packets).
fn split_quic_initial(sni: &str) -> (Vec<u8>, Vec<u8>) {
    use super::quic::test_utils;
    let hello = test_utils::build_client_hello(Some(sni));
    let split = 40;
    (
        test_utils::protect_initial_packet(
            b"dcid1234",
            b"",
            super::quic::QUIC_VERSION_1,
            0,
            1,
            &test_utils::wrap_crypto_frame(0, &hello[..split]),
        ),
        test_utils::protect_initial_packet(
            b"dcid1234",
            b"",
            super::quic::QUIC_VERSION_1,
            1,
            1,
            &test_utils::wrap_crypto_frame(split as u64, &hello[split..]),
        ),
    )
}

/// Reserve an initializer with the first fragment, queue the second as a
/// follower, then serve.
async fn serve_split_initial(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    first: &[u8],
    second: &[u8],
) -> anyhow::Result<()> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let crate::control::udp_endpoint::EndpointReservation::Initializing(lease) = handle
        .udp_pool
        .reserve_or_enqueue(client, dst, first, slow_permit, &handle.stats)
    else {
        panic!("fresh flow must reserve an initializer");
    };
    let follower_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    assert!(matches!(
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, second, follower_permit, &handle.stats),
        crate::control::udp_endpoint::EndpointReservation::Enqueued
    ));
    handle
        .serve_udp_connection(
            lease,
            Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        )
        .await
}

/// A fragmented ClientHello whose SNI matches a proxy domain rule: the
/// engine must collect the follower fragment, complete the sniff, and relay
/// via the proxy — never offload on the IP-only first-fragment view.
#[tokio::test]
async fn udp_offload_fragmented_client_hello_proxy_domain_is_not_offloaded() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let mut config = udp_offload_test_config("direct", vec![udp_test_node()]);
    let mut rule = domain_rule("udp-test");
    rule.name = "split-proxy".into();
    rule.condition.domain_suffix = vec!["split-proxy.example".into()];
    config.routing.rules = vec![rule];
    config.global.dial_mode = "domain++".into();
    let (handle, handler) = udp_offload_test_handle(config, None);
    let proxied = seeded_meta_raw(
        honk_ebpf_common::OutboundIndex::UserBase as u8,
        honk_ebpf_common::TPROXY_MARK,
        0,
    );
    let key = seed_udp_conn_state(&handle, client, dst, proxied).await;
    let (first, second) = split_quic_initial("split-proxy.example");

    serve_split_initial(&handle, client, dst, &first, &second)
        .await
        .unwrap();

    assert_eq!(
        udp_conn_meta_raw(&handle, &key).await,
        Some(proxied),
        "a flow whose fragmented SNI matches a proxy rule must never be offloaded"
    );
    assert!(handle.udp_pool.get(client, dst).is_some());
    assert_eq!(handler.dial_count(), 1);
    assert_eq!(
        handler.send_count(),
        2,
        "every Initial fragment consumed for sniffing must still reach the proxy transport"
    );
}

/// The same fragmented ClientHello converging to direct is collected and
/// then offloaded exactly like a single-Initial flow.
#[tokio::test]
async fn udp_offload_fragmented_client_hello_direct_offloads_after_collection() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let mut config = udp_offload_test_config("direct", vec![]);
    config.global.dial_mode = "domain++".into();
    let (handle, handler) = udp_offload_test_handle(config, None);
    let direct = seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0);
    let key = seed_udp_conn_state(&handle, client, dst, direct).await;
    let (first, second) = split_quic_initial("quic.example.org");

    serve_split_initial(&handle, client, dst, &first, &second)
        .await
        .unwrap();

    let raw = udp_conn_meta_raw(&handle, &key)
        .await
        .expect("conn state kept");
    assert_ne!(
        raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD,
        0,
        "a fragmented CH that resolves to direct must still be offloaded"
    );
    assert!(handle.udp_pool.is_empty());
    assert_eq!(handler.dial_count(), 0);
}

/// P1a regression, with the real production removal worker: the offload
/// handoff (`commit_offloaded` / KernelOffloadHandoff) must leave the
/// offloaded conn_state in place — a plain lease drop would notify
/// UserspaceEndpointRetired and the worker would delete the very conn_state
/// that anchors the offload, bouncing the retransmission back to userspace.
#[tokio::test]
async fn udp_offload_conn_state_survives_production_removal_worker() {
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let (handle, handler) =
        udp_offload_test_handle(udp_offload_test_config("direct", vec![]), None);
    let worker = super::spawn_udp_removal_worker(
        handle.udp_pool.clone(),
        handle.ebpf.clone(),
        handle.connection_tracker.clone(),
    );

    let key = seed_udp_conn_state(
        &handle,
        client,
        dst,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    let initial = quic_initial_payload(Some("quic.example.org"));
    serve_test_udp_to(&handle, client, dst, &initial)
        .await
        .unwrap();
    assert!(
        handle.udp_pool.is_empty(),
        "commit_offloaded retires the reservation"
    );

    // Push a real userspace-endpoint retirement through the same worker and
    // wait for its conn_state deletion — the FIFO channel then proves the
    // earlier KernelOffloadHandoff notification was already processed.
    let client2 = addr("10.0.0.3:53001");
    let dst2 = addr("203.0.113.9:443");
    let key2 = seed_udp_conn_state(
        &handle,
        client2,
        dst2,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    serve_test_udp_to(&handle, client2, dst2, b"plain udp payload")
        .await
        .unwrap();
    assert!(handle.udp_pool.get(client2, dst2).is_some());
    handle.udp_pool.remove(client2, dst2);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if udp_conn_meta_raw(&handle, &key2).await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the removal worker must retire a userspace endpoint's conn_state");
    assert_eq!(handler.dial_count(), 1);

    let raw = udp_conn_meta_raw(&handle, &key)
        .await
        .expect("the offloaded conn_state must survive the removal worker");
    assert_ne!(raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD, 0);
    worker.abort();
}

/// End-to-end drop-and-reinject: a real quinn client's first Initial is fed
/// to the engine (which offloads the flow and drops the packet), the
/// client's retransmission is then forwarded along the "kernel path" stand-
/// in, and the QUIC handshake must complete.  A raw recorder in front of
/// the QUIC server logs every client-side `recvfrom` peer: the whole flow —
/// everything after the offload switch included — must show exactly one
/// tuple, and the engine must never have dialed (its own ephemeral socket
/// must never appear on the wire).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_offload_quic_handshake_after_initial_drop_keeps_single_server_tuple() {
    use tokio_rustls::rustls;

    // QUIC server (rustls, self-signed "localhost").
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut tls_server = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
    )
    .unwrap();
    tls_server.alpn_protocols = vec![b"h3".to_vec()];
    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_server).unwrap();
    let server_ep = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
        addr("127.0.0.1:0"),
    )
    .unwrap();
    let server_addr = server_ep.local_addr().unwrap();
    // quinn drives the server handshake only while `accept` is polled.
    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("server must accept");
        incoming.await.expect("server-side handshake")
    });

    // Raw recorder in front of the server: logs every client-side peer and
    // relays datagrams between the current peer and the server.
    let recorder = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recorder_addr = recorder.local_addr().unwrap();
    let seen_peers = Arc::new(std::sync::Mutex::new(
        std::collections::HashSet::<SocketAddr>::new(),
    ));
    {
        let recorder = recorder.clone();
        let seen_peers = seen_peers.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut uplink: Option<SocketAddr> = None;
            loop {
                let (n, peer) = recorder.recv_from(&mut buf).await.unwrap();
                if peer == server_addr {
                    if let Some(uplink) = uplink {
                        recorder.send_to(&buf[..n], uplink).await.unwrap();
                    }
                } else {
                    seen_peers.lock().unwrap().insert(peer);
                    uplink = Some(peer);
                    recorder.send_to(&buf[..n], server_addr).await.unwrap();
                }
            }
        });
    }

    // Engine under test: a domain-class rule (matching nothing here) makes
    // the flow genuinely require userspace evaluation, exactly the flows
    // this offload exists for; the sniffed "localhost" misses it and the
    // decision converges to the default direct.
    let mut config = udp_offload_test_config("direct", vec![udp_test_node()]);
    config.routing.rules = vec![domain_rule("udp-test")];
    let (handle, handler) = udp_offload_test_handle(config, None);

    // Harness "network": the client connects here.  Each client datagram
    // either goes through the engine (no offload bit yet) or — once the
    // conn_state carries the offload bit — is forwarded unchanged from the
    // kernel-path socket, like the offloaded datapath preserving the client
    // tuple.
    let net = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let net_addr = net.local_addr().unwrap();
    let kernel_fwd = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let kernel_addr = kernel_fwd.local_addr().unwrap();
    {
        let handle = handle.clone();
        let net = net.clone();
        let kernel_fwd = kernel_fwd.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, peer) = net.recv_from(&mut buf).await.unwrap();
                let payload = buf[..n].to_vec();
                let key = super::connection::build_tuples_key(
                    recorder_addr.ip(),
                    recorder_addr.port(),
                    peer.ip(),
                    peer.port(),
                    17,
                );
                let meta = udp_conn_meta_raw(&handle, &key).await;
                let offloaded = meta
                    .map(|raw| raw & honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD != 0)
                    .unwrap_or(false);
                if offloaded {
                    kernel_fwd.send_to(&payload, recorder_addr).await.unwrap();
                    continue;
                }
                if meta.is_none() {
                    // Emulate the kernel's route-time publication for a flow
                    // that needed userspace evaluation.
                    seed_udp_conn_state(
                        &handle,
                        peer,
                        recorder_addr,
                        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
                    )
                    .await;
                }
                let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
                    .try_acquire_owned()
                    .expect("harness slow permit");
                if let crate::control::udp_endpoint::EndpointReservation::Initializing(lease) =
                    handle.udp_pool.reserve_or_enqueue(
                        peer,
                        recorder_addr,
                        &payload,
                        slow_permit,
                        &handle.stats,
                    )
                {
                    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    let _ = handle.serve_udp_connection(lease, socket).await;
                }
            }
        });
    }
    // quinn client endpoint is created up front so its address is known to
    // the reply forwarder; the connect happens after the harness is live.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut tls_client = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls_client.alpn_protocols = vec![b"h3".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap();
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_rtt(Duration::from_millis(50));
    client_config.transport_config(Arc::new(transport));
    let mut client_ep = quinn::Endpoint::client(addr("127.0.0.1:0")).unwrap();
    client_ep.set_default_client_config(client_config);
    let client_addr = client_ep.local_addr().unwrap();

    // Kernel-path replies: server → recorder → kernel_fwd → client.
    {
        let net = net.clone();
        let kernel_fwd = kernel_fwd.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, peer) = kernel_fwd.recv_from(&mut buf).await.unwrap();
                if peer == recorder_addr {
                    net.send_to(&buf[..n], client_addr).await.unwrap();
                }
            }
        });
    }

    let connection = tokio::time::timeout(
        Duration::from_secs(15),
        client_ep.connect(net_addr, "localhost").unwrap(),
    )
    .await
    .expect("QUIC handshake must complete via retransmission after the Initial drop")
    .expect("QUIC connect failed");

    let server_conn = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_conn.remote_address(), recorder_addr);

    connection.close(0u32.into(), b"done");

    let peers = seen_peers.lock().unwrap();
    assert_eq!(
        peers.len(),
        1,
        "the whole flow must show a single server-visible tuple, got {peers:?}"
    );
    assert!(peers.contains(&kernel_addr));
    drop(peers);
    assert_eq!(
        handler.dial_count(),
        0,
        "the engine must never relay an offloaded flow (no ephemeral socket on the wire)"
    );
}

/// Quantify the cost the drop-and-reinject offload adds to a QUIC handshake:
/// exactly one Initial PTO.  A plain relay harness forwards everything
/// except — in the drop run — the client's very first datagram.  Prints both
/// handshake times; the assertion stays deliberately loose (the numbers are
/// for the commit message / docs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_offload_pto_cost_measurement() {
    use tokio_rustls::rustls;
    let mut timings = Vec::new();
    for drop_first in [false, true] {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut tls_server = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
        )
        .unwrap();
        tls_server.alpn_protocols = vec![b"h3".to_vec()];
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_server).unwrap();
        let server_ep = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(server_crypto)),
            addr("127.0.0.1:0"),
        )
        .unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("server must accept");
            incoming.await.expect("server-side handshake")
        });

        // Relay: client-facing socket + server-facing socket; optionally
        // drop the first client datagram (the offloaded Initial).
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let front_addr = front.local_addr().unwrap();
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_slot = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
        {
            let front = front.clone();
            let back = back.clone();
            let client_slot = client_slot.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let mut dropped = false;
                loop {
                    let (n, peer) = front.recv_from(&mut buf).await.unwrap();
                    *client_slot.lock().unwrap() = Some(peer);
                    if drop_first && !dropped {
                        dropped = true;
                        continue;
                    }
                    back.send_to(&buf[..n], server_addr).await.unwrap();
                }
            });
        }
        {
            let front = front.clone();
            let back = back.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let (n, peer) = back.recv_from(&mut buf).await.unwrap();
                    if peer != server_addr {
                        continue;
                    }
                    let client = *client_slot.lock().unwrap();
                    if let Some(client) = client {
                        front.send_to(&buf[..n], client).await.unwrap();
                    }
                }
            });
        }

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut tls_client = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls_client.alpn_protocols = vec![b"h3".to_vec()];
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.initial_rtt(Duration::from_millis(50));
        client_config.transport_config(Arc::new(transport));
        let mut client_ep = quinn::Endpoint::client(addr("127.0.0.1:0")).unwrap();
        client_ep.set_default_client_config(client_config);

        let started = std::time::Instant::now();
        let connection = tokio::time::timeout(
            Duration::from_secs(15),
            client_ep.connect(front_addr, "localhost").unwrap(),
        )
        .await
        .expect("handshake must complete")
        .expect("connect failed");
        let elapsed = started.elapsed();
        timings.push((drop_first, elapsed));
        connection.close(0u32.into(), b"done");
        server_task.abort();
        client_ep.close(0u32.into(), b"done");
    }
    let baseline = timings[0].1;
    let dropped = timings[1].1;
    eprintln!(
        "drop-and-reinject PTO cost: baseline={baseline:?} drop-first-initial={dropped:?} delta={:?}",
        dropped.saturating_sub(baseline)
    );
    assert!(
        dropped < Duration::from_secs(5),
        "one Initial PTO must stay bounded"
    );
}

/// Run a command, panicking with stderr on failure (netns test setup).
#[cfg(target_os = "linux")]
fn run_cmd(program: &str, args: &[&str]) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    assert!(
        output.status.success(),
        "{program} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run `f` inside the named network namespace, restoring the caller's
/// namespace afterwards.  Socket creation pins the fd to the namespace it
/// was created in, so the returned socket keeps working after the restore.
#[cfg(target_os = "linux")]
fn with_netns<R>(name: &str, f: impl FnOnce() -> R) -> R {
    use std::os::fd::AsRawFd;
    let current = std::fs::File::open("/proc/thread-self/ns/net").unwrap();
    let target = std::fs::File::open(format!("/var/run/netns/{name}")).expect("named netns exists");
    assert_eq!(
        unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) },
        0
    );
    let result = f();
    assert_eq!(
        unsafe { libc::setns(current.as_raw_fd(), libc::CLONE_NEWNET) },
        0
    );
    result
}

/// Real netns/kernel-path variant of the drop-and-reinject e2e: three
/// namespaces (client — root gateway — server) with genuine kernel routing.
/// A stateless TPROXY rule diverts only the flow's first datagram(s) to the
/// harness (which feeds the engine and lets it offload+drop); deleting the
/// rule then lets the client's retransmission flow entirely through the
/// kernel.  The server must observe the client's real tuple end-to-end —
/// no userspace socket ever appears on the wire.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires root; run via just test-netns"]
async fn udp_offload_netns_retransmit_uses_real_kernel_path() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: requires root");
        return;
    }
    use tokio_rustls::rustls;

    let pid = std::process::id();
    let ns_cl = format!("honkcl{pid}");
    let ns_srv = format!("honksrv{pid}");
    let v_cl = format!("vcl{pid}");
    let v_cl_br = format!("vcb{pid}");
    let v_srv = format!("vsv{pid}");
    let v_srv_br = format!("vsb{pid}");
    const CLIENT_IP: &str = "10.177.0.2";
    const SERVER_IP: &str = "10.177.1.2";
    const SERVER_PORT: u16 = 4433;
    const HARNESS_PORT: u16 = 14434;

    // Best-effort teardown of everything the setup created.
    struct Cleanup {
        rule: Vec<String>,
        ns_cl: String,
        ns_srv: String,
        ip_forward_was: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("iptables")
                .args(&self.rule)
                .output();
            let _ = std::process::Command::new("ip")
                .args(["rule", "del", "fwmark", "0x66/0x66", "lookup", "106"])
                .output();
            let _ = std::process::Command::new("ip")
                .args(["route", "flush", "table", "106"])
                .output();
            for ns in [&self.ns_cl, &self.ns_srv] {
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", ns])
                    .output();
            }
            let _ = std::fs::write(
                "/proc/sys/net/ipv4/ip_forward",
                self.ip_forward_was.as_bytes(),
            );
        }
    }

    let ip_forward_was =
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_else(|_| "1\n".into());
    let rule: Vec<String> = [
        "-t",
        "mangle",
        "-D",
        "PREROUTING",
        "-i",
        &v_cl_br,
        "-p",
        "udp",
        "-d",
        SERVER_IP,
        "--dport",
        "4433",
        "-j",
        "TPROXY",
        "--on-ip",
        "127.0.0.1",
        "--on-port",
        "14434",
        "--tproxy-mark",
        "0x66/0x66",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let _cleanup = Cleanup {
        rule,
        ns_cl: ns_cl.clone(),
        ns_srv: ns_srv.clone(),
        ip_forward_was,
    };

    run_cmd("ip", &["netns", "add", &ns_cl]);
    run_cmd("ip", &["netns", "add", &ns_srv]);
    run_cmd(
        "ip",
        &[
            "link", "add", &v_cl, "type", "veth", "peer", "name", &v_cl_br,
        ],
    );
    run_cmd(
        "ip",
        &[
            "link", "add", &v_srv, "type", "veth", "peer", "name", &v_srv_br,
        ],
    );
    run_cmd("ip", &["link", "set", &v_cl, "netns", &ns_cl]);
    run_cmd("ip", &["link", "set", &v_srv, "netns", &ns_srv]);
    run_cmd("ip", &["addr", "add", "10.177.0.1/24", "dev", &v_cl_br]);
    run_cmd("ip", &["link", "set", &v_cl_br, "up"]);
    run_cmd("ip", &["addr", "add", "10.177.1.1/24", "dev", &v_srv_br]);
    run_cmd("ip", &["link", "set", &v_srv_br, "up"]);
    for (ns, dev, ip_addr, gw) in [
        (&ns_cl, &v_cl, "10.177.0.2/24", "10.177.0.1"),
        (&ns_srv, &v_srv, "10.177.1.2/24", "10.177.1.1"),
    ] {
        run_cmd(
            "ip",
            &["netns", "exec", ns, "ip", "link", "set", "lo", "up"],
        );
        run_cmd(
            "ip",
            &[
                "netns", "exec", ns, "ip", "addr", "add", ip_addr, "dev", dev,
            ],
        );
        run_cmd("ip", &["netns", "exec", ns, "ip", "link", "set", dev, "up"]);
        run_cmd(
            "ip",
            &[
                "netns", "exec", ns, "ip", "route", "add", "default", "via", gw,
            ],
        );
    }
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    run_cmd(
        "ip",
        &["rule", "add", "fwmark", "0x66/0x66", "lookup", "106"],
    );
    run_cmd(
        "ip",
        &[
            "route",
            "add",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            "106",
        ],
    );
    run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            &v_cl_br,
            "-p",
            "udp",
            "-d",
            SERVER_IP,
            "--dport",
            "4433",
            "-j",
            "TPROXY",
            "--on-ip",
            "127.0.0.1",
            "--on-port",
            "14434",
            "--tproxy-mark",
            "0x66/0x66",
        ],
    );

    // Harness socket: the TPROXY target for the flow's first datagram(s).
    // IP_TRANSPARENT must be set before bind so the TPROXY socket lookup
    // finds it.
    let harness_std = {
        use std::os::fd::AsRawFd;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        let one: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "IP_TRANSPARENT");
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], HARNESS_PORT)).into())
            .unwrap();
        socket.set_nonblocking(true).unwrap();
        std::net::UdpSocket::from(socket)
    };
    let harness = UdpSocket::from_std(harness_std).unwrap();

    // QUIC server living in the server namespace.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut tls_server = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
    )
    .unwrap();
    tls_server.alpn_protocols = vec![b"h3".to_vec()];
    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_server).unwrap();
    let server_socket = with_netns(&ns_srv, || {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", SERVER_PORT)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    });
    let server_ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn::ServerConfig::with_crypto(Arc::new(server_crypto))),
        server_socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    let server_task = tokio::spawn(async move {
        let incoming = server_ep.accept().await.expect("server must accept");
        incoming.await.expect("server-side handshake")
    });

    // Engine under test (mock backend): decides the diverted first datagram.
    let (handle, handler) =
        udp_offload_test_handle(udp_offload_test_config("direct", vec![]), None);
    let server_addr = addr(&format!("{SERVER_IP}:{SERVER_PORT}"));

    // QUIC client living in the client namespace.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut tls_client = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls_client.alpn_protocols = vec![b"h3".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client).unwrap();
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_rtt(Duration::from_millis(50));
    client_config.transport_config(Arc::new(transport));
    let client_socket = with_netns(&ns_cl, || {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    });
    let mut client_ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        client_socket,
        quinn::default_runtime().unwrap(),
    )
    .unwrap();
    client_ep.set_default_client_config(client_config);

    // Start the client first: its Initial is what the harness waits for.
    let connecting = client_ep.connect(server_addr, "localhost").unwrap();

    // The client's first Initial arrives via TPROXY; feed it to the engine
    // exactly like the production slow path (kernel route-time publication
    // emulated by the seed).
    let mut buf = vec![0u8; 65536];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(5), harness.recv_from(&mut buf))
        .await
        .expect("the client's Initial must be diverted to the harness")
        .unwrap();
    assert_eq!(peer.ip().to_string(), CLIENT_IP);
    seed_udp_conn_state(
        &handle,
        peer,
        server_addr,
        seeded_meta_raw(honk_ebpf_common::OutboundIndex::Direct as u8, 0, 0),
    )
    .await;
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("harness slow permit");
    if let crate::control::udp_endpoint::EndpointReservation::Initializing(lease) = handle
        .udp_pool
        .reserve_or_enqueue(peer, server_addr, &buf[..n], slow_permit, &handle.stats)
    {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        handle.serve_udp_connection(lease, socket).await.unwrap();
    }
    assert_eq!(
        handler.dial_count(),
        0,
        "the engine must drop-and-reinject, never relay"
    );
    // The offload is published: remove the divert rule so the client's
    // retransmission takes the real kernel path, end to end.
    run_cmd(
        "iptables",
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            &v_cl_br,
            "-p",
            "udp",
            "-d",
            SERVER_IP,
            "--dport",
            "4433",
            "-j",
            "TPROXY",
            "--on-ip",
            "127.0.0.1",
            "--on-port",
            "14434",
            "--tproxy-mark",
            "0x66/0x66",
        ],
    );

    let connection = tokio::time::timeout(Duration::from_secs(15), connecting)
        .await
        .expect("QUIC handshake must complete over the real kernel path after the Initial drop")
        .expect("QUIC connect failed");
    let server_conn = tokio::time::timeout(Duration::from_secs(15), server_task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        server_conn.remote_address(),
        peer,
        "the server must see the client's real tuple — no userspace socket on the wire"
    );
    assert_eq!(handler.dial_count(), 0);
    connection.close(0u32.into(), b"done");
}

#[test]
fn udp_slow_admission_is_identical_for_ipv4_and_ipv6() {
    for (client, dst) in [
        (addr("10.0.0.2:53000"), addr("203.0.113.2:443")),
        (addr("[2001:db8::2]:53000"), addr("[2001:db8::3]:443")),
    ] {
        let pool = Arc::new(UdpEndpointPool::with_capacity_limit(1));
        let stats = Arc::new(StatsManager::new());
        let slow = Arc::new(tokio::sync::Semaphore::new(1));
        let lease =
            super::reserve_udp_slow_path(&pool, &stats, &slow, client, dst, b"family-symmetric")
                .expect("both listener families must admit before reserving");
        assert_eq!(pool.len(), 1);
        let udp = stats.udp_snapshot();
        assert_eq!(udp.slow_permit_accepted, 1);
        assert_eq!(udp.capacity_rejections, 0);
        assert_eq!(udp.queue_accepted, 0);
        drop(lease);
        assert!(pool.is_empty());
    }
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
    assert_eq!(udp.flow_queue_full, 0);
    assert_eq!(udp.global_payload_full, 0);
    assert_eq!(udp.queue_closed, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = super::try_admit_udp_slow_path(&stats, &open).expect("slow path should admit");
    drop(permit);
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(udp.slow_permit_rejected, 1);
    assert!(stats.snapshot().is_empty());
}

fn production_dns_controller(
    upstream_calls: Arc<std::sync::atomic::AtomicUsize>,
    response: Vec<u8>,
) -> Arc<crate::control::dns_control::DnsController> {
    use crate::dns::forwarder::{DnsForwarder, DnsUpstreamPool};

    struct CountingUpstream {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        response: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl DnsUpstreamPool for CountingUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.response.clone())
        }
    }

    let upstream = Arc::new(CountingUpstream {
        calls: upstream_calls,
        response,
    });
    let router =
        Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(
                &honk_config::dns::DnsConfig::default(),
            )
            .unwrap(),
        );
    let forwarder = Arc::new(
        DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            router,
        )
        .with_cache_enabled(false),
    );
    Arc::new(crate::control::dns_control::DnsController::new(
        forwarder,
        Arc::new(tokio::sync::RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").unwrap(),
        )),
    ))
}

fn dns_response_payload() -> Vec<u8> {
    let mut resp = dns_query_payload();
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp
}

fn production_dns_controller_with_upstream(
    upstream: Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
) -> Arc<crate::control::dns_control::DnsController> {
    let router =
        Arc::new(
            crate::dns::routing::DnsRouter::new_from_dns_config(
                &honk_config::dns::DnsConfig::default(),
            )
            .unwrap(),
        );
    let forwarder = Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            upstream,
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                16,
            ))),
            router,
        )
        .with_cache_enabled(false),
    );
    Arc::new(crate::control::dns_control::DnsController::new(
        forwarder,
        Arc::new(tokio::sync::RwLock::new(Box::new(
            crate::ebpf::mock::MockEbpfBackend::new(),
        ))),
        Arc::new(tokio::sync::RwLock::new(
            Router::new(&[], "direct").unwrap(),
        )),
    ))
}

#[tokio::test]
async fn udp_dns_dispatch_registers_connection_guard_before_task_poll() {
    struct BlockingUpstream {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl crate::dns::forwarder::DnsUpstreamPool for BlockingUpstream {
        async fn query(&self, _name: &str, _raw: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(dns_response_payload())
        }
    }

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let config = udp_test_config("udp-test", vec![udp_test_node()], vec![]);
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler {
        mode: UdpTestMode::Success,
    });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    plane.dns_controller = production_dns_controller_with_upstream(Arc::new(BlockingUpstream {
        entered: entered.clone(),
        release: release.clone(),
    }));
    let drain = Arc::new(DrainTracker::new());
    let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = addr("10.0.0.3:53000");
    let dst = addr("203.0.113.3:53");

    let state = super::UdpLoopState {
        udp_pool: Arc::clone(&plane.udp_pool),
        stats: Arc::clone(&plane.stats),
        udp_concurrency_limit: Arc::clone(&plane.udp_concurrency_limit),
        dns_concurrency_limit: Arc::clone(&plane.dns_concurrency_limit),
        dns_controller: Arc::clone(&plane.dns_controller),
        drain: Arc::clone(&drain),
        handle: plane.spawn_handle(),
    };
    super::dispatch_udp_slow_path(&state, &listener, client, dst, &dns_query_payload());
    assert_eq!(
        drain.active_count(),
        1,
        "DNS work must be drain-counted when the dispatcher returns, before the spawned task polls"
    );
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("production DNS controller must receive the slow-path query");

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if drain.active_count() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("DNS task must release its ConnectionGuard after completion");
}

/// Production-branch DNS path with an existing Ready endpoint: the shared
/// slow-path helper must run DnsController first and must not enqueue onto
/// the proxy driver.
#[tokio::test]
async fn udp_dns_with_ready_endpoint_uses_controller_not_queue() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    ready_udp_endpoint(
        &pool,
        &stats,
        client,
        dst,
        Arc::new(honk_outbound::proxy::UdpSocketTransport::new(
            proxy, echo_addr,
        )),
        echo_addr,
    )
    .await;
    // Drain the bootstrap first packet from the echo socket.
    let mut buf = [0u8; 64];
    echo.recv_from(&mut buf).await.unwrap();

    let upstream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dns = production_dns_controller(upstream_calls.clone(), dns_response_payload());
    let slow = Arc::new(tokio::sync::Semaphore::new(1));
    let query = dns_query_payload();

    // Fast path must force DNS-shaped traffic slow even with Ready present.
    assert!(!udp_fast_path(&pool, &stats, &query, client, dst).await);

    match super::begin_udp_slow_path(&pool, &stats, &slow, client, dst, &query) {
        super::UdpSlowPathWork::DnsThenMaybeInitialize { permit, data } => {
            let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let lease = super::complete_udp_dns_slow_path(
                super::UdpDnsSlowPathContext {
                    pool: &pool,
                    stats: &stats,
                    dns_controller: dns.as_ref(),
                    udp_socket: &listener,
                    src_addr: client,
                    original_dst: dst,
                },
                permit,
                &data,
            )
            .await;
            assert!(
                lease.is_none(),
                "DNS controller must handle the packet without reserve/enqueue"
            );
        }
        _other => panic!(
            "DNS-shaped Ready traffic must take DnsThenMaybeInitialize, got unexpected variant"
        ),
    }

    assert_eq!(
        upstream_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "production DnsController must run for Ready+DNS"
    );
    // No follower was enqueued onto the Ready driver.
    assert_eq!(stats.udp_snapshot().queue_accepted, 0);
    let recv = tokio::time::timeout(Duration::from_millis(50), echo.recv_from(&mut buf)).await;
    assert!(
        recv.is_err(),
        "DNS query must not be forwarded to the proxy transport"
    );
}

/// Production-branch DNS path while an Initializing entry owns the tuple:
/// controller still runs first; the Initializing queue must not grow.
#[tokio::test]
async fn udp_dns_with_initializing_endpoint_uses_controller_not_queue() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.1:12345");
    let dst = addr("203.0.113.1:53");
    let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"bootstrap", init_permit, &stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("DNS+Initializing fixture must reserve"),
    };
    let queue_before = stats.udp_snapshot().queue_accepted;

    let upstream_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dns = production_dns_controller(upstream_calls.clone(), dns_response_payload());
    let slow = Arc::new(tokio::sync::Semaphore::new(1));
    let query = dns_query_payload();

    assert!(!udp_fast_path(&pool, &stats, &query, client, dst).await);
    match super::begin_udp_slow_path(&pool, &stats, &slow, client, dst, &query) {
        super::UdpSlowPathWork::DnsThenMaybeInitialize { permit, data } => {
            let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let maybe_lease = super::complete_udp_dns_slow_path(
                super::UdpDnsSlowPathContext {
                    pool: &pool,
                    stats: &stats,
                    dns_controller: dns.as_ref(),
                    udp_socket: &listener,
                    src_addr: client,
                    original_dst: dst,
                },
                permit,
                &data,
            )
            .await;
            assert!(maybe_lease.is_none());
        }
        _ => panic!("DNS-shaped Initializing traffic must take DnsThenMaybeInitialize"),
    }

    assert_eq!(upstream_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        stats.udp_snapshot().queue_accepted,
        queue_before,
        "DNS must not enqueue onto the Initializing follower queue"
    );
    assert!(lease.still_initializing());
    drop(lease);
}

/// Initializing followers must not use the direct fast queue path. With a
/// zero-permit semaphore the shared dispatch helper rejects without copying
/// or queue growth; with a permit it enqueues exactly once.
#[tokio::test]
async fn udp_initializing_follower_requires_slow_permit_via_shared_helper() {
    let pool = Arc::new(UdpEndpointPool::new());
    let stats = Arc::new(StatsManager::new());
    let client = addr("10.0.0.2:53000");
    let dst = addr("203.0.113.2:443");
    let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let lease = match pool.reserve_or_enqueue(client, dst, b"first", init_permit, &stats) {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => lease,
        _ => panic!("follower fixture must initialize"),
    };

    // Fast path must miss for Initializing — no direct enqueue, no copy.
    assert!(!udp_fast_path(&pool, &stats, b"follower", client, dst).await);
    assert_eq!(stats.udp_snapshot().endpoint_misses, 1);
    assert_eq!(stats.udp_snapshot().queue_accepted, 0);

    let zero = Arc::new(tokio::sync::Semaphore::new(0));
    match super::begin_udp_slow_path(&pool, &stats, &zero, client, dst, b"follower") {
        super::UdpSlowPathWork::Done => {}
        _ => panic!("zero slow permit must not reserve or enqueue"),
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_rejected, 1);
    assert_eq!(udp.queue_accepted, 0);

    let open = Arc::new(tokio::sync::Semaphore::new(1));
    match super::begin_udp_slow_path(&pool, &stats, &open, client, dst, b"follower") {
        super::UdpSlowPathWork::Done => {}
        super::UdpSlowPathWork::Initialize(_) => {
            panic!("Initializing follower must enqueue, not create a second lease")
        }
        super::UdpSlowPathWork::DnsThenMaybeInitialize { .. } => {
            panic!("non-DNS follower must not take the DNS branch")
        }
    }
    let udp = stats.udp_snapshot();
    assert_eq!(udp.slow_permit_accepted, 1);
    assert_eq!(
        udp.queue_accepted, 1,
        "with a slow permit the follower enqueues exactly once"
    );
    drop(lease);
}

#[test]
fn resolve_udp_outbound_plan_preserves_terminal_provenance() {
    let first = Node {
        id: uuid::Uuid::new_v4(),
        name: "first".into(),
        ..udp_test_node()
    };
    let second = Node {
        id: uuid::Uuid::new_v4(),
        name: "second".into(),
        ..udp_test_node()
    };
    let cold_child = Group {
        name: "cold-child".into(),
        policy: GroupPolicy::URLTest,
        nodes: vec![first.id, second.id],
        ..Default::default()
    };
    let nested_parent = Group {
        name: "nested-parent".into(),
        policy: GroupPolicy::Selector,
        groups: vec!["cold-child".into()],
        ..Default::default()
    };
    let empty_final = Group {
        name: "empty-final".into(),
        policy: GroupPolicy::Selector,
        final_outbound: Some("cold-child".into()),
        ..Default::default()
    };
    let config = udp_test_config(
        "direct",
        vec![first.clone(), second.clone()],
        vec![cold_child, nested_parent, empty_final],
    );
    let manager = GroupManager::new(&config.groups, &config.nodes);

    let direct = resolve_udp_outbound_plan(&config, &manager, "direct", IpVersion::V4);
    assert_eq!(direct.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        direct
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["direct"]
    );

    let node = resolve_udp_outbound_plan(&config, &manager, "first", IpVersion::V4);
    assert_eq!(node.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        node.nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );

    let nested = resolve_udp_outbound_plan(&config, &manager, "nested-parent", IpVersion::V4);
    assert_eq!(nested.mode, crate::group::SelectionPlanMode::Authoritative);
    assert_eq!(
        nested
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );

    let final_plan = resolve_udp_outbound_plan(&config, &manager, "empty-final", IpVersion::V4);
    assert_eq!(
        final_plan.mode,
        crate::group::SelectionPlanMode::ColdUrlTest
    );
    assert_eq!(
        final_plan
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
}

#[test]
fn resolve_udp_outbound_plan_tracks_v4_fallback_and_final_resolution_guards() {
    let v4_only = Node {
        id: uuid::Uuid::new_v4(),
        name: "v4-only".into(),
        ..udp_test_node()
    };
    let groups = vec![
        Group {
            name: "v4-group".into(),
            policy: GroupPolicy::URLTest,
            nodes: vec![v4_only.id],
            ..Default::default()
        },
        Group {
            name: "empty".into(),
            policy: GroupPolicy::Selector,
            ..Default::default()
        },
        Group {
            name: "missing-final".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("not-configured".into()),
            ..Default::default()
        },
        Group {
            name: "cycle-a".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("cycle-b".into()),
            ..Default::default()
        },
        Group {
            name: "cycle-b".into(),
            policy: GroupPolicy::Selector,
            final_outbound: Some("cycle-a".into()),
            ..Default::default()
        },
    ];
    let v4_only_id = v4_only.id;
    let config = udp_test_config("direct", vec![v4_only], groups);
    let alive = Arc::new(AliveDialerSet::new());
    alive.report_unavailable_forced(v4_only_id, ProbeDomain::DataUdp, IpVersion::V6);
    alive.report_unavailable_forced(v4_only_id, ProbeDomain::DnsUdp, IpVersion::V6);
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive));

    let v4_fallback = resolve_udp_outbound_plan(&config, &manager, "v4-group", IpVersion::V6);
    assert_eq!(
        v4_fallback.mode,
        crate::group::SelectionPlanMode::ColdUrlTest
    );
    assert_eq!(v4_fallback.ipver, IpVersion::V4);
    assert_eq!(
        v4_fallback
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["v4-only"]
    );

    let empty = resolve_udp_outbound_plan(&config, &manager, "empty", IpVersion::V4);
    assert!(empty.nodes.is_empty());
    assert_eq!(empty.mode, crate::group::SelectionPlanMode::Authoritative);

    let missing = resolve_udp_outbound_plan(&config, &manager, "missing-final", IpVersion::V4);
    assert_eq!(
        missing
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["direct"]
    );

    let cycle = resolve_udp_outbound_plan(&config, &manager, "cycle-a", IpVersion::V4);
    assert!(
        cycle.nodes.is_empty(),
        "final cycles fail closed instead of bypassing policy"
    );
}

#[test]
fn resolve_udp_outbound_plan_explicit_node_falls_back_to_v4_through_final() {
    let node = Node {
        id: uuid::Uuid::new_v4(),
        name: "v4-explicit".into(),
        ..udp_test_node()
    };
    let final_group = Group {
        name: "final-to-explicit".into(),
        policy: GroupPolicy::Selector,
        final_outbound: Some(node.name.clone()),
        ..Default::default()
    };
    let node_id = node.id;
    let config = udp_test_config("direct", vec![node], vec![final_group]);
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(node_id, domain, IpVersion::V6);
    }
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive.clone()));

    for outbound in ["v4-explicit", "final-to-explicit"] {
        let plan = resolve_udp_outbound_plan(&config, &manager, outbound, IpVersion::V6);
        assert_eq!(plan.mode, crate::group::SelectionPlanMode::Authoritative);
        assert_eq!(plan.ipver, IpVersion::V4, "{outbound}");
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["v4-explicit"],
            "{outbound}"
        );
    }

    for outbound in ["direct", "block"] {
        let plan = resolve_udp_outbound_plan(&config, &manager, outbound, IpVersion::V6);
        assert_eq!(plan.ipver, IpVersion::V6, "{outbound}");
        assert_eq!(
            plan.nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [outbound]
        );
    }

    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(node_id, domain, IpVersion::V4);
    }
    for outbound in ["v4-explicit", "final-to-explicit"] {
        assert!(
            resolve_udp_outbound_plan(&config, &manager, outbound, IpVersion::V6)
                .nodes
                .is_empty(),
            "{outbound} must stay empty when neither family is selectable"
        );
    }
}

#[test]
fn resolve_udp_outbound_plan_excludes_unselectable_explicit_node() {
    let node = udp_test_node();
    let config = udp_test_config("udp-test", vec![node], vec![]);
    let alive = Arc::new(AliveDialerSet::new());
    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        alive.report_unavailable_forced(udp_test_node().id, domain, IpVersion::V4);
    }
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive));

    let plan = resolve_udp_outbound_plan(&config, &manager, "udp-test", IpVersion::V4);

    assert!(plan.nodes.is_empty());
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_uses_absolute_offsets_bounds_inflight_and_drains_losers() {
    let start = tokio::time::Instant::now();
    let starts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release_first = Arc::new(tokio::sync::Notify::new());
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let starts = starts.clone();
        let active = active.clone();
        let max_active = max_active.clone();
        let release_first = release_first.clone();
        Arc::new(move |node: Node| {
            let starts = starts.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            let release_first = release_first.clone();
            Box::pin(async move {
                let now_active = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                max_active.fetch_max(now_active, std::sync::atomic::Ordering::SeqCst);
                starts.lock().unwrap().push((
                    node.name.clone(),
                    tokio::time::Instant::now().duration_since(start),
                ));
                match node.name.as_str() {
                    "first-error" => {
                        release_first.notified().await;
                        active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Err(anyhow::anyhow!("scripted dial error"))
                    }
                    "winner" => {
                        active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(node.name)
                    }
                    _ => std::future::pending::<anyhow::Result<String>>().await,
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = [
        "first-error",
        "loser-1",
        "loser-2",
        "winner",
        "never-started",
    ]
    .into_iter()
    .map(|name| Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        ..udp_test_node()
    })
    .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(80)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        starts
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["first-error", "loser-1", "loser-2"],
        "the fourth offset passed, but max-three in-flight blocks its start"
    );

    release_first.notify_one();
    let (winner, _) = task
        .await
        .unwrap()
        .expect("the first successful preparation wins");
    assert_eq!(winner.name, "winner");
    let starts = starts.lock().unwrap();
    assert_eq!(
        starts
            .iter()
            .map(|(name, offset)| (name.as_str(), *offset))
            .collect::<Vec<_>>(),
        [
            ("first-error", Duration::ZERO),
            ("loser-1", Duration::from_millis(30)),
            ("loser-2", Duration::from_millis(80)),
            ("winner", Duration::from_millis(160)),
        ]
    );
    assert_eq!(max_active.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert_eq!(
        errors.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only a real dial Err changes health"
    );
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        cancellations.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "only started losers are cancelled"
    );
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_drain_reports_completed_error_without_cancelling_ready_losers() {
    let release = Arc::new(tokio::sync::Notify::new());
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let release = release.clone();
        Arc::new(move |node: Node| {
            let release = release.clone();
            Box::pin(async move {
                release.notified().await;
                match node.name.as_str() {
                    "winner" => Ok(node.name),
                    "completed-error" => Err(anyhow::anyhow!("scripted dial error")),
                    "completed-ok" => Ok(node.name),
                    _ => unreachable!(),
                }
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["winner", "completed-error", "completed-ok"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        prepare,
        callbacks,
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);

    release.notify_waiters();
    let (winner, _) = task
        .await
        .unwrap()
        .expect("the first completed success should win");
    assert_eq!(winner.name, "winner");
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_authoritative_prepares_only_the_current_node_without_delay() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = Arc::new(|node: Node| Box::pin(async move { Ok(node.name) }));
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: Arc::new(|_| panic!("authoritative success must not report an error")),
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["authoritative", "must-not-start"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();

    let (winner, _) = prepare_udp_plan(
        crate::group::SelectionPlanMode::Authoritative,
        candidates,
        prepare,
        callbacks,
    )
    .await
    .expect("authoritative candidate should start at offset zero");
    assert_eq!(winner.name, "authoritative");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_authoritative_failure_preserves_fixed_metric_zeros() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<()> =
        Arc::new(|_: Node| Box::pin(async { Err(anyhow::anyhow!("dial failed")) }));
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: {
            let winners = winners.clone();
            Arc::new(move || {
                winners.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = vec![Node {
        id: uuid::Uuid::new_v4(),
        name: "authoritative-failure".into(),
        ..udp_test_node()
    }];

    assert!(
        prepare_udp_plan(
            crate::group::SelectionPlanMode::Authoritative,
            candidates,
            prepare,
            callbacks,
        )
        .await
        .is_none()
    );
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(winners.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_all_dial_failures_report_health_without_cancellation() {
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<()> =
        Arc::new(|_: Node| Box::pin(async { Err(anyhow::anyhow!("dial failed")) }));
    let callbacks = UdpStaggerCallbacks {
        is_eligible: Arc::new(|_| true),
        on_dial_error: {
            let errors = errors.clone();
            Arc::new(move |_| {
                errors.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: {
            let cancellations = cancellations.clone();
            Arc::new(move || {
                cancellations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
    };
    let candidates = ["first", "second"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    assert!(task.await.unwrap().is_none());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(errors.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn udp_stagger_rechecks_eligibility_before_accepting_prepared_transport() {
    let became_ineligible = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let prepare: UdpPrepare<String> = {
        let became_ineligible = became_ineligible.clone();
        Arc::new(move |node: Node| {
            let became_ineligible = became_ineligible.clone();
            Box::pin(async move {
                if node.name == "became-ineligible" {
                    became_ineligible.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(node.name)
            })
        })
    };
    let callbacks = UdpStaggerCallbacks {
        is_eligible: {
            let became_ineligible = became_ineligible.clone();
            Arc::new(move |node| {
                node.name != "became-ineligible"
                    || !became_ineligible.load(std::sync::atomic::Ordering::SeqCst)
            })
        },
        on_dial_error: Arc::new(|_| panic!("prepared success is not a dial error")),
        on_attempt: {
            let attempts = attempts.clone();
            Arc::new(move || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        on_winner: Arc::new(|| {}),
        on_cancellation: Arc::new(|| {}),
    };
    let candidates = ["became-ineligible", "eligible-winner"]
        .into_iter()
        .map(|name| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            ..udp_test_node()
        })
        .collect();
    let task = tokio::spawn(prepare_udp_plan(
        crate::group::SelectionPlanMode::ColdUrlTest,
        candidates,
        prepare,
        callbacks,
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(30)).await;
    let (winner, _) = task
        .await
        .unwrap()
        .expect("eligible candidate should still win");
    assert_eq!(winner.name, "eligible-winner");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
}

fn preconnect_test_node(name: &str, protocol: NodeProtocol) -> Node {
    Node {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        protocol,
        address: format!("{name}.example.com:443"),
        ..Default::default()
    }
}

fn preconnect_test_group(name: &str, policy: GroupPolicy, ids: Vec<uuid::Uuid>) -> Group {
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
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn preconnect_candidates_zero_disables_and_eligibility_is_descriptor_driven() {
    let anytls = preconnect_test_node("anytls", NodeProtocol::AnyTLS);
    let ss = preconnect_test_node("ss", NodeProtocol::SS);
    let tuic = preconnect_test_node("tuic", NodeProtocol::Tuic);
    let trojan = preconnect_test_node("trojan", NodeProtocol::Trojan);
    let hy2 = preconnect_test_node("hy2", NodeProtocol::Hysteria2);
    let direct = preconnect_test_node("direct", NodeProtocol::Direct);
    let block = preconnect_test_node("block", NodeProtocol::Block);
    let nodes = vec![anytls, ss.clone(), tuic, trojan.clone(), hy2, direct, block];
    let config = Config {
        nodes,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    assert!(preconnect_candidates(&config, &manager, 0).is_empty());

    let picked = preconnect_candidates(
        &config,
        &manager,
        honk_config::config::PRECONNECT_NODE_COUNT_AUTO,
    );
    assert_eq!(
        picked.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        vec!["ss", "trojan"],
        "AnyTLS/QUIC can never consume a pooled bare TCP; built-ins have no server"
    );
}

#[test]
fn preconnect_candidates_prefer_group_selections_then_config_order() {
    let ss = preconnect_test_node("ss", NodeProtocol::SS);
    let trojan = preconnect_test_node("trojan", NodeProtocol::Trojan);
    let vmess = preconnect_test_node("vmess", NodeProtocol::VMess);
    let config = Config {
        nodes: vec![ss, trojan.clone(), vmess],
        groups: vec![preconnect_test_group(
            "g",
            GroupPolicy::Selector,
            vec![trojan.id],
        )],
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    let picked = preconnect_candidates(&config, &manager, 8);
    assert_eq!(
        picked.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        vec!["trojan", "ss", "vmess"],
        "the group's current pick leads; config order fills the rest"
    );
}

#[test]
fn preconnect_candidates_auto_caps_at_eight() {
    let nodes: Vec<_> = (0..12)
        .map(|i| preconnect_test_node(&format!("ss-{i}"), NodeProtocol::SS))
        .collect();
    let config = Config {
        nodes,
        ..Default::default()
    };
    let manager = GroupManager::new(&config.groups, &config.nodes);

    assert_eq!(
        preconnect_candidates(
            &config,
            &manager,
            honk_config::config::PRECONNECT_NODE_COUNT_AUTO
        )
        .len(),
        8
    );
    assert_eq!(
        preconnect_candidates(&config, &manager, 3).len(),
        3,
        "an explicit count smaller than the eligible set is honored"
    );
}

#[test]
fn probe_warm_runtime_reuses_only_warm_or_stateless_nodes() {
    let anytls = Node {
        id: uuid::Uuid::new_v4(),
        name: "anytls".into(),
        protocol: NodeProtocol::AnyTLS,
        address: "anytls.example.com:443".into(),
        ..Default::default()
    };
    let trojan = Node {
        id: uuid::Uuid::new_v4(),
        name: "trojan".into(),
        protocol: NodeProtocol::Trojan,
        address: "trojan.example.com:443".into(),
        ..Default::default()
    };
    let absent = Node {
        id: uuid::Uuid::new_v4(),
        name: "absent".into(),
        protocol: NodeProtocol::SS,
        address: "absent.example.com:443".into(),
        ..Default::default()
    };
    let generation =
        honk_outbound::runtime::OutboundRuntimeRegistry::build(&[anytls.clone(), trojan.clone()])
            .unwrap();

    assert!(
        probers::warm_runtime(&generation, &anytls).is_none(),
        "a cold AnyTLS node probes through an ephemeral runtime"
    );
    assert!(
        probers::warm_runtime(&generation, &absent).is_none(),
        "a node outside the generation probes ephemerally"
    );
    assert!(
        probers::warm_runtime(&generation, &trojan).is_some(),
        "a session-less protocol has nothing to retain; reuse the generation runtime"
    );
}

fn link_lifecycle_cp(backend: crate::ebpf::mock::MockEbpfBackend) -> ControlPlane {
    ControlPlane::new(
        Config::default(),
        Box::new(backend),
        Router::new(&[], "direct").unwrap(),
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
}

/// Reload and subscription merge share `apply_runtime_config`, which only
/// rewrites maps through the live backend — datapath hooks must never be
/// detached or re-attached outside shutdown.
#[tokio::test]
async fn reload_and_merge_never_touch_ebpf_hooks() {
    use std::sync::atomic::Ordering;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let detach = backend.detach_calls.clone();
    let dyn_attach = backend.dynamic_attach_calls.clone();
    let dyn_forget = backend.dynamic_forget_calls.clone();
    let cp = link_lifecycle_cp(backend);

    let drain = DrainTracker::new();
    assert!(cp.apply_runtime_config(Config::default(), &drain).await);
    assert!(cp.apply_runtime_config(Config::default(), &drain).await);

    assert_eq!(
        detach.load(Ordering::Relaxed),
        0,
        "reload/merge must never detach datapath hooks"
    );
    assert_eq!(dyn_attach.load(Ordering::Relaxed), 0);
    assert_eq!(dyn_forget.load(Ordering::Relaxed), 0);
}

/// Shutdown with a flow that never finishes must still detach the hooks and
/// return in bounded time (the drain tracker caps the wait).
#[tokio::test]
async fn shutdown_detaches_hooks_and_stays_bounded_with_stuck_flow() {
    use std::sync::atomic::Ordering;
    let backend = crate::ebpf::mock::MockEbpfBackend::new();
    let detach = backend.detach_calls.clone();
    let mut cp = link_lifecycle_cp(backend);

    // A flow that never finishes: the drain tracker must cap the wait.
    cp.drain_tracker.increment();
    let drain = cp.drain_tracker.clone();
    let mut removal_task = tokio::spawn(async {});

    tokio::time::timeout(Duration::from_secs(30), async {
        cp.shutdown_datapath(&drain, &mut removal_task, None)
            .await
            .unwrap();
        cp.finalize_shutdown().await.unwrap();
    })
    .await
    .expect("shutdown must stay bounded with a stuck flow");
    assert!(
        detach.load(Ordering::Relaxed) >= 1,
        "shutdown must detach the datapath hooks"
    );
}

fn offload_flags_test_plane(
    config: Config,
) -> (ControlPlane, std::sync::Arc<std::sync::Mutex<Vec<u32>>>) {
    let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut backend = crate::ebpf::mock::MockEbpfBackend::new();
    backend.datapath_flags_writes = writes.clone();
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let plane = ControlPlane::new(
        config,
        Box::new(backend),
        router,
        Arc::new(ProxyRegistry::default_resolver().unwrap()),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    (plane, writes)
}

fn domain_rule(outbound: &str) -> honk_config::routing::RoutingRule {
    honk_config::routing::RoutingRule {
        name: "domain-rule".into(),
        condition: honk_config::routing::RoutingCondition {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        },
        outbound: honk_config::routing::RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

#[tokio::test]
async fn sync_direct_offload_flags_composes_mode_and_static_bits() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_ALL as ALL, DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES as NO_DOMAIN,
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
    };

    // dial_mode ip: the static bit is set even with domain rules present —
    // sniffing is disabled, so no domain re-evaluation can ever happen.
    let mut config = udp_test_config("direct", vec![], vec![]);
    config.global.dial_mode = "ip".into();
    config.routing.rules = vec![domain_rule("direct")];
    let (mut plane, writes) = offload_flags_test_plane(config);

    // No mode state (clash API disabled) behaves as Rule.
    plane.sync_direct_offload_flags().await;
    plane.set_mode_state(std::sync::Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("global", "proxy"),
    )));
    plane.sync_direct_offload_flags().await;
    plane.set_mode_state(std::sync::Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("direct", "proxy"),
    )));
    plane.sync_direct_offload_flags().await;
    plane.set_mode_state(std::sync::Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("rule", "proxy"),
    )));
    plane.sync_direct_offload_flags().await;
    assert_eq!(
        writes.lock().unwrap().clone(),
        vec![
            RULE | NO_DOMAIN,
            NO_DOMAIN,
            ALL | NO_DOMAIN,
            RULE | NO_DOMAIN
        ]
    );

    // dial_mode domain++ with a domain rule: the static bit stays clear, so
    // Rule-mode offload remains constrained by per-flow DomainRouting hits.
    let mut config = udp_test_config("direct", vec![], vec![]);
    config.global.dial_mode = "domain++".into();
    config.routing.rules = vec![domain_rule("direct")];
    let (plane, writes) = offload_flags_test_plane(config);
    plane.sync_direct_offload_flags().await;
    assert_eq!(writes.lock().unwrap().clone(), vec![RULE]);

    // dial_mode domain++ without any domain-class rule: sniffing cannot
    // change routing, so the static bit is set.
    let mut config = udp_test_config("direct", vec![], vec![]);
    config.global.dial_mode = "domain++".into();
    let (plane, writes) = offload_flags_test_plane(config);
    plane.sync_direct_offload_flags().await;
    assert_eq!(writes.lock().unwrap().clone(), vec![RULE | NO_DOMAIN]);
}

/// A reload re-asserts the datapath offload flags and recomputes the static
/// bit from the NEW config (dial_mode / domain rules), not the old one.
#[tokio::test]
async fn reload_reasserts_and_recomputes_datapath_offload_flags() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_OFFLOAD_NO_DOMAIN_RULES as NO_DOMAIN,
        DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
    };

    let mut config = udp_test_config("direct", vec![], vec![]);
    config.global.dial_mode = "domain++".into();
    config.routing.rules = vec![domain_rule("direct")];
    let (plane, writes) = offload_flags_test_plane(config);

    let mut new_config = udp_test_config("direct", vec![], vec![]);
    new_config.global.dial_mode = "ip".into();
    new_config.routing.rules = vec![domain_rule("direct")];
    assert!(
        plane
            .apply_runtime_config(new_config, &DrainTracker::new())
            .await
    );

    // dial_mode switched to ip: the static bit is now set even though the
    // domain rule survived the reload.
    assert_eq!(
        writes.lock().unwrap().clone(),
        vec![RULE | NO_DOMAIN],
        "reload must re-assert the flags recomputed from the new config"
    );
    assert_eq!(
        plane
            .direct_offload_static_handle()
            .load(std::sync::atomic::Ordering::Relaxed),
        NO_DOMAIN
    );
}
