#[tokio::test]
async fn test_response_requery_stops_at_depth_limit() {
    use honk_config::dns::{
        DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
        DnsResponseRule,
    };

    struct RecordingUpstream {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsUpstreamPool for RecordingUpstream {
        async fn query(&self, upstream_name: &str, _raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.calls.lock().unwrap().push(upstream_name.to_string());
            let last_octet = match upstream_name {
                "default" => 1,
                "one" => 2,
                "two" => 3,
                "three" => 4,
                _ => 255,
            };
            Ok(make_a_response([192, 0, 2, last_octet], 60))
        }
    }

    let response_rules = [("default", "one"), ("one", "two"), ("two", "three")]
        .into_iter()
        .map(|(from, to)| DnsResponseRule {
            conditions: vec![DnsCond::Upstream {
                not: false,
                names: vec![from.to_string()],
            }],
            action: DnsResponseAction::Upstream(to.to_string()),
        })
        .collect();
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![],
                fallback: DnsRequestAction::Upstream("default".into()),
            },
            response: DnsResponseRouting {
                rules: response_rules,
                fallback: DnsResponseAction::Accept,
            },
            ..Default::default()
        })
        .unwrap(),
    );
    let upstream = Arc::new(RecordingUpstream {
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let forwarder = DnsForwarder::new(upstream.clone(), test_cache(), router);

    let response = forwarder.resolve(&make_a_query()).await.unwrap();

    assert_eq!(
        upstream.calls.lock().unwrap().as_slice(),
        ["default", "one", "two"],
        "depth three is accepted without issuing a fourth exchange"
    );
    assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 3]);
}

#[tokio::test]
async fn test_asis_uses_original_destination() {
    use honk_config::dns::{DnsRequestAction, DnsRequestRouting};

    let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let original_dst = socket.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut request = vec![0u8; 512];
        let (size, peer) = socket.recv_from(&mut request).await.unwrap();
        request.truncate(size);
        let mut response = make_a_response([203, 0, 113, 7], 60);
        response[0..2].copy_from_slice(&request[0..2]);
        socket.send_to(&response, peer).await.unwrap();
    });
    let router = Arc::new(
        DnsRouter::new(&DnsRouting {
            request: DnsRequestRouting {
                rules: vec![],
                fallback: DnsRequestAction::AsIs,
            },
            ..Default::default()
        })
        .unwrap(),
    );
    let forwarder = DnsForwarder::new(Arc::new(FailUpstream), test_cache(), router);
    let query = make_a_query();

    let response = forwarder
        .resolve_with_context(&query, Some(original_dst))
        .await
        .unwrap();
    responder.await.unwrap();

    assert_eq!(&response[0..2], &query[0..2]);
    assert_eq!(&response[response.len() - 4..], &[203, 0, 113, 7]);
}

#[tokio::test]
async fn test_fixed_domain_ttl_zero_skips_cache() {
    use std::collections::HashMap;

    let response = make_a_response([1, 2, 3, 4], 300);
    let mock = Arc::new(MockUpstream::new(response));
    let cache = test_cache();
    let mut ttl = HashMap::new();
    ttl.insert("example.com".to_string(), 0u32);
    let router = Arc::new(DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &ttl).unwrap());
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        cache.clone(),
        router,
    );

    let query = make_a_query();
    let _ = forwarder.resolve(&query).await.unwrap();
    assert!(
        cache.lock().await.get("example.com:1").is_none(),
        "fixed_domain_ttl=0 must not cache"
    );
    // Second resolve hits upstream again.
    let _ = forwarder.resolve(&query).await.unwrap();
    assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
}

#[test]
fn test_extract_answer_ips_a_record() {
    let resp = make_a_response([1, 2, 3, 4], 60);
    let ips = extract_answer_ips(&resp);
    assert_eq!(ips, vec![IpAddr::from([1, 2, 3, 4])]);
}

/// Build an AAAA-record response for example.com with a given IPv6 and TTL.
fn make_aaaa_response(ip: [u8; 16], ttl: u32) -> Vec<u8> {
    let ttl_bytes = ttl.to_be_bytes();
    let mut v = vec![
        0x00,
        0x00, // ID
        0x81,
        0x80, // Flags: QR=1, RD=1, RA=1
        0x00,
        0x01, // QDCOUNT
        0x00,
        0x01, // ANCOUNT
        0x00,
        0x00, // NSCOUNT
        0x00,
        0x00, // ARCOUNT
        // Question: example.com AAAA IN
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
        0x1c, // QTYPE AAAA
        0x00,
        0x01, // QCLASS IN
        // Answer
        0xc0,
        0x0c, // NAME pointer to offset 12
        0x00,
        0x1c, // TYPE AAAA
        0x00,
        0x01, // CLASS IN
        ttl_bytes[0],
        ttl_bytes[1],
        ttl_bytes[2],
        ttl_bytes[3], // TTL
        0x00,
        0x10, // RDLENGTH 16
    ];
    v.extend_from_slice(&ip);
    v
}

fn nodata_response(domain: &str, qtype: u16) -> Vec<u8> {
    make_empty_response(&build_dns_query(domain, qtype), domain, qtype)
}

fn answer_count(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// Mock upstream answering per query qtype.
struct QtypeMock {
    a: Vec<u8>,
    aaaa: Vec<u8>,
    call_count: AtomicUsize,
}

#[async_trait]
impl DnsUpstreamPool for QtypeMock {
    async fn query(&self, _upstream_name: &str, raw_query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let (domain, qtype) = parse_dns_question(raw_query).expect("question");
        Ok(match qtype {
            1 => self.a.clone(),
            28 => self.aaaa.clone(),
            _ => make_empty_response(raw_query, &domain, qtype),
        })
    }
}

fn qtype_mock(a: Vec<u8>, aaaa: Vec<u8>) -> Arc<QtypeMock> {
    Arc::new(QtypeMock {
        a,
        aaaa,
        call_count: AtomicUsize::new(0),
    })
}

const TEST_V6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
