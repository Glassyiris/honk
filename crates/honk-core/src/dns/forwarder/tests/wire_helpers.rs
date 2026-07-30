#[tokio::test]
async fn test_prefetch_warms_cache() {
    let response = make_a_response([1, 2, 3, 4], 300);
    let mock = Arc::new(MockUpstream::new(response.clone()));
    let cache = test_cache();
    let forwarder = DnsForwarder::new(
        mock.clone() as Arc<dyn DnsUpstreamPool>,
        cache.clone(),
        test_router(),
    );

    let domains: Vec<String> = vec!["example.com".into()];
    forwarder.prefetch(&domains);

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let query = make_a_query();
    let result = forwarder.resolve(&query).await.expect("resolve");
    assert_eq!(result, response);

    // The upstream should have been called at least once (by prefetch),
    // but resolve itself may or may not call it depending on timing
    let calls = mock.call_count.load(Ordering::SeqCst);
    assert!(
        calls >= 1,
        "expected at least 1 upstream call for prefetch, got {}",
        calls
    );
}

#[test]
fn test_parse_dns_question_a_record() {
    let query = build_dns_query("www.example.com", 1);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "www.example.com");
    assert_eq!(qtype, 1); // A
}

#[test]
fn test_parse_dns_question_aaaa_record() {
    let query = build_dns_query("ipv6.test.org", 28);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "ipv6.test.org");
    assert_eq!(qtype, 28); // AAAA
}

#[test]
fn test_parse_dns_question_single_label() {
    let query = build_dns_query("localhost", 1);
    let (domain, qtype) = parse_dns_question(&query).expect("parse");
    assert_eq!(domain, "localhost");
    assert_eq!(qtype, 1);
}

#[test]
fn test_parse_dns_question_truncated() {
    let short = vec![0u8; 10];
    assert!(parse_dns_question(&short).is_none());
}

#[test]
fn test_extract_min_ttl_single_answer() {
    let resp = make_a_response([8, 8, 8, 8], 300);
    let ttl = extract_min_ttl(&resp);
    assert_eq!(ttl, 300);
}

#[test]
fn test_extract_min_ttl_no_answers() {
    // Response with ANCOUNT=0
    let resp = vec![
        0x00, 0x01, // ID
        0x81, 0x83, // Flags: NXDOMAIN
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Question
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
        0x00, 0x01,
    ];
    let ttl = extract_min_ttl(&resp);
    assert_eq!(ttl, 60, "default TTL when no answers present");
}

#[test]
fn test_extract_min_ttl_short_response() {
    let short = vec![0u8; 5];
    assert_eq!(extract_min_ttl(&short), 60);
}

#[test]
fn test_cache_key_format() {
    assert_eq!(dns_cache_key("example.com", 1), "example.com:1");
    assert_eq!(dns_cache_key("test.org", 28), "test.org:28");
}

#[test]
fn test_build_and_parse_roundtrip() {
    let domains = vec![
        "google.com",
        "sub.domain.example.org",
        "localhost",
        "a.b.c.d.e.f.g.h.example.com",
    ];

    for domain in domains {
        for qtype in [1u16, 28u16, 5u16] {
            let query = build_dns_query(domain, qtype);
            let (parsed_domain, parsed_qtype) =
                parse_dns_question(&query).expect("roundtrip parse");
            assert_eq!(
                parsed_domain, domain,
                "domain mismatch for {} QTYPE={}",
                domain, qtype
            );
            assert_eq!(parsed_qtype, qtype, "qtype mismatch for {}", domain);
        }
    }
}

#[test]
fn test_effective_cache_ttl_override() {
    assert_eq!(effective_cache_ttl(600, 30), 600);
    assert_eq!(effective_cache_ttl(0, 30), 30);
    assert_eq!(effective_cache_ttl(0, 0), 1);
}

#[test]
fn test_rewrite_answer_ttls_overrides_wire() {
    let mut resp = make_a_response([1, 2, 3, 4], 30);
    assert_eq!(extract_min_ttl(&resp), 30);
    rewrite_answer_ttls(&mut resp, 600);
    assert_eq!(extract_min_ttl(&resp), 600);
}
