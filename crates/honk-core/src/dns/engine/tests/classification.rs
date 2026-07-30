#[test]
fn classifies_positive_nodata_nxdomain_and_servfail_responses() {
    // Given
    let positive = [0_u8, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    let nodata = [0_u8, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    let nxdomain = [0_u8, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
    let servfail = [0_u8, 0, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0];

    // When / Then
    assert_eq!(classify_response(&positive), ResponseClass::Positive);
    assert_eq!(classify_response(&nodata), ResponseClass::Nodata);
    assert_eq!(classify_response(&nxdomain), ResponseClass::Nxdomain);
    assert_eq!(classify_response(&servfail), ResponseClass::Servfail);
}

#[tokio::test]
async fn real_forwarding_paths_classify_each_response() {
    let query = build_dns_query("example.com", 1);
    let positive = response(&query, [192, 0, 2, 1], 30);
    let nodata = nodata_response(&query);
    let mut nxdomain = nodata.clone();
    nxdomain[3] = 0x83;
    let mut servfail = nodata.clone();
    servfail[3] = 0x82;

    for (wire, class) in [
        (positive, ResponseClass::Positive),
        (nodata, ResponseClass::Nodata),
        (nxdomain, ResponseClass::Nxdomain),
        (servfail, ResponseClass::Servfail),
    ] {
        let forwarder = DnsForwarder::new(
            exchange([("first", Ok(wire))], None),
            Arc::new(Mutex::new(DnsCache::new(8))),
            router("first", Vec::new(), None),
        );
        let outcome = forwarder.resolve_outcome(&query).await.expect("outcome");
        assert_eq!(outcome.response_class(), class);
    }
}

#[test]
fn fixed_zero_disables_cache_instead_of_clamping_to_one() {
    // Given / When
    let expiry = effective_expiry(Some(0), 600, 30);

    // Then
    assert!(!expiry.is_cacheable());
}
