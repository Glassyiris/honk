use super::*;

#[test]
fn query_parameters_reject_semantic_duplicates_and_name_wire_overflow() {
    let id = RequestId("dns-test".into());
    for query in [
        "type=A&type=TYPE1",
        "type=1&type=A",
        "domain=a&domain=b",
        "type=A&unknown=x",
    ] {
        let uri: Uri = format!("/api/v1/dns/query?{query}").parse().unwrap();
        assert!(parameters(&uri, &["domain", "type"], &id).is_err());
    }
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert!(validate_name(&maximum));
    assert!(!validate_name(&format!("{maximum}x")));
    assert!(!validate_name(&format!("{}.example", "x".repeat(64))));
    assert!(!validate_name("example..com"));
    assert!(!validate_name("example.com.."));
    assert_eq!(canonical_name("EXAMPLE.Com.", &id).unwrap(), "example.com.");
}

#[tokio::test]
async fn cache_snapshot_filters_before_budget_admission_and_freezes_selected_pages() {
    use crate::dns::cache::{CacheInvalidation, CacheKey, OperationKind};
    use crate::dns::forwarder::build_dns_query;
    use crate::dns::planner::RequestScope;
    use crate::dns::query::QueryContext;

    let mut config = honk_config::Config::default();
    config.dns.cache.max_size = 8192;
    let state = dns_state(config).await;
    let service = state.dns.cache().lock().await.service();
    let scope = RequestScope::Upstream(UpstreamTag::new("default").unwrap());
    for index in 0..320 {
        let mut response = build_dns_query(&format!("bulk-{index}.example"), 16);
        let key = CacheKey::new(
            &QueryContext::parse(&response).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 1, 44]);
        response.extend_from_slice(&32768u16.to_be_bytes());
        for _ in 0..128 {
            response.push(255);
            response.extend_from_slice(&[b'x'; 255]);
        }
        service.put_exact(key, response, 300, None);
    }
    let mut expected_ids = Vec::new();
    for ingress in [IngressProfile::Internal, IngressProfile::Tcp] {
        let mut response = build_dns_query("Selected.Example", 1);
        let key = CacheKey::new(
            &QueryContext::parse_with_profile(&response, ingress).unwrap(),
            None,
            scope.clone(),
            OperationKind::Resolve,
        );
        response[2..4].copy_from_slice(&[0x81, 0x80]);
        service.put_exact(key.clone(), response, 300, None);
        expected_ids.push(service.entry_id(&key).unwrap());
    }
    expected_ids.sort();

    for query in ["", "?type=TXT"] {
        assert_eq!(
            cache_page(&state, query).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    for query in ["?name=missing.example", "?domain=missing", "?type=AAAA"] {
        let (status, page) = cache_page(&state, query).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["total"], 0);
        assert_eq!(page["entries"], json!([]));
    }

    let filters = "?name=SELECTED.Example.&domain=LECTED.EXA&type=TYPE1&limit=1";
    let (status, first) = cache_page(&state, filters).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["total"], 2);
    assert_eq!(
        first["usage"],
        json!({"entries":"322","entry_capacity":"8192"})
    );
    assert_eq!(first["entries"][0]["entry_id"], expected_ids[0]);
    assert_eq!(first["entries"][0]["type"], "A");
    let cursor = first["next_cursor"].as_str().unwrap();
    service.invalidate(CacheInvalidation::All).await.unwrap();
    let (status, second) = cache_page(&state, &format!("{filters}&cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["total"], 2);
    assert_eq!(second["entries"][0]["entry_id"], expected_ids[1]);
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["usage"], first["usage"]);
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        cache_page(
            &state,
            &format!("?name=selected.example&type=AAAA&cursor={cursor}")
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

async fn cache_page(state: &NativeState, query: &str) -> (StatusCode, Value) {
    let uri = format!("/api/v1/dns/cache{query}").parse().unwrap();
    let response = cache(state, &uri, &RequestId("cache-test".into()))
        .await
        .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn dns_state(mut config: honk_config::Config) -> NativeState {
    use std::sync::Arc;
    use std::time::Instant;

    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;
    config.ensure_builtin_nodes();
    let resolver = crate::dns::DnsResolver::new(&config.dns).unwrap();
    let forwarder = resolver.forwarder();
    let mut control = crate::control::ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        crate::routing::Router::new(&[], "direct").unwrap(),
        Arc::new(crate::proxy::ProxyRegistry::default_resolver().unwrap()),
        resolver,
        forwarder,
    )
    .unwrap();
    let state = NativeState::new(
        &mut control,
        "127.0.0.1:9527".parse().unwrap(),
        SystemTime::now(),
        Instant::now(),
    )
    .await
    .unwrap();
    control.publish_phase(crate::control::EnginePhase::Running);
    state
}

#[tokio::test]
async fn root_query_replays_lists_and_invalidates_only_root() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mut upstream = tokio::task::JoinSet::new();
    upstream.spawn(async move {
        for name in [".", "ordinary.example."] {
            let mut wire = [0u8; 512];
            let (length, peer) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
                    .await
                    .unwrap()
                    .unwrap();
            let question = records::question(&wire[..length], IngressProfile::Api).unwrap();
            assert_eq!(question.name, name);
            assert_eq!(question.rtype, "NS");
            if name == "." {
                assert_eq!(&wire[12..length], &[0, 0, 2, 0, 1]);
            }
            let mut response = wire[..length].to_vec();
            response[2..4].copy_from_slice(&[0x81, 0x80]);
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 1, 44, 0, 12]);
            response.extend_from_slice(b"\x02ns\x07example\0");
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut config = honk_config::Config::default();
    config.dns.cache.ttl = 0;
    config.dns.upstream = vec![honk_config::dns::DnsUpstream {
        name: "default".into(),
        address: address.to_string(),
        protocol: honk_config::types::DnsProtocol::Udp,
        tls_server_name: None,
        outbound: None,
    }];
    let state = dns_state(config).await;
    let id = RequestId("root-dns".into());
    for name in ["", "..", "ordinary..example"] {
        let uri = format!("/api/v1/dns/query?domain={name}&type=NS")
            .parse()
            .unwrap();
        let response = query(&state, &uri, &id)
            .await
            .unwrap_or_else(IntoResponse::into_response);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut root_entry = Value::Null;
    for (name, expected, cached) in [
        (".", ".", false),
        (".", ".", true),
        ("OrDiNaRy.Example.", "ordinary.example.", false),
        ("ordinary.example", "ordinary.example.", true),
    ] {
        let uri = format!("/api/v1/dns/query?domain={name}&type=NS&detail=full")
            .parse()
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), query(&state, &uri, &id))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["domain"], expected);
        let result = &value["results"][0];
        assert_eq!(
            result["question"],
            json!({"name":expected,"type":"NS","class":"IN"})
        );
        assert_eq!(result["status"], "NOERROR");
        assert_eq!(result["cached"], cached);
        assert_eq!(
            result["upstream"],
            if cached {
                Value::Null
            } else {
                json!("default")
            }
        );
        assert_eq!(result["answers"].as_array().unwrap().len(), 1);
        let answer = &result["answers"][0];
        assert_eq!(answer["name"], expected);
        assert_eq!(answer["type"], "NS");
        assert_eq!(answer["class"], "IN");
        assert_eq!(answer["data"], "ns.example.");
        assert!((1..=300).contains(&answer["ttl"].as_u64().unwrap()));
        if expected == "." {
            if cached {
                assert_eq!(result["cache_entry_id"], root_entry);
            } else {
                assert!(result["cache_entry_id"].is_string());
                root_entry = result["cache_entry_id"].clone();
            }
        }
    }
    upstream.join_next().await.unwrap().unwrap();

    let (status, page) = cache_page(&state, "?name=.&type=NS&detail=full").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 1);
    assert_eq!(page["entries"][0]["entry_id"], root_entry);
    assert_eq!(page["entries"][0]["domain"], ".");
    assert_eq!(page["entries"][0]["answers"][0]["name"], ".");
    assert_eq!(page["entries"][0]["answers"][0]["data"], "ns.example.");
    for (kind, deleted) in [("A", 0), ("NS", 1)] {
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/dns/cache?name=.&type={kind}"))
            .body(Body::empty())
            .unwrap();
        let response = delete_name(&state, request, &id).await.unwrap();
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"matched":deleted,"deleted":deleted}),
        );
    }
    let (status, page) = cache_page(&state, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["total"], 1);
    assert_eq!(page["entries"][0]["domain"], "ordinary.example.");
    assert_eq!(cache_page(&state, "?name=.").await.1["total"], 0);
    state.dns.provider().unwrap().shutdown().await;
}
