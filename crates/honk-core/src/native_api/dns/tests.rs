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
    for name in [".", "example.com."] {
        let query = crate::dns::forwarder::build_dns_query(name, 1);
        assert!(crate::dns::query::QueryContext::parse(&query).is_ok());
    }
}

#[tokio::test]
async fn cache_snapshot_filters_before_budget_admission_and_freezes_selected_pages() {
    use std::sync::Arc;
    use std::time::Instant;

    use crate::dns::cache::{CacheInvalidation, CacheKey, OperationKind};
    use crate::dns::forwarder::build_dns_query;
    use crate::dns::planner::RequestScope;
    use crate::dns::query::QueryContext;

    let mut config = honk_config::Config::default();
    config.global.nfqueue_enable = false;
    config.experimental.native_api.enabled = true;
    config.experimental.native_api.allow_anonymous_loopback = true;
    config.dns.cache.max_size = 8192;
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
    assert_eq!(first["entries"][0]["entry_id"], expected_ids[0]);
    assert_eq!(first["entries"][0]["type"], "A");
    let cursor = first["next_cursor"].as_str().unwrap();
    service.invalidate(CacheInvalidation::All).await.unwrap();
    let (status, second) = cache_page(&state, &format!("{filters}&cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["total"], 2);
    assert_eq!(second["entries"][0]["entry_id"], expected_ids[1]);
    assert_eq!(second["observed_at"], first["observed_at"]);
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
