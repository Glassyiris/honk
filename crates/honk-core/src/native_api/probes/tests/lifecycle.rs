use super::*;

#[tokio::test]
async fn pause_drains_started_and_disconnected_queued_jobs_then_resumes_same_owner() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = Config::default();
    config.global.tcp_check_url = vec![format!("http://{address}/check")];
    config.experimental.native_api.probe_allowed_ports = vec![address.port()];
    for index in 0..=MAX_ACTIVE {
        config.groups.push(serde_json::from_value(json!({"name":format!("pause-{index}"),"nodes":[honk_config::config::DIRECT_NODE_ID]})).unwrap());
    }
    let state = state(config).await;
    let service = &state.observation.probes;
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Unavailable));
    assert_eq!(
        service.resume().await,
        Err(ProbeLifecycleError::Unavailable)
    );
    let identity = state.observation.catalog.snapshot();
    let (stop, receiver) = watch::channel(false);
    let worker = service.start(Arc::clone(&state), receiver);
    let mut held = Vec::new();
    let mut accepted = Vec::new();
    for index in 0..MAX_ACTIVE {
        let input = request(
            json!({"type":"group","group_id":identity.groups[&format!("pause-{index}")]}),
            "http",
            json!(["tcp"]),
            "ipv4",
        );
        accepted.push(
            body(
                create(
                    &state,
                    http_request(&input, &format!("active-{index}")),
                    &RequestId("active".into()),
                )
                .await
                .unwrap(),
            )
            .await,
        );
        let (mut socket, _) = listener.accept().await.unwrap();
        receive_headers(&mut socket).await;
        held.push(socket);
    }
    let input = request(
        json!({"type":"group","group_id":identity.groups[&format!("pause-{MAX_ACTIVE}")]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let caller = tokio::spawn({
        let state = Arc::clone(&state);
        let input = input.clone();
        async move {
            create(
                &state,
                http_request(&input, "queued"),
                &RequestId("queued".into()),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.sender.capacity() == MAX_QUEUED {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiter = service
        .operations
        .reserve(
            "anonymous",
            "POST",
            "/api/v1/probes",
            Some("queued"),
            input.to_string().as_bytes(),
            OperationKind::Probe,
        )
        .unwrap();
    assert!(!waiter.fresh);
    caller.abort();
    let _ = caller.await;
    tokio::time::timeout(Duration::from_secs(2), service.pause())
        .await
        .unwrap()
        .unwrap();
    assert!(!service.running());
    assert_eq!(service.capability()["available"], false);
    assert_eq!(
        waiter
            .admission()
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
    for mut socket in held {
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    for operation in &accepted {
        let result = terminal(&state, operation["operation_id"].as_str().unwrap()).await;
        assert_eq!(result["result"]["results"][0]["state"], "unknown");
        assert_eq!(result["result"]["results"][0]["error"], "cancelled");
        assert_eq!(result["result"]["results"][0]["health_updated"], false);
    }
    let old = request(
        json!({"type":"group","group_id":identity.groups["pause-0"]}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let replay = body(
        create(
            &state,
            http_request(&old, "active-0"),
            &RequestId("replay".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(replay["operation_id"], accepted[0]["operation_id"]);
    assert_eq!(
        create(
            &state,
            http_request(&input, "fresh-paused"),
            &RequestId("fresh".into())
        )
        .await
        .unwrap_err()
        .into_response()
        .status(),
        StatusCode::CONFLICT
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert!(
        state
            .alive_set
            .native_observations(honk_config::config::DIRECT_NODE_ID)
            .is_empty()
    );
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Conflict));
    service.resume().await.unwrap();
    assert!(service.running());
    let resumed = body(
        create(
            &state,
            http_request(&input, "resumed"),
            &RequestId("resumed".into()),
        )
        .await
        .unwrap(),
    )
    .await;
    let (mut socket, _) = listener.accept().await.unwrap();
    receive_headers(&mut socket).await;
    socket
        .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
        .await
        .unwrap();
    let result = terminal(&state, resumed["operation_id"].as_str().unwrap()).await;
    assert_eq!(result["result"]["results"][0]["state"], "healthy");
    stop.send(true).unwrap();
    worker.await.unwrap();
    assert_eq!(service.pause().await, Err(ProbeLifecycleError::Unavailable));
}

#[tokio::test]
async fn pause_cancels_body_and_reserved_capture_without_late_enqueue() {
    let state = state(Config::default()).await;
    let service = &state.observation.probes;
    let (stop, receiver) = watch::channel(false);
    let worker = service.start(Arc::clone(&state), receiver);
    let router = state.traffic_router.write().await;
    let input = request(
        json!({"type":"node","node_id":honk_config::config::DIRECT_NODE_ID.to_string()}),
        "http",
        json!(["tcp"]),
        "ipv4",
    );
    let capture = tokio::spawn({
        let state = Arc::clone(&state);
        let input = input.clone();
        async move {
            create(
                &state,
                http_request(&input, "capture"),
                &RequestId("capture".into()),
            )
            .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.gate.lock().requests != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiter = service
        .operations
        .reserve(
            "anonymous",
            "POST",
            "/api/v1/probes",
            Some("capture"),
            input.to_string().as_bytes(),
            OperationKind::Probe,
        )
        .unwrap();
    assert!(!waiter.fresh);
    let body = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/probes")
                .header("content-type", "application/json")
                .body(Body::from_stream(futures::stream::pending::<
                    Result<bytes::Bytes, std::io::Error>,
                >()))
                .unwrap();
            create(&state, request, &RequestId("body".into())).await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.gate.lock().requests != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), service.pause())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        capture.await.unwrap().unwrap_err().into_response().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        body.await.unwrap().unwrap_err().into_response().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        waiter
            .admission()
            .await
            .unwrap_err()
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
    drop(router);
    service.resume().await.unwrap();
    assert!(
        state
            .alive_set
            .native_observations(honk_config::config::DIRECT_NODE_ID)
            .is_empty()
    );
    stop.send(true).unwrap();
    worker.await.unwrap();
}
