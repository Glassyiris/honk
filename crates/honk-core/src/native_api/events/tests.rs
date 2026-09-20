use super::*;
use futures::{FutureExt, StreamExt};

fn hub() -> Arc<EventHub> {
    Arc::new(EventHub::new("instance-a".into()))
}

fn all() -> Filter {
    Filter::new(63, None)
}

fn request_id() -> RequestId {
    RequestId("test-request".into())
}

fn subscribe(hub: &Arc<EventHub>, filter: Filter, cursor: Option<&str>) -> Subscription {
    hub.subscribe(filter, cursor, &request_id()).unwrap()
}

fn publish_flow(hub: &EventHub, id: &str, revision: u64) {
    hub.flow_updated(id, revision);
}

async fn next(stream: &mut Subscription) -> String {
    String::from_utf8(stream.next().await.unwrap().unwrap().to_vec()).unwrap()
}

fn cursor(frame: &str) -> &str {
    frame
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .unwrap()
}

fn data(frame: &str) -> Value {
    serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap()
}

fn assert_expired(hub: &Arc<EventHub>, filter: Filter, cursor: &str) {
    let response = match hub.subscribe(filter, Some(cursor), &request_id()) {
        Ok(_) => panic!("expired cursor opened a stream"),
        Err(error) => error.into_response(),
    };
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn fresh_ready_then_replay_ready_and_live_have_no_gap() {
    let hub = hub();
    let filter = Filter::new(1 << 2, Some("flow-a".into()));
    let mut fresh = subscribe(&hub, filter.clone(), None);
    let ready = next(&mut fresh).await;
    assert!(ready.starts_with("event: stream.ready\n"));
    publish_flow(&hub, "flow-a", 1);
    let original = next(&mut fresh).await;
    publish_flow(&hub, "flow-b", 1);
    publish_flow(&hub, "flow-a", 2);
    drop(fresh);

    let mut resumed = subscribe(&hub, filter.clone(), Some(cursor(&ready)));
    publish_flow(&hub, "flow-a", 3);
    let replay_one = next(&mut resumed).await;
    assert_eq!(cursor(&replay_one), cursor(&original));
    assert_eq!(data(&replay_one)["revision"], 1);
    assert_eq!(data(&next(&mut resumed).await)["revision"], 2);
    let resumed_ready = next(&mut resumed).await;
    assert!(resumed_ready.starts_with("event: stream.ready\n"));
    assert_ne!(cursor(&ready), cursor(&resumed_ready));
    assert_eq!(data(&next(&mut resumed).await)["revision"], 3);
    drop(resumed);

    let mut after_ready = subscribe(&hub, filter, Some(cursor(&resumed_ready)));
    assert_eq!(data(&next(&mut after_ready).await)["revision"], 3);
    assert!(
        next(&mut after_ready)
            .await
            .starts_with("event: stream.ready\n")
    );
}

#[tokio::test]
async fn live_flow_updates_coalesce_at_the_tail_without_rewriting_replay() {
    let hub = hub();
    let mut live = subscribe(&hub, all(), None);
    let ready = next(&mut live).await;
    publish_flow(&hub, "flow-a", 1);
    publish_flow(&hub, "flow-b", 1);
    hub.publish(
        "flow.gap",
        json!({"resource_id":"flow-a","reason":"buffer_overflow","dropped_records":"1"}),
        Some("flow-a"),
    );
    hub.publish("runtime.updated", json!({}), None);
    publish_flow(&hub, "flow-a", 2);

    assert_eq!(data(&next(&mut live).await)["resource_id"], "flow-b");
    assert!(next(&mut live).await.starts_with("event: flow.gap\n"));
    let runtime = next(&mut live).await;
    assert!(runtime.starts_with("event: runtime.updated\n"));
    let latest = next(&mut live).await;
    assert_eq!(data(&latest)["revision"], 2);
    let sequence = |frame: &str| {
        let bytes = URL_SAFE_NO_PAD.decode(cursor(frame)).unwrap();
        u64::from_be_bytes(bytes[..8].try_into().unwrap())
    };
    assert!(sequence(&runtime) < sequence(&latest));
    assert!(live.next().now_or_never().is_none());
    drop(live);

    let mut resumed = subscribe(&hub, all(), Some(cursor(&ready)));
    publish_flow(&hub, "flow-a", 3);
    publish_flow(&hub, "flow-a", 4);
    assert_eq!(data(&next(&mut resumed).await)["revision"], 1);
    assert_eq!(data(&next(&mut resumed).await)["resource_id"], "flow-b");
    assert!(next(&mut resumed).await.starts_with("event: flow.gap\n"));
    assert_eq!(next(&mut resumed).await, runtime);
    assert_eq!(next(&mut resumed).await, latest);
    let ready = next(&mut resumed).await;
    assert!(ready.starts_with("event: stream.ready\n"));
    let last = next(&mut resumed).await;
    assert_eq!(data(&last)["revision"], 4);
    assert!(sequence(&ready) < sequence(&last));
    assert!(resumed.next().now_or_never().is_none());
    drop(resumed);

    publish_flow(&hub, "flow-a", 5);
    let mut replay = subscribe(&hub, all(), Some(cursor(&last)));
    assert_eq!(data(&next(&mut replay).await)["revision"], 5);
    assert!(next(&mut replay).await.starts_with("event: stream.ready\n"));
}

#[tokio::test]
async fn queued_flow_replacement_preserves_capacity_for_latest_revision() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    for index in 0..CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    for revision in 2..=100 {
        publish_flow(&hub, "flow-0", revision);
    }
    for index in 1..CLIENT_QUEUE {
        assert_eq!(
            data(&next(&mut stream).await)["resource_id"],
            format!("flow-{index}")
        );
    }
    assert_eq!(data(&next(&mut stream).await)["revision"], 100);
    assert!(stream.next().now_or_never().is_none());
}

#[tokio::test]
async fn cursors_reject_changed_filters_instance_and_forgery() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    let saved = cursor(&ready);
    assert_expired(&hub, Filter::new(1 << 2, None), saved);
    assert_expired(&hub, Filter::new(63, Some("flow-a".into())), saved);
    assert_expired(&Arc::new(EventHub::new("instance-b".into())), all(), saved);
    assert_expired(&Arc::new(EventHub::new("instance-a".into())), all(), saved);
    assert_expired(&hub, all(), "unknown");
    let mut tampered = URL_SAFE_NO_PAD.decode(saved).unwrap();
    tampered[7] ^= 1;
    assert_expired(&hub, all(), &URL_SAFE_NO_PAD.encode(tampered));
}

#[tokio::test(start_paused = true)]
async fn time_and_count_pressure_expire_before_stream_creation() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    drop(stream);
    tokio::time::advance(RETENTION).await;
    assert_expired(&hub, all(), cursor(&ready));

    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    publish_flow(&hub, "flow-a", 1);
    let first = next(&mut stream).await;
    drop(stream);
    for revision in 2..=MAX_EVENTS as u64 + 1 {
        publish_flow(&hub, "flow-a", revision);
    }
    assert_expired(&hub, all(), cursor(&first));
}

#[tokio::test]
async fn queue_overflow_discards_buffered_frames_and_wakes_receiver() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    assert!(stream.next().now_or_never().is_none());
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(stream.next().await.is_none());

    let mut before_ready = subscribe(&hub, all(), None);
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert!(before_ready.next().await.unwrap().is_err());
}

#[tokio::test]
async fn body_drop_releases_client_capacity_even_before_polling() {
    let hub = hub();
    let mut bodies: Vec<_> = (0..MAX_CLIENTS)
        .map(|_| Body::from_stream(subscribe(&hub, all(), None)))
        .collect();
    let error = hub.subscribe(all(), None, &request_id()).err().unwrap();
    assert_eq!(
        error.into_response().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    bodies.pop();
    let replacement = Body::from_stream(subscribe(&hub, all(), None));
    for index in 0..=CLIENT_QUEUE {
        publish_flow(&hub, &format!("flow-{index}"), 1);
    }
    assert_eq!(
        hub.subscribe(all(), None, &request_id())
            .err()
            .unwrap()
            .into_response()
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
    );
    drop(replacement);
    let mut fresh = subscribe(&hub, all(), None);
    assert!(next(&mut fresh).await.starts_with("event: stream.ready\n"));
}

#[tokio::test]
async fn replay_eviction_terminates_instead_of_skipping_to_ready() {
    let hub = hub();
    let filter = Filter::new(1 << 2, None);
    let mut fresh = subscribe(&hub, filter.clone(), None);
    let ready = next(&mut fresh).await;
    drop(fresh);
    publish_flow(&hub, "flow-a", 1);
    let mut resumed = subscribe(&hub, filter, Some(cursor(&ready)));
    for _ in 0..MAX_EVENTS {
        hub.publish("runtime.updated", json!({}), None);
    }
    assert!(resumed.next().await.unwrap().is_err());
    assert!(resumed.next().await.is_none());
}

#[tokio::test]
async fn ready_churn_does_not_evict_event_history() {
    let hub = hub();
    let mut first = subscribe(&hub, all(), None);
    next(&mut first).await;
    publish_flow(&hub, "flow-a", 1);
    let event = next(&mut first).await;
    drop(first);
    for _ in 0..MAX_EVENTS + 1 {
        let mut stream = subscribe(&hub, all(), None);
        assert!(next(&mut stream).await.starts_with("event: stream.ready\n"));
    }
    publish_flow(&hub, "flow-a", 2);
    let mut resumed = subscribe(&hub, all(), Some(cursor(&event)));
    assert_eq!(data(&next(&mut resumed).await)["revision"], 2);
}

#[tokio::test(start_paused = true)]
async fn heartbeat_has_no_cursor_and_shutdown_ends_pending_clients() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    tokio::time::advance(HEARTBEAT - Duration::from_secs(1)).await;
    assert!(stream.next().now_or_never().is_none());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(next(&mut stream).await, ": heartbeat\n\n");
    assert!(stream.next().now_or_never().is_none());
    hub.shutdown();
    assert!(stream.next().await.unwrap().is_err());
    assert_eq!(
        hub.subscribe(all(), None, &request_id())
            .err()
            .unwrap()
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE,
    );
}

#[tokio::test]
async fn payloads_enforce_identifier_and_integer_contracts() {
    let hub = hub();
    let mut stream = subscribe(&hub, all(), None);
    let ready = next(&mut stream).await;
    publish_flow(&hub, "flow-a", MAX_SAFE_UINT);
    let event = data(&next(&mut stream).await);
    assert_eq!(event["revision"], MAX_SAFE_UINT);
    assert_eq!(event["href"], "/api/v1/flows/flow-a");
    hub.publish("flow.gap", json!({
        "resource_id": null, "reason": "buffer_overflow", "dropped_records": u64::MAX.to_string(),
    }), None);
    assert_eq!(
        data(&next(&mut stream).await)["dropped_records"],
        u64::MAX.to_string()
    );
    publish_flow(&hub, "flow-a", MAX_SAFE_UINT + 1);
    assert!(stream.next().await.unwrap().is_err());
    assert_expired(&hub, all(), cursor(&ready));

    let mut stream = subscribe(&hub, all(), None);
    next(&mut stream).await;
    hub.publish("flow.gap", json!({
        "resource_id": null, "reason": "buffer_overflow", "dropped_records": "18446744073709551616",
    }), None);
    assert!(stream.next().await.unwrap().is_err());

    for (flow_id, revision) in [
        ("", 1),
        ("https://user:password@private.invalid", 1),
        ("flow-a", 0),
    ] {
        let mut stream = subscribe(&hub, all(), None);
        let ready = next(&mut stream).await;
        publish_flow(&hub, flow_id, revision);
        assert!(stream.next().await.unwrap().is_err());
        assert_expired(&hub, all(), cursor(&ready));
    }
}

#[tokio::test]
async fn flow_filter_keeps_global_events_but_excludes_other_flows() {
    let hub = hub();
    let filter = Filter::new(63, Some("flow-a".into()));
    let mut stream = subscribe(&hub, filter.clone(), None);
    let ready = next(&mut stream).await;
    publish_flow(&hub, "flow-b", 1);
    hub.publish("runtime.updated", json!({}), None);
    assert!(
        next(&mut stream)
            .await
            .starts_with("event: runtime.updated\n")
    );
    assert!(stream.next().now_or_never().is_none());
    hub.publish(
        "flow.gap",
        json!({"resource_id":"flow-b","reason":"buffer_overflow","dropped_records":"1"}),
        Some("flow-b"),
    );
    hub.publish(
        "flow.gap",
        json!({"resource_id":null,"reason":"buffer_overflow","dropped_records":"2"}),
        None,
    );
    let live = tokio::time::timeout(Duration::from_secs(1), next(&mut stream))
        .await
        .unwrap();
    assert_eq!(data(&live)["dropped_records"], "2");
    let mut resumed = subscribe(&hub, filter, Some(cursor(&ready)));
    assert!(
        next(&mut resumed)
            .await
            .starts_with("event: runtime.updated\n")
    );
    assert_eq!(cursor(&next(&mut resumed).await), cursor(&live));
}

#[test]
fn request_validation_rejects_ambiguous_filters_headers_and_accept() {
    for uri in [
        "/api/v1/events?unknown=1",
        "/api/v1/events?kinds=flow.updated&kinds=flow.gap",
        "/api/v1/events?kinds=flow.updated,flow.updated",
        "/api/v1/events?kinds=flow.updated,unknown",
        "/api/v1/events?kinds=",
        "/api/v1/events?flow_id=",
    ] {
        let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        assert_eq!(
            request_options(&request, &request_id())
                .err()
                .unwrap()
                .into_response()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for accept in [
        "application/json",
        "text/event-stream;q=0, */*;q=1",
        "invalid",
        "text/event-stream;q=NaN",
        "text/event-stream;q=1e0",
        "text/event-stream;q=0.0001",
        "text/event-stream;q=1.001",
        "text/event-stream;q=1;q=0",
        "te xt/event-stream",
    ] {
        let request = Request::builder()
            .header(header::ACCEPT, accept)
            .body(Body::empty())
            .unwrap();
        assert!(request_options(&request, &request_id()).is_err());
    }
    for accept in [
        "text/event-stream",
        "*/*",
        "application/json, text/event-stream;q=0.5",
        "text/event-stream;charset=utf-8",
        "text/event-stream;charset=\"utf-8\";q=1.000",
    ] {
        let request = Request::builder()
            .header(header::ACCEPT, accept)
            .body(Body::empty())
            .unwrap();
        assert!(request_options(&request, &request_id()).is_ok());
    }
    let request = Request::builder()
        .header("last-event-id", "first")
        .header("last-event-id", "second")
        .body(Body::empty())
        .unwrap();
    assert!(request_options(&request, &request_id()).is_err());
    let first = Request::builder()
        .uri("/api/v1/events?kinds=flow.updated,flow.gap")
        .body(Body::empty())
        .unwrap();
    let second = Request::builder()
        .uri("/api/v1/events?kinds=flow.gap,flow.updated")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        request_options(&first, &request_id()).unwrap().0.binding,
        request_options(&second, &request_id()).unwrap().0.binding
    );
}

#[tokio::test]
async fn notification_live_queue_survives_unrelated_history_eviction() {
    let hub = hub();
    let mut stream = subscribe(&hub, Filter::new(1 << 2, None), None);
    next(&mut stream).await;
    publish_flow(&hub, "flow-a", 1);
    for _ in 0..MAX_EVENTS {
        hub.publish("runtime.updated", json!({}), None);
    }
    assert_eq!(data(&next(&mut stream).await)["revision"], 1);
}

#[tokio::test]
async fn log_stream_binding_and_rejected_payload_invalidate_cursors() {
    let events = hub();
    let logs = Arc::new(EventHub::logs("instance-a".into()));
    let mut event_stream = subscribe(&events, all(), None);
    let event_ready = next(&mut event_stream).await;
    let filter = Filter::logs(5, None);
    assert_expired(&logs, filter.clone(), cursor(&event_ready));
    let mut stream = subscribe(&logs, filter.clone(), None);
    let ready = next(&mut stream).await;
    assert_expired(&events, all(), cursor(&ready));
    assert_expired(&logs, all(), cursor(&ready));
    logs.publish_log(
        3,
        "honk_core",
        Bytes::from(vec![b'x'; MAX_PAYLOAD_BYTES + 1]),
    );
    assert!(stream.next().await.unwrap().is_err());
    assert_expired(&logs, filter, cursor(&ready));
}
