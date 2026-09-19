use super::record::{FlowError, OutboundAttempt, Selection};
use super::*;
use honk_config::types::DialMode;

fn store() -> Arc<FlowStore> {
    let instance = Uuid::new_v4().to_string();
    Arc::new(FlowStore::new(
        instance.clone(),
        Arc::new(EventHub::new(instance)),
    ))
}

fn begin(store: &Arc<FlowStore>, network: &'static str) -> FlowGuard {
    store.begin(
        network,
        "127.0.0.1:31000".parse().unwrap(),
        "127.0.0.2:443".parse().unwrap(),
    )
}

fn request_id() -> RequestId {
    RequestId("flow-test".to_owned())
}

fn filters(network: &str, state: &str, full: bool, limit: usize) -> Filters {
    Filters {
        network: network.to_owned(),
        state: state.to_owned(),
        connection_id: None,
        full,
        limit,
    }
}

fn error_code(error: ApiError, status: StatusCode, code: &str) {
    assert_eq!(serde_json::to_value(&error).unwrap()["error"]["code"], code);
    assert_eq!(error.into_response().status(), status);
}

fn dial_mode() -> StepData {
    StepData::DialMode {
        configured: DialMode::Ip,
        effective_target: "ip",
        domain: None,
        domain_source: None,
        verification: "not_required",
        reason: "original_destination",
    }
}

#[test]
fn tuple_reincarnation_keeps_history_and_exact_connection_identity() {
    let store = store();
    let first = begin(&store, "tcp");
    first.attach_connection("connection-old");
    first.routed("original-group", None, None, "unknown");
    first.selected(vec![
        "original-group-id".to_owned(),
        "original-node-id".to_owned(),
    ]);
    first.step(Some(7), dial_mode());
    first.finish("closed", "relay_finished");
    let second = begin(&store, "tcp");
    second.attach_connection("connection-new");
    second.routed("replacement-group", None, None, "unknown");
    second.selected(vec![
        "replacement-group-id".to_owned(),
        "replacement-node-id".to_owned(),
    ]);
    assert_ne!(first.id(), second.id());
    let evidence = store.connection_evidence(first.id()).unwrap();
    assert_eq!(evidence.chain, ["original-group-id", "original-node-id"]);
    let detail = store.get(first.id(), &request_id()).unwrap();
    assert_eq!(detail["outbound"], "original-group");
    assert_eq!(
        detail["trace"]["steps"][1]["generation_id"],
        format!("{}:7", store.instance_id)
    );
    let mut query = filters("all", "all", true, 100);
    query.connection_id = Some("connection-old".to_owned());
    let page = store.page(query, None, &request_id()).unwrap();
    assert_eq!(page["flows"].as_array().unwrap().len(), 1);
    assert_eq!(page["flows"][0]["id"], first.id());
    assert_eq!(page["flows"][0]["input"]["src"], "127.0.0.1:31000");
}

#[test]
fn guards_finalize_once_and_do_not_fabricate_kernel_connection_close() {
    let store = store();
    let flow = begin(&store, "udp");
    assert!(flow.first_reply());
    assert!(!flow.first_reply());
    flow.finish("closed", "idle_after_reply");
    let id = flow.id().to_owned();
    let terminal = store.get(&id, &request_id()).unwrap();
    flow.finish("failed", "late_error");
    flow.routed("late-outbound", None, None, "unknown");
    drop(flow);
    assert_eq!(store.get(&id, &request_id()).unwrap(), terminal);
    assert_eq!(
        terminal["trace"]["steps"][1]["data"]["reply_received"],
        true
    );

    let cancelled = begin(&store, "tcp");
    let id = cancelled.id().to_owned();
    drop(cancelled);
    let detail = store.get(&id, &request_id()).unwrap();
    assert_eq!(detail["state"], "failed");
    assert_eq!(detail["trace"]["steps"][1]["data"]["reason"], "cancelled");

    let handoff = begin(&store, "udp");
    handoff.finish("unknown", "kernel_handoff");
    let detail = store.get(handoff.id(), &request_id()).unwrap();
    assert_eq!(detail["state"], "unknown");
    assert!(detail["ended_at"].is_string());
}

#[test]
fn pinned_pages_survive_mutation_and_bind_all_filters() {
    let store = store();
    let old = begin(&store, "tcp");
    old.transition("active", "ready", "transport_ready", None);
    let ignored = begin(&store, "udp");
    ignored.transition("active", "ready", "transport_ready", None);
    let recent = begin(&store, "tcp");
    recent.transition("active", "ready", "transport_ready", None);
    let query = filters("tcp", "active", true, 1);
    let first = store.page(query.clone(), None, &request_id()).unwrap();
    assert_eq!(first["flows"][0]["id"], recent.id());
    let cursor = first["next_cursor"].as_str().unwrap();
    old.finish("closed", "relay_finished");
    let newcomer = begin(&store, "tcp");
    newcomer.transition("active", "ready", "transport_ready", None);
    let second = store
        .page(query.clone(), Some(cursor), &request_id())
        .unwrap();
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["flows"][0]["id"], old.id());
    assert_eq!(second["flows"][0]["state"], "active");
    assert!(second["next_cursor"].is_null());
    for changed in [
        filters("udp", "active", true, 1),
        filters("tcp", "closed", true, 1),
        filters("tcp", "active", false, 1),
    ] {
        error_code(
            store
                .page(changed, Some(cursor), &request_id())
                .unwrap_err(),
            StatusCode::GONE,
            "snapshot_expired",
        );
    }
    let other_instance = super::tests::store();
    error_code(
        other_instance
            .page(query.clone(), Some(cursor), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    store.inner.lock().snapshots[0].created = Instant::now() - SNAPSHOT_TTL;
    error_code(
        store.page(query, Some(cursor), &request_id()).unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
}

#[test]
fn snapshot_capacity_is_explicit_and_recording_disable_releases_every_owner() {
    let store = store();
    let first = begin(&store, "tcp");
    let _second = begin(&store, "tcp");
    let query = filters("all", "all", true, 1);
    let mut cursor = String::new();
    let mut oldest = String::new();
    for round in 0..MAX_SNAPSHOTS {
        let page = store.page(query.clone(), None, &request_id()).unwrap();
        cursor = page["next_cursor"].as_str().unwrap().to_owned();
        if round == 0 {
            oldest = cursor.clone();
        }
    }
    // A full table makes room by dropping its oldest snapshot; only that
    // reader starts over, the newest cursors stay valid.
    let page = store.page(query.clone(), None, &request_id()).unwrap();
    assert!(page["next_cursor"].is_string());
    assert_eq!(store.inner.lock().snapshots.len(), MAX_SNAPSHOTS);
    error_code(
        store
            .page(query.clone(), Some(&oldest), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    store
        .page(query.clone(), Some(&cursor), &request_id())
        .unwrap();
    store.set_recording(false);
    let inert = begin(&store, "tcp");
    assert!(inert.id().is_empty());
    assert!(!inert.first_reply());
    first.finish("closed", "late_finish");
    error_code(
        store
            .page(query.clone(), Some(&cursor), &request_id())
            .unwrap_err(),
        StatusCode::GONE,
        "snapshot_expired",
    );
    let page = store.page(query, None, &request_id()).unwrap();
    assert_eq!(page["flows"], json!([]));
    assert_eq!(page["coverage"]["userspace_tcp"], "none");
    let inner = store.inner.lock();
    assert_eq!(inner.records.capacity(), 0);
    assert_eq!(inner.snapshots.capacity(), 0);
    assert_eq!(inner.tombstones.capacity(), 0);
    assert_eq!(inner.record_bytes + inner.snapshot_bytes, 0);
    drop(inner);
    store.set_recording(true);
    let restarted = begin(&store, "tcp");
    assert_ne!(restarted.id(), first.id());
    assert!(!restarted.id().is_empty());
}

#[test]
fn aged_out_records_report_one_gap_per_interval_with_the_running_count() {
    let store = store();
    let gaps = || {
        store
            .events
            .buffered_kinds()
            .into_iter()
            .filter(|kind| *kind == "flow.gap")
            .count()
    };
    for _ in 0..5 {
        begin(&store, "tcp").finish("closed", "relay_finished");
    }
    assert_eq!(gaps(), 0);
    let later = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), later);
    assert_eq!(gaps(), 1);
    let inner = store.inner.lock();
    assert_eq!(inner.dropped, 5);
    assert!(inner.records.is_empty());
    drop(inner);
    // Within the interval a further eviction only advances the count; after
    // it the next eviction is reported again.
    begin(&store, "tcp").finish("closed", "relay_finished");
    store.prune(&mut store.inner.lock(), later + Duration::from_secs(1));
    assert_eq!((gaps(), store.inner.lock().dropped), (1, 6));
    begin(&store, "tcp").finish("closed", "relay_finished");
    store.prune(&mut store.inner.lock(), later + EVICTED_GAP_INTERVAL);
    assert_eq!((gaps(), store.inner.lock().dropped), (2, 7));
}

#[test]
fn room_making_overflow_is_reported_per_interval_but_lost_history_per_record() {
    let store = store();
    let gaps = || {
        store
            .events
            .buffered_kinds()
            .into_iter()
            .filter(|kind| *kind == "flow.gap")
            .count()
    };
    // Keep going until twenty records had to make room for newer ones.
    while store.inner.lock().dropped < 20 {
        begin(&store, "tcp").finish("closed", "relay_finished");
    }
    assert_eq!(gaps(), 1);
    // A record that overflowed its own step budget is still named on its own.
    let flow = begin(&store, "tcp");
    for _ in 0..MAX_STEPS + 1 {
        flow.step(Some(1), dial_mode());
    }
    assert_eq!(gaps(), 2);
}

#[test]
fn a_userspace_evaluation_is_recomputed_evidence_on_the_wire() {
    let store = store();
    let flow = begin(&store, "tcp");
    flow.routed(
        "group",
        Some("gen:0:rule:0"),
        Some("dip(<redacted>)"),
        "evaluation",
    );
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["rule_id"], "gen:0:rule:0");
    assert_eq!(detail["rule_source"], "recomputed");
    flow.routed("group", None, None, "forced");
    assert_eq!(
        store.get(flow.id(), &request_id()).unwrap()["rule_source"],
        "unknown"
    );
}

#[test]
fn retention_distinguishes_expired_unknown_and_active_records() {
    let store = store();
    let terminal = begin(&store, "tcp");
    terminal.finish("failed", "dial_failed");
    let active = begin(&store, "udp");
    let future = Instant::now() + TERMINAL_TTL;
    store.prune(&mut store.inner.lock(), future);
    error_code(
        store.get(terminal.id(), &request_id()).unwrap_err(),
        StatusCode::GONE,
        "flow_expired",
    );
    error_code(
        store.get("not-a-recorded-id", &request_id()).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    );
    assert_eq!(
        store.get(active.id(), &request_id()).unwrap()["state"],
        "observed"
    );
    store.prune(&mut store.inner.lock(), future + TERMINAL_TTL);
    error_code(
        store.get(terminal.id(), &request_id()).unwrap_err(),
        StatusCode::NOT_FOUND,
        "resource_not_found",
    );
}

#[test]
fn trace_bounds_keep_terminal_state_and_explicit_loss_without_private_errors() {
    let store = store();
    let flow = begin(&store, "tcp");
    for _ in 0..MAX_STEPS + 10 {
        flow.step(Some(1), dial_mode());
    }
    let mut unsafe_data = dial_mode();
    if let StepData::DialMode { domain, .. } = &mut unsafe_data {
        *domain = Some("https://operator:credential@example.test".into());
    }
    flow.step(Some(1), unsafe_data);
    flow.finish("failed", "dial_failed");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["state"], "failed");
    assert!(detail["ended_at"].is_string());
    assert_eq!(
        detail["trace"]["steps"].as_array().unwrap().len(),
        MAX_STEPS
    );
    assert_eq!(
        detail["trace"]["missing"],
        json!(["not_instrumented", "buffer_overflow", "redacted"])
    );
    assert!(!detail.to_string().contains("credential"));
    assert!(detail["input"]["process_path"].is_null());
    assert!(detail["input"]["domain_rule_ids"].is_null());
}

#[test]
fn unsafe_causal_identity_drops_step_without_losing_the_terminal_outcome() {
    let store = store();
    let flow = begin(&store, "udp");
    flow.step(
        None,
        StepData::Connection {
            state: "dialing",
            reason: "transport_failed",
            milestone: "unknown",
            attempt_id: Some("https://operator:credential@example.test/private".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
        },
    );
    flow.finish("failed", "transport_failed");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(detail["state"], "failed");
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["reason"],
        "transport_failed"
    );
    assert_eq!(
        detail["trace"]["missing"],
        json!(["not_instrumented", "redacted"])
    );
    assert!(!detail.to_string().contains("credential"));
}

#[test]
fn fixed_error_codes_and_safe_addresses_do_not_invent_input_provenance() {
    let store = store();
    let flow = store.begin(
        "udp",
        "[::1]:31000".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
    );
    flow.update_input(None, None, Some("client"), Some(42), None, Some(0), Some(0));
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 1);
    assert_eq!(detail["input"]["pid"], 42);
    flow.update_input(
        Some("secret.example.test"),
        Some("quic_sni"),
        Some("client"),
        Some(42),
        None,
        Some(0),
        Some(0),
    );
    flow.step(
        None,
        StepData::Connection {
            state: "dialing",
            reason: "transport_failed",
            milestone: "unknown",
            attempt_id: Some("attempt-1".into()),
            reply_received: None,
            error: Some(FlowError::UdpPrepareFailed),
        },
    );
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["input"]["domain"], "secret.example.test");
    assert_eq!(detail["trace"]["steps"][1]["data"]["source"], "sniffer");
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["values"]["src"],
        "[::1]:31000"
    );
    assert_eq!(
        detail["trace"]["steps"][1]["data"]["values"]["dst"],
        "[2001:db8::1]:443"
    );
    assert_eq!(
        detail["trace"]["steps"][2]["data"]["error"],
        "udp_prepare_failed"
    );
    assert_eq!(detail["trace"]["missing"], json!(["not_instrumented"]));
}

#[test]
fn optional_display_redaction_preserves_attempt_transitions_and_selection_ids() {
    let store = store();
    let flow = begin(&store, "tcp");
    for status in ["started", "succeeded"] {
        flow.step(
            Some(1),
            StepData::Outbound {
                attempt_id: "attempt-1".into(),
                status,
                error: None,
                attempt: OutboundAttempt {
                    parent_attempt_id: None,
                    kind: "leaf",
                    evaluation_id: Some("evaluation-1".into()),
                    routing_source: "evaluation",
                    routed_outbound: Some("Group/Proxy".into()),
                    effective_outbound: Some("Group/Proxy".into()),
                    mode_override: "none",
                    selection_path: vec![Selection {
                        group_id: "group-1".into(),
                        member_id: "node-1".into(),
                        member_name: Some("HK/Trojan".into()),
                        policy: "urltest",
                        reason: "selected",
                        selection: (),
                    }],
                    leaf_node_id: "node-1".into(),
                    leaf_node_name: Some("HK/Trojan".into()),
                    target: Some("127.0.0.2:443".into()),
                    target_kind: "ip",
                    dial_ip: Some("127.0.0.2".parse().unwrap()),
                    server_addr: (),
                    resolution_location: "original_ip",
                },
            },
        );
    }
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 3);
    for (index, status) in [(1, "started"), (2, "succeeded")] {
        let data = &detail["trace"]["steps"][index]["data"];
        assert_eq!(data["attempt_id"], "attempt-1");
        assert_eq!(data["status"], status);
        assert_eq!(data["leaf_node_id"], "node-1");
        assert_eq!(data["selection_path"][0]["group_id"], "group-1");
        assert_eq!(data["selection_path"][0]["member_id"], "node-1");
        assert!(data["selection_path"][0]["member_name"].is_null());
        assert!(data["routed_outbound"].is_null());
    }
    assert_eq!(
        detail["trace"]["missing"],
        json!(["not_instrumented", "redacted"])
    );
}

#[test]
fn recorder_and_snapshots_share_the_byte_budget_and_tombstones_are_bounded() {
    let store = store();
    let original = begin(&store, "tcp");
    let original_id = original.id().to_owned();
    for _ in 0..MAX_RECORDS * 2 {
        let flow = begin(&store, "tcp");
        flow.step(Some(1), dial_mode());
        flow.finish("closed", "relay_finished");
    }
    let inner = store.inner.lock();
    assert!(inner.bytes() <= MAX_BYTES);
    assert!(inner.records.len() <= MAX_RECORDS);
    assert!(inner.tombstones.len() <= MAX_RECORDS);
    assert!(inner.dropped > 0);
    assert!(
        inner
            .records
            .iter()
            .all(|record| record.id() != original_id)
    );
    drop(inner);
    // The ring at its own limit still leaves the listing its reserved share:
    // a walk over every record starts, and the whole store stays in budget.
    let page = store
        .page(filters("all", "all", true, 1), None, &request_id())
        .unwrap();
    assert!(page["next_cursor"].is_string());
    let inner = store.inner.lock();
    assert!(inner.snapshot_bytes > 0);
    assert!(inner.bytes() <= MAX_BYTES);
    drop(inner);
    // A result that fits in one page keeps nothing.
    let before = store.inner.lock().snapshot_bytes;
    store
        .page(
            filters("all", "all", true, MAX_RECORDS),
            None,
            &request_id(),
        )
        .unwrap();
    assert_eq!(store.inner.lock().snapshot_bytes, before);
}

#[test]
fn six_captured_forms_preserve_wire_fields_and_nulls() {
    let store = store();
    let flow = begin(&store, "tcp");
    flow.step(Some(7), dial_mode());
    flow.step(
        Some(7),
        StepData::Route {
            evaluation_id: "evaluation-1".into(),
            chain: "traffic",
            plane: "userspace",
            rule_id: Some("rule-1".into()),
            rules: [],
            outbound: Some("direct".into()),
            must: false,
            mark: 0,
            input: Some(super::record::RouteInput {
                network: "tcp",
                src_ip: "127.0.0.1".parse().unwrap(),
                src_port: 31000,
                dst_ip: "127.0.0.2".parse().unwrap(),
                dst_port: 443,
                domain: None,
                pname: None,
                src_mac: None,
                dscp: None,
                mark: (),
                ingress: (),
                domain_rule_ids: (),
            }),
            dns_action: (),
        },
    );
    flow.step(
        Some(7),
        StepData::Reroute {
            performed: false,
            reason: "not_required",
            from_evaluation_id: None,
            to_evaluation_id: Some("evaluation-1".into()),
        },
    );
    flow.step(
        Some(7),
        StepData::Outbound {
            attempt_id: "attempt-1".into(),
            status: "failed",
            error: Some(FlowError::DialTimeout),
            attempt: OutboundAttempt {
                parent_attempt_id: None,
                kind: "leaf",
                evaluation_id: Some("evaluation-1".into()),
                routing_source: "evaluation",
                routed_outbound: Some("direct".into()),
                effective_outbound: Some("direct".into()),
                mode_override: "none",
                selection_path: vec![],
                leaf_node_id: "direct-id".into(),
                leaf_node_name: Some("direct".into()),
                target: Some("127.0.0.2:443".into()),
                target_kind: "ip",
                dial_ip: Some("127.0.0.2".parse().unwrap()),
                server_addr: (),
                resolution_location: "original_ip",
            },
        },
    );
    flow.finish("failed", "dial_failed");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    let steps: Vec<_> = detail["trace"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| json!({"stage": step["stage"], "data": step["data"]}))
        .collect();
    assert_eq!(
        steps,
        vec![
            json!({"stage":"input","data":{"source":"socket","values":{
                "src":"127.0.0.1:31000","dst":"127.0.0.2:443","domain":null,"domain_source":null,
                "pid":null,"process_path":null,"src_mac":null,"ingress":null,"domain_rule_ids":null,
                "dscp":null,"mark":null,"pname":null
            }}}),
            json!({"stage":"dial_mode","data":{"configured":"ip","effective_target":"ip",
            "domain":null,"domain_source":null,"verification":"not_required","reason":"original_destination"}}),
            json!({"stage":"route","data":{"evaluation_id":"evaluation-1","chain":"traffic","plane":"userspace",
            "rule_id":"rule-1","rules":[],"outbound":"direct","must":false,"mark":0,"dns_action":null,
            "input":{"network":"tcp","src_ip":"127.0.0.1","src_port":31000,"dst_ip":"127.0.0.2","dst_port":443,
                "domain":null,"pname":null,"src_mac":null,"dscp":null,"mark":null,"ingress":null,"domain_rule_ids":null}}}),
            json!({"stage":"reroute","data":{"performed":false,"reason":"not_required",
            "from_evaluation_id":null,"to_evaluation_id":"evaluation-1"}}),
            json!({"stage":"outbound","data":{"attempt_id":"attempt-1","parent_attempt_id":null,"kind":"leaf",
            "evaluation_id":"evaluation-1","routing_source":"evaluation","routed_outbound":"direct","effective_outbound":"direct",
            "mode_override":"none","selection_path":[],"leaf_node_id":"direct-id","leaf_node_name":"direct",
            "target":"127.0.0.2:443","target_kind":"ip","dial_ip":"127.0.0.2","server_addr":null,
            "resolution_location":"original_ip","status":"failed","error":"dial_timeout"}}),
            json!({"stage":"connection","data":{"state":"failed","reason":"dial_failed","milestone":"terminal",
            "attempt_id":null,"reply_received":null,"error":null}}),
        ]
    );
    let summary = store
        .page(filters("all", "all", false, 100), None, &request_id())
        .unwrap();
    assert!(summary["flows"][0].get("input").is_none());
    assert!(summary["flows"][0].get("trace").is_none());
    let full = store
        .page(filters("all", "all", true, 100), None, &request_id())
        .unwrap();
    assert_eq!(full["flows"][0]["input"], detail["input"]);
    assert!(full["flows"][0].get("trace").is_none());
}

#[test]
fn step_capacity_not_only_string_length_counts_toward_retention() {
    let store = store();
    let flow = begin(&store, "tcp");
    let mut evaluation_id = String::with_capacity(MAX_STEP_BYTES + 1);
    evaluation_id.push_str("evaluation-1");
    flow.step(
        None,
        StepData::Reroute {
            performed: false,
            reason: "not_required",
            from_evaluation_id: Some(evaluation_id),
            to_evaluation_id: None,
        },
    );
    flow.finish("closed", "relay_finished");
    let detail = store.get(flow.id(), &request_id()).unwrap();
    assert_eq!(detail["trace"]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(
        detail["trace"]["missing"],
        json!(["not_instrumented", "buffer_overflow"])
    );
    assert_eq!(detail["state"], "closed");
}
