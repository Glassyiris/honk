use super::*;
use honk_config::node::Node;

fn fixture() -> Config {
    let mut config = Config::default();
    config.nodes = (1..=3)
        .map(|number| Node {
            id: Uuid::from_u128(number),
            name: format!("node-{number}"),
            ..Default::default()
        })
        .collect();
    config.groups = vec![
        Group {
            name: "parent".into(),
            nodes: vec![config.nodes[0].id],
            groups: vec!["child".into()],
            ..Default::default()
        },
        Group {
            name: "child".into(),
            nodes: vec![config.nodes[1].id, config.nodes[2].id],
            ..Default::default()
        },
    ];
    config
}

async fn body(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), MAX_SNAPSHOT_BYTES + 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn capture(config: &Config, catalog: &Catalog, filter: Option<&str>) -> NodeSnapshot {
    node_snapshot(
        config,
        &GroupManager::new(&config.groups, &config.nodes),
        &catalog.snapshot(),
        &AliveDialerSet::new(),
        "instance",
        filter,
        &RequestId("request".into()),
    )
    .unwrap()
}

#[test]
fn identities_survive_reordering_but_not_removal_or_restart() {
    let mut config = fixture();
    let catalog = Catalog::new(&config);
    let original = catalog.snapshot();
    config.groups.reverse();
    for group in &mut config.groups {
        group.id = Uuid::new_v4();
    }
    config.experimental.native_api.secret = "not part of a group revision".into();
    catalog.install(&config);
    assert_eq!(catalog.snapshot().revision, original.revision);
    assert_eq!(catalog.snapshot().groups, original.groups);

    config.groups[0].tolerance += 1;
    catalog.install(&config);
    assert_ne!(catalog.snapshot().revision, original.revision);
    assert_eq!(catalog.snapshot().groups, original.groups);

    let removed = config.groups.remove(0);
    catalog.install(&config);
    assert!(!catalog.snapshot().groups.contains_key(&removed.name));
    config.groups.push(removed);
    catalog.install(&config);
    assert_ne!(catalog.snapshot().groups["child"], original.groups["child"]);
    assert_eq!(
        catalog.snapshot().groups["parent"],
        original.groups["parent"]
    );
    assert_ne!(
        Catalog::new(&config).snapshot().groups["parent"],
        original.groups["parent"]
    );
}

#[test]
fn revision_and_members_follow_effective_duplicate_and_cycle_rules() {
    let mut config = fixture();
    let mut shadow = config.groups[0].clone();
    shadow.nodes.clear();
    config.groups.insert(0, shadow);
    config.groups[2].groups.push("parent".into());
    let catalog = Catalog::new(&config);
    let original = catalog.snapshot();
    config.groups[0].tolerance += 1;
    catalog.install(&config);
    assert_eq!(catalog.snapshot().revision, original.revision);
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let effective = GroupManager::native_effective_groups(&config.groups);
    for (name, group) in &effective {
        assert_eq!(manager.native_group(name).unwrap(), group);
    }
    let before = catalog.snapshot().revision.clone();
    config.groups[1].nodes.push(config.nodes[2].id);
    catalog.install(&config);
    assert_ne!(catalog.snapshot().revision, before);
}

#[tokio::test]
async fn pages_freeze_rows_and_bind_instance_and_direct_group_filter() {
    let mut config = fixture();
    config.nodes[1].name = config.nodes[0].name.clone();
    let catalog = Catalog::new(&config);
    let identity = catalog.snapshot();
    let request = RequestId("request".into());
    let parent = &identity.groups["parent"];
    let parent_page = body(
        catalog
            .page(capture(&config, &catalog, Some(parent)), 100, &request)
            .unwrap(),
    )
    .await;
    assert_eq!(
        parent_page["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![config.nodes[0].id.to_string()]
    );

    let child = &identity.groups["child"];
    let first = body(
        catalog
            .page(capture(&config, &catalog, Some(child)), 1, &request)
            .unwrap(),
    )
    .await;
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(
        catalog
            .resume(cursor, "other-instance", Some(child), 1, &request)
            .is_err()
    );
    assert!(
        catalog
            .resume(cursor, "instance", Some(parent), 1, &request)
            .is_err()
    );
    assert!(
        catalog
            .resume(cursor, "instance", None, 1, &request)
            .is_err()
    );
    config.nodes[2].name = "new-name".into();
    config.groups.clear();
    catalog.install(&config);
    let second = body(
        catalog
            .resume(cursor, "instance", Some(child), 100, &request)
            .unwrap(),
    )
    .await;
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["nodes"][0]["name"], "node-3");
    assert_eq!(second["nodes"][0]["group_ids"], json!([child]));
    assert_eq!(second["next_cursor"], Value::Null);
    catalog.snapshots.lock()[0].created = Instant::now() - SNAPSHOT_TTL;
    let error = catalog
        .resume(cursor, "instance", Some(child), 1, &request)
        .unwrap_err()
        .into_response();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn snapshot_count_and_byte_caps_evict_old_cursors_and_reject_oversized_rows() {
    let mut config = fixture();
    let catalog = Catalog::new(&config);
    let request = RequestId("request".into());
    let first = body(
        catalog
            .page(capture(&config, &catalog, None), 1, &request)
            .unwrap(),
    )
    .await;
    for _ in 0..MAX_SNAPSHOTS {
        catalog
            .page(capture(&config, &catalog, None), 1, &request)
            .unwrap();
    }
    assert_eq!(catalog.snapshots.lock().len(), MAX_SNAPSHOTS);
    assert!(
        catalog
            .resume(
                first["next_cursor"].as_str().unwrap(),
                "instance",
                None,
                1,
                &request
            )
            .is_err()
    );

    config.nodes[0].name = "x".repeat(MAX_SNAPSHOT_BYTES / 2);
    let first_large = body(
        catalog
            .page(capture(&config, &catalog, None), 1, &request)
            .unwrap(),
    )
    .await;
    catalog
        .page(capture(&config, &catalog, None), 1, &request)
        .unwrap();
    assert!(
        catalog
            .snapshots
            .lock()
            .iter()
            .map(|snapshot| snapshot.bytes)
            .sum::<usize>()
            <= MAX_SNAPSHOT_BYTES
    );
    assert!(
        catalog
            .resume(
                first_large["next_cursor"].as_str().unwrap(),
                "instance",
                None,
                1,
                &request
            )
            .is_err()
    );

    config.nodes[0].name = "x".repeat(MAX_SNAPSHOT_BYTES);
    let response = node_snapshot(
        &config,
        &GroupManager::new(&config.groups, &config.nodes),
        &catalog.snapshot(),
        &AliveDialerSet::new(),
        "instance",
        None,
        &request,
    )
    .err()
    .unwrap()
    .into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body(response).await["error"]["code"],
        "snapshot_unavailable"
    );
}

#[test]
fn projections_keep_duplicate_names_and_nested_member_identity_separate() {
    let mut config = fixture();
    config.nodes[0].name = "same".into();
    config.nodes[1].name = "same".into();
    config.groups[0].nodes.push(config.nodes[1].id);
    config.groups[0].default = Some("child".into());
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let value = group_value(
        &manager,
        manager.native_group("parent").unwrap(),
        &identity,
        &AliveDialerSet::new(),
        true,
    );
    assert_eq!(
        value["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string(),
            identity.groups["child"].clone()
        ]
    );
    assert_eq!(
        value["runtime"]["selection"]["tcp"]["member_id"],
        identity.groups["child"]
    );
    assert_eq!(
        value["runtime"]["selection"]["tcp"]["resolved_leaf_node_id"],
        config.nodes[1].id.to_string()
    );
    assert_eq!(
        value["config"]["default_member_id"],
        identity.groups["child"]
    );

    config.groups[0].policy = GroupPolicy::Fallback;
    let manager = GroupManager::new(&config.groups, &config.nodes);
    assert_eq!(
        manager.select_node("parent").unwrap().id,
        config.nodes[0].id
    );
    assert!(
        manager
            .native_selection("parent", SelectionNetwork::Tcp)
            .is_none()
    );
}

#[test]
fn native_reads_do_not_rotate_load_balance_wake_urltest_or_train_score() {
    let mut config = fixture();
    config.groups = [
        GroupPolicy::LoadBalance,
        GroupPolicy::URLTest,
        GroupPolicy::Score,
    ]
    .into_iter()
    .map(|policy_kind| Group {
        name: policy(policy_kind).into(),
        policy: policy_kind,
        nodes: config.nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    })
    .collect();
    let alive = Arc::new(AliveDialerSet::new());
    alive.register_urltest_group(
        "urltest",
        &config.groups[1].nodes,
        Some(Duration::from_secs(60)),
    );
    let manager = GroupManager::with_alive_set(&config.groups, &config.nodes, Some(alive.clone()));
    let untouched = GroupManager::with_alive_set(
        &config.groups,
        &config.nodes,
        Some(Arc::new(AliveDialerSet::new())),
    );
    let identity = Catalog::new(&config).snapshot();
    let counters = manager.score_reason_snapshot();
    let cache = manager.score_cache_snapshot();
    for _ in 0..20 {
        for group in &config.groups {
            group_value(&manager, group, &identity, &alive, true);
        }
    }
    assert!(alive.is_urltest_group_idle("urltest"));
    assert!(
        manager
            .native_selection("urltest", SelectionNetwork::Tcp)
            .is_none()
    );
    assert_eq!(manager.score_reason_snapshot(), counters);
    assert_eq!(manager.score_cache_snapshot(), cache);
    for _ in 0..8 {
        for group in ["loadbalance", "score"] {
            assert_eq!(
                manager.select_node(group).unwrap().id,
                untouched.select_node(group).unwrap().id
            );
        }
    }
}

#[test]
fn cold_nested_selection_keeps_member_without_inventing_leaf() {
    let mut config = fixture();
    config.groups[0].default = Some("child".into());
    config.groups[1].policy = GroupPolicy::URLTest;
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let value = selection(
        &manager,
        manager.native_group("parent").unwrap(),
        SelectionNetwork::Tcp,
        &identity,
    );
    assert_eq!(value["member_id"], identity.groups["child"]);
    assert_eq!(value["resolved_leaf_node_id"], Value::Null);
}

#[test]
fn check_urls_remove_userinfo_and_fragments_without_rewriting_request_target() {
    let group = Group {
        check_url: Some("https://user:password@example.com:8443/a/../probe?round=1#private".into()),
        ..Default::default()
    };
    assert_eq!(
        check_url(&group).as_deref(),
        Some("https://example.com:8443/a/../probe?round=1")
    );
    assert_eq!(
        check_url(&Group {
            check_url: Some("file:///private/path".into()),
            ..Default::default()
        }),
        None
    );
}

#[test]
fn native_probe_context_keeps_exact_members_without_expanding_probe_set() {
    let mut config = fixture();
    config.nodes[0].name = "child".into();
    config.nodes[1].name = "child".into();
    config.groups[0].nodes.push(config.nodes[1].id);
    config.groups[1].default = Some("node-3".into());
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let probes = manager.native_delay_test_members("parent");
    assert_eq!(
        probes
            .iter()
            .map(|(member, _)| member_id(*member, &identity).unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string(),
            identity.groups["child"].clone()
        ]
    );
    assert_eq!(
        probes.iter().map(|(_, leaf)| leaf.id).collect::<Vec<_>>(),
        vec![config.nodes[0].id, config.nodes[1].id, config.nodes[2].id]
    );
    assert_eq!(
        probes.iter().map(|(_, leaf)| leaf.id).collect::<Vec<_>>(),
        manager
            .delay_test_members("parent")
            .iter()
            .map(|(_, leaf)| leaf.id)
            .collect::<Vec<_>>()
    );
    manager
        .set_selector_choice(
            "child",
            "child",
            honk_outbound::group::SelectorNetworks::Both,
        )
        .unwrap();
    let probes = manager.native_delay_test_members("parent");
    assert_eq!(
        probes
            .iter()
            .map(|(member, _)| member_id(*member, &identity).unwrap())
            .collect::<Vec<_>>(),
        vec![
            config.nodes[0].id.to_string(),
            config.nodes[1].id.to_string()
        ]
    );
    assert_eq!(probes.len(), manager.delay_test_members("parent").len());
}

#[test]
fn group_health_falls_back_by_member_and_full_measurement_key() {
    use honk_outbound::alive::{
        HealthMeasurement, HealthPurpose, HealthState, HealthTransport, HealthWarmth,
        NativeGroupProbeContext, ProbeDomain,
    };

    let mut config = fixture();
    let node = &config.nodes[0];
    for (name, check_url) in [
        ("other", None),
        ("custom", Some("https://example.test/".into())),
    ] {
        config.groups.push(Group {
            name: name.into(),
            nodes: vec![node.id],
            check_url,
            ..Default::default()
        });
    }
    let manager = GroupManager::new(&config.groups, &config.nodes);
    let identity = Catalog::new(&config).snapshot();
    let alive = AliveDialerSet::new();
    alive.enable_native_observations();
    alive.register_node(node.id, node.name.clone(), "127.0.0.1:1".into());
    let ticket = alive.native_probe_ticket(node.id);
    let tcp = NativeHealthObservation::probe(
        ProbeDomain::Tcp,
        HealthMeasurement::TcpConnect,
        IpVersion::V4,
        Some(Duration::from_millis(12)),
        SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    );
    let http = NativeHealthObservation {
        measurement: HealthMeasurement::HttpHeaders,
        ..tcp
    };
    let dns = NativeHealthObservation {
        measurement: HealthMeasurement::DnsRoundTrip,
        purpose: HealthPurpose::Dns,
        ..tcp
    };
    let udp_dns = NativeHealthObservation {
        transport: HealthTransport::Udp,
        ..dns
    };
    let global = [
        tcp,
        http,
        NativeHealthObservation {
            warmth: HealthWarmth::Warm,
            ..http
        },
        NativeHealthObservation {
            ip_version: IpVersion::V6,
            ..http
        },
        dns,
        udp_dns,
        NativeHealthObservation {
            purpose: HealthPurpose::Data,
            ..udp_dns
        },
    ];
    for sample in global {
        assert!(alive.complete_native_probe(&ticket, None, sample));
    }
    for sample in [http, udp_dns] {
        assert!(alive.complete_native_probe(
            &ticket,
            Some(NativeGroupProbeContext {
                group_id: identity.groups["parent"].parse().unwrap(),
                member_id: node.id,
            }),
            NativeHealthObservation {
                state: HealthState::Unavailable,
                latency: None,
                error: Some("probe_failed"),
                ..sample
            },
        ));
    }
    let rows = group_health(
        &manager,
        manager.native_group("parent").unwrap(),
        &identity,
        &alive,
    );
    assert_eq!(rows.len(), global.len());
    for row in &rows {
        assert_eq!(row["member_id"], node.id.to_string());
        assert_eq!(row["resolved_leaf_node_id"], node.id.to_string());
        let scoped = row["ip_version"] == "ipv4"
            && row["warmth"] == "cold"
            && (row["measurement"] == "http_headers"
                || row["transport"] == "udp" && row["purpose"] == "dns");
        assert_eq!(row["state"], if scoped { "unavailable" } else { "healthy" });
        assert_eq!(
            row["latency_ms"],
            if scoped { Value::Null } else { json!(12.0) }
        );
    }
    for sample in global {
        assert!(rows.iter().any(|row| {
            row["transport"] == json!(sample.transport)
                && row["purpose"] == json!(sample.purpose)
                && row["measurement"] == json!(sample.measurement)
                && row["ip_version"]
                    == if sample.ip_version == IpVersion::V4 {
                        "ipv4"
                    } else {
                        "ipv6"
                    }
                && row["warmth"] == json!(sample.warmth)
        }));
    }
    let other = group_health(
        &manager,
        manager.native_group("other").unwrap(),
        &identity,
        &alive,
    );
    assert_eq!(other.len(), global.len());
    assert!(
        other
            .iter()
            .all(|row| row["state"] == "healthy" && row["latency_ms"] == json!(12.0))
    );
    assert!(
        group_health(
            &manager,
            manager.native_group("custom").unwrap(),
            &identity,
            &alive
        )
        .is_empty()
    );
    assert_eq!(alive.native_observations(node.id), global);
}
