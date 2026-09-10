use super::*;

#[test]
#[ignore = "isolated real publisher verifier failure probe"]
fn publisher_verifier_rejection() {
    let ids = outbound_ids();
    let mut connection = golden::connection();
    connection.dst_ip = "192.0.2.1".parse().unwrap();
    connection.src_ip = "198.51.100.1".parse().unwrap();
    connection.mac = Some("02:00:00:00:00:01".into());
    let kept = rule("kept-facts", honk_config::routing::RoutingCondition {
        domain: vec!["kept.test".into()],
        ip: vec!["192.0.2.1".into()],
        source_ip: vec!["198.51.100.1".into()],
        mac: vec!["02:00:00:00:00:01".into()],
        ..Default::default()
    }, "proxy", 0xec5, true);
    let original_router = Router::new(&[kept], "block").unwrap();
    let original = RoutingPushPlan::compile(&original_router, &ids, "block", DialMode::Domain).unwrap();
    let learned = [domain_entry(&original_router, &connection, "kept.test")];
    let mut backend = RealEbpfBackend::load_routing_test_fixture(&object()).unwrap();
    let input = input(&connection);
    let mut evidence = Vec::new();
    let mut rejected_by_verifier = false;
    for count in [16, 64, 256, 512, 1024] {
        backend.publish_routing_plan(&original, &learned).unwrap();
        let expected = backend.run_routing_test(&input).unwrap();
        assert_eq!(expected.status, 0);
        assert_eq!(expected.decision, decision(2, 0xec5, true, 1, 0));
        let slot = backend.active_routing_generation().unwrap();
        let rules = (0..count).map(|index| honk_config::routing::RoutingRule {
            name: format!("verifier-pressure-{index}"),
            condition: honk_config::routing::RoutingCondition {
                process_name: vec![format!("abcdefg{index:07}")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("proxy".into()),
            priority: 0, mark: index, must: false,
        }).collect::<Vec<_>>();
        let router = Router::new(&rules, "block").unwrap();
        let candidate = RoutingPushPlan::compile(&router, &ids, "block", DialMode::Ip).unwrap();
        let descriptors_before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        match backend.publish_routing_plan(&candidate, &[]) {
            Ok(()) => evidence.push(serde_json::json!({"rules":count,"published":true})),
            Err(error) => {
                let description = format!("{error:#}");
                assert_eq!(backend.active_routing_generation().unwrap(), slot);
                assert_eq!(backend.run_routing_test(&input).unwrap(), expected);
                let descriptors_after = std::fs::read_dir("/proc/self/fd").unwrap().count();
                assert_eq!(descriptors_before, descriptors_after, "failed publication retained candidate FDs");
                rejected_by_verifier = description.contains("BPF_PROG_LOAD EXT");
                evidence.push(serde_json::json!({"rules":count,"published":false,"error":description,"old_slot_preserved":true,"old_complete_decision_preserved":true,"candidate_fd_count_delta":0}));
                break;
            }
        }
    }
    let result = serde_json::json!({"actual_publisher_called":true,"verifier_rejection_observed":rejected_by_verifier,"attempts":evidence});
    std::fs::write(std::env::var("HONK_CSE_PUBLICATION_RESULTS").unwrap(), serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    assert!(rejected_by_verifier, "probe did not reach an actual publisher verifier rejection");
}
