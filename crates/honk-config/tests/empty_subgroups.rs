use honk_config::{
    Config,
    parser::{parse_dae_config_with_detailed_diagnostics, resolve_group_filters},
};

#[test]
fn explicit_empty_contributions_survive_roundtrip_and_refresh() {
    let mut diagnostics = Vec::new();
    let config = parse_dae_config_with_detailed_diagnostics("node {\n edge: 'socks5://127.0.0.1:1080'\n}\nsubscription {\n paid: 'https://example.test/sub'\n}\ngroup {\n empty { filter: group() }\n blank { filter: }\n nested { filter: group(empty) }\n late { filter: subtag(paid) }\n sibling {\n filter: group()\n filter: name(edge)\n final: direct\n }\n}", &mut diagnostics).unwrap();
    assert!(config.groups[..4].iter().all(|g| g.nodes.is_empty()));
    assert_eq!(config.groups[4].nodes, [config.nodes[0].id]);
    assert_eq!(config.groups[4].final_outbound.as_deref(), Some("direct"));
    assert_eq!(
        diagnostics
            .iter()
            .filter(|d| d.code == "empty-subgroup")
            .count(),
        2
    );
    assert_eq!(config.groups[0].filters, ["group()"]);
    for mut restored in [
        serde_json::from_str::<Config>(&serde_json::to_string(&config).unwrap()).unwrap(),
        serde_yaml::from_str::<Config>(&serde_yaml::to_string(&config).unwrap()).unwrap(),
        toml::from_str::<Config>(&toml::to_string(&config).unwrap()).unwrap(),
    ] {
        restored.nodes[0].subscription_id = Some(restored.subscriptions[0].id);
        resolve_group_filters(
            &mut restored.groups,
            &restored.nodes,
            &restored.subscriptions,
        );
        assert!(restored.groups[..3].iter().all(|g| g.nodes.is_empty()));
        assert_eq!(restored.groups[2].groups, ["empty"]);
        assert_eq!(restored.groups[3].nodes, [restored.nodes[0].id]);
        restored.nodes[0].subscription_id = None;
        resolve_group_filters(
            &mut restored.groups,
            &restored.nodes,
            &restored.subscriptions,
        );
        assert!(restored.groups[..4].iter().all(|g| g.nodes.is_empty()));
        assert_eq!(restored.groups[4].nodes, [restored.nodes[0].id]);
    }
}
