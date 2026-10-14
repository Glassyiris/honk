use honk_config::{Config, node::Node};

/// A structured configuration written before an identity change names its
/// nodes by the old stored ID; loading re-derives the ID and the group
/// member must follow instead of dangling.
#[test]
fn group_members_follow_a_node_to_its_rederived_id() {
    let node = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=uot-v2#uot",
    )
    .unwrap();
    let stale = uuid::Uuid::from_u128(1);
    assert_ne!(node.id, stale);
    let mut value = serde_json::to_value(&node).unwrap();
    value["id"] = serde_json::json!(stale);
    let source = serde_json::json!({
        "nodes": [value],
        "groups": [{"name": "pool", "nodes": [stale]}],
    })
    .to_string();

    let config = Config::from_json_str(&source).unwrap();
    assert_eq!(config.nodes[0].id, node.id);
    assert_eq!(config.groups[0].nodes, vec![node.id]);
    config.validate_detailed().unwrap();
}

/// Two nodes storing the same ID, one of which keeps it: the reference no
/// longer says which node it meant, so the member must not move to the
/// node that was re-derived away from it.
#[test]
fn group_member_is_not_redirected_by_a_stale_duplicate_of_a_live_id() {
    let holder = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000001@a.example.com:443#holder",
    )
    .unwrap();
    let stale = Node::from_share_link(
        "vless://00000000-0000-0000-0000-000000000002@b.example.com:443?packetEncoding=uot-v2#stale",
    )
    .unwrap();
    let mut stale_value = serde_json::to_value(&stale).unwrap();
    stale_value["id"] = serde_json::json!(holder.id);
    let source = serde_json::json!({
        "nodes": [serde_json::to_value(&holder).unwrap(), stale_value],
        "groups": [{"name": "pool", "nodes": [holder.id]}],
    })
    .to_string();

    let config = Config::from_json_str(&source).unwrap();
    assert_eq!(config.nodes[0].id, holder.id);
    assert_eq!(config.nodes[1].id, stale.id);
    assert_eq!(config.groups[0].nodes, vec![holder.id]);
}
