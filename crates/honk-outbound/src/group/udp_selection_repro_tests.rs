use super::*;
use std::time::Duration;

fn nid(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&honk_config::node::NODE_ID_NAMESPACE, name.as_bytes())
}

fn make_node(id: uuid::Uuid, name: &str) -> Node {
    Node {
        id,
        name: name.into(),
        ..Default::default()
    }
}
fn make_group(name: &str, policy: GroupPolicy, ids: Vec<uuid::Uuid>) -> Group {
    Group {
        name: name.into(),
        policy,
        nodes: ids,
        ..Default::default()
    }
}

/// Repro of the gateway scenario: urltest group where one node has a
/// good UDP latency (trojan) and another (anytls, UoT-blackhole) has
/// none. The UDP pick must choose the trojan node, not mirror TCP.
#[test]
fn udp_pick_prefers_node_with_udp_latency_over_mirror() {
    let (t, a) = (nid("trojan"), nid("anytls"));
    let nodes = vec![make_node(t, "trojan"), make_node(a, "anytls")];
    let alive = std::sync::Arc::new(AliveDialerSet::new());
    let m = GroupManager::with_alive_set(
        &[make_group("japan", GroupPolicy::URLTest, vec![t, a])],
        &nodes,
        Some(alive.clone()),
    );
    // anytls: great TCP latency (best TCP), no UDP latency.
    alive.record_probe_latency(
        nid("anytls"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(50),
    );
    // trojan: worse TCP, but has real UDP latency.
    alive.record_probe_latency(
        nid("trojan"),
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(200),
    );
    alive.record_probe_latency(
        nid("trojan"),
        ProbeDomain::DataUdp,
        IpVersion::V4,
        Duration::from_millis(283),
    );

    let udp = m.select_node_for_domain("japan", ProbeDomain::DataUdp, IpVersion::V4);
    assert_eq!(
        udp.unwrap().name,
        "trojan",
        "UDP pick must prefer the node with real UDP latency"
    );
}
