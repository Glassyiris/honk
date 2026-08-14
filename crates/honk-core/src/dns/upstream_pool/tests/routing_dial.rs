use std::sync::Arc;

use honk_config::group::GroupPolicy;
use honk_config::routing::{RoutingCondition, RoutingOutbound, RoutingRule};
use honk_outbound::group::GroupManager;
use tokio::sync::RwLock;

use super::*;
use crate::routing::Router;

fn route(ip: &str, outbound: &str) -> RoutingRule {
    RoutingRule {
        name: "dns-route".into(),
        condition: RoutingCondition {
            ip: vec![ip.into()],
            ..Default::default()
        },
        outbound: RoutingOutbound::Simple(outbound.into()),
        priority: 0,
        must: false,
        mark: 0,
    }
}

#[test]
fn dial_context_pins_its_outbound_runtime_generation() {
    let node = test_node("dns-proxy");
    let generation = Arc::new(
        honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
            .unwrap(),
    );
    let upstream = make_upstream("proxy", "1.1.1.1:53", DnsProtocol::Tcp);
    let pool = UpstreamPool::new_with_proxy(
        &[upstream],
        make_router(),
        Some(Arc::new(
            crate::proxy::ProxyRegistry::default_resolver().unwrap(),
        )),
        vec![node.clone()],
        vec![],
    )
    .unwrap()
    .with_runtime_generation(Arc::clone(&generation));

    let entry = pool.entries.get("proxy").unwrap();
    let context = pool.dial_context(entry, Some(&node), "1.1.1.1:53".parse().unwrap());
    let captured = context
        .proxy
        .and_then(|proxy| proxy.generation)
        .expect("proxy dial must capture the owning DNS generation");
    assert!(Arc::ptr_eq(&captured, &generation));
}

#[tokio::test]
async fn resolve_dial_leaf_forced_arrow_bypasses_traffic_router() {
    let forced = test_node("forced-node");
    let routed = test_node("routed-node");
    let forced_group = test_group("force_g", GroupPolicy::Selector, vec![forced.id]);
    let routed_group = test_group("route_g", GroupPolicy::Selector, vec![routed.id]);
    let group_manager = GroupManager::new(
        &[forced_group, routed_group],
        &[forced.clone(), routed.clone()],
    )
    .into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("8.8.8.8/32", "route_g")], "direct").unwrap(),
    ));
    let upstream = DnsUpstream {
        outbound: Some("force_g".into()),
        ..make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new_with_proxy(
        &[upstream],
        make_router(),
        None,
        vec![forced, routed],
        vec![],
    )
    .unwrap()
    .with_group_manager(group_manager)
    .with_traffic_router(traffic);

    let entry = pool.entries.get("google").unwrap();
    let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
    assert_eq!(leaf.name, "forced-node");
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_uses_traffic_router() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Selector, vec![node.id]);
    let group_manager = GroupManager::new(&[group], std::slice::from_ref(&node)).into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("8.8.8.8/32", "proxy")], "direct").unwrap(),
    ));
    let upstream = make_upstream("google", "8.8.8.8:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node], vec![])
        .unwrap()
        .with_group_manager(group_manager)
        .with_traffic_router(traffic);

    let entry = pool.entries.get("google").unwrap();
    let leaf = pool.resolve_dial_leaf(entry).await.unwrap().unwrap();
    assert_eq!(leaf.name, "proxy-leaf");
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_direct_when_route_is_direct() {
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("223.5.5.5/32", "direct")], "proxy").unwrap(),
    ));
    let upstream = make_upstream("alidns", "223.5.5.5:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![], vec![])
        .unwrap()
        .with_traffic_router(traffic);

    let entry = pool.entries.get("alidns").unwrap();
    assert!(pool.resolve_dial_leaf(entry).await.unwrap().is_none());
}

#[tokio::test]
async fn resolve_dial_leaf_implicit_default_fallback() {
    let traffic = Arc::new(RwLock::new(Router::new(&[], "direct").unwrap()));
    let upstream = make_upstream("any", "1.1.1.1:53", DnsProtocol::Udp);
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![], vec![])
        .unwrap()
        .with_traffic_router(traffic);

    let entry = pool.entries.get("any").unwrap();
    assert!(pool.resolve_dial_leaf(entry).await.unwrap().is_none());
}

#[cfg(feature = "honk-policy")]
#[tokio::test]
async fn forced_honk_route_keeps_target_and_nested_attribution() {
    let node = test_node("proxy-leaf");
    let child = test_group("child", GroupPolicy::Honk, vec![node.id]);
    let mut parent = test_group("parent", GroupPolicy::Honk, vec![]);
    parent.groups.push("child".into());
    let manager = Arc::new(GroupManager::new(
        &[parent, child],
        std::slice::from_ref(&node),
    ));
    let upstream = DnsUpstream {
        outbound: Some("parent".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp)
    };
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager_snapshot(manager);

    let route = pool
        .resolve_dial_route(&pool.entries["google"])
        .await
        .unwrap();
    assert_eq!(route.target, "192.0.2.53:53".parse().unwrap());
    assert_eq!(route.node.unwrap().id, node.id);
    let feedback = route.feedback.expect("honk attribution");
    assert_eq!(
        feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["parent", "child"]
    );
}

#[cfg(feature = "honk-policy")]
#[tokio::test]
async fn tcp_fallback_keeps_selected_honk_group_chain() {
    let node = test_node("shared-leaf");
    let selected = test_group("selected", GroupPolicy::Honk, vec![node.id]);
    let unrelated = test_group("unrelated", GroupPolicy::Honk, vec![node.id]);
    let manager = Arc::new(GroupManager::new(
        &[selected, unrelated],
        std::slice::from_ref(&node),
    ));
    let upstream = DnsUpstream {
        outbound: Some("selected".into()),
        ..make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp)
    };
    let pool = UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node], vec![])
        .unwrap()
        .with_group_manager_snapshot(manager);
    let entry = &pool.entries["google"];
    let route = pool.resolve_dial_route(entry).await.unwrap();
    assert_eq!(
        route
            .feedback
            .as_ref()
            .unwrap()
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["selected"]
    );
    let feedback = pool.tcp_feedback_for_route(entry, &route).unwrap();
    assert_eq!(
        feedback
            .attributions()
            .iter()
            .map(|attribution| attribution.group.as_str())
            .collect::<Vec<_>>(),
        ["selected"]
    );
    assert_eq!(
        feedback.context().network,
        honk_outbound::group::SelectionNetwork::Tcp
    );
    assert_eq!(
        feedback.context().probe_domain,
        honk_outbound::alive::ProbeDomain::Tcp
    );
}

#[cfg(feature = "honk-policy")]
#[tokio::test]
async fn implicit_honk_route_keeps_target_and_attribution() {
    let node = test_node("proxy-leaf");
    let group = test_group("proxy", GroupPolicy::Honk, vec![node.id]);
    let manager = GroupManager::new(&[group], std::slice::from_ref(&node)).into_shared();
    let traffic = Arc::new(RwLock::new(
        Router::new(&[route("192.0.2.53/32", "proxy")], "direct").unwrap(),
    ));
    let upstream = make_upstream("google", "192.0.2.53:53", DnsProtocol::Udp);
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![node.clone()], vec![])
            .unwrap()
            .with_group_manager(manager)
            .with_traffic_router(traffic);

    let route = pool
        .resolve_dial_route(&pool.entries["google"])
        .await
        .unwrap();
    assert_eq!(route.target, "192.0.2.53:53".parse().unwrap());
    assert_eq!(route.node.unwrap().id, node.id);
    assert_eq!(route.feedback.unwrap().attributions()[0].group, "proxy");
}
