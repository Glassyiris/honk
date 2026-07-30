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
