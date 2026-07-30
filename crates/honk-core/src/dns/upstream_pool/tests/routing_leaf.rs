use honk_config::group::GroupPolicy;
use honk_outbound::group::GroupManager;

use super::*;

#[test]
fn resolve_outbound_leaf_node_by_name() {
    let node = test_node("hk-1");
    let pool =
        UpstreamPool::new_with_proxy(&[], make_router(), None, vec![node.clone()], vec![]).unwrap();
    let leaf = pool.resolve_outbound_leaf("hk-1").unwrap();
    assert_eq!(leaf.name, "hk-1");
    assert!(pool.resolve_outbound_leaf("direct").is_none());
    assert!(pool.resolve_outbound_leaf("missing").is_none());
}

#[test]
fn resolve_outbound_group_uses_group_manager_selector() {
    let alpha = test_node("alpha");
    let beta = test_node("beta");
    let mut group = test_group("proxy", GroupPolicy::Selector, vec![alpha.id, beta.id]);
    group.default = Some("beta".into());
    let group_manager = GroupManager::new(&[group], &[alpha.clone(), beta.clone()]).into_shared();
    group_manager.read().set_selector_choice("proxy", "alpha");
    let upstream = DnsUpstream {
        outbound: Some("proxy".into()),
        ..make_upstream("google", "dns.google/dns-query", DnsProtocol::Https)
    };
    let pool =
        UpstreamPool::new_with_proxy(&[upstream], make_router(), None, vec![alpha, beta], vec![])
            .unwrap()
            .with_group_manager(group_manager);

    assert_eq!(pool.resolve_outbound_leaf("proxy").unwrap().name, "alpha");
    pool.group_manager
        .read()
        .as_ref()
        .unwrap()
        .read()
        .set_selector_choice("proxy", "beta");
    assert_eq!(pool.resolve_outbound_leaf("proxy").unwrap().name, "beta");
}

#[test]
fn resolve_outbound_group_without_gm_uses_first_member() {
    let first = test_node("first");
    let second = test_node("second");
    let group = test_group("proxy", GroupPolicy::URLTest, vec![first.id, second.id]);
    let pool =
        UpstreamPool::new_with_proxy(&[], make_router(), None, vec![first, second], vec![group])
            .unwrap();
    assert_eq!(pool.resolve_outbound_leaf("proxy").unwrap().name, "first");
}
