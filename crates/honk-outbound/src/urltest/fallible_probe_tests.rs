use super::*;

#[test]
fn try_probe_runtime_rejects_stale_id_before_warm_lookup() {
    let mut node = Node::from_share_link("socks5://127.0.0.1:1080").unwrap();
    let generation =
        crate::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node)).unwrap();
    node.port += 1;
    let error =
        try_probe_runtime(&generation, &node, crate::proxy::WarmRequirement::Session).unwrap_err();
    let crate::runtime::RuntimeRegistryError::Admission(error) = error else {
        panic!("expected node admission error");
    };
    assert_eq!(error.diagnostic.code, "noncanonical-node-id");
}
