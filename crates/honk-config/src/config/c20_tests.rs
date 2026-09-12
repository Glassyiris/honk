use super::*;
use crate::node::{Node, OutboundConfig};

#[test]
fn c20_config_admission_preserves_canonical_identity() {
    let mut canonical = Node {
        name: "endpoint".into(),
        address: "192.0.2.10:1080".into(),
        host: "192.0.2.10".into(),
        port: 1080,
        outbound: OutboundConfig::Socks5(Default::default()),
        ..Default::default()
    };
    canonical.id = canonical.derive_id();
    let config = Config {
        nodes: vec![
            canonical.clone(),
            Config::builtin_direct_node(),
            Config::builtin_block_node(),
        ],
        ..Default::default()
    };
    config.validate().unwrap();

    let mut stale = canonical.clone();
    stale.host = "192.0.2.11".into();
    stale.address = "192.0.2.11:1080".into();
    let mut nil = canonical.clone();
    nil.id = uuid::Uuid::nil();
    let mut second_id = canonical.clone();
    second_id.id = uuid::Uuid::new_v4();
    let mut wrong_builtin = Config::builtin_direct_node();
    wrong_builtin.id = uuid::Uuid::new_v4();
    for nodes in [
        vec![stale],
        vec![nil],
        vec![canonical.clone(), second_id],
        vec![canonical.clone(), canonical],
        vec![wrong_builtin],
    ] {
        assert!(
            Config {
                nodes,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}
