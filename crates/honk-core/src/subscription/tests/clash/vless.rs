use super::*;
use crate::subscription::clash::options::parse_vless_external_mode;

#[test]
fn test_parse_clash_vless_modes() {
    let yaml = r#"
proxies:
  - name: h2-default
    type: vless
    server: h2.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    smux:
      enabled: true
      padding: false
  - name: h2-padded
    type: vless
    server: padded.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    multiplex:
      enabled: true
      protocol: h2mux
      padding: true
  - name: uot-default
    type: vless
    server: uot-default.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    udp-over-tcp: true
  - name: uot-v2
    type: vless
    server: uot-v2.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    udp_over_tcp:
      enabled: true
      version: 2
  - name: legacy
    type: vless
    server: legacy.example
    port: 443
    uuid: eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
    smux:
      enabled: false
  - name: xudp
    type: vless
    server: xudp.example
    port: 443
    uuid: ffffffff-ffff-4fff-8fff-ffffffffffff
    packet-encoding: xudp
    flow: xtls-rprx-vision
    tls: true
"#;

    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 6);
    assert_eq!(
        nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::H2mux
    );
    assert_eq!(
        nodes[1].vless().unwrap().mode,
        honk_config::node::WireMode::H2muxPadded
    );
    assert_eq!(
        nodes[2].vless().unwrap().mode,
        honk_config::node::WireMode::UotV2
    );
    assert_eq!(
        nodes[3].vless().unwrap().mode,
        honk_config::node::WireMode::UotV2
    );
    assert_eq!(
        nodes[4].vless().unwrap().mode,
        honk_config::node::WireMode::Legacy
    );
    assert_eq!(
        nodes[5].vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );
    assert_eq!(
        nodes[5].vless().unwrap().flow.as_deref(),
        Some("xtls-rprx-vision")
    );
}

#[test]
fn test_external_vless_mode_representations() {
    use honk_config::node::WireMode;

    for (options, expected) in [
        ("{}", WireMode::Legacy),
        ("packet-encoding: ''", WireMode::Legacy),
        ("packet-encoding: none", WireMode::Native),
        ("packet-encoding: legacy", WireMode::Native),
        ("packet_encoding: xudp", WireMode::Xudp),
        ("xudp: true", WireMode::Xudp),
        ("xudp: false", WireMode::Native),
        ("udp: true\nxudp: true", WireMode::Xudp),
        ("udp: true", WireMode::Xudp),
        ("udp: true\npacket-encoding: ''", WireMode::Xudp),
        ("udp: true\npacket-encoding: none", WireMode::Native),
        ("udp: false\npacket-encoding: xudp", WireMode::Xudp),
        (
            "udp: false\nmultiplex: { enabled: true, protocol: h2mux }",
            WireMode::H2mux,
        ),
        (
            "multiplex: { enabled: true, protocol: '', padding: false }",
            WireMode::H2mux,
        ),
        (
            "multiplex: { enabled: true, padding: true }",
            WireMode::H2muxPadded,
        ),
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        assert_eq!(
            parse_vless_external_mode(value.as_mapping().unwrap()).unwrap(),
            expected,
            "{options}"
        );
    }
}

#[test]
fn clash_vless_udp_defaults_to_xudp() {
    let yaml = r#"proxies:
  - name: ordinary
    type: vless
    server: vless.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    udp: true
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(
        nodes[0].vless().unwrap().mode,
        honk_config::node::WireMode::Xudp
    );
}

#[test]
fn clash_vless_udp_gate_is_independent_from_selected_carrier() {
    use honk_config::node::WireMode;

    let yaml = r#"proxies:
  - {name: implicit-legacy, type: vless, server: legacy.example, port: 443, uuid: 00000000-0000-4000-8000-000000000041}
  - {name: source-xudp, type: vless, server: default.example, port: 443, uuid: 00000000-0000-4000-8000-000000000042, udp: true}
  - {name: native-enabled, type: vless, server: native.example, port: 443, uuid: 00000000-0000-4000-8000-000000000043, udp: true, packet-encoding: none}
  - {name: disabled-xudp, type: vless, server: xudp.example, port: 443, uuid: 00000000-0000-4000-8000-000000000044, udp: false, packet-encoding: xudp}
  - {name: disabled-h2mux, type: vless, server: mux.example, port: 443, uuid: 00000000-0000-4000-8000-000000000045, udp: false, multiplex: {enabled: true, protocol: h2mux}}
  - {name: native-vision-tcp, type: vless, server: vision.example, port: 443, uuid: 00000000-0000-4000-8000-000000000046, udp: false, packet-encoding: legacy, flow: xtls-rprx-vision, tls: true}
  - {name: wrapper-precedence, type: vless, server: wrapper.example, port: 443, uuid: 00000000-0000-4000-8000-000000000047, packet-encoding: none, udp-over-tcp: true}
  - {name: rejected-native-vision-udp, type: vless, server: bad-vision.example, port: 443, uuid: 00000000-0000-4000-8000-000000000048, udp: true, packet-encoding: none, flow: xtls-rprx-vision, tls: true}
  - {name: rejected-carrier-conflict, type: vless, server: conflict.example, port: 443, uuid: 00000000-0000-4000-8000-000000000049, packet-encoding: xudp, udp-over-tcp: true}
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "implicit-legacy",
            "source-xudp",
            "native-enabled",
            "disabled-xudp",
            "disabled-h2mux",
            "native-vision-tcp",
            "wrapper-precedence",
        ]
    );
    let modes = nodes
        .iter()
        .map(|node| node.vless().unwrap().mode)
        .collect::<Vec<_>>();
    assert_eq!(
        modes,
        [
            WireMode::Legacy,
            WireMode::Xudp,
            WireMode::Native,
            WireMode::Xudp,
            WireMode::H2mux,
            WireMode::Native,
            WireMode::UotV2,
        ]
    );
    assert!(!nodes[0].vless().unwrap().udp_enabled());
    assert!(nodes[1].vless().unwrap().udp_enabled());
    assert!(nodes[2].vless().unwrap().udp_enabled());
    assert!(!nodes[3].vless().unwrap().udp_enabled());
    assert!(!nodes[4].vless().unwrap().udp_enabled());
    assert!(!nodes[5].vless().unwrap().udp_enabled());
    assert!(nodes[6].vless().unwrap().udp_enabled());
    assert!(nodes.iter().all(|node| node.id == node.derive_id()));
}

#[test]
fn test_rejects_ambiguous_external_vless_modes() {
    for options in [
        "smux: { enabled: true }",
        "multiplex: { enabled: true, protocol: '' }",
        "smux: { enabled: true, protocol: smux }",
        "smux: { enabled: true, protocol: yamux }",
        "udp-over-tcp: { enabled: true, version: 1 }",
        "packet-encoding: packetaddr",
        "packet-encoding: mux-cool",
        "packet-encoding: unsupported",
        "packet-addr: true",
        "mux: true",
        "mux: { enabled: true }",
        "packet-encoding: xudp\nxudp: true",
        "packet-encoding: xudp\npacket_encoding: xudp",
        "packet-encoding: xudp\nsmux: { enabled: true }",
        "xudp: true\nudp-over-tcp: true",
        "smux: { enabled: true, only-tcp: true }",
        "smux: { enabled: true, brutal: { enabled: true } }",
        "smux: { enabled: true, brutal-opts: { enabled: true, up: 100 Mbps } }",
        "smux: { enabled: true, max-connections: 2 }",
        "smux: { enabled: true, min-streams: 1 }",
        "smux: { enabled: true, max-streams: 128 }",
        "smux: { enabled: true }\nudp-over-tcp: true",
    ] {
        let value: serde_yaml::Value = serde_yaml::from_str(options).unwrap();
        let mapping = value.as_mapping().unwrap();
        assert!(
            parse_vless_external_mode(mapping).is_err(),
            "unsupported options must fail: {options}"
        );
    }
}

#[test]
fn test_clash_import_skips_unsupported_vless_mode() {
    let yaml = r#"
proxies:
  - name: unsupported
    type: vless
    server: bad.example
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    packet-encoding: packetaddr
  - name: unsupported-flow
    type: vless
    server: flow.example
    port: 443
    uuid: cccccccc-cccc-4ccc-8ccc-cccccccccccc
    flow: xtls-rprx-vision
    tls: true
    smux:
      enabled: true
  - name: unsupported-encryption
    type: vless
    server: encryption.example
    port: 443
    uuid: dddddddd-dddd-4ddd-8ddd-dddddddddddd
    encryption: mlkem768x25519plus.native.1rtt.key
    udp-over-tcp: true
  - name: valid
    type: vless
    server: good.example
    port: 443
    uuid: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
    udp-over-tcp: true
"#;
    let nodes = parse_clash_subscription(yaml, None).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "valid");
}

#[test]
fn empty_packet_encoding_does_not_shadow_xudp_declaration() {
    for (empty, enabled, expected) in [
        ("", true, honk_config::node::WireMode::Xudp),
        ("  ", false, honk_config::node::WireMode::Native),
    ] {
        let yaml = format!(
            r#"proxies:
  - name: empty-encoding
    type: vless
    server: example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    packet-encoding: '{empty}'
    xudp: {enabled}
"#
        );
        let nodes = parse_clash_subscription(&yaml, None).unwrap();
        assert_eq!(nodes[0].vless().unwrap().mode, expected);
    }
}
