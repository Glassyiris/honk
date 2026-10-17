use super::*;
use aya::maps::IterableMap;
use honk_ebpf_common::{
    FlowMapValue,
    conn::{ConnState, TCP_SYN_ORIGINAL_INTERCEPT},
};

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn failed_syn_publication_retries_but_committed_metadata_loss_refuses() {
    isolated(|| {
        for (src, dst) in PEERS {
            for side in ["lan_ingress_l2", "wan_egress_l2"] {
                for name in ["ROUTING_HANDOFF_MAP", "REDIRECT_TRACK"] {
                    let (mut backend, _, _listeners) = publish(&[rule(
                        "unmarked-proxy",
                        RoutingCondition {
                            port: vec!["443".into()],
                            ..Default::default()
                        },
                        "proxy",
                        0,
                        false,
                    )]);
                    let capacity = if name == "ROUTING_HANDOFF_MAP" {
                        backend
                            .hash_map::<TuplesKey, FlowMapValue<RoutingHandoffEntry>>(name)
                            .unwrap()
                            .map()
                            .info()
                            .unwrap()
                            .max_entries()
                    } else {
                        backend
                            .hash_map::<RedirectTuple, FlowMapValue<RedirectEntry>>(name)
                            .unwrap()
                            .map()
                            .info()
                            .unwrap()
                            .max_entries()
                    };
                    let filler = |index: u32| TuplesKey {
                        src_port: index as u16,
                        dst_port: (index >> 16) as u16,
                        l4proto: IPPROTO_UDP,
                        ..Default::default()
                    };
                    for index in 0..capacity {
                        let key = filler(index);
                        if name == "ROUTING_HANDOFF_MAP" {
                            backend
                                .flow_insert(name, &key, &RoutingHandoffEntry::default())
                                .unwrap();
                        } else {
                            backend
                                .flow_insert(
                                    name,
                                    &RedirectTuple::from_tuples(&key),
                                    &RedirectEntry::default(),
                                )
                                .unwrap();
                        }
                    }
                    if name == "REDIRECT_TRACK" {
                        let udp = packet(src, dst, IPPROTO_UDP, 46101, 443, 5, 0);
                        assert_eq!(
                            run(&backend, side, &udp, SkbInput::default()).verdict,
                            TC_ACT_SHOT,
                            "{side} let a proxy UDP datagram escape when redirect publication failed"
                        );
                    }
                    let key = tuple(src, dst, 46100, 443, IPPROTO_TCP);
                    let bytes = packet(src, dst, IPPROTO_TCP, key.src_port, key.dst_port, 5, 0x02);
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT,
                        "{side} delivered an incomplete SYN publication with full {name}"
                    );
                    let failed = backend.tcp_conn_state_lookup(&key).unwrap().unwrap();
                    assert_eq!(failed.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT, 0);
                    assert_eq!(failed.tcp_request_count, 0);
                    if name == "ROUTING_HANDOFF_MAP" {
                        backend
                            .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>(name, &filler(0))
                            .unwrap();
                    } else {
                        backend
                            .hash_remove::<_, FlowMapValue<RedirectEntry>>(
                                name,
                                &RedirectTuple::from_tuples(&filler(0)),
                            )
                            .unwrap();
                    }
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} could not retry the unpublished SYN after {name} pressure cleared"
                    );
                    let committed: ConnState =
                        backend.tcp_conn_state_lookup(&key).unwrap().unwrap();
                    assert_ne!(committed.incarnation, failed.incarnation);
                    assert_ne!(committed.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT, 0);
                    assert_eq!(committed.tcp_request_count, 0);
                    assert_eq!(handoff(&backend, &key).incarnation, committed.incarnation);
                    assert_eq!(
                        backend
                            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))
                            .unwrap()
                            .unwrap()
                            .incarnation,
                        committed.incarnation
                    );
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT
                    );
                    let pending = backend.tcp_conn_state_lookup(&key).unwrap().unwrap();
                    assert_eq!(pending.incarnation, committed.incarnation);
                    assert_eq!(pending.tcp_request_count, 0);
                    backend
                        .hash_remove::<_, FlowMapValue<RoutingHandoffEntry>>(
                            "ROUTING_HANDOFF_MAP",
                            &key,
                        )
                        .unwrap();
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_SHOT
                    );
                    assert_eq!(
                        backend
                            .tcp_conn_state_lookup(&key)
                            .unwrap()
                            .unwrap()
                            .incarnation,
                        committed.incarnation
                    );
                    assert_eq!(
                        backend
                            .tcp_conn_state_lookup(&key)
                            .unwrap()
                            .unwrap()
                            .tcp_request_count,
                        0
                    );
                    assert!(backend.routing_handoff_lookup(&key).unwrap().is_none());
                }
            }
        }
    });
}
