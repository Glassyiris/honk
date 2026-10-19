use super::*;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn untouched_passes_return_next_before_backend_admission() {
    isolated(|| {
        // No backend ABI validation: this also replays the pre-cutover object.
        let mut bpf = aya::Ebpf::load(&object()).unwrap();
        for name in [
            "lan_ingress_l2",
            "lan_ingress_l3",
            "lan_egress_l2",
            "lan_egress_l3",
            "wan_ingress_l2",
            "wan_ingress_l3",
            "wan_egress_l2",
            "wan_egress_l3",
            "dae0_ingress",
        ] {
            let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
            program.load().unwrap();
            let result = program
                .test_run(TestRunOptions {
                    data_in: Some(&[0u8; 64]),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(result.return_value, TC_ACT_UNSPEC, "{name}");
        }
    });
}

fn wire_packet(
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    source_port: u16,
    destination_port: u16,
    tcp_flags: u8,
    l3: bool,
) -> Vec<u8> {
    let mut frame = packet(
        src,
        dst,
        protocol,
        source_port,
        destination_port,
        0,
        tcp_flags,
    );
    if l3 {
        frame = frame.split_off(14);
        // Since 7.2, test-run needs Ethernet + IP header bytes before running BPF.
        frame.resize(frame.len().max(14 + 40), 0);
    }
    frame
}

fn assert_next(backend: &RealEbpfBackend, name: &str, bytes: &[u8], input: SkbInput) {
    let result = run(backend, name, bytes, input);
    assert_eq!(result.verdict, TC_ACT_UNSPEC, "{name}, input={bytes:02x?}");
    assert_eq!(result.mark, input.mark, "{name}");
    assert_eq!(&result.data[..bytes.len()], bytes, "{name}");
}

// Test-run derives skb->protocol from bytes 12..14 even for an L3 classifier.
// These valid raw-IP sources put the matching EtherType at that offset.
const PEERS: [(IpAddr, IpAddr, IpAddr); 2] = [
    (
        IpAddr::V4(Ipv4Addr::new(8, 0, 2, 91)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x86dd, 0, 0, 0, 0, 91)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 91)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    ),
];

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn pure_passes_continue_tcx_without_changing_marks() {
    isolated(|| {
        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            &object(),
            DaeParam {
                local_ip: u32::from_ne_bytes([203, 0, 113, 99]),
                ..fixture_param()
            },
        )
        .unwrap();
        load_classifier(&mut backend, "dae0_ingress");
        let input = SkbInput {
            mark: USER_MARK,
            ..Default::default()
        };
        for (l3, names) in [
            (
                false,
                [
                    "lan_ingress_l2",
                    "lan_egress_l2",
                    "wan_ingress_l2",
                    "wan_egress_l2",
                ],
            ),
            (
                true,
                [
                    "lan_ingress_l3",
                    "lan_egress_l3",
                    "wan_ingress_l3",
                    "wan_egress_l3",
                ],
            ),
        ] {
            for name in names {
                load_classifier(&mut backend, name);
            }
            for (src, dst, multicast) in PEERS {
                let port = 46000 + u16::from(l3) * 100;
                let bytes = wire_packet(src, dst, IPPROTO_UDP, port, 443, 0, l3);
                set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 0u32);
                for name in [names[0], names[3]] {
                    assert_next(&backend, name, &bytes, input);
                }
                set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 1u32);

                let mut unsupported = bytes.clone();
                let offset = if l3 { 0 } else { 14 };
                unsupported[offset + if src.is_ipv4() { 9 } else { 6 }] = 47;
                for name in [names[1], names[2], names[3]] {
                    assert_next(&backend, name, &unsupported, input);
                }
                if !l3 {
                    assert_next(&backend, "dae0_ingress", &unsupported, input);
                    assert_next(&backend, "dae0_ingress", &bytes, input);
                }

                let special = wire_packet(src, multicast, IPPROTO_UDP, port + 1, 5353, 0, l3);
                for name in [names[1], names[3]] {
                    assert_next(&backend, name, &special, input);
                    if !l3 {
                        let mut broadcast = bytes.clone();
                        broadcast[..6].fill(0xff);
                        assert_next(&backend, name, &broadcast, input);
                    }
                }
                if src.is_ipv4() {
                    let local = wire_packet(
                        src,
                        "203.0.113.99".parse().unwrap(),
                        IPPROTO_UDP,
                        port + 2,
                        443,
                        0,
                        l3,
                    );
                    assert_next(&backend, names[3], &local, input);
                }
                assert_next(
                    &backend,
                    names[3],
                    &bytes,
                    SkbInput {
                        ingress_ifindex: 1,
                        ..input
                    },
                );

                for name in [names[1], names[2]] {
                    for (sport, dport) in [(port + 3, 53), (53, port + 3), (port + 4, 3478)] {
                        let reply = wire_packet(src, dst, IPPROTO_UDP, sport, dport, 0, l3);
                        assert_next(&backend, name, &reply, input);
                    }
                }
                let ack = wire_packet(src, dst, IPPROTO_TCP, port + 5, 443, 0x10, l3);
                assert_next(&backend, names[3], &ack, input);
                let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap();
                let state = ConnState {
                    incarnation: 1,
                    last_seen_ns: time.tv_sec() as u64 * 1_000_000_000 + time.tv_nsec() as u64,
                    ..Default::default()
                };
                backend
                    .flow_insert(
                        "CONN_STATE_MAP",
                        &tuple(src, dst, port + 5, 443, IPPROTO_TCP),
                        &state,
                    )
                    .unwrap();
                assert_next(&backend, names[3], &ack, input);
                let reply_state = ConnState {
                    is_wan_ingress_direction: 1,
                    ..state
                };
                backend
                    .flow_insert(
                        "CONN_STATE_MAP",
                        &tuple(src, dst, port, 443, IPPROTO_UDP),
                        &reply_state,
                    )
                    .unwrap();
                assert_next(&backend, names[3], &bytes, input);
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn mark_setting_and_owned_passes_keep_terminating_tcx() {
    isolated(|| {
        let mut backend =
            RealEbpfBackend::load_routing_test_fixture(&object(), fixture_param()).unwrap();
        set_array(&mut backend, "DATAPATH_STATE_MAP", 0, 1u32);
        for (l3, lan, wan) in [
            (false, "lan_ingress_l2", "wan_egress_l2"),
            (true, "lan_ingress_l3", "wan_egress_l3"),
        ] {
            load_classifier(&mut backend, lan);
            load_classifier(&mut backend, wan);
            for (src, dst, multicast) in PEERS {
                let bytes = wire_packet(src, multicast, IPPROTO_UDP, 46100, 5353, 0, l3);
                let result = run(
                    &backend,
                    lan,
                    &bytes,
                    SkbInput {
                        mark: USER_MARK,
                        ..Default::default()
                    },
                );
                assert_eq!(
                    (result.verdict, result.mark),
                    (TC_ACT_OK, USER_MARK | CLASSIFIED_MARK),
                    "{lan}"
                );
                let bytes = wire_packet(src, dst, IPPROTO_UDP, 46101, 443, 0, l3);
                for mark in [CLASSIFIED_MARK | USER_MARK, pack_nfqueue_mark(123).unwrap()] {
                    let result = run(
                        &backend,
                        lan,
                        &bytes,
                        SkbInput {
                            mark,
                            ..Default::default()
                        },
                    );
                    assert_eq!((result.verdict, result.mark), (TC_ACT_OK, mark), "{lan}");
                }
                for mark in [DAE_BYPASS_MARK, CLASSIFIED_MARK | USER_MARK] {
                    let result = run(
                        &backend,
                        wan,
                        &bytes,
                        SkbInput {
                            mark,
                            ..Default::default()
                        },
                    );
                    assert_eq!((result.verdict, result.mark), (TC_ACT_OK, mark), "{wan}");
                }
            }
        }
        load_classifier(&mut backend, "dae0peer_ingress");
        let (src, dst, _) = PEERS[0];
        let bytes = wire_packet(src, dst, IPPROTO_TCP, 46102, 443, 0x10, false);
        let result = run(
            &backend,
            "dae0peer_ingress",
            &bytes,
            SkbInput {
                cb: [TPROXY_MARK, 0, 0, 0x1234, 0],
                ..Default::default()
            },
        );
        assert_eq!(
            (result.verdict, result.mark),
            (TC_ACT_OK, TPROXY_MARK | 0x1234)
        );
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT"]
fn conn_capacity_native_passes_continue_tcx_without_clearing_marks() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[]);
        for name in ["wan_egress_l2", "wan_egress_l3"] {
            load_classifier(&mut backend, name);
        }
        {
            let map = backend
                .bpf_mut()
                .unwrap()
                .map_mut("CONN_STATE_MAP")
                .unwrap();
            let mut map = HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(map).unwrap();
            for index in 0..honk_ebpf_common::conn::MAX_CONN_STATE_NUM {
                let key = tuple(
                    IpAddr::V4(Ipv4Addr::from(0xac10_0000 + index)),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 254)),
                    9,
                    9,
                    IPPROTO_UDP,
                );
                map.insert(key, FlowMapValue::new(ConnState::default()), 1 | 4)
                    .unwrap();
            }
        }
        for (l3, name) in [(false, "wan_egress_l2"), (true, "wan_egress_l3")] {
            for (src, dst, _) in PEERS {
                for protocol in [IPPROTO_TCP, IPPROTO_UDP] {
                    let bytes = wire_packet(src, dst, protocol, 46200, 443, 0x02, l3);
                    assert_next(
                        &backend,
                        name,
                        &bytes,
                        SkbInput {
                            mark: USER_MARK,
                            ..Default::default()
                        },
                    );
                    assert!(
                        backend
                            .conn_state_lookup(&tuple(src, dst, 46200, 443, protocol))
                            .unwrap()
                            .is_none()
                    );
                }
            }
        }
    });
}
