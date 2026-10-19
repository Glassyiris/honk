use super::*;

fn age_udp_conn(backend: &mut RealEbpfBackend, key: &TuplesKey, age_s: u64) -> ConnState {
    let wait_ns = (age_s + 1) * 1_000_000_000;
    let wait_ns = wait_ns.saturating_sub(now_ns());
    if wait_ns != 0 {
        std::thread::sleep(Duration::from_nanos(wait_ns));
    }
    let mut state = backend.conn_state_lookup(key).unwrap().unwrap();
    state.last_seen_ns = now_ns() - age_s * 1_000_000_000;
    backend.udp_conn_state_store(key, &state).unwrap();
    state
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn idle_udp_handoff_renews_only_its_matching_owner_without_an_expiry_hint() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        let mut ring = RingBuf::try_from(
            backend.bpf_mut().unwrap().take_map("EVENT_RINGBUF").unwrap(),
        )
        .unwrap();
        for (src, dst) in PEERS {
            for (direction, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                for age_s in [40, 90] {
                    let key = tuple(src, dst, 45800 + direction as u16 * 100 + age_s as u16, 443, IPPROTO_UDP);
                    seed(&backend, side, &key, src, dst);
                    let state = age_udp_conn(&mut backend, &key, age_s);
                    let mut entry = handoff(&backend, &key);
                    entry.last_seen_ns = state.last_seen_ns;
                    backend.flow_insert("ROUTING_HANDOFF_MAP", &key, &entry).unwrap();
                    let bytes = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
                    assert_eq!(
                        run(&backend, side, &bytes, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{side} {src} after {age_s}s idle"
                    );
                    let renewed = handoff(&backend, &key);
                    assert_eq!(renewed.incarnation, entry.incarnation);
                    assert_eq!(renewed.result.decision_token, entry.result.decision_token);
                    assert!(now_ns().saturating_sub(renewed.last_seen_ns) < 1_000_000_000);
                    while let Some(item) = ring.next() {
                        let event: DaeEvent = unsafe { ptr::read_unaligned(item.as_ptr().cast()) };
                        assert_ne!(event.type_, DaeEventType::FlowExpired as u32);
                    }
                    for mismatch_token in [false, true] {
                        let mut foreign = entry;
                        if mismatch_token {
                            foreign.result.decision_token += 1;
                        } else {
                            foreign.incarnation += 1;
                        }
                        backend.flow_insert("ROUTING_HANDOFF_MAP", &key, &foreign).unwrap();
                        assert_eq!(
                            run(&backend, side, &bytes, SkbInput::default()).verdict,
                            TC_ACT_SHOT,
                            "{side} {src} accepted a foreign handoff"
                        );
                        assert_eq!(format!("{:?}", handoff(&backend, &key)), format!("{foreign:?}"));
                    }
                }
            }
        }
    });
}
