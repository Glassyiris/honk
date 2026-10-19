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
            backend
                .bpf_mut()
                .unwrap()
                .take_map("EVENT_RINGBUF")
                .unwrap(),
        )
        .unwrap();
        for (src, dst) in PEERS {
            for (direction, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                for age_s in [40, 90] {
                    let key = tuple(
                        src,
                        dst,
                        45800 + direction as u16 * 100 + age_s as u16,
                        443,
                        IPPROTO_UDP,
                    );
                    seed(&backend, side, &key, src, dst);
                    let state = age_udp_conn(&mut backend, &key, age_s);
                    let mut entry = handoff(&backend, &key);
                    entry.last_seen_ns = state.last_seen_ns;
                    backend
                        .flow_insert("ROUTING_HANDOFF_MAP", &key, &entry)
                        .unwrap();
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
                        backend
                            .flow_insert("ROUTING_HANDOFF_MAP", &key, &foreign)
                            .unwrap();
                        assert_eq!(
                            run(&backend, side, &bytes, SkbInput::default()).verdict,
                            TC_ACT_SHOT,
                            "{side} {src} accepted a foreign handoff"
                        );
                        assert_eq!(
                            format!("{:?}", handoff(&backend, &key)),
                            format!("{foreign:?}")
                        );
                    }
                }
            }
        }
    });
}

fn set_udp_reply_owner(backend: &mut RealEbpfBackend, key: &TuplesKey, state: u8, token: u32) {
    let mut conn = backend.conn_state_lookup(key).unwrap().unwrap();
    conn.state = state;
    conn.decision_token = token;
    backend.udp_conn_state_store(key, &conn).unwrap();
    let mut entry = handoff(backend, key);
    entry.result.decision_token = token;
    backend
        .flow_insert("ROUTING_HANDOFF_MAP", key, &entry)
        .unwrap();
    let redirect_key = RedirectTuple::from_tuples(key);
    let mut redirect = backend
        .redirect_track_lookup(&redirect_key)
        .unwrap()
        .unwrap();
    redirect.decision_token = token;
    backend
        .redirect_track_store(&redirect_key, &redirect)
        .unwrap();
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn proxied_udp_replies_renew_exact_connection_liveness() {
    isolated(|| {
        use std::io::Write;
        let (mut backend, _, _listeners) = proxy_fixture();
        load_classifier(&mut backend, "dae0_ingress");
        for (src, dst) in PEERS {
            for (index, side) in ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate() {
                for token in [0, 29] {
                    let key = tuple(
                        src,
                        dst,
                        46100 + index as u16 * 100 + token as u16,
                        443,
                        IPPROTO_UDP,
                    );
                    seed(&backend, side, &key, src, dst);
                    if token != 0 {
                        set_udp_reply_owner(
                            &mut backend,
                            &key,
                            UdpDecisionState::Proxy as u8,
                            token,
                        );
                    }
                    let reply = packet(dst, src, IPPROTO_UDP, 443, key.src_port, 5, 0);
                    let owner = handoff(&backend, &key).incarnation;
                    let mut timings = [0; 32];
                    for duration in &mut timings {
                        age_udp_conn(&mut backend, &key, 100);
                        let result = run(&backend, "dae0_ingress", &reply, SkbInput::default());
                        assert_eq!(result.verdict, TC_ACT_REDIRECT);
                        *duration = result.duration.as_nanos();
                    }
                    timings.sort_unstable();
                    writeln!(
                        std::io::stderr().lock(),
                        "UDP reply aged-write {side} {src} token={token}: p50={}ns p90={}ns",
                        timings[16],
                        timings[28]
                    )
                    .unwrap();
                    let renewed = backend.conn_state_lookup(&key).unwrap().unwrap();
                    assert_eq!(renewed.incarnation, owner);
                    assert_eq!(renewed.decision_token, token);
                    assert!(
                        now_ns().saturating_sub(renewed.last_seen_ns) < 1_000_000_000,
                        "{side} {src} token={token} did not renew from an exact reply"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn client_udp_resumes_after_idle_connection_and_handoff_are_kept_alive_by_a_reply() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        load_classifier(&mut backend, "dae0_ingress");
        for (src, dst) in PEERS {
            let key = tuple(src, dst, 46300, 443, IPPROTO_UDP);
            seed(&backend, "lan_ingress_l2", &key, src, dst);
            let state = age_udp_conn(&mut backend, &key, 100);
            age_auxiliaries(&mut backend, &key, state.last_seen_ns);
            let reply = packet(dst, src, IPPROTO_UDP, 443, key.src_port, 5, 0);
            assert_eq!(
                run(&backend, "dae0_ingress", &reply, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            let client = packet(src, dst, IPPROTO_UDP, key.src_port, 443, 5, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &client, SkbInput::default()).verdict,
                TC_ACT_REDIRECT,
                "{src} resumed client packet was dropped after an exact reply"
            );
            let current = backend.conn_state_lookup(&key).unwrap().unwrap();
            assert_eq!(current.incarnation, state.incarnation);
            assert!(now_ns().saturating_sub(current.last_seen_ns) < 1_000_000_000);
            assert!(now_ns().saturating_sub(handoff(&backend, &key).last_seen_ns) < 1_000_000_000);
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn udp_replies_preserve_frozen_and_expired_connection_timestamps() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        load_classifier(&mut backend, "dae0_ingress");
        let (src, dst) = PEERS[0];
        for (index, (state, age_s, expected)) in [
            (UdpDecisionState::Preparing, 2, TC_ACT_SHOT),
            (UdpDecisionState::Aborted, 2, TC_ACT_SHOT),
            (UdpDecisionState::Pending, 2, TC_ACT_REDIRECT),
            (UdpDecisionState::DirectArmed, 2, TC_ACT_REDIRECT),
            (UdpDecisionState::None, 121, TC_ACT_SHOT),
        ]
        .into_iter()
        .enumerate()
        {
            let key = tuple(src, dst, 46400 + index as u16, 443, IPPROTO_UDP);
            seed(&backend, "lan_ingress_l2", &key, src, dst);
            set_udp_reply_owner(&mut backend, &key, state as u8, 51);
            let before = age_udp_conn(&mut backend, &key, age_s);
            let reply = packet(dst, src, IPPROTO_UDP, 443, key.src_port, 5, 0);
            assert_eq!(
                run(&backend, "dae0_ingress", &reply, SkbInput::default()).verdict,
                expected,
                "{state:?}"
            );
            let after = backend.conn_state_lookup(&key).unwrap().unwrap();
            assert_eq!(after.last_seen_ns, before.last_seen_ns, "{state:?}");
            assert_eq!(after.incarnation, before.incarnation);
            assert_eq!(after.state, before.state);
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn udp_reply_renewal_requires_exact_redirect_and_connection_identity() {
    isolated(|| {
        let (mut backend, _, _listeners) = proxy_fixture();
        load_classifier(&mut backend, "dae0_ingress");
        let (src, dst) = PEERS[0];
        for index in 0..4 {
            let key = tuple(src, dst, 46500 + index, 443, IPPROTO_UDP);
            seed(&backend, "lan_ingress_l2", &key, src, dst);
            let before = age_udp_conn(&mut backend, &key, 2);
            let redirect_key = RedirectTuple::from_tuples(&key);
            if index == 3 {
                backend
                    .hash_remove::<_, FlowMapValue<ConnState>>("CONN_STATE_MAP", &key)
                    .unwrap();
            } else if index == 2 {
                backend
                    .hash_remove::<_, FlowMapValue<RedirectEntry>>("REDIRECT_TRACK", &redirect_key)
                    .unwrap();
            } else {
                let mut redirect = backend
                    .redirect_track_lookup(&redirect_key)
                    .unwrap()
                    .unwrap();
                if index == 0 {
                    redirect.incarnation += 1;
                } else {
                    redirect.decision_token += 1;
                }
                backend
                    .redirect_track_store(&redirect_key, &redirect)
                    .unwrap();
            }
            let reply = packet(dst, src, IPPROTO_UDP, 443, key.src_port, 5, 0);
            assert_eq!(
                run(&backend, "dae0_ingress", &reply, SkbInput::default()).verdict,
                TC_ACT_REDIRECT
            );
            let after = backend.conn_state_lookup(&key).unwrap();
            if index == 3 {
                assert!(after.is_none(), "reply created a missing conn");
            } else {
                assert_eq!(
                    after.unwrap().last_seen_ns,
                    before.last_seen_ns,
                    "case {index}"
                );
            }
        }
    });
}
