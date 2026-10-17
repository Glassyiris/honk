use super::*;
use aya::maps::IterableMap;

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn locked_flow_snapshots_are_coherent_during_native_in_place_updates() -> anyhow::Result<()> {
    use std::os::fd::AsFd;
    use std::sync::{Arc, Barrier};

    // Real concurrent syscalls, not a simulated reader or a forced kernel
    // instruction interleaving. Every correlated field must come from one copy.
    fn exercise<K, V>(
        backend: &mut RealEbpfBackend,
        name: &str,
        key: K,
        values: [V; 2],
    ) -> anyhow::Result<()>
    where
        K: aya::Pod + Send + Sync,
        V: aya::Pod + Send + Sync + std::fmt::Debug,
    {
        backend.flow_insert(name, &key, &values[0])?;
        let map = backend.hash_map::<K, FlowMapValue<V>>(name)?;
        let data = aya::maps::MapData::from_fd(map.map().fd().as_fd().try_clone_to_owned()?)?;
        let mut writer =
            aya::maps::HashMap::<_, K, FlowMapValue<V>>::try_from(aya::maps::Map::HashMap(data))?;
        let start = Arc::new(Barrier::new(2));
        let writer_start = Arc::clone(&start);
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let thread = scope.spawn(move || -> anyhow::Result<()> {
                writer_start.wait();
                for index in 0..4096 {
                    writer.insert(key, FlowMapValue::new(values[index % 2]), 2 | 4)?;
                }
                Ok(())
            });
            let expected = values.map(|value| format!("{value:?}"));
            start.wait();
            for _ in 0..1024 {
                let value = backend
                    .flow_lookup::<K, V>(name, &key)?
                    .expect("stable element disappeared");
                assert!(
                    expected.contains(&format!("{value:?}")),
                    "torn locked singleton in {name}: {value:?}"
                );
                let mut seen = 0;
                backend.flow_for_each_chunk::<K, V>(name, 1, &mut |chunk| {
                    for (_, value) in chunk {
                        assert!(
                            expected.contains(&format!("{value:?}")),
                            "torn locked batch in {name}: {value:?}"
                        );
                        seen += 1;
                    }
                    true
                })?;
                assert_eq!(
                    seen, 1,
                    "native in-place writer recycled an element in {name}"
                );
            }
            thread.join().expect("native locked writer panicked")?;
            Ok(())
        })
    }

    for ipv6 in [false, true] {
        let mut backend = retirement_fixture();
        let address = if ipv6 {
            honk_ebpf_common::dae_ip::In6Addr::from_ipv6_addr("2001:db8::81".parse()?)
        } else {
            honk_ebpf_common::dae_ip::In6Addr::from_ipv4_bytes([192, 0, 2, 81])
        };
        let key = TuplesKey {
            src_ip: address,
            dst_ip: address,
            src_port: 41300,
            l4proto: 6,
            ..Default::default()
        };
        exercise(
            &mut backend,
            "CONN_STATE_MAP",
            key,
            [
                ConnState {
                    incarnation: 1,
                    decision_token: 7,
                    last_seen_ns: 101,
                    trace_id: 31,
                    ..Default::default()
                },
                ConnState {
                    incarnation: 2,
                    decision_token: 8,
                    last_seen_ns: 202,
                    trace_id: 32,
                    ..Default::default()
                },
            ],
        )?;
        exercise(
            &mut backend,
            "ROUTING_HANDOFF_MAP",
            key,
            [
                RoutingHandoffEntry {
                    incarnation: 1,
                    last_seen_ns: 101,
                    trace_id: 31,
                    result: RoutingResult {
                        decision_token: 7,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                RoutingHandoffEntry {
                    incarnation: 2,
                    last_seen_ns: 202,
                    trace_id: 32,
                    result: RoutingResult {
                        decision_token: 8,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
        )?;
        exercise(
            &mut backend,
            "REDIRECT_TRACK",
            RedirectTuple::from_tuples(&key),
            [
                RedirectEntry {
                    incarnation: 1,
                    decision_token: 7,
                    last_seen_ns: 101,
                    ifindex: 31,
                    ..Default::default()
                },
                RedirectEntry {
                    incarnation: 2,
                    decision_token: 8,
                    last_seen_ns: 202,
                    ifindex: 32,
                    ..Default::default()
                },
            ],
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn request_retirement_fences_both_domains_deduplicates_and_preserves_failures() -> anyhow::Result<()>
{
    use honk_ebpf_common::redirect_need::{TCP_BINDING_CHILD, TcpRequestKey, TcpSocketBinding};

    let key = TuplesKey {
        src_port: 41301,
        l4proto: 6,
        ..Default::default()
    };
    let request = TcpRequestKey {
        address: 0x1234,
        cookie: 0x5678,
    };
    let mut backend = retirement_fixture();
    // Controlled inspection after the real grace barrier; not a claim that
    // this synthetic request address belongs to a native request_sock.
    backend.with_retirement_fences_and_requests(
        &[(key, 7), (key, 7)],
        &[request, request],
        |backend| {
            assert_eq!(backend.array_get::<u32>("RETIRE_ACTIVE", 0)?, Some(1));
            let tuple_owner = backend
                .hash_lookup::<_, RetirementFence>(RETIRE_FENCE_MAP, &key)?
                .unwrap();
            assert_eq!(
                backend.hash_lookup::<_, u64>("REQUEST_FENCE", &request)?,
                Some(tuple_owner.owner)
            );
            assert_eq!(tuple_owner.decision_token, 7);
            Ok(())
        },
    )?;
    assert_retirement_fence(&backend, &key, false);
    assert!(
        backend
            .hash_lookup::<_, u64>("REQUEST_FENCE", &request)?
            .is_none()
    );
    assert_eq!(backend.array_get::<u32>("RETIRE_ACTIVE", 0)?, Some(0));

    let proof = TcpSocketBinding {
        tuples: key,
        kind: TCP_BINDING_CHILD,
        handoff: RoutingHandoffEntry {
            incarnation: 1,
            last_seen_ns: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    backend.hash_insert_noexist("TCP_REQUEST_BINDINGS", &request, &proof)?;
    let sibling = TcpRequestKey {
        address: request.address + 1,
        cookie: request.cookie + 1,
    };
    backend.hash_insert_noexist("TCP_REQUEST_BINDINGS", &sibling, &proof)?;
    backend.tcp_conn_state_store(
        &key,
        &ConnState {
            incarnation: 1,
            tcp_syn_flags: 3,
            tcp_request_count: 2,
            ..Default::default()
        },
    )?;
    let retire = RetireRequest {
        key,
        kind: RetireKind::ExpiredRequest {
            request: &request,
            expected: &proof,
            expired_before_ns: 2,
        },
    };
    backend.retirement_faults.acquire = Some(1); // Request fence after the tuple fence.
    let mut outcomes = [None; 2];
    let error = backend
        .retire_batch(&[retire, retire], &mut outcomes)
        .unwrap_err();
    assert_eq!(error.counts, RetireCounts::default());
    assert_eq!(outcomes, [None; 2]);
    assert!(
        backend
            .hash_lookup::<_, TcpSocketBinding>("TCP_REQUEST_BINDINGS", &request)?
            .is_some()
    );
    assert_retirement_fence(&backend, &key, false);
    assert!(
        backend
            .hash_lookup::<_, u64>("REQUEST_FENCE", &request)?
            .is_none()
    );
    assert!(!backend.retirement_failed);
    assert_eq!(
        backend
            .tcp_conn_state_lookup(&key)?
            .unwrap()
            .tcp_request_count,
        2
    );

    backend.retirement_faults.release = Some(1); // Release tuple, fail exact request release.
    let error = backend
        .retire_batch(&[retire, retire], &mut outcomes)
        .unwrap_err();
    assert_eq!(
        error.counts,
        RetireCounts {
            request: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        outcomes,
        [
            Some(UdpDecisionCommitResult::Applied),
            Some(UdpDecisionCommitResult::Missing)
        ]
    );
    assert!(
        backend
            .hash_lookup::<_, TcpSocketBinding>("TCP_REQUEST_BINDINGS", &request)?
            .is_none()
    );
    let state = backend.tcp_conn_state_lookup(&key)?.unwrap();
    assert_eq!(state.tcp_request_count, 1);
    assert_eq!(state.tcp_syn_flags, 3);
    assert!(
        backend
            .hash_lookup::<_, TcpSocketBinding>("TCP_REQUEST_BINDINGS", &sibling)?
            .is_some()
    );
    assert_retirement_fence(&backend, &key, false);
    assert!(
        backend
            .hash_lookup::<_, u64>("REQUEST_FENCE", &request)?
            .is_some()
    );
    assert_eq!(backend.array_get::<u32>("RETIRE_ACTIVE", 0)?, Some(1));
    assert!(backend.retirement_failed);
    assert!(backend.set_datapath_ready(true).is_err());
    Ok(())
}
