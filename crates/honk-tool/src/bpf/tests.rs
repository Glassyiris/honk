use super::*;

#[test]
fn batch_lock_flag_matches_kernel_abi() {
    assert_eq!(BPF_F_LOCK, 4);
}

#[test]
fn batch_errors_never_return_partial_or_fallback_success() {
    for elem_flags in [0, BPF_F_LOCK] {
        for errno in [
            libc::EINVAL,
            libc::ENOSYS,
            libc::EOPNOTSUPP,
            libc::EFAULT,
            libc::EPERM,
            libc::EIO,
            libc::ENOSPC,
        ] {
            for after_progress in [false, true] {
                let error = batch_error(
                    BatchError::Errno {
                        errno,
                        after_progress,
                    },
                    elem_flags,
                );
                if matches!(errno, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) {
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                } else {
                    assert_eq!(error.raw_os_error(), Some(errno));
                }
            }
        }
    }
    let error = batch_error(
        BatchError::InvalidCount {
            count: BPF_BATCH_CHUNK + 1,
            terminal: false,
        },
        BPF_F_LOCK,
    );
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn flow_wrapper_layouts_reject_old_payload_only_maps() {
    for (name, key_size, payload_size, wrapper_size, expected_size, offset) in [
        (
            "CONN_STATE_MAP",
            std::mem::size_of::<TuplesKey>(),
            std::mem::size_of::<ConnState>(),
            std::mem::size_of::<FlowMapValue<ConnState>>(),
            80,
            std::mem::offset_of!(FlowMapValue<ConnState>, value),
        ),
        (
            "REDIRECT_TRACK",
            std::mem::size_of::<RedirectTuple>(),
            std::mem::size_of::<RedirectEntry>(),
            std::mem::size_of::<FlowMapValue<RedirectEntry>>(),
            48,
            std::mem::offset_of!(FlowMapValue<RedirectEntry>, value),
        ),
        (
            "ROUTING_HANDOFF_MAP",
            std::mem::size_of::<TuplesKey>(),
            std::mem::size_of::<RoutingHandoffEntry>(),
            std::mem::size_of::<FlowMapValue<RoutingHandoffEntry>>(),
            80,
            std::mem::offset_of!(FlowMapValue<RoutingHandoffEntry>, value),
        ),
    ] {
        assert_eq!(offset, 8);
        assert_eq!(wrapper_size, payload_size + 8);
        assert_eq!(wrapper_size, expected_size);
        let info = [1, 0, key_size as u32, wrapper_size as u32, 0, 0];
        check_map_layout(name, info, 1, key_size as u32, wrapper_size as u32).unwrap();
        for (field, value) in [(0, 2), (2, key_size as u32 + 1), (3, payload_size as u32)] {
            let mut old = info;
            old[field] = value;
            assert!(check_map_layout(name, old, 1, key_size as u32, wrapper_size as u32).is_err());
        }
    }
}

#[test]
fn flow_payload_decodes_fixed_wire_offsets_without_lock_header() {
    let mut aligned = [0u64; 11];
    let bytes = unsafe { std::slice::from_raw_parts_mut(aligned.as_mut_ptr() as *mut u8, 88) };
    let bytes = &mut bytes[1..81];
    bytes[..8].fill(0xa5);
    bytes[9] = 6;
    bytes[10..12].copy_from_slice(&1u16.to_ne_bytes());
    bytes[12..16].copy_from_slice(&42u32.to_ne_bytes());
    bytes[16..24].copy_from_slice(&456u64.to_ne_bytes());
    bytes[60..64].copy_from_slice(&123u32.to_ne_bytes());
    bytes[64..72].copy_from_slice(&789u64.to_ne_bytes());
    bytes[72..76].copy_from_slice(&u32::MAX.to_ne_bytes());
    bytes[76..80].copy_from_slice(&2u32.to_ne_bytes());
    let conn: ConnState = flow_payload(bytes);
    assert_eq!(conn.state, 6);
    assert_eq!(conn.decision_token, 42);
    assert_eq!(conn.last_seen_ns, 456);
    assert_eq!(conn.trace_id, 123);
    assert_eq!(conn.incarnation, 789);
    assert_eq!(conn.tcp_syn_flags, 1);
    assert_eq!(conn.tcp_syn_isn, u32::MAX);
    assert_eq!(conn.reserved, 2);

    bytes[8..].fill(0);
    bytes[8..16].copy_from_slice(&321u64.to_ne_bytes());
    bytes[28] = 1;
    bytes[29] = 7;
    bytes[32..36].copy_from_slice(&12u32.to_ne_bytes());
    bytes[36..40].copy_from_slice(&43u32.to_ne_bytes());
    bytes[40..48].copy_from_slice(&790u64.to_ne_bytes());
    let redirect: RedirectEntry = flow_payload(&bytes[..48]);
    assert_eq!(redirect.last_seen_ns, 321);
    assert_eq!(redirect.from_wan, 1);
    assert_eq!(redirect.outbound, 7);
    assert_eq!(redirect.ifindex, 12);
    assert_eq!(redirect.decision_token, 43);
    assert_eq!(redirect.incarnation, 790);

    bytes[8..].fill(0);
    bytes[8..16].copy_from_slice(&654u64.to_ne_bytes());
    bytes[56..64].copy_from_slice(&44u64.to_ne_bytes());
    bytes[64..68].copy_from_slice(&124u32.to_ne_bytes());
    bytes[72..80].copy_from_slice(&791u64.to_ne_bytes());
    let handoff: RoutingHandoffEntry = flow_payload(bytes);
    assert_eq!(handoff.last_seen_ns, 654);
    assert_eq!(handoff.routing_generation, 44);
    assert_eq!(handoff.trace_id, 124);
    assert_eq!(handoff.incarnation, 791);
}

#[test]
fn ordinary_stats_print_all_canonical_keys_and_zero_missing_counters() {
    let mut reads = 0;
    let mut output = Vec::new();
    print_ordinary_stats_with(
        stats_cardinality_info(BpfStatsKey::COUNT),
        |key| {
            let index = u32::from_ne_bytes(key.try_into().unwrap());
            assert_eq!(index, reads);
            reads += 1;
            Ok((index != 4).then_some(u64::from(index) + 10))
        },
        &mut output,
    )
    .unwrap();
    assert_eq!(reads, BpfStatsKey::COUNT);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "udp_conn_overflow: 10\n",
            "tcp_conn_overflow: 11\n",
            "redirect_track_insert_failure: 12\n",
            "routing_handoff_insert_failure: 13\n",
            "socket_identity_capture_failure: 0\n",
            "tcp_child_proof_storage_failure: 15\n",
            "tcp_publisher_claim_failure: 16\n",
            "new_flow_rate_limited: 17\n",
            "udp_reverse_learning_suspended: 18\n",
        )
    );
}

fn stats_cardinality_info(max_entries: u32) -> [u32; 6] {
    let mut info = [0; 6];
    info[4] = max_entries;
    info
}

#[test]
fn ordinary_stats_refuse_other_cardinality_before_any_read() {
    for found in [BpfStatsKey::COUNT - 1, BpfStatsKey::COUNT + 1] {
        let mut reads = 0;
        let mut output = Vec::new();
        print_ordinary_stats_with(
            stats_cardinality_info(found),
            |_| {
                reads += 1;
                Ok(Some(1))
            },
            &mut output,
        )
        .expect_err("mismatched statistics map was accepted");
        assert_eq!(reads, 0);
        assert!(output.is_empty());
    }
}

struct SysfsFixture(tempfile::TempDir);

impl SysfsFixture {
    fn new(possible: Option<&str>, present: &[u32]) -> Self {
        let fixture = Self(tempfile::tempdir().unwrap());
        if let Some(possible) = possible {
            std::fs::write(fixture.root().join("possible"), possible).unwrap();
        }
        for cpu in present {
            std::fs::create_dir(fixture.root().join(format!("cpu{cpu}"))).unwrap();
        }
        fixture
    }

    fn root(&self) -> &Path {
        self.0.path()
    }
}

fn stats_metadata_fixture(name: &str) -> [u32; 6] {
    let mut info = [0; 6];
    info[0] = 6;
    info[2] = 4;
    info[3] = match name {
        "CONN_STATE_OCCUPANCY" => 8,
        "OUTBOUND_STATS" => 32,
        _ => panic!("unexpected statistics map {name}"),
    };
    info
}

fn open_stats_fixture(name: &str) -> anyhow::Result<(OwnedFd, [u32; 6])> {
    Ok((
        std::fs::File::open("/dev/null")?.into(),
        stats_metadata_fixture(name),
    ))
}

fn prepared(root: &Path) -> PerCpuStats {
    prepare_percpu_stats(root, || Ok(()), open_stats_fixture).unwrap()
}

fn assert_source_error(fixture: &SysfsFixture) {
    let mut opened = 0;
    let result = prepare_percpu_stats(
        fixture.root(),
        || Ok(()),
        |name| {
            opened += 1;
            open_stats_fixture(name)
        },
    );
    let error = result.err().expect("invalid CPU source was accepted");
    assert!(
        error
            .to_string()
            .contains(&fixture.root().join("possible").display().to_string())
    );
    assert_eq!(opened, 0, "CPU source failure must precede map opening");
}

#[test]
fn prepare_percpu_stats_uses_possible_population_not_present_directories() {
    let fixture = SysfsFixture::new(Some("0-63\n"), &(0..32).collect::<Vec<_>>());
    let stats = prepared(fixture.root());
    assert_eq!((stats.occupancy.len(), stats.outbound.len()), (512, 2048));
}

#[test]
fn prepare_percpu_stats_counts_sparse_possible_members() {
    for (mask, present, lengths) in [
        ("0,2-3\n", &[0, 2, 3][..], (24, 96)),
        ("0,2-3,8\n", &[0, 2, 3, 8][..], (32, 128)),
        ("7\n", &[7][..], (8, 32)),
    ] {
        let fixture = SysfsFixture::new(Some(mask), present);
        let stats = prepared(fixture.root());
        assert_eq!(
            (stats.occupancy.len(), stats.outbound.len()),
            lengths,
            "{mask}"
        );
    }
}

#[test]
fn prepare_percpu_stats_rejects_missing_or_unreadable_possible_before_opening() {
    for possible_is_directory in [false, true] {
        let fixture = SysfsFixture::new(None, &[0, 1, 2]);
        if possible_is_directory {
            std::fs::create_dir(fixture.root().join("possible")).unwrap();
        }
        assert_source_error(&fixture);
    }
}

#[test]
fn prepare_percpu_stats_rejects_noncanonical_possible_lists() {
    for input in [
        "", ",", "0,", ",0", "x", "+1", "01", "-1", "2-1", "0,0", "0-2,2-3", "1,0", "0-1-2",
    ] {
        let fixture = SysfsFixture::new(Some(input), &[0]);
        assert_source_error(&fixture);
    }
}

#[test]
fn checked_possible_parser_and_percpu_size_reject_overflow_without_allocating() {
    let half = usize::MAX / 2;
    for input in [
        format!("{}0", usize::MAX),
        format!("0-{}", usize::MAX),
        format!("0-{half},{}-{}", half + 1, usize::MAX),
    ] {
        assert!(parse_possible_cpus(&input).is_err(), "{input}");
    }
    assert_eq!(percpu_buffer_len(1, 9).unwrap(), 16);
    for (count, value_size) in [
        ((usize::MAX / 8) + 1, 8),
        (1, usize::MAX),
        ((isize::MAX as usize / 8) + 1, 8),
    ] {
        assert!(
            percpu_buffer_len(count, value_size).is_err(),
            "{count} x {value_size}"
        );
    }
}

#[test]
fn prepare_percpu_stats_rejects_each_percpu_map_layout_field() {
    let fixture = SysfsFixture::new(Some("0\n"), &[0]);
    for map in ["CONN_STATE_OCCUPANCY", "OUTBOUND_STATS"] {
        for (field, value) in [(0, 1), (2, 8), (3, 16)] {
            let expected = stats_metadata_fixture(map);
            let mut actual = expected;
            actual[field] = value;
            let result = prepare_percpu_stats(
                fixture.root(),
                || Ok(()),
                |name| {
                    let (fd, info) = open_stats_fixture(name)?;
                    Ok((fd, if name == map { actual } else { info }))
                },
            );
            let error = result
                .err()
                .expect("invalid per-CPU layout was accepted")
                .to_string();
            assert!(error.contains(map), "{error}");
            for (label, info) in [("expected", expected), ("actual", actual)] {
                assert!(
                    error.contains(&format!(
                        "{label} type={} key={} value={}",
                        info[0], info[2], info[3]
                    )),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn prepare_percpu_stats_propagates_metadata_query_errors_for_each_map() {
    let fixture = SysfsFixture::new(Some("0\n"), &[0]);
    for failed_map in ["CONN_STATE_OCCUPANCY", "OUTBOUND_STATS"] {
        let result = prepare_percpu_stats(
            fixture.root(),
            || Ok(()),
            |name| {
                anyhow::ensure!(name != failed_map, "synthetic metadata query failure");
                open_stats_fixture(name)
            },
        );
        let error = result.err().expect("metadata query failure was ignored");
        let text = format!("{error:#}");
        assert!(text.contains(failed_map), "{text}");
        assert!(text.contains("synthetic metadata query failure"), "{text}");
    }
}

fn encode(counters: OutboundStatsCounters) -> Vec<u8> {
    [
        counters.tx_packets.to_ne_bytes(),
        counters.tx_bytes.to_ne_bytes(),
        counters.rx_packets.to_ne_bytes(),
        counters.rx_bytes.to_ne_bytes(),
    ]
    .concat()
}

#[test]
fn sums_packed_outbound_counters_across_cpus() {
    let mut values = encode(OutboundStatsCounters {
        tx_packets: 1,
        tx_bytes: 20,
        rx_packets: 3,
        rx_bytes: 40,
    });
    values.extend(encode(OutboundStatsCounters {
        tx_packets: 5,
        tx_bytes: 60,
        rx_packets: 7,
        rx_bytes: 80,
    }));

    let total = sum_percpu_outbound(&values);
    assert_eq!(total.tx_packets, 6);
    assert_eq!(total.tx_bytes, 80);
    assert_eq!(total.rx_packets, 10);
    assert_eq!(total.rx_bytes, 120);
}
