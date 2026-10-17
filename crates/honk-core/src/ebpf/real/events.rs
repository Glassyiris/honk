use super::*;
use honk_ebpf_common::dae_ip::In6Addr;
use honk_ebpf_common::event::{DaeEvent, DaeEventType};

pub(super) fn validate_flow_lifetime_object_layout(obj: &[u8]) -> anyhow::Result<()> {
    let object = aya_obj::Object::parse(obj)?;
    let data = object
        .btf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("required flow lifetime object BTF not found"))?
        .to_bytes();
    validate_flow_lifetime_btf(&data)?;
    let btf = btf::Btf::parse(&data).ok_or_else(|| anyhow::anyhow!("invalid flow map BTF"))?;
    for (map, payload, size) in [
        (
            "CONN_STATE_MAP",
            "ConnState",
            core::mem::size_of::<FlowMapValue<ConnState>>(),
        ),
        (
            "REDIRECT_TRACK",
            "RedirectEntry",
            core::mem::size_of::<FlowMapValue<RedirectEntry>>(),
        ),
        (
            "ROUTING_HANDOFF_MAP",
            "RoutingHandoffEntry",
            core::mem::size_of::<FlowMapValue<RoutingHandoffEntry>>(),
        ),
    ] {
        let value = object_map_value_type(&object, &btf, map)?;
        anyhow::ensure!(
            flow_value_btf_matches(&btf, value, payload, size),
            "incompatible locked value BTF for {map}; rebuild the eBPF object"
        );
    }
    for map in ["TCP_SOCKET_BINDING", "TCP_REQUEST_BINDINGS"] {
        let value = object_map_value_type(&object, &btf, map)?;
        anyhow::ensure!(
            tcp_proof_btf_matches(&btf, value),
            "incompatible native proof BTF for {map}; rebuild the eBPF object"
        );
    }
    Ok(())
}

fn object_map_value_type(
    object: &aya_obj::Object,
    btf: &btf::Btf<'_>,
    name: &str,
) -> anyhow::Result<usize> {
    let Some(aya_obj::maps::Map::Btf(map)) = object.maps.get(name) else {
        anyhow::bail!("required BTF map {name} missing");
    };
    btf.resolve_composite(map.def.btf_value_type_id)
        .ok_or_else(|| anyhow::anyhow!("required BTF value type for {name} missing"))
}

fn flow_value_btf_matches(btf: &btf::Btf<'_>, value: usize, payload: &str, size: usize) -> bool {
    (|| {
        let (lock, lock_offset) = btf.direct_member(value, "lock")?;
        let lock = btf.resolve_modifiers(lock)?;
        let (padding, padding_offset) = btf.direct_member(value, "padding")?;
        let (inner, payload_offset) = btf.direct_member(value, "value")?;
        Some(
            btf.u32_at(value + 8)? == size as u32
                && lock_offset == 0
                && btf.kind(lock)? == 4
                && btf.string(btf.u32_at(lock)?)? == "bpf_spin_lock"
                && btf.u32_at(lock + 8)? == 4
                && btf.sized_member_offset("bpf_spin_lock", "val", 4) == Some(0)
                && padding_offset == 4
                && btf.unsigned_integer_width(padding, 4)
                && payload_offset == 8
                && Some(btf.resolve_modifiers(inner)?) == btf.find_type(4, payload),
        )
    })()
    .unwrap_or(false)
}

fn tcp_proof_btf_matches(btf: &btf::Btf<'_>, value: usize) -> bool {
    Some(value) == btf.find_type(4, "TcpSocketBinding")
        && btf.u32_at(value + 8) == Some(120)
        && btf.sized_member_offset("TcpSocketBinding", "tuples", 40) == Some(0)
        && btf.sized_member_offset("TcpSocketBinding", "handoff", 72) == Some(40)
        && btf.sized_member_offset("TcpSocketBinding", "kind", 4) == Some(112)
        && btf.sized_member_offset("TcpSocketBinding", "syn_isn", 4) == Some(116)
}

fn validate_flow_lifetime_btf(data: &[u8]) -> anyhow::Result<()> {
    use core::mem::{offset_of, size_of};

    let btf =
        btf::Btf::parse(data).ok_or_else(|| anyhow::anyhow!("invalid flow lifetime object BTF"))?;
    for (name, size, fields) in [
        (
            "TuplesKey",
            size_of::<TuplesKey>(),
            &[("padding", 3, offset_of!(TuplesKey, padding))][..],
        ),
        (
            "ConnState",
            size_of::<ConnState>(),
            &[
                (
                    "is_wan_ingress_direction",
                    1,
                    offset_of!(ConnState, is_wan_ingress_direction),
                ),
                ("state", 1, offset_of!(ConnState, state)),
                ("tcp_syn_flags", 2, offset_of!(ConnState, tcp_syn_flags)),
                ("decision_token", 4, offset_of!(ConnState, decision_token)),
                ("last_seen_ns", 8, offset_of!(ConnState, last_seen_ns)),
                ("meta", 8, offset_of!(ConnState, meta)),
                ("mac", 6, offset_of!(ConnState, mac)),
                ("padding", 2, offset_of!(ConnState, padding)),
                ("pname", 16, offset_of!(ConnState, pname)),
                ("pid", 4, offset_of!(ConnState, pid)),
                ("trace_id", 4, offset_of!(ConnState, trace_id)),
                ("incarnation", 8, offset_of!(ConnState, incarnation)),
                ("tcp_syn_isn", 4, offset_of!(ConnState, tcp_syn_isn)),
                (
                    "tcp_request_count",
                    4,
                    offset_of!(ConnState, tcp_request_count),
                ),
            ][..],
        ),
        (
            "RoutingHandoffEntry",
            size_of::<RoutingHandoffEntry>(),
            &[
                (
                    "last_seen_ns",
                    8,
                    offset_of!(RoutingHandoffEntry, last_seen_ns),
                ),
                ("result", 40, offset_of!(RoutingHandoffEntry, result)),
                (
                    "routing_generation",
                    8,
                    offset_of!(RoutingHandoffEntry, routing_generation),
                ),
                ("trace_id", 4, offset_of!(RoutingHandoffEntry, trace_id)),
                (
                    "trace_padding",
                    4,
                    offset_of!(RoutingHandoffEntry, trace_padding),
                ),
                (
                    "incarnation",
                    8,
                    offset_of!(RoutingHandoffEntry, incarnation),
                ),
            ][..],
        ),
        (
            "RoutingResult",
            size_of::<RoutingResult>(),
            &[
                ("mark", 4, offset_of!(RoutingResult, mark)),
                ("must", 1, offset_of!(RoutingResult, must)),
                ("mac", 6, offset_of!(RoutingResult, mac)),
                ("outbound", 1, offset_of!(RoutingResult, outbound)),
                ("pname", 16, offset_of!(RoutingResult, pname)),
                ("pid", 4, offset_of!(RoutingResult, pid)),
                ("dscp", 1, offset_of!(RoutingResult, dscp)),
                (
                    "decision_token",
                    4,
                    offset_of!(RoutingResult, decision_token),
                ),
            ][..],
        ),
        (
            "RedirectEntry",
            size_of::<RedirectEntry>(),
            &[
                ("last_seen_ns", 8, offset_of!(RedirectEntry, last_seen_ns)),
                ("dmac", 6, offset_of!(RedirectEntry, dmac)),
                ("smac", 6, offset_of!(RedirectEntry, smac)),
                ("from_wan", 1, offset_of!(RedirectEntry, from_wan)),
                ("outbound", 1, offset_of!(RedirectEntry, outbound)),
                ("padding", 2, offset_of!(RedirectEntry, padding)),
                ("ifindex", 4, offset_of!(RedirectEntry, ifindex)),
                (
                    "decision_token",
                    4,
                    offset_of!(RedirectEntry, decision_token),
                ),
                ("incarnation", 8, offset_of!(RedirectEntry, incarnation)),
            ][..],
        ),
        (
            "DaeEvent",
            size_of::<DaeEvent>(),
            &[("incarnation", 8, offset_of!(DaeEvent, incarnation))][..],
        ),
    ] {
        anyhow::ensure!(
            btf.find_type(4, name)
                .and_then(|record| btf.u32_at(record + 8))
                == Some(size as u32)
                && fields.iter().all(|(member, width, offset)| btf
                    .sized_member_offset(name, member, *width)
                    == Some(*offset as u32)),
            "incompatible {name} ABI; rebuild the eBPF object"
        );
    }
    Ok(())
}

/// Format a `DaeEvent` IP field — four u32 chunks of a 16-byte address in
/// network order, IPv4-mapped for v4 flows — as an `IpAddr` for logging.
pub fn event_ip(chunks: &[u32; 4]) -> std::net::IpAddr {
    let mut bytes = [0u8; 16];
    for (i, chunk) in chunks.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&chunk.to_ne_bytes());
    }
    let v6 = std::net::Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    }
}

/// Maximum eBPF datapath events logged per second; excess events within the
/// window are counted and reported in aggregate when the window rolls over,
/// so a conntrack overflow burst cannot storm the log.
pub const EVENT_LOG_MAX_PER_SEC: u32 = 32;

fn dispatch_expiry_event(
    event: &DaeEvent,
    expiry_hints: &tokio::sync::mpsc::Sender<FlowExpiryHint>,
) -> bool {
    if event.type_ != DaeEventType::FlowExpired as u32 {
        return false;
    }
    if matches!(event.l4proto, 6 | 17)
        && event.incarnation != 0
        && event.incarnation <= honk_ebpf_common::conn::FLOW_INCARNATION_MAX
    {
        let hint = FlowExpiryHint {
            key: TuplesKey {
                src_ip: In6Addr {
                    u6_addr32: event.sip,
                },
                dst_ip: In6Addr {
                    u6_addr32: event.dip,
                },
                src_port: event.sport,
                dst_port: event.dport,
                l4proto: event.l4proto,
                padding: [0; 3],
            },
            incarnation: event.incarnation,
        };
        // Advisory only: the ordinary janitor backs up a full hint queue.
        let _ = expiry_hints.try_send(hint);
    }
    true
}

/// Drain functional expiry hints before rate-limiting diagnostic events.
pub async fn consume_dae_events(
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    expiry_hints: tokio::sync::mpsc::Sender<FlowExpiryHint>,
) {
    let mut window = std::time::Instant::now();
    let mut emitted: u32 = 0;
    let mut suppressed: u64 = 0;
    loop {
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                debug!("DaeEvent ringbuf AsyncFd wait failed: {}", e);
                break;
            }
        };
        {
            let ring_buf = guard.get_inner_mut();
            while let Some(item) = ring_buf.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < core::mem::size_of::<DaeEvent>() {
                    continue;
                }
                let ev: DaeEvent =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DaeEvent) };
                if dispatch_expiry_event(&ev, &expiry_hints) {
                    continue;
                }
                if window.elapsed() >= std::time::Duration::from_secs(1) {
                    if suppressed > 0 {
                        warn!(
                            "eBPF datapath events suppressed: {} in the last second",
                            suppressed
                        );
                    }
                    window = std::time::Instant::now();
                    emitted = 0;
                    suppressed = 0;
                }
                if emitted >= EVENT_LOG_MAX_PER_SEC {
                    suppressed += 1;
                    continue;
                }
                emitted += 1;
                let pname_end = ev
                    .pname
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(ev.pname.len());
                let pname = String::from_utf8_lossy(&ev.pname[..pname_end]);
                let sip = event_ip(&ev.sip);
                let dip = event_ip(&ev.dip);
                let is_overflow = ev.type_ == DaeEventType::UdpConnOverflow as u32
                    || ev.type_ == DaeEventType::TcpConnOverflow as u32;
                let is_token_exhaustion =
                    ev.type_ == DaeEventType::UdpDecisionTokenExhausted as u32;
                let kind = match ev.type_ {
                    t if t == DaeEventType::UdpConnOverflow as u32 => "udp_conn_overflow",
                    t if t == DaeEventType::TcpConnOverflow as u32 => "tcp_conn_overflow",
                    t if t == DaeEventType::Blocked as u32 => "blocked",
                    t if t == DaeEventType::UdpDecisionTokenExhausted as u32 => {
                        "udp_decision_token_exhausted"
                    }
                    _ => "unknown",
                };
                if is_overflow {
                    debug!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF conntrack overflow");
                } else if is_token_exhaustion {
                    warn!(target: "honk-ebpf", event = kind, "UDP decision token allocator exhausted");
                } else {
                    debug!(target: "honk-ebpf", event = kind, pid = ev.pid, pname = %pname, l4proto = ev.l4proto, %sip, sport = ev.sport, %dip, dport = ev.dport, outbound = ev.outbound, "eBPF datapath event");
                }
            }
        }
        guard.clear_ready();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_layout_rejects_implicit_padding_and_stale_incarnation() {
        let mut strings = vec![0];
        let mut add_name = |name: &str| {
            let offset = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            offset
        };
        let mut types = vec![
            0u32,
            1 << 24,
            1,
            8,
            0,
            1 << 24,
            8,
            64,
            0,
            3 << 24,
            0,
            1,
            1,
            3,
        ];
        let mut records = [0; 5];
        for (index, (name, size, members)) in [
            ("TuplesKey", 40, &[("padding", 3, 37)][..]),
            (
                "ConnState",
                72,
                &[
                    ("is_wan_ingress_direction", 1, 0),
                    ("state", 1, 1),
                    ("tcp_syn_flags", 19, 2),
                    ("decision_token", 9, 4),
                    ("last_seen_ns", 2, 8),
                    ("meta", 2, 16),
                    ("mac", 15, 24),
                    ("padding", 18, 30),
                    ("pname", 16, 32),
                    ("pid", 9, 48),
                    ("trace_id", 9, 52),
                    ("incarnation", 2, 56),
                    ("tcp_syn_isn", 9, 64),
                    ("tcp_request_count", 9, 68),
                ][..],
            ),
            (
                "RoutingHandoffEntry",
                72,
                &[
                    ("last_seen_ns", 2, 0),
                    ("result", 17, 8),
                    ("routing_generation", 2, 48),
                    ("trace_id", 9, 56),
                    ("trace_padding", 9, 60),
                    ("incarnation", 2, 64),
                ][..],
            ),
            (
                "RedirectEntry",
                40,
                &[
                    ("last_seen_ns", 2, 0),
                    ("dmac", 15, 8),
                    ("smac", 15, 14),
                    ("from_wan", 1, 20),
                    ("outbound", 1, 21),
                    ("padding", 18, 22),
                    ("ifindex", 9, 24),
                    ("decision_token", 9, 28),
                    ("incarnation", 2, 32),
                ][..],
            ),
            ("DaeEvent", 80, &[("incarnation", 2, 72)][..]),
        ]
        .into_iter()
        .enumerate()
        {
            records[index] = btf::BTF_HEADER_LEN + types.len() * 4;
            types.extend_from_slice(&[add_name(name), (4 << 24) | members.len() as u32, size]);
            for (member, type_id, offset) in members {
                types.extend_from_slice(&[add_name(member), *type_id, offset * 8]);
            }
        }
        // IDs 9/10: native u32 and the actual lock type, not a same-size integer.
        types.extend_from_slice(&[add_name("u32"), 1 << 24, 4, 32]);
        types.extend_from_slice(&[
            add_name("bpf_spin_lock"),
            (4 << 24) | 1,
            4,
            add_name("val"),
            9,
            0,
        ]);
        let mut wrappers = [0; 3];
        for (index, (name, payload, size)) in [
            ("ConnValue", 5, 80),
            ("RedirectValue", 7, 48),
            ("HandoffValue", 6, 80),
        ]
        .into_iter()
        .enumerate()
        {
            wrappers[index] = btf::BTF_HEADER_LEN + types.len() * 4;
            types.extend_from_slice(&[
                add_name(name),
                (4 << 24) | 3,
                size,
                add_name("lock"),
                10,
                0,
                add_name("padding"),
                9,
                32,
                add_name("value"),
                payload,
                64,
            ]);
        }
        let proof = btf::BTF_HEADER_LEN + types.len() * 4;
        types.extend_from_slice(&[
            add_name("TcpSocketBinding"),
            (4 << 24) | 4,
            120,
            add_name("tuples"),
            4,
            0,
            add_name("handoff"),
            6,
            320,
            add_name("kind"),
            9,
            896,
            add_name("syn_isn"),
            9,
            928,
        ]);
        // IDs 15/16: byte arrays used by the unchanged payloads.
        for length in [6, 16] {
            types.extend_from_slice(&[0, 3 << 24, 0, 1, 1, length]);
        }
        // ID 17: the unwrapped routing result nested in handoff/proof payloads.
        types.extend_from_slice(&[add_name("RoutingResult"), (4 << 24) | 8, 40]);
        for (name, type_id, offset) in [
            ("mark", 9, 0),
            ("must", 1, 4),
            ("mac", 15, 5),
            ("outbound", 1, 11),
            ("pname", 16, 12),
            ("pid", 9, 28),
            ("dscp", 1, 32),
            ("decision_token", 9, 36),
        ] {
            types.extend_from_slice(&[add_name(name), type_id, offset * 8]);
        }
        types.extend_from_slice(&[0, 3 << 24, 0, 1, 1, 2]);
        types.extend_from_slice(&[add_name("u16"), 1 << 24, 2, 16]);
        let type_len = (types.len() * 4) as u32;
        let mut data = vec![0x9f, 0xeb, 1, 0];
        for word in [
            btf::BTF_HEADER_LEN as u32,
            0,
            type_len,
            type_len,
            strings.len() as u32,
        ] {
            data.extend_from_slice(&word.to_le_bytes());
        }
        for word in types {
            data.extend_from_slice(&word.to_le_bytes());
        }
        data.extend_from_slice(&strings);
        let validate = |data: &[u8]| -> anyhow::Result<()> {
            validate_flow_lifetime_btf(data)?;
            let btf = btf::Btf::parse(data).unwrap();
            for ((record, payload), size) in wrappers
                .iter()
                .zip(["ConnState", "RedirectEntry", "RoutingHandoffEntry"])
                .zip([80, 48, 80])
            {
                anyhow::ensure!(
                    flow_value_btf_matches(&btf, *record, payload, size),
                    "wrapper rejected"
                );
            }
            anyhow::ensure!(tcp_proof_btf_matches(&btf, proof), "proof rejected");
            Ok(())
        };
        assert!(validate(&data).is_ok());
        let syn_name = proof + 48;
        let name: [u8; 4] = data[syn_name..syn_name + 4].try_into().unwrap();
        data[syn_name..syn_name + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[syn_name..syn_name + 4].copy_from_slice(&name);

        let padding_name = records[0] + 12;
        let name: [u8; 4] = data[padding_name..padding_name + 4].try_into().unwrap();
        data[padding_name..padding_name + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[padding_name..padding_name + 4].copy_from_slice(&name);

        let size_offset = records[4] + 8;
        data[size_offset..size_offset + 4].copy_from_slice(&72u32.to_le_bytes());
        assert!(validate(&data).is_err());
        data[size_offset..size_offset + 4].copy_from_slice(&80u32.to_le_bytes());
        let incarnation_offset = records[4] + 20;
        data[incarnation_offset..incarnation_offset + 4]
            .copy_from_slice(&(64u32 * 8).to_le_bytes());
        assert!(validate(&data).is_err());
        data[incarnation_offset..incarnation_offset + 4]
            .copy_from_slice(&(72u32 * 8).to_le_bytes());
        assert!(validate(&data).is_ok());
        for wrapper in wrappers {
            for (offset, invalid) in [
                (wrapper + 16, 9u32),
                (wrapper + 20, 32),
                (wrapper + 32, 0),
                (wrapper + 44, 0),
            ] {
                let original: [u8; 4] = data[offset..offset + 4].try_into().unwrap();
                data[offset..offset + 4].copy_from_slice(&invalid.to_le_bytes());
                assert!(validate(&data).is_err());
                data[offset..offset + 4].copy_from_slice(&original);
                assert!(validate(&data).is_ok());
            }
        }
        let handoff_offset = proof + 32;
        data[handoff_offset..handoff_offset + 4].copy_from_slice(&328u32.to_le_bytes());
        assert!(validate(&data).is_err());
    }

    #[test]
    fn expiry_dispatch_preserves_tuple_and_drops_only_advisory_overflow() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut event: DaeEvent = unsafe { core::mem::zeroed() };
        event.type_ = DaeEventType::FlowExpired as u32;
        event.l4proto = 6;
        event.incarnation = 42;
        event.sip = unsafe { In6Addr::from_ipv4_bytes([192, 0, 2, 1]).u6_addr32 };
        event.dip = unsafe { In6Addr::from_ipv4_bytes([198, 51, 100, 2]).u6_addr32 };
        event.sport = 49152;
        event.dport = 443;

        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = 43;
        assert!(dispatch_expiry_event(&event, &tx));
        let hint = rx.try_recv().unwrap();
        assert_eq!(hint.incarnation, 42);
        assert_eq!(unsafe { hint.key.src_ip.u6_addr32 }, event.sip);
        assert_eq!(unsafe { hint.key.dst_ip.u6_addr32 }, event.dip);
        assert_eq!(hint.key.src_port, 49152);
        assert_eq!(hint.key.dst_port, 443);
        assert_eq!(hint.key.l4proto, 6);
        assert_eq!(hint.key.padding, [0; 3]);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        event.l4proto = 17;
        assert!(dispatch_expiry_event(&event, &tx));
        assert_eq!(rx.try_recv().unwrap().key.l4proto, 17);
        event.incarnation = 0;
        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = honk_ebpf_common::conn::FLOW_INCARNATION_MAX + 1;
        assert!(dispatch_expiry_event(&event, &tx));
        event.incarnation = 44;
        event.l4proto = 1;
        assert!(dispatch_expiry_event(&event, &tx));
        event.type_ = DaeEventType::Blocked as u32;
        assert!(!dispatch_expiry_event(&event, &tx));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        drop(tx);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
