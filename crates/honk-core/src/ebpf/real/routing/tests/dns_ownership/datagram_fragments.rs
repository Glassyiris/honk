use super::*;
use aya::maps::HashMap as AyaHashMap;
use honk_ebpf_common::conn::{FRAGMENT_VERDICT_TTL_NS, FragmentKey, FragmentVerdict};

const PORT_FIRST: u16 = 40000;

/// One fragment of a UDP datagram. The first fragment carries the UDP header and MF;
/// a later fragment is the bare second 8-byte block.
fn fragment(src: IpAddr, dst: IpAddr, dst_port: u16, id: u32, first: bool) -> Vec<u8> {
    fragment_with_dscp(src, dst, dst_port, id, first, 0)
}

fn fragment_with_dscp(
    src: IpAddr,
    dst: IpAddr,
    dst_port: u16,
    id: u32,
    first: bool,
    dscp: u8,
) -> Vec<u8> {
    let mut frame = packet(src, dst, IPPROTO_UDP, PORT_FIRST, dst_port, dscp, 0);
    // The test device's all-zero address makes this PACKET_HOST, which the DNS fragment path requires.
    frame[..6].fill(0);
    match src {
        IpAddr::V4(_) => {
            if !first {
                frame.truncate(14 + 20 + 8);
                frame[16..18].copy_from_slice(&28u16.to_be_bytes());
            }
            frame[18..20].copy_from_slice(&(id as u16).to_be_bytes());
            let flags_offset: u16 = if first { 0x2000 } else { 1 };
            frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
            frame[24..26].fill(0);
            let checksum = internet_checksum(&[&frame[14..34]]);
            frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        }
        IpAddr::V6(_) => {
            let payload = if first {
                frame.split_off(54)
            } else {
                vec![0xa5; 8]
            };
            frame.truncate(54);
            frame[20] = 44;
            let offset_flags: u16 = if first { 1 } else { 1 << 3 };
            let mut header = vec![IPPROTO_UDP, 0];
            header.extend_from_slice(&offset_flags.to_be_bytes());
            header.extend_from_slice(&id.to_be_bytes());
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&payload);
            let payload_len = (frame.len() - 54) as u16;
            frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
        }
    }
    frame
}

fn families() -> [(IpAddr, IpAddr, IpAddr); 2] {
    [
        (
            "192.0.2.110".parse().unwrap(),
            "192.0.2.111".parse().unwrap(),
            "203.0.113.110".parse().unwrap(),
        ),
        (
            "2001:db8:1::110".parse().unwrap(),
            "2001:db8:1::111".parse().unwrap(),
            "2001:db8:2::110".parse().unwrap(),
        ),
    ]
}

fn host(base: IpAddr, index: u8) -> IpAddr {
    match base {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            octets[3] = octets[3].wrapping_add(index);
            IpAddr::V4(octets.into())
        }
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            octets[15] = octets[15].wrapping_add(index);
            IpAddr::V6(octets.into())
        }
    }
}

fn fixture(outbound: &str, must: bool, port: &str) -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&[rule(
        "fragments",
        RoutingCondition {
            port: vec![port.into()],
            ..Default::default()
        },
        outbound,
        USER_MARK,
        must,
    )]);
    for name in ["lan_ingress_l2", "wan_egress_l2"] {
        load_classifier(&mut backend, name);
    }
    (backend, listeners)
}

fn publish_dns_fixture() -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&dns_ordering_rules());
    load_classifier(&mut backend, "lan_ingress_l2");
    (backend, listeners)
}

fn verdict(backend: &RealEbpfBackend, side: &str, frame: &[u8]) -> u32 {
    run(backend, side, frame, SkbInput::default()).verdict
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn later_fragments_of_a_redirected_or_dropped_datagram_are_dropped() {
    isolated(|| {
        // A proxy flow is redirected to userspace; block and a dead proxy are dropped in the kernel.
        for (case, outbound, dead, first_verdict) in [
            ("proxy", "proxy", false, TC_ACT_REDIRECT),
            ("block", "block", false, TC_ACT_SHOT),
            ("dead proxy", "proxy", true, TC_ACT_SHOT),
        ] {
            let (mut backend, _listeners) = fixture(outbound, true, "443");
            if dead {
                for key in 2 * 6..3 * 6 {
                    set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 0u64);
                }
            }
            for (family, (src, other_src, dst)) in families().into_iter().enumerate() {
                for (side_index, side) in
                    ["lan_ingress_l2", "wan_egress_l2"].into_iter().enumerate()
                {
                    let src = host(src, 4 * side_index as u8);
                    let context = format!("{case} {side} family {family}");
                    let id = 0x1234 + side_index as u32;
                    assert_eq!(
                        verdict(&backend, side, &fragment(src, dst, 443, id, true)),
                        first_verdict,
                        "{context}: first fragment"
                    );
                    assert_eq!(
                        verdict(&backend, side, &fragment(src, dst, 443, id, false)),
                        TC_ACT_SHOT,
                        "{context}: later fragment of the same datagram"
                    );
                    for (label, other) in [
                        (
                            "another datagram ID",
                            fragment(src, dst, 443, id + 7, false),
                        ),
                        ("another source", fragment(other_src, dst, 443, id, false)),
                    ] {
                        assert_eq!(
                            verdict(&backend, side, &other),
                            TC_ACT_OK,
                            "{context}: {label}"
                        );
                    }
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn later_fragments_of_direct_staged_and_dns_datagrams_still_pass() {
    isolated(|| {
        for (family, (src, _, dst)) in families().into_iter().enumerate() {
            // Native direct on the LAN hook; the WAN hook reroutes direct marked traffic.
            let (backend, _listeners) = fixture("direct", true, "443");
            let src = host(src, 0);
            let first = fragment(src, dst, 443, 0x2000, true);
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &first),
                TC_ACT_OK,
                "direct family {family}: first fragment"
            );
            assert_eq!(
                verdict(
                    &backend,
                    "lan_ingress_l2",
                    &fragment(src, dst, 443, 0x2000, false)
                ),
                TC_ACT_OK,
                "direct family {family}: later fragment"
            );

            // NFQUEUE-staged: no rule matches, so the unresolved direct fallback is held.
            let (mut backend, _listeners) = fixture("proxy", true, "443");
            backend
                .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                .unwrap();
            let src = host(src, 8);
            let first = run(
                &backend,
                "lan_ingress_l2",
                &fragment(src, dst, 444, 0x3000, true),
                SkbInput::default(),
            );
            assert_eq!(first.verdict, TC_ACT_OK, "staged family {family}");
            assert_ne!(first.mark & NFQUEUE_TOKEN_MASK, 0, "staged family {family}");
            assert_eq!(
                verdict(
                    &backend,
                    "lan_ingress_l2",
                    &fragment(src, dst, 444, 0x3000, false)
                ),
                TC_ACT_OK,
                "staged family {family}: later fragment"
            );

            // UDP/53 fragments belong to the DNS fragment path, which keeps no verdict.
            // DSCP 46 selects the raw must-proxy DNS rule, the only one that stages fragments.
            let (mut backend, _listeners) = publish_dns_fixture();
            let src = host(src, 4);
            let dns = |id, first| fragment_with_dscp(src, dst, 53, id, first, 46);
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &dns(0x4000, true)),
                TC_ACT_SHOT,
                "DNS family {family} without NFQUEUE"
            );
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &dns(0x4000, false)),
                TC_ACT_OK,
                "DNS family {family} without NFQUEUE: later fragment"
            );
            backend
                .set_datapath_flags(DATAPATH_FLAG_NFQ_ENABLED | DATAPATH_FLAG_NFQ_READY)
                .unwrap();
            let src = host(src, 1);
            let dns = |id, first| fragment_with_dscp(src, dst, 53, id, first, 46);
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &dns(0x4001, true)),
                TC_ACT_OK,
                "DNS family {family} with NFQUEUE"
            );
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &dns(0x4001, false)),
                TC_ACT_OK,
                "DNS family {family} with NFQUEUE: later fragment"
            );
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn an_expired_fragment_record_does_not_affect_a_reused_datagram_id() {
    isolated(|| {
        // A fresh VM may have less uptime than the record TTL. Wait once for a
        // genuine old monotonic timestamp, rather than wrapping the backdated age.
        let wait_ns = (FRAGMENT_VERDICT_TTL_NS + 2_000_000_000).saturating_sub(monotonic_ns());
        if wait_ns != 0 {
            std::thread::sleep(std::time::Duration::from_nanos(wait_ns));
        }
        for (family, (src, _, dst)) in families().into_iter().enumerate() {
            let (mut backend, _listeners) = fixture("proxy", true, "443");
            let id = 0x5000;
            let later = fragment(src, dst, 443, id, false);
            assert_eq!(
                verdict(
                    &backend,
                    "lan_ingress_l2",
                    &fragment(src, dst, 443, id, true)
                ),
                TC_ACT_REDIRECT
            );
            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &later),
                TC_ACT_SHOT,
                "family {family}: fresh record"
            );

            let map = backend.bpf_mut().unwrap().map_mut("FRAG_VERDICT").unwrap();
            let mut map = AyaHashMap::<_, FragmentKey, FragmentVerdict>::try_from(map).unwrap();
            let keys: Vec<_> = map.keys().map(Result::unwrap).collect();
            assert_eq!(keys.len(), 1, "family {family}");
            let mut aged = map.get(&keys[0], 0).unwrap();
            aged.ktime_ns = monotonic_ns() - FRAGMENT_VERDICT_TTL_NS - 1_000_000_000;
            map.insert(keys[0], aged, 0).unwrap();

            assert_eq!(
                verdict(&backend, "lan_ingress_l2", &later),
                TC_ACT_OK,
                "family {family}: expired record"
            );
        }
    });
}

fn monotonic_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}
