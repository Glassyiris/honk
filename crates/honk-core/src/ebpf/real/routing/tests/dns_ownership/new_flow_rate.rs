use super::*;
use honk_ebpf_common::conn::{BpfStatsKey, NEW_FLOW_LIMIT_PER_CPU_SECOND};
use nix::sched::{CpuSet, sched_setaffinity};
use nix::unistd::Pid;

const EXCESS: u16 = 20;

fn monotonic_ns() -> u64 {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
        0
    );
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

/// The budget is per CPU and per second: stay on one CPU.
fn pin_to_current_cpu() {
    let cpu = unsafe { libc::sched_getcpu() } as usize;
    let mut set = CpuSet::new();
    set.set(cpu).unwrap();
    sched_setaffinity(Pid::from_raw(0), &set).unwrap();
}

/// Start a burst early in a second so it cannot straddle the window boundary.
fn align_to_second() {
    while monotonic_ns() % 1_000_000_000 > 200_000_000 {
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn limited(backend: &RealEbpfBackend) -> u64 {
    backend
        .get_bpf_stats(BpfStatsKey::NewFlowRateLimited as u32)
        .ok()
        .flatten()
        .unwrap_or(0)
}

fn state_counts(backend: &RealEbpfBackend) -> (usize, usize) {
    (
        flow_count::<TuplesKey, ConnState>(backend, "CONN_STATE_MAP"),
        flow_count::<TuplesKey, RoutingHandoffEntry>(backend, "ROUTING_HANDOFF_MAP"),
    )
}

fn fixture() -> (RealEbpfBackend, TproxyListeners) {
    let (mut backend, _, listeners) = publish(&[rule(
        "all-ports",
        RoutingCondition {
            port: vec!["1-65535".into()],
            ..Default::default()
        },
        "proxy",
        USER_MARK,
        true,
    )]);
    load_classifier(&mut backend, "lan_ingress_l2");
    (backend, listeners)
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn lan_source_over_the_new_flow_limit_is_dropped_before_any_state_is_published() {
    isolated(|| {
        let families: [(IpAddr, IpAddr, IpAddr); 2] = [
            (
                "192.0.2.90".parse().unwrap(),
                "192.0.2.91".parse().unwrap(),
                "203.0.113.90".parse().unwrap(),
            ),
            (
                "2001:db8:1::90".parse().unwrap(),
                "2001:db8:1::91".parse().unwrap(),
                "2001:db8:2::90".parse().unwrap(),
            ),
        ];
        // Pure SYN, first packet of a UDP flow, and stateless UDP/53.
        let kinds = [
            ("TCP SYN", IPPROTO_TCP, 443, 0x02),
            ("UDP", IPPROTO_UDP, 443, 0),
            ("UDP/53", IPPROTO_UDP, 53, 0),
        ];
        let (backend, _listeners) = fixture();
        pin_to_current_cpu();
        for (family, (attacker, other, target)) in families.into_iter().enumerate() {
            for (kind, (label, proto, port, flags)) in kinds.into_iter().enumerate() {
                let attacker = nth_host(attacker, kind);
                align_to_second();
                let context = format!("{label} family {family}");
                let attempt = |source: IpAddr, index: u16| {
                    let bytes = packet(source, target, proto, 20000 + index, port, 0, flags);
                    run(&backend, "lan_ingress_l2", &bytes, SkbInput::default()).verdict
                };
                for index in 0..NEW_FLOW_LIMIT_PER_CPU_SECOND as u16 {
                    assert_eq!(
                        attempt(attacker, index),
                        TC_ACT_REDIRECT,
                        "{context} #{index}"
                    );
                }
                let admitted = state_counts(&backend);
                let before_limited = limited(&backend);

                for index in 0..EXCESS {
                    assert_eq!(
                        attempt(attacker, 1000 + index),
                        TC_ACT_SHOT,
                        "{context}: attempt beyond the limit"
                    );
                }
                assert_eq!(
                    state_counts(&backend),
                    admitted,
                    "{context}: rejected attempts must leave no conn or handoff state"
                );
                assert_eq!(limited(&backend), before_limited + u64::from(EXCESS));

                assert_eq!(
                    attempt(nth_host(other, kind), 0),
                    TC_ACT_REDIRECT,
                    "{context}: another host's new flow"
                );

                if proto == IPPROTO_TCP {
                    // A flow admitted before the limit keeps passing.
                    let ack = packet(attacker, target, proto, 20000, port, 0, 0x10);
                    assert_eq!(
                        run(&backend, "lan_ingress_l2", &ack, SkbInput::default()).verdict,
                        TC_ACT_REDIRECT,
                        "{context}: established flow"
                    );
                }
            }
        }
    });
}

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn local_udp_learning_shares_the_source_budget_without_dropping_service_requests() {
    isolated(|| {
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success()
        );
        pin_to_current_cpu();
        for (client, local, target) in [
            (
                "192.0.2.120".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                "203.0.113.120".parse().unwrap(),
            ),
            (
                "2001:db8:1::120".parse().unwrap(),
                "::1".parse().unwrap(),
                "2001:db8:2::120".parse().unwrap(),
            ),
        ] {
            let (backend, _listeners) = fixture();
            let service = UdpSocket::bind(SocketAddr::new(local, 0)).unwrap();
            let port = service.local_addr().unwrap().port();
            let limit = NEW_FLOW_LIMIT_PER_CPU_SECOND as u16;
            let before_drops = limited(&backend);
            align_to_second();
            for index in 0..limit + EXCESS {
                let request = packet(client, local, IPPROTO_UDP, 20000 + index, port, 0, 0);
                assert_eq!(
                    run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                    TC_ACT_OK,
                    "{client}: service request #{index} must stay native"
                );
            }
            assert_eq!(
                state_counts(&backend),
                (usize::from(limit), 0),
                "{client}: only budgeted requests may allocate reverse conn state"
            );
            assert_eq!(
                limited(&backend),
                before_drops,
                "{client}: skipped learning must not count a packet drop"
            );

            let other = nth_host(client, 1);
            let request = packet(other, local, IPPROTO_UDP, 20000, port, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &request, SkbInput::default()).verdict,
                TC_ACT_OK
            );
            assert!(
                backend
                    .conn_state_lookup(&tuple(local, other, port, 20000, IPPROTO_UDP))
                    .unwrap()
                    .is_some(),
                "{client}: another source still learns"
            );

            // The local-service requests spent the same budget as ordinary routed flows.
            let routed = packet(client, target, IPPROTO_UDP, 30000, 443, 0, 0);
            assert_eq!(
                run(&backend, "lan_ingress_l2", &routed, SkbInput::default()).verdict,
                TC_ACT_SHOT,
                "{client}: local and routed traffic must share one budget"
            );
            assert_eq!(limited(&backend), before_drops + 1);
            assert_eq!(state_counts(&backend), (usize::from(limit) + 1, 0));
            for index in 0..limit + EXCESS {
                let state = backend
                    .conn_state_lookup(&tuple(local, client, port, 20000 + index, IPPROTO_UDP))
                    .unwrap();
                assert_eq!(
                    state.is_some(),
                    index < limit,
                    "{client}: learned reverse tuple #{index}"
                );
            }
        }
    });
}

fn nth_host(base: IpAddr, index: usize) -> IpAddr {
    match base {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            octets[3] = octets[3].wrapping_add(10 * index as u8);
            IpAddr::V4(octets.into())
        }
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            octets[15] = octets[15].wrapping_add(10 * index as u8);
            IpAddr::V6(octets.into())
        }
    }
}
