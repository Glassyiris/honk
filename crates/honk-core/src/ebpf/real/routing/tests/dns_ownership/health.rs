use super::*;

#[test]
#[ignore = "requires root, Linux 6.12+, and HONK_ROUTING_TEST_OBJECT; disposable VM only"]
fn wan_tcp_dns_must_proxy_is_exempt_from_dead_outbound_health() {
    isolated(|| {
        let (mut backend, _, _listeners) = publish(&[rule(
            "dns-proxy",
            RoutingCondition {
                port: vec!["53".into()],
                ..Default::default()
            },
            "proxy",
            USER_MARK,
            true,
        )]);
        for key in 2 * 6..3 * 6 {
            set_array(&mut backend, "OUTBOUND_CONNECTIVITY_MAP", key, 0u64);
        }
        for (src, dst) in [
            ("192.0.2.83".parse().unwrap(), "198.51.100.83".parse().unwrap()),
            ("2001:db8:1::83".parse().unwrap(), "2001:db8:2::83".parse().unwrap()),
        ] {
            let key = tuple(src, dst, 45900, 53, IPPROTO_TCP);
            let syn = packet(src, dst, IPPROTO_TCP, key.src_port, 53, 5, 0x02);
            assert_eq!(
                run(&backend, "wan_egress_l2", &syn, SkbInput::default()).verdict,
                TC_ACT_REDIRECT,
                "{src} TCP53 was dropped by health rather than sent to userspace"
            );
            let entry = handoff(&backend, &key);
            assert_eq!(entry.result.outbound, 2);
            assert_eq!(entry.result.must, 1);
        }
    });
}
