use super::*;

#[test]
fn test_parse_possible_cpus() {
    assert_eq!(parse_possible_cpus("0"), 1);
    assert_eq!(parse_possible_cpus("0-3"), 4);
    assert_eq!(parse_possible_cpus("0-3,8-11"), 8);
    assert_eq!(parse_possible_cpus("0,2,4"), 3);
    assert_eq!(parse_possible_cpus("0-1,4,8-9"), 5);
    // Garbage / empty input degrades to a single CPU, never zero.
    assert_eq!(parse_possible_cpus(""), 1);
    assert_eq!(parse_possible_cpus("nonsense"), 1);
}

#[test]
fn test_sum_percpu_u64() {
    // 3 CPUs, contiguous 8-byte native-endian slots.
    let mut buf = Vec::new();
    for v in [100u64, 20, 3] {
        buf.extend_from_slice(&v.to_ne_bytes());
    }
    assert_eq!(sum_percpu_u64(&buf, 3), 123);
    // Fewer CPUs than slots: only the first ncpu slots are summed.
    assert_eq!(sum_percpu_u64(&buf, 2), 120);
    // More CPUs than the buffer holds: missing slots read as zero.
    assert_eq!(sum_percpu_u64(&buf, 4), 123);
    // Saturating accumulation on overflow.
    let mut wide = Vec::new();
    for v in [u64::MAX, 2] {
        wide.extend_from_slice(&v.to_ne_bytes());
    }
    assert_eq!(sum_percpu_u64(&wide, 2), 1);
}

#[test]
fn test_event_ip() {
    // IPv4-mapped (::ffff:8.8.8.8) in network-order u32 chunks.
    let chunks = [0u32, 0, 0x0000ffffu32.to_be(), 0x08080808u32.to_be()];
    assert_eq!(
        event_ip(&chunks),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
    );
    // Plain IPv6 (::1).
    let v6 = [0u32, 0, 0, 1u32.to_be()];
    assert_eq!(
        event_ip(&v6),
        std::net::IpAddr::V6("::1".parse::<std::net::Ipv6Addr>().unwrap())
    );
}
