use super::*;

/// Number of bpf links this process currently holds open. Every link fd
/// shows a `link_type:` line in its /proc/self/fdinfo entry.
fn held_bpf_link_count() -> usize {
    std::fs::read_dir("/proc/self/fdinfo")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_to_string(e.path())
                        .map(|c| c.contains("link_type:"))
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Total programs attached to the root cgroup2 across every attach type,
/// via raw BPF_PROG_QUERY (kernel ground truth, no aya state involved).
fn cgroup_attached_prog_count(cgroup_fd: RawFd) -> u32 {
    use aya_obj::generated::bpf_attr;
    use aya_obj::generated::bpf_cmd::*;
    let mut total = 0;
    for attach_type in 0..64u32 {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.query.__bindgen_anon_1.target_fd = cgroup_fd as u32;
        attr.query.attach_type = attach_type;
        if unsafe { bpf_syscall(BPF_PROG_QUERY as _, &mut attr) }.is_ok() {
            total += unsafe { attr.query.__bindgen_anon_2.prog_cnt };
        }
    }
    total
}

/// Regression test: every link aya hands us (TC, cgroup sock/sock_addr)
/// must stay owned by the backend until `detach_hooks`. The cgroup links
/// were once dropped at the end of `load()`'s attach loop, detaching all
/// six programs within microseconds and silently disabling pname routing.
#[tokio::test]
#[ignore = "requires root; run via just test-netns"]
async fn link_lifecycle_held_until_detach_hooks() {
    use std::os::fd::AsRawFd;
    let cgroup_path = match detect_cgroup_path() {
        Ok(p) => p,
        Err(_) => return, // cgroup2 unavailable: nothing to attach, nothing to test
    };
    let cgroup_file = std::fs::File::open(&cgroup_path).unwrap();
    let pin_root = Path::new("/sys/fs/bpf").join(format!("honk-link-test-{}", std::process::id()));
    // Other agents (systemd, …) may legitimately hold root-cgroup programs;
    // only the delta belongs to this backend.
    let baseline = cgroup_attached_prog_count(cgroup_file.as_raw_fd());
    let mut backend = RealEbpfBackend::load(
        crate::DEFAULT_BPF_OBJECT,
        &pin_root,
        12345,
        0x0800_0000,
        "lo",
        "",
        true,
    )
    .await
    .expect("backend load");

    // 6 cgroup links + lan_ingress on lo (single-homed: no egress/wan links).
    let held = held_bpf_link_count();
    assert!(
        held >= 7,
        "expected >= 7 held bpf links after load, got {held}"
    );
    assert_eq!(
        cgroup_attached_prog_count(cgroup_file.as_raw_fd()),
        baseline + 6,
        "all 6 cgroup programs must stay attached after load"
    );

    backend.detach_hooks().expect("detach_hooks");
    assert_eq!(
        held_bpf_link_count(),
        0,
        "detach_hooks must release every link"
    );
    assert_eq!(
        cgroup_attached_prog_count(cgroup_file.as_raw_fd()),
        baseline,
        "detach_hooks must detach the cgroup programs"
    );
    backend.cleanup().await.expect("cleanup");
}

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
