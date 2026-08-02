use super::*;

#[test]
fn test_parse_url_host_dae_comma_format() {
    // dae fallback-IP list: only the first segment is the URL host.
    assert_eq!(
        AliveDialerSet::parse_url_host("http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111")
            .as_deref(),
        Some("cp.cloudflare.com")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("http://1.1.1.1,8.8.8.8").as_deref(),
        Some("1.1.1.1")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("https://example.com:8443/").as_deref(),
        Some("example.com")
    );
}

#[test]
fn test_parse_url_host_strips_path_and_missing_scheme() {
    // Regression: the path must never leak into DNS resolution — this was
    // the "Name does not resolve" health-check failure.
    assert_eq!(
        AliveDialerSet::parse_url_host("http://www.google-analytics.com/generate_204").as_deref(),
        Some("www.google-analytics.com")
    );
    // No scheme at all.
    assert_eq!(
        AliveDialerSet::parse_url_host("www.google-analytics.com/generate_204").as_deref(),
        Some("www.google-analytics.com")
    );
    // Path + port + query.
    assert_eq!(
        AliveDialerSet::parse_url_host("https://example.com:8443/check?q=1#f").as_deref(),
        Some("example.com")
    );
    // Bracketed IPv6 with port and path, scheme or not.
    assert_eq!(
        AliveDialerSet::parse_url_host("http://[2606:4700:4700::1111]:443/").as_deref(),
        Some("2606:4700:4700::1111")
    );
    assert_eq!(
        AliveDialerSet::parse_url_host("[2606:4700:4700::1111]:443/path").as_deref(),
        Some("2606:4700:4700::1111")
    );
}

#[test]
fn test_parse_url_port() {
    assert_eq!(AliveDialerSet::parse_url_port("http://a.com"), 80);
    assert_eq!(AliveDialerSet::parse_url_port("https://a.com"), 443);
    assert_eq!(AliveDialerSet::parse_url_port("http://a.com:8080/"), 8080);
    assert_eq!(
        AliveDialerSet::parse_url_port("https://a.com:8443/check?q=1#f"),
        8443
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("http://10.10.10.70:9043/,1.1.1.1"),
        9043
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("http://[2606:4700:4700::1111]:8443/"),
        8443
    );
    assert_eq!(
        AliveDialerSet::parse_url_port("[2606:4700:4700::1111]/path"),
        80
    );
}

#[test]
fn test_parse_check_literals() {
    let lits = AliveDialerSet::parse_check_literals(
        "http://cp.cloudflare.com,1.1.1.1,2606:4700:4700::1111",
        80,
    );
    assert_eq!(
        lits,
        vec![
            "1.1.1.1:80".parse::<SocketAddr>().unwrap(),
            "[2606:4700:4700::1111]:80".parse::<SocketAddr>().unwrap(),
        ]
    );
    // The URL's explicit port applies to the literal fallbacks as well.
    let lits = AliveDialerSet::parse_check_literals("http://a.com:8443/,1.1.1.1", 8443);
    assert_eq!(lits, vec!["1.1.1.1:8443".parse::<SocketAddr>().unwrap()]);
    // No fallback segments → empty; garbage segments skipped.
    assert!(AliveDialerSet::parse_check_literals("http://cp.cloudflare.com", 80).is_empty());
    assert_eq!(
        AliveDialerSet::parse_check_literals("http://a.com,bogus,8.8.8.8", 80).len(),
        1
    );
}

#[test]
fn test_merge_check_addrs_dedup() {
    let resolved = vec!["1.1.1.1:80".parse::<SocketAddr>().unwrap()];
    let merged =
        AliveDialerSet::merge_check_addrs(resolved, "http://cp.cloudflare.com,1.1.1.1,8.8.8.8", 80);
    assert_eq!(merged.len(), 2); // 1.1.1.1 deduped against resolved
}

#[test]
fn test_alive_set_basic() {
    let set = AliveDialerSet::new();
    assert!(set.is_alive("n1"));
    // TCP probe threshold = 1 (Go: immediate death on probe failure):
    // the first failure already marks the node dead.
    set.mark_dead_for("n1", ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive("n1"), "TCP should die after 1 probe failure");
    // DNS UDP probe threshold = 3 — verify per-protocol thresholds
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for("n1", ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for("n1", ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    set.mark_dead_for("n1", ProbeDomain::DnsUdp, IpVersion::V4);
    assert!(!set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    // Mark alive should restore all domains
    set.mark_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4);
    assert!(set.is_alive("n1"));
}

#[test]
fn test_alive_set_per_protocol() {
    let set = AliveDialerSet::new();
    set.register_node("n1".into(), "127.0.0.1:1".into());
    assert!(set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    // Use forced death to bypass grace period for registered nodes.
    set.report_unavailable_forced("n1", ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
}

/// Traffic failures during the grace period must not mark a fresh node
/// dead (restart warm-up regression: mass traffic failures used to kill
/// every node seconds after startup).
#[test]
fn test_traffic_failures_ignored_during_grace() {
    let set = AliveDialerSet::new();
    set.register_node("n1".into(), "127.0.0.1:1".into());
    let threshold = 50;
    for _ in 0..threshold {
        set.report_unavailable_traffic("n1", ProbeDomain::Tcp, IpVersion::V4);
    }
    assert!(
        set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4),
        "traffic failures during grace must not kill the node"
    );
}

#[test]
fn test_probe_cooldown_backoff() {
    let set = AliveDialerSet::new();
    set.register_node("n1".into(), "127.0.0.1:1".into());
    assert!(set.should_probe("n1", ProbeDomain::Tcp, IpVersion::V4));
    // Use forced death to bypass grace period and trigger backoff.
    set.report_unavailable_forced("n1", ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4));
}

#[test]
fn test_sticky_cache_ttl() {
    let c = StickyCache::new(Duration::from_millis(10));
    c.set_sticky(
        "x".into(),
        StickyTarget {
            addr: "a:1".into(),
            protocol: "t".into(),
        },
    );
    assert!(c.get_sticky("x").is_some());
    std::thread::sleep(Duration::from_millis(20));
    assert!(c.get_sticky("x").is_none());
}

#[tokio::test]
async fn test_urltest_idle_suspension() {
    let set = AliveDialerSet::new();
    set.register_node("n1".into(), "127.0.0.1:1".into());
    set.register_urltest_group("g", &["n1".to_string()], Some(Duration::from_millis(50)));

    // Lazy start: a never-active group is idle → probing suspended.
    assert!(set.is_urltest_group_idle("g"));
    assert!(set.is_probe_suspended("n1"));

    // Activity wakes the group.
    set.mark_group_active("g");
    assert!(!set.is_urltest_group_idle("g"));
    assert!(!set.is_probe_suspended("n1"));

    // After the idle timeout it goes idle again.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(set.is_urltest_group_idle("g"));
    assert!(set.is_probe_suspended("n1"));

    // Unregistered groups are never idle; ungrouped nodes never suspended.
    assert!(!set.is_urltest_group_idle("nope"));
    assert!(!set.is_probe_suspended("nope"));
}

#[tokio::test]
async fn test_health_cycle_skips_idle_urltest_nodes() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    // 127.0.0.1:1 refuses connections → a probe records a failure.
    set.register_node("n1".into(), "127.0.0.1:1".into());
    set.register_node("n2".into(), "127.0.0.1:1".into());
    set.register_urltest_group("g", &["n1".to_string()], Some(Duration::from_secs(3600)));

    // n1's group was never active → suspended → cycle never probes it.
    set.run_health_check_cycle(Duration::from_millis(200)).await;
    assert!(
        set.get_probe_history("n1", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "idle URLTest node must not be probed"
    );
    assert!(
        !set.get_probe_history("n2", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "ungrouped node must be probed"
    );

    // Wake the group → next cycle probes n1 again.
    set.mark_group_active("g");
    set.run_health_check_cycle(Duration::from_millis(200)).await;
    assert!(
        !set.get_probe_history("n1", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty(),
        "active URLTest node must be probed"
    );
}

#[test]
fn test_push_ebpf_uses_outbound_resolver() {
    let set = AliveDialerSet::new();
    let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    set.set_ebpf_callback(Box::new(move |o, d, ip, alive| {
        calls2.lock().unwrap().push((o, d, ip, alive));
    }));

    // No resolver installed → legacy outbound 0.
    set.mark_dead("n1"); // Tcp×V4+V6
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[(0u8, 0u32, 0u32, false), (0u8, 0u32, 1u32, false)]
    );

    // Resolver maps n2 → outbound 5; unknown nodes are skipped.
    set.set_outbound_resolver(Some(Arc::new(
        |name: &str| {
            if name == "n2" { Some(5u8) } else { None }
        },
    )));
    set.mark_dead("n2");
    set.mark_dead("n3");
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[
            (0u8, 0u32, 0u32, false),
            (0u8, 0u32, 1u32, false),
            (5u8, 0u32, 0u32, false),
            (5u8, 0u32, 1u32, false),
        ]
    );
}

#[test]
fn test_clear_latency() {
    let set = AliveDialerSet::new();
    set.record_probe_latency(
        "n1",
        ProbeDomain::Tcp,
        IpVersion::V4,
        Duration::from_millis(42),
    );
    assert_eq!(
        set.get_last_latency("n1", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(42))
    );
    set.clear_latency("n1");
    assert_eq!(
        set.get_last_latency("n1", ProbeDomain::Tcp, IpVersion::V4),
        None
    );
}

#[test]
fn test_sync_urltest_groups_full_refresh() {
    let set = AliveDialerSet::new();
    for n in ["n1", "n2", "n3"] {
        set.register_node(n.into(), "127.0.0.1:1".into());
    }
    // Re-registering the same group twice duplicates the node→groups
    // index; the full refresh must rebuild it cleanly.
    set.register_urltest_group("g1", &["n1".to_string()], Some(Duration::from_secs(10)));
    set.register_urltest_group("g1", &["n1".to_string()], Some(Duration::from_secs(10)));
    set.register_urltest_group("g2", &["n2".to_string()], Some(Duration::from_secs(20)));
    set.mark_group_active("g1");

    // Reload: g1 survives with new members/timeout, g2 removed, g3 new.
    set.sync_urltest_groups(&[
        (
            "g1".into(),
            vec!["n2".to_string(), "n3".to_string()],
            Some(Duration::from_secs(30)),
        ),
        ("g3".into(), vec!["n1".to_string()], None),
    ]);

    // g1 keeps its activity timestamp (not idle despite the new 30s
    // timeout because it was just active).
    assert!(!set.is_urltest_group_idle("g1"));
    // g2 is gone → treated as unregistered (never idle).
    assert!(!set.is_urltest_group_idle("g2"));
    // g3 registered with the default timeout, never active → idle.
    assert!(set.is_urltest_group_idle("g3"));

    // Node → groups index rebuilt: n1 now belongs only to g3, n2/n3 to g1.
    assert!(set.is_probe_suspended("n1")); // g3 idle
    assert!(!set.is_probe_suspended("n2")); // g1 active
    assert!(!set.is_probe_suspended("n3")); // g1 active

    // Wake-up membership follows the new table.
    set.sync_urltest_groups(&[("g3".into(), vec!["n1".to_string()], None)]);
    assert!(!set.is_urltest_group_idle("g1")); // removed → never idle
    assert!(!set.is_probe_suspended("n2")); // no groups → not suspended
}

struct MockUdpProber {
    result: std::sync::Mutex<Result<Duration, String>>,
}

impl MockUdpProber {
    fn ok(latency: Duration) -> Self {
        Self {
            result: std::sync::Mutex::new(Ok(latency)),
        }
    }
    fn err(msg: &str) -> Self {
        Self {
            result: std::sync::Mutex::new(Err(msg.to_string())),
        }
    }
}

impl UdpProber for MockUdpProber {
    fn probe_udp(
        &self,
        _node_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>> {
        let r = self.result.lock().unwrap().clone();
        Box::pin(async move { r })
    }
}

struct PendingUdpProber;

impl UdpProber for PendingUdpProber {
    fn probe_udp(
        &self,
        _node_name: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Duration, String>> + Send + 'static>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn test_probe_node_udp_success_marks_udp_domains_alive() {
    let set = AliveDialerSet::new();
    set.register_node("n1".into(), "127.0.0.1:1".into());
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(42))));

    assert!(!set.has_udp_state("n1"));
    assert!(set.probe_node_udp("n1", Duration::from_millis(200)).await);

    for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            assert!(
                set.is_alive_for("n1", domain, ipver),
                "{domain:?}/{ipver:?} must be alive after a successful UDP probe"
            );
            assert_eq!(
                set.get_last_latency("n1", domain, ipver),
                Some(Duration::from_millis(42))
            );
        }
    }
    assert!(set.has_udp_state("n1"));
    // TCP state is untouched by the UDP probe.
    assert!(set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4));
    assert_eq!(
        set.get_last_latency("n1", ProbeDomain::Tcp, IpVersion::V4),
        None
    );
}

#[tokio::test]
async fn test_probe_node_udp_failures_kill_udp_domains_only() {
    let set = AliveDialerSet::new();
    // No register_node → outside the grace period, failures count
    // immediately. Probe failure threshold for the UDP domains is 3.
    set.set_udp_probe(Arc::new(MockUdpProber::err("uot refused")));

    for i in 1..=2 {
        assert!(!set.probe_node_udp("n1", Duration::from_millis(200)).await);
        assert!(
            set.is_alive_for("n1", ProbeDomain::DataUdp, IpVersion::V4),
            "failure {i} must not kill DataUdp yet"
        );
        assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
    }
    assert!(!set.probe_node_udp("n1", Duration::from_millis(200)).await);
    for ipver in [IpVersion::V4, IpVersion::V6] {
        assert!(!set.is_alive_for("n1", ProbeDomain::DataUdp, ipver));
        assert!(!set.is_alive_for("n1", ProbeDomain::DnsUdp, ipver));
    }
    // TCP domains are never touched by UDP probe failures.
    assert!(set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4));
    assert!(set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V6));
    assert!(set.has_udp_state("n1"));

    // A later success revives both UDP domains immediately.
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(10))));
    assert!(set.probe_node_udp("n1", Duration::from_millis(200)).await);
    assert!(set.is_alive_for("n1", ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_probe_node_udp_timeout_counts_as_failure() {
    let set = AliveDialerSet::new();
    set.set_udp_probe(Arc::new(PendingUdpProber));
    assert!(!set.probe_node_udp("n1", Duration::from_millis(20)).await);
    assert!(set.has_udp_state("n1"));
    // One failure is below the threshold of 3 — still alive.
    assert!(set.is_alive_for("n1", ProbeDomain::DataUdp, IpVersion::V4));
    assert!(
        !set.get_probe_history("n1", ProbeDomain::DataUdp, IpVersion::V4)
            .is_empty()
    );
}

#[tokio::test]
async fn test_probe_node_udp_no_prober_is_noop() {
    let set = AliveDialerSet::new();
    assert!(!set.probe_node_udp("n1", Duration::from_millis(20)).await);
    // Without an installed prober nothing is recorded, so the node
    // keeps the legacy TCP-fallback selection semantics.
    assert!(!set.has_udp_state("n1"));
    assert!(set.is_alive_for("n1", ProbeDomain::DataUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_tcp_probe_failure_does_not_touch_udp() {
    let set = AliveDialerSet::new();
    // 127.0.0.1:1 refuses connections → the TCP probe fails.
    set.register_node("n1".into(), "127.0.0.1:1".into());
    assert!(!set.probe_node("n1", Duration::from_millis(100)).await);
    // The failure was recorded for TCP (history is written even inside
    // the registration grace period)…
    assert!(
        !set.get_probe_history("n1", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    // …but no UDP domain was touched.
    assert!(!set.has_udp_state("n1"));
    assert!(set.is_alive_for("n1", ProbeDomain::DataUdp, IpVersion::V4));
    assert!(set.is_alive_for("n1", ProbeDomain::DnsUdp, IpVersion::V4));
}

#[tokio::test]
async fn test_health_cycle_runs_udp_probe_after_tcp() {
    let set = std::sync::Arc::new(AliveDialerSet::new());
    set.register_node("n1".into(), "127.0.0.1:1".into());
    set.set_udp_probe(Arc::new(MockUdpProber::ok(Duration::from_millis(5))));

    set.run_health_check_cycle(Duration::from_millis(200)).await;

    // The cycle ran both probes: TCP failed (connection refused) and
    // the UDP probe succeeded through the mock.
    assert!(
        !set.get_probe_history("n1", ProbeDomain::Tcp, IpVersion::V4)
            .is_empty()
    );
    assert_eq!(
        set.get_last_latency("n1", ProbeDomain::DataUdp, IpVersion::V4),
        Some(Duration::from_millis(5))
    );
    assert!(set.has_udp_state("n1"));
}

#[test]
fn test_has_udp_state_from_traffic_reports() {
    let set = AliveDialerSet::new();
    assert!(!set.has_udp_state("n1"));
    set.report_unavailable_traffic("n1", ProbeDomain::DataUdp, IpVersion::V4);
    assert!(set.has_udp_state("n1"));
    // TCP-domain reports do not count as UDP state.
    let set2 = AliveDialerSet::new();
    set2.report_unavailable_traffic("n1", ProbeDomain::Tcp, IpVersion::V4);
    assert!(!set2.has_udp_state("n1"));
}

/// Stopped nodes (MAX_PROBE_BACKOFF_FAILURES consecutive failures) must
/// still probe once their (max_cooldown) backoff expires — permanent
/// starvation would make the recovery path unreachable and kill
/// single-member Selector groups forever.
#[test]
fn test_stopped_node_probes_on_slow_cadence_and_recovers() {
    let set = AliveDialerSet::new();
    // Unregistered → outside the grace period, failures count immediately.
    for _ in 0..10 {
        set.mark_dead("n1");
    }
    let idx_domain = ProbeDomain::Tcp;
    assert!(set.is_probe_stopped("n1", idx_domain, IpVersion::V4));
    // Deep backoff cooldown (300s) has not expired → no probe yet.
    assert!(!set.should_probe("n1", idx_domain, IpVersion::V4));

    // Backdate the cooldown: a stopped node probes again on the slow
    // cadence (previously it never would).
    {
        let mut states = set.states.write();
        let entry = states.get_mut("n1").unwrap();
        let idx = alive_index(idx_domain, IpVersion::V4);
        entry[idx].cooldown_until = Instant::now() - Duration::from_secs(1);
    }
    assert!(set.should_probe("n1", idx_domain, IpVersion::V4));

    // Recovery hysteresis still applies: two consecutive successes revive
    // the node and clear the stopped flag.
    set.record_probe_latency("n1", idx_domain, IpVersion::V4, Duration::from_millis(50));
    assert!(!set.is_alive_for("n1", idx_domain, IpVersion::V4));
    set.record_probe_latency("n1", idx_domain, IpVersion::V4, Duration::from_millis(50));
    assert!(set.is_alive_for("n1", idx_domain, IpVersion::V4));
    assert!(!set.is_probe_stopped("n1", idx_domain, IpVersion::V4));
}

/// The death callback fires on the probe-path alive→dead flip (per
/// domain/ip-version), not on repeated failures of an already-dead node.
#[test]
fn test_death_callback_fires_on_flip_only() {
    let set = AliveDialerSet::new();
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls2 = calls.clone();
    set.set_death_callback(Some(Box::new(move |node: &str| {
        calls2.lock().unwrap().push(node.to_string());
    })));

    // Unregistered → outside grace; TCP probe threshold is 1. mark_dead
    // covers both IP versions → one call per flipped (domain, ipver).
    set.mark_dead("n1");
    assert_eq!(calls.lock().unwrap().len(), 2);

    // Already dead → no more calls for the same domains.
    set.mark_dead("n1");
    assert_eq!(calls.lock().unwrap().len(), 2);

    // A different domain flips (UDP probe threshold is 3) → one more call.
    for _ in 0..3 {
        set.mark_dead_for("n1", ProbeDomain::DataUdp, IpVersion::V4);
    }
    assert_eq!(calls.lock().unwrap().len(), 3);
}

/// Restored (persisted) delay samples seed ranking data without touching
/// liveness: an unknown node stays in its default alive state, and a
/// previously dead node stays dead.
#[test]
fn test_restore_latency_seeds_ranking_not_liveness() {
    let set = AliveDialerSet::new();
    let at = std::time::SystemTime::now();
    set.restore_latency("n1", Duration::from_millis(88), at);

    // Ranking data present…
    assert_eq!(
        set.get_moving_average("n1", ProbeDomain::Tcp, IpVersion::V4),
        Some(Duration::from_millis(88))
    );
    // …and visible as a real (non-synthetic) display sample.
    let (d, _t) = set
        .get_last_real_sample("n1", ProbeDomain::Tcp, IpVersion::V4)
        .expect("restored sample");
    assert_eq!(d, Duration::from_millis(88));

    // A dead node is not revived by restoration.
    set.report_unavailable_forced("n2", ProbeDomain::Tcp, IpVersion::V4);
    set.restore_latency("n2", Duration::from_millis(50), at);
    assert!(!set.is_alive_for("n2", ProbeDomain::Tcp, IpVersion::V4));
}

/// Per-(node, url) state is fully independent of the global six domains:
/// a node dead for one check URL stays alive globally and for other URLs.
#[test]
fn test_url_probe_state_independence() {
    let set = AliveDialerSet::new();
    let url_a = "http://a.example";
    let url_b = "http://b.example";

    set.record_url_probe_success("n1", url_a, Duration::from_millis(40));
    assert!(set.is_alive_for_url("n1", url_a));
    assert_eq!(
        set.get_avg_latency_for_url("n1", url_a),
        Some(Duration::from_millis(40))
    );

    // One failure kills (TCP-probe parity) — for url_a only.
    set.record_url_probe_failure("n1", url_a);
    assert!(!set.is_alive_for_url("n1", url_a));
    assert!(set.is_alive_for_url("n1", url_b), "other URL unaffected");
    assert!(
        set.is_alive_for("n1", ProbeDomain::Tcp, IpVersion::V4),
        "global TCP state unaffected"
    );

    // Recovery hysteresis: two consecutive successes.
    set.record_url_probe_success("n1", url_a, Duration::from_millis(50));
    assert!(!set.is_alive_for_url("n1", url_a));
    set.record_url_probe_success("n1", url_a, Duration::from_millis(50));
    assert!(set.is_alive_for_url("n1", url_a));
}

/// sync_group_check_urls drops registrations and prunes state for URLs
/// no longer used by any group.
#[test]
fn test_sync_group_check_urls_prunes_unused_urls() {
    let set = AliveDialerSet::new();
    let url_a = "http://a.example";
    set.sync_group_check_urls(&[("g1".into(), url_a.into())]);
    set.record_url_probe_failure("n1", url_a);
    assert!(set.has_url_state("n1", url_a));

    set.sync_group_check_urls(&[]);
    assert!(set.group_check_urls().is_empty());
    assert!(!set.has_url_state("n1", url_a), "unused URL state pruned");
}

/// block is exempt from probes — there is no liveness to measure. The
/// exemption must not touch any alive state (unknown defaults to alive).
#[tokio::test]
async fn test_block_probe_exempt() {
    let set = AliveDialerSet::new();
    set.register_node("block".into(), String::new());
    assert!(set.probe_node("block", Duration::from_millis(1)).await);
    assert!(set.probe_node_udp("block", Duration::from_millis(1)).await);
    assert!(
        set.probe_node_with_url(
            "block",
            "block",
            "http://x.example",
            Duration::from_millis(1)
        )
        .await
    );
    assert!(set.is_alive_for("block", ProbeDomain::Tcp, IpVersion::V4));
}

/// direct is probed against the dedicated direct check target (bootstrap
/// resolver; default 223.5.5.5:53) instead of the proxy check URL, so the
/// clash API gets a real direct latency. Uses a loopback listener as the
/// target; per-group custom-URL and UDP probes stay exempt.
#[tokio::test]
async fn test_direct_probe_uses_direct_check_addr() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let set = AliveDialerSet::new();
    set.register_node("direct".into(), String::new());
    set.set_direct_check_addr(format!("127.0.0.1:{port}"));
    assert!(set.probe_node("direct", Duration::from_secs(2)).await);
    assert!(set.is_alive_for("direct", ProbeDomain::Tcp, IpVersion::V4));
    // UDP and per-group custom-URL probes remain exempt.
    assert!(set.probe_node_udp("direct", Duration::from_millis(1)).await);
    assert!(
        set.probe_node_with_url(
            "direct",
            "direct",
            "http://x.example",
            Duration::from_millis(1)
        )
        .await
    );
}
