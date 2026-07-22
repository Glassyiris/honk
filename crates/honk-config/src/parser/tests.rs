#[allow(unused_imports)]
use crate::parser::parse_dae_config;

#[cfg(test)]
mod parser_tests {
    use crate::parser::parse_dae_config;

    #[test]
    fn test_parse_example_dae() {
        let example = include_str!("../../../../config.dae");
        let result = parse_dae_config(example);
        assert!(
            result.is_ok(),
            "Failed to parse example.dae: {:?}",
            result.err()
        );
        let config = result.unwrap();
        assert!(!config.global.tcp_check_url.is_empty());
        assert!(!config.dns.upstream.is_empty());
    }

    #[test]
    fn test_parse_global_section() {
        let input = r#"
global {
    tproxy_port: 12345
    log_level: info
    dial_mode: domain
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.global.tproxy_port, 12345);
        assert_eq!(config.global.log_level, "info");
        assert_eq!(config.global.dial_mode, "domain");
    }

    #[test]
    fn test_parse_dns_upstream() {
        let input = r#"
dns {
    upstream {
        alidns: 'udp://dns.alidns.com:53'
        googledns: 'tcp+udp://dns.google:53'
        cloudflare_dot: 'tls://1.1.1.1:853'
        google_doh: 'https://dns.google/dns-query'
        cf_h3: 'h3://cloudflare-dns.com/dns-query'
        adguard_doq: 'quic://dns.adguard-dns.com'
        proxied: 'tcp://8.8.8.8:53' -> proxy
        google_via: 'https://dns.google/dns-query' -> proxy
        legacy_out: 'tcp://1.1.1.1:53' outbound: oldproxy
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.dns.upstream.len(), 9);
        assert_eq!(config.dns.upstream[0].name, "alidns");
        assert_eq!(config.dns.upstream[1].name, "googledns");

        let dot = &config.dns.upstream[2];
        assert_eq!(dot.protocol, crate::types::DnsProtocol::Tls);
        assert_eq!(dot.address, "1.1.1.1:853");
        // IP literal → no SNI derived from host.
        assert_eq!(dot.tls_server_name, None);

        let doh = &config.dns.upstream[3];
        assert_eq!(doh.protocol, crate::types::DnsProtocol::Https);
        assert_eq!(doh.address, "dns.google/dns-query");
        assert_eq!(doh.tls_server_name.as_deref(), Some("dns.google"));

        let h3 = &config.dns.upstream[4];
        assert_eq!(h3.protocol, crate::types::DnsProtocol::H3);
        assert_eq!(h3.tls_server_name.as_deref(), Some("cloudflare-dns.com"));

        let doq = &config.dns.upstream[5];
        assert_eq!(doq.protocol, crate::types::DnsProtocol::Quic);
        assert_eq!(doq.tls_server_name.as_deref(), Some("dns.adguard-dns.com"));

        let proxied = &config.dns.upstream[6];
        assert_eq!(proxied.outbound.as_deref(), Some("proxy"));

        let google_via = &config.dns.upstream[7];
        assert_eq!(google_via.protocol, crate::types::DnsProtocol::Https);
        assert_eq!(google_via.address, "dns.google/dns-query");
        assert_eq!(google_via.outbound.as_deref(), Some("proxy"));
        assert_eq!(google_via.tls_server_name.as_deref(), Some("dns.google"));

        // Legacy `outbound:` still accepted.
        let legacy = &config.dns.upstream[8];
        assert_eq!(legacy.outbound.as_deref(), Some("oldproxy"));
    }

    #[test]
    fn test_parse_routing_rules() {
        let input = r#"
routing {
    pname(NetworkManager) -> direct
    dip(224.0.0.0/3) -> direct
    domain(geosite:cn) -> direct
    fallback: my_group
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 3);
        assert_eq!(config.routing.default_outbound, "my_group");
    }

    #[test]
    fn test_parse_nodes() {
        let input = r#"
node {
    'socks5://localhost:1080'
    mylink: 'ss://LINK'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert!(!config.nodes.is_empty());
    }

    #[test]
    fn test_parse_groups() {
        let input = r#"
group {
    my_group {
        policy: min_moving_avg
    }
    group2 {
        filter: name(HK_node)
        filter: name(US_node)
        policy: min_avg10
    }
    iris {
        filter: name('iris')
        policy: fixed(0)
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        // Regression: nested group sections must not be emitted twice (the
        // splitter used to clone the accumulated body at close, so each
        // group was pushed again at the next open / at end-of-input).
        assert_eq!(config.groups.len(), 3);
        assert!(config.groups.iter().any(|g| g.name == "my_group"));
        assert!(config.groups.iter().any(|g| g.name == "group2"));
        let iris = config
            .groups
            .iter()
            .find(|g| g.name == "iris")
            .expect("iris group");
        assert_eq!(iris.policy, crate::group::GroupPolicy::Selector);
        let my_group = config
            .groups
            .iter()
            .find(|g| g.name == "my_group")
            .expect("my_group");
        assert_eq!(my_group.policy, crate::group::GroupPolicy::URLTest);
    }

    #[test]
    fn test_parse_group_policies_loadbalance_fallback() {
        let input = r#"
group {
    rr {
        policy: roundrobin
    }
    rr2 {
        policy: round_robin
    }
    rr3 {
        policy: loadbalance
    }
    rr4 {
        policy: balance
    }
    fb {
        policy: fallback
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        let policy = |name: &str| {
            config
                .groups
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("group '{}' missing", name))
                .policy
        };
        assert_eq!(policy("rr"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr2"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr3"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("rr4"), crate::group::GroupPolicy::LoadBalance);
        assert_eq!(policy("fb"), crate::group::GroupPolicy::Fallback);
    }

    #[test]
    fn test_parse_group_nested_group_filter() {
        // `filter: group('tag')` names nested sub-groups (sing-box style):
        // it lands in `Group.groups`, not in the node `filters`, and a
        // group whose only membership is sub-groups must NOT swallow every
        // node via the filter-less fallback.
        let input = r#"
node {
    hk1: 'socks5://127.0.0.1:1080'
    us1: 'socks5://127.0.0.1:1081'
}
group {
    hk {
        filter: name(keyword: 'hk')
        policy: urltest
    }
    proxy {
        filter: group('hk')
        policy: select
    }
    multi {
        filter: group('hk', 'proxy')
        filter: name('us1')
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        let group = |name: &str| {
            config
                .groups
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("group '{}' missing", name))
        };

        let proxy = group("proxy");
        assert_eq!(proxy.groups, vec!["hk".to_string()]);
        assert!(proxy.filters.is_empty());
        assert!(proxy.nodes.is_empty());
        assert_eq!(proxy.policy, crate::group::GroupPolicy::Selector);

        let multi = group("multi");
        assert_eq!(multi.groups, vec!["hk".to_string(), "proxy".to_string()]);
        assert_eq!(multi.filters, vec!["name('us1')".to_string()]);
        let us1 = config.nodes.iter().find(|n| n.name == "us1").unwrap();
        assert_eq!(multi.nodes, vec![us1.id]);

        let hk1 = config.nodes.iter().find(|n| n.name == "hk1").unwrap();
        assert_eq!(group("hk").nodes, vec![hk1.id]);
    }

    #[test]
    fn test_parse_subscriptions() {
        let input = r#"
subscription {
    my_sub: 'https://www.example.com/subscription/link'
    another_sub: 'https://example.com/another_sub'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.subscriptions.len(), 2);
    }

    #[test]
    fn test_parse_full_global() {
        let input = r#"
global {
    tproxy_port: 12345
    tproxy_port_protect: true
    pprof_port: 0
    so_mark_from_dae: 0
    log_level: info
    disable_waiting_network: false
    wan_interface: auto
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    tcp_check_http_method: HEAD
    udp_check_dns: 'dns.google:53,8.8.8.8'
    check_interval: 30s
    check_tolerance: 50ms
    dial_mode: domain
    allow_insecure: false
    sniffing_timeout: 30ms
    tls_implementation: tls
    utls_imitate: chrome_auto
    tls_fragment: false
    tls_fragment_length: '50-100'
    tls_fragment_interval: '10-20'
    mptcp: false
    fallback_resolver: '8.8.8.8:53'
    bandwidth_max_tx: '200 mbps'
    bandwidth_max_rx: '1 gbps'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.global.tproxy_port, 12345);
        assert!(config.global.tproxy_port_protect);
        assert_eq!(config.global.check_interval_secs, 30);
        assert_eq!(config.global.check_tolerance_ms, 50);
        assert_eq!(config.global.sniffing_timeout_ms, 30);
    }

    #[test]
    fn test_parse_domain_condition_prefixes() {
        let input = r#"
routing {
    domain(suffix: example.com, keyword: foo, full: bar.org) -> direct
    domain(geosite: cn, geosite: category-ai@cn) -> direct
    domain(geosite: private, suffix: example.net) -> direct
    fallback: direct
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 3);

        let r0 = &config.routing.rules[0];
        assert_eq!(r0.condition.domain_suffix, vec!["example.com"]);
        assert_eq!(r0.condition.domain_keyword, vec!["foo"]);
        assert_eq!(r0.condition.domain, vec!["bar.org"]);

        let r1 = &config.routing.rules[1];
        assert_eq!(r1.condition.geosite, vec!["cn", "category-ai-cn"]);

        let r2 = &config.routing.rules[2];
        assert_eq!(r2.condition.geosite, vec!["private"]);
        assert_eq!(r2.condition.domain_suffix, vec!["example.net"]);
    }

    #[test]
    fn test_parse_ip_routing_rules() {
        let input = r#"
routing {
    dip(10.0.0.0/8) -> direct
    dip(172.16.0.0/12, 192.168.0.0/16) -> direct
    fallback: proxy
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(config.routing.rules[0].condition.ip, vec!["10.0.0.0/8"]);
        assert_eq!(
            config.routing.rules[1].condition.ip,
            vec!["172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn test_parse_anytls_node() {
        let input = r#"
node {
    test_node: 'anytls://00000000-0000-0000-0000-000000000000@example.com:443/?sni=example.com&insecure=1#test-node'
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(config.nodes.len(), 1);
        let node = &config.nodes[0];
        // Named node key is the config name; URL fragment is not the name.
        assert_eq!(node.name, "test_node");
        assert!(matches!(node.protocol, crate::types::NodeProtocol::AnyTLS));
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(
            node.password.as_deref(),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert!(node.tls);
        assert_eq!(node.sni.as_deref(), Some("example.com"));
        assert!(node.skip_cert_verify);
    }

    #[test]
    fn test_parse_experimental_section() {
        let input = r#"
experimental {
    clash_api {
        external_controller: 0.0.0.0:9999
        external_ui: yacd
        secret: s3cret
        default_mode: Global
    }
    cache_file {
        enabled: true
        path: cache.db
        cache_id: router1
        store_fakeip: true
        store_dns: true
    }
}
"#;
        let config = parse_dae_config(input).unwrap();
        assert_eq!(
            config.experimental.clash_api.external_controller,
            "0.0.0.0:9999"
        );
        assert_eq!(config.experimental.clash_api.external_ui, "yacd");
        assert_eq!(config.experimental.clash_api.secret, "s3cret");
        assert_eq!(config.experimental.clash_api.default_mode, "Global");
        assert!(config.experimental.cache_file.enabled);
        assert_eq!(config.experimental.cache_file.path, "cache.db");
        assert_eq!(config.experimental.cache_file.cache_id, "router1");
        assert!(config.experimental.cache_file.store_fakeip);
        assert!(config.experimental.cache_file.store_dns);
    }
}

#[test]
fn test_parse_group_default_key() {
    let input = r#"
group {
    proxy {
        filter: group('hk')
        filter: name('direct-out')
        policy: select
        default: 'hk'
        final: direct-out
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let g = config.groups.iter().find(|g| g.name == "proxy").unwrap();
    assert_eq!(g.default.as_deref(), Some("hk"));
    assert_eq!(g.groups, vec!["hk".to_string()]);
    assert_eq!(g.final_outbound.as_deref(), Some("direct-out"));
}

#[test]
fn test_group_filter_multi_tags_comma_and_pipe() {
    let input = r#"
group {
    proxy {
        filter: group('hk', 'jp')
        filter: group('sg|us')
        filter: group('tw', 'ar|de')
        policy: select
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    let g = config.groups.iter().find(|g| g.name == "proxy").unwrap();
    assert_eq!(
        g.groups,
        vec!["hk", "jp", "sg", "us", "tw", "ar", "de"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_group_tags_serde_string_and_array() {
    let g: crate::group::Group =
        serde_json::from_str(r#"{"name":"p","groups":"hk|jp, sg"}"#).unwrap();
    assert_eq!(
        g.groups,
        vec!["hk".to_string(), "jp".to_string(), "sg".to_string()]
    );
    let g: crate::group::Group =
        serde_json::from_str(r#"{"name":"p","groups":["hk","jp|sg"]}"#).unwrap();
    assert_eq!(
        g.groups,
        vec!["hk".to_string(), "jp".to_string(), "sg".to_string()]
    );
}

// ---------------------------------------------------------------------------
// DNS routing parser tests (new dae-shaped model)
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dns_request_routing_qname() {
    let input = r#"
dns {
    routing {
        request {
            qname(geosite:cn) -> alidns
            fallback: default
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    let rule = &config.dns.routing.request.rules[0];
    assert_eq!(rule.conditions.len(), 1);
    match &rule.conditions[0] {
        crate::dns::DnsCond::Qname { not, matchers } => {
            assert!(!not);
            assert_eq!(matchers.len(), 1);
        }
        _ => panic!("expected Qname condition"),
    }
    assert_eq!(
        rule.action,
        crate::dns::DnsRequestAction::Upstream("alidns".to_string())
    );
    // fallback synced to legacy field
    assert_eq!(config.dns.routing.fallback, "default");
}

#[test]
fn test_parse_dns_request_routing_qtype() {
    let input = r#"
dns {
    routing {
        request {
            qtype(a, aaaa) -> alidns
            qtype(https) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    // First rule: qtype(a,aaaa) -> alidns
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qtype { not, types } => {
            assert!(!not);
            assert!(types.contains(&1));
            assert!(types.contains(&28));
        }
        _ => panic!("expected Qtype"),
    }
    // Second rule: qtype(https) -> reject
    match &config.dns.routing.request.rules[1].conditions[0] {
        crate::dns::DnsCond::Qtype { not, types } => {
            assert!(!not);
            assert!(types.contains(&65));
        }
        _ => panic!("expected Qtype"),
    }
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::Reject
    );
}

#[test]
fn test_parse_dns_request_routing_qname_and_qtype() {
    let input = r#"
dns {
    routing {
        request {
            qname(suffix:cn) && qtype(a, aaaa) -> alidns
            qname(full:block.test) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    // First rule: AND of qname + qtype
    assert_eq!(config.dns.routing.request.rules[0].conditions.len(), 2);
    // Second rule: reject
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::Reject
    );
}

#[test]
fn test_parse_dns_request_routing_negation() {
    let input = r#"
dns {
    routing {
        request {
            !qname(geosite:cn) -> googledns
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qname { not, .. } => {
            assert!(*not);
        }
        _ => panic!("expected Qname"),
    }
}

#[test]
fn test_parse_dns_request_routing_reject_asis() {
    let input = r#"
dns {
    routing {
        request {
            qname(keyword:ads) -> reject
            qname(full:local.test) -> asis
            fallback: default
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.request.rules.len(), 2);
    assert_eq!(
        config.dns.routing.request.rules[0].action,
        crate::dns::DnsRequestAction::Reject
    );
    assert_eq!(
        config.dns.routing.request.rules[1].action,
        crate::dns::DnsRequestAction::AsIs
    );
}

#[test]
fn test_parse_dns_response_routing() {
    let input = r#"
dns {
    routing {
        response {
            ip(geoip:private) && !qname(geosite:cn) -> accept
            upstream(googledns) -> reject
            fallback: accept
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.routing.response.rules.len(), 2);
    // First rule
    let rule0 = &config.dns.routing.response.rules[0];
    assert_eq!(rule0.conditions.len(), 2);
    assert_eq!(rule0.action, crate::dns::DnsResponseAction::Accept);
    // Second rule
    let rule1 = &config.dns.routing.response.rules[1];
    match &rule1.conditions[0] {
        crate::dns::DnsCond::Upstream { not, names } => {
            assert!(!not);
            assert!(names.contains(&"googledns".to_string()));
        }
        _ => panic!("expected Upstream"),
    }
    assert_eq!(rule1.action, crate::dns::DnsResponseAction::Reject);
}

#[test]
fn test_parse_fixed_domain_ttl() {
    let input = r#"
dns {
    fixed_domain_ttl {
        a.test: 0
        b.test: 300
        c.test: 60
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    assert_eq!(config.dns.fixed_domain_ttl.get("a.test"), Some(&0u32));
    assert_eq!(config.dns.fixed_domain_ttl.get("b.test"), Some(&300u32));
    assert_eq!(config.dns.fixed_domain_ttl.get("c.test"), Some(&60u32));
}

#[test]
fn test_parse_dns_request_ignores_sub() {
    let input = r#"
dns {
    routing {
        request {
            qname(geosite:cn) -> alidns
            sub(whatever) -> reject
        }
    }
}
"#;
    let config = parse_dae_config(input).unwrap();
    // sub() rule should be ignored, only the qname rule remains
    assert_eq!(config.dns.routing.request.rules.len(), 1);
    match &config.dns.routing.request.rules[0].conditions[0] {
        crate::dns::DnsCond::Qname { .. } => {}
        _ => panic!("expected Qname"),
    }
}
