use super::{CompiledPredicate, PortRange, Router, protocol_value};
use std::net::IpAddr;

impl Router {
    /// Confirms unconditional direct(must) coverage, not listener or firewall reachability.
    pub(crate) fn confirms_lan_self_protection(&self, address: IpAddr) -> bool {
        ["tcp", "udp"].into_iter().all(|protocol| {
            'rules: for route in self.compiled_routes() {
                if route.conditions.is_empty() {
                    continue;
                }
                let mut certain = true;
                for condition in &route.conditions {
                    let matched = match &condition.predicate {
                        CompiledPredicate::DestinationIp(matcher) => {
                            Some(matcher.matches(&address))
                        }
                        CompiledPredicate::DestinationPort(ranges) => non_dns_ports_match(ranges),
                        CompiledPredicate::Protocol(mask) => {
                            Some(protocol_value(protocol) & mask != 0)
                        }
                        CompiledPredicate::IpVersion(mask) => {
                            Some(mask & if address.is_ipv4() { 1 } else { 2 } != 0)
                        }
                        CompiledPredicate::Domain(_)
                        | CompiledPredicate::SourceIp(_)
                        | CompiledPredicate::SourcePort(_)
                        | CompiledPredicate::Dscp(_)
                        | CompiledPredicate::ProcessName(_)
                        | CompiledPredicate::Mac(_) => None,
                    };
                    match matched.map(|matched| matched != condition.not) {
                        Some(false) => continue 'rules,
                        Some(true) => {}
                        None => certain = false,
                    }
                }
                if route.outbound != "direct" || !route.must {
                    return false;
                }
                if certain {
                    return true;
                }
            }
            false
        })
    }
}

fn non_dns_ports_match(ranges: &[PortRange]) -> Option<bool> {
    // Partial unions remain unconfirmed rather than growing a second policy solver.
    let covers = |start, end| {
        ranges
            .iter()
            .any(|range| range.contains(start) && range.contains(end))
    };
    if covers(1, 52) && covers(54, u16::MAX) {
        Some(true)
    } else if ranges.iter().all(|range| {
        range.start > range.end || range.end == 0 || (range.start == 53 && range.end == 53)
    }) {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honk_config::routing::{
        RoutingCondition, RoutingNotCondition, RoutingOutbound, RoutingRule,
    };

    fn rule(condition: RoutingCondition, outbound: &str, must: bool) -> RoutingRule {
        RoutingRule {
            name: "local-access".into(),
            condition,
            outbound: RoutingOutbound::Simple(outbound.into()),
            priority: 0,
            must,
            mark: 0,
        }
    }

    fn local_rule() -> RoutingRule {
        rule(
            RoutingCondition {
                ip: vec!["192.168.50.0/24".into(), "fd00:50::/64".into()],
                not: RoutingNotCondition {
                    port: vec!["53".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "direct",
            true,
        )
    }

    #[test]
    fn explicit_native_coverage_requires_both_families_and_terminal_ownership() {
        let ipv4 = "192.168.50.1".parse().unwrap();
        let ipv6 = "fd00:50::1".parse().unwrap();
        assert!(
            !Router::new(&[], "direct")
                .unwrap()
                .confirms_lan_self_protection(ipv4)
        );
        let router = Router::new(&[local_rule()], "block").unwrap();
        assert!(router.confirms_lan_self_protection(ipv4));
        assert!(router.confirms_lan_self_protection(ipv6));
        assert!(!router.confirms_lan_self_protection("192.168.51.1".parse().unwrap()));
        let mut ordinary = local_rule();
        ordinary.must = false;
        assert!(
            !Router::new(&[ordinary], "direct")
                .unwrap()
                .confirms_lan_self_protection(ipv4)
        );
        assert!(
            !Router::new(
                &[rule(RoutingCondition::default(), "direct", true)],
                "direct"
            )
            .unwrap()
            .confirms_lan_self_protection(ipv4)
        );
    }

    #[test]
    fn earlier_possible_interception_is_not_hidden_by_a_later_protection_rule() {
        let address = "192.168.50.1".parse().unwrap();
        let conditional = rule(
            RoutingCondition {
                source_ip: vec!["192.168.50.0/25".into()],
                ..Default::default()
            },
            "block",
            true,
        );
        assert!(
            !Router::new(&[conditional.clone(), local_rule()], "direct")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        assert!(
            Router::new(&[local_rule(), conditional.clone()], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let mut harmless = conditional.clone();
        harmless.outbound = RoutingOutbound::Simple("direct".into());
        assert!(
            Router::new(&[harmless, local_rule()], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let mut impossible = conditional;
        impossible.condition.ip = vec!["203.0.113.0/24".into()];
        impossible.condition.domain_suffix = vec!["example.org".into()];
        assert!(
            Router::new(&[impossible, local_rule()], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let dns_only = rule(
            RoutingCondition {
                port: vec!["53".into()],
                ..Default::default()
            },
            "block",
            true,
        );
        assert!(
            Router::new(&[dns_only, local_rule()], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let management_block = rule(
            RoutingCondition {
                port: vec!["22".into()],
                ..Default::default()
            },
            "block",
            true,
        );
        assert!(
            !Router::new(&[management_block, local_rule()], "direct")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let negated_source = rule(
            RoutingCondition {
                not: RoutingNotCondition {
                    source_ip: vec!["192.168.50.0/25".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            "direct",
            true,
        );
        assert!(
            !Router::new(&[negated_source], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
    }

    #[test]
    fn port_and_protocol_boundaries_cannot_hide_uncovered_management_traffic() {
        let address = "192.168.50.1".parse().unwrap();
        for ports in [vec!["1-65535"], vec!["1-52", "54-65535"]] {
            let candidate = rule(
                RoutingCondition {
                    port: ports.into_iter().map(str::to_owned).collect(),
                    ..Default::default()
                },
                "direct",
                true,
            );
            assert!(
                Router::new(&[candidate], "block")
                    .unwrap()
                    .confirms_lan_self_protection(address)
            );
        }
        for ports in [
            vec!["2-65535"],
            vec!["1-52", "55-65535"],
            vec!["1-65534"],
            vec!["53"],
        ] {
            let candidate = rule(
                RoutingCondition {
                    port: ports.into_iter().map(str::to_owned).collect(),
                    ..Default::default()
                },
                "direct",
                true,
            );
            assert!(
                !Router::new(&[candidate], "block")
                    .unwrap()
                    .confirms_lan_self_protection(address)
            );
        }
        let mut tcp = local_rule();
        tcp.condition.protocol = vec!["tcp".into()];
        assert!(
            !Router::new(&[tcp.clone()], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let mut udp = local_rule();
        udp.condition.protocol = vec!["udp".into()];
        assert!(
            Router::new(&[tcp, udp], "block")
                .unwrap()
                .confirms_lan_self_protection(address)
        );
        let mut ipv4_only = local_rule();
        ipv4_only.condition.ip_version = vec!["4".into()];
        let router = Router::new(&[ipv4_only], "block").unwrap();
        assert!(router.confirms_lan_self_protection(address));
        assert!(!router.confirms_lan_self_protection("fd00:50::1".parse().unwrap()));
    }
}
