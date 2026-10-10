use std::collections::HashMap;
use std::net::IpAddr;

use honk_config::dns::{
    DnsCond, DnsResponseAction, DnsResponseRouting, DnsResponseRule, DnsRouting,
};

use super::DnsRouter;
use crate::dns::routing::DnsResponseDecision;

#[test]
fn upstream_match_preserves_first_match_and_fallback() {
    let router = DnsRouter::new(&DnsRouting {
        response: DnsResponseRouting {
            rules: vec![DnsResponseRule {
                conditions: vec![DnsCond::Upstream {
                    not: false,
                    names: vec!["googledns".into()],
                }],
                action: DnsResponseAction::Reject,
            }],
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    })
    .expect("response routing must compile");
    assert_eq!(
        router.select_response("test.com", 1, &[], "googledns"),
        DnsResponseDecision::Reject
    );
    assert_eq!(
        router.select_response("test.com", 1, &[], "other"),
        DnsResponseDecision::Accept
    );
}

#[test]
fn response_rules_remain_first_match() {
    let matching = DnsCond::Upstream {
        not: false,
        names: vec!["source".into()],
    };
    let router = DnsRouter::new(&DnsRouting {
        response: DnsResponseRouting {
            rules: vec![
                DnsResponseRule {
                    conditions: vec![matching.clone()],
                    action: DnsResponseAction::Reject,
                },
                DnsResponseRule {
                    conditions: vec![matching],
                    action: DnsResponseAction::Upstream("second".into()),
                },
            ],
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    })
    .expect("response routing must compile");
    assert_eq!(
        router.select_response("example.com", 1, &[], "source"),
        DnsResponseDecision::Reject
    );
}

#[test]
fn cidr_match_preserves_requery_and_fallback() {
    let router = DnsRouter::new(&DnsRouting {
        response: DnsResponseRouting {
            rules: vec![DnsResponseRule {
                conditions: vec![DnsCond::Ip {
                    not: false,
                    cidrs: vec![
                        "10.0.0.0/8".into(),
                        "192.168.0.0/16".into(),
                        "2001:db8::/32".into(),
                    ],
                    geoip: vec![],
                }],
                action: DnsResponseAction::Upstream("googledns".into()),
            }],
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    })
    .expect("response routing must compile");
    let private_ip: IpAddr = "10.1.2.3".parse().expect("valid private IP");
    assert_eq!(
        router.select_response("test.com", 1, &[private_ip], "any"),
        DnsResponseDecision::Requery("googledns".into())
    );
    let private_v6: IpAddr = "2001:db8::1".parse().expect("valid private IPv6 address");
    assert_eq!(
        router.select_response("test.com", 1, &[private_v6], "any"),
        DnsResponseDecision::Requery("googledns".into())
    );
    let public_ip: IpAddr = "8.8.8.8".parse().expect("valid public IP");
    assert_eq!(
        router.select_response("test.com", 1, &[public_ip], "any"),
        DnsResponseDecision::Accept
    );
}

#[test]
fn c23_network_forms_share_identity_and_response_behavior() {
    for (input, canonical, answer) in [
        ("192.0.2.1", "192.0.2.1/32", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1/128", "2001:db8::1"),
        ("192.0.2.17/24", "192.0.2.0/24", "192.0.2.99"),
    ] {
        let config = |network: &str| {
            let mut config = honk_config::dns::DnsConfig::default();
            config.routing.response.rules.push(DnsResponseRule {
                conditions: vec![DnsCond::Ip {
                    not: false,
                    cidrs: vec![network.into()],
                    geoip: vec![],
                }],
                action: DnsResponseAction::Reject,
            });
            config
        };
        let candidate = config(input);
        let router = DnsRouter::new(&candidate.routing).unwrap();
        assert_eq!(
            router.select_response("example.test", 1, &[answer.parse().unwrap()], "default"),
            DnsResponseDecision::Reject
        );
        assert_eq!(
            crate::dns::policy::PolicyId::from_config(&candidate).unwrap(),
            crate::dns::policy::PolicyId::from_config(&config(canonical)).unwrap()
        );
        assert!(DnsRouter::new(&config("PRIVATE_INVALID").routing).is_err());
    }
}

#[test]
fn fixed_ttl_lookup_preserves_exact_domain_semantics() {
    let ttl = HashMap::from([("nocache.test".into(), 0), ("custom.test".into(), 300)]);
    let router = DnsRouter::new_with_fixed_ttl(&DnsRouting::default(), &ttl)
        .expect("default routing must compile");
    assert_eq!(router.fixed_ttl("nocache.test"), Some(0));
    assert_eq!(router.fixed_ttl("custom.test"), Some(300));
    assert_eq!(router.fixed_ttl("normal.test"), None);
}

#[test]
fn response_sip_condition_is_rejected() {
    let routing = DnsRouting {
        response: DnsResponseRouting {
            rules: vec![DnsResponseRule {
                conditions: vec![DnsCond::Sip {
                    not: false,
                    cidrs: vec!["192.0.2.0/24".into()],
                }],
                action: DnsResponseAction::Reject,
            }],
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    };

    assert!(DnsRouter::new(&routing).is_err());
}
