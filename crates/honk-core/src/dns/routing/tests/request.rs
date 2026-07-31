use honk_config::dns::{
    DnsCond, DnsDomainMatcher, DnsLegacyRule, DnsRequestAction, DnsRequestRouting, DnsRequestRule,
    DnsRouting,
};

use super::{DnsRouter, router_from_request};
use crate::dns::routing::DnsRequestDecision;

fn rule(condition: DnsCond, action: DnsRequestAction) -> DnsRequestRule {
    DnsRequestRule {
        conditions: vec![condition],
        action,
    }
}

fn request(rules: Vec<DnsRequestRule>) -> DnsRequestRouting {
    DnsRequestRouting {
        rules,
        fallback: DnsRequestAction::Upstream("default".to_owned()),
    }
}

#[test]
fn legacy_rules_are_converted() {
    let router = DnsRouter::new(&DnsRouting {
        rules: vec![DnsLegacyRule {
            domain: "suffix:.cn".into(),
            upstream: "alidns".into(),
        }],
        fallback: "default".into(),
        ..Default::default()
    })
    .expect("legacy routing must compile");
    assert_eq!(router.rule_count(), 1);
    assert_eq!(router.select_upstream("baidu.cn"), "alidns");
    assert_eq!(router.select_upstream("google.com"), "default");
}

#[test]
fn qname_matchers_preserve_semantics() {
    let cases = [
        (
            DnsDomainMatcher::Suffix("cn".into()),
            "www.baidu.cn",
            "google.com",
        ),
        (
            DnsDomainMatcher::Full("example.com".into()),
            "example.com",
            "sub.example.com",
        ),
        (
            DnsDomainMatcher::Keyword("ads".into()),
            "ads.google.com",
            "normal.com",
        ),
        (
            DnsDomainMatcher::Regex(r"^.*\.example\.com$".into()),
            "sub.example.com",
            "other.com",
        ),
    ];
    for (matcher, matching, other) in cases {
        let router = router_from_request(request(vec![rule(
            DnsCond::Qname {
                not: false,
                matchers: vec![matcher],
            },
            DnsRequestAction::Upstream("custom".into()),
        )]));
        assert_eq!(
            router.select_request(matching, 1),
            DnsRequestDecision::Upstream("custom".into())
        );
        assert_eq!(
            router.select_request(other, 1),
            DnsRequestDecision::Upstream("default".into())
        );
    }
}

#[test]
fn qtype_and_combined_conditions_preserve_semantics() {
    let router = router_from_request(request(vec![DnsRequestRule {
        conditions: vec![
            DnsCond::Qname {
                not: false,
                matchers: vec![DnsDomainMatcher::Suffix("cn".into())],
            },
            DnsCond::Qtype {
                not: false,
                types: vec![1, 28],
            },
        ],
        action: DnsRequestAction::Upstream("alidns".into()),
    }]));
    assert_eq!(
        router.select_request("baidu.cn", 1),
        DnsRequestDecision::Upstream("alidns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 28),
        DnsRequestDecision::Upstream("alidns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 65),
        DnsRequestDecision::Upstream("default".into())
    );
    assert_eq!(
        router.select_request("google.com", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn qtype_only_condition_preserves_semantics() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qtype {
            not: false,
            types: vec![65],
        },
        DnsRequestAction::Reject,
    )]));
    assert_eq!(
        router.select_request("test.com", 65),
        DnsRequestDecision::Reject
    );
    assert_eq!(
        router.select_request("test.com", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn negation_preserves_semantics() {
    let router = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: true,
            matchers: vec![DnsDomainMatcher::Suffix("cn".into())],
        },
        DnsRequestAction::Upstream("googledns".into()),
    )]));
    assert_eq!(
        router.select_request("google.com", 1),
        DnsRequestDecision::Upstream("googledns".into())
    );
    assert_eq!(
        router.select_request("baidu.cn", 1),
        DnsRequestDecision::Upstream("default".into())
    );
}

#[test]
fn request_rules_remain_first_match() {
    let router = router_from_request(request(vec![
        rule(
            DnsCond::Qtype {
                not: false,
                types: vec![1],
            },
            DnsRequestAction::Upstream("first".into()),
        ),
        rule(
            DnsCond::Qtype {
                not: false,
                types: vec![1],
            },
            DnsRequestAction::Upstream("second".into()),
        ),
    ]));
    assert_eq!(
        router.select_request("example.com", 1),
        DnsRequestDecision::Upstream("first".into())
    );
}

#[test]
fn request_actions_and_fallback_preserve_semantics() {
    let reject = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Keyword("blocked".into())],
        },
        DnsRequestAction::Reject,
    )]));
    assert_eq!(
        reject.select_request("blocked-site.com", 1),
        DnsRequestDecision::Reject
    );
    let asis = router_from_request(request(vec![rule(
        DnsCond::Qname {
            not: false,
            matchers: vec![DnsDomainMatcher::Full("local.test".into())],
        },
        DnsRequestAction::AsIs,
    )]));
    assert_eq!(
        asis.select_request("local.test", 1),
        DnsRequestDecision::AsIs
    );
    let fallback = router_from_request(DnsRequestRouting {
        rules: vec![],
        fallback: DnsRequestAction::Upstream("fallback_upstream".into()),
    });
    assert_eq!(
        fallback.select_request("anything.com", 1),
        DnsRequestDecision::Upstream("fallback_upstream".into())
    );
}
