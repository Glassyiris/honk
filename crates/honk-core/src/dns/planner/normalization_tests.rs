use std::collections::BTreeSet;

use honk_config::dns::{
    DnsCond, DnsRequestAction, DnsRequestRouting, DnsResponseAction, DnsResponseRouting,
    DnsResponseRule, DnsRouting,
};

use super::*;

#[test]
fn mixed_case_response_condition_matches_direct_router_decision() {
    // Given
    let routing = DnsRouting {
        response: DnsResponseRouting {
            rules: vec![DnsResponseRule {
                conditions: vec![DnsCond::Upstream {
                    not: false,
                    names: vec!["DNSMain".into()],
                }],
                action: DnsResponseAction::Reject,
            }],
            fallback: DnsResponseAction::Accept,
        },
        ..DnsRouting::default()
    };
    let direct_router = DnsRouter::new(&routing).expect("direct router");
    let direct = direct_router.select_response("example.test", 1, &[], "DNSMain");
    let planner = Planner::new(
        DnsRouter::new(&routing).expect("planner router"),
        BTreeSet::from([UpstreamTag::new("DNSMain").expect("tag")]),
    );

    // When
    let planned = planner
        .plan_response(
            ResponseContext {
                domain: "example.test",
                qtype: 1,
                answer_ips: &[],
            },
            ResponseTraversal::start(UpstreamTag::new("DNSMain").expect("tag")),
        )
        .expect("response plan");

    // Then
    assert_eq!(direct, DnsResponseDecision::Reject);
    assert_eq!(planned, ResponsePlan::Reject);
}

#[test]
fn mixed_case_request_target_matches_direct_router_decision() {
    // Given
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: vec![],
            fallback: DnsRequestAction::Upstream("DNSMain".into()),
        },
        ..DnsRouting::default()
    };
    let direct = DnsRouter::new(&routing)
        .expect("direct router")
        .select_request("example.test", 1);
    let planner = Planner::new(
        DnsRouter::new(&routing).expect("planner router"),
        BTreeSet::from([UpstreamTag::new("DNSMain").expect("tag")]),
    );

    // When
    let planned = planner
        .plan_request(RequestContext {
            domain: "example.test",
            qtype: 1,
            metadata: DnsRequestMeta::EMPTY,
        })
        .expect("request plan");

    // Then
    assert_eq!(direct, DnsRequestDecision::Upstream("DNSMain".to_string()));
    assert!(matches!(
        planned,
        RequestPlan::Exchange(RequestScope::Upstream(upstream))
            if upstream.as_str() == "DNSMain"
    ));
}

#[test]
fn traversal_cycle_identity_is_case_sensitive_like_runtime_keys() {
    // Given
    let traversal = ResponseTraversal::start(UpstreamTag::new("DNSMain").expect("tag"));

    // When
    let result = traversal.advance(UpstreamTag::new("dnsmain").expect("tag"));

    // Then
    assert!(result.is_ok());
}
