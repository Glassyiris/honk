use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use honk_config::dns::{
    DnsCond, DnsRequestAction, DnsRequestRouting, DnsRequestRule, DnsResponseAction,
    DnsResponseRouting, DnsResponseRule, DnsRouting,
};

use super::*;

fn planner() -> Planner {
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: vec![
                request_rule(DnsRequestAction::Reject),
                request_rule(DnsRequestAction::Upstream("second".into())),
            ],
            fallback: DnsRequestAction::AsIs,
        },
        response: DnsResponseRouting {
            rules: vec![
                response_rule(DnsResponseAction::Upstream("second".into())),
                response_rule(DnsResponseAction::Reject),
            ],
            fallback: DnsResponseAction::Accept,
        },
        ..DnsRouting::default()
    };
    let router = DnsRouter::new(&routing).expect("valid router");
    let upstreams = BTreeSet::from([
        UpstreamTag::new("default").expect("tag"),
        UpstreamTag::new("second").expect("tag"),
        UpstreamTag::new("third").expect("tag"),
    ]);
    Planner::new(router, upstreams)
}

#[test]
fn request_rules_are_first_match() {
    // Given
    let planner = planner();

    // When
    let request_plan = planner
        .plan_request(RequestContext {
            domain: "example.test",
            qtype: 1,
            original_dst: Some(SocketAddr::from(([1, 1, 1, 1], 53))),
        })
        .expect("request plan");

    // Then
    assert_eq!(request_plan, RequestPlan::Reject);
}

#[test]
fn response_rules_are_first_match() {
    // Given
    let planner = planner();

    // When
    let response_plan = planner
        .plan_response(
            ResponseContext {
                domain: "example.test",
                qtype: 1,
                answer_ips: &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            },
            ResponseTraversal::start(UpstreamTag::new("default").expect("tag")),
        )
        .expect("response plan");

    // Then
    assert!(matches!(
        response_plan,
        ResponsePlan::Requery { upstream, .. } if upstream.as_str() == "second"
    ));
}

#[test]
fn asis_request_scope_retains_original_destination() {
    // Given
    let planner = planner();
    let destination = SocketAddr::from(([9, 9, 9, 9], 53));

    // When
    let plan = planner
        .plan_request(RequestContext {
            domain: "example.test",
            qtype: 28,
            original_dst: Some(destination),
        })
        .expect("request plan");

    // Then
    assert_eq!(plan, RequestPlan::Exchange(RequestScope::AsIs(destination)));
}

#[test]
fn nested_response_requery_rejects_cycles() {
    // Given
    let planner = planner();
    let default = UpstreamTag::new("default").expect("tag");
    let second = UpstreamTag::new("second").expect("tag");
    let response = ResponseContext {
        domain: "example.test",
        qtype: 1,
        answer_ips: &[],
    };

    // When
    let cycle = planner.plan_response(
        response,
        ResponseTraversal::from_path([second.clone(), default.clone()]).expect("path"),
    );

    // Then
    assert!(matches!(cycle, Err(PlanError::UpstreamCycle { .. })));
}

#[test]
fn nested_response_requery_rejects_depth_overflow() {
    // Given
    let path = [
        UpstreamTag::new("default").expect("tag"),
        UpstreamTag::new("second").expect("tag"),
        UpstreamTag::new("third").expect("tag"),
    ];

    // When
    let depth = ResponseTraversal::from_path(path)
        .expect("path")
        .advance(UpstreamTag::new("fourth").expect("tag"));

    // Then
    assert!(matches!(depth, Err(PlanError::DepthExceeded { max: 3 })));
}

#[test]
fn unknown_upstream_reference_is_a_typed_failure() {
    // Given
    let mut planner = planner();
    planner.upstreams.clear();

    // When
    let result = planner.plan_response(
        ResponseContext {
            domain: "example.test",
            qtype: 1,
            answer_ips: &[],
        },
        ResponseTraversal::start(UpstreamTag::new("default").expect("tag")),
    );

    // Then
    assert!(matches!(result, Err(PlanError::UnknownUpstream { .. })));
}

#[test]
fn upstream_request_scope_uses_logical_tag() {
    // Given
    let planner = default_planner();

    // When
    let result = planner
        .plan_request(RequestContext {
            domain: "example.test",
            qtype: 1,
            original_dst: None,
        })
        .expect("plan");

    // Then
    assert_eq!(
        result,
        RequestPlan::Exchange(RequestScope::Upstream(
            UpstreamTag::new("default").expect("tag")
        ))
    );
}

#[test]
fn asis_without_original_destination_is_a_typed_failure() {
    // Given
    let planner = planner();

    // When
    let result = planner.plan_request(RequestContext {
        domain: "example.test",
        qtype: 28,
        original_dst: None,
    });

    // Then
    assert_eq!(result, Err(PlanError::MissingOriginalDestination));
}

#[test]
fn response_fallback_accepts() {
    // Given
    let planner = planner();

    // When
    let result = planner
        .plan_response(
            ResponseContext {
                domain: "example.test",
                qtype: 1,
                answer_ips: &[],
            },
            ResponseTraversal::start(UpstreamTag::new("second").expect("tag")),
        )
        .expect("plan");

    // Then
    assert_eq!(result, ResponsePlan::Accept);
}

#[test]
fn response_fallback_rejects() {
    // Given
    let routing = DnsRouting {
        response: DnsResponseRouting {
            rules: vec![],
            fallback: DnsResponseAction::Reject,
        },
        ..DnsRouting::default()
    };
    let planner = Planner::new(
        DnsRouter::new(&routing).expect("router"),
        BTreeSet::from([UpstreamTag::new("default").expect("tag")]),
    );

    // When
    let result = planner
        .plan_response(
            ResponseContext {
                domain: "example.test",
                qtype: 1,
                answer_ips: &[],
            },
            ResponseTraversal::start(UpstreamTag::new("default").expect("tag")),
        )
        .expect("plan");

    // Then
    assert_eq!(result, ResponsePlan::Reject);
}

fn request_rule(action: DnsRequestAction) -> DnsRequestRule {
    DnsRequestRule {
        conditions: vec![DnsCond::Qtype {
            not: false,
            types: vec![1],
        }],
        action,
    }
}

fn response_rule(action: DnsResponseAction) -> DnsResponseRule {
    DnsResponseRule {
        conditions: vec![DnsCond::Upstream {
            not: false,
            names: vec!["default".into()],
        }],
        action,
    }
}

fn default_planner() -> Planner {
    let router = DnsRouter::new(&DnsRouting::default()).expect("router");
    Planner::new(
        router,
        BTreeSet::from([UpstreamTag::new("default").expect("tag")]),
    )
}
