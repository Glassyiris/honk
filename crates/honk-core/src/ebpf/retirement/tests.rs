use super::*;
use crate::ebpf::UdpDecisionCommitResult::{StateMismatch, Superseded, TokenMismatch};
use honk_ebpf_common::conn::{
    TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
    UDP_CONN_STATE_TIMEOUT_NS,
};
use honk_ebpf_common::{
    OutboundIndex, ROUTING_META_FLAG_OFFLOAD, ROUTING_META_FLAG_PUBLISHED,
    ROUTING_META_FLAG_WAN_USERSPACE, RoutingMeta, UdpDecisionState,
};

#[test]
fn snapshots_reject_changed_owner_payload_and_future_timestamps() {
    macro_rules! changed {
        ($compare:ident, $base:expr; $($field:ident $(.$nested:ident)* = $value:expr),+ $(,)?) => {
            let base = $base;
            assert!($compare(&base, &base, 10));
            assert!(!$compare(&base, &base, 9));
            $(
                let mut current = base;
                current.$field$(.$nested)* = $value;
                assert!(!$compare(&current, &base, 10), stringify!($field$(.$nested)*));
            )+
        };
    }
    changed!(conn_matches, ConnState { last_seen_ns: 10, ..Default::default() };
        last_seen_ns = 9,
        incarnation = 1,
        state = 1,
        decision_token = 1,
        is_wan_ingress_direction = 1,
        meta.raw = 1,
        mac = [1; 6],
        pname = [1; honk_ebpf_common::TASK_COMM_LEN],
        pid = 1,
        trace_id = 1,
    );
    changed!(redirect_matches, RedirectEntry { last_seen_ns: 10, ..Default::default() };
        last_seen_ns = 9,
        incarnation = 1,
        decision_token = 1,
        dmac = [1; 6],
        smac = [1; 6],
        from_wan = 1,
        outbound = 1,
        ifindex = 1,
    );
    changed!(handoff_matches, RoutingHandoffEntry { last_seen_ns: 10, ..Default::default() };
        last_seen_ns = 9,
        incarnation = 1,
        routing_generation = 1,
        trace_id = 1,
        result.mark = 1,
        result.must = 1,
        result.mac = [1; 6],
        result.outbound = 1,
        result.pname = [1; honk_ebpf_common::TASK_COMM_LEN],
        result.pid = 1,
        result.dscp = 1,
        result.decision_token = 1,
    );
}

#[test]
fn conn_retirement_checks_owner_state_and_snapshot() {
    let state = ConnState {
        incarnation: 1,
        decision_token: 7,
        state: UdpDecisionState::Pending as u8,
        last_seen_ns: 10,
        ..Default::default()
    };
    for (incarnation, expected) in [(1, Ok(())), (2, Err(Superseded))] {
        assert_eq!(
            validate_conn_retirement(&state, 6, RetireKind::Tcp { incarnation }),
            expected,
        );
    }
    for pending_only in [false, true] {
        for token in [7, 8] {
            for incarnation in [None, Some(1), Some(2)] {
                for decision in [
                    UdpDecisionState::None,
                    UdpDecisionState::Preparing,
                    UdpDecisionState::Pending,
                    UdpDecisionState::Aborted,
                    UdpDecisionState::DirectArmed,
                    UdpDecisionState::Proxy,
                ] {
                    let current = ConnState {
                        state: decision as u8,
                        ..state
                    };
                    let expected = if token != 7 || incarnation == Some(2) {
                        Err(if pending_only {
                            TokenMismatch
                        } else {
                            Superseded
                        })
                    } else if matches!(
                        decision,
                        UdpDecisionState::Preparing
                            | UdpDecisionState::Pending
                            | UdpDecisionState::Aborted
                    ) || (!pending_only && decision == UdpDecisionState::Proxy)
                    {
                        Ok(())
                    } else {
                        Err(StateMismatch)
                    };
                    assert_eq!(
                        validate_conn_retirement(
                            &current,
                            17,
                            RetireKind::Udp {
                                token,
                                incarnation,
                                pending_only,
                            },
                        ),
                        expected,
                    );
                }
            }
        }
    }
    for expired_before_ns in [9, 10] {
        assert_eq!(
            validate_conn_retirement(
                &state,
                17,
                RetireKind::ExpiredConn {
                    expected: &state,
                    expired_before_ns,
                },
            ),
            if expired_before_ns == 10 {
                Ok(())
            } else {
                Err(Superseded)
            },
        );
    }
    let aborted = ConnState {
        state: UdpDecisionState::Aborted as u8,
        ..state
    };
    assert_eq!(
        validate_conn_retirement(
            &aborted,
            17,
            RetireKind::ExpiredConn {
                expected: &aborted,
                expired_before_ns: 0,
            },
        ),
        Ok(()),
    );
    assert_eq!(
        validate_conn_retirement(
            &aborted,
            6,
            RetireKind::ExpiredConn {
                expected: &aborted,
                expired_before_ns: 0,
            },
        ),
        Err(Superseded),
    );
    let changed = ConnState {
        incarnation: 2,
        ..state
    };
    assert_eq!(
        validate_conn_retirement(
            &changed,
            17,
            RetireKind::ExpiredConn {
                expected: &state,
                expired_before_ns: 10,
            },
        ),
        Err(Superseded),
    );
}

#[test]
fn token_zero_requires_legacy_ownership_or_exact_aborted_owner() {
    for (raw, owned) in [
        (0, false),
        (ROUTING_META_FLAG_PUBLISHED, true),
        (
            ROUTING_META_FLAG_PUBLISHED | OutboundIndex::UserBase as u64,
            true,
        ),
        (
            ROUTING_META_FLAG_PUBLISHED | ROUTING_META_FLAG_OFFLOAD,
            false,
        ),
        (ROUTING_META_FLAG_PUBLISHED | (1 << 40), false),
        (
            ROUTING_META_FLAG_PUBLISHED | OutboundIndex::Block as u64,
            false,
        ),
        (
            ROUTING_META_FLAG_PUBLISHED | (1 << 40) | ROUTING_META_FLAG_WAN_USERSPACE,
            true,
        ),
    ] {
        let state = ConnState {
            incarnation: 1,
            meta: RoutingMeta { raw },
            ..Default::default()
        };
        for incarnation in [None, Some(1), Some(2)] {
            assert_eq!(
                validate_conn_retirement(
                    &state,
                    17,
                    RetireKind::Udp {
                        token: 0,
                        incarnation,
                        pending_only: false,
                    },
                ),
                if owned && incarnation != Some(2) {
                    Ok(())
                } else {
                    Err(Superseded)
                },
            );
        }
    }
    for (decision, terminal_owner, pending_owner) in [
        (UdpDecisionState::None, false, false),
        (UdpDecisionState::Preparing, false, true),
        (UdpDecisionState::Pending, false, true),
        (UdpDecisionState::Aborted, true, true),
        (UdpDecisionState::DirectArmed, false, false),
        (UdpDecisionState::Proxy, false, false),
    ] {
        let state = ConnState {
            incarnation: 1,
            state: decision as u8,
            ..Default::default()
        };
        for incarnation in [None, Some(1), Some(2)] {
            for pending_only in [false, true] {
                let expected = if pending_only {
                    if incarnation == Some(2) {
                        Err(TokenMismatch)
                    } else if pending_owner {
                        Ok(())
                    } else {
                        Err(StateMismatch)
                    }
                } else if terminal_owner && incarnation == Some(1) {
                    Ok(())
                } else {
                    Err(Superseded)
                };
                assert_eq!(
                    validate_conn_retirement(
                        &state,
                        17,
                        RetireKind::Udp {
                            token: 0,
                            incarnation,
                            pending_only,
                        },
                    ),
                    expected
                );
            }
        }
    }
}

#[test]
fn expiry_hint_checks_incarnation_and_strict_protocol_deadlines() {
    for (proto, decision, timeout) in [
        (
            6,
            TcpState::TcpStateActive as u8,
            TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS,
        ),
        (
            6,
            TcpState::TcpStateClosing as u8,
            TCP_CONN_STATE_CLOSING_TIMEOUT_NS,
        ),
        (
            17,
            UdpDecisionState::Pending as u8,
            UDP_CONN_STATE_TIMEOUT_NS,
        ),
    ] {
        let state = ConnState {
            incarnation: 1,
            state: decision,
            last_seen_ns: 10,
            ..Default::default()
        };
        let hint_conn = |incarnation, now_ns, conn| {
            let request = RetireRequest {
                key: TuplesKey {
                    l4proto: proto,
                    ..Default::default()
                },
                kind: RetireKind::ExpiryHint {
                    incarnation,
                    now_ns,
                },
            };
            let owners = Owners {
                conn,
                handoff: None,
                redirect: None,
            };
            plan_retirement(&request, &owners).map(|plan| plan.conn)
        };
        assert_eq!(hint_conn(1, u64::MAX, None), Ok(false));
        for (now_ns, expired) in [(0, false), (10 + timeout, false), (11 + timeout, true)] {
            assert_eq!(conn_expired(proto, &state, now_ns), expired);
            assert_eq!(hint_conn(1, now_ns, Some(&state)), Ok(expired));
            assert_eq!(hint_conn(2, now_ns, Some(&state)), Err(Superseded));
            assert_eq!(
                validate_conn_retirement(
                    &state,
                    proto,
                    RetireKind::ExpiryHint {
                        incarnation: 1,
                        now_ns,
                    },
                ),
                if expired { Ok(()) } else { Err(StateMismatch) },
            );
        }
    }
    let aborted = ConnState {
        state: UdpDecisionState::Aborted as u8,
        last_seen_ns: u64::MAX,
        ..Default::default()
    };
    assert!(conn_expired(17, &aborted, 0));
    assert!(!conn_expired(6, &aborted, 0));
}

#[test]
fn auxiliary_ownership_and_hint_expiry_truth_table() {
    let state = ConnState {
        incarnation: 1,
        decision_token: 7,
        ..Default::default()
    };
    let handoff = RoutingHandoffEntry {
        incarnation: 1,
        result: honk_ebpf_common::RoutingResult {
            decision_token: 7,
            ..Default::default()
        },
        ..Default::default()
    };
    let track = RedirectEntry {
        incarnation: 1,
        decision_token: 7,
        ..Default::default()
    };
    let owners = [None, Some((1, 7)), Some((1, 8)), Some((2, 7))];
    let matching = [
        [true, true, false, false],
        [true, true, false, false],
        [false; 4],
        [false; 4],
    ];
    let hint_mismatches = [
        [false; 4],
        [false, false, true, false],
        [false, true, false, false],
        [false; 4],
    ];
    let conn_mismatches = [
        [false, false, true, false],
        [false, false, true, false],
        [true; 4],
        [false, false, true, false],
    ];
    for current in [None, Some(&state)] {
        for (h, handoff_owner) in owners.into_iter().enumerate() {
            for (t, track_owner) in owners.into_iter().enumerate() {
                let handoff = handoff_owner.map(|(incarnation, token)| RoutingHandoffEntry {
                    incarnation,
                    result: honk_ebpf_common::RoutingResult {
                        decision_token: token,
                        ..handoff.result
                    },
                    ..handoff
                });
                let track = track_owner.map(|(incarnation, decision_token)| RedirectEntry {
                    incarnation,
                    decision_token,
                    ..track
                });
                assert_eq!(
                    auxiliaries_match(1, 7, handoff.as_ref(), track.as_ref()),
                    matching[h][t],
                );
                for (now_ns, handoff_expired, track_expired) in [
                    (0, false, false),
                    (ROUTING_HANDOFF_TIMEOUT_NS, false, false),
                    (ROUTING_HANDOFF_TIMEOUT_NS + 1, true, false),
                    (REDIRECT_TRACK_TIMEOUT_NS, true, false),
                    (REDIRECT_TRACK_TIMEOUT_NS + 1, true, true),
                ] {
                    let result = expiry_hint_auxiliary_plan(
                        1,
                        now_ns,
                        &Owners {
                            conn: current,
                            handoff: handoff.as_ref(),
                            redirect: track.as_ref(),
                        },
                    );
                    if if current.is_some() {
                        conn_mismatches[h][t]
                    } else {
                        hint_mismatches[h][t]
                    } {
                        assert!(matches!(result, Err(TokenMismatch)));
                        continue;
                    }
                    let plan = result.unwrap();
                    assert_eq!(plan.handoff, matches!(h, 1 | 2) && handoff_expired,);
                    assert_eq!(plan.redirect, matches!(t, 1 | 2) && track_expired,);
                    if !(plan.handoff || plan.redirect) {
                        assert_eq!(
                            plan.unchanged,
                            if current.is_none() && handoff.is_none() && track.is_none() {
                                crate::ebpf::UdpDecisionCommitResult::Missing
                            } else {
                                StateMismatch
                            },
                        );
                    }
                }
            }
        }
    }
}

fn flow_owners() -> (ConnState, RoutingHandoffEntry, RedirectEntry) {
    (
        ConnState {
            incarnation: 1,
            decision_token: 7,
            state: UdpDecisionState::Pending as u8,
            ..Default::default()
        },
        RoutingHandoffEntry {
            incarnation: 1,
            result: honk_ebpf_common::RoutingResult {
                decision_token: 7,
                ..Default::default()
            },
            ..Default::default()
        },
        RedirectEntry {
            incarnation: 1,
            decision_token: 7,
            ..Default::default()
        },
    )
}

#[test]
fn deletes_are_counted_for_success_and_partial_failure() {
    let counts = RetireCounts {
        conn: 3,
        handoff: 5,
        ..Default::default()
    };
    assert_eq!(conn_deletes(&Ok(counts)), 3);
    assert_eq!(
        conn_deletes(&Err(RetireError {
            counts,
            source: anyhow::anyhow!("fault after partial progress"),
        })),
        3,
    );
}

#[test]
fn only_removed_absent_or_superseded_owners_are_settled() {
    use UdpDecisionCommitResult::*;
    assert!(!RetireOutcome::default().settled());
    for (result, settled) in [
        (Applied, true),
        (Missing, true),
        (Superseded, true),
        (TokenMismatch, false),
        (StateMismatch, false),
    ] {
        assert_eq!(RetireOutcome::from(result).settled(), settled, "{result:?}");
    }
}

#[test]
fn flow_plan_removes_auxiliaries_with_conn_and_refuses_foreign_owners() {
    let (state, handoff, track) = flow_owners();
    let request = RetireRequest::pending_udp(TuplesKey::default(), 7, Some(1));
    let owners = |conn, handoff, redirect| Owners {
        conn,
        handoff,
        redirect,
    };
    let plan = plan_retirement(
        &request,
        &owners(Some(&state), Some(&handoff), Some(&track)),
    )
    .unwrap();
    assert!(plan.conn && plan.handoff && plan.redirect);
    let removed = RetireCounts {
        conn: 1,
        ..Default::default()
    };
    assert_eq!(plan.outcome(removed), RetireOutcome::ConnRetired);
    assert_eq!(
        plan.outcome(RetireCounts::default()),
        RetireOutcome::Done(UdpDecisionCommitResult::Missing),
    );

    let plan = plan_retirement(&request, &owners(Some(&state), None, None)).unwrap();
    assert!(plan.conn && !plan.handoff && !plan.redirect);
    assert_eq!(
        plan_retirement(&request, &owners(None, None, None)).err(),
        Some(UdpDecisionCommitResult::Missing),
    );
    let foreign = RoutingHandoffEntry {
        incarnation: 2,
        ..handoff
    };
    assert_eq!(
        plan_retirement(&request, &owners(Some(&state), Some(&foreign), None)).err(),
        Some(TokenMismatch),
    );
}

#[test]
fn auxiliary_plans_decide_from_their_own_snapshot() {
    let (_, _, track) = flow_owners();
    let none = Owners {
        conn: None,
        handoff: None,
        redirect: None,
    };
    let expire = |kind| RetireRequest {
        key: TuplesKey::default(),
        kind,
    };
    let redirect = expire(RetireKind::ExpiredRedirect {
        expected: &track,
        expired_before_ns: 0,
    });
    assert_eq!(
        plan_retirement(&redirect, &none).err(),
        Some(UdpDecisionCommitResult::Missing),
    );
    let owners = Owners {
        redirect: Some(&track),
        ..none
    };
    let plan = plan_retirement(&redirect, &owners).unwrap();
    assert!(plan.redirect && !plan.conn && !plan.handoff);
    assert_eq!(
        plan.outcome(RetireCounts::default()),
        RetireOutcome::Done(UdpDecisionCommitResult::Applied),
    );
    let newer = RedirectEntry {
        incarnation: 2,
        ..track
    };
    let owners = Owners {
        redirect: Some(&newer),
        ..owners
    };
    assert_eq!(plan_retirement(&redirect, &owners).err(), Some(Superseded));
}

#[test]
fn udp_commit_plan_rewrites_proxy_track_and_requires_initial_auxiliaries() {
    let (state, handoff, track) = flow_owners();
    let plan = plan_udp_commit(
        state,
        7,
        UdpDecisionTransition::ActivateProxy(9, 0),
        Some(&handoff),
        Some(&track),
    )
    .unwrap();
    assert!(plan.remove_handoff);
    assert!(matches!(
        plan.redirect,
        Some(RedirectEffect::Rewrite(rewritten)) if rewritten.outbound == 9
    ));
    assert_eq!(plan.state.state, UdpDecisionState::Proxy as u8);

    let plan = plan_udp_commit(
        state,
        7,
        UdpDecisionTransition::Block,
        Some(&handoff),
        Some(&track),
    )
    .unwrap();
    assert!(matches!(plan.redirect, Some(RedirectEffect::Remove)));
    for (handoff, track) in [(None, Some(&track)), (Some(&handoff), None)] {
        assert_eq!(
            plan_udp_commit(state, 7, UdpDecisionTransition::Block, handoff, track).err(),
            Some(UdpDecisionCommitResult::Missing),
        );
    }
    assert_eq!(
        plan_udp_commit(state, 8, UdpDecisionTransition::Block, Some(&handoff), None).err(),
        Some(TokenMismatch),
    );
}
