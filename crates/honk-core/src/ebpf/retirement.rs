//! Owned flow retirement shared by real and explicit model backends.

use honk_ebpf_common::redirect_need::{TcpRequestKey, TcpSocketBinding};
use honk_ebpf_common::{ConnState, RedirectEntry, RoutingHandoffEntry, TuplesKey};

pub const RETIRE_BATCH_CAPACITY: usize = 128;

pub(crate) const HANDOFF_TIMEOUT_NS: u64 = 30_000_000_000;
pub(crate) const REDIRECT_TIMEOUT_NS: u64 = 120_000_000_000;

#[derive(Debug, Clone, Copy)]
pub struct FlowExpiryHint {
    pub key: TuplesKey,
    pub incarnation: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum TcpSocketOwnership {
    Kernel(TcpSocketBinding),
    Model,
}

#[derive(Debug, Clone, Copy)]
pub struct RetireRequest<'a> {
    pub key: TuplesKey,
    pub kind: RetireKind<'a>,
}

#[derive(Debug, Clone, Copy)]
pub enum RetireKind<'a> {
    Tcp {
        incarnation: u64,
    },
    Udp {
        token: u32,
        incarnation: Option<u64>,
        pending_only: bool,
    },
    ExpiredConn {
        expected: &'a ConnState,
        expired_before_ns: u64,
    },
    ExpiredRedirect {
        expected: &'a RedirectEntry,
        expired_before_ns: u64,
    },
    ExpiredHandoff {
        expected: &'a RoutingHandoffEntry,
        expired_before_ns: u64,
    },
    ExpiredRequest {
        request: &'a TcpRequestKey,
        expected: &'a TcpSocketBinding,
        expired_before_ns: u64,
    },
    ExpiryHint {
        incarnation: u64,
        now_ns: u64,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetireCounts {
    pub conn: u64,
    pub redirect: u64,
    pub handoff: u64,
    pub request: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("flow retirement failed after {counts:?}: {source:#}")]
pub struct RetireError {
    pub counts: RetireCounts,
    #[source]
    pub source: anyhow::Error,
}

pub(crate) fn tuple_matches(a: &TuplesKey, b: &TuplesKey) -> bool {
    (unsafe { a.src_ip.u6_addr8 == b.src_ip.u6_addr8 && a.dst_ip.u6_addr8 == b.dst_ip.u6_addr8 })
        && a.src_port == b.src_port
        && a.dst_port == b.dst_port
        && a.l4proto == b.l4proto
}

pub(crate) fn conn_matches(a: &ConnState, b: &ConnState, cutoff: u64) -> bool {
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.state == b.state
        && a.decision_token == b.decision_token
        && a.is_wan_ingress_direction == b.is_wan_ingress_direction
        && unsafe { a.meta.raw == b.meta.raw }
        && a.mac == b.mac
        && a.pname == b.pname
        && a.pid == b.pid
        && a.trace_id == b.trace_id
}

pub(crate) fn redirect_matches(a: &RedirectEntry, b: &RedirectEntry, cutoff: u64) -> bool {
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.decision_token == b.decision_token
        && a.dmac == b.dmac
        && a.smac == b.smac
        && a.from_wan == b.from_wan
        && a.outbound == b.outbound
        && a.ifindex == b.ifindex
}

pub(crate) fn handoff_matches(
    a: &RoutingHandoffEntry,
    b: &RoutingHandoffEntry,
    cutoff: u64,
) -> bool {
    let (x, y) = (&a.result, &b.result);
    a.last_seen_ns <= cutoff
        && a.last_seen_ns == b.last_seen_ns
        && a.incarnation == b.incarnation
        && a.routing_generation == b.routing_generation
        && a.trace_id == b.trace_id
        && x.mark == y.mark
        && x.must == y.must
        && x.mac == y.mac
        && x.outbound == y.outbound
        && x.pname == y.pname
        && x.pid == y.pid
        && x.dscp == y.dscp
        && x.decision_token == y.decision_token
}

pub(crate) fn request_matches(a: &TcpSocketBinding, b: &TcpSocketBinding, cutoff: u64) -> bool {
    a.kind == b.kind
        && a.syn_isn == b.syn_isn
        && tuple_matches(&a.tuples, &b.tuples)
        && handoff_matches(&a.handoff, &b.handoff, cutoff)
}

pub(crate) fn conn_expired(proto: u8, state: &ConnState, now_ns: u64) -> bool {
    use honk_ebpf_common::conn::{
        TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
        UDP_CONN_STATE_TIMEOUT_NS,
    };
    if proto == libc::IPPROTO_UDP as u8
        && state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
    {
        return true;
    }
    let timeout = if proto == libc::IPPROTO_UDP as u8 {
        UDP_CONN_STATE_TIMEOUT_NS
    } else if state.state == TcpState::TcpStateClosing as u8 {
        TCP_CONN_STATE_CLOSING_TIMEOUT_NS
    } else {
        TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
    };
    now_ns.saturating_sub(state.last_seen_ns) > timeout
}

pub(crate) fn validate_conn_retirement(
    state: &ConnState,
    proto: u8,
    kind: RetireKind<'_>,
) -> Result<(), super::UdpDecisionCommitResult> {
    use super::UdpDecisionCommitResult::*;
    match kind {
        RetireKind::Tcp { incarnation } => {
            if state.incarnation != incarnation {
                return Err(Superseded);
            }
        }
        RetireKind::Udp {
            token,
            incarnation,
            pending_only,
        } => {
            if state.decision_token != token
                || incarnation.is_some_and(|id| id != state.incarnation)
            {
                return Err(if pending_only {
                    TokenMismatch
                } else {
                    Superseded
                });
            }
            if pending_only {
                if state.state != honk_ebpf_common::UdpDecisionState::Preparing as u8
                    && state.state != honk_ebpf_common::UdpDecisionState::Pending as u8
                    && state.state != honk_ebpf_common::UdpDecisionState::Aborted as u8
                {
                    return Err(StateMismatch);
                }
            } else if token != 0 {
                if !super::udp_state_is_userspace_owned(state.state) {
                    return Err(StateMismatch);
                }
            } else if !super::udp_state_is_legacy_userspace_owned(state)
                && !(state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
                    && incarnation == Some(state.incarnation))
            {
                return Err(Superseded);
            }
        }
        RetireKind::ExpiredConn {
            expected,
            expired_before_ns,
        } => {
            let cutoff = if proto == libc::IPPROTO_UDP as u8
                && state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
            {
                u64::MAX
            } else {
                expired_before_ns
            };
            if !conn_matches(state, expected, cutoff) {
                return Err(Superseded);
            }
        }
        RetireKind::ExpiryHint {
            incarnation,
            now_ns,
        } => {
            if state.incarnation != incarnation {
                return Err(Superseded);
            }
            if !conn_expired(proto, state, now_ns) {
                return Err(StateMismatch);
            }
        }
        _ => unreachable!("auxiliary retirement has no conn owner"),
    }
    Ok(())
}

pub(crate) fn auxiliaries_match(
    incarnation: u64,
    token: u32,
    handoff: Option<&RoutingHandoffEntry>,
    track: Option<&RedirectEntry>,
) -> bool {
    handoff.is_none_or(|entry| {
        entry.incarnation == incarnation && entry.result.decision_token == token
    }) && track
        .is_none_or(|entry| entry.incarnation == incarnation && entry.decision_token == token)
}

pub(crate) fn expiry_hint_conn_expired(
    proto: u8,
    incarnation: u64,
    now_ns: u64,
    current: Option<&ConnState>,
) -> Result<bool, super::UdpDecisionCommitResult> {
    let Some(state) = current else {
        return Ok(false);
    };
    match validate_conn_retirement(
        state,
        proto,
        RetireKind::ExpiryHint {
            incarnation,
            now_ns,
        },
    ) {
        Ok(()) => Ok(true),
        Err(super::UdpDecisionCommitResult::StateMismatch) => Ok(false),
        Err(result) => Err(result),
    }
}

pub(crate) struct ExpiryHintAuxiliaryRemoval {
    pub(crate) handoff: bool,
    pub(crate) redirect: bool,
    unchanged: super::UdpDecisionCommitResult,
}

impl ExpiryHintAuxiliaryRemoval {
    pub(crate) fn outcome(self, removed: bool) -> super::UdpDecisionCommitResult {
        if removed {
            super::UdpDecisionCommitResult::Applied
        } else {
            self.unchanged
        }
    }
}

pub(crate) fn expiry_hint_auxiliary_removal(
    incarnation: u64,
    now_ns: u64,
    current: Option<&ConnState>,
    handoff: Option<&RoutingHandoffEntry>,
    track: Option<&RedirectEntry>,
) -> Result<ExpiryHintAuxiliaryRemoval, super::UdpDecisionCommitResult> {
    use super::UdpDecisionCommitResult::*;
    let unchanged = if current.is_none() && handoff.is_none() && track.is_none() {
        Missing
    } else {
        StateMismatch
    };
    let handoff = handoff.filter(|entry| entry.incarnation == incarnation);
    let track = track.filter(|entry| entry.incarnation == incarnation);
    let token = current
        .map(|state| state.decision_token)
        .or_else(|| handoff.map(|entry| entry.result.decision_token))
        .or_else(|| track.map(|entry| entry.decision_token));
    if token.is_some_and(|token| !auxiliaries_match(incarnation, token, handoff, track)) {
        return Err(TokenMismatch);
    }
    Ok(ExpiryHintAuxiliaryRemoval {
        handoff: handoff
            .is_some_and(|entry| now_ns.saturating_sub(entry.last_seen_ns) > HANDOFF_TIMEOUT_NS),
        redirect: track
            .is_some_and(|entry| now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TIMEOUT_NS),
        unchanged,
    })
}

#[cfg(test)]
mod tests {
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
        let request = TcpSocketBinding {
            handoff: RoutingHandoffEntry {
                last_seen_ns: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        changed!(request_matches, request;
            kind = 1,
            syn_isn = 1,
            tuples.src_port = 1,
            tuples.dst_port = 1,
            tuples.l4proto = 1,
            handoff.incarnation = 1,
        );
        for source in [false, true] {
            let mut current = request;
            if source {
                current.tuples.src_ip[0] = 1;
            } else {
                current.tuples.dst_ip[0] = 1;
            }
            assert!(!request_matches(&current, &request, 10));
        }
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
            assert_eq!(
                expiry_hint_conn_expired(proto, 1, u64::MAX, None),
                Ok(false),
            );
            for (now_ns, expired) in [(0, false), (10 + timeout, false), (11 + timeout, true)] {
                assert_eq!(conn_expired(proto, &state, now_ns), expired);
                assert_eq!(
                    expiry_hint_conn_expired(proto, 1, now_ns, Some(&state)),
                    Ok(expired),
                );
                assert_eq!(
                    expiry_hint_conn_expired(proto, 2, now_ns, Some(&state)),
                    Err(Superseded),
                );
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
                        (HANDOFF_TIMEOUT_NS, false, false),
                        (HANDOFF_TIMEOUT_NS + 1, true, false),
                        (REDIRECT_TIMEOUT_NS, true, false),
                        (REDIRECT_TIMEOUT_NS + 1, true, true),
                    ] {
                        let result = expiry_hint_auxiliary_removal(
                            1,
                            now_ns,
                            current,
                            handoff.as_ref(),
                            track.as_ref(),
                        );
                        if if current.is_some() {
                            conn_mismatches[h][t]
                        } else {
                            hint_mismatches[h][t]
                        } {
                            assert!(matches!(result, Err(TokenMismatch)));
                            continue;
                        }
                        let removal = result.unwrap();
                        assert_eq!(removal.handoff, matches!(h, 1 | 2) && handoff_expired,);
                        assert_eq!(removal.redirect, matches!(t, 1 | 2) && track_expired,);
                        let removed = removal.handoff || removal.redirect;
                        assert_eq!(
                            removal.outcome(removed),
                            if removed {
                                crate::ebpf::UdpDecisionCommitResult::Applied
                            } else if current.is_none() && handoff.is_none() && track.is_none() {
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
