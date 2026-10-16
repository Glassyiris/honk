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

pub(crate) fn hint_auxiliary_tokens_match(
    incarnation: u64,
    current: Option<&ConnState>,
    handoff: Option<&RoutingHandoffEntry>,
    track: Option<&RedirectEntry>,
) -> bool {
    let handoff = handoff.filter(|entry| entry.incarnation == incarnation);
    let track = track.filter(|entry| entry.incarnation == incarnation);
    let token = current
        .map(|state| state.decision_token)
        .or_else(|| handoff.map(|entry| entry.result.decision_token))
        .or_else(|| track.map(|entry| entry.decision_token));
    token.is_none_or(|token| auxiliaries_match(incarnation, token, handoff, track))
}
