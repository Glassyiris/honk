//! Owned flow retirement shared by real and explicit model backends.

use honk_ebpf_common::redirect_need::{TcpRequestKey, TcpSocketBinding};
use honk_ebpf_common::{ConnState, RedirectEntry, RoutingHandoffEntry, TuplesKey};

pub const RETIRE_BATCH_CAPACITY: usize = 128;

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
