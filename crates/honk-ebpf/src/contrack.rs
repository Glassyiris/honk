//! Connection tracking for honk-ebpf.
//!
//! Ported from daed/wing/dae-core/control/kern/tproxy.c

#![allow(clippy::too_many_arguments)]

use crate::log_shim::*;
use crate::{
    event::{send_dae_event, send_flow_expired},
    maps::{
        BPF_STATS_MAP, CONN_STATE_MAP, CONN_STATE_OCCUPANCY, CONNTRACK_ARGS_MAP,
        CONNTRACK_SNAPSHOT_MAP, FLOW_INCARNATION_SEQUENCE, TCP_LIVE_PINS, UDP_DECISION_SEQUENCE,
        tuple_retiring,
    },
};
use aya_ebpf_bindings::{
    bindings::BPF_NOEXIST,
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
};
use honk_ebpf_common::{
    NFQUEUE_TOKEN_MASK, RoutingMeta, UDP_DECISION_SEQUENCE_MASK,
    conn::{
        BpfStatsKey, ConnState, ConntrackArgs, FLOW_INCARNATION_MAX, FlowMapValue,
        OCCUPANCY_INSERTS, TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TcpState, UDP_CONN_STATE_TIMEOUT_NS,
        UdpDecisionState, tcp_conn_state_expired,
    },
    redirect_need::TuplesKey,
};
use network_types::tcp::TcpHdr;

/// Lazy-timestamp update interval: only bump `last_seen_ns` when > 1 s elapsed.
pub const UDP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000;

/// Refresh interval for `REDIRECT_TRACK` and `ROUTING_HANDOFF_MAP`:
/// cached packets skip timestamp writes while an entry
/// is fresher than one second. A concurrent writer may publish a later timestamp
/// after this invocation reads the clock, so flow ages saturate at zero.
pub const AUXILIARY_MAP_REFRESH_INTERVAL_NS: u64 = 1_000_000_000;

pub const TCP_CONN_STATE_UPDATE_INTERVAL_NS: u64 = 1_000_000_000; // 1 second

/// Bump a slot of the CONN_STATE_OCCUPANCY gauge (per-CPU, contention-free).
#[inline(always)]
fn occupancy_add(slot: u32) {
    if let Some(counter) = CONN_STATE_OCCUPANCY.get_ptr_mut(slot) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Allocate a nonzero ID once per generation. Exhaustion never wraps or resets.
#[inline(always)]
pub fn allocate_flow_incarnation() -> Option<u64> {
    let sequence = unsafe { &mut *FLOW_INCARNATION_SEQUENCE.get_ptr_mut(0)? };
    unsafe { bpf_spin_lock(&mut sequence.lock) };
    let incarnation = if sequence.next < FLOW_INCARNATION_MAX {
        sequence.next += 1;
        sequence.next
    } else {
        0
    };
    unsafe { bpf_spin_unlock(&mut sequence.lock) };
    if incarnation == 0 {
        None
    } else {
        Some(incarnation)
    }
}

/// A SYN owns every tuple publication until its invocation stops using maps.
/// The key stays in packet scratch (or the reverse caller's stack) until Drop.
pub struct TcpPublisher {
    key: core::ptr::NonNull<TuplesKey>,
    pub incarnation: u64,
}

const _: () = assert!(core::mem::size_of::<Option<TcpPublisher>>() == 16);

impl TcpPublisher {
    #[inline(always)]
    pub fn acquire(key: &TuplesKey) -> Option<Self> {
        if tuple_retiring(key) {
            return None;
        }
        let incarnation = allocate_flow_incarnation()?;
        crate::maps::TCP_PUBLISHING
            .insert(key, incarnation, BPF_NOEXIST as u64)
            .ok()?;
        Some(Self {
            key: core::ptr::NonNull::from(key),
            incarnation,
        })
    }
}

impl Drop for TcpPublisher {
    #[inline(always)]
    fn drop(&mut self) {
        // Only this producer can release its NOEXIST claim. No competing SYN
        // can replace tuple metadata until the final borrowed access completes.
        let key = unsafe { self.key.as_ref() };
        if let Some(owner) = crate::maps::TCP_PUBLISHING.get_ptr(key)
            && unsafe { *owner } == self.incarnation
        {
            let _ = crate::maps::TCP_PUBLISHING.remove(key);
        }
    }
}

/// Atomically reserve a fresh UDP tuple for this producer, never replacing a hit.
#[inline(always)]
pub fn claim_udp_preparing(key: &TuplesKey, mac: &[u8; 6]) -> Option<u64> {
    if tuple_retiring(key) {
        return None;
    }
    let incarnation = allocate_flow_incarnation()?;
    let mut state: ConnState = unsafe { core::mem::zeroed() };
    state.state = UdpDecisionState::Preparing as u8;
    state.incarnation = incarnation;
    state.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    state.mac.copy_from_slice(mac);

    if CONN_STATE_MAP
        .insert(key, FlowMapValue::new(state), BPF_NOEXIST as u64)
        .is_ok()
    {
        occupancy_add(OCCUPANCY_INSERTS);
        return Some(incarnation);
    }

    if CONN_STATE_MAP.get_ptr(key).is_none() {
        let stats_key = BpfStatsKey::UdpConnOverflow as u32;
        if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe {
                *counter += 1;
            }
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpConnOverflow as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }
    None
}

/// Publish only the captured unpublished claim; followers cannot complete it.
#[inline(always)]
pub fn publish_claimed_udp_state(key: &TuplesKey, state: &ConnState) -> bool {
    if tuple_retiring(key) || state.incarnation == 0 {
        return false;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.state == UdpDecisionState::Preparing as u8
        && current.decision_token == 0
        && current.incarnation == state.incarnation;
    if owned {
        unsafe { crate::flow::copy_payload(current, state) };
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    owned
}

/// An admitted unpublished producer may cancel through a subsequently installed fence.
#[inline(always)]
pub fn abort_udp_preparing(key: &TuplesKey, incarnation: u64, actual_token: u32) {
    if incarnation == 0 {
        return;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.state == UdpDecisionState::Preparing as u8
        && current.decision_token == 0
        && current.incarnation == incarnation;
    if owned {
        current.decision_token = actual_token;
        current.state = UdpDecisionState::Aborted as u8;
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    if owned {
        send_flow_expired(key, incarnation);
    }
}

#[inline(always)]
pub fn populate_udp_conn_state(
    conn: &mut ConnState,
    meta: RoutingMeta,
    mac: &[u8; 6],
    state: UdpDecisionState,
    decision_token: u32,
    incarnation: u64,
) {
    *conn = unsafe { core::mem::zeroed() };
    conn.state = state as u8;
    conn.decision_token = decision_token;
    conn.incarnation = incarnation;
    conn.last_seen_ns = unsafe { bpf_ktime_get_ns() };
    conn.meta = meta;
    conn.mac.copy_from_slice(mac);
}

/// Allocate each generation-tagged mark token once until userspace rotates it.
#[inline(always)]
pub fn allocate_udp_decision_token(key: &TuplesKey) -> Option<u32> {
    let sequence_ptr = UDP_DECISION_SEQUENCE.get_ptr_mut(0)?;
    let sequence = unsafe { &mut *sequence_ptr };
    unsafe {
        bpf_spin_lock(&mut sequence.lock);
    }

    let mut became_exhausted = false;
    let token = if sequence.exhausted != 0
        || sequence.next & UDP_DECISION_SEQUENCE_MASK >= UDP_DECISION_SEQUENCE_MASK
    {
        0
    } else {
        sequence.next += 1;
        became_exhausted = sequence.next & UDP_DECISION_SEQUENCE_MASK == UDP_DECISION_SEQUENCE_MASK;
        if sequence.next == NFQUEUE_TOKEN_MASK {
            sequence.exhausted = 1;
        }
        sequence.next
    };

    unsafe {
        bpf_spin_unlock(&mut sequence.lock);
    }

    if became_exhausted {
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpDecisionTokenExhausted as u32,
            0,
            None,
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
    }

    if token == 0 { None } else { Some(token) }
}

/// Build a [`RoutingMeta`] from routing parameters.
///
/// Encodes the routing decision into a `u64` for storage in [`ConnState::meta`].
/// The bit layout must match [`RoutingMetaData`] for struct-field access to work:
///
/// | bits    | field       |
/// |---------|-------------|
/// |  0–7    | `outbound`  |
/// |  8–39   | `mark`      |
/// |  40–47  | `must`      |
/// |  48–55  | `dscp`      |
/// |  56     | `has_routing` |
/// |  57     | `offload` (mode-based direct offload; see
///           [`honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD`]) |
///
/// **Note**: this differs from the C dae layout (where mark occupies bits 0–31
/// and outbound bits 32–39). Do **not** copy bit offsets from C code.
#[inline(always)]
pub fn build_routing_meta(outbound: u8, mark: u32, must: u8, dscp: u8) -> RoutingMeta {
    build_routing_meta_with_offload(outbound, mark, must, dscp, false)
}

/// [`build_routing_meta`] plus the per-flow offload bit, set only by
/// `lan_ingress` when the mode-based policy selected this flow for kernel
/// direct offload at route-decision time.
#[inline(always)]
pub fn build_routing_meta_with_offload(
    outbound: u8,
    mark: u32,
    must: u8,
    dscp: u8,
    offload: bool,
) -> RoutingMeta {
    let raw: u64 = (outbound as u64)
        | ((mark as u64) << 8)
        | ((must as u64) << 40)
        | ((dscp as u64) << 48)
        | (1u64 << 56)
        | if offload {
            honk_ebpf_common::ROUTING_META_FLAG_OFFLOAD
        } else {
            0
        };
    RoutingMeta { raw }
}

/// Copy a [`TuplesKey`] with src↔dst and sport↔dport swapped,
/// preserving `l4proto`.  Zero-initialises `dst` first.
#[inline(always)]
pub fn copy_reversed_tuples(key: &TuplesKey, dst: &mut TuplesKey) {
    *dst = unsafe { core::mem::zeroed() };
    dst.dst_ip = key.src_ip;
    dst.src_ip = key.dst_ip;
    dst.dst_port = key.src_port;
    dst.src_port = key.dst_port;
    dst.l4proto = key.l4proto;
}

/// DNS queries/replies are short-lived; skipping conntrack for them
/// reduces unnecessary UDP state churn.
#[inline(always)]
pub fn is_short_lived_udp_traffic(key: &TuplesKey) -> bool {
    // Ports are stored in host byte order (see transport::get_tuples).
    key.l4proto == crate::transport::IPPROTO_UDP && (key.dst_port == 53 || key.src_port == 53)
}

/// Returns `true` when the TCP header carries a pure SYN (SYN set, ACK clear).
#[inline(always)]
pub fn is_new_tcp_connection(tcph: &TcpHdr) -> bool {
    tcph.syn() != 0 && tcph.ack() == 0
}

/// Unpublished aborts are immediately eligible; other UDP entries retain the age backstop.
#[inline(always)]
fn udp_conn_state_expired(state: &ConnState, now: u64) -> bool {
    state.state == UdpDecisionState::Aborted as u8
        || now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS
}

/// Expiry refuses this invocation rather than masquerading as a lookup miss.
#[inline(always)]
pub fn tuple_unavailable(key: &TuplesKey, new_tcp_syn: bool) -> bool {
    if tuple_retiring(key) {
        return true;
    }
    if new_tcp_syn {
        return false;
    }
    let Some(state) = crate::flow::conn_lifecycle(key) else {
        return false;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let expired = if key.l4proto == crate::transport::IPPROTO_TCP {
        state.state == TcpState::TcpStateClosing as u8
            && now.saturating_sub(state.last_seen_ns) > TCP_CONN_STATE_CLOSING_TIMEOUT_NS
            && !tcp_live_pinned(state.incarnation)
    } else {
        state.state == UdpDecisionState::Aborted as u8
            || now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_TIMEOUT_NS
    };
    if expired {
        send_flow_expired(key, state.incarnation);
    }
    expired
        || (key.l4proto == crate::transport::IPPROTO_UDP
            && state.state == UdpDecisionState::Preparing as u8)
}

#[inline(always)]
pub fn auxiliary_expired(
    key: &TuplesKey,
    incarnation: u64,
    elapsed_ns: u64,
    handoff: bool,
) -> bool {
    let expired = elapsed_ns
        > if handoff {
            30_000_000_000
        } else {
            120_000_000_000
        };
    let expired = expired
        && !(!handoff
            && key.l4proto == crate::transport::IPPROTO_TCP
            && tcp_live_pinned(incarnation));
    if expired {
        send_flow_expired(key, incarnation);
    }
    expired
}

#[inline(always)]
fn conntrack_output() -> Option<*mut ConnState> {
    // Keep array keys on stack, away from overridable zero-valued globals.
    let mut zero = 0u32;
    unsafe { core::ptr::write_volatile(&mut zero, 0) };
    CONNTRACK_SNAPSHOT_MAP.get_ptr_mut(unsafe { core::ptr::read_volatile(&zero) })
}

#[inline(always)]
fn tcp_live_pinned(incarnation: u64) -> bool {
    incarnation != 0 && TCP_LIVE_PINS.get_ptr(incarnation).is_some()
}

#[inline(always)]
fn update_tcp_locked(state: &mut ConnState, args: &ConntrackArgs, now: u64, fin_rst: bool) {
    if now.saturating_sub(state.last_seen_ns) > TCP_CONN_STATE_UPDATE_INTERVAL_NS {
        state.last_seen_ns = now;
    }
    if fin_rst {
        state.state = TcpState::TcpStateClosing as u8;
    }
    if args.has_routing() {
        if args.has_mac() {
            let mut i = 0;
            while i < 6 {
                unsafe {
                    state
                        .mac
                        .as_mut_ptr()
                        .add(i)
                        .write_volatile(args.mac.as_ptr().add(i).read_volatile())
                };
                i += 1;
            }
        }
        if args.has_pname() {
            let mut i = 0;
            while i < 16 {
                unsafe {
                    state
                        .pname
                        .as_mut_ptr()
                        .add(i)
                        .write_volatile(args.pname.as_ptr().add(i).read_volatile())
                };
                i += 1;
            }
        }
        state.pid = args.pid;
        state.trace_id = args.trace_id;
        state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
    }
}

/// Returns invocation-local scratch, never a borrowed map payload.
fn __mark_tcp_seen(
    key: *const TuplesKey,
    is_wan_ingress_direction: u8,
    tcp_flags: u8,
    args: *mut ConntrackArgs,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &mut *args };
    if tuple_retiring(key) {
        return core::ptr::null_mut();
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(output) = conntrack_output() else {
        return core::ptr::null_mut();
    };
    let ptr_opt = CONN_STATE_MAP.get_ptr_mut(key);
    let fin_rst = tcp_flags & 2 != 0;
    if tcp_flags & 1 == 0 {
        let Some(ptr) = ptr_opt else {
            return core::ptr::null_mut();
        };
        unsafe { bpf_spin_lock(&mut (*ptr).lock) };
        let state = unsafe { &mut (*ptr).value };
        let expired = tcp_conn_state_expired(state, now.saturating_sub(state.last_seen_ns));
        if !expired {
            update_tcp_locked(state, args, now, fin_rst);
        }
        unsafe {
            crate::flow::copy_payload(output, state);
            bpf_spin_unlock(&mut (*ptr).lock);
        }
        let incarnation = unsafe { (*output).incarnation };
        if expired {
            if !tcp_live_pinned(incarnation) {
                send_flow_expired(key, incarnation);
                return core::ptr::null_mut();
            }
            unsafe { bpf_spin_lock(&mut (*ptr).lock) };
            let state = unsafe { &mut (*ptr).value };
            let owned = state.incarnation == incarnation;
            if owned {
                update_tcp_locked(state, args, now, fin_rst);
                unsafe { crate::flow::copy_payload(output, state) };
            }
            unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
            if !owned {
                return core::ptr::null_mut();
            }
        }
        args.incarnation = incarnation;
        return output;
    }

    let incarnation = args.incarnation;
    if incarnation == 0
        || crate::maps::TCP_PUBLISHING
            .get_ptr(key)
            .is_none_or(|owner| unsafe { *owner } != incarnation)
    {
        return core::ptr::null_mut();
    }
    let new_state = unsafe { &mut *output };
    *new_state = unsafe { core::mem::zeroed() };
    new_state.incarnation = incarnation;
    new_state.is_wan_ingress_direction = (is_wan_ingress_direction != 0) as u8;
    new_state.state = TcpState::TcpStateActive as u8;
    new_state.last_seen_ns = now;
    new_state.pid = args.pid;
    new_state.trace_id = if args.has_routing() {
        args.trace_id
    } else if ptr_opt.is_some() {
        u32::MAX
    } else {
        0
    };
    if args.has_routing() {
        update_tcp_locked(new_state, args, now, false);
    }
    if let Some(ptr) = ptr_opt {
        unsafe {
            bpf_spin_lock(&mut (*ptr).lock);
            crate::flow::copy_payload(&raw mut (*ptr).value, new_state);
            bpf_spin_unlock(&mut (*ptr).lock);
        }
    } else if CONN_STATE_MAP
        .insert(key, FlowMapValue::new(*new_state), BPF_NOEXIST as u64)
        .is_ok()
    {
        occupancy_add(OCCUPANCY_INSERTS);
    } else {
        let stats_key = BpfStatsKey::TcpConnOverflow as u32;
        if let Some(counter) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe { *counter += 1 };
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::TcpConnOverflow as u32,
            args.pid,
            args.pname_or_null(),
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
        return core::ptr::null_mut();
    }
    output
}

/// Commit only this captured SYN's routing fields; preserve concurrent lifecycle refreshes.
#[inline(always)]
pub fn publish_tcp_routing(key: &TuplesKey, snapshot: &ConnState) -> bool {
    if tuple_retiring(key) || snapshot.incarnation == 0 {
        return false;
    }
    let Some(ptr) = CONN_STATE_MAP.get_ptr_mut(key) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let current = unsafe { &mut (*ptr).value };
    let owned = current.incarnation == snapshot.incarnation;
    if owned {
        current.meta = snapshot.meta;
        current.trace_id = snapshot.trace_id;
        let mut i = 0;
        while i < 6 {
            unsafe {
                current
                    .mac
                    .as_mut_ptr()
                    .add(i)
                    .write_volatile(snapshot.mac.as_ptr().add(i).read_volatile())
            };
            i += 1;
        }
    }
    unsafe { bpf_spin_unlock(&mut (*ptr).lock) };
    owned
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_tcp_seen`].
#[inline(always)]
pub fn mark_tcp_seen(
    key: &TuplesKey,
    tcph: &TcpHdr,
    is_wan_ingress_direction: u8,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
    trace_id: u32,
    incarnation: &mut u64,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);
    args.trace_id = trace_id;
    args.incarnation = if is_new_tcp_connection(tcph) {
        *incarnation
    } else {
        0
    };

    // Encode tcp_flags: bit 0 = pure SYN, bit 1 = FIN || RST
    let mut tcp_flags: u8 = 0;
    if tcph.syn() != 0 && tcph.ack() == 0 {
        tcp_flags |= 1;
    }
    if tcph.fin() != 0 || tcph.rst() != 0 {
        tcp_flags |= 2;
    }

    let key_ptr: *const TuplesKey = key;
    let args_ptr: *mut ConntrackArgs = args;
    let result = __mark_tcp_seen(key_ptr, is_wan_ingress_direction, tcp_flags, args_ptr);
    *incarnation = args.incarnation;
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}

#[inline(always)]
fn lookup_udp_seen_at(key: &TuplesKey, now: u64) -> Option<&'static mut ConnState> {
    if tuple_retiring(key) {
        return None;
    }
    let output = conntrack_output()?;
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    unsafe { bpf_spin_lock(&mut (*ptr).lock) };
    let state = unsafe { &mut (*ptr).value };
    let expired = udp_conn_state_expired(state, now);
    if !expired
        && state.state != UdpDecisionState::Preparing as u8
        && now.saturating_sub(state.last_seen_ns) > UDP_CONN_STATE_UPDATE_INTERVAL_NS
    {
        state.last_seen_ns = now;
    }
    unsafe {
        crate::flow::copy_payload(output, state);
        bpf_spin_unlock(&mut (*ptr).lock);
    }
    if expired {
        send_flow_expired(key, unsafe { (*output).incarnation });
        return None;
    }
    Some(unsafe { &mut *output })
}

/// Look up an existing live UDP entry and lazily refresh its timestamp.
/// Missing or expired entries are never allocated on this path.
#[inline(always)]
pub fn lookup_udp_seen(key: &TuplesKey) -> Option<&'static mut ConnState> {
    lookup_udp_seen_at(key, unsafe { bpf_ktime_get_ns() })
}

/// Returns an invocation-local snapshot after publication, never a map payload pointer.
fn __mark_udp_seen(
    key: *const TuplesKey,
    is_wan_ingress_direction: u8,
    args: *const ConntrackArgs,
    routing_meta_flags: u64,
) -> *mut ConnState {
    let key = unsafe { &*key };
    let args = unsafe { &*args };
    let now = unsafe { bpf_ktime_get_ns() };

    if tuple_retiring(key) {
        return core::ptr::null_mut();
    }
    if let Some(state) = lookup_udp_seen_at(key, now) {
        // A cached lifecycle never inherits a competing producer's new route.
        if args.has_routing() {
            return core::ptr::null_mut();
        }
        return state as *mut ConnState;
    }

    let mac = if args.has_mac() { args.mac } else { [0; 6] };
    let Some(incarnation) = claim_udp_preparing(key, &mac) else {
        return core::ptr::null_mut();
    };
    let has_rt = args.has_routing();

    let mut new_state: ConnState = unsafe { core::mem::zeroed() };
    new_state.is_wan_ingress_direction = (is_wan_ingress_direction != 0) as u8;
    new_state.state = UdpDecisionState::None as u8;
    new_state.incarnation = incarnation;
    new_state.last_seen_ns = now;
    new_state.pid = args.pid;
    new_state.trace_id = args.trace_id;

    if has_rt {
        new_state.meta = build_routing_meta(args.outbound, args.mark, args.must, args.dscp);
        unsafe { new_state.meta.raw |= routing_meta_flags };
        if args.has_mac() {
            new_state.mac.copy_from_slice(&args.mac);
        }
        if args.has_pname() {
            new_state.pname.copy_from_slice(&args.pname);
        }
    }

    if !publish_claimed_udp_state(key, &new_state) {
        abort_udp_preparing(key, incarnation, 0);
        let stats_key: u32 = BpfStatsKey::UdpConnOverflow as u32;
        if let Some(overflow_count) = BPF_STATS_MAP.get_ptr_mut(stats_key) {
            unsafe {
                *overflow_count += 1;
            }
        }
        send_dae_event(
            honk_ebpf_common::event::DaeEventType::UdpConnOverflow as u32,
            args.pid,
            args.pname_or_null(),
            0,
            key.l4proto,
            Some(unsafe { &key.src_ip.u6_addr32 }),
            Some(unsafe { &key.dst_ip.u6_addr32 }),
            key.src_port,
            key.dst_port,
        );
        warn!((), target: "honk", "udp conn state map overflow, key: {:i}:{} -> {:i}:{}", unsafe { key.src_ip.u6_addr8 }, key.src_port, unsafe { key.dst_ip.u6_addr8 }, key.dst_port);
        return core::ptr::null_mut();
    }
    let Some(output) = conntrack_output() else {
        return core::ptr::null_mut();
    };
    // Publication copied these exact immutable contents under the element lock.
    unsafe { crate::flow::copy_payload(output, &new_state) };
    output
}

/// Thin inline wrapper: populates the per-CPU `CONNTRACK_ARGS_MAP` scratch
/// and delegates to [`__mark_udp_seen`].
#[inline(always)]
pub fn mark_udp_seen(
    key: &TuplesKey,
    is_wan_ingress_direction: u8,
    outbound: Option<&u8>,
    mark: Option<&u32>,
    must: Option<&u8>,
    mac: Option<&[u8; 6]>,
    dscp: u8,
    pname: Option<&[u8; 16]>,
    pid: u32,
    trace_id: u32,
    routing_meta_flags: u64,
) -> Option<&'static mut ConnState> {
    let zero: u32 = 0;
    let args = unsafe { CONNTRACK_ARGS_MAP.get_ptr_mut(zero).map(|ptr| &mut *ptr)? };

    // Build routing tuple (all three must be present for routing to be set).
    let routing = match (outbound, mark, must) {
        (Some(o), Some(mk), Some(ms)) => Some((o, mk, ms)),
        _ => None,
    };

    args.set(dscp, pid, routing, mac, pname);
    args.trace_id = trace_id;
    let key_ptr: *const TuplesKey = key;
    let args_ptr: *const ConntrackArgs = args;
    let result = __mark_udp_seen(
        key_ptr,
        is_wan_ingress_direction,
        args_ptr,
        routing_meta_flags,
    );
    if result.is_null() {
        None
    } else {
        Some(unsafe { &mut *result })
    }
}
