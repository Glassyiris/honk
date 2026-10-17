//! Bind a SYN incarnation to its request object, then to the actual child socket.

use crate::flow::{conn_incarnation, handoff_incarnation, handoff_snapshot, redirect_incarnation};
use crate::maps::{
    CONN_STATE_MAP, CONNTRACK_ARGS_MAP, PARAM, PKT_SCRATCH_KEY, TCP_REQUEST_BINDINGS,
    TCP_SOCKET_BINDING, increment_bpf_stat, request_retiring, tuple_retiring,
};
use aya_ebpf::{
    Global,
    bindings::BPF_SK_STORAGE_GET_F_CREATE,
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_sk_storage_get},
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext, TcContext},
};
use aya_ebpf_bindings::{
    bindings::{
        bpf_sock, bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
        bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2,
    },
    helpers::{
        bpf_sk_fullsock, bpf_sk_release, bpf_skc_lookup_tcp, bpf_spin_lock, bpf_spin_unlock,
    },
};
use core::{ffi::c_void, mem, ptr};
use honk_ebpf_common::{
    RedirectTuple, TPROXY_MARK,
    conn::{
        BpfStatsKey, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TCP_SYN_ORIGINAL_INTERCEPT,
        TCP_SYN_REQUEST_SEEN,
    },
    dae_ip::In6Addr,
    redirect_need::{
        TCP_BINDING_CHILD, TCP_BINDING_LISTENER, TcpRequestKey, TcpSocketBinding, TuplesKey,
    },
    tcp_binding::TcpBindingOffsets,
};

#[unsafe(no_mangle)]
pub static TCP_BINDING_OFFSETS: Global<TcpBindingOffsets> = Global::new(TcpBindingOffsets {
    skb_head: 0,
    skb_network_header: 0,
    skb_transport_header: 0,
    skb_tail: 0,
    skb_mark: 0,
    skb_priority: 0,
    socket_cookie: 0,
    request_rcv_isn: 0,
});

#[inline(always)]
unsafe fn read<T: Copy>(base: *const u8, offset: u32) -> Option<T> {
    unsafe { bpf_probe_read_kernel(base.add(offset as usize).cast::<T>()) }.ok()
}

#[inline(always)]
fn listener(sk: *mut c_void) -> bool {
    let binding = unsafe {
        bpf_sk_storage_get(
            (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
            sk.cast(),
            ptr::null_mut(),
            0,
        )
    }
    .cast::<TcpSocketBinding>();
    !binding.is_null() && unsafe { (*binding).kind == TCP_BINDING_LISTENER }
}

#[inline(always)]
fn skb_tuple(skb: *const u8, ipv6: bool) -> Option<(TuplesKey, u64, u32)> {
    let offsets = TCP_BINDING_OFFSETS.load();
    let mark: u32 = unsafe { read(skb, offsets.skb_mark)? };
    if mark & 0xff00_0000 != TPROXY_MARK {
        return None;
    }
    let priority: u32 = unsafe { read(skb, offsets.skb_priority)? };
    let incarnation = ((priority as u64) << 24) | (mark & 0x00ff_ffff) as u64;
    if incarnation == 0 {
        return None;
    }
    let head: *const u8 = unsafe { read(skb, offsets.skb_head)? };
    if head.is_null() {
        return None;
    }
    let network: u16 = unsafe { read(skb, offsets.skb_network_header)? };
    let transport: u16 = unsafe { read(skb, offsets.skb_transport_header)? };
    let tail: u32 = unsafe { read(skb, offsets.skb_tail)? };
    let network = network as u32;
    let transport = transport as u32;
    let minimum = if ipv6 { 40 } else { 20 };
    if network + minimum > tail || transport < network + minimum || transport + 20 > tail {
        return None;
    }
    let version: u8 = unsafe { read(head, network)? };
    let flags: u8 = unsafe { read(head, transport + 13)? };
    if flags & 0x12 != 0x02 {
        return None;
    }
    let (src_ip, dst_ip) = if ipv6 {
        if version >> 4 != 6 {
            return None;
        }
        (
            In6Addr {
                u6_addr8: unsafe { read(head, network + 8)? },
            },
            In6Addr {
                u6_addr8: unsafe { read(head, network + 24)? },
            },
        )
    } else {
        if version >> 4 != 4
            || version & 0x0f < 5
            || transport < network + ((version & 0x0f) as u32 * 4)
        {
            return None;
        }
        let protocol: u8 = unsafe { read(head, network + 9)? };
        if protocol != 6 {
            return None;
        }
        (
            In6Addr::from_ipv4_bytes(unsafe { read(head, network + 12)? }),
            In6Addr::from_ipv4_bytes(unsafe { read(head, network + 16)? }),
        )
    };
    Some((
        TuplesKey {
            src_ip,
            dst_ip,
            src_port: u16::from_be(unsafe { read(head, transport)? }),
            dst_port: u16::from_be(unsafe { read(head, transport + 2)? }),
            l4proto: 6,
            padding: [0; 3],
        },
        incarnation,
        u32::from_be(unsafe { read(head, transport + 4)? }),
    ))
}

#[inline(always)]
fn current(tuples: &TuplesKey, incarnation: u64) -> bool {
    if incarnation == 0 || tuple_retiring(tuples) {
        return false;
    }
    conn_incarnation(tuples) == Some(incarnation)
        && handoff_incarnation(tuples) == Some(incarnation)
        && redirect_incarnation(&RedirectTuple::from_tuples(tuples)) == Some(incarnation)
}

#[inline(always)]
fn same_tuple(left: &TuplesKey, right: &TuplesKey) -> bool {
    (unsafe {
        left.src_ip.u6_addr64 == right.src_ip.u6_addr64
            && left.dst_ip.u6_addr64 == right.dst_ip.u6_addr64
    }) && left.src_port == right.src_port
        && left.dst_port == right.dst_port
        && left.l4proto == right.l4proto
}

#[inline(always)]
fn valid_proof(binding: &TcpSocketBinding, tuples: &TuplesKey, isn: u32) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let incarnation = binding.handoff.incarnation;
    if binding.kind != TCP_BINDING_CHILD
        || !same_tuple(&binding.tuples, tuples)
        || binding.syn_isn != isn
        || now < binding.handoff.last_seen_ns
        || now - binding.handoff.last_seen_ns > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
        || incarnation == 0
        || tuple_retiring(tuples)
    {
        return false;
    }
    let Some(conn) = CONN_STATE_MAP.get_ptr_mut(tuples) else {
        return false;
    };
    unsafe { bpf_spin_lock(&mut (*conn).lock) };
    let state = unsafe { &raw const (*conn).value };
    let owned = unsafe {
        (&raw const (*state).incarnation).read_volatile() == incarnation
            && (&raw const (*state).tcp_syn_isn).read_volatile() == isn
            && (&raw const (*state).tcp_syn_flags).read_volatile() & TCP_SYN_ORIGINAL_INTERCEPT != 0
    };
    unsafe { bpf_spin_unlock(&mut (*conn).lock) };
    owned
        && !tuple_retiring(tuples)
        && handoff_incarnation(tuples) == Some(incarnation)
        && redirect_incarnation(&RedirectTuple::from_tuples(tuples)) == Some(incarnation)
}

/// Scalar decision: 0 absent, reserved top values for fresh/refuse, otherwise
/// the cached incarnation (always within the nonzero 56-bit domain). Scalars
/// stay fully initialized across lookup/release helper calls.
pub const SYN_OWNER_ABSENT: u64 = 0;
pub const SYN_OWNER_FRESH: u64 = u64::MAX - 1;
pub const SYN_OWNER_REFUSE: u64 = u64::MAX;

macro_rules! some_or_refuse {
    ($value:expr) => {
        match $value {
            Some(value) => value,
            None => return SYN_OWNER_REFUSE,
        }
    };
}

// Keep common-socket field access separate from validated raw field probes.
#[inline(never)]
fn socket_state(sk: *const bpf_sock) -> u32 {
    unsafe { (*sk).state }
}

#[inline(always)]
fn read_native_request(sk: *mut bpf_sock, cookie: &mut u64, isn: &mut u32) -> bool {
    const CAPACITY: u32 = mem::size_of::<honk_ebpf_common::KernelRouteWitness>() as u32;
    let offsets = TCP_BINDING_OFFSETS.load();
    if offsets.socket_cookie > CAPACITY - 8 || offsets.request_rcv_isn > CAPACITY - 4 {
        return false;
    }
    let cookie_end = offsets.socket_cookie + 8;
    let isn_end = offsets.request_rcv_isn + 4;
    let length = if cookie_end > isn_end {
        cookie_end
    } else {
        isn_end
    };
    let mut zero = 0u32;
    unsafe { ptr::write_volatile(&mut zero, 0) };
    let Some(packet) = PKT_SCRATCH_KEY.get_ptr_mut(unsafe { ptr::read_volatile(&zero) }) else {
        return false;
    };
    // ponytail: reuse the dead 328-byte witness; larger prefixes need dedicated scratch.
    // The lookup reference pins the request even when SockMap wraps sk_prot.
    let witness = unsafe { &raw mut (*packet).route_witness };
    let bytes = witness.cast::<u8>();
    let result = unsafe {
        aya_ebpf_bindings::helpers::bpf_probe_read_kernel(bytes.cast(), length, sk.cast())
    };
    if result == 0 {
        *cookie =
            unsafe { ptr::read_unaligned(bytes.add(offsets.socket_cookie as usize).cast::<u64>()) };
        *isn = unsafe {
            ptr::read_unaligned(bytes.add(offsets.request_rcv_isn as usize).cast::<u32>())
        };
    }
    // A failed probe may have partially copied kernel pointers. Never let the
    // prefix survive in the readable packet scratch or a later route witness.
    unsafe { ptr::write_bytes(witness, 0, 1) };
    result == 0
}

#[inline(always)]
fn inspect_syn_owner(sk: *mut bpf_sock, tuples: &TuplesKey, isn: u32) -> u64 {
    match socket_state(sk) {
        12 => {
            let mut cookie = 0u64;
            let mut request_isn = 0u32;
            if !read_native_request(sk, &mut cookie, &mut request_isn) {
                return SYN_OWNER_REFUSE;
            }
            if cookie == 0 {
                return SYN_OWNER_REFUSE;
            }
            let key = TcpRequestKey {
                address: sk as u64,
                cookie,
            };
            if request_retiring(&key) {
                return SYN_OWNER_REFUSE;
            }
            if request_isn != isn {
                return SYN_OWNER_FRESH;
            }
            let binding = some_or_refuse!(unsafe { TCP_REQUEST_BINDINGS.get(&key) });
            if !valid_proof(binding, tuples, isn) {
                return SYN_OWNER_REFUSE;
            }
            binding.handoff.incarnation
        }
        6 => SYN_OWNER_FRESH, // TIME_WAIT is never child storage authority.
        10 => SYN_OWNER_ABSENT,
        _ => {
            let full = unsafe { bpf_sk_fullsock(sk) };
            if full.is_null() {
                return SYN_OWNER_REFUSE;
            }
            let binding = unsafe {
                bpf_sk_storage_get(
                    (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
                    full.cast(),
                    ptr::null_mut(),
                    0,
                )
            }
            .cast::<TcpSocketBinding>();
            if binding.is_null() || unsafe { (*binding).kind != TCP_BINDING_CHILD } {
                return SYN_OWNER_REFUSE;
            }
            let binding = unsafe { &*binding };
            if binding.syn_isn != isn {
                return SYN_OWNER_FRESH;
            }
            if !valid_proof(binding, tuples, isn) {
                return SYN_OWNER_REFUSE;
            }
            binding.handoff.incarnation
        }
    }
}

/// Only a referenced request or child can authorize native cached-SYN reuse.
#[inline(always)]
pub fn native_syn_owner(ctx: &TcContext, tuples: &TuplesKey, isn: u32) -> u64 {
    let nsid = PARAM.load().tcp_daens_netns_id;
    if nsid < 0 || tuple_retiring(tuples) {
        return SYN_OWNER_REFUSE;
    }
    // The conntrack argument scratch is dead until mark_tcp_seen rezeroes it;
    // using it keeps the 36-byte lookup tuple out of this 3-call stack chain.
    let mut zero = 0u32;
    unsafe { ptr::write_volatile(&mut zero, 0) };
    let Some(scratch) = CONNTRACK_ARGS_MAP.get_ptr_mut(unsafe { ptr::read_volatile(&zero) }) else {
        return SYN_OWNER_REFUSE;
    };
    const _: () = assert!(
        mem::size_of::<bpf_sock_tuple>() <= mem::size_of::<crate::contrack::ConntrackArgs>()
    );
    const _: () = assert!(
        mem::align_of::<bpf_sock_tuple>() <= mem::align_of::<crate::contrack::ConntrackArgs>()
    );
    let tuple = scratch.cast::<bpf_sock_tuple>();
    unsafe { ptr::write_bytes(tuple, 0, 1) };
    let size = if tuples.src_ip.is_v4_mapped() {
        unsafe {
            (*tuple).__bindgen_anon_1.ipv4.saddr = tuples.src_ip.u6_addr32[3];
            (*tuple).__bindgen_anon_1.ipv4.daddr = tuples.dst_ip.u6_addr32[3];
            (*tuple).__bindgen_anon_1.ipv4.sport = tuples.src_port.to_be();
            (*tuple).__bindgen_anon_1.ipv4.dport = tuples.dst_port.to_be();
        }
        mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32
    } else {
        unsafe {
            (*tuple).__bindgen_anon_1.ipv6.saddr = tuples.src_ip.u6_addr32;
            (*tuple).__bindgen_anon_1.ipv6.daddr = tuples.dst_ip.u6_addr32;
            (*tuple).__bindgen_anon_1.ipv6.sport = tuples.src_port.to_be();
            (*tuple).__bindgen_anon_1.ipv6.dport = tuples.dst_port.to_be();
        }
        mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_2>() as u32
    };
    let sk = unsafe { bpf_skc_lookup_tcp(ctx.skb.skb.cast(), tuple, size, nsid as u64, 0) };
    if sk.is_null() {
        return SYN_OWNER_ABSENT;
    }
    let result = inspect_syn_owner(sk, tuples, isn);
    unsafe { bpf_sk_release(sk.cast()) };
    result
}

#[inline(always)]
fn route_request(sk: *mut c_void, skb: *const u8, request: *mut c_void, ipv6: bool) {
    if sk.is_null() || skb.is_null() || request.is_null() || !listener(sk) {
        return;
    }
    let Some((tuples, incarnation, syn_isn)) = skb_tuple(skb, ipv6) else {
        return;
    };
    if !current(&tuples, incarnation) {
        return;
    }
    let Some(handoff) = handoff_snapshot(&tuples) else {
        return;
    };
    if handoff.incarnation != incarnation {
        return;
    }
    let actual_isn: Option<u32> =
        unsafe { read(request.cast(), TCP_BINDING_OFFSETS.load().request_rcv_isn) };
    if actual_isn != Some(syn_isn) {
        return;
    }
    let cookie = unsafe { bpf_get_socket_cookie(request) };
    if cookie == 0 {
        return;
    }
    let key = TcpRequestKey {
        address: request as u64,
        cookie,
    };
    if request_retiring(&key) || tuple_retiring(&tuples) {
        return;
    }
    // Exact proofs are immutable and already accounted; never reserve twice.
    if unsafe { TCP_REQUEST_BINDINGS.get(&key).is_some() } {
        return;
    }
    let Some(conn) = CONN_STATE_MAP.get_ptr_mut(&tuples) else {
        return;
    };
    unsafe { bpf_spin_lock(&mut (*conn).lock) };
    let state = unsafe { &mut (*conn).value };
    let reserved = state.incarnation == incarnation
        && state.tcp_syn_isn == syn_isn
        && state.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT != 0
        && (state.tcp_syn_flags & TCP_SYN_REQUEST_SEEN == 0 || state.tcp_request_count != 0)
        && state.tcp_request_count < u32::MAX;
    if reserved {
        state.tcp_syn_flags |= TCP_SYN_REQUEST_SEEN;
        state.tcp_request_count += 1;
    }
    unsafe { bpf_spin_unlock(&mut (*conn).lock) };
    if !reserved {
        return;
    }
    let binding = TcpSocketBinding {
        tuples,
        handoff,
        kind: TCP_BINDING_CHILD,
        syn_isn,
    };
    if TCP_REQUEST_BINDINGS.insert(&key, &binding, 1).is_err() {
        increment_bpf_stat(BpfStatsKey::TcpRequestProofInsertFailure);
        unsafe { bpf_spin_lock(&mut (*conn).lock) };
        let state = unsafe { &mut (*conn).value };
        if state.incarnation == incarnation && state.tcp_request_count != 0 {
            state.tcp_request_count -= 1;
        }
        unsafe { bpf_spin_unlock(&mut (*conn).lock) };
    }
}

#[fentry]
pub fn honk_tcp_v4_route_req(ctx: FEntryContext) -> u32 {
    route_request(ctx.arg(0), ctx.arg(1), ctx.arg(3), false);
    0
}

#[fentry]
pub fn honk_tcp_v6_route_req(ctx: FEntryContext) -> u32 {
    route_request(ctx.arg(0), ctx.arg(1), ctx.arg(3), true);
    0
}

#[fexit]
pub fn honk_tcp_create_openreq_child(ctx: FExitContext) -> u32 {
    let request: *mut c_void = ctx.arg(1);
    let child: *mut c_void = ctx.arg(3);
    if child.is_null() || request.is_null() || !listener(ctx.arg(0)) {
        return 0;
    }
    let cookie = unsafe { bpf_get_socket_cookie(request) };
    if cookie == 0 {
        return 0;
    }
    let key = TcpRequestKey {
        address: request as u64,
        cookie,
    };
    if request_retiring(&key) {
        return 0;
    }
    let Some(binding) = (unsafe { TCP_REQUEST_BINDINGS.get(&key) }) else {
        return 0;
    };
    let binding = *binding;
    if !valid_proof(&binding, &binding.tuples, binding.syn_isn) {
        return 0;
    }
    let actual_isn: Option<u32> =
        unsafe { read(request.cast(), TCP_BINDING_OFFSETS.load().request_rcv_isn) };
    if actual_isn != Some(binding.syn_isn) {
        return 0;
    }
    // inet_csk_clone_lock copies ir_cookie before this exit, but not the endpoints.
    let inherited: Option<u64> =
        unsafe { read(child.cast(), TCP_BINDING_OFFSETS.load().socket_cookie) };
    if inherited != Some(cookie) {
        return 0;
    }
    let mut binding = binding;
    let stored = unsafe {
        bpf_sk_storage_get(
            (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
            child.cast(),
            ptr::from_mut(&mut binding).cast(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    };
    if stored.is_null() {
        increment_bpf_stat(BpfStatsKey::TcpChildProofStorageFailure);
    }
    0
}

#[inline(always)]
fn destroy_request(request: *mut c_void) {
    if request.is_null() {
        return;
    }
    let Some(cookie) =
        (unsafe { read::<u64>(request.cast(), TCP_BINDING_OFFSETS.load().socket_cookie) })
    else {
        return;
    };
    if cookie == 0 {
        return;
    }
    let key = TcpRequestKey {
        address: request as u64,
        cookie,
    };
    if request_retiring(&key) {
        return;
    }
    let Some(binding) = (unsafe { TCP_REQUEST_BINDINGS.get(&key) }) else {
        return;
    };
    if binding.kind != TCP_BINDING_CHILD {
        return;
    }
    let tuples = binding.tuples;
    let incarnation = binding.handoff.incarnation;
    // A tuple fence also protects this accounting borrow. The post-grace owner
    // must remove the retained proof and finish its decrement, never just delete it.
    if tuple_retiring(&tuples) {
        return;
    }
    let Some(conn) = CONN_STATE_MAP.get_ptr_mut(&tuples) else {
        return;
    };
    unsafe { bpf_spin_lock(&mut (*conn).lock) };
    let state = unsafe { &(*conn).value };
    let accounted = state.incarnation != incarnation || state.tcp_request_count != 0;
    unsafe { bpf_spin_unlock(&mut (*conn).lock) };
    if !accounted {
        return;
    }
    if TCP_REQUEST_BINDINGS.remove(&key).is_err() {
        return;
    }
    unsafe { bpf_spin_lock(&mut (*conn).lock) };
    let state = unsafe { &mut (*conn).value };
    if state.incarnation == incarnation && state.tcp_request_count != 0 {
        state.tcp_request_count -= 1;
    }
    unsafe { bpf_spin_unlock(&mut (*conn).lock) };
}

#[fentry]
pub fn honk_tcp_v4_reqsk_destructor(ctx: FEntryContext) -> u32 {
    destroy_request(ctx.arg(0));
    0
}

#[fentry]
pub fn honk_tcp_v6_reqsk_destructor(ctx: FEntryContext) -> u32 {
    destroy_request(ctx.arg(0));
    0
}
