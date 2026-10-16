//! Bind a SYN incarnation to its request object, then to the actual child socket.

use crate::maps::{
    CONN_STATE_MAP, REDIRECT_TRACK, ROUTING_HANDOFF_MAP, TCP_REQUEST_BINDINGS, TCP_SOCKET_BINDING,
    tuple_retiring,
};
use aya_ebpf::{
    Global,
    bindings::BPF_SK_STORAGE_GET_F_CREATE,
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_sk_storage_get},
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
};
use core::{ffi::c_void, ptr};
use honk_ebpf_common::{
    RedirectTuple, TPROXY_MARK,
    conn::TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS,
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
fn skb_tuple(skb: *const u8, ipv6: bool) -> Option<(TuplesKey, u64)> {
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
    ))
}

#[inline(always)]
fn current(tuples: &TuplesKey, incarnation: u64) -> bool {
    if incarnation == 0 || tuple_retiring(tuples) {
        return false;
    }
    let Some(conn) = (unsafe { CONN_STATE_MAP.get(tuples) }) else {
        return false;
    };
    if conn.incarnation != incarnation {
        return false;
    }
    let Some(handoff) = (unsafe { ROUTING_HANDOFF_MAP.get(tuples) }) else {
        return false;
    };
    if handoff.incarnation != incarnation {
        return false;
    }
    let Some(redirect) = (unsafe { REDIRECT_TRACK.get(&RedirectTuple::from_tuples(tuples)) })
    else {
        return false;
    };
    redirect.incarnation == incarnation
}

#[inline(always)]
fn route_request(sk: *mut c_void, skb: *const u8, request: *mut c_void, ipv6: bool) {
    if sk.is_null() || skb.is_null() || request.is_null() || !listener(sk) {
        return;
    }
    let Some((tuples, incarnation)) = skb_tuple(skb, ipv6) else {
        return;
    };
    if !current(&tuples, incarnation) {
        return;
    }
    let Some(handoff) = (unsafe { ROUTING_HANDOFF_MAP.get(&tuples) }) else {
        return;
    };
    let handoff = *handoff;
    if handoff.incarnation != incarnation {
        return;
    }
    // Keep the context-derived request pointer typed through this helper call.
    let cookie = unsafe { bpf_get_socket_cookie(request) };
    if cookie == 0 {
        return;
    }
    let key = TcpRequestKey {
        address: request as u64,
        cookie,
    };
    let binding = TcpSocketBinding {
        tuples,
        handoff,
        kind: TCP_BINDING_CHILD,
        padding: 0,
    };
    // Retransmissions cannot rewrite a proof belonging to this exact request.
    let _ = TCP_REQUEST_BINDINGS.insert(&key, &binding, 1);
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
    // Direct fexit context access retains the return's socket BTF pointer type.
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
    let Some(binding) = (unsafe { TCP_REQUEST_BINDINGS.get(&key) }) else {
        return 0;
    };
    let binding = *binding;
    let now = unsafe { bpf_ktime_get_ns() };
    if binding.kind != TCP_BINDING_CHILD
        || now < binding.handoff.last_seen_ns
        || now - binding.handoff.last_seen_ns > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
        || !current(&binding.tuples, binding.handoff.incarnation)
    {
        return 0;
    }
    // inet_csk_clone_lock copies ir_cookie before this exit, but not the endpoints.
    let inherited: Option<u64> =
        unsafe { read(child.cast(), TCP_BINDING_OFFSETS.load().socket_cookie) };
    if inherited != Some(cookie) {
        return 0;
    }
    let mut binding = binding;
    let _ = unsafe {
        bpf_sk_storage_get(
            (&raw const TCP_SOCKET_BINDING).cast_mut().cast(),
            child.cast(),
            ptr::from_mut(&mut binding).cast(),
            BPF_SK_STORAGE_GET_F_CREATE as u64,
        )
    };
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
    if cookie != 0 {
        let _ = TCP_REQUEST_BINDINGS.remove(&TcpRequestKey {
            address: request as u64,
            cookie,
        });
    }
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
