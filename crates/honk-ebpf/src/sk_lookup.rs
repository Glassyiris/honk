//! Socket-lookup program for the isolated `daens` namespace.
//!
//! When proxy-bound packets are redirected from the host namespace into `daens`
//! via the `dae0peer` link, normal socket lookup fails because the destination
//! port belongs to the original remote endpoint, not to the local TPROXY
//! listener.  This program overrides the lookup and assigns the transparent
//! listener socket, letting the kernel deliver the packet with the original
//! destination intact.
//!
//! UDP listeners are published in parallel groups (`UDP_LISTENER_COUNT` per
//! family); the flow tuple is hashed so a flow's datagrams always land on the
//! same socket while different flows spread across the per-socket receive
//! loops in userspace.

use crate::{
    maps::LISTEN_SOCKET_MAP,
    transport::{IPPROTO_TCP, IPPROTO_UDP},
};
use aya_ebpf::{bindings::bpf_sk_lookup, programs::SkLookupContext};
use honk_ebpf_common::redirect_need::TuplesKey;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

/// Listener map keys shared with TC UDP assignment and userspace publication.
pub(crate) const KEY_TCP4: u32 = 0;
pub(crate) const KEY_TCP6: u32 = 1;
pub(crate) const KEY_UDP4_BASE: u32 = 2;
/// Parallel UDP listeners per family.
pub(crate) const UDP_LISTENER_COUNT: u32 = 4;
pub(crate) const KEY_UDP6_BASE: u32 = KEY_UDP4_BASE + UDP_LISTENER_COUNT;

/// Marker bit in `cb[4]` that carries the listener index chosen at the
/// redirect site to `dae0peer_ingress`; `cb[4]` is otherwise unused for UDP.
pub(crate) const UDP_LISTENER_MARKER: u32 = 0x100;

/// Flow-consistent spread over the parallel UDP listeners. The sole
/// definition: the redirect sites, `dae0peer_ingress` and `sk_lookup` all
/// derive the index from the flow tuple here, with addresses and ports in
/// host byte order, so a flow lands on one socket whichever path delivers it.
#[inline(always)]
pub(crate) fn udp_listener_index(src: u32, dst: u32, src_port: u16, dst_port: u16) -> u32 {
    let ports = ((src_port as u32) << 16) | dst_port as u32;
    src.wrapping_add(dst.rotate_left(8))
        .wrapping_add(ports.rotate_left(16))
        % UDP_LISTENER_COUNT
}

/// `cb[4]` value for a UDP flow. Both families hash the low address word: the
/// IPv4-mapped tuple form keeps the IPv4 address there, like `remote_ip4`.
#[inline(always)]
pub(crate) fn udp_listener_marker(five: &TuplesKey) -> u32 {
    let (src, dst) = unsafe { (five.src_ip.u6_addr32[3], five.dst_ip.u6_addr32[3]) };
    UDP_LISTENER_MARKER
        | udp_listener_index(
            u32::from_be(src),
            u32::from_be(dst),
            five.src_port,
            five.dst_port,
        )
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "sk_lookup")]
pub fn tproxy_sk_lookup(ctx: *mut aya_ebpf::bindings::bpf_sk_lookup) -> u32 {
    let ctx = SkLookupContext::new(ctx);
    do_tproxy_sk_lookup(&ctx)
}

#[inline(always)]
fn do_tproxy_sk_lookup(ctx: &SkLookupContext) -> u32 {
    let lookup = unsafe { &*ctx.lookup };
    let protocol = lookup.protocol as u8;
    let family = lookup.family;
    if family == AF_INET6 && crate::sk::IPV6_SOCKETS_AVAILABLE.load() == 0 {
        return SK_DROP;
    }

    let key = if family == AF_INET && protocol as u32 == IPPROTO_TCP as u32 {
        KEY_TCP4
    } else if family == AF_INET6 && protocol as u32 == IPPROTO_TCP as u32 {
        KEY_TCP6
    } else if protocol as u32 == IPPROTO_UDP as u32 {
        if family == AF_INET {
            udp_listener_key_v4(ctx.lookup)
        } else if family == AF_INET6 {
            udp_listener_key_v6(ctx.lookup)
        } else {
            return SK_DROP;
        }
    } else {
        return SK_PASS;
    };

    match LISTEN_SOCKET_MAP.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}

// `#[inline(never)]` keeps each family variant in its own subprogram so every
// ctx read stays a constant-offset access. Inlined at opt-level=2, LLVM
// if-converts the family branch into one load through a computed ctx offset
// (`r2 = r1; r2 += select(...)`), which the verifier rejects ("dereference of
// modified ctx ptr") — volatile reads do not stop the fold.
#[inline(never)]
fn udp_listener_key_v4(lookup: *const bpf_sk_lookup) -> u32 {
    let lookup = unsafe { &*lookup };
    let h = udp_listener_index(
        u32::from_be(lookup.remote_ip4),
        u32::from_be(lookup.local_ip4),
        u16::from_be(lookup.remote_port),
        lookup.local_port as u16,
    );
    KEY_UDP4_BASE + h
}

/// IPv6 variant of [`udp_listener_key_v4`]; see its `#[inline(never)]` note.
#[inline(never)]
fn udp_listener_key_v6(lookup: *const bpf_sk_lookup) -> u32 {
    let lookup = unsafe { &*lookup };
    let h = udp_listener_index(
        u32::from_be(lookup.remote_ip6[3]),
        u32::from_be(lookup.local_ip6[3]),
        u16::from_be(lookup.remote_port),
        lookup.local_port as u16,
    );
    KEY_UDP6_BASE + h
}
