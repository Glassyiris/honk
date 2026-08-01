//! Socket-lookup program for the isolated `daens` namespace.
//!
//! When proxy-bound packets are redirected from the host namespace into `daens`
//! via the `dae0peer` veth, normal socket lookup fails because the destination
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
use aya_ebpf::programs::SkLookupContext;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

/// Listener socket map keys shared with `assign_listener` (ingress.rs) and
/// the userspace publish path: 0 = TCP4, 1 = TCP6, 2.. = UDP4 group,
/// 2 + UDP_LISTENER_COUNT.. = UDP6 group.
pub(crate) const KEY_TCP4: u32 = 0;
pub(crate) const KEY_TCP6: u32 = 1;
pub(crate) const KEY_UDP4_BASE: u32 = 2;
/// Parallel UDP listeners per family.
pub(crate) const UDP_LISTENER_COUNT: u32 = 4;
pub(crate) const KEY_UDP6_BASE: u32 = KEY_UDP4_BASE + UDP_LISTENER_COUNT;

/// Flow-consistent spread over the parallel UDP listeners.
#[inline(always)]
pub(crate) fn listener_hash(a: u32, b: u32, c: u32, d: u32) -> u32 {
    (a.wrapping_add(b.rotate_left(8))
        .wrapping_add(c.rotate_left(16))
        ^ d)
        % UDP_LISTENER_COUNT
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

    let key = if family == AF_INET && protocol as u32 == IPPROTO_TCP as u32 {
        KEY_TCP4
    } else if family == AF_INET6 && protocol as u32 == IPPROTO_TCP as u32 {
        KEY_TCP6
    } else if protocol as u32 == IPPROTO_UDP as u32 {
        let (remote, local) = if family == AF_INET {
            (lookup.remote_ip4, lookup.local_ip4)
        } else {
            (lookup.remote_ip6[3], lookup.local_ip6[3])
        };
        let h = listener_hash(
            remote,
            local,
            (lookup.remote_port as u32) << 16,
            lookup.local_port,
        );
        if family == AF_INET {
            KEY_UDP4_BASE + h
        } else {
            KEY_UDP6_BASE + h
        }
    } else {
        return SK_PASS;
    };

    match LISTEN_SOCKET_MAP.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}
