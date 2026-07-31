//! Socket-lookup program for the isolated `daens` namespace.
//!
//! When proxy-bound packets are redirected from the host namespace into `daens`
//! via the `dae0peer` veth, normal socket lookup fails because the destination
//! port belongs to the original remote endpoint, not to the local TPROXY
//! listener.  This program overrides the lookup and assigns the transparent
//! listener socket, letting the kernel deliver the packet with the original
//! destination intact.

use crate::{
    maps::LISTEN_SOCKET_MAP,
    transport::{IPPROTO_TCP, IPPROTO_UDP},
};
use aya_ebpf::programs::SkLookupContext;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const SK_DROP: u32 = 0;
const SK_PASS: u32 = 1;

/// Listener socket map keys used by `publish_listener_sockets` in userspace.
const SK_TCP4: u32 = 0;
const SK_UDP4: u32 = 1;
const SK_TCP6: u32 = 2;
const SK_UDP6: u32 = 3;

#[unsafe(no_mangle)]
#[unsafe(link_section = "sk_lookup")]
pub fn tproxy_sk_lookup(ctx: *mut aya_ebpf::bindings::bpf_sk_lookup) -> u32 {
    let ctx = SkLookupContext::new(ctx);
    do_tproxy_sk_lookup(&ctx)
}

#[inline(always)]
fn do_tproxy_sk_lookup(ctx: &SkLookupContext) -> u32 {
    let protocol = unsafe { (*ctx.lookup).protocol } as u8;
    let family = unsafe { (*ctx.lookup).family };

    let key = match (family, protocol as u32) {
        (AF_INET, p) if p == IPPROTO_TCP as u32 => SK_TCP4,
        (AF_INET, p) if p == IPPROTO_UDP as u32 => SK_UDP4,
        (AF_INET6, p) if p == IPPROTO_TCP as u32 => SK_TCP6,
        (AF_INET6, p) if p == IPPROTO_UDP as u32 => SK_UDP6,
        _ => return SK_PASS,
    };

    match LISTEN_SOCKET_MAP.redirect_sk_lookup(ctx, key, 0) {
        Ok(_) => SK_PASS,
        Err(_) => SK_DROP,
    }
}
