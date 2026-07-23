//! Socket lookup/assign helpers for TC programs — the TC-side counterpart
//! of `SockMap::redirect_sk_lookup` (which aya-ebpf only offers for
//! `SkLookupContext` programs). All helpers release the lookup's implicit
//! socket reference, which the verifier requires.

use core::ffi::{c_long, c_void};

use aya_ebpf::programs::TcContext;
use aya_ebpf_bindings::{
    bindings::{bpf_sock, bpf_sock_tuple},
    helpers::{
        bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_lookup_tcp, bpf_sk_lookup_udp, bpf_sk_release,
    },
};

use crate::{errno::ENOENT, routing::bpf_sock_is_dae_socket};

/// TC-side `SockMap::redirect_sk_lookup`: look the socket up by sockmap
/// index and assign it to the current skb.
///
/// `map` is the raw map-definition pointer (a `&static` BTF map's address).
/// `Ok(())` when the assign succeeded; `Err(-ENOENT)` when the index holds
/// no socket; `Err(errno)` propagated from `bpf_sk_assign` otherwise.
#[inline(always)]
pub(crate) fn sk_assign_by_index(
    ctx: &TcContext,
    map: *const c_void,
    index: &u32,
    flags: u64,
) -> Result<(), c_long> {
    let sk = unsafe { bpf_map_lookup_elem(map as *mut c_void, index as *const u32 as *const c_void) };
    if sk.is_null() {
        return Err(-(ENOENT as c_long));
    }
    sk_assign_released(ctx, sk as *const bpf_sock, flags)
}

/// Assign `sk` to the TC skb, then release the lookup's implicit reference.
/// `Ok(())` when `bpf_sk_assign` returned 0, `Err(errno)` otherwise.
#[inline(always)]
pub(crate) fn sk_assign_released(
    ctx: &TcContext,
    sk: *const bpf_sock,
    flags: u64,
) -> Result<(), c_long> {
    let ret = unsafe { bpf_sk_assign(ctx.skb.skb as *mut c_void, sk as *mut c_void, flags) };
    let _: c_long = unsafe { bpf_sk_release(sk as *mut _) };
    if ret == 0 { Ok(()) } else { Err(ret as c_long) }
}

/// Outcome of a socket probe, captured before the reference is released so
/// callers can never leak it.
pub(crate) struct SkProbe {
    /// `bpf_sock.state` (e.g. `BPF_TCP_LISTEN` = 10).
    pub state: u32,
    /// The socket belongs to the proxy engine itself (its own listeners and
    /// control-plane sockets must not be re-intercepted).
    pub is_dae_socket: bool,
}

/// Probe the TCP socket matching `tuple` in `netns_id`, releasing the
/// reference before returning. `None` when nothing matched.
#[inline(always)]
pub(crate) fn probe_tcp_socket(
    ctx: &TcContext,
    tuple: &mut bpf_sock_tuple,
    tuple_size: u32,
    netns_id: u64,
) -> Option<SkProbe> {
    let sk = unsafe { bpf_sk_lookup_tcp(ctx.skb.skb as *mut _, tuple, tuple_size, netns_id, 0) };
    probe_result(sk)
}

/// UDP variant of [`probe_tcp_socket`].
#[inline(always)]
pub(crate) fn probe_udp_socket(
    ctx: &TcContext,
    tuple: &mut bpf_sock_tuple,
    tuple_size: u32,
    netns_id: u64,
) -> Option<SkProbe> {
    let sk = unsafe { bpf_sk_lookup_udp(ctx.skb.skb as *mut _, tuple, tuple_size, netns_id, 0) };
    probe_result(sk)
}

#[inline(always)]
fn probe_result(sk: *mut bpf_sock) -> Option<SkProbe> {
    if sk.is_null() {
        return None;
    }
    let probe = SkProbe {
        state: unsafe { (*sk).state },
        is_dae_socket: bpf_sock_is_dae_socket(sk as *const _),
    };
    unsafe { bpf_sk_release(sk as *mut c_void) };
    Some(probe)
}
