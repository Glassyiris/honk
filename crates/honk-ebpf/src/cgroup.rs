//! Cgroup programs for immutable socket-lifetime process identity.

use aya_ebpf::{
    macros::{cgroup_sock, cgroup_sock_addr},
    programs::{SockAddrContext, SockContext},
};

use crate::socket_identity::capture;

/// These hooks sit on the root cgroup: a lost identity only costs process-name
/// matching, so capture failure never denies a host socket operation.
const CGROUP_ALLOW: i32 = 1;

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create(ctx: SockContext) -> i32 {
    // Cgroup sock storage expects the context itself, not a loaded socket field.
    unsafe { capture(ctx.sock.cast(), true) };
    CGROUP_ALLOW
}

#[cgroup_sock(sock_create)]
pub fn tproxy_wan_cg_sock_create_comm(ctx: SockContext) -> i32 {
    unsafe { capture(ctx.sock.cast(), false) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn tproxy_wan_cg_connect4(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), true) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn tproxy_wan_cg_connect4_comm(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), false) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), true) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn tproxy_wan_cg_connect6_comm(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), false) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), true) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn tproxy_wan_cg_sendmsg4_comm(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), false) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), true) };
    CGROUP_ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn tproxy_wan_cg_sendmsg6_comm(ctx: SockAddrContext) -> i32 {
    unsafe { capture((*ctx.sock_addr).__bindgen_anon_1.sk.cast(), false) };
    CGROUP_ALLOW
}
