//! ABI compatibility stubs preserved for Go bpf2go code compatibility.
//! Ported from daed/wing/dae-core/control/kern/tproxy.c.
//!
//! These programs are intentionally no-ops. The sockops + sk_msg combination
//! has been proven to cause Kernel Panic; TC-based redirect is used instead.
//! The Go side interacts with these stubs but they do nothing in the kernel.

use aya_ebpf::{macros::sock_ops, programs::SockOpsContext};

/// sock_ops verdict: allow the operation.
const BPF_OK: u32 = 0;

#[sock_ops]
pub fn tproxy_sockops(_ctx: SockOpsContext) -> u32 {
    BPF_OK
}

use aya_ebpf::{macros::sk_msg, programs::SkMsgContext};

/// sk_msg verdict: deliver to the socket without redirect.
const SK_PASS: u32 = 1;

#[sk_msg]
pub fn tproxy_sk_msg_redir(_ctx: SkMsgContext) -> u32 {
    SK_PASS
}
