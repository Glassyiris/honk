//! Per-outbound traffic counters for the TC datapath.
//!
//! Counters live in the per-CPU `OUTBOUND_STATS` array (see `maps.rs`) so
//! the per-packet update never contends across CPUs; each packed entry holds
//! packet and byte counters for one outbound.  Tx (LAN → outbound) is
//! counted at `lan_ingress` when the routing decision lands — both for redirected
//! flows and for direct+must pass-throughs — and rx (outbound → LAN) at
//! `dae0_ingress` on the reply path.  Flows that never carry an outbound
//! index (unclassified pass-throughs, drops) are not counted.

use crate::maps::OUTBOUND_STATS;
use aya_ebpf::programs::TcContext;
use honk_ebpf_common::OutboundStatsCounters;

#[inline(always)]
fn add_tx(outbound: u8, bytes: u64) {
    if let Some(ptr) = OUTBOUND_STATS.get_ptr_mut(OutboundStatsCounters::for_outbound(outbound)) {
        unsafe { (&mut *ptr).add_tx(bytes) }
    }
}

#[inline(always)]
fn add_rx(outbound: u8, bytes: u64) {
    if let Some(ptr) = OUTBOUND_STATS.get_ptr_mut(OutboundStatsCounters::for_outbound(outbound)) {
        unsafe { (&mut *ptr).add_rx(bytes) }
    }
}

/// Account one packet travelling LAN → outbound (request direction).
#[inline(always)]
pub fn count_tx(ctx: &TcContext, outbound: u8) {
    add_tx(outbound, ctx.len() as u64);
}

/// Account one packet travelling outbound → LAN (reply direction).
#[inline(always)]
pub fn count_rx(ctx: &TcContext, outbound: u8) {
    add_rx(outbound, ctx.len() as u64);
}
