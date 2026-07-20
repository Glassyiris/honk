//! Per-outbound traffic counters for the TC datapath.
//!
//! Counters live in the per-CPU `OUTBOUND_STATS` array (see `maps.rs`) so
//! the per-packet update never contends across CPUs; userspace aggregates
//! the per-CPU slots when reading.  tx (LAN → outbound) is accounted at
//! `lan_ingress` when the routing decision lands — both for redirected
//! flows and for direct+must pass-throughs — and rx (outbound → LAN) at
//! `dae0_ingress` on the reply path.  Flows that never carry an outbound
//! index (unclassified pass-throughs, drops) are not counted.

use crate::maps::OUTBOUND_STATS;
use aya_ebpf::programs::TcContext;
use honk_ebpf_common::{
    OUTBOUND_STATS_RX_BYTES, OUTBOUND_STATS_RX_PACKETS, OUTBOUND_STATS_TX_BYTES,
    OUTBOUND_STATS_TX_PACKETS, outbound_stats_index,
};

/// Increment `counter` of `outbound` by `delta`, skipping outbounds that
/// have no counter block (cannot happen for `u8` indices; the map covers
/// all 256).
#[inline(always)]
fn add(outbound: u8, counter: u32, delta: u64) {
    if let Some(ptr) = OUTBOUND_STATS.get_ptr_mut(outbound_stats_index(outbound, counter)) {
        unsafe {
            *ptr = (*ptr).wrapping_add(delta);
        }
    }
}

/// Account one packet travelling LAN → outbound (request direction).
#[inline(always)]
pub fn count_tx(ctx: &TcContext, outbound: u8) {
    let len = ctx.len() as u64;
    add(outbound, OUTBOUND_STATS_TX_PACKETS, 1);
    add(outbound, OUTBOUND_STATS_TX_BYTES, len);
}

/// Account one packet travelling outbound → LAN (reply direction).
#[inline(always)]
pub fn count_rx(ctx: &TcContext, outbound: u8) {
    let len = ctx.len() as u64;
    add(outbound, OUTBOUND_STATS_RX_PACKETS, 1);
    add(outbound, OUTBOUND_STATS_RX_BYTES, len);
}
