//! Per-source new-flow budget for LAN ingress.

use crate::maps::{NEW_FLOW_RATE, NewFlowWindow, increment_bpf_stat};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use honk_ebpf_common::{
    conn::{BpfStatsKey, NEW_FLOW_LIMIT_PER_CPU_SECOND},
    dae_ip::In6Addr,
};

/// Counts one new-flow attempt from `src`; true when this CPU's budget for the
/// current second is spent and the attempt must be dropped.
#[inline(always)]
pub fn exceeded(src: &In6Addr) -> bool {
    let exceeded = !try_acquire(src);
    if exceeded {
        increment_bpf_stat(BpfStatsKey::NewFlowRateLimited);
    }
    exceeded
}

/// Consumes one attempt without counting a packet drop: local-service requests
/// keep passing when their optional reply-state learning cannot get a budget.
/// An IPv6 host owns its whole /64 (SLAAC privacy addresses rotate within it),
/// so the budget is keyed by the prefix, not the address. The key lives in this
/// frame because its callers already sit near the BPF stack limit.
#[inline(never)]
pub fn try_acquire(src: &In6Addr) -> bool {
    let mut key = *src;
    if !key.is_v4_mapped() {
        unsafe {
            key.u6_addr32[2] = 0;
            key.u6_addr32[3] = 0;
        }
    }
    let src = &key;
    let second = (unsafe { bpf_ktime_get_ns() } / 1_000_000_000) as u32;
    let Some(window) = NEW_FLOW_RATE.get_ptr_mut(src) else {
        // A failed insert only leaves this attempt uncounted.
        let _ = NEW_FLOW_RATE.insert(src, NewFlowWindow { second, count: 1 }, 0);
        return true;
    };
    let window = unsafe { &mut *window };
    if window.second != second {
        window.second = second;
        window.count = 1;
        return true;
    }
    if window.count >= NEW_FLOW_LIMIT_PER_CPU_SECOND {
        return false;
    }
    window.count += 1;
    true
}
