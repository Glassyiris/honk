//! nfqueue_* metrics skeleton (design doc §16).  Counters are lock-free and
//! process-shared; honk-core exposes a snapshot through its own stats
//! surface.  Fields reserved for later phases exist so the public shape is
//! stable — they stay at zero until their producer lands.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Default)]
pub struct NfqueueMetrics {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    packets_total: AtomicU64,
    bytes_total: AtomicU64,
    kernel_overrun_total: AtomicU64,
    netlink_enobufs_total: AtomicU64,
    decision_timeout_total: AtomicU64,
    verdict_accept_total: AtomicU64,
    verdict_drop_total: AtomicU64,
    guard_default_drop_total: AtomicU64,
    late_packet_total: AtomicU64,
    fallback_userspace_total: AtomicU64,
    // Reserved (phase 2+): nfqueue_active_flows gauge,
    // nfqueue_direct_armed_seconds / nfqueue_decision_latency_seconds /
    // nfqueue_first_accept_latency_seconds histograms.
}

pub struct Counter<'a>(&'a AtomicU64);

impl Counter<'_> {
    pub fn inc(&self) {
        self.inc_by(1);
    }

    pub fn inc_by(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
}

macro_rules! counter {
    ($name:ident) => {
        pub fn $name(&self) -> Counter<'_> {
            Counter(&self.inner.$name)
        }
    };
}

impl NfqueueMetrics {
    counter!(packets_total);
    counter!(bytes_total);
    counter!(kernel_overrun_total);
    counter!(netlink_enobufs_total);
    counter!(decision_timeout_total);
    counter!(verdict_accept_total);
    counter!(verdict_drop_total);
    counter!(guard_default_drop_total);
    counter!(late_packet_total);
    counter!(fallback_userspace_total);

    pub fn snapshot(&self) -> NfqueueMetricsSnapshot {
        let read = |c: &AtomicU64| c.load(Ordering::Relaxed);
        NfqueueMetricsSnapshot {
            packets_total: read(&self.inner.packets_total),
            bytes_total: read(&self.inner.bytes_total),
            kernel_overrun_total: read(&self.inner.kernel_overrun_total),
            netlink_enobufs_total: read(&self.inner.netlink_enobufs_total),
            decision_timeout_total: read(&self.inner.decision_timeout_total),
            verdict_accept_total: read(&self.inner.verdict_accept_total),
            verdict_drop_total: read(&self.inner.verdict_drop_total),
            guard_default_drop_total: read(&self.inner.guard_default_drop_total),
            late_packet_total: read(&self.inner.late_packet_total),
            fallback_userspace_total: read(&self.inner.fallback_userspace_total),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NfqueueMetricsSnapshot {
    pub packets_total: u64,
    pub bytes_total: u64,
    pub kernel_overrun_total: u64,
    pub netlink_enobufs_total: u64,
    pub decision_timeout_total: u64,
    pub verdict_accept_total: u64,
    pub verdict_drop_total: u64,
    pub guard_default_drop_total: u64,
    pub late_packet_total: u64,
    pub fallback_userspace_total: u64,
}
