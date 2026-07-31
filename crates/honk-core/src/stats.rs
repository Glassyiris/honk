//! Statistics tracking for honk-core.

use dashmap::DashMap;
use honk_ebpf_common::OutboundStats;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) mod dns;
#[cfg(test)]
pub(crate) use dns::dns_snapshot;
pub(crate) use dns::{DnsStatEvent, record_dns_event};

/// Per-outbound statistics tracked in user-space.
#[derive(Debug, Clone, Default)]
pub struct OutboundTracker {
    /// Total connections through this outbound
    pub total_connections: Arc<AtomicU64>,
    /// Active connections currently open
    pub active_connections: Arc<AtomicU64>,
    /// Total bytes transferred (client → proxy)
    pub tx_bytes: Arc<AtomicU64>,
    /// Total bytes transferred (proxy → client)
    pub rx_bytes: Arc<AtomicU64>,
    /// Failed connection attempts
    pub errors: Arc<AtomicU64>,
}

impl OutboundTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, tx: u64, rx: u64) {
        self.tx_bytes.fetch_add(tx, Ordering::Relaxed);
        self.rx_bytes.fetch_add(rx, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> OutboundStats {
        OutboundStats {
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_packets: 0, // Not tracked at user-space level
            rx_packets: 0,
            active_conns: self.active_connections.load(Ordering::Relaxed) as u32,
            total_conns: self.total_connections.load(Ordering::Relaxed) as u32,
            errors: self.errors.load(Ordering::Relaxed) as u32,
            _pad: 0,
        }
    }
}

/// Fixed number of log2 latency buckets for UDP metrics. Bucket `n` covers
/// values from `2^n` through `2^(n+1)-1` nanoseconds (except bucket 0,
/// which also includes zero); the final bucket saturates at `u64::MAX`.
pub const UDP_LOG2_BUCKETS: usize = 64;

#[derive(Debug)]
struct Log2Histogram {
    count: AtomicU64,
    sum_nanos: AtomicU64,
    buckets: [AtomicU64; UDP_LOG2_BUCKETS],
}

impl Default for Log2Histogram {
    fn default() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Log2Histogram {
    fn record(&self, elapsed: std::time::Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        let bucket = nanos.max(1).ilog2() as usize;
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> UdpLatencyHistogramSnapshot {
        UdpLatencyHistogramSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_nanos: self.sum_nanos.load(Ordering::Relaxed),
            buckets: std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed)),
        }
    }
}

/// Immutable copy of one fixed-size UDP latency histogram.
#[derive(Debug, Clone)]
pub struct UdpLatencyHistogramSnapshot {
    pub count: u64,
    pub sum_nanos: u64,
    pub buckets: [u64; UDP_LOG2_BUCKETS],
}

impl UdpLatencyHistogramSnapshot {
    /// Inclusive upper bound, in nanoseconds, of a log2 bucket.
    pub const fn bucket_upper_bound_ns(bucket: usize) -> u64 {
        if bucket >= UDP_LOG2_BUCKETS - 1 {
            u64::MAX
        } else {
            (1u64 << (bucket + 1)) - 1
        }
    }

    /// Return the inclusive bucket upper bound containing the requested
    /// quantile. This remains bounded and needs no labels or dynamic storage.
    pub fn quantile_upper_bound_ns(&self, quantile: f64) -> Option<u64> {
        if self.count == 0 || !(0.0..=1.0).contains(&quantile) {
            return None;
        }
        let target = ((self.count as f64 * quantile).ceil() as u64).max(1);
        let mut seen: u64 = 0;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                return Some(Self::bucket_upper_bound_ns(index));
            }
        }
        Some(Self::bucket_upper_bound_ns(UDP_LOG2_BUCKETS - 1))
    }
}

/// Fixed, allocation-free UDP pipeline metrics for the current control-plane
/// path. The schema is intentionally stable while each recorder is wired to
/// its corresponding production event.
#[derive(Debug, Default)]
struct UdpStats {
    endpoint_hits: AtomicU64,
    endpoint_misses: AtomicU64,
    route_latency: Log2Histogram,
    dial_latency: Log2Histogram,
    reply_ready_latency: Log2Histogram,
    first_send_latency: Log2Histogram,
    first_reply_latency: Log2Histogram,
    capacity_rejections: AtomicU64,
    slow_permit_accepted: AtomicU64,
    slow_permit_rejected: AtomicU64,
    slow_permit_closed: AtomicU64,
    queue_accepted: AtomicU64,
    queue_full: AtomicU64,
    queue_closed: AtomicU64,
    first_send_failures: AtomicU64,
    stagger_attempts: AtomicU64,
    stagger_winners: AtomicU64,
    stagger_cancellations: AtomicU64,
    warm_attempts: AtomicU64,
    warm_successes: AtomicU64,
    warm_failures: AtomicU64,
}

/// Immutable snapshot of the fixed UDP metrics schema exposed by `/stats`.
#[derive(Debug, Clone)]
pub struct UdpStatsSnapshot {
    pub endpoint_hits: u64,
    pub endpoint_misses: u64,
    pub route_latency: UdpLatencyHistogramSnapshot,
    pub dial_latency: UdpLatencyHistogramSnapshot,
    pub reply_ready_latency: UdpLatencyHistogramSnapshot,
    pub first_send_latency: UdpLatencyHistogramSnapshot,
    pub first_reply_latency: UdpLatencyHistogramSnapshot,
    pub capacity_rejections: u64,
    pub slow_permit_accepted: u64,
    pub slow_permit_rejected: u64,
    pub slow_permit_closed: u64,
    pub queue_accepted: u64,
    pub queue_full: u64,
    pub queue_closed: u64,
    pub first_send_failures: u64,
    pub stagger_attempts: u64,
    pub stagger_winners: u64,
    pub stagger_cancellations: u64,
    pub warm_attempts: u64,
    pub warm_successes: u64,
    pub warm_failures: u64,
}

impl UdpStats {
    fn snapshot(&self) -> UdpStatsSnapshot {
        UdpStatsSnapshot {
            endpoint_hits: self.endpoint_hits.load(Ordering::Relaxed),
            endpoint_misses: self.endpoint_misses.load(Ordering::Relaxed),
            route_latency: self.route_latency.snapshot(),
            dial_latency: self.dial_latency.snapshot(),
            reply_ready_latency: self.reply_ready_latency.snapshot(),
            first_send_latency: self.first_send_latency.snapshot(),
            first_reply_latency: self.first_reply_latency.snapshot(),
            capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
            slow_permit_accepted: self.slow_permit_accepted.load(Ordering::Relaxed),
            slow_permit_rejected: self.slow_permit_rejected.load(Ordering::Relaxed),
            slow_permit_closed: self.slow_permit_closed.load(Ordering::Relaxed),
            queue_accepted: self.queue_accepted.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            queue_closed: self.queue_closed.load(Ordering::Relaxed),
            first_send_failures: self.first_send_failures.load(Ordering::Relaxed),
            stagger_attempts: self.stagger_attempts.load(Ordering::Relaxed),
            stagger_winners: self.stagger_winners.load(Ordering::Relaxed),
            stagger_cancellations: self.stagger_cancellations.load(Ordering::Relaxed),
            warm_attempts: self.warm_attempts.load(Ordering::Relaxed),
            warm_successes: self.warm_successes.load(Ordering::Relaxed),
            warm_failures: self.warm_failures.load(Ordering::Relaxed),
        }
    }
}

/// Keeps exactly one per-outbound active-connection increment live. Dropping
/// the guard only balances `active_connections`; explicit error paths remain
/// responsible for recording errors themselves.
pub struct ActiveConnectionGuard {
    tracker: OutboundTracker,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.tracker.decrement_connections();
    }
}

/// Statistics manager that tracks per-outbound metrics.
#[derive(Debug)]
pub struct StatsManager {
    trackers: DashMap<String, OutboundTracker>,
    udp: UdpStats,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            trackers: DashMap::new(),
            udp: UdpStats::default(),
        }
    }

    /// Record a new connection on an outbound.
    pub fn record_connection(&self, outbound: &str) {
        self.trackers
            .entry(outbound.to_string())
            .or_default()
            .increment_connections();
    }

    /// Track one connection with an exactly-once active counter balance.
    pub fn track_connection(self: &Arc<Self>, outbound: &str) -> ActiveConnectionGuard {
        let tracker = self
            .trackers
            .entry(outbound.to_string())
            .or_default()
            .clone();
        tracker.increment_connections();
        ActiveConnectionGuard { tracker }
    }

    /// Record a real established-endpoint fast-path hit. This is deliberately
    /// separate from the slow-path endpoint lookup so one receive event is
    /// never counted twice.
    pub fn record_udp_endpoint_hit(&self) {
        self.udp.endpoint_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a real cold-flow endpoint lookup miss.
    pub fn record_udp_endpoint_miss(&self) {
        self.udp.endpoint_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record cold route selection latency.
    pub fn record_udp_route_latency(&self, elapsed: std::time::Duration) {
        self.udp.route_latency.record(elapsed);
    }

    /// Record one cold UDP dial attempt latency.
    pub fn record_udp_dial_latency(&self, elapsed: std::time::Duration) {
        self.udp.dial_latency.record(elapsed);
    }

    /// Record a transport-preparation attempt from the fixed cold URLTest
    /// stagger scheduler. The schema is fixed; callers never attach labels.
    pub fn record_udp_stagger_attempt(&self) {
        self.udp.stagger_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one started generation-owned UDP warm dispatch. These counters
    /// remain fixed, aggregate-only recorder fields: no per-node labels or
    /// outbound health/error state is created for warm-up work.
    pub fn record_udp_warm_attempt(&self) {
        self.udp.warm_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a warm dispatch that found or established a usable session.
    pub fn record_udp_warm_success(&self) {
        self.udp.warm_successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a true warm failure while its generation remains live.
    pub fn record_udp_warm_failure(&self) {
        self.udp.warm_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the first eligible successful staggered preparation.
    pub fn record_udp_stagger_winner(&self) {
        self.udp.stagger_winners.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one started speculative preparation aborted after a winner.
    pub fn record_udp_stagger_cancellation(&self) {
        self.udp
            .stagger_cancellations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record admission into the active UDP slow path.
    pub fn record_udp_slow_permit_accepted(&self) {
        self.udp
            .slow_permit_accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record rejection of a UDP slow-path admission because the shared
    /// connection semaphore is full.
    pub fn record_udp_slow_permit_rejected(&self) {
        self.udp
            .slow_permit_rejected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an exact endpoint-capacity reservation rejection.
    pub fn record_udp_capacity_rejection(&self) {
        self.udp.capacity_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a bounded endpoint-driver queue admission.
    pub fn record_udp_queue_accepted(&self) {
        self.udp.queue_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record drop-newest because a per-flow or global queue bound was full.
    pub fn record_udp_queue_full(&self) {
        self.udp.queue_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a queue attempt against a closing/closed endpoint driver.
    pub fn record_udp_queue_closed(&self) {
        self.udp.queue_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record synchronous anyfrom preparation latency before driver commit.
    pub fn record_udp_reply_ready_latency(&self, elapsed: std::time::Duration) {
        self.udp.reply_ready_latency.record(elapsed);
    }

    /// Record the fixed five-second first-send attempt latency.
    pub fn record_udp_first_send_latency(&self, elapsed: std::time::Duration) {
        self.udp.first_send_latency.record(elapsed);
    }

    /// Record a first-send error or timeout (both are ambiguous sends).
    pub fn record_udp_first_send_failure(&self) {
        self.udp.first_send_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the first reply successfully reinjected to the client.
    pub fn record_udp_first_reply_latency(&self, elapsed: std::time::Duration) {
        self.udp.first_reply_latency.record(elapsed);
    }

    /// Record rejection of a UDP slow-path admission while draining.
    pub fn record_udp_slow_permit_closed(&self) {
        self.udp.slow_permit_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a closed connection on an outbound.
    pub fn record_close(&self, outbound: &str) {
        if let Some(tracker) = self.trackers.get(outbound) {
            tracker.decrement_connections();
        }
    }

    /// Record bytes transferred through an outbound.
    pub fn record_bytes(&self, outbound: &str, tx: u64, rx: u64) {
        self.trackers
            .entry(outbound.to_string())
            .or_default()
            .add_bytes(tx, rx);
    }

    /// Record an error on an outbound.
    pub fn record_error(&self, outbound: &str) {
        self.trackers
            .entry(outbound.to_string())
            .or_default()
            .increment_errors();
    }

    /// Get a snapshot of all per-outbound statistics.
    pub fn snapshot(&self) -> std::collections::HashMap<String, OutboundStats> {
        self.trackers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect()
    }

    /// Get the complete fixed UDP metrics schema.
    pub fn udp_snapshot(&self) -> UdpStatsSnapshot {
        self.udp.snapshot()
    }
}

impl Default for StatsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_tracker() {
        let tracker = OutboundTracker::new();

        tracker.increment_connections();
        tracker.increment_connections();
        assert_eq!(tracker.total_connections.load(Ordering::Relaxed), 2);
        assert_eq!(tracker.active_connections.load(Ordering::Relaxed), 2);

        tracker.decrement_connections();
        assert_eq!(tracker.active_connections.load(Ordering::Relaxed), 1);

        tracker.add_bytes(100, 200);
        assert_eq!(tracker.tx_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(tracker.rx_bytes.load(Ordering::Relaxed), 200);

        let snap = tracker.snapshot();
        assert_eq!(snap.total_conns, 2);
        assert_eq!(snap.active_conns, 1);
    }

    #[test]
    fn test_stats_manager() {
        let mgr = StatsManager::new();

        mgr.record_connection("proxy1");
        mgr.record_connection("proxy1");
        mgr.record_connection("proxy2");
        mgr.record_bytes("proxy1", 1000, 2000);
        mgr.record_error("proxy2");

        let snap = mgr.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap.get("proxy1").unwrap().total_conns, 2);
        assert_eq!(snap.get("proxy2").unwrap().total_conns, 1);
        assert_eq!(snap.get("proxy2").unwrap().errors, 1);
    }

    #[test]
    fn active_connection_guard_decrements_active_exactly_once() {
        let manager = Arc::new(StatsManager::new());
        let guard = manager.track_connection("udp-test");

        let snapshot = manager.snapshot();
        let tracker = snapshot.get("udp-test").unwrap();
        assert_eq!(tracker.total_conns, 1);
        assert_eq!(tracker.active_conns, 1);
        assert_eq!(tracker.errors, 0);

        drop(guard);
        let snapshot = manager.snapshot();
        let tracker = snapshot.get("udp-test").unwrap();
        assert_eq!(tracker.total_conns, 1);
        assert_eq!(tracker.active_conns, 0);
        assert_eq!(tracker.errors, 0);
    }

    #[test]
    fn udp_latency_histogram_uses_fixed_log2_bounds_and_quantiles() {
        let manager = StatsManager::new();
        manager.record_udp_route_latency(std::time::Duration::from_nanos(1));
        manager.record_udp_route_latency(std::time::Duration::from_nanos(3));
        manager.record_udp_route_latency(std::time::Duration::from_nanos(4));

        let route = manager.udp_snapshot().route_latency;
        assert_eq!(route.count, 3);
        assert_eq!(route.sum_nanos, 8);
        assert_eq!(route.buckets[0], 1);
        assert_eq!(route.buckets[1], 1);
        assert_eq!(route.buckets[2], 1);
        assert_eq!(UdpLatencyHistogramSnapshot::bucket_upper_bound_ns(0), 1);
        assert_eq!(UdpLatencyHistogramSnapshot::bucket_upper_bound_ns(1), 3);
        assert_eq!(route.quantile_upper_bound_ns(0.5), Some(3));
    }
}
