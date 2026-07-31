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

/// Statistics manager that tracks per-outbound metrics.
#[derive(Debug)]
pub struct StatsManager {
    trackers: DashMap<String, OutboundTracker>,
}

impl StatsManager {
    pub fn new() -> Self {
        Self {
            trackers: DashMap::new(),
        }
    }

    /// Record a new connection on an outbound.
    pub fn record_connection(&self, outbound: &str) {
        self.trackers
            .entry(outbound.to_string())
            .or_default()
            .increment_connections();
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

    /// Get a snapshot of all statistics.
    pub fn snapshot(&self) -> std::collections::HashMap<String, OutboundStats> {
        self.trackers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect()
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
}
