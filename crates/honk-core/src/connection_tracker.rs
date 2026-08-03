//! Per-connection state tracker for the Clash API.
//!
//! Uses [`DashMap`] for concurrent-safe access from multiple tokio tasks
//! (accept loop, relay workers, and HTTP API handlers).

use crate::control::udp_endpoint::UdpEndpointPool;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

/// Snapshot of a connection's state, safe to serialize and expose via API.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    /// Matched routing rule (dae expression; "Fallback" = fallback).
    pub rule: String,
    /// Value that drove the match (sniffed domain or destination IP).
    pub rule_payload: String,
    /// Selection path, leaf-first ([leaf, ..sub-groups.., topGroup]).
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    pub dscp: u8,
}

enum ConnectionCloseAction {
    Tcp(tokio::sync::oneshot::Sender<()>),
    Udp {
        pool: Weak<UdpEndpointPool>,
        client: SocketAddr,
        destination: SocketAddr,
    },
}

enum ConnectionCloseState {
    Detached,
    Open(ConnectionCloseAction),
    Closing,
}

enum CloseDisposition {
    Detached,
    Signalled,
    Closing,
}

#[derive(Clone)]
pub struct ConnectionCloseHandle {
    state: Arc<parking_lot::Mutex<ConnectionCloseState>>,
}

impl ConnectionCloseHandle {
    pub fn detached() -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(ConnectionCloseState::Detached)),
        }
    }

    pub(crate) fn tcp(sender: tokio::sync::oneshot::Sender<()>) -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(ConnectionCloseState::Open(
                ConnectionCloseAction::Tcp(sender),
            ))),
        }
    }

    pub(crate) fn udp(
        pool: Weak<UdpEndpointPool>,
        client: SocketAddr,
        destination: SocketAddr,
    ) -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(ConnectionCloseState::Open(
                ConnectionCloseAction::Udp {
                    pool,
                    client,
                    destination,
                },
            ))),
        }
    }

    fn close(&self) -> CloseDisposition {
        let action = {
            let mut state = self.state.lock();
            match &*state {
                ConnectionCloseState::Detached => return CloseDisposition::Detached,
                ConnectionCloseState::Closing => return CloseDisposition::Closing,
                ConnectionCloseState::Open(_) => {}
            }
            match std::mem::replace(&mut *state, ConnectionCloseState::Closing) {
                ConnectionCloseState::Open(action) => action,
                ConnectionCloseState::Detached | ConnectionCloseState::Closing => unreachable!(),
            }
        };

        match action {
            ConnectionCloseAction::Tcp(sender) => {
                let _ = sender.send(());
            }
            ConnectionCloseAction::Udp {
                pool,
                client,
                destination,
            } => {
                if let Some(pool) = pool.upgrade() {
                    pool.remove(client, destination);
                }
            }
        }
        CloseDisposition::Signalled
    }
}

/// Live per-connection entry, updated concurrently from the relay task.
pub struct ConnectionEntry {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    /// Byte counters are shared with the relay task, which increments them
    /// as data flows so `/connections` shows live (not close-time) totals.
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
    pub dscp: u8,
    pub close_handle: ConnectionCloseHandle,
}

impl ConnectionEntry {
    /// Create a read-only snapshot of the current entry state.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            source: self.source.clone(),
            destination: self.destination.clone(),
            proxy: self.proxy.clone(),
            rule: self.rule.clone(),
            rule_payload: self.rule_payload.clone(),
            chains: self.chains.clone(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            start_time: self.start_time,
            domain: self.domain.clone(),
            network: self.network.clone(),
            dscp: self.dscp,
        }
    }
}

/// Concurrent-safe tracking of all active connections.
///
/// Thread-safe by construction via [`DashMap`] — no external locks needed.
pub struct ConnectionTracker {
    entries: DashMap<String, ConnectionEntry>,
    traffic_handoff: parking_lot::Mutex<()>,
}

impl ConnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            traffic_handoff: parking_lot::Mutex::new(()),
        }
    }

    /// Register a new connection and return its unique ID (UUID v4).
    pub fn register(&self, entry: ConnectionEntry) -> String {
        let id = entry.id.clone();
        self.entries.insert(id.clone(), entry);
        id
    }

    /// Add upload/download bytes to an existing connection.
    ///
    /// If the connection is no longer in the map, the update is silently
    /// dropped (the relay task may have raced with a close).
    pub fn update_bytes(&self, id: &str, upload_delta: u64, download_delta: u64) {
        if let Some(entry) = self.entries.get(id) {
            entry.upload.fetch_add(upload_delta, Ordering::Relaxed);
            entry.download.fetch_add(download_delta, Ordering::Relaxed);
        }
    }

    /// Remove a connection from the tracker.
    pub fn remove(&self, id: &str) {
        self.entries.remove(id);
    }

    /// Commit one TCP flow's final counters and remove its live ownership.
    pub(crate) fn commit_tcp_traffic_and_remove(
        &self,
        id: &str,
        stats: &crate::stats::StatsManager,
        outbound: &str,
    ) -> Option<(u64, u64)> {
        let _handoff = self.traffic_handoff.lock();
        let entry = self.entries.get(id)?;
        if entry.network != "tcp" {
            return None;
        }
        let totals = (
            entry.upload.load(Ordering::Relaxed),
            entry.download.load(Ordering::Relaxed),
        );
        drop(entry);
        stats.record_bytes(outbound, totals.0, totals.1);
        self.entries.remove(id);
        Some(totals)
    }

    /// Sum completed/UDP bytes and live TCP bytes under one ownership fence.
    pub fn combined_traffic_totals(&self, stats: &crate::stats::StatsManager) -> (u64, u64) {
        let _handoff = self.traffic_handoff.lock();
        self.entries
            .iter()
            .filter(|entry| entry.network == "tcp")
            .fold(stats.traffic_totals(), |totals, entry| {
                (
                    totals
                        .0
                        .saturating_add(entry.upload.load(Ordering::Relaxed)),
                    totals
                        .1
                        .saturating_add(entry.download.load(Ordering::Relaxed)),
                )
            })
    }

    /// Return a point-in-time snapshot of all active connections.
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.entries
            .iter()
            .map(|ref_multi| ref_multi.value().snapshot())
            .collect()
    }

    /// Signal lifecycle-owned termination for a connection.
    pub fn close_connection(&self, id: &str) -> bool {
        let Some(entry) = self.entries.get(id) else {
            return false;
        };
        let disposition = entry.close_handle.close();
        drop(entry);
        if matches!(disposition, CloseDisposition::Detached) {
            self.entries.remove(id);
        }
        true
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: shared tracker reference used throughout the control plane.
pub type SharedTracker = Arc<ConnectionTracker>;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, network: &str, upload: u64, download: u64) -> ConnectionEntry {
        ConnectionEntry {
            id: id.into(),
            source: "127.0.0.1:1000".into(),
            destination: "127.0.0.1:2000".into(),
            proxy: "proxy".into(),
            rule: "Match".into(),
            rule_payload: String::new(),
            chains: vec!["proxy".into()],
            upload: Arc::new(AtomicU64::new(upload)),
            download: Arc::new(AtomicU64::new(download)),
            start_time: Instant::now(),
            domain: None,
            network: network.into(),
            dscp: 0,
            close_handle: ConnectionCloseHandle::detached(),
        }
    }

    #[test]
    fn tcp_traffic_handoff_is_monotonic_and_exactly_once() {
        let tracker = ConnectionTracker::new();
        let stats = crate::stats::StatsManager::new();
        tracker.register(entry("tcp", "tcp", 7, 11));

        assert_eq!(tracker.combined_traffic_totals(&stats), (7, 11));
        assert_eq!(
            tracker.commit_tcp_traffic_and_remove("tcp", &stats, "proxy"),
            Some((7, 11))
        );
        assert_eq!(tracker.combined_traffic_totals(&stats), (7, 11));
        assert_eq!(
            tracker.commit_tcp_traffic_and_remove("tcp", &stats, "proxy"),
            None
        );
        assert_eq!(stats.traffic_totals(), (7, 11));
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn combined_totals_do_not_double_count_live_udp_entries() {
        let tracker = ConnectionTracker::new();
        let stats = crate::stats::StatsManager::new();
        stats.record_bytes("proxy", 5, 9);
        tracker.register(entry("udp", "udp", 5, 9));

        assert_eq!(tracker.combined_traffic_totals(&stats), (5, 9));
    }

    #[tokio::test]
    async fn close_signals_tcp_once_and_leaves_lifecycle_owned_entry() {
        let tracker = ConnectionTracker::new();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel();
        let mut connection = entry("tcp-close", "tcp", 0, 0);
        connection.close_handle = ConnectionCloseHandle::tcp(close_tx);
        tracker.register(connection);

        assert!(tracker.close_connection("tcp-close"));
        assert!(tracker.close_connection("tcp-close"));
        close_rx.await.unwrap();
        assert_eq!(tracker.snapshot().len(), 1);
        tracker.remove("tcp-close");
        assert!(!tracker.close_connection("tcp-close"));
    }

    #[test]
    fn close_removes_detached_entries_immediately() {
        let tracker = ConnectionTracker::new();
        tracker.register(entry("detached", "tcp", 0, 0));

        assert!(tracker.close_connection("detached"));
        assert!(tracker.snapshot().is_empty());
        assert!(!tracker.close_connection("missing"));
    }
}
