//! Per-connection state tracker for the Clash API.
//!
//! Uses [`DashMap`] for concurrent-safe access from multiple tokio tasks
//! (accept loop, relay workers, and HTTP API handlers).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Snapshot of a connection's state, safe to serialize and expose via API.
#[derive(Debug, Clone)]
pub struct ConnectionSnapshot {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    pub upload: u64,
    pub download: u64,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
}

/// Live per-connection entry, updated concurrently from the relay task.
pub struct ConnectionEntry {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    /// Byte counters are shared with the relay task, which increments them
    /// as data flows so `/connections` shows live (not close-time) totals.
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    pub start_time: Instant,
    pub domain: Option<String>,
    pub network: String,
}

impl ConnectionEntry {
    /// Create a read-only snapshot of the current entry state.
    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            source: self.source.clone(),
            destination: self.destination.clone(),
            proxy: self.proxy.clone(),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
            start_time: self.start_time,
            domain: self.domain.clone(),
            network: self.network.clone(),
        }
    }
}

/// Concurrent-safe tracking of all active connections.
///
/// Thread-safe by construction via [`DashMap`] — no external locks needed.
pub struct ConnectionTracker {
    entries: DashMap<String, ConnectionEntry>,
}

impl ConnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
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

    /// Return a point-in-time snapshot of all active connections.
    pub fn snapshot(&self) -> Vec<ConnectionSnapshot> {
        self.entries
            .iter()
            .map(|ref_multi| ref_multi.value().snapshot())
            .collect()
    }

    /// Return the current number of tracked connections.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if there are no tracked connections.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Force-remove a connection by ID (for admin-initiated close).
    pub fn close_connection(&self, id: &str) {
        self.entries.remove(id);
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: shared tracker reference used throughout the control plane.
pub type SharedTracker = Arc<ConnectionTracker>;
