//! Per-connection state tracker for HTTP APIs and interrupting groups.
//!
//! Uses [`DashMap`] for concurrent-safe access from multiple tokio tasks
//! (accept loop, relay workers, and HTTP API handlers).

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
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
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe at registration time; None when the pid is unknown
    /// or the process already exited.
    pub process_path: Option<String>,
}

/// Live per-connection entry, updated concurrently from the relay task.
pub struct ConnectionEntry {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub proxy: String,
    #[cfg(feature = "native-api")]
    pub routed_outbound: Option<String>,
    #[cfg(feature = "native-api")]
    pub native_flow_id: Option<String>,
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
    /// Originating process name for locally-generated flows (cgroup cookie
    /// attribution); None for LAN-forwarded traffic.
    pub process: Option<String>,
    /// /proc/<pid>/exe resolved at registration; None when the pid is
    /// unknown or the process already exited.
    pub process_path: Option<String>,
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
            process: self.process.clone(),
            process_path: self.process_path.clone(),
        }
    }
}

/// Concurrent-safe tracking of all active connections.
///
/// Thread-safe by construction via [`DashMap`] — no external locks needed.
pub struct ConnectionTracker {
    entries: DashMap<String, ConnectionEntry>,
    consumers: AtomicU8,
    consumer_transition: parking_lot::Mutex<()>,
}

const API_CONSUMER: u8 = 1;
const INTERRUPT_CONSUMER: u8 = 2;
#[cfg(feature = "native-api")]
const NATIVE_CONSUMER: u8 = 4;

impl ConnectionTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            consumers: AtomicU8::new(0),
            consumer_transition: parking_lot::Mutex::new(()),
        }
    }

    /// Enable tracking for the Clash API.
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn enable(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers.fetch_or(API_CONSUMER, Ordering::AcqRel);
    }

    /// Enable tracking for interrupting group selections.
    pub(crate) fn enable_for_interrupts(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers
            .fetch_or(INTERRUPT_CONSUMER, Ordering::AcqRel);
    }

    /// Stop API-only tracking after its server terminates.
    #[cfg(any(feature = "clash-api", test))]
    pub(crate) fn disable_api(&self) {
        let _transition = self.consumer_transition.lock();
        let previous = self.consumers.fetch_and(!API_CONSUMER, Ordering::AcqRel);
        if previous & !API_CONSUMER == 0 {
            self.entries.clear();
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.consumers.load(Ordering::Acquire) != 0
    }

    pub(crate) fn needs_rule_details(&self) -> bool {
        self.consumers.load(Ordering::Acquire) & (API_CONSUMER | INTERRUPT_CONSUMER) != 0
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn enable_native(&self) {
        let _transition = self.consumer_transition.lock();
        self.consumers.fetch_or(NATIVE_CONSUMER, Ordering::AcqRel);
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn disable_native(&self) {
        let _transition = self.consumer_transition.lock();
        let previous = self.consumers.fetch_and(!NATIVE_CONSUMER, Ordering::AcqRel);
        if previous & !NATIVE_CONSUMER == 0 {
            self.entries.clear();
        }
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn native_enabled(&self) -> bool {
        self.consumers.load(Ordering::Acquire) & NATIVE_CONSUMER != 0
    }

    /// The visitor must not re-enter the tracker or acquire control-plane locks.
    #[cfg(feature = "native-api")]
    pub(crate) fn visit(&self, mut visitor: impl FnMut(&ConnectionEntry)) {
        for entry in &self.entries {
            visitor(entry.value());
        }
    }

    pub(crate) fn register_if_enabled(
        &self,
        make_entry: impl FnOnce() -> ConnectionEntry,
    ) -> Option<String> {
        self.is_enabled().then(|| self.register(make_entry()))
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

    /// Attach process metadata after registration. A missing entry means the
    /// flow closed before the blocking `/proc` lookup completed.
    pub fn update_process_path(&self, id: &str, process_path: String) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.process_path = Some(process_path);
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
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionTracker;

    #[test]
    fn interrupt_consumer_survives_api_shutdown() {
        let tracker = ConnectionTracker::new();
        tracker.enable();
        tracker.enable_for_interrupts();
        tracker.disable_api();
        assert!(tracker.is_enabled());
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_consumer_preserves_other_observers() {
        let tracker = ConnectionTracker::new();
        tracker.enable_native();
        assert!(!tracker.needs_rule_details());
        tracker.enable();
        tracker.disable_native();
        assert!(tracker.is_enabled());
        assert!(tracker.needs_rule_details());
        tracker.enable_native();
        tracker.disable_api();
        assert!(tracker.native_enabled());
        assert!(!tracker.needs_rule_details());
        tracker.enable_for_interrupts();
        tracker.disable_native();
        assert!(tracker.needs_rule_details());
    }

    #[cfg(feature = "native-api")]
    #[test]
    fn native_enable_cannot_overtake_last_consumer_clear() {
        use super::*;
        fn entry(id: &str) -> ConnectionEntry {
            ConnectionEntry {
                id: id.into(),
                source: "127.0.0.1:1".into(),
                destination: "127.0.0.1:2".into(),
                proxy: "direct".into(),
                routed_outbound: Some("direct".into()),
                native_flow_id: None,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                upload: Arc::new(AtomicU64::new(0)),
                download: Arc::new(AtomicU64::new(0)),
                start_time: Instant::now(),
                domain: None,
                network: "tcp".into(),
                process: None,
                process_path: None,
            }
        }
        let tracker = Arc::new(ConnectionTracker::new());
        tracker.enable();
        tracker.register(entry("old"));
        let old = tracker.entries.get("old").unwrap();
        let disabling = Arc::clone(&tracker);
        let disabled = std::thread::spawn(move || disabling.disable_api());
        let deadline = Instant::now() + std::time::Duration::from_secs(2);
        while tracker.is_enabled() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(tracker.consumer_transition.try_lock().is_none());
        let enabling = Arc::clone(&tracker);
        let enabled = std::thread::spawn(move || {
            enabling.enable_native();
            enabling.register(entry("new"));
        });
        drop(old);
        disabled.join().unwrap();
        enabled.join().unwrap();
        assert!(tracker.native_enabled());
        assert_eq!(
            tracker
                .snapshot()
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["new"]
        );
    }
}
