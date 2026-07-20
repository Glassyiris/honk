//! BPF map janitor — background task that cleans up stale eBPF map entries.
//!
//! Mirrors Go's `startConnStateJanitor` from `daed/wing/dae-core/control/control_plane.go`.
//! The janitor runs on a configurable tick interval and performs periodic cleanup
//! of redirect tracking, cookie PID metadata, and routing handoff entries.
//!
//! CONN_STATE_MAP is deliberately *not* scanned from userspace: the eBPF
//! datapath expires entries lazily on every hit (`contrack.rs`), and the map
//! is an LRU hash that evicts the oldest entries when full, so cold entries
//! only cost memory.  Pressure mode is therefore purely overflow-driven:
//! any growth in the kernel's UDP/TCP overflow counters latches it on, and
//! it switches off after a few ticks without new overflow.

use crate::ebpf::EbpfBackend;
use honk_ebpf_common::{RedirectTuple, TuplesKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Janitor tick interval: 2 seconds.
const JANITOR_TICK_INTERVAL_SECS: u64 = 2;
/// Normal-mode redirect-track scan interval: 60 seconds.
const REDIRECT_STEADY_INTERVAL_SECS: u64 = 60;
/// Aggressive-mode redirect-track scan interval: 8 seconds.
const REDIRECT_PRESSURE_INTERVAL_SECS: u64 = 8;
/// Normal-mode routing-handoff scan interval: 60 seconds.
const ROUTING_HANDOFF_STEADY_SECS: u64 = 60;
/// Aggressive-mode routing-handoff scan interval: 8 seconds.
const ROUTING_HANDOFF_PRESSURE_SECS: u64 = 8;
/// Map health check interval: 5 seconds.
const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

/// Redirect track entry timeout: 120 seconds.
const REDIRECT_TRACK_TIMEOUT_NS: u64 = 120_000_000_000;
/// Cookie PID entry timeout: 600 seconds.
const COOKIE_PID_TIMEOUT_NS: u64 = 600_000_000_000;
/// Routing handoff entry timeout: 30 seconds.
const ROUTING_HANDOFF_TIMEOUT_NS: u64 = 30_000_000_000;

/// Number of consecutive ticks without conn-state overflow after which
/// pressure mode is switched off.
const PRESSURE_EXIT_ROUNDS: u32 = 3;

/// Tracks the pressure state of the BPF maps for adaptive cleanup intervals.
#[derive(Debug, Clone, Default)]
struct PressureState {
    /// Whether pressure mode is active (shorter scan intervals).
    active: bool,
    /// Consecutive ticks without new conn-state overflow while active.
    quiet_rounds: u32,
    /// Last observed UDP overflow counter value.
    last_udp_overflow: u64,
    /// Last observed TCP overflow counter value.
    last_tcp_overflow: u64,
}

/// The BPF map janitor.
///
/// Runs background cleanup of stale eBPF map entries to prevent map overflow
/// and memory pressure. The janitor adapts its behaviour based on map pressure.
pub struct BpfJanitor {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    stop_tx: tokio::sync::watch::Sender<bool>,
}

impl BpfJanitor {
    /// Create a new janitor bound to the given eBPF backend.
    pub fn new(ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>) -> Self {
        let (stop_tx, _) = tokio::sync::watch::channel(false);
        Self { ebpf, stop_tx }
    }

    /// Return a receiver that fires when `stop()` is called.
    pub fn stop_handle(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop_tx.subscribe()
    }

    /// Signal the janitor to stop.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }

    /// Spawn the janitor on a tokio task.
    ///
    /// Returns a `JoinHandle` that completes when the janitor exits.
    /// The janitor runs until `stop()` is called or the stop receiver is dropped.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        let mut stop_rx = self.stop_tx.subscribe();

        tokio::spawn(async move {
            let tick_duration = Duration::from_secs(JANITOR_TICK_INTERVAL_SECS);
            let mut interval = tokio::time::interval(tick_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first immediate tick.
            interval.tick().await;

            let mut pressure = PressureState::default();

            let mut last_redirect_cleanup = tokio::time::Instant::now();
            let mut last_cookie_pid_cleanup = tokio::time::Instant::now();
            let mut last_routing_handoff = tokio::time::Instant::now();
            let mut last_health_check = tokio::time::Instant::now();

            info!(
                "BPF janitor: started (tick={}s; conn state expiry is kernel-side, pressure is overflow-driven)",
                JANITOR_TICK_INTERVAL_SECS
            );

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = stop_rx.changed() => {
                        info!("BPF janitor: received stop signal, exiting");
                        return;
                    }
                }

                if *stop_rx.borrow() {
                    info!("BPF janitor: stopping");
                    return;
                }

                let now = tokio::time::Instant::now();

                let overflow_delta = {
                    let ebpf = self.ebpf.read().await;
                    let udp = ebpf.get_bpf_stats(0).unwrap_or(None).unwrap_or(0);
                    let tcp = ebpf.get_bpf_stats(1).unwrap_or(None).unwrap_or(0);
                    let delta =
                        udp > pressure.last_udp_overflow || tcp > pressure.last_tcp_overflow;
                    pressure.last_udp_overflow = udp;
                    pressure.last_tcp_overflow = tcp;
                    delta
                };
                update_pressure_state(&mut pressure, overflow_delta);

                let redirect_interval = if pressure.active {
                    Duration::from_secs(REDIRECT_PRESSURE_INTERVAL_SECS)
                } else {
                    Duration::from_secs(REDIRECT_STEADY_INTERVAL_SECS)
                };
                let routing_interval = if pressure.active {
                    Duration::from_secs(ROUTING_HANDOFF_PRESSURE_SECS)
                } else {
                    Duration::from_secs(ROUTING_HANDOFF_STEADY_SECS)
                };

                if last_redirect_cleanup + redirect_interval <= now {
                    self.cleanup_redirect_track().await;
                    last_redirect_cleanup = now;
                }
                if last_cookie_pid_cleanup + redirect_interval <= now {
                    self.cleanup_cookie_pid().await;
                    last_cookie_pid_cleanup = now;
                }

                if last_routing_handoff + routing_interval <= now {
                    self.cleanup_routing_handoff().await;
                    last_routing_handoff = now;
                }

                if last_health_check + Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS) <= now {
                    self.check_map_health().await;
                    last_health_check = now;
                }
            }
        })
    }

    /// Clean up stale redirect track entries.
    async fn cleanup_redirect_track(&self) -> u64 {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(e) => {
                error!("BPF janitor: failed to get monotonic time: {}", e);
                return 0;
            }
        };

        // Batched snapshot under a read lock (one syscall per 128 entries on
        // capable kernels); the expiry predicate runs in memory afterwards.
        let mut entries = Vec::new();
        {
            let ebpf = self.ebpf.read().await;
            if ebpf.redirect_track_snapshot(&mut entries).is_err() {
                return 0;
            }
        }

        let expired: Vec<RedirectTuple> = entries
            .iter()
            .filter(|(_, entry)| {
                now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS
            })
            .map(|(key, _)| *key)
            .collect();

        if !expired.is_empty() {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.redirect_track_remove_batch(&expired) {
                debug!("BPF janitor: failed to batch-remove redirect track: {}", e);
            }
        }

        let deleted = expired.len();
        if deleted > 0 {
            debug!(
                "BPF janitor: removed {} redirect track entries (total scanned: {})",
                deleted,
                entries.len()
            );
        }
        deleted as u64
    }

    /// Clean up stale cookie PID metadata entries.
    ///
    /// Entries whose `last_seen_ns` is older than `COOKIE_PID_TIMEOUT_NS`
    /// are evicted, matching Go's `cleanupCookiePidMap` behaviour.
    async fn cleanup_cookie_pid(&self) -> u64 {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(e) => {
                error!("BPF janitor: failed to get monotonic time: {}", e);
                return 0;
            }
        };

        let mut entries = Vec::new();
        {
            let ebpf = self.ebpf.read().await;
            if ebpf.cookie_pid_snapshot(&mut entries).is_err() {
                return 0;
            }
        }

        let expired: Vec<u64> = entries
            .iter()
            .filter(|(_, entry)| now_ns.saturating_sub(entry.last_seen_ns) > COOKIE_PID_TIMEOUT_NS)
            .map(|(cookie, _)| *cookie)
            .collect();

        if !expired.is_empty() {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.cookie_pid_remove_batch(&expired) {
                debug!(
                    "BPF janitor: failed to batch-remove cookie PID entries: {}",
                    e
                );
            }
        }

        let deleted = expired.len();
        if deleted > 0 {
            debug!(
                "BPF janitor: removed {} cookie PID entries (total scanned: {})",
                deleted,
                entries.len()
            );
        }
        deleted as u64
    }

    /// Clean up expired routing handoff entries.
    ///
    /// The handoff map is a short-lived bridge for userspace consumers that
    /// miss the authoritative conn-state publication window.
    async fn cleanup_routing_handoff(&self) -> u64 {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(e) => {
                error!("BPF janitor: failed to get monotonic time: {}", e);
                return 0;
            }
        };

        let mut entries = Vec::new();
        {
            let ebpf = self.ebpf.read().await;
            if ebpf.routing_handoff_snapshot(&mut entries).is_err() {
                return 0;
            }
        }

        let expired: Vec<TuplesKey> = entries
            .iter()
            .filter(|(_, entry)| {
                now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS
            })
            .map(|(key, _)| *key)
            .collect();

        if !expired.is_empty() {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = ebpf.routing_handoff_remove_batch(&expired) {
                debug!("BPF janitor: failed to batch-remove routing handoff: {}", e);
            }
        }

        let deleted = expired.len();
        if deleted > 0 {
            debug!(
                "BPF janitor: removed {} routing handoff entries (total scanned: {})",
                deleted,
                entries.len()
            );
        }
        deleted as u64
    }

    /// Check BPF map health — overflow counter warnings.
    async fn check_map_health(&self) {
        let ebpf = self.ebpf.read().await;
        let udp_overflow = ebpf.get_bpf_stats(0).unwrap_or(None).unwrap_or(0);
        let tcp_overflow = ebpf.get_bpf_stats(1).unwrap_or(None).unwrap_or(0);
        drop(ebpf);

        if udp_overflow > 0 || tcp_overflow > 0 {
            warn!(
                "BPF janitor: map overflow detected — UDP={}, TCP={}. \
                 Some packets may be falling back to slower paths. \
                 Consider increasing map capacity.",
                udp_overflow, tcp_overflow
            );
        }

        if udp_overflow > 100 {
            error!(
                "BPF janitor: CRITICAL — UDP conn state map under heavy pressure (overflow={}). \
                 Consider increasing udp_conn_state_map capacity or reducing UDP connection timeout.",
                udp_overflow
            );
        }
        if tcp_overflow > 100 {
            error!(
                "BPF janitor: CRITICAL — TCP conn state map under heavy pressure (overflow={}). \
                 Consider increasing tcp_conn_state_map capacity or reducing TCP connection timeout.",
                tcp_overflow
            );
        }
    }
}

/// Get the current monotonic time in nanoseconds (CLOCK_MONOTONIC).
///
/// Uses `nix::time::clock_gettime` for cross-platform monotonic time access.
/// This matches `bpf_ktime_get_ns()` which also uses CLOCK_MONOTONIC on Linux.
fn monotonic_now_ns() -> anyhow::Result<u64> {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
    Ok(ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64)
}

/// Update the pressure state from the conn-state overflow counters.
///
/// Pressure mode is purely overflow-driven: any growth in the kernel's
/// UDP/TCP overflow counters latches it on, and it switches off after
/// `PRESSURE_EXIT_ROUNDS` consecutive ticks without new overflow.  Map
/// usage is no longer sampled — CONN_STATE_MAP is an LRU hash with
/// kernel-side lazy expiry, so its occupancy is self-managing.
fn update_pressure_state(state: &mut PressureState, overflow_delta: bool) {
    if overflow_delta {
        if !state.active {
            info!("BPF janitor: entering pressure mode (conn state overflow)");
        }
        state.active = true;
        state.quiet_rounds = 0;
        return;
    }
    if !state.active {
        return;
    }
    state.quiet_rounds += 1;
    if state.quiet_rounds >= PRESSURE_EXIT_ROUNDS {
        state.active = false;
        state.quiet_rounds = 0;
        info!(
            "BPF janitor: exiting pressure mode (no overflow for {} rounds)",
            PRESSURE_EXIT_ROUNDS
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pressure_state_enter_on_overflow_delta() {
        let mut state = PressureState::default();
        assert!(!state.active);

        update_pressure_state(&mut state, true);
        assert!(state.active);
        assert_eq!(state.quiet_rounds, 0);
    }

    #[test]
    fn test_pressure_state_exit_after_quiet_rounds() {
        let mut state = PressureState {
            active: true,
            quiet_rounds: 0,
            last_udp_overflow: 0,
            last_tcp_overflow: 0,
        };

        // No overflow for PRESSURE_EXIT_ROUNDS consecutive ticks → exit.
        for _ in 0..PRESSURE_EXIT_ROUNDS {
            assert!(state.active);
            update_pressure_state(&mut state, false);
        }
        assert!(!state.active);
    }

    #[test]
    fn test_pressure_state_overflow_resets_quiet_counter() {
        let mut state = PressureState {
            active: true,
            quiet_rounds: 2,
            last_udp_overflow: 0,
            last_tcp_overflow: 0,
        };

        // A new overflow restarts the quiet-period countdown.
        update_pressure_state(&mut state, true);
        assert!(state.active);
        assert_eq!(state.quiet_rounds, 0);

        // And it still takes the full run of quiet ticks to exit.
        for _ in 0..PRESSURE_EXIT_ROUNDS - 1 {
            update_pressure_state(&mut state, false);
            assert!(state.active);
        }
        update_pressure_state(&mut state, false);
        assert!(!state.active);
    }

    #[test]
    fn test_pressure_state_inactive_stays_inactive_without_overflow() {
        let mut state = PressureState::default();
        for _ in 0..10 {
            update_pressure_state(&mut state, false);
            assert!(!state.active);
        }
    }

    #[test]
    fn test_monotonic_now_ns_returns_value() {
        let ns = monotonic_now_ns().expect("monotonic time should be available");
        assert!(ns > 0, "monotonic time should be positive, got {}", ns);
    }
}
