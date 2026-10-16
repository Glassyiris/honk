//! BPF map janitor — background task that cleans up stale eBPF map entries.
//!
//! Mirrors Go's `startConnStateJanitor` from `daed/wing/dae-core/control/control_plane.go`.
//! The janitor runs on a configurable tick interval and performs periodic cleanup
//! of conn-state, redirect tracking, routing handoff, and immutable TCP request
//! proofs. Socket identity storage is reclaimed by the kernel with the socket,
//! never by this janitor.
//!
//! All swept maps are plain hashes: the kernel never evicts on its own
//! (silent LRU eviction could re-route or break live flows mid-flight), so
//! occupancy management lives here. Accepted TCP owners pin conn-state and
//! redirect metadata for their full relay lifetime; unpinned TCP ACTIVE and
//! UDP entries keep the 120-second userspace backstop, while TCP CLOSING uses
//! the datapath's strict 10-second rule. `CONN_STATE_OCCUPANCY` drives
//! conn-state pressure; auxiliary scans use their current completion and
//! coverage to accelerate cleanup when stale work or map occupancy warrants it:
//!
//! - `< 70%` full: steady sweep interval (60 s)
//! - `70–85%`: elevated interval (15 s)
//! - `>= 85%`: conn-state pressure mode — sweep every tick
//! - a bounded auxiliary scan or `>= 85%` current auxiliary coverage selects
//!   the aggressive auxiliary cadence

#[cfg(test)]
use super::connection::TcpFlowKey;
use super::connection::TcpFlowPins;
use crate::ebpf::{
    EbpfBackend, RETIRE_BATCH_CAPACITY, RetireCounts, RetireError, RetireKind, RetireRequest,
};
use honk_ebpf_common::TuplesKey;
use honk_ebpf_common::conn::{
    BpfStatsKey, ConnState, MAX_CONN_STATE_NUM, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState,
    UDP_CONN_STATE_TIMEOUT_NS, tcp_conn_state_expired,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, watch};
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

/// Conn-state sweep interval below the elevated watermark: 60 seconds.
const CONN_STATE_STEADY_INTERVAL_SECS: u64 = 60;
/// Conn-state sweep interval between the elevated and pressure watermarks.
const CONN_STATE_ELEVATED_INTERVAL_SECS: u64 = 15;
/// Occupancy fraction of CONN_STATE_MAP that shortens the sweep interval.
const CONN_STATE_ELEVATED_WATERMARK: f64 = 0.70;
/// Occupancy fraction that latches pressure mode (sweep every tick).
const CONN_STATE_PRESSURE_WATERMARK: f64 = 0.85;

/// Visit granularity for backends without `BPF_MAP_LOOKUP_BATCH`; the batch
/// path streams fixed-size kernel batches instead.
const JANITOR_SCAN_CHUNK: usize = 256;
const JANITOR_DELETE_CHUNK: usize = RETIRE_BATCH_CAPACITY;
const JANITOR_BASE_CANDIDATES: usize = 1024;
const JANITOR_MAX_CANDIDATES: usize = 4096;
const JANITOR_BASE_SCAN_BUDGET: Duration = Duration::from_millis(100);
const JANITOR_ELEVATED_SCAN_BUDGET: Duration = Duration::from_millis(150);
const JANITOR_PRESSURE_SCAN_BUDGET: Duration = Duration::from_millis(200);
const AUX_MAP_CAPACITY: usize = 65_536;
const AUX_MAP_PRESSURE_WATERMARK: f64 = 0.80;

/// Redirect track entry timeout: 120 seconds.
const REDIRECT_TRACK_TIMEOUT_NS: u64 = 120_000_000_000;
/// Routing handoff entry timeout: 30 seconds.
const ROUTING_HANDOFF_TIMEOUT_NS: u64 = 30_000_000_000;

/// Number of consecutive ticks without conn-state overflow after which
/// pressure mode is switched off.
const PRESSURE_EXIT_ROUNDS: u32 = 3;

/// TCP protocol number in `TuplesKey::l4proto`.
const IPPROTO_TCP: u8 = 6;

/// Live CONN_STATE_MAP occupancy estimate, derived from the datapath's
/// insert/delete counters plus the janitor's own delete accounting, and
/// recalibrated against the exact entry count on every sweep.
#[derive(Debug, Default)]
struct OccupancyGauge {
    /// Cumulative entries deleted by janitor sweeps.
    janitor_deletes: u64,
    /// `exact_count - raw_estimate` recorded at the last sweep, absorbing
    /// races (e.g. a datapath delete of an entry the janitor also removed).
    drift: i64,
}

impl OccupancyGauge {
    /// Raw counter-derived occupancy before drift correction.
    fn raw_estimate(&self, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> i64 {
        inserts as i64
            - ebpf_deletes as i64
            - self.janitor_deletes as i64
            - userspace_deletes as i64
    }

    fn estimate(&self, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) -> u64 {
        (self.raw_estimate(inserts, ebpf_deletes, userspace_deletes) + self.drift).max(0) as u64
    }

    /// Recalibrate with the exact entry count observed during a sweep.
    fn calibrate(&mut self, exact: u64, inserts: u64, ebpf_deletes: u64, userspace_deletes: u64) {
        self.drift = exact as i64 - self.raw_estimate(inserts, ebpf_deletes, userspace_deletes);
    }

    fn note_janitor_deletes(&mut self, n: u64) {
        self.janitor_deletes += n;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ScanTuning {
    candidates: usize,
    budget: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AuxScanResult {
    /// Number of entries removed after the bounded scan.
    deleted: u64,
    /// Entries visited; exact map cardinality only when `complete` is true.
    scanned: usize,
    /// False when the candidate or wall-clock bound stopped traversal.
    complete: bool,
}

fn aux_scan_is_pressured(scanned: usize, complete: bool) -> bool {
    !complete || scanned as f64 / AUX_MAP_CAPACITY as f64 >= CONN_STATE_PRESSURE_WATERMARK
}

fn scan_tuning(utilization: f64) -> ScanTuning {
    let (candidates, budget) = if utilization >= CONN_STATE_PRESSURE_WATERMARK {
        (JANITOR_MAX_CANDIDATES, JANITOR_PRESSURE_SCAN_BUDGET)
    } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
        (JANITOR_BASE_CANDIDATES * 2, JANITOR_ELEVATED_SCAN_BUDGET)
    } else {
        (JANITOR_BASE_CANDIDATES, JANITOR_BASE_SCAN_BUDGET)
    };
    ScanTuning { candidates, budget }
}

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
    tcp_flow_pins: Arc<TcpFlowPins>,
    #[cfg(test)]
    blocking_read_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    before_delete_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl BpfJanitor {
    /// Create a new janitor bound to the given eBPF backend.
    pub(super) fn new(
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        tcp_flow_pins: Arc<TcpFlowPins>,
    ) -> Self {
        Self {
            ebpf,
            tcp_flow_pins,
            #[cfg(test)]
            blocking_read_hook: None,
            #[cfg(test)]
            before_delete_hook: None,
        }
    }

    /// Spawn with a guard that reports unexpected task death to the control plane.
    pub(super) fn spawn_supervised(
        self,
        exit_guard: super::runtime::CriticalTaskExit,
        mut stop: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut exit_guard = exit_guard;
            let tick_duration = Duration::from_secs(JANITOR_TICK_INTERVAL_SECS);
            let mut interval = tokio::time::interval(tick_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Skip the first immediate tick.
            interval.tick().await;

            let mut pressure = PressureState::default();
            let mut gauge = OccupancyGauge::default();
            let mut aux_scan_results = [AuxScanResult {
                complete: true,
                ..AuxScanResult::default()
            }; 3];

            let mut last_aux_failures = [0u64; 3];
            let mut aux_pressure_warned = [false; 3];
            let mut pressure_warned = [false; 4];

            let mut last_redirect_cleanup = tokio::time::Instant::now();
            let mut last_routing_handoff = tokio::time::Instant::now();
            let mut last_health_check = tokio::time::Instant::now();
            let mut last_conn_state_cleanup = tokio::time::Instant::now();

            info!(
                "BPF janitor: started (tick={}s; conn-state sweep is watermark-driven)",
                JANITOR_TICK_INTERVAL_SECS
            );

            loop {
                // Never race a stop against an in-flight blocking scan or deletion.
                if *stop.borrow_and_update() {
                    exit_guard.expected_stop();
                    return;
                }
                tokio::select! {
                    biased;
                    changed = stop.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                    _ = interval.tick() => {}
                }

                let now = tokio::time::Instant::now();

                let (overflow_delta, utilization, occ_counters) = {
                    let ebpf = self.ebpf.read().await;
                    let udp = ebpf.get_bpf_stats(0).unwrap_or(None).unwrap_or(0);
                    let tcp = ebpf.get_bpf_stats(1).unwrap_or(None).unwrap_or(0);
                    let delta =
                        udp > pressure.last_udp_overflow || tcp > pressure.last_tcp_overflow;
                    pressure.last_udp_overflow = udp;
                    pressure.last_tcp_overflow = tcp;
                    let counters = ebpf.conn_state_occupancy().unwrap_or((0, 0));
                    let userspace_deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let occupancy = gauge.estimate(counters.0, counters.1, userspace_deletes);
                    (
                        delta,
                        occupancy as f64 / f64::from(MAX_CONN_STATE_NUM),
                        (counters, userspace_deletes),
                    )
                };
                update_pressure_state(&mut pressure, overflow_delta, utilization);

                let aux_pressure = aux_scan_results
                    .iter()
                    .any(|result| aux_scan_is_pressured(result.scanned, result.complete));
                let redirect_interval = if pressure.active || aux_pressure {
                    Duration::from_secs(REDIRECT_PRESSURE_INTERVAL_SECS)
                } else {
                    Duration::from_secs(REDIRECT_STEADY_INTERVAL_SECS)
                };
                let routing_interval = if pressure.active || aux_pressure {
                    Duration::from_secs(ROUTING_HANDOFF_PRESSURE_SECS)
                } else {
                    Duration::from_secs(ROUTING_HANDOFF_STEADY_SECS)
                };

                let conn_state_interval = if pressure.active {
                    Duration::from_secs(JANITOR_TICK_INTERVAL_SECS)
                } else if utilization >= CONN_STATE_ELEVATED_WATERMARK {
                    Duration::from_secs(CONN_STATE_ELEVATED_INTERVAL_SECS)
                } else {
                    Duration::from_secs(CONN_STATE_STEADY_INTERVAL_SECS)
                };

                if last_conn_state_cleanup + conn_state_interval <= now {
                    let tuning = scan_tuning(utilization);
                    let (deleted, total) = match self
                        .cleanup_conn_state(&mut gauge, occ_counters, tuning)
                        .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            error!(%error, "BPF janitor: conn-state retirement failed");
                            return;
                        }
                    };
                    last_conn_state_cleanup = now;
                    if utilization >= CONN_STATE_ELEVATED_WATERMARK || deleted > 0 {
                        debug!(
                            "BPF janitor: conn-state sweep removed {}/{} entries (occupancy ~{:.1}%)",
                            deleted,
                            total,
                            utilization * 100.0
                        );
                    }
                }
                let auxiliary_pressure_floor = if pressure.active || aux_pressure {
                    CONN_STATE_PRESSURE_WATERMARK
                } else {
                    0.0
                };

                if last_redirect_cleanup + redirect_interval <= now {
                    let utilization = (aux_scan_results[0].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    let tuning = scan_tuning(utilization);
                    aux_scan_results[0] =
                        match self.cleanup_redirect_track(tuning, &mut gauge).await {
                            Ok(result) => result,
                            Err(error) => {
                                error!(%error, "BPF janitor: redirect retirement failed");
                                return;
                            }
                        };
                    last_redirect_cleanup = now;
                }
                if last_routing_handoff + routing_interval <= now {
                    let utilization = (aux_scan_results[1].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    let tuning = scan_tuning(utilization);
                    aux_scan_results[1] =
                        match self.cleanup_routing_handoff(tuning, &mut gauge).await {
                            Ok(result) => result,
                            Err(error) => {
                                error!(%error, "BPF janitor: handoff retirement failed");
                                return;
                            }
                        };
                    let utilization = (aux_scan_results[2].scanned as f64
                        / AUX_MAP_CAPACITY as f64)
                        .max(auxiliary_pressure_floor);
                    aux_scan_results[2] = match self
                        .cleanup_tcp_requests(scan_tuning(utilization), &mut gauge)
                        .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            error!(%error, "BPF janitor: TCP request retirement failed");
                            return;
                        }
                    };
                    last_routing_handoff = now;
                }

                if last_health_check + Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS) <= now {
                    self.check_map_health(
                        utilization,
                        pressure.active,
                        aux_scan_results,
                        &mut last_aux_failures,
                        &mut aux_pressure_warned,
                        &mut pressure_warned,
                    )
                    .await;
                    last_health_check = now;
                }
            }
        })
    }
    async fn run_blocking_read<T, F>(&self, label: &'static str, work: F) -> Option<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn EbpfBackend) -> T + Send + 'static,
    {
        let ebpf = Arc::clone(&self.ebpf);
        #[cfg(test)]
        let blocking_read_hook = self.blocking_read_hook.clone();
        match tokio::task::spawn_blocking(move || {
            let ebpf = ebpf.blocking_read();
            #[cfg(test)]
            if let Some(hook) = blocking_read_hook {
                hook();
            }
            work(ebpf.as_ref())
        })
        .await
        {
            Ok(result) => Some(result),
            Err(error) => {
                error!(%error, map = label, "BPF janitor blocking read task failed");
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
                None
            }
        }
    }

    async fn run_blocking_chunked_delete<T, F>(
        &self,
        entries: Vec<T>,
        gauge: &mut OccupancyGauge,
        mut request: F,
    ) -> anyhow::Result<RetireCounts>
    where
        T: Send + 'static,
        F: for<'a> FnMut(&'a T) -> RetireRequest<'a> + Send + 'static,
    {
        let ebpf = Arc::clone(&self.ebpf);
        let pins = Arc::clone(&self.tcp_flow_pins);
        #[cfg(test)]
        let before_delete_hook = self.before_delete_hook.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut counts = RetireCounts::default();
            let mut requests = Vec::with_capacity(JANITOR_DELETE_CHUNK);
            let mut outcomes = [None; JANITOR_DELETE_CHUNK];
            #[cfg(test)]
            if let Some(hook) = before_delete_hook {
                hook();
            }
            // Release between batches so queued per-flow readers can proceed.
            for chunk in entries.chunks(JANITOR_DELETE_CHUNK) {
                let mut ebpf = ebpf.blocking_write();
                requests.clear();
                requests.extend(chunk.iter().map(&mut request).filter(|request| {
                    // Child socket storage owns its proof independently of request storage.
                    matches!(request.kind, RetireKind::ExpiredRequest { .. })
                        || request.key.l4proto != IPPROTO_TCP
                        || !pins.contains(&request.key)
                }));
                if requests.is_empty() {
                    continue;
                }
                let result = ebpf.retire_batch(&requests, &mut outcomes[..requests.len()]);
                let progress = match &result {
                    Ok(progress) => progress,
                    Err(error) => &error.counts,
                };
                counts.conn += progress.conn;
                counts.redirect += progress.redirect;
                counts.handoff += progress.handoff;
                counts.request += progress.request;
                if let Err(error) = result {
                    return Err(RetireError {
                        counts,
                        source: error.source,
                    });
                }
            }
            Ok(counts)
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => return Err(error.into()),
        };
        let counts = match &result {
            Ok(counts) => counts,
            Err(error) => &error.counts,
        };
        gauge.note_janitor_deletes(counts.conn);
        result.map_err(Into::into)
    }

    /// Clean up unowned conn-state entries with state-based timeouts (TCP
    /// closing: 10 s, TCP active: 120 s, UDP: 120 s). Current TCP pins are
    /// checked under the backend writer lock before retirement. Returns
    /// `(deleted, total_scanned)` and recalibrates only after a complete scan.
    async fn cleanup_conn_state(
        &self,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> anyhow::Result<(u64, usize)> {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                warn!(%error, "BPF janitor: failed to get monotonic time");
                return Ok((0, 0));
            }
        };
        self.cleanup_conn_state_at(now_ns, gauge, occ_counters, tuning)
            .await
    }

    async fn cleanup_conn_state_at(
        &self,
        now_ns: u64,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> anyhow::Result<(u64, usize)> {
        let scanned = self
            .run_blocking_read("conn-state", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::<(TuplesKey, ConnState)>::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut completed = true;
                ebpf.conn_state_for_each_chunk(JANITOR_SCAN_CHUNK, &mut |chunk| {
                    total += chunk.len();
                    for (key, state) in chunk {
                        let age = now_ns.saturating_sub(state.last_seen_ns);
                        let stale = if key.l4proto == IPPROTO_TCP {
                            tcp_conn_state_expired(state, age)
                                || (state.state != TcpState::TcpStateClosing as u8
                                    && age > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS)
                        } else {
                            age > UDP_CONN_STATE_TIMEOUT_NS
                        };
                        if stale {
                            expired.push((*key, *state));
                        }
                    }
                    let keep_scanning =
                        expired.len() < tuning.candidates && Instant::now() < deadline;
                    completed &= keep_scanning;
                    keep_scanning
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, completed))
            })
            .await;
        let Some(scanned) = scanned else {
            return Ok((0, 0));
        };
        let (expired, total, completed) = match scanned {
            Ok(result) => result,
            Err(error) => {
                debug!(%error, "BPF janitor: conn-state scan failed");
                return Ok((0, 0));
            }
        };
        if completed {
            let ((inserts, ebpf_deletes), userspace_deletes) = occ_counters;
            gauge.calibrate(total as u64, inserts, ebpf_deletes, userspace_deletes);
        }
        let deleted = if expired.is_empty() {
            0
        } else {
            self.run_blocking_chunked_delete(expired, gauge, move |(key, expected)| {
                let timeout = if key.l4proto != IPPROTO_TCP {
                    UDP_CONN_STATE_TIMEOUT_NS
                } else if expected.state == TcpState::TcpStateClosing as u8 {
                    honk_ebpf_common::conn::TCP_CONN_STATE_CLOSING_TIMEOUT_NS
                } else {
                    TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
                };
                RetireRequest {
                    key: *key,
                    kind: RetireKind::ExpiredConn {
                        expected,
                        expired_before_ns: now_ns.saturating_sub(timeout),
                    },
                }
            })
            .await?
            .conn
        };
        Ok((deleted, total))
    }

    #[cfg(test)]
    pub(super) async fn cleanup_conn_state_for_test(&self, now_ns: u64) -> (u64, usize) {
        let mut gauge = OccupancyGauge::default();
        self.cleanup_conn_state_at(
            now_ns,
            &mut gauge,
            ((0, 0), 0),
            ScanTuning {
                candidates: JANITOR_MAX_CANDIDATES,
                budget: Duration::from_secs(1),
            },
        )
        .await
        .expect("conn-state retirement succeeds")
    }

    /// Clean up stale redirect track entries.
    async fn cleanup_redirect_track(
        &self,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                warn!(%error, "BPF janitor: failed to get monotonic time");
                return Ok(AuxScanResult::default());
            }
        };
        self.cleanup_redirect_track_at(now_ns, tuning, gauge).await
    }

    async fn cleanup_redirect_track_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let scanned = self
            .run_blocking_read("redirect-track", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.redirect_track_for_each_chunk(JANITOR_SCAN_CHUNK, &mut |chunk| {
                    total += chunk.len();
                    for (key, entry) in chunk {
                        if now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS {
                            expired.push((
                                TuplesKey {
                                    src_ip: key.src_ip,
                                    dst_ip: key.dst_ip,
                                    src_port: key.src_port,
                                    dst_port: key.dst_port,
                                    l4proto: key.l4proto,
                                    padding: [0; 3],
                                },
                                *entry,
                            ));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: redirect-track scan failed");
                return Ok(AuxScanResult::default());
            }
            None => return Ok(AuxScanResult::default()),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            self.run_blocking_chunked_delete(expired, gauge, move |(key, expected)| RetireRequest {
                key: *key,
                kind: RetireKind::ExpiredRedirect {
                    expected,
                    expired_before_ns: now_ns.saturating_sub(REDIRECT_TRACK_TIMEOUT_NS),
                },
            })
            .await?
            .redirect
        };
        if deleted > 0 {
            debug!(deleted, "BPF janitor: removed redirect track entries");
        }
        Ok(AuxScanResult {
            deleted,
            scanned: total,
            complete,
        })
    }

    #[cfg(test)]
    pub(super) async fn cleanup_redirect_track_for_test(&self, now_ns: u64) -> (u64, usize) {
        let result = self
            .cleanup_redirect_track_at(
                now_ns,
                ScanTuning {
                    candidates: JANITOR_MAX_CANDIDATES,
                    budget: Duration::from_secs(1),
                },
                &mut OccupancyGauge::default(),
            )
            .await
            .expect("redirect retirement succeeds");
        (result.deleted, result.scanned)
    }

    /// Clean up expired routing handoff entries.
    async fn cleanup_routing_handoff(
        &self,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let now_ns = match monotonic_now_ns() {
            Ok(ns) => ns,
            Err(error) => {
                warn!(%error, "BPF janitor: failed to get monotonic time");
                return Ok(AuxScanResult::default());
            }
        };
        let scanned = self
            .run_blocking_read("routing-handoff", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.routing_handoff_for_each_chunk(JANITOR_SCAN_CHUNK, &mut |chunk| {
                    total += chunk.len();
                    for (key, entry) in chunk {
                        if now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS {
                            expired.push((*key, *entry));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: routing-handoff scan failed");
                return Ok(AuxScanResult::default());
            }
            None => return Ok(AuxScanResult::default()),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            self.run_blocking_chunked_delete(expired, gauge, move |(key, expected)| RetireRequest {
                key: *key,
                kind: RetireKind::ExpiredHandoff {
                    expected,
                    expired_before_ns: now_ns.saturating_sub(ROUTING_HANDOFF_TIMEOUT_NS),
                },
            })
            .await?
            .handoff
        };
        if deleted > 0 {
            debug!(deleted, "BPF janitor: removed routing handoff entries");
        }
        Ok(AuxScanResult {
            deleted,
            scanned: total,
            complete,
        })
    }

    async fn cleanup_tcp_requests(
        &self,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let now_ns = match monotonic_now_ns() {
            Ok(now_ns) => now_ns,
            Err(error) => {
                warn!(%error, "BPF janitor: failed to get monotonic time");
                return Ok(AuxScanResult::default());
            }
        };
        self.cleanup_tcp_requests_at(now_ns, tuning, gauge).await
    }

    async fn cleanup_tcp_requests_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let scanned = self
            .run_blocking_read("tcp-request-bindings", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.tcp_request_for_each_chunk(JANITOR_SCAN_CHUNK, &mut |chunk| {
                    total += chunk.len();
                    for (key, binding) in chunk {
                        if now_ns.saturating_sub(binding.handoff.last_seen_ns)
                            > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
                        {
                            expired.push((*key, *binding));
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                expired.truncate(tuning.candidates);
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, "BPF janitor: TCP request scan failed");
                return Ok(AuxScanResult::default());
            }
            None => return Ok(AuxScanResult::default()),
        };
        let deleted = if expired.is_empty() {
            0
        } else {
            self.run_blocking_chunked_delete(expired, gauge, move |(request, expected)| {
                RetireRequest {
                    key: expected.tuples,
                    kind: RetireKind::ExpiredRequest {
                        request,
                        expected,
                        expired_before_ns: now_ns
                            .saturating_sub(TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS),
                    },
                }
            })
            .await?
            .request
        };
        Ok(AuxScanResult {
            deleted,
            scanned: total,
            complete,
        })
    }

    /// Check BPF map health — overflow counter warnings plus conn-state
    /// occupancy watermark warnings.
    async fn check_map_health(
        &self,
        utilization: f64,
        pressure_active: bool,
        aux_scans: [AuxScanResult; 3],
        last_aux_failures: &mut [u64; 3],
        aux_pressure_warned: &mut [bool; 3],
        pressure_warned: &mut [bool; 4],
    ) {
        let ebpf = self.ebpf.read().await;
        let stat = |key: BpfStatsKey| ebpf.get_bpf_stats(key as u32).unwrap_or(None).unwrap_or(0);
        let udp_overflow = stat(BpfStatsKey::UdpConnOverflow);
        let tcp_overflow = stat(BpfStatsKey::TcpConnOverflow);
        let redirect_failures = stat(BpfStatsKey::RedirectTrackInsertFailure);
        let handoff_failures = stat(BpfStatsKey::RoutingHandoffInsertFailure);
        let identity_failures = stat(BpfStatsKey::SocketIdentityCaptureFailure);
        drop(ebpf);

        // The overflow counters are cumulative and this runs every few
        // seconds: warn once per pressure episode, repeats stay at DEBUG.
        if !pressure_active {
            *pressure_warned = [false; 4];
        }
        let mut first_in_episode =
            |index: usize| pressure_active && !std::mem::replace(&mut pressure_warned[index], true);

        if udp_overflow > 0 || tcp_overflow > 0 {
            crate::logging::warn_on_entry!(
                first_in_episode(0),
                "BPF janitor: map overflow detected — UDP={}, TCP={}. \
                 Some packets may be falling back to slower paths. \
                 Consider increasing map capacity.",
                udp_overflow,
                tcp_overflow
            );
        }
        let aux_failures = [redirect_failures, handoff_failures, identity_failures];
        if aux_failures[..2]
            .iter()
            .zip(last_aux_failures[..2].iter())
            .any(|(current, previous)| current > previous)
        {
            warn!(
                redirect_failures,
                handoff_failures, "BPF janitor: auxiliary map insert failures increased"
            );
        }
        if identity_failures > last_aux_failures[2] {
            warn!(
                identity_failures,
                "BPF janitor: socket identity capture failures increased; socket operations were denied"
            );
        }
        *last_aux_failures = aux_failures;

        for (index, (map, scan)) in [
            ("redirect-track", aux_scans[0]),
            ("routing-handoff", aux_scans[1]),
            ("tcp-request-bindings", aux_scans[2]),
        ]
        .into_iter()
        .enumerate()
        {
            let entries = scan.scanned;
            let utilization = entries as f64 / AUX_MAP_CAPACITY as f64;
            if utilization >= AUX_MAP_PRESSURE_WATERMARK {
                if !aux_pressure_warned[index] {
                    warn!(
                        map,
                        entries,
                        capacity = AUX_MAP_CAPACITY,
                        utilization_pct = utilization * 100.0,
                        "BPF janitor: auxiliary map scan high-water indicates pressure"
                    );
                    aux_pressure_warned[index] = true;
                }
            } else if scan.complete {
                // A bounded scan is only a lower bound; a complete one proves
                // the map left pressure.
                aux_pressure_warned[index] = false;
            }
        }

        if udp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(1),
                "BPF janitor: UDP conn state map under heavy pressure (overflow={}). \
                 Consider increasing udp_conn_state_map capacity or reducing UDP connection timeout.",
                udp_overflow
            );
        }
        if tcp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(2),
                "BPF janitor: TCP conn state map under heavy pressure (overflow={}). \
                 Consider increasing tcp_conn_state_map capacity or reducing TCP connection timeout.",
                tcp_overflow
            );
        }

        if utilization >= CONN_STATE_PRESSURE_WATERMARK {
            crate::logging::warn_on_entry!(
                first_in_episode(3),
                "BPF janitor: conn-state map occupancy ~{:.1}% — sweeping every tick; \
                 consider increasing MAX_CONN_STATE_NUM if this persists",
                utilization * 100.0
            );
        }
    }
}

/// Get the current monotonic time in nanoseconds (CLOCK_MONOTONIC).
///
/// Uses `nix::time::clock_gettime` for cross-platform monotonic time access.
/// This matches `bpf_ktime_get_ns()` which also uses CLOCK_MONOTONIC on Linux.
pub(super) fn monotonic_now_ns() -> anyhow::Result<u64> {
    let ts = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
    Ok(ts.tv_sec() as u64 * 1_000_000_000 + ts.tv_nsec() as u64)
}

/// Update the pressure state from the conn-state overflow counters and the
/// live occupancy watermark.
///
/// Pressure mode latches on when either the kernel's UDP/TCP overflow
/// counters grow (insert failures — the fail-closed last resort) or the
/// estimated occupancy crosses `CONN_STATE_PRESSURE_WATERMARK`.  It switches
/// off after `PRESSURE_EXIT_ROUNDS` consecutive ticks with neither signal.
fn update_pressure_state(state: &mut PressureState, overflow_delta: bool, utilization: f64) {
    let high_water = utilization >= CONN_STATE_PRESSURE_WATERMARK;
    if overflow_delta || high_water {
        if !state.active {
            if overflow_delta {
                warn!("BPF janitor: entering pressure mode (conn state overflow)");
            } else {
                warn!(
                    "BPF janitor: entering pressure mode (conn-state occupancy ~{:.1}%)",
                    utilization * 100.0
                );
            }
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
            "BPF janitor: exiting pressure mode (quiet for {} rounds)",
            PRESSURE_EXIT_ROUNDS
        );
    }
}

#[cfg(test)]
mod tests;
