//! Bounded map scans and fenced retirement, separate from janitor scheduling.

use super::{
    AuxScanResult, BpfJanitor, IPPROTO_TCP, JANITOR_DELETE_CHUNK, JANITOR_SCAN_CHUNK,
    OccupancyGauge, REDIRECT_TRACK_TIMEOUT_NS, ROUTING_HANDOFF_TIMEOUT_NS, ScanTuning,
    monotonic_now_ns,
};
use crate::ebpf::{EbpfBackend, RetireCounts, RetireError, RetireKind, RetireRequest};
use honk_ebpf_common::TuplesKey;
use honk_ebpf_common::conn::{
    ConnState, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState, UDP_CONN_STATE_TIMEOUT_NS,
    tcp_conn_state_expired,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, warn};

impl BpfJanitor {
    pub(super) async fn run_blocking_read<T, F>(&self, label: &'static str, work: F) -> Option<T>
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
    /// closing: 10 s, TCP active: 120 s). Current TCP pins are excluded before
    /// candidate budgeting, then rechecked under the backend writer lock.
    /// Returns `(deleted, total_scanned)` and recalibrates only after a complete scan.
    pub(super) async fn cleanup_conn_state(
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

    pub(super) async fn cleanup_conn_state_at(
        &self,
        now_ns: u64,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> anyhow::Result<(u64, usize)> {
        let pins = Arc::clone(&self.tcp_flow_pins);
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
                            state.state == honk_ebpf_common::UdpDecisionState::Aborted as u8
                                || age > UDP_CONN_STATE_TIMEOUT_NS
                        };
                        if stale && (key.l4proto != IPPROTO_TCP || !pins.contains(key)) {
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
                    if expected.state == honk_ebpf_common::UdpDecisionState::Aborted as u8 {
                        0
                    } else {
                        UDP_CONN_STATE_TIMEOUT_NS
                    }
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

    /// Clean up stale redirect track entries.
    pub(super) async fn cleanup_redirect_track(
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

    pub(super) async fn cleanup_redirect_track_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let pins = Arc::clone(&self.tcp_flow_pins);
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
                            let key = TuplesKey {
                                src_ip: key.src_ip,
                                dst_ip: key.dst_ip,
                                src_port: key.src_port,
                                dst_port: key.dst_port,
                                l4proto: key.l4proto,
                                padding: [0; 3],
                            };
                            if key.l4proto != IPPROTO_TCP || !pins.contains(&key) {
                                expired.push((key, *entry));
                            }
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

    /// Clean up expired routing handoff entries.
    pub(super) async fn cleanup_routing_handoff(
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
        self.cleanup_routing_handoff_at(now_ns, tuning, gauge).await
    }

    pub(super) async fn cleanup_routing_handoff_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
        gauge: &mut OccupancyGauge,
    ) -> anyhow::Result<AuxScanResult> {
        let pins = Arc::clone(&self.tcp_flow_pins);
        let scanned = self
            .run_blocking_read("routing-handoff", move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0usize;
                let mut complete = true;
                ebpf.routing_handoff_for_each_chunk(JANITOR_SCAN_CHUNK, &mut |chunk| {
                    total += chunk.len();
                    for (key, entry) in chunk {
                        if now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS
                            && (key.l4proto != IPPROTO_TCP || !pins.contains(key))
                        {
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

    pub(super) async fn cleanup_tcp_requests(
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

    pub(super) async fn cleanup_tcp_requests_at(
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
}
