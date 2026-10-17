//! Bounded map scans and fenced retirement, separate from janitor scheduling.

use super::{
    AuxScanResult, BpfJanitor, JANITOR_DELETE_CHUNK, JANITOR_SCAN_CHUNK, OccupancyGauge, ScanTuning,
};
use crate::ebpf::{
    EbpfBackend, RetireCounts, RetireError, RetireKind, RetireOutcome, RetireRequest, conn_expired,
    conn_state_timeout_ns,
};
use honk_ebpf_common::TuplesKey;
use honk_ebpf_common::conn::{
    REDIRECT_TRACK_TIMEOUT_NS, ROUTING_HANDOFF_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS,
};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error};

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
            let mut outcomes = [RetireOutcome::NotRun; JANITOR_DELETE_CHUNK];
            #[cfg(test)]
            if let Some(hook) = before_delete_hook {
                hook();
            }
            // Release between batches so queued per-flow readers can proceed.
            for chunk in entries.chunks(JANITOR_DELETE_CHUNK) {
                let mut ebpf = ebpf.blocking_write();
                requests.clear();
                requests.extend(
                    chunk
                        .iter()
                        .map(&mut request)
                        .filter(|request| !pins.blocks(request)),
                );
                if requests.is_empty() {
                    continue;
                }
                match ebpf.retire_batch(&requests, &mut outcomes[..requests.len()]) {
                    Ok(progress) => counts += progress,
                    Err(error) => {
                        counts += error.counts;
                        return Err(RetireError {
                            counts,
                            source: error.source,
                        });
                    }
                }
            }
            Ok(counts)
        })
        .await;
        match result {
            Ok(result) => result.map_err(Into::into),
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(error.into()),
        }
    }

    // Keep scan facts on retirement errors so conn-state drift still recalibrates.
    async fn sweep<K, V>(
        &self,
        label: &'static str,
        tuning: ScanTuning,
        for_each: impl FnOnce(&dyn EbpfBackend, &mut dyn FnMut(&[(K, V)]) -> bool) -> anyhow::Result<()>
        + Send
        + 'static,
        stale: impl Fn(&K, &V) -> bool + Send + 'static,
        request: impl for<'a> Fn(&'a (K, V)) -> RetireRequest<'a> + Copy + Send + 'static,
        pick_count: impl FnOnce(RetireCounts) -> u64 + Send,
    ) -> (AuxScanResult, anyhow::Result<()>)
    where
        K: Copy + Send + 'static,
        V: Copy + Send + 'static,
    {
        let pins = Arc::clone(&self.tcp_flow_pins);
        let scanned = self
            .run_blocking_read(label, move |ebpf| {
                let deadline = Instant::now() + tuning.budget;
                let mut expired = Vec::with_capacity(tuning.candidates);
                let mut total = 0;
                let mut complete = true;
                for_each(ebpf, &mut |chunk| {
                    total += chunk.len();
                    for entry in chunk {
                        if expired.len() == tuning.candidates {
                            break;
                        }
                        if stale(&entry.0, &entry.1) && !pins.blocks(&request(entry)) {
                            expired.push(*entry);
                        }
                    }
                    complete = expired.len() < tuning.candidates && Instant::now() < deadline;
                    complete
                })?;
                anyhow::Ok((expired, total, complete))
            })
            .await;
        let (expired, total, complete) = match scanned {
            Some(Ok(scanned)) => scanned,
            Some(Err(error)) => {
                debug!(%error, map = label, "BPF janitor: map scan failed");
                return (AuxScanResult::default(), Ok(()));
            }
            None => return (AuxScanResult::default(), Ok(())),
        };
        let mut result = AuxScanResult {
            scanned: total,
            complete,
            ..AuxScanResult::default()
        };
        let retired = if expired.is_empty() {
            Ok(())
        } else {
            self.run_blocking_chunked_delete(expired, request)
                .await
                .map(|counts| result.deleted = pick_count(counts))
        };
        (result, retired)
    }

    pub(super) async fn cleanup_conn_state_at(
        &self,
        now_ns: u64,
        gauge: &mut OccupancyGauge,
        occ_counters: ((u64, u64), u64),
        tuning: ScanTuning,
    ) -> anyhow::Result<(u64, usize)> {
        let (scan, retired) = self
            .sweep(
                "conn-state",
                tuning,
                |ebpf, visit| ebpf.conn_state_for_each_chunk(JANITOR_SCAN_CHUNK, visit),
                move |key, state| conn_expired(key.l4proto, state, now_ns),
                move |(key, expected)| RetireRequest {
                    key: *key,
                    kind: RetireKind::ExpiredConn {
                        expected,
                        expired_before_ns: now_ns
                            .saturating_sub(conn_state_timeout_ns(key.l4proto, expected)),
                    },
                },
                |counts| counts.conn,
            )
            .await;
        if scan.complete {
            let ((inserts, ebpf_deletes), userspace_deletes) = occ_counters;
            gauge.calibrate(
                scan.scanned as u64,
                inserts,
                ebpf_deletes,
                userspace_deletes,
            );
        }
        retired?;
        Ok((scan.deleted, scan.scanned))
    }

    pub(super) async fn cleanup_redirect_track_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
    ) -> anyhow::Result<AuxScanResult> {
        let (scan, retired) = self
            .sweep(
                "redirect-track",
                tuning,
                |ebpf, visit| ebpf.redirect_track_for_each_chunk(JANITOR_SCAN_CHUNK, visit),
                move |_, entry| {
                    now_ns.saturating_sub(entry.last_seen_ns) > REDIRECT_TRACK_TIMEOUT_NS
                },
                move |(key, expected)| RetireRequest {
                    key: TuplesKey {
                        src_ip: key.src_ip,
                        dst_ip: key.dst_ip,
                        src_port: key.src_port,
                        dst_port: key.dst_port,
                        l4proto: key.l4proto,
                        padding: [0; 3],
                    },
                    kind: RetireKind::ExpiredRedirect {
                        expected,
                        expired_before_ns: now_ns.saturating_sub(REDIRECT_TRACK_TIMEOUT_NS),
                    },
                },
                |counts| counts.redirect,
            )
            .await;
        retired?;
        if scan.deleted > 0 {
            debug!(
                deleted = scan.deleted,
                "BPF janitor: removed redirect track entries"
            );
        }
        Ok(scan)
    }

    pub(super) async fn cleanup_routing_handoff_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
    ) -> anyhow::Result<AuxScanResult> {
        let (scan, retired) = self
            .sweep(
                "routing-handoff",
                tuning,
                |ebpf, visit| ebpf.routing_handoff_for_each_chunk(JANITOR_SCAN_CHUNK, visit),
                move |_, entry| {
                    now_ns.saturating_sub(entry.last_seen_ns) > ROUTING_HANDOFF_TIMEOUT_NS
                },
                move |(key, expected)| RetireRequest {
                    key: *key,
                    kind: RetireKind::ExpiredHandoff {
                        expected,
                        expired_before_ns: now_ns.saturating_sub(ROUTING_HANDOFF_TIMEOUT_NS),
                    },
                },
                |counts| counts.handoff,
            )
            .await;
        retired?;
        if scan.deleted > 0 {
            debug!(
                deleted = scan.deleted,
                "BPF janitor: removed routing handoff entries"
            );
        }
        Ok(scan)
    }

    pub(super) async fn cleanup_tcp_requests_at(
        &self,
        now_ns: u64,
        tuning: ScanTuning,
    ) -> anyhow::Result<AuxScanResult> {
        let (scan, retired) = self
            .sweep(
                "tcp-request-bindings",
                tuning,
                |ebpf, visit| ebpf.tcp_request_for_each_chunk(JANITOR_SCAN_CHUNK, visit),
                move |_, binding| {
                    now_ns.saturating_sub(binding.handoff.last_seen_ns)
                        > TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS
                },
                move |(request, expected)| RetireRequest {
                    key: expected.tuples,
                    kind: RetireKind::ExpiredRequest {
                        request,
                        expected,
                        expired_before_ns: now_ns
                            .saturating_sub(TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS),
                    },
                },
                |counts| counts.request,
            )
            .await;
        retired?;
        Ok(scan)
    }
}
