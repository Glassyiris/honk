use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;

use super::{ProjectionCounters, RoutingProjection};
use crate::ebpf::{DomainRouteWriteError, EbpfBackend, maps};

const WARN_INTERVAL: Duration = Duration::from_secs(5);

pub(super) async fn run(
    projection: std::sync::Weak<RoutingProjection>,
    mut receiver: mpsc::Receiver<()>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    counters: Arc<ProjectionCounters>,
) {
    let mut last_warning = None;
    loop {
        let Some(active) = projection.upgrade() else {
            return;
        };
        let deadline = active.state.lock().next_deadline();
        drop(active);
        match deadline {
            Some(deadline) => {
                tokio::select! {
                    wake = receiver.recv() => if wake.is_none() { return; },
                    () = tokio::time::sleep_until(deadline) => {}
                }
            }
            None => {
                if receiver.recv().await.is_none() {
                    return;
                }
            }
        }
        let Some(active) = projection.upgrade() else {
            return;
        };
        flush(&active, &ebpf, &counters, &mut last_warning).await;
    }
}

async fn flush(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    counters: &ProjectionCounters,
    last_warning: &mut Option<Instant>,
) {
    flush_after_snapshot(projection, ebpf, counters, last_warning, || {}).await;
}

async fn flush_after_snapshot(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    counters: &ProjectionCounters,
    last_warning: &mut Option<Instant>,
    after_snapshot: impl FnOnce(),
) {
    let now = Instant::now();
    let batch = {
        let mut state = projection.state.lock();
        state.expire(now);
        state.batch(now)
    };
    after_snapshot();
    if batch.sets.is_empty() && batch.removes.is_empty() {
        return;
    }

    let mut successful_sets = Vec::new();
    let mut successful_removes = Vec::new();
    let mut failures = Vec::new();
    {
        let mut backend = ebpf.write().await;
        for set in &batch.sets {
            match ip_key(set.ip).and_then(|key| backend.set_domain_ip_bitmap(&key, &set.bitmap)) {
                Ok(()) => successful_sets.push(*set),
                Err(error) => failures.push((set.ip, error)),
            }
        }
        for remove in &batch.removes {
            match ip_key(remove.ip).and_then(|key| backend.remove_domain_ip_bitmap(&key)) {
                Ok(()) => successful_removes.push(*remove),
                Err(error) => failures.push((remove.ip, error)),
            }
        }
    }

    let (writes_current, generation_changed) = {
        let mut state = projection.state.lock();
        let generation_changed = batch.generation != state.snapshot.generation();
        for (ip, _) in &failures {
            state.record_failure(*ip, now);
        }
        (
            state.commit_success(batch.generation, &successful_sets, &successful_removes),
            generation_changed,
        )
    };
    if generation_changed {
        counters.generation_rebuilds.fetch_add(1, Ordering::Relaxed);
    }
    if !writes_current {
        let _ = projection.wake.try_send(());
    }
    for (_, error) in failures {
        counters.write_failures.fetch_add(1, Ordering::Relaxed);
        if error.is_map_full() {
            counters.map_full.fetch_add(1, Ordering::Relaxed);
        }
        let should_warn = last_warning.is_none_or(|last| now.duration_since(last) >= WARN_INTERVAL);
        if should_warn {
            tracing::warn!(error = %error, "DNS routing projection write failed; retrying");
            *last_warning = Some(now);
        }
    }
}

fn ip_key(ip: IpAddr) -> Result<honk_ebpf_common::LpmKey, DomainRouteWriteError> {
    let prefix = match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    };
    maps::cidr_to_lpm_key(&prefix).map_err(DomainRouteWriteError::Other)
}

#[cfg(test)]
pub(super) async fn flush_for_test(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
) {
    let mut last_warning = None;
    flush(projection, ebpf, &projection.counters, &mut last_warning).await;
}

#[cfg(test)]
pub(super) async fn flush_for_test_after_snapshot(
    projection: &RoutingProjection,
    ebpf: &RwLock<Box<dyn EbpfBackend>>,
    after_snapshot: impl FnOnce(),
) {
    let mut last_warning = None;
    flush_after_snapshot(
        projection,
        ebpf,
        &projection.counters,
        &mut last_warning,
        after_snapshot,
    )
    .await;
}
