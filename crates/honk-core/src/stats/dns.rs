use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod snapshot;
pub(crate) use snapshot::DnsStatsSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsStatEvent {
    CacheHit,
    CacheMiss,
    CacheStale,
    SingleflightKeySaturation,
    SingleflightWaiterSaturation,
    SingleflightCancel,
    SingleflightRetry,
    PersistenceDrop,
    PersistenceFlushFailure,
    RuntimeRetirementTimeout,
    RuntimeForcedClose,
    TransportInit,
    TransportReset,
    ProjectionStaleGeneration,
    ProjectionWriteFailure,
    ProjectionRetry,
    OutcomePositive,
    OutcomeNodata,
    OutcomeNxdomain,
    OutcomeServfail,
    OutcomeRejected,
    OutcomeError,
}

#[derive(Default)]
struct DnsStats {
    writer: AtomicBool,
    cache_hit: AtomicU64,
    cache_miss: AtomicU64,
    cache_stale: AtomicU64,
    singleflight_key_saturation: AtomicU64,
    singleflight_waiter_saturation: AtomicU64,
    singleflight_cancel: AtomicU64,
    singleflight_retry: AtomicU64,
    persistence_drop: AtomicU64,
    persistence_flush_failure: AtomicU64,
    runtime_retirement_timeout: AtomicU64,
    runtime_forced_close: AtomicU64,
    transport_init: AtomicU64,
    transport_reset: AtomicU64,
    projection_stale_generation: AtomicU64,
    projection_write_failure: AtomicU64,
    projection_retry: AtomicU64,
    outcome_positive: AtomicU64,
    outcome_nodata: AtomicU64,
    outcome_nxdomain: AtomicU64,
    outcome_servfail: AtomicU64,
    outcome_rejected: AtomicU64,
    outcome_error: AtomicU64,
}

static DNS_STATS: LazyLock<DnsStats> = LazyLock::new(DnsStats::default);

impl DnsStats {
    fn record(&self, event: DnsStatEvent) {
        self.write(|| {
            self.counter(event).fetch_add(1, Ordering::Relaxed);
        });
    }

    #[cfg(test)]
    fn record_pair_for_test(&self, first: DnsStatEvent, second: DnsStatEvent) {
        self.write(|| {
            self.counter(first).fetch_add(1, Ordering::Relaxed);
            self.counter(second).fetch_add(1, Ordering::Relaxed);
        });
    }

    fn write(&self, update: impl FnOnce()) {
        let _guard = self.lock();
        update();
    }

    fn lock(&self) -> DnsStatsGuard<'_> {
        let mut spins = 0;
        while self
            .writer
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if spins < 16 {
                std::hint::spin_loop();
                spins += 1;
            } else {
                std::thread::yield_now();
                spins = 0;
            }
        }
        DnsStatsGuard {
            writer: &self.writer,
        }
    }

    fn counter(&self, event: DnsStatEvent) -> &AtomicU64 {
        match event {
            DnsStatEvent::CacheHit => &self.cache_hit,
            DnsStatEvent::CacheMiss => &self.cache_miss,
            DnsStatEvent::CacheStale => &self.cache_stale,
            DnsStatEvent::SingleflightKeySaturation => &self.singleflight_key_saturation,
            DnsStatEvent::SingleflightWaiterSaturation => &self.singleflight_waiter_saturation,
            DnsStatEvent::SingleflightCancel => &self.singleflight_cancel,
            DnsStatEvent::SingleflightRetry => &self.singleflight_retry,
            DnsStatEvent::PersistenceDrop => &self.persistence_drop,
            DnsStatEvent::PersistenceFlushFailure => &self.persistence_flush_failure,
            DnsStatEvent::RuntimeRetirementTimeout => &self.runtime_retirement_timeout,
            DnsStatEvent::RuntimeForcedClose => &self.runtime_forced_close,
            DnsStatEvent::TransportInit => &self.transport_init,
            DnsStatEvent::TransportReset => &self.transport_reset,
            DnsStatEvent::ProjectionStaleGeneration => &self.projection_stale_generation,
            DnsStatEvent::ProjectionWriteFailure => &self.projection_write_failure,
            DnsStatEvent::ProjectionRetry => &self.projection_retry,
            DnsStatEvent::OutcomePositive => &self.outcome_positive,
            DnsStatEvent::OutcomeNodata => &self.outcome_nodata,
            DnsStatEvent::OutcomeNxdomain => &self.outcome_nxdomain,
            DnsStatEvent::OutcomeServfail => &self.outcome_servfail,
            DnsStatEvent::OutcomeRejected => &self.outcome_rejected,
            DnsStatEvent::OutcomeError => &self.outcome_error,
        }
    }

    fn snapshot(&self) -> DnsStatsSnapshot {
        // The gate's acquire synchronizes with the preceding release. Holding
        // it while loading every relaxed counter makes the returned values one
        // coherent snapshot and prevents a writer from publishing half an
        // update.
        let _guard = self.lock();
        self.load_snapshot()
    }

    fn load_snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            cache_hit: self.cache_hit.load(Ordering::Relaxed),
            cache_miss: self.cache_miss.load(Ordering::Relaxed),
            cache_stale: self.cache_stale.load(Ordering::Relaxed),
            singleflight_key_saturation: self.singleflight_key_saturation.load(Ordering::Relaxed),
            singleflight_waiter_saturation: self
                .singleflight_waiter_saturation
                .load(Ordering::Relaxed),
            singleflight_cancel: self.singleflight_cancel.load(Ordering::Relaxed),
            singleflight_retry: self.singleflight_retry.load(Ordering::Relaxed),
            persistence_drop: self.persistence_drop.load(Ordering::Relaxed),
            persistence_flush_failure: self.persistence_flush_failure.load(Ordering::Relaxed),
            runtime_retirement_timeout: self.runtime_retirement_timeout.load(Ordering::Relaxed),
            runtime_forced_close: self.runtime_forced_close.load(Ordering::Relaxed),
            transport_init: self.transport_init.load(Ordering::Relaxed),
            transport_reset: self.transport_reset.load(Ordering::Relaxed),
            projection_stale_generation: self.projection_stale_generation.load(Ordering::Relaxed),
            projection_write_failure: self.projection_write_failure.load(Ordering::Relaxed),
            projection_retry: self.projection_retry.load(Ordering::Relaxed),
            outcome_positive: self.outcome_positive.load(Ordering::Relaxed),
            outcome_nodata: self.outcome_nodata.load(Ordering::Relaxed),
            outcome_nxdomain: self.outcome_nxdomain.load(Ordering::Relaxed),
            outcome_servfail: self.outcome_servfail.load(Ordering::Relaxed),
            outcome_rejected: self.outcome_rejected.load(Ordering::Relaxed),
            outcome_error: self.outcome_error.load(Ordering::Relaxed),
        }
    }
}

struct DnsStatsGuard<'a> {
    writer: &'a AtomicBool,
}

impl Drop for DnsStatsGuard<'_> {
    fn drop(&mut self) {
        self.writer.store(false, Ordering::Release);
    }
}

pub(crate) fn record_dns_event(event: DnsStatEvent) {
    DNS_STATS.record(event);
}

#[cfg_attr(
    all(not(test), not(feature = "dns-bench")),
    expect(
        dead_code,
        reason = "the internal snapshot intentionally has no public endpoint"
    )
)]
pub(crate) fn dns_snapshot() -> DnsStatsSnapshot {
    DNS_STATS.snapshot()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::{DnsStatEvent, DnsStats};

    #[test]
    fn concurrent_snapshot_never_observes_half_of_a_serialized_update() {
        let stats = Arc::new(DnsStats::default());
        let done = Arc::new(AtomicBool::new(false));
        let writer_stats = Arc::clone(&stats);
        let writer_done = Arc::clone(&done);
        let writer = std::thread::spawn(move || {
            for _ in 0..100_000 {
                writer_stats.record_pair_for_test(DnsStatEvent::CacheHit, DnsStatEvent::CacheMiss);
            }
            writer_done.store(true, Ordering::Release);
        });

        while !done.load(Ordering::Acquire) {
            let snapshot = stats.snapshot();
            assert_eq!(snapshot.cache_hit, snapshot.cache_miss);
        }
        writer.join().expect("writer");
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hit, 100_000);
        assert_eq!(snapshot.cache_miss, 100_000);
    }

    #[test]
    fn cancelled_reader_releases_gate_and_multiple_writers_make_progress() {
        const WRITERS: u64 = 4;
        const WRITES_PER_THREAD: u64 = 25_000;

        let stats = Arc::new(DnsStats::default());
        let cancel_reader = Arc::new(AtomicBool::new(false));
        let reader_iterations = Arc::new(AtomicU64::new(0));
        let reader_stats = Arc::clone(&stats);
        let reader_cancel = Arc::clone(&cancel_reader);
        let iterations = Arc::clone(&reader_iterations);
        let reader = std::thread::spawn(move || {
            while !reader_cancel.load(Ordering::Acquire) {
                let snapshot = reader_stats.snapshot();
                assert_eq!(snapshot.cache_hit, snapshot.cache_miss);
                iterations.fetch_add(1, Ordering::Relaxed);
            }
        });

        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                let stats = Arc::clone(&stats);
                std::thread::spawn(move || {
                    for _ in 0..WRITES_PER_THREAD {
                        stats.record_pair_for_test(DnsStatEvent::CacheHit, DnsStatEvent::CacheMiss);
                    }
                })
            })
            .collect();

        while reader_iterations.load(Ordering::Relaxed) < 100 {
            std::thread::yield_now();
        }
        cancel_reader.store(true, Ordering::Release);
        reader.join().expect("reader");
        for writer in writers {
            writer.join().expect("writer");
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hit, WRITERS * WRITES_PER_THREAD);
        assert_eq!(snapshot.cache_miss, WRITERS * WRITES_PER_THREAD);
        assert!(reader_iterations.load(Ordering::Relaxed) >= 100);
    }
}
