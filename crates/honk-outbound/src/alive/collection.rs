//! Per-node-per-domain health tracking: Latencies10 + MovingAverage + Alive.

use super::latencies::{LatencySample, SyncLatencies10};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(crate) const TIMEOUT_LATENCY: Duration = Duration::from_secs(10);

pub(crate) struct DialerCollection {
    pub latencies: SyncLatencies10,
    pub moving_average: Mutex<Duration>,
    pub alive: AtomicBool,
}

impl DialerCollection {
    pub(crate) fn new() -> Self {
        Self {
            latencies: SyncLatencies10::new(10),
            moving_average: Mutex::new(Duration::ZERO),
            alive: AtomicBool::new(true),
        }
    }

    fn update_moving_average(&self, latency: Duration) {
        let mut ma = self.moving_average.lock();
        if *ma == Duration::ZERO {
            *ma = latency;
        } else {
            *ma = (*ma + latency) / 2;
        }
    }

    pub(crate) fn mark_available(&self, latency: Duration) {
        self.latencies.append(LatencySample::real(latency));
        self.update_moving_average(latency);
        self.alive.store(true, Ordering::Release);
    }

    pub(crate) fn mark_unavailable(&self) {
        // Synthetic 10s placeholder: marks the latest sample as a failure so
        // selection demotes the node (see `latest_is_synthetic`), flagged so
        // it is never displayed as a measured delay (clash history would
        // show a bogus 10000ms). It does NOT feed the moving average —
        // ranking stays on real measurements.
        self.latencies
            .append(LatencySample::synthetic(TIMEOUT_LATENCY));
        self.alive.store(false, Ordering::Release);
    }

    /// Seed a restored (persisted) sample: feeds latency history and the
    /// moving average WITHOUT touching the alive flag — liveness is
    /// decided by probes; this only pre-seeds ranking data at startup.
    pub(crate) fn restore_sample(&self, latency: Duration, at: std::time::SystemTime) {
        self.latencies.append(LatencySample {
            latency,
            at,
            synthetic: false,
        });
        self.update_moving_average(latency);
    }

    pub(crate) fn moving_average_duration(&self) -> Duration {
        *self.moving_average.lock()
    }
}
