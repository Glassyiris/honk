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

    pub(crate) fn mark_available(&self, latency: Duration) {
        self.latencies.append(LatencySample::real(latency));
        let mut ma = self.moving_average.lock();
        if *ma == Duration::ZERO {
            *ma = latency;
        } else {
            *ma = (*ma + latency) / 2;
        }
        self.alive.store(true, Ordering::Release);
    }

    pub(crate) fn mark_unavailable(&self) {
        // Synthetic 10s placeholder: pushes the node to the back of
        // latency-sorted selection, flagged so it is never displayed as a
        // measured delay (clash history would show a bogus 10000ms).
        self.latencies
            .append(LatencySample::synthetic(TIMEOUT_LATENCY));
        let mut ma = self.moving_average.lock();
        if *ma == Duration::ZERO {
            *ma = TIMEOUT_LATENCY;
        } else {
            *ma = (*ma + TIMEOUT_LATENCY) / 2;
        }
        self.alive.store(false, Ordering::Release);
    }

    #[allow(dead_code)]
    pub(crate) fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Release);
    }

    pub(crate) fn moving_average_duration(&self) -> Duration {
        *self.moving_average.lock()
    }

    #[allow(dead_code)]
    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}
