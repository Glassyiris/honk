//! Per-node-per-domain health tracking: Latencies10 + MovingAverage + Alive.

use super::latencies::{LatencySample, SyncLatencies10};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

pub(crate) const TIMEOUT_LATENCY: Duration = Duration::from_secs(10);

/// Strike cap: repeated failures stop mattering beyond this.
pub(crate) const FAILURE_STRIKES_MAX: u8 = 3;
/// Minimum consecutive real successes to clear any demotion — mirrors the
/// RECOVERY_SUCCESSES_NEEDED liveness hysteresis at ranking level.
pub(crate) const STRIKE_CLEAR_SUCCESSES: u8 = 2;

/// Real-traffic EMA weight: α = 1/8 (self-referential — the probe-target
/// vs real-target RTT distribution mismatch never enters the baseline).
pub(crate) const TRAFFIC_EMA_SHIFT: u32 = 3;
/// Dials before the EMA judges anything.
pub(crate) const TRAFFIC_EMA_WARMUP: u8 = 3;
/// Consecutive slow dials that demote the node.
pub(crate) const SLOW_DIAL_STREAK_MAX: u8 = 3;
/// Absolute slack on top of the relative 2×EMA slow threshold.
pub(crate) const SLOW_DIAL_MARGIN: Duration = Duration::from_millis(500);

/// Verdict of one real dial against the node's own traffic EMA.
pub(crate) enum TrafficVerdict {
    /// EMA still warming up — no judgement made.
    Warmup,
    Fast,
    Slow,
}

pub(crate) struct DialerCollection {
    pub latencies: SyncLatencies10,
    pub moving_average: Mutex<Duration>,
    pub alive: AtomicBool,
    failure_strikes: AtomicU8,
    strike_clear_progress: AtomicU8,
    traffic_ema_nanos: AtomicU64,
    traffic_samples: AtomicU8,
    slow_dial_streak: AtomicU8,
}

impl DialerCollection {
    pub(crate) fn new() -> Self {
        Self {
            latencies: SyncLatencies10::new(10),
            moving_average: Mutex::new(Duration::ZERO),
            alive: AtomicBool::new(true),
            failure_strikes: AtomicU8::new(0),
            strike_clear_progress: AtomicU8::new(0),
            traffic_ema_nanos: AtomicU64::new(0),
            traffic_samples: AtomicU8::new(0),
            slow_dial_streak: AtomicU8::new(0),
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
        // Demotion clears only after max(strikes, STRIKE_CLEAR_SUCCESSES)
        // consecutive real successes — a fast-but-flaky node cannot reclaim
        // rank with one lucky probe.
        let strikes = self.failure_strikes.load(Ordering::Relaxed);
        if strikes > 0 {
            let progress = self.strike_clear_progress.fetch_add(1, Ordering::Relaxed) + 1;
            if progress >= strikes.max(STRIKE_CLEAR_SUCCESSES) {
                self.failure_strikes.store(0, Ordering::Relaxed);
                self.strike_clear_progress.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Record a real dial failure for ranking. Periodic probe failures use
    /// [`Self::mark_probe_unavailable`] instead and never create strikes or
    /// synthetic latency samples.
    pub(crate) fn mark_unavailable(&self) {
        // The synthetic sample is display-excluded and never feeds the moving
        // average; the failure strike owns ranking demotion.
        self.latencies
            .append(LatencySample::synthetic(TIMEOUT_LATENCY));
        self.alive.store(false, Ordering::Release);
        let strikes = self.failure_strikes.load(Ordering::Relaxed);
        self.failure_strikes
            .store((strikes + 1).min(FAILURE_STRIKES_MAX), Ordering::Relaxed);
        self.strike_clear_progress.store(0, Ordering::Relaxed);
    }

    /// Record probe unavailability without creating a ranking strike. Probe
    /// liveness counters own exclusion; dial failures alone own demotion.
    pub(crate) fn mark_probe_unavailable(&self) {
        self.alive.store(false, Ordering::Release);
        self.strike_clear_progress.store(0, Ordering::Relaxed);
    }

    /// Failure-demoted nodes rank below every non-demoted candidate until
    /// enough consecutive real successes clear the strikes.
    pub(crate) fn is_failure_demoted(&self) -> bool {
        self.failure_strikes.load(Ordering::Relaxed) > 0
    }

    /// Judge one real dial against the node's own traffic EMA, then fold it
    /// in. Sudden degradation (elapsed > min(2×ema, ema+SLOW_DIAL_MARGIN))
    /// reports Slow; gradual drift stays owned by the probe cycle.
    pub(crate) fn record_traffic_latency(&self, elapsed: Duration) -> TrafficVerdict {
        let elapsed_nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let ema = self.traffic_ema_nanos.load(Ordering::Relaxed);
        let samples = self.traffic_samples.load(Ordering::Relaxed);
        let verdict =
            if samples < TRAFFIC_EMA_WARMUP {
                TrafficVerdict::Warmup
            } else if ema > 0
                && elapsed_nanos
                    > ema.saturating_mul(2).min(ema.saturating_add(
                        u64::try_from(SLOW_DIAL_MARGIN.as_nanos()).unwrap_or(u64::MAX),
                    ))
            {
                TrafficVerdict::Slow
            } else {
                TrafficVerdict::Fast
            };
        let new_ema = if ema == 0 {
            elapsed_nanos
        } else {
            ema.saturating_mul(7).saturating_add(elapsed_nanos) >> TRAFFIC_EMA_SHIFT
        };
        self.traffic_ema_nanos.store(new_ema, Ordering::Relaxed);
        if samples < TRAFFIC_EMA_WARMUP {
            self.traffic_samples.store(samples + 1, Ordering::Relaxed);
        }
        verdict
    }

    /// One more consecutive slow dial; returns the new streak length.
    pub(crate) fn bump_slow_streak(&self) -> u8 {
        let streak = self.slow_dial_streak.load(Ordering::Relaxed);
        let streak = (streak + 1).min(SLOW_DIAL_STREAK_MAX);
        self.slow_dial_streak.store(streak, Ordering::Relaxed);
        streak
    }

    pub(crate) fn reset_slow_streak(&self) {
        self.slow_dial_streak.store(0, Ordering::Relaxed);
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
