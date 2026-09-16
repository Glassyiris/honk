use std::time::Duration;

use quinn::{Connection, VarInt};

use super::{AdaptiveFlowProfile, AdaptiveFlowProfiles};

const FLOW_CONTROL_MIN_RTT: Duration = Duration::from_millis(80);
const FLOW_CONTROL_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const FLOW_CONTROL_MIN_WINDOW: u64 = 8 << 20;
pub(super) const FLOW_CONTROL_MAX_WINDOW: u64 = 32 << 20;
const FLOW_CONTROL_PROMOTION_SAMPLES: u8 = 3;

impl AdaptiveFlowProfiles {
    pub(super) fn lock(&self) -> parking_lot::MutexGuard<'_, [AdaptiveFlowProfile; 2]> {
        self.0.lock()
    }
}

#[derive(Debug)]
pub(super) struct AdaptiveFlowSampler {
    last_sample_ms: u64,
    last_received_bytes: u64,
    last_sent_bytes: u64,
    last_stream_data_blocked: u64,
    last_data_blocked: u64,
    receive_rate_ewma: u64,
    send_rate_ewma: u64,
    connection_receive_high_samples: u8,
    send_high_samples: u8,
}

impl AdaptiveFlowSampler {
    pub(super) fn new(stats: &quinn::ConnectionStats, now: u64) -> Self {
        Self {
            last_sample_ms: now,
            last_received_bytes: stats.flow_control.received_bytes,
            last_sent_bytes: stats.flow_control.sent_bytes,
            last_stream_data_blocked: stats.frame_rx.stream_data_blocked,
            last_data_blocked: stats.frame_rx.data_blocked,
            receive_rate_ewma: 0,
            send_rate_ewma: 0,
            connection_receive_high_samples: 0,
            send_high_samples: 0,
        }
    }

    pub(super) fn observe(
        &mut self,
        profile: &mut AdaptiveFlowProfile,
        stats: &quinn::ConnectionStats,
        now: u64,
    ) {
        let elapsed_ms = now.saturating_sub(self.last_sample_ms);
        if elapsed_ms == 0 {
            return;
        }
        let received = stats
            .flow_control
            .received_bytes
            .saturating_sub(self.last_received_bytes);
        let sent = stats
            .flow_control
            .sent_bytes
            .saturating_sub(self.last_sent_bytes);
        let stream_data_blocked = stats
            .frame_rx
            .stream_data_blocked
            .saturating_sub(self.last_stream_data_blocked);
        let data_blocked = stats
            .frame_rx
            .data_blocked
            .saturating_sub(self.last_data_blocked);
        self.last_sample_ms = now;
        self.last_received_bytes = stats.flow_control.received_bytes;
        self.last_sent_bytes = stats.flow_control.sent_bytes;
        self.last_stream_data_blocked = stats.frame_rx.stream_data_blocked;
        self.last_data_blocked = stats.frame_rx.data_blocked;
        self.receive_rate_ewma = flow_rate_ewma(
            self.receive_rate_ewma,
            bytes_per_second(received, elapsed_ms),
        );
        self.send_rate_ewma =
            flow_rate_ewma(self.send_rate_ewma, bytes_per_second(sent, elapsed_ms));

        let receive_bdp = flow_bdp_bytes(self.receive_rate_ewma, stats.path.rtt);
        let send_bdp = flow_bdp_bytes(self.send_rate_ewma, stats.path.rtt);
        let receive_credit_pressured = flow_credit_pressured(
            stats.flow_control.receive_window_available,
            stats.flow_control.receive_window,
        );
        let receive_near = stats.path.rtt >= FLOW_CONTROL_MIN_RTT
            && flow_nears_window(
                receive_bdp,
                stats.flow_control.receive_window,
                receive_credit_pressured,
            );
        // DATA_BLOCKED is direct peer evidence that our advertised window is
        // the constraint: it fires below the RTT gate and independent of the
        // goodput estimate, which is understated exactly while the window
        // throttles the flow. Blocked growth doubles the current window
        // because 2xBDP derived from that throttled rate would be a no-op.
        let receive_blocked = data_blocked != 0;
        update_flow_window(
            &mut self.connection_receive_high_samples,
            &mut profile.connection_receive_floor,
            &mut profile.last_connection_receive_adjust_ms,
            (received != 0 && receive_near) || receive_blocked,
            received == 0 && receive_near && receive_credit_pressured,
            receive_bdp,
            if receive_blocked {
                stats.flow_control.receive_window.saturating_mul(2)
            } else {
                0
            },
            now,
        );
        update_stream_receive_window(
            &mut profile.stream_receive_floor,
            &mut profile.last_stream_receive_adjust_ms,
            stream_data_blocked != 0,
            stats.flow_control.stream_receive_window,
            now,
        );
        let send_credit_pressured = flow_credit_pressured(
            stats.flow_control.send_window_available,
            stats.flow_control.send_window,
        );
        let send_near = stats.path.rtt >= FLOW_CONTROL_MIN_RTT
            && flow_nears_window(
                send_bdp,
                stats.flow_control.send_window,
                send_credit_pressured,
            );
        update_flow_window(
            &mut self.send_high_samples,
            &mut profile.send_floor,
            &mut profile.last_send_adjust_ms,
            sent != 0 && send_near,
            sent == 0 && send_near && send_credit_pressured,
            send_bdp,
            0,
            now,
        );
    }
}

fn bytes_per_second(bytes: u64, elapsed_ms: u64) -> u64 {
    (u128::from(bytes) * 1_000 / u128::from(elapsed_ms.max(1))).min(u128::from(u64::MAX)) as u64
}

fn flow_rate_ewma(previous: u64, sample: u64) -> u64 {
    if previous == 0 {
        sample
    } else {
        ((u128::from(previous) * 9 + u128::from(sample)) / 10).min(u128::from(u64::MAX)) as u64
    }
}

fn flow_bdp_bytes(rate: u64, rtt: Duration) -> u64 {
    (u128::from(rate) * rtt.as_nanos() / 1_000_000_000).min(u128::from(u64::MAX)) as u64
}

fn flow_credit_pressured(available: u64, window: u64) -> bool {
    window != 0 && u128::from(available) * 4 <= u128::from(window)
}

pub(super) fn flow_nears_window(bdp: u64, window: u64, credit_pressured: bool) -> bool {
    window != 0
        && (u128::from(bdp) * 4 >= u128::from(window) * 3
            || (credit_pressured && u128::from(bdp) * 2 >= u128::from(window)))
}

pub(super) fn adaptive_window(bdp: u64) -> u64 {
    bdp.saturating_mul(2)
        .clamp(FLOW_CONTROL_MIN_WINDOW, FLOW_CONTROL_MAX_WINDOW)
        .next_multiple_of(1 << 20)
        .min(FLOW_CONTROL_MAX_WINDOW)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn update_flow_window(
    high_samples: &mut u8,
    floor: &mut u64,
    last_adjust_ms: &mut Option<u64>,
    high: bool,
    preserve: bool,
    bdp: u64,
    min_target: u64,
    now: u64,
) {
    if high {
        *high_samples = high_samples
            .saturating_add(1)
            .min(FLOW_CONTROL_PROMOTION_SAMPLES);
    } else if !preserve {
        *high_samples = 0;
    }
    if *high_samples < FLOW_CONTROL_PROMOTION_SAMPLES
        || last_adjust_ms
            .is_some_and(|last| now.saturating_sub(last) < FLOW_CONTROL_COOLDOWN.as_millis() as u64)
    {
        return;
    }
    let target = adaptive_window(bdp)
        .max(min_target)
        .min(FLOW_CONTROL_MAX_WINDOW);
    if target > *floor {
        *floor = target;
        *last_adjust_ms = Some(now);
    }
    *high_samples = 0;
}

fn update_stream_receive_window(
    floor: &mut u64,
    last_adjust_ms: &mut Option<u64>,
    blocked: bool,
    current_window: u64,
    now: u64,
) {
    if !blocked
        || last_adjust_ms
            .is_some_and(|last| now.saturating_sub(last) < FLOW_CONTROL_COOLDOWN.as_millis() as u64)
    {
        return;
    }
    let target = current_window
        .saturating_mul(2)
        .clamp(FLOW_CONTROL_MIN_WINDOW, FLOW_CONTROL_MAX_WINDOW);
    if target > *floor {
        *floor = target;
        *last_adjust_ms = Some(now);
    }
}

pub(super) fn apply_flow_control_profile(
    conn: &Connection,
    stats: &quinn::ConnectionStats,
    profile: &AdaptiveFlowProfile,
) {
    if profile.stream_receive_floor > stats.flow_control.stream_receive_window {
        conn.set_stream_receive_window(
            VarInt::try_from(profile.stream_receive_floor)
                .expect("stream receive floor originated from a QUIC window"),
        );
    }
    if profile.connection_receive_floor > stats.flow_control.receive_window {
        conn.set_receive_window(
            VarInt::try_from(profile.connection_receive_floor)
                .expect("connection receive floor originated from a QUIC window"),
        );
    }
    if profile.send_floor > stats.flow_control.send_window {
        conn.set_send_window(profile.send_floor);
    }
}

pub(super) fn seed_flow_control_profile(
    profile: &mut AdaptiveFlowProfile,
    stats: &quinn::ConnectionStats,
) {
    profile.connection_receive_floor = profile
        .connection_receive_floor
        .max(stats.flow_control.receive_window);
    profile.stream_receive_floor = profile
        .stream_receive_floor
        .max(stats.flow_control.stream_receive_window);
    profile.send_floor = profile.send_floor.max(stats.flow_control.send_window);
}
