use super::*;
use crate::proxy::QuicSendToken;

fn health(last_ack: u64, epoch: u64, streak: u8, since: u64) -> QuicPathHealth {
    QuicPathHealth {
        ack_state: AtomicU64::new(path_state(epoch, since != 0)),
        last_acked_packets: AtomicU64::new(last_ack),
        sampled_acked_packets: AtomicU64::new(last_ack),
        sampled_sent_ack_eliciting_packets: AtomicU64::new(last_ack),
        waiting_sent_baseline: AtomicU64::new(last_ack),
        waiting_acked_baseline: AtomicU64::new(last_ack),
        unacked_since_ms: AtomicU64::new(0),
        last_sample_ms: AtomicU64::new(path_now_millis()),
        timeout_state: AtomicU64::new(timeout_state(epoch, streak)),
        waiting_since_ms: AtomicU64::new(since),
        send_timeout_ms: AtomicU64::new(1_000),
        path_stall_timeout_ms: AtomicU64::new(10_000),
        path_stalled: AtomicBool::new(false),
        telemetry_enabled: AtomicBool::new(false),
    }
}

fn flow_stats(received: u64, sent: u64, window: u64) -> quinn::ConnectionStats {
    let mut stats = quinn::ConnectionStats::default();
    stats.path.rtt = Duration::from_millis(125);
    stats.flow_control.received_bytes = received;
    stats.flow_control.sent_bytes = sent;
    stats.flow_control.receive_window = window;
    stats.flow_control.receive_window_available = window;
    stats.flow_control.stream_receive_window = window;
    stats.flow_control.send_window = window;
    stats.flow_control.send_window_available = window;
    stats
}

#[test]
fn sustained_high_bdp_promotes_with_cooldown_and_cap() {
    const MIB: u64 = 1 << 20;
    let mut stats = flow_stats(0, 0, 8 * MIB);
    let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
    let mut profile = AdaptiveFlowProfile::default();

    for step in 1..=3 {
        stats.flow_control.received_bytes += 48 * MIB;
        stats.flow_control.sent_bytes += 48 * MIB;
        sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
        if step < 3 {
            assert_eq!(
                (
                    profile.connection_receive_floor,
                    profile.stream_receive_floor,
                    profile.send_floor,
                ),
                (0, 0, 0),
            );
        }
    }
    assert_eq!(
        (
            profile.connection_receive_floor,
            profile.stream_receive_floor,
            profile.send_floor,
        ),
        (12 * MIB, 0, 12 * MIB),
    );

    stats.flow_control.receive_window = 12 * MIB;
    stats.flow_control.stream_receive_window = 12 * MIB;
    stats.flow_control.send_window = 12 * MIB;
    let mut cooldown_sampler = AdaptiveFlowSampler::new(&stats, 4_000);
    for step in 1..=3 {
        stats.flow_control.received_bytes += 256 * MIB;
        stats.flow_control.sent_bytes += 256 * MIB;
        cooldown_sampler.observe(&mut profile, &stats, 4_000 + step * 1_000);
    }
    assert_eq!(
        (
            profile.connection_receive_floor,
            profile.stream_receive_floor,
            profile.send_floor,
        ),
        (12 * MIB, 0, 12 * MIB),
    );

    let mut resumed_sampler = AdaptiveFlowSampler::new(&stats, 304_000);
    for step in 1..=3 {
        stats.flow_control.received_bytes += 256 * MIB;
        stats.flow_control.sent_bytes += 256 * MIB;
        resumed_sampler.observe(&mut profile, &stats, 304_000 + step * 1_000);
    }
    assert_eq!(
        (
            profile.connection_receive_floor,
            profile.stream_receive_floor,
            profile.send_floor,
        ),
        (FLOW_CONTROL_MAX_WINDOW, 0, FLOW_CONTROL_MAX_WINDOW),
    );

    let mut idle_sampler = AdaptiveFlowSampler::new(&stats, 307_000);
    for step in 1..=60 {
        idle_sampler.observe(&mut profile, &stats, 307_000 + step * 1_000);
    }
    assert_eq!(
        (
            profile.connection_receive_floor,
            profile.stream_receive_floor,
            profile.send_floor,
        ),
        (FLOW_CONTROL_MAX_WINDOW, 0, FLOW_CONTROL_MAX_WINDOW),
    );
    assert!(!flow_nears_window(4 * MIB, 8 * MIB, false));
    assert!(flow_nears_window(4 * MIB, 8 * MIB, true));
    assert_eq!(adaptive_window(u64::MAX), FLOW_CONTROL_MAX_WINDOW);
}

#[test]
fn aggregate_bdp_does_not_train_stream_window() {
    const MIB: u64 = 1 << 20;
    let mut stats = flow_stats(0, 0, 8 * MIB);
    let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
    let mut profile = AdaptiveFlowProfile::default();
    for step in 1..=3 {
        stats.flow_control.received_bytes += 48 * MIB;
        sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
    }
    assert_eq!(profile.connection_receive_floor, 12 * MIB);
    assert_eq!(profile.stream_receive_floor, 0);

    stats.frame_rx.stream_data_blocked += 1;
    sampler.observe(&mut profile, &stats, 5_000);
    assert_eq!(profile.stream_receive_floor, 16 * MIB);
}

#[test]
fn credit_stalls_preserve_but_do_not_advance_promotion() {
    const MIB: u64 = 1 << 20;
    fn sampled_floor(pressured: bool) -> u64 {
        let mut stats = flow_stats(0, 0, 8 * MIB);
        stats.flow_control.send_window_available = if pressured { 0 } else { 8 * MIB };
        let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
        let mut profile = AdaptiveFlowProfile::default();
        for step in 1..=7 {
            if matches!(step, 1 | 4 | 7) {
                stats.flow_control.sent_bytes += 48 * MIB;
            }
            sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
        }
        profile.send_floor
    }

    assert!(sampled_floor(true) > 8 * MIB);
    assert_eq!(sampled_floor(false), 0);
}

#[test]
fn configured_window_does_not_start_cooldown() {
    const MIB: u64 = 1 << 20;
    let mut seeded = AdaptiveFlowProfile::default();
    seed_flow_control_profile(&mut seeded, &flow_stats(0, 0, 16 * MIB));
    let mut samples = 0;
    for now in 1..=3 {
        update_flow_window(
            &mut samples,
            &mut seeded.connection_receive_floor,
            &mut seeded.last_connection_receive_adjust_ms,
            true,
            false,
            4 * MIB,
            0,
            now,
        );
    }
    assert_eq!(seeded.connection_receive_floor, 16 * MIB);
    assert_eq!(seeded.last_connection_receive_adjust_ms, None);
    for now in 4..=6 {
        update_flow_window(
            &mut samples,
            &mut seeded.connection_receive_floor,
            &mut seeded.last_connection_receive_adjust_ms,
            true,
            false,
            12 * MIB,
            0,
            now,
        );
    }
    assert_eq!(seeded.connection_receive_floor, 24 * MIB);
    assert_eq!(seeded.last_connection_receive_adjust_ms, Some(6));
}

#[test]
fn blocked_frames_raise_windows_below_the_rtt_gate() {
    const MIB: u64 = 1 << 20;
    let mut stats = flow_stats(0, 0, 8 * MIB);
    stats.path.rtt = Duration::from_millis(50);
    let mut sampler = AdaptiveFlowSampler::new(&stats, 1_000);
    let mut profile = AdaptiveFlowProfile::default();

    // Throttled by the window: goodput-derived BDP stays far below the
    // window, so the estimator path must stay silent at this RTT.
    for step in 1..=3 {
        stats.flow_control.received_bytes += MIB;
        sampler.observe(&mut profile, &stats, 1_000 + step * 1_000);
    }
    assert_eq!(
        (
            profile.connection_receive_floor,
            profile.stream_receive_floor,
        ),
        (0, 0),
    );

    stats.frame_rx.stream_data_blocked += 1;
    stats.frame_rx.data_blocked += 1;
    sampler.observe(&mut profile, &stats, 5_000);
    assert_eq!(profile.stream_receive_floor, 16 * MIB);
    assert_eq!(profile.connection_receive_floor, 0);

    for step in 6..=7 {
        stats.flow_control.received_bytes += MIB;
        stats.frame_rx.data_blocked += 1;
        sampler.observe(&mut profile, &stats, step * 1_000);
    }
    assert_eq!(profile.connection_receive_floor, 16 * MIB);
}

#[test]
fn metric_tracker_counts_post_close_reads_once() {
    const DELIVERED: u64 = 1 << 50;
    let totals = &quic_metrics().totals.flow_received_bytes;
    let before = totals.load(Ordering::Relaxed);
    let mut tracker = QuicMetricTracker::default();
    let stats = quinn::ConnectionStats::default();
    tracker.sample(stats);
    tracker.close(stats);
    let mut drained = stats;
    drained.flow_control.received_bytes = DELIVERED;
    tracker.finish(drained);

    assert!(totals.load(Ordering::Relaxed).wrapping_sub(before) >= DELIVERED);
    tracker.sample(stats);
    assert!(tracker.id.is_none());
}

#[test]
fn send_deadline_is_bounded_by_rtt() {
    assert_eq!(
        bounded_quic_send_timeout(Duration::ZERO),
        Duration::from_secs(1)
    );
    assert_eq!(
        bounded_quic_send_timeout(Duration::from_millis(250)),
        Duration::from_secs(1)
    );
    assert_eq!(
        bounded_quic_send_timeout(Duration::from_secs(2)),
        Duration::from_secs(5)
    );
    assert_eq!(elapsed_since_millis(20_000, 0), Duration::ZERO);
    assert_eq!(
        elapsed_since_millis(20_000, 19_990),
        Duration::from_millis(10)
    );
}

#[test]
fn repeated_timeouts_or_long_silence_retire() {
    assert!(!should_retire_path(
        Duration::from_secs(3),
        Duration::from_secs(10),
        PATH_TIMEOUT_STREAK,
        0,
        Duration::from_secs(4),
        Duration::from_secs(10),
    ));
    assert!(should_retire_path(
        Duration::from_secs(4),
        Duration::ZERO,
        PATH_TIMEOUT_STREAK,
        0,
        Duration::from_secs(4),
        Duration::from_secs(10),
    ));
    assert!(!should_retire_path(
        Duration::from_secs(10),
        Duration::from_secs(10),
        0,
        1,
        Duration::from_secs(4),
        Duration::from_secs(10),
    ));
    assert!(should_retire_path(
        Duration::ZERO,
        Duration::from_secs(10),
        0,
        PATH_MIN_UNACKED_SENDS,
        Duration::from_secs(4),
        Duration::from_secs(10),
    ));
}
#[test]
fn ack_progress_clears_wait_and_stale_completion_cannot_rearm() {
    let h = health(3, 0, 2, 42);
    assert!(h.note_ack_progress(4));
    assert!(!h.complete_send(QuicSendToken::new(0, 3, 3, 10), SendCompletion::Timeout, 4,));
    assert_eq!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
    assert_eq!(
        timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
        0
    );
}

#[test]
fn historical_losses_do_not_count_as_current_unacked_sends() {
    let h = health(95, 0, 0, 0);
    h.sampled_sent_ack_eliciting_packets
        .store(100, Ordering::Release);
    assert!(h.complete_send(
        QuicSendToken::new(0, 95, 100, 10),
        SendCompletion::Timeout,
        95,
    ));
    h.sampled_sent_ack_eliciting_packets
        .store(101, Ordering::Release);
    assert_eq!(h.unacked_sends_since_wait(), 1);
    assert!(!should_retire_path(
        Duration::from_secs(10),
        Duration::from_secs(10),
        0,
        h.unacked_sends_since_wait(),
        Duration::from_secs(4),
        Duration::from_secs(10),
    ));
}

#[test]
fn timeout_streak_is_scoped_to_ack_epoch() {
    let h = health(0, 0, 0, 0);
    assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 10), SendCompletion::Timeout, 0,));
    assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 20), SendCompletion::Timeout, 0,));
    assert_eq!(
        timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
        2
    );
    assert_ne!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
}

#[test]
fn concurrent_send_completion_keeps_earliest_baseline() {
    let h = health(0, 0, 0, 0);
    assert!(h.complete_send(
        QuicSendToken::new(0, 0, 20, 200),
        SendCompletion::Success,
        0,
    ));
    assert!(h.complete_send(
        QuicSendToken::new(0, 0, 10, 100),
        SendCompletion::Success,
        0,
    ));
    h.sampled_sent_ack_eliciting_packets
        .store(20, Ordering::Release);
    assert_eq!(h.waiting_sent_baseline.load(Ordering::Acquire), 10);
    assert_eq!(h.waiting_since_ms.load(Ordering::Acquire), 100);
    assert_eq!(h.unacked_sends_since_wait(), 10);
}

#[test]
fn successful_send_preserves_first_stall_deadline() {
    let h = health(0, 0, 2, 42);
    assert!(h.complete_send(QuicSendToken::new(0, 0, 0, 100), SendCompletion::Success, 0,));
    assert_eq!(h.waiting_since_ms.load(Ordering::Acquire), 42);
    assert_eq!(
        timeout_state_streak(h.timeout_state.load(Ordering::Acquire)),
        0
    );
}

#[test]
fn ack_progress_invalidates_all_old_send_tokens() {
    let h = health(0, 0, 0, 0);
    let token = QuicSendToken::new(0, 0, 0, 100);
    assert!(h.note_ack_progress(1));
    assert!(!h.complete_send(token, SendCompletion::Success, 1));
    assert_eq!(h.ack_state.load(Ordering::Acquire) & PATH_WAITING, 0);
}
