use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};

use parking_lot::Mutex as SyncMutex;
use quinn::Connection;

use super::flow_control::{
    AdaptiveFlowSampler, apply_flow_control_profile, seed_flow_control_profile,
};
use super::path_health::path_now_millis;
use super::{
    AdaptiveFlowProfiles, QUIC_SAMPLE_INTERVAL, QuicMetricEntry, QuicMetricTotals,
    QuicMetricTracker, QuicMetrics,
};

/// Process-wide QUIC path telemetry. Connection labels are intentionally not
/// retained; the snapshot is suitable for the aggregate `/stats` surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicStatsSnapshot {
    pub active_connections: u64,
    pub srtt_us: u64,
    pub cwnd_bytes: u64,
    pub flow_received_bytes: u64,
    pub flow_sent_bytes: u64,
    pub receive_window_bytes: u64,
    pub receive_window_available_bytes: u64,
    pub stream_receive_window_bytes: u64,
    pub send_window_bytes: u64,
    pub send_window_available_bytes: u64,
    pub loss_rate_ppm: u64,
    pub sent_packets: u64,
    pub ack_frames: u64,
    pub lost_packets: u64,
    pub sent_plpmtud_probes: u64,
    pub lost_plpmtud_probes: u64,
    pub current_mtu: u64,
    pub black_holes: u64,
    pub congestion_events: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_datagrams: u64,
    pub rx_datagrams: u64,
    pub tx_ios: u64,
    pub rx_ios: u64,
    pub transport_tx_would_block: u64,
    pub transport_rx_drops: u64,
    pub transport_tx_drops: u64,
    pub session_rx_drops: u64,
    pub send_timeouts: u64,
    pub path_stalls: u64,
}

impl QuicMetricTotals {
    fn add_stats(&self, stats: &quinn::ConnectionStats) {
        self.sent_packets
            .fetch_add(stats.path.sent_packets, Ordering::Relaxed);
        self.ack_frames
            .fetch_add(stats.frame_rx.acks, Ordering::Relaxed);
        self.lost_packets
            .fetch_add(stats.path.lost_packets, Ordering::Relaxed);
        self.sent_plpmtud_probes
            .fetch_add(stats.path.sent_plpmtud_probes, Ordering::Relaxed);
        self.lost_plpmtud_probes
            .fetch_add(stats.path.lost_plpmtud_probes, Ordering::Relaxed);
        self.black_holes
            .fetch_add(stats.path.black_holes_detected, Ordering::Relaxed);
        self.congestion_events
            .fetch_add(stats.path.congestion_events, Ordering::Relaxed);
        self.flow_received_bytes
            .fetch_add(stats.flow_control.received_bytes, Ordering::Relaxed);
        self.flow_sent_bytes
            .fetch_add(stats.flow_control.sent_bytes, Ordering::Relaxed);
        self.tx_bytes
            .fetch_add(stats.udp_tx.bytes, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(stats.udp_rx.bytes, Ordering::Relaxed);
        self.tx_datagrams
            .fetch_add(stats.udp_tx.datagrams, Ordering::Relaxed);
        self.rx_datagrams
            .fetch_add(stats.udp_rx.datagrams, Ordering::Relaxed);
        self.tx_ios.fetch_add(stats.udp_tx.ios, Ordering::Relaxed);
        self.rx_ios.fetch_add(stats.udp_rx.ios, Ordering::Relaxed);
    }

    fn add_received_bytes(&self, bytes: u64) {
        self.flow_received_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

static QUIC_METRICS: LazyLock<QuicMetrics> = LazyLock::new(QuicMetrics::default);

pub(super) fn quic_metrics() -> &'static QuicMetrics {
    &QUIC_METRICS
}

fn register_quic_connection(stats: quinn::ConnectionStats) -> u64 {
    let metrics = quic_metrics();
    let id = metrics
        .next_id
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    metrics.entries.lock().insert(id, QuicMetricEntry { stats });
    id
}

fn update_quic_connection(id: u64, stats: quinn::ConnectionStats) {
    let metrics = quic_metrics();
    if let Some(entry) = metrics.entries.lock().get_mut(&id) {
        entry.stats = stats;
    }
}

fn finish_quic_connection(id: u64, stats: quinn::ConnectionStats) -> bool {
    let metrics = quic_metrics();
    let mut entries = metrics.entries.lock();
    if entries.remove(&id).is_none() {
        return false;
    }
    metrics.totals.add_stats(&stats);
    true
}

impl QuicMetricTracker {
    pub(super) fn sample(&mut self, stats: quinn::ConnectionStats) {
        if self.finished || self.closed_received_bytes.is_some() {
            return;
        }
        match self.id {
            Some(id) => update_quic_connection(id, stats),
            None => self.id = Some(register_quic_connection(stats)),
        }
    }

    pub(super) fn close(&mut self, stats: quinn::ConnectionStats) {
        let Some(id) = self.id else {
            return;
        };
        if finish_quic_connection(id, stats) {
            self.closed_received_bytes = Some(stats.flow_control.received_bytes);
        }
    }

    pub(super) fn finish(&mut self, stats: quinn::ConnectionStats) {
        self.finished = true;
        if let Some(closed) = self.closed_received_bytes.take() {
            quic_metrics()
                .totals
                .add_received_bytes(stats.flow_control.received_bytes.saturating_sub(closed));
        } else if let Some(id) = self.id {
            finish_quic_connection(id, stats);
        }
        self.id = None;
    }
}

fn add_active_stats(snapshot: &mut QuicStatsSnapshot, stats: &quinn::ConnectionStats) {
    snapshot.sent_packets = snapshot
        .sent_packets
        .saturating_add(stats.path.sent_packets);
    snapshot.ack_frames = snapshot.ack_frames.saturating_add(stats.frame_rx.acks);
    snapshot.lost_packets = snapshot
        .lost_packets
        .saturating_add(stats.path.lost_packets);
    snapshot.sent_plpmtud_probes = snapshot
        .sent_plpmtud_probes
        .saturating_add(stats.path.sent_plpmtud_probes);
    snapshot.lost_plpmtud_probes = snapshot
        .lost_plpmtud_probes
        .saturating_add(stats.path.lost_plpmtud_probes);
    snapshot.black_holes = snapshot
        .black_holes
        .saturating_add(stats.path.black_holes_detected);
    snapshot.congestion_events = snapshot
        .congestion_events
        .saturating_add(stats.path.congestion_events);
    snapshot.flow_received_bytes = snapshot
        .flow_received_bytes
        .saturating_add(stats.flow_control.received_bytes);
    snapshot.flow_sent_bytes = snapshot
        .flow_sent_bytes
        .saturating_add(stats.flow_control.sent_bytes);
    snapshot.tx_bytes = snapshot.tx_bytes.saturating_add(stats.udp_tx.bytes);
    snapshot.rx_bytes = snapshot.rx_bytes.saturating_add(stats.udp_rx.bytes);
    snapshot.tx_datagrams = snapshot.tx_datagrams.saturating_add(stats.udp_tx.datagrams);
    snapshot.rx_datagrams = snapshot.rx_datagrams.saturating_add(stats.udp_rx.datagrams);
    snapshot.tx_ios = snapshot.tx_ios.saturating_add(stats.udp_tx.ios);
    snapshot.rx_ios = snapshot.rx_ios.saturating_add(stats.udp_rx.ios);
}

/// Return aggregate QUIC counters and averages for active paths.
pub fn quic_stats_snapshot() -> QuicStatsSnapshot {
    let metrics = quic_metrics();
    let entries = metrics.entries.lock();
    let active = entries.len() as u64;
    let mut snapshot = QuicStatsSnapshot {
        sent_packets: metrics.totals.sent_packets.load(Ordering::Relaxed),
        ack_frames: metrics.totals.ack_frames.load(Ordering::Relaxed),
        lost_packets: metrics.totals.lost_packets.load(Ordering::Relaxed),
        sent_plpmtud_probes: metrics.totals.sent_plpmtud_probes.load(Ordering::Relaxed),
        lost_plpmtud_probes: metrics.totals.lost_plpmtud_probes.load(Ordering::Relaxed),
        black_holes: metrics.totals.black_holes.load(Ordering::Relaxed),
        congestion_events: metrics.totals.congestion_events.load(Ordering::Relaxed),
        flow_received_bytes: metrics.totals.flow_received_bytes.load(Ordering::Relaxed),
        flow_sent_bytes: metrics.totals.flow_sent_bytes.load(Ordering::Relaxed),
        tx_bytes: metrics.totals.tx_bytes.load(Ordering::Relaxed),
        rx_bytes: metrics.totals.rx_bytes.load(Ordering::Relaxed),
        tx_datagrams: metrics.totals.tx_datagrams.load(Ordering::Relaxed),
        rx_datagrams: metrics.totals.rx_datagrams.load(Ordering::Relaxed),
        tx_ios: metrics.totals.tx_ios.load(Ordering::Relaxed),
        rx_ios: metrics.totals.rx_ios.load(Ordering::Relaxed),
        transport_tx_would_block: metrics
            .totals
            .transport_tx_would_block
            .load(Ordering::Relaxed),
        transport_rx_drops: metrics.totals.transport_rx_drops.load(Ordering::Relaxed),
        transport_tx_drops: metrics.totals.transport_tx_drops.load(Ordering::Relaxed),
        session_rx_drops: metrics.totals.session_rx_drops.load(Ordering::Relaxed),
        send_timeouts: metrics.totals.send_timeouts.load(Ordering::Relaxed),
        path_stalls: metrics.totals.path_stalls.load(Ordering::Relaxed),
        active_connections: active,
        ..Default::default()
    };
    let mut rtt_us = 0u128;
    let mut cwnd_bytes = 0u128;
    let mut mtu = 0u128;
    let mut receive_window = 0u128;
    let mut receive_window_available = 0u128;
    let mut stream_receive_window = 0u128;
    let mut send_window = 0u128;
    let mut send_window_available = 0u128;
    for entry in entries.values() {
        add_active_stats(&mut snapshot, &entry.stats);
        rtt_us += entry.stats.path.rtt.as_micros();
        cwnd_bytes += entry.stats.path.cwnd as u128;
        mtu += entry.stats.path.current_mtu as u128;
        receive_window += u128::from(entry.stats.flow_control.receive_window);
        receive_window_available += u128::from(entry.stats.flow_control.receive_window_available);
        stream_receive_window += u128::from(entry.stats.flow_control.stream_receive_window);
        send_window += u128::from(entry.stats.flow_control.send_window);
        send_window_available += u128::from(entry.stats.flow_control.send_window_available);
    }
    let data_sent = snapshot
        .sent_packets
        .saturating_sub(snapshot.sent_plpmtud_probes);
    snapshot.loss_rate_ppm = if data_sent == 0 {
        0
    } else {
        (u128::from(snapshot.lost_packets) * 1_000_000 / u128::from(data_sent)).min(1_000_000)
            as u64
    };
    if active != 0 {
        let active = u128::from(active);
        snapshot.srtt_us = (rtt_us / active).min(u128::from(u64::MAX)) as u64;
        snapshot.cwnd_bytes = (cwnd_bytes / active).min(u128::from(u64::MAX)) as u64;
        snapshot.receive_window_bytes = (receive_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.receive_window_available_bytes =
            (receive_window_available / active).min(u128::from(u64::MAX)) as u64;
        snapshot.stream_receive_window_bytes =
            (stream_receive_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.send_window_bytes = (send_window / active).min(u128::from(u64::MAX)) as u64;
        snapshot.send_window_available_bytes =
            (send_window_available / active).min(u128::from(u64::MAX)) as u64;
        snapshot.current_mtu = (mtu / active).min(u128::from(u64::MAX)) as u64;
    }
    snapshot
}

/// Count a QUIC packet-send timeout observed by the core driver.
pub fn record_quic_send_timeout() {
    quic_metrics()
        .totals
        .send_timeouts
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a QUIC path retired by the core driver watchdog.
pub fn record_quic_path_stall() {
    quic_metrics()
        .totals
        .path_stalls
        .fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_transport_tx_would_block() {
    quic_metrics()
        .totals
        .transport_tx_would_block
        .fetch_add(1, Ordering::Relaxed);
}

pub(super) fn record_transport_rx_drop() {
    quic_metrics()
        .totals
        .transport_rx_drops
        .fetch_add(1, Ordering::Relaxed);
}
pub(super) fn record_transport_tx_drop() {
    quic_metrics()
        .totals
        .transport_tx_drops
        .fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_quic_session_rx_drop() {
    quic_metrics()
        .totals
        .session_rx_drops
        .fetch_add(1, Ordering::Relaxed);
}

/// Keeps one QUIC connection in the aggregate metrics registry until it is
/// closed or the owning pooled client drops it.
pub struct QuicConnectionMonitor {
    conn: Connection,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: Option<tokio::task::AbortHandle>,
}

impl Drop for QuicConnectionMonitor {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.tracker.lock().finish(self.conn.stats());
    }
}

/// Register a pooled QUIC connection for one-second aggregate sampling.
pub fn monitor_quic_connection(conn: &Connection) -> QuicConnectionMonitor {
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    tracker.lock().sample(conn.stats());
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task = crate::runtime::spawn_owned(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + QUIC_SAMPLE_INTERVAL,
            QUIC_SAMPLE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = task_conn.closed() => break,
                _ = ticker.tick() => task_tracker.lock().sample(task_conn.stats()),
            }
        }
        task_tracker.lock().close(task_conn.stats());
    });
    QuicConnectionMonitor {
        conn: conn.clone(),
        tracker,
        task,
    }
}

pub(super) struct QuicClientConnectionMonitor {
    conn: Connection,
    metrics_enabled: Arc<AtomicBool>,
    tracker: Arc<SyncMutex<QuicMetricTracker>>,
    task: Option<tokio::task::AbortHandle>,
}

impl QuicClientConnectionMonitor {
    pub(super) fn enable_metrics(&self) {
        self.metrics_enabled.store(true, Ordering::Release);
        self.tracker.lock().sample(self.conn.stats());
    }
}

impl Drop for QuicClientConnectionMonitor {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.tracker.lock().finish(self.conn.stats());
    }
}

pub(super) fn spawn_quic_client_connection_monitor<C: Send + Sync + 'static>(
    conn: Connection,
    profiles: Arc<AdaptiveFlowProfiles>,
    ipv6: bool,
    owner: Weak<C>,
    metrics_enabled: bool,
) -> QuicClientConnectionMonitor {
    let family = usize::from(ipv6);
    let initial_stats = conn.stats();
    {
        let mut profiles = profiles.lock();
        let profile = &mut profiles[family];
        seed_flow_control_profile(profile, &initial_stats);
        apply_flow_control_profile(&conn, &initial_stats, profile);
    }
    let mut sampler = AdaptiveFlowSampler::new(&initial_stats, path_now_millis());
    let tracker = Arc::new(SyncMutex::new(QuicMetricTracker::default()));
    if metrics_enabled {
        tracker.lock().sample(initial_stats);
    }
    let enabled = Arc::new(AtomicBool::new(metrics_enabled));
    let task_conn = conn.clone();
    let task_tracker = Arc::clone(&tracker);
    let task_enabled = Arc::clone(&enabled);
    let task = crate::runtime::spawn_owned(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + QUIC_SAMPLE_INTERVAL,
            QUIC_SAMPLE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = task_conn.closed() => break,
                _ = ticker.tick() => {
                    if owner.upgrade().is_none() {
                        break;
                    }
                    let stats = task_conn.stats();
                    {
                        let mut profiles = profiles.lock();
                        let profile = &mut profiles[family];
                        sampler.observe(profile, &stats, path_now_millis());
                        apply_flow_control_profile(&task_conn, &stats, profile);
                    }
                    if task_enabled.load(Ordering::Acquire) {
                        task_tracker.lock().sample(stats);
                    }
                }
            }
        }
        let stats = task_conn.stats();
        let mut tracker = task_tracker.lock();
        if task_enabled.load(Ordering::Acquire) {
            tracker.sample(stats);
        }
        tracker.close(stats);
    });
    QuicClientConnectionMonitor {
        conn,
        metrics_enabled: enabled,
        tracker,
        task,
    }
}
