use super::*;
use crate::ebpf::mock::MockTelemetryFaults;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn telemetry_read_failures_before_any_sample_still_run_steady_sweeps() -> anyhow::Result<()> {
    for failed_signal in 0..3 {
        let mut model = MockEbpfBackend::new();
        model.redirect_track_store(
            &RedirectTuple::from_tuples(&test_tuple(1, 17)),
            &RedirectEntry::default(),
        )?;
        let faults = Arc::clone(&model.telemetry_faults);
        *faults.lock() = MockTelemetryFaults {
            stats: failed_signal == 0,
            conn_occupancy: failed_signal == 1,
            aux_occupancy: failed_signal == 2,
        };
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
        let start = tokio::time::Instant::now();
        let mut state = tick::TickState::new(start);
        janitor
            .tick(
                &mut state,
                start + Duration::from_secs(60),
                Some(REDIRECT_TRACK_TIMEOUT_NS + 1),
            )
            .await?;
        *faults.lock() = MockTelemetryFaults::default();
        assert_eq!(backend.read().await.aux_occupancy()?, (0, 0));
        assert!(!state.pressure.active);
    }
    Ok(())
}

#[tokio::test]
async fn failed_stats_reads_keep_last_overflow_samples_and_still_sweep() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    model
        .bpf_stats
        .insert(BpfStatsKey::UdpConnOverflow as u32, 7);
    model
        .bpf_stats
        .insert(BpfStatsKey::TcpConnOverflow as u32, 11);
    model.redirect_track_store(
        &RedirectTuple::from_tuples(&test_tuple(1, 17)),
        &RedirectEntry::default(),
    )?;
    let faults = Arc::clone(&model.telemetry_faults);
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    janitor.tick(&mut state, start, None).await?;
    faults.lock().stats = true;
    for round in 1..=4 {
        janitor
            .tick(
                &mut state,
                start + Duration::from_secs(round * 2),
                Some(REDIRECT_TRACK_TIMEOUT_NS + 1),
            )
            .await?;
        assert!(
            state.pressure.active,
            "failed reads cannot establish quiet rounds"
        );
        assert_eq!(
            (
                state.pressure.last_udp_overflow,
                state.pressure.last_tcp_overflow
            ),
            (7, 11)
        );
    }
    faults.lock().stats = false;
    for round in 5..=7 {
        janitor
            .tick(&mut state, start + Duration::from_secs(round * 2), None)
            .await?;
    }
    assert!(
        !state.pressure.active,
        "fresh quiet samples can release pressure"
    );
    assert_eq!(backend.read().await.aux_occupancy()?, (0, 0));
    Ok(())
}

#[tokio::test]
async fn failed_conn_reads_keep_sampled_pressure_and_skip_stale_calibration() -> anyhow::Result<()>
{
    let mut model = MockEbpfBackend::new();
    model.redirect_track_store(
        &RedirectTuple::from_tuples(&test_tuple(1, 17)),
        &RedirectEntry::default(),
    )?;
    let faults = Arc::clone(&model.telemetry_faults);
    let admission = Arc::clone(&model.admission_pressure);
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    state.gauge.calibrate(
        u64::from(MAX_CONN_STATE_NUM) * 9 / 10,
        0,
        0,
        crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed),
    );
    janitor.tick(&mut state, start, None).await?;
    assert!(admission.load(Ordering::Relaxed));
    faults.lock().conn_occupancy = true;
    // A failed read must retain its estimate, not reinterpret stale raw counters
    // using a changed gauge or userspace-delete count.
    state.gauge.calibrate(
        0,
        0,
        0,
        crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed),
    );
    let before = state.gauge.drift;
    for round in 1..=4 {
        janitor
            .tick(
                &mut state,
                start + Duration::from_secs(round * 2),
                Some(REDIRECT_TRACK_TIMEOUT_NS + 1),
            )
            .await?;
        assert!(state.pressure.active);
        assert!(admission.load(Ordering::Relaxed));
        assert_eq!(
            state.gauge.drift, before,
            "missing counters must not recalibrate the gauge"
        );
    }
    assert_eq!(backend.read().await.aux_occupancy()?, (0, 0));
    faults.lock().conn_occupancy = false;
    janitor
        .tick(&mut state, start + Duration::from_secs(10), None)
        .await?;
    assert!(
        !admission.load(Ordering::Relaxed),
        "a fresh low sample clears admission pressure"
    );
    Ok(())
}

#[tokio::test]
async fn failed_aux_reads_keep_pressured_cadence_and_candidate_capacity() -> anyhow::Result<()> {
    let count = AUX_MAP_CAPACITY * 9 / 10;
    let mut model = MockEbpfBackend::new();
    for port in 0..count as u16 {
        model.redirect_track_store(
            &RedirectTuple::from_tuples(&test_tuple(port, 17)),
            &RedirectEntry::default(),
        )?;
    }
    let faults = Arc::clone(&model.telemetry_faults);
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    janitor.tick(&mut state, start, None).await?;
    faults.lock().aux_occupancy = true;
    for round in 1..=4 {
        janitor
            .tick(
                &mut state,
                start + Duration::from_secs(round * 2),
                Some(REDIRECT_TRACK_TIMEOUT_NS + 1),
            )
            .await?;
        assert!(state.pressure.active);
    }
    faults.lock().aux_occupancy = false;
    assert_eq!(
        backend.read().await.aux_occupancy()?.0,
        (count - JANITOR_MAX_CANDIDATES * 4) as u64
    );
    Ok(())
}

#[derive(Clone, Default)]
struct LogSink(Arc<parking_lot::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn telemetry_read_warnings_are_throttled() {
    const CHILD: &str = "HONK_JANITOR_TELEMETRY_LOG_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The macro's static throttle must not inherit another test's failures.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "control::janitor::tests::telemetry::telemetry_read_warnings_are_throttled",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let sink = LogSink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..64 {
            let result = Err(anyhow::anyhow!("injected read fault").context("BPF telemetry"));
            assert_eq!(tick::telemetry_sample::<u64>("test signal", result), None);
        }
    });
    let logs = String::from_utf8(sink.0.lock().clone()).unwrap();
    assert_eq!(
        logs.lines().filter(|line| line.contains("WARN")).count(),
        1,
        "{logs}"
    );
    assert_eq!(
        logs.lines().filter(|line| line.contains("DEBUG")).count(),
        63,
        "{logs}"
    );
    assert!(
        logs.contains("BPF telemetry: injected read fault"),
        "{logs}"
    );
}
