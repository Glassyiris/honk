use super::*;
use std::sync::atomic::Ordering;

#[test]
fn reverse_admission_pressure_has_separate_enter_and_exit_watermarks() {
    assert!(!tick::admission_pressured(false, 0.69999));
    assert!(tick::admission_pressured(false, 0.70));
    assert!(tick::admission_pressured(true, 0.65));
    assert!(tick::admission_pressured(true, 0.60));
    assert!(!tick::admission_pressured(true, 0.59999));
}

#[tokio::test]
async fn tick_publishes_conn_pressure_without_using_auxiliary_pressure() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    for port in 0..((AUX_MAP_CAPACITY as f64 * 0.9) as u16) {
        model.redirect_track_store(&RedirectTuple::from_tuples(&test_tuple(port, 17)), &RedirectEntry::default())?;
    }
    let pressure = Arc::clone(&model.admission_pressure);
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(backend, Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    // No scan or synthetic clock is needed to exercise the production tick's
    // gauge-to-publication path. Auxiliary occupancy is high throughout.
    for (utilization, expected) in [(0.0, false), (0.75, true), (0.65, true), (0.59, false)] {
        let deletes = crate::ebpf::USERSPACE_CONN_STATE_DELETES.load(Ordering::Relaxed);
        state.gauge.calibrate((f64::from(MAX_CONN_STATE_NUM) * utilization) as u64, 0, 0, deletes);
        janitor.tick(&mut state, start, None).await?;
        assert_eq!(pressure.load(Ordering::Relaxed), expected);
    }
    Ok(())
}
