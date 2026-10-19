use super::*;
use honk_ebpf_common::RoutingHandoffEntry;

#[tokio::test]
async fn auxiliary_occupancy_drives_real_ticks_and_drains_backlog() -> anyhow::Result<()> {
    let count = (AUX_MAP_CAPACITY as f64 * CONN_STATE_PRESSURE_WATERMARK).ceil() as u16;
    let now_ns = REDIRECT_TRACK_TIMEOUT_NS + 1;
    for handoff in [false, true] {
        let mut model = MockEbpfBackend::new();
        for port in 0..count {
            let key = test_tuple(port, IPPROTO_TCP);
            if handoff {
                model.tcp_conn_state_store(&key, &test_state(TcpState::TcpStateActive, now_ns))?;
            } else {
                model.redirect_track_store(&RedirectTuple::from_tuples(&key), &RedirectEntry::default())?;
            }
        }
        if handoff {
            for key in model.tcp_conn_states.keys() {
                model.routing_handoffs.lock().insert(*key, RoutingHandoffEntry::default());
            }
        }
        let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
        let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
        let start = tokio::time::Instant::now();
        let mut state = tick::TickState::new(start);
        let max_ticks = usize::from(count).div_ceil(JANITOR_MAX_CANDIDATES) + 1;
        let mut previous = u64::from(count);
        for tick in 1..=max_ticks {
            janitor.tick(&mut state, start + Duration::from_secs(tick as u64 * 2), Some(now_ns)).await?;
            if tick == 1 {
                assert!(state.pressure.active, "aux occupancy alone must enter pressure mode");
            }
            let (redirect, handoffs) = backend.read().await.aux_occupancy()?;
            let remaining = if handoff { handoffs } else { redirect };
            assert!(previous - remaining <= JANITOR_MAX_CANDIDATES as u64);
            assert!(remaining < previous || previous == 0, "every pressured tick must make progress");
            previous = remaining;
        }
        assert_eq!(previous, 0, "bounded ticks must drain the auxiliary map");
    }
    Ok(())
}

#[tokio::test]
async fn low_auxiliary_occupancy_keeps_steady_tick_cadence() -> anyhow::Result<()> {
    let mut model = MockEbpfBackend::new();
    model.redirect_track_store(&RedirectTuple::from_tuples(&test_tuple(1, 17)), &RedirectEntry::default())?;
    let backend: Arc<RwLock<Box<dyn EbpfBackend>>> = Arc::new(RwLock::new(Box::new(model)));
    let janitor = BpfJanitor::new(Arc::clone(&backend), Arc::new(TcpFlowPins::default()));
    let start = tokio::time::Instant::now();
    let mut state = tick::TickState::new(start);
    janitor.tick(&mut state, start + Duration::from_secs(2), Some(REDIRECT_TRACK_TIMEOUT_NS + 1)).await?;
    assert!(!state.pressure.active);
    assert_eq!(backend.read().await.aux_occupancy()?, (1, 0));
    janitor.tick(&mut state, start + Duration::from_secs(60), Some(REDIRECT_TRACK_TIMEOUT_NS + 1)).await?;
    assert_eq!(backend.read().await.aux_occupancy()?, (0, 0));
    Ok(())
}
