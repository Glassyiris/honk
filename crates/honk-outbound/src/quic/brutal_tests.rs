use super::*;
use congestion::ControllerFactory;

fn controller(rate_bps: u64) -> Box<dyn congestion::Controller> {
    Arc::new(BrutalConfig::from_bps(rate_bps)).build(Instant::now(), 1200)
}

#[test]
fn window_is_rate_times_rtt() {
    let cc = controller(100_000_000);
    // Initial RTT guess 333ms: BDP = 12.5e6 × 0.333 ≈ 4.16 MB.
    let w = cc.window();
    assert!((4_000_000..4_400_000).contains(&w), "window {w}");
}

#[test]
fn bdp_divides_before_u64_clamp() {
    let brutal = Brutal {
        rate: 1_000_000_000_000_000,
        rtt: Duration::from_secs(1),
        mtu: 1200,
    };
    assert_eq!(brutal.bdp(), 1_000_000_000_000_000);
}

#[test]
fn loss_never_shrinks_window() {
    let mut cc = controller(50_000_000);
    let before = cc.window();
    cc.on_congestion_event(Instant::now(), Instant::now(), true, 12000);
    cc.on_congestion_event(Instant::now(), Instant::now(), false, 0);
    assert_eq!(cc.window(), before);
}
