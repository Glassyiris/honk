use super::*;

fn fixture() -> (Arc<TransportQuality>, CarrierSampler, CarrierSample) {
    let quality = Arc::new(TransportQuality::default());
    quality.enable();
    let sampler = CarrierSampler::new(Arc::clone(&quality), false);
    let sample = CarrierSample {
        at: Instant::now(),
        rtt: Some(Duration::from_millis(40)),
        acknowledged: Some(0),
        transmitted: Some(0),
        lost: Some(0),
        lost_bytes: Some(0),
        tx_bytes: Some(0),
        rx_bytes: Some(0),
        tx_datagrams: Some(0),
        rx_datagrams: Some(0),
    };
    (quality, sampler, sample)
}

fn step(sample: &mut CarrierSample, rtt_ms: u64, lost: u64) -> CarrierSample {
    sample.at += Duration::from_secs(1);
    sample.rtt = Some(Duration::from_millis(rtt_ms));
    sample.acknowledged = sample.acknowledged.map(|n| n + 8192);
    sample.transmitted = sample.transmitted.map(|n| n + 64);
    sample.lost = sample.lost.map(|n| n + lost);
    sample.lost_bytes = sample.lost_bytes.map(|n| n + lost * 512);
    sample.tx_bytes = sample.tx_bytes.map(|n| n + 8192);
    sample.rx_bytes = sample.rx_bytes.map(|n| n + 4096);
    *sample
}

#[test]
fn trained_rtt_requires_sustain_and_rearms_without_refreshing_a_continuing_episode() {
    let (quality, mut sampler, mut sample) = fixture();
    sampler.observe(sample);
    for _ in 0..4 {
        sampler.observe(step(&mut sample, 40, 0));
    }
    for _ in 0..2 {
        sampler.observe(step(&mut sample, 80, 0));
        assert!(quality.snapshot()[0].is_none());
    }
    sampler.observe(step(&mut sample, 80, 0));
    let first = quality.snapshot()[0].unwrap();
    assert_eq!(first.reason, PressureReason::Rtt);
    assert_eq!(first.observed_at, sample.at);
    for _ in 0..65 {
        sampler.observe(step(&mut sample, 80, 0));
    }
    assert_eq!(
        quality.snapshot()[0].unwrap().observed_at,
        first.observed_at
    );
    sampler.observe(step(&mut sample, 40, 0));
    sampler.observe(step(&mut sample, 80, 0));
    assert_eq!(
        quality.snapshot()[0].unwrap().observed_at,
        first.observed_at
    );
    for _ in 0..2 {
        sampler.observe(step(&mut sample, 40, 0));
    }
    for _ in 0..3 {
        sampler.observe(step(&mut sample, 80, 0));
    }
    assert_eq!(quality.snapshot()[0].unwrap().observed_at, sample.at);
    assert!(quality.snapshot()[1].is_none());
}

#[test]
fn outgoing_loss_is_independent_of_rtt_but_requires_payload_and_packet_volume() {
    let (quality, mut sampler, mut sample) = fixture();
    sample.rtt = None;
    sampler.observe(sample);
    for _ in 0..3 {
        let mut next = step(&mut sample, 40, 4);
        next.rtt = None;
        sampler.observe(next);
    }
    assert_eq!(quality.snapshot()[0].unwrap().reason, PressureReason::Loss);

    for mode in 0..4 {
        let (quality, mut sampler, mut sample) = fixture();
        sampler.observe(sample);
        for _ in 0..8 {
            let before = sample;
            step(&mut sample, 40, 4);
            match mode {
                0 => sample.tx_bytes = before.tx_bytes, // RX-only ACKs are not send loss.
                1 => sample.transmitted = before.transmitted.map(|n| n + 31),
                2 => sample.lost_bytes = None,
                _ => sample.lost = before.lost.map(|n| n + 3), // Below five percent.
            }
            sampler.observe(sample);
        }
        assert!(quality.snapshot()[0].is_none(), "mode {mode}");
    }

    let (quality, mut sampler, mut sample) = fixture();
    sample.tx_bytes = None;
    sample.rx_bytes = None;
    sampler.observe(sample);
    for _ in 0..3 {
        step(&mut sample, 40, 4);
        sample.tx_datagrams = sample.tx_datagrams.map(|n| n + 32);
        sampler.observe(sample);
    }
    assert_eq!(quality.snapshot()[0].unwrap().reason, PressureReason::Loss);
}

#[test]
fn unknown_idle_resets_and_out_of_order_samples_do_not_invent_episodes() {
    for interruption in 0..6 {
        let (quality, mut sampler, mut sample) = fixture();
        sampler.observe(sample);
        for _ in 0..4 {
            sampler.observe(step(&mut sample, 40, 0));
        }
        for _ in 0..2 {
            sampler.observe(step(&mut sample, 80, 4));
        }
        match interruption {
            0 => {
                // Idle counters cannot preserve a sustain streak.
                sample.at += Duration::from_secs(1);
                sampler.observe(sample);
            }
            1 => {
                // An unknown RTT/loss window is not recovery or suspicion.
                step(&mut sample, 80, 4);
                let mut unknown = sample;
                unknown.rtt = None;
                unknown.lost_bytes = None;
                sampler.observe(unknown);
            }
            2 => {
                // Counter reset seeds, rather than interpreting lifetime loss.
                let at = sample.at + Duration::from_secs(1);
                sample = fixture().2;
                sample.at = at;
                sampler.observe(sample);
            }
            3 => {
                sample.at += Duration::from_secs(11);
                sampler.observe(sample);
            }
            4 => {
                // Tiny payload cannot be accumulated across windows.
                sample.at += Duration::from_secs(1);
                sample.tx_bytes = sample.tx_bytes.map(|n| n + 8);
                sample.rx_bytes = sample.rx_bytes.map(|n| n + 8);
                sample.acknowledged = sample.acknowledged.map(|n| n + 8);
                sampler.observe(sample);
            }
            _ => {
                // Missing ACK progress is not fresh RTT evidence.
                let acknowledged = sample.acknowledged;
                step(&mut sample, 80, 4);
                sample.acknowledged = acknowledged;
                sampler.observe(sample);
            }
        }
        sampler.observe(step(&mut sample, 80, 4));
        assert!(
            quality.snapshot()[0].is_none(),
            "interruption {interruption}"
        );
    }

    let (quality, mut sampler, mut sample) = fixture();
    sampler.observe(sample);
    for _ in 0..4 {
        sampler.observe(step(&mut sample, 40, 0));
    }
    for _ in 0..2 {
        sampler.observe(step(&mut sample, 80, 0));
    }
    let mut stale = sample;
    stale.at -= Duration::from_secs(2);
    stale.tx_bytes = Some(0);
    sampler.observe(stale);
    sampler.observe(step(&mut sample, 80, 0));
    assert_eq!(quality.snapshot()[0].unwrap().observed_at, sample.at);
}

#[test]
fn runtime_coalesces_carriers_and_disabled_history_cannot_publish() {
    let quality = Arc::new(TransportQuality::default());
    let mut sampler = CarrierSampler::new(Arc::clone(&quality), false);
    let mut sample = fixture().2;
    sampler.observe(sample);
    for _ in 0..8 {
        sampler.observe(step(&mut sample, 80, 8));
    }
    quality.enable();
    sampler.observe(step(&mut sample, 80, 8));
    assert!(quality.snapshot()[0].is_none());
    for _ in 0..3 {
        sampler.observe(step(&mut sample, 80, 8));
    }
    let at = quality.snapshot()[0].unwrap().observed_at;
    quality.report(false, PressureReason::Rtt, at + Duration::from_secs(29));
    quality.report(false, PressureReason::Both, at - Duration::from_secs(1));
    assert_eq!(quality.snapshot()[0].unwrap().observed_at, at);
    quality.report(true, PressureReason::Rtt, at);
    assert_eq!(quality.snapshot()[1].unwrap().observed_at, at);
    quality.report(false, PressureReason::Both, at + Duration::from_secs(30));
    assert_eq!(quality.snapshot()[0].unwrap().reason, PressureReason::Both);
}
