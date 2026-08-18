use super::*;

fn handoff(outbound: u8, must: u8) -> HandoffResult {
    HandoffResult {
        outbound,
        must,
        mark: 0,
        decision_token: 0,
        dscp: 0,
        mac: [0; 6],
        pname: [0; 16],
        pid: 0,
    }
}

#[test]
fn udp_direct_mark_preserves_rule_and_clears_override() {
    assert_eq!(final_udp_rule_mark(true, "direct", 0x1234), 0x1234);
    assert_eq!(final_udp_rule_mark(false, "direct", 0x1234), 0);
    assert_eq!(final_udp_rule_mark(false, "proxy", 0x1234), 0x1234);
}

#[test]
fn udp_domain_modes_reroute_preliminary_group_handoffs() {
    let group = handoff(OutboundIndex::UserBase as u8, 0);
    for mode in [
        DialMode::Domain,
        DialMode::DomainPlus,
        DialMode::DomainPlusPlus,
    ] {
        assert!(ControlPlaneHandle::should_reroute_sniffed_domain(
            mode,
            Some("www.youtube.com"),
            Some(&group)
        ));
    }
}

#[test]
fn tcp_domain_writeback_includes_preliminary_handoffs() {
    for outbound in [OutboundIndex::Direct as u8, OutboundIndex::UserBase as u8] {
        assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
            Some(&handoff(outbound, 0)),
            true,
        ));
    }
    assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
        Some(&handoff(OutboundIndex::ControlPlaneRouting as u8, 0)),
        false,
    ));
    assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
        None, false,
    ));
    assert!(!ControlPlaneHandle::should_write_sniffed_domain_bitmap(
        Some(&handoff(OutboundIndex::Direct as u8, 0)),
        false,
    ));
}

#[test]
fn udp_domain_reroute_preserves_final_decisions() {
    let group = handoff(OutboundIndex::UserBase as u8, 0);
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::Ip,
        Some("www.youtube.com"),
        Some(&group)
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        None,
        Some(&group)
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        Some("www.youtube.com"),
        Some(&handoff(OutboundIndex::Block as u8, 0))
    ));
    assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
        DialMode::DomainPlusPlus,
        Some("www.youtube.com"),
        Some(&handoff(OutboundIndex::UserBase as u8, 1))
    ));
}

#[tokio::test]
async fn handoff_process_fields_decode_and_fail_closed() {
    let mut ho = handoff(OutboundIndex::UserBase as u8, 0);
    assert_eq!(ho.process_name(), None, "zeroed pname means no process");
    assert_eq!(ho.process_path().await, None, "pid 0 means no process");

    ho.pname[..4].copy_from_slice(b"curl");
    assert_eq!(ho.process_name().as_deref(), Some("curl"));

    ho.pid = std::process::id();
    assert!(ho.process_path().await.is_some());
    // A dead/invalid pid just omits the path instead of erroring.
    ho.pid = u32::MAX;
    assert_eq!(ho.process_path().await, None);
}
