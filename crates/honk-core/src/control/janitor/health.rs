use super::{
    AUX_MAP_CAPACITY, AUX_MAP_PRESSURE_WATERMARK, AuxScanResult, BpfJanitor,
    CONN_STATE_PRESSURE_WATERMARK,
};
use honk_ebpf_common::conn::BpfStatsKey;
use tracing::warn;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(super) enum AuxMap {
    RedirectTrack,
    RoutingHandoff,
    TcpRequestBindings,
}

impl AuxMap {
    pub(super) const ALL: [Self; 3] = [
        Self::RedirectTrack,
        Self::RoutingHandoff,
        Self::TcpRequestBindings,
    ];
    pub(super) const COUNT: usize = Self::ALL.len();

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::RedirectTrack => "redirect-track",
            Self::RoutingHandoff => "routing-handoff",
            Self::TcpRequestBindings => "tcp-request-bindings",
        }
    }
}

#[derive(Default)]
pub(super) struct HealthLatches {
    pub(super) last_failures: [u64; BpfStatsKey::COUNT as usize],
    pub(super) aux_pressure_warned: [bool; AuxMap::COUNT],
    overflow_warned: bool,
    udp_pressure_warned: bool,
    tcp_pressure_warned: bool,
    pub(super) occupancy_warned: bool,
}

impl BpfJanitor {
    pub(super) async fn check_map_health(
        &self,
        utilization: f64,
        pressure_active: bool,
        aux_scans: [AuxScanResult; AuxMap::COUNT],
        latches: &mut HealthLatches,
    ) {
        let ebpf = self.ebpf.read().await;
        let mut stats = [0; BpfStatsKey::COUNT as usize];
        for key in BpfStatsKey::ALL {
            stats[key as usize] = ebpf.get_bpf_stats(key as u32).unwrap_or(None).unwrap_or(0);
        }
        drop(ebpf);
        let udp_overflow = stats[BpfStatsKey::UdpConnOverflow as usize];
        let tcp_overflow = stats[BpfStatsKey::TcpConnOverflow as usize];

        // Cumulative counters retain history after pressure ends; only a new
        // episode should promote repeated diagnostics back to WARN.
        if !pressure_active {
            latches.overflow_warned = false;
            latches.udp_pressure_warned = false;
            latches.tcp_pressure_warned = false;
            latches.occupancy_warned = false;
        }
        let first_in_episode =
            |warned: &mut bool| pressure_active && !std::mem::replace(warned, true);

        if udp_overflow > 0 || tcp_overflow > 0 {
            crate::logging::warn_on_entry!(
                first_in_episode(&mut latches.overflow_warned),
                "BPF janitor: map overflow detected — UDP={}, TCP={}. \
                 Some packets may be falling back to slower paths. \
                 Consider increasing map capacity.",
                udp_overflow,
                tcp_overflow
            );
        }
        for key in BpfStatsKey::ALL {
            let message = match key {
                BpfStatsKey::UdpConnOverflow | BpfStatsKey::TcpConnOverflow => continue,
                BpfStatsKey::RedirectTrackInsertFailure
                | BpfStatsKey::RoutingHandoffInsertFailure => {
                    "BPF janitor: auxiliary map insert failures increased"
                }
                BpfStatsKey::SocketIdentityCaptureFailure => {
                    "BPF janitor: socket identity capture failures increased; affected sockets lost process-name matching"
                }
                BpfStatsKey::TcpRequestProofInsertFailure
                | BpfStatsKey::TcpChildProofStorageFailure
                | BpfStatsKey::TcpPublisherClaimFailure => {
                    "BPF janitor: TCP ownership publication failures increased; affected connections were refused"
                }
            };
            let failures = stats[key as usize];
            if failures > latches.last_failures[key as usize] {
                warn!(counter = key.label(), failures, "{message}");
            }
        }
        latches.last_failures = stats;

        for map in AuxMap::ALL {
            let index = map as usize;
            let scan = aux_scans[index];
            let entries = scan.scanned;
            let utilization = entries as f64 / AUX_MAP_CAPACITY as f64;
            if utilization >= AUX_MAP_PRESSURE_WATERMARK {
                if !latches.aux_pressure_warned[index] {
                    warn!(
                        map = map.label(),
                        entries,
                        capacity = AUX_MAP_CAPACITY,
                        utilization_pct = utilization * 100.0,
                        "BPF janitor: auxiliary map scan high-water indicates pressure"
                    );
                    latches.aux_pressure_warned[index] = true;
                }
            } else if scan.complete {
                // A bounded scan is only a lower bound; a complete one proves
                // the map left pressure.
                latches.aux_pressure_warned[index] = false;
            }
        }

        if udp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(&mut latches.udp_pressure_warned),
                "BPF janitor: UDP conn state map under heavy pressure (overflow={}). \
                 Consider increasing udp_conn_state_map capacity or reducing UDP connection timeout.",
                udp_overflow
            );
        }
        if tcp_overflow > 100 {
            crate::logging::warn_on_entry!(
                first_in_episode(&mut latches.tcp_pressure_warned),
                "BPF janitor: TCP conn state map under heavy pressure (overflow={}). \
                 Consider increasing tcp_conn_state_map capacity or reducing TCP connection timeout.",
                tcp_overflow
            );
        }

        if utilization >= CONN_STATE_PRESSURE_WATERMARK {
            crate::logging::warn_on_entry!(
                first_in_episode(&mut latches.occupancy_warned),
                "BPF janitor: conn-state map occupancy ~{:.1}% — sweeping every tick; \
                 consider increasing MAX_CONN_STATE_NUM if this persists",
                utilization * 100.0
            );
        }
    }
}
