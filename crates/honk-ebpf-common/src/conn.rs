use core::mem;

use crate::{RoutingMeta, TASK_COMM_LEN};
use network_types::{
    eth::EthHdr,
    icmp::Icmpv6Hdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

/// Unified connection state stored in CONN_STATE_MAP (hash map).
/// Used by both eBPF programs (for conntrack/lifecycle) and userspace janitor
/// (for cleanup).  All fields are repr(C) so the binary layout is identical
/// regardless of compiler or target triple.
///
/// Layout (repr(C), total 56 bytes):
///   offset 0:  is_wan_ingress_direction: u8
///   offset 1:  state: u8 (0=active, 1=closing for TCP)
///   offset 8:  last_seen_ns: u64 (monotonic timestamp from bpf_ktime_get_ns)
///   offset 16: meta: RoutingMeta (cached routing decision)
///   offset 24: mac: [u8; 6] (source MAC)
///   offset 30: padding: [u8; 2]
///   offset 32: pname: [u8; TASK_COMM_LEN] (process name)
///   offset 48: pid: u32
///   offset 52: decision_cookie: u32 (NFQUEUE staging; fills the former tail
///              padding, so the map value size is unchanged)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnState {
    pub is_wan_ingress_direction: u8,
    pub state: u8,
    pub last_seen_ns: u64,
    pub meta: RoutingMeta,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
    pub pname: [u8; TASK_COMM_LEN],
    pub pid: u32,
    /// Random per-decision-round cookie stamped when the datapath parks a
    /// UDP flow in `UdpDecisionState::Pending`.  The control plane must
    /// compare it against its own copy before writing a decision back, or a
    /// re-used five-tuple (old entry swept, new flow same tuple) could
    /// receive the previous flow's verdict.
    pub decision_cookie: u32,
}

const _CONN_STATE_SIZE: () = assert!(core::mem::size_of::<ConnState>() == 56);
const _CONN_STATE_META_OFFSET: () = assert!(core::mem::offset_of!(ConnState, meta) == 16);
const _CONN_STATE_PID_OFFSET: () = assert!(core::mem::offset_of!(ConnState, pid) == 48);
const _CONN_STATE_COOKIE_OFFSET: () =
    assert!(core::mem::offset_of!(ConnState, decision_cookie) == 52);

// Matches the C enum bpf_stats_key.
// The C enum's underlying type defaults to int (32-bit); use u32 for compatibility.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfStatsKey {
    UdpConnOverflow = 0,
    TcpConnOverflow = 1,
    RedirectTrackInsertFailure = 2,
    RoutingHandoffInsertFailure = 3,
    CookiePidInsertFailure = 4,
}

/// CONN_STATE_MAP capacity, shared by the eBPF map definition and the
/// userspace janitor's pressure gauge.  ~68 MB kernel memory at 524,288
/// entries.
pub const MAX_CONN_STATE_NUM: u32 = 65536 * 8;

/// Conn-state entry timeouts, applied lazily by the eBPF datapath on every
/// hit and proactively by the userspace janitor sweep.  Both sides must use
/// the same values.
pub const TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s
pub const TCP_CONN_STATE_CLOSING_TIMEOUT_NS: u64 = 10_000_000_000; // 10 s
pub const UDP_CONN_STATE_TIMEOUT_NS: u64 = 120_000_000_000; // 120 s backstop

/// Slots of the `CONN_STATE_OCCUPANCY` per-CPU array: the datapath's
/// cumulative successful inserts / deletes into CONN_STATE_MAP.  Userspace
/// derives the live occupancy estimate as
/// `inserts - ebpf_deletes - janitor_deletes`, recalibrated against the exact
/// count on every janitor sweep.
pub const OCCUPANCY_INSERTS: u32 = 0;
pub const OCCUPANCY_EBPF_DELETES: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum TcpState {
    TcpStateActive = 0,
    TcpStateClosing = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParseTransportCtx {
    pub ethh: EthHdr,         // struct ethhdr
    pub iph: Ipv4Hdr,         // struct ipv4hdr
    pub ipv6h: Ipv6Hdr,       // struct ipv6hdr
    pub icmp6h: Icmpv6Hdr,    // struct icmp6hdr
    pub tcph: TcpHdr,         // struct tcphdr
    pub udph: UdpHdr,         // struct udphdr
    pub ihl: u8,              // IP header length in 4-byte units
    pub l4proto: u8,          // Actual L4 protocol
    pub listener_l4proto: u8, // Listener protocol
    pub pad: u8,              // Alignment padding
}

/// CT_ARGS_HAS_* bit flags.
pub const CT_ARGS_HAS_ROUTING: u8 = 1 << 0;
pub const CT_ARGS_HAS_MAC: u8 = 1 << 1;
pub const CT_ARGS_HAS_PNAME: u8 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConntrackArgs {
    pub flags: u8, // CT_ARGS_HAS_* bit mask
    pub outbound: u8,
    pub must: u8,
    pub dscp: u8,
    pub mark: u32,
    pub pid: u32,
    pub mac: [u8; 6],
    pub padding: [u8; 2],
    pub pname: [u8; TASK_COMM_LEN],
}

impl ConntrackArgs {
    #[inline(always)]
    pub fn has_routing(&self) -> bool {
        (self.flags & CT_ARGS_HAS_ROUTING) != 0
    }

    #[inline(always)]
    pub fn has_mac(&self) -> bool {
        (self.flags & CT_ARGS_HAS_MAC) != 0
    }

    #[inline(always)]
    pub fn has_pname(&self) -> bool {
        (self.flags & CT_ARGS_HAS_PNAME) != 0
    }

    #[inline(always)]
    pub fn set_routing(&mut self, val: bool) {
        if val {
            self.flags |= CT_ARGS_HAS_ROUTING;
        } else {
            self.flags &= !CT_ARGS_HAS_ROUTING;
        }
    }

    #[inline(always)]
    pub fn set_mac(&mut self, val: bool) {
        if val {
            self.flags |= CT_ARGS_HAS_MAC;
        } else {
            self.flags &= !CT_ARGS_HAS_MAC;
        }
    }

    #[inline(always)]
    pub fn set_pname(&mut self, val: bool) {
        if val {
            self.flags |= CT_ARGS_HAS_PNAME;
        } else {
            self.flags &= !CT_ARGS_HAS_PNAME;
        }
    }

    #[inline(always)]
    pub fn set(
        &mut self,
        dscp: u8,
        pid: u32,
        routing: Option<(&u8, &u32, &u8)>,
        mac: Option<&[u8; 6]>,
        pname: Option<&[u8; TASK_COMM_LEN]>,
    ) {
        *self = unsafe { mem::zeroed() };
        self.dscp = dscp;
        self.pid = pid;

        if let Some((outbound, mark, must)) = routing {
            self.set_routing(true);
            self.outbound = *outbound;
            self.mark = *mark;
            self.must = *must;
        }

        if let Some(mac_addr) = mac {
            self.set_mac(true);
            self.mac.copy_from_slice(mac_addr);
        }

        if let Some(pname_bytes) = pname {
            self.set_pname(true);
            self.pname.copy_from_slice(pname_bytes);
        }
    }

    #[inline(always)]
    pub fn pname_or_null(&self) -> Option<&[u8; TASK_COMM_LEN]> {
        if self.has_pname() {
            Some(&self.pname)
        } else {
            None
        }
    }
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for ConnState {}
