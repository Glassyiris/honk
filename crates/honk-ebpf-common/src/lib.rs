#![no_std]

use crate::dae_ip::In6Addr;

pub mod conn;
pub mod dae_ip;
pub mod event;
pub mod redirect_need;
pub mod route;

// Re-export types moved to sub-modules (for honk-core compatibility)
pub use crate::conn::ConnState;
pub use crate::redirect_need::{
    DomainRouting, IPPort, IPPortProto, PIDName, RoutingHandoffEntry, RoutingResult, Tuples,
    TuplesKey,
};
pub use crate::route::{
    MatchSet, MatchSetValue, MatchType, PortRange, ROUTING_GROUP_BITMAP_WORDS, ROUTING_GROUP_COUNT,
    ROUTING_GROUP_TCP4, ROUTING_GROUP_TCP6, ROUTING_GROUP_UDP4, ROUTING_GROUP_UDP6,
    ROUTING_META_MAP_LEN, RoutingGroupBitmaps, routing_group_index,
};

pub const TASK_COMM_LEN: usize = 16;
pub const TPROXY_MARK: u32 = 0x0800_0000;
/// Socket mark bit used by the control plane to tell the eBPF datapath to
/// pass its own traffic through without re-routing it.
pub const DAE_BYPASS_MARK: u32 = 0x100;
pub const RECOGNIZE_MAGIC: u16 = 0x2017;
pub const LOOPBACK_IFINDEX: u32 = 1;
pub const MAX_OUTBOUNDS: u32 = 256;
pub const MAX_DOMAIN_LEN: usize = 256;
pub const MAX_ROUTING_RULES: u32 = 512;
pub const MAX_CONN_TRACK: u32 = 65536;
pub const LINK_HDR_LEN_ETHERNET: u32 = 14;
pub const LINK_HDR_LEN_NONE: u32 = 0;
pub const MAX_MATCH_SET_LEN: u32 = 128;
pub const MAX_LPM_SIZE: u32 = 2048000;
pub const MAX_LPM_NUM: u32 = MAX_MATCH_SET_LEN + 8;
pub const MAX_DST_MAPPING_NUM: u32 = 65536 * 2;
pub const MAX_COOKIE_PID_NUM: u32 = 65536;
pub const MAX_DOMAIN_ROUTING_NUM: u32 = 65536;

// Rust struct with a memory layout identical to the C struct.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DaeParam {
    pub tproxy_port: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub dae_netns_id: u32,
    pub wan_ifindex: u32,
    pub dae0peer_mac: [u8; 6],
    pub padding_after_mac: [u8; 2], // Padding to align to use_redirect_peer
    pub use_redirect_peer: u8,
    pub has_bpf_get_current_task: u8,
    /// Datapath log gate (convention only; layout unchanged): bit 0 enables
    /// the per-flow `info!` logging in honk-ebpf (e.g. "lan new flow").
    /// Userspace always writes 0, so these logs are OFF by default; set
    /// bit 0 to re-enable them for debugging.
    pub padding2: u16,
    pub dae_socket_mark: u32,
    pub local_ip: u32,
}

// Pod impls are only needed on the userspace side (honk-core).
// The BPF side (honk-ebpf) uses aya-ebpf which doesn't have a Pod trait.
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DaeParam {}

// Userspace copy of PARAM (BPF side uses maps.rs's Global<DaeParam>).
#[cfg(not(target_arch = "bpf"))]
#[unsafe(no_mangle)]
static PARAM: DaeParam = DaeParam {
    tproxy_port: 0,
    control_plane_pid: 0,
    dae0_ifindex: 0,
    dae_netns_id: 0,
    wan_ifindex: 0,
    dae0peer_mac: [0; 6],
    padding_after_mac: [0; 2],
    use_redirect_peer: 0,
    has_bpf_get_current_task: 0,
    padding2: 0,
    dae_socket_mark: 0,
    local_ip: 0,
};

/// Outbound indices written into eBPF `match_set.outbound`.
///
/// These values are aligned with dae-core so that the eBPF datapath can use
/// the high logical values (>= 0xFC) for rule-composition without colliding
/// with user-defined outbounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutboundIndex {
    Direct = 0,
    Block = 1,
    /// Base value for user-defined outbound groups. The actual eBPF value for
    /// user group *i* is `UserBase as u8 + i`.
    UserBase = 2,
    MustRules = 0xFC,
    ControlPlaneRouting = 0xFD,
    LogicalOr = 0xFE,
    LogicalAnd = 0xFF,
}

impl OutboundIndex {
    pub const fn is_reserved(self) -> bool {
        let v = self as u8;
        v < Self::UserBase as u8 || v >= 0xFC
    }
    pub const fn to_user_num(self) -> u32 {
        let v = self as u8;
        if v >= Self::UserBase as u8 && v < 0xFC {
            (v - Self::UserBase as u8) as u32
        } else {
            0
        }
    }
    pub fn from_user(n: u32) -> Self {
        match n {
            0 => Self::Direct,
            1 => Self::Block,
            0xFC => Self::MustRules,
            0xFD => Self::ControlPlaneRouting,
            0xFE => Self::LogicalOr,
            0xFF => Self::LogicalAnd,
            _ => Self::UserBase,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum L4ChecksumPolicy {
    Enable = 0,
    Restore = 1,
    SetZero = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L4ProtoType {
    Tcp = 1,
    Udp = 2,
}

impl L4ProtoType {
    #[inline(always)]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpVersionType {
    V4 = 4,
    V6 = 6,
}

impl IpVersionType {
    #[inline(always)]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            4 => Some(Self::V4),
            6 => Some(Self::V6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConnTuple {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union RoutingMeta {
    pub raw: u64,
    pub data: RoutingMetaData,
}

impl core::fmt::Debug for RoutingMeta {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RoutingMeta")
            .field("raw", &unsafe { self.raw })
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct RoutingMetaData {
    pub outbound: u8, // offset 0 → u64 bits 0-7
    pub mark: u32,    // offset 1 → u64 bits 8-39
    pub must: u8,     // offset 5 → u64 bit 40
    pub dscp: u8,     // offset 6 → u64 bits 48-55
    pub _pad: u8,     // offset 7 → u64 bits 56-63
}

// Layout assertions — must hold for the union to work correctly.
// RoutingMeta is a union of u64 and RoutingMetaData, so both must be 8 bytes
// and field byte-offsets must match the bit-encoding in build_routing_meta().
const _RT_META_SIZE: () = assert!(core::mem::size_of::<RoutingMeta>() == 8);
const _RT_META_RAW_SIZE: () = assert!(core::mem::size_of::<u64>() == 8);

impl Default for RoutingMeta {
    fn default() -> Self {
        Self { raw: 0 }
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RedirectTuple {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
}

impl RedirectTuple {
    /// Construct a `RedirectTuple` from a [`TuplesKey`]'s IPs, respecting the
    /// IPv4-mapped representation used by the kernel.  When `is_ipv4` is
    /// `true`, the addresses are stored as `::ffff:<ipv4>` by copying only the
    /// low 32 bits alongside the fixed ::ffff prefix.
    #[inline(always)]
    pub fn from_tuples_ip(tuples: &crate::redirect_need::TuplesKey, is_ipv4: bool) -> Self {
        if is_ipv4 {
            let mut rt: Self = unsafe { core::mem::zeroed() };
            unsafe {
                rt.src_ip.u6_addr32[2] = 0x0000ffffu32.to_be();
                rt.src_ip.u6_addr32[3] = tuples.src_ip.u6_addr32[3];
                rt.dst_ip.u6_addr32[2] = 0x0000ffffu32.to_be();
                rt.dst_ip.u6_addr32[3] = tuples.dst_ip.u6_addr32[3];
            }
            rt
        } else {
            Self {
                src_ip: tuples.src_ip,
                dst_ip: tuples.dst_ip,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RedirectEntry {
    pub last_seen_ns: u64,
    pub dmac: [u8; 6],
    pub smac: [u8; 6],
    pub from_wan: u8,
    /// Final outbound index of the redirected flow, recorded at redirect
    /// time so `dae0_ingress` can attribute reply traffic in `OUTBOUND_STATS`.
    pub outbound: u8,
    pub padding: [u8; 2],
    pub ifindex: u32,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PidPname {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; 16],
}

/// Parameter keys for the `params` BPF array map.
/// Used by honk-core to configure eBPF program behaviour at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ParamKey {
    Zero = 0,
    BigEndianTproxyPort = 1,
    DisableL4TxChecksum = 2,
    DisableL4RxChecksum = 3,
    ControlPlanePid = 4,
    ControlPlaneNatDirect = 5,
    ControlPlaneDnsRouting = 6,
    SoMarkFromDae = 7,
    Dae0Ifindex = 8,
    Dae0peerMacHi = 9,
    Dae0peerMacLo = 10,
    UseRedirectPeer = 11,
    Dae0peerIfindex = 12,
    LoIfindex = 13,
    TproxyMark = 14,
}

/// LPM trie key for IP/CIDR routing.
/// Matches the kernel's `struct bpf_lpm_trie_key` layout:
/// prefixlen (u32) + data (4 × u32 = IPv6 / IPv4-mapped).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct LpmKey {
    pub prefix_len: u32,
    pub data: [u32; 4],
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for LpmKey {}

/// Number of `u64` counters per outbound in the eBPF `OUTBOUND_STATS`
/// per-CPU array (`tx_packets`, `tx_bytes`, `rx_packets`, `rx_bytes`).
pub const OUTBOUND_STATS_COUNTERS: u32 = 4;
/// Counter slot offsets within one outbound's `OUTBOUND_STATS` block.
pub const OUTBOUND_STATS_TX_PACKETS: u32 = 0;
pub const OUTBOUND_STATS_TX_BYTES: u32 = 1;
pub const OUTBOUND_STATS_RX_PACKETS: u32 = 2;
pub const OUTBOUND_STATS_RX_BYTES: u32 = 3;
/// Total entries of the eBPF `OUTBOUND_STATS` per-CPU array: one counter
/// block per possible outbound index (the datapath carries it as a `u8`).
pub const OUTBOUND_STATS_MAP_LEN: u32 = MAX_OUTBOUNDS * OUTBOUND_STATS_COUNTERS;

/// Index of `counter` for `outbound` in the eBPF `OUTBOUND_STATS` per-CPU
/// array: `outbound * OUTBOUND_STATS_COUNTERS + counter`.
#[inline(always)]
pub const fn outbound_stats_index(outbound: u8, counter: u32) -> u32 {
    outbound as u32 * OUTBOUND_STATS_COUNTERS + counter
}

/// Per-outbound statistics as returned by
/// `EbpfBackend::get_outbound_stats`.  `tx`/`rx` packets and bytes are
/// aggregated from the eBPF `OUTBOUND_STATS` per-CPU array (tx counted at
/// `lan_ingress` when the routing decision lands, rx counted at
/// `dae0_ingress` on the reply path); the connection/error fields are only
/// populated by userspace accounting (see `honk-core`'s `StatsManager`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct OutboundStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub active_conns: u32,
    pub total_conns: u32,
    pub errors: u32,
    pub _pad: u32,
}

unsafe impl aya::Pod for RedirectTuple {}
unsafe impl aya::Pod for RedirectEntry {}
