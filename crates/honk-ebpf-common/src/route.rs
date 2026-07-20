use crate::{IpVersionType, L4ProtoType, TASK_COMM_LEN, redirect_need::MAX_MATCH_SET_LEN};

// The datapath pre-filters MatchSets by the flow's (L4 protocol × IP
// version) group so that rules which can never match the flow (e.g. a
// tcp-only rule evaluated for a UDP flow) are skipped without reading
// ROUTING_MAP or running the match state machine.

/// Number of routing groups: tcp4, tcp6, udp4, udp6.
pub const ROUTING_GROUP_COUNT: usize = 4;
/// Group index of TCP-over-IPv4 flows.
pub const ROUTING_GROUP_TCP4: u32 = 0;
/// Group index of TCP-over-IPv6 flows.
pub const ROUTING_GROUP_TCP6: u32 = 1;
/// Group index of UDP-over-IPv4 flows.
pub const ROUTING_GROUP_UDP4: u32 = 2;
/// Group index of UDP-over-IPv6 flows.
pub const ROUTING_GROUP_UDP6: u32 = 3;
/// u32 words per group bitmap: one bit per `ROUTING_MAP` slot.
pub const ROUTING_GROUP_BITMAP_WORDS: usize = MAX_MATCH_SET_LEN / 32;
/// Total width of `ROUTING_META_MAP` in u32 slots.
///
/// Layout: slot 0 holds the active rule count (kept for compatibility);
/// slots `[1..ROUTING_META_MAP_LEN)` hold `ROUTING_GROUP_COUNT` bitmaps of
/// `ROUTING_GROUP_BITMAP_WORDS` words each.  Bit N of group g's bitmap —
/// slot `1 + g * ROUTING_GROUP_BITMAP_WORDS + N / 32`, bit `N % 32` — is
/// set when `ROUTING_MAP[N]` belongs to group g.  MatchSets are never
/// duplicated across groups; a rule belonging to several groups simply
/// has its global index set in each of them.
pub const ROUTING_META_MAP_LEN: usize = 1 + ROUTING_GROUP_COUNT * ROUTING_GROUP_BITMAP_WORDS;

// The layout is hard-coded for 128 MatchSet slots (4 bitmap words) and a
// 17-wide meta map; both the eBPF loader and the userspace backend rely on
// these exact numbers.
const _: () = assert!(ROUTING_GROUP_BITMAP_WORDS == 4);
const _: () = assert!(ROUTING_META_MAP_LEN == 17);

/// Per-group rule bitmaps published to `ROUTING_META_MAP[1..]`.
/// `bitmaps[g][w]` is word w of group g's 128-bit bitmap over
/// `ROUTING_MAP` indices.
pub type RoutingGroupBitmaps = [[u32; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];

/// Map a flow's (L4 protocol, IP version) pair to its routing group index.
///
/// `l4proto`/`ipversion` use the datapath encodings (`L4ProtoType`:
/// Tcp=1, Udp=2; `IpVersionType`: V4=4, V6=6).  Unknown values fall back
/// to group 0 (tcp4) so the flow still evaluates a deterministic subset.
#[inline(always)]
pub const fn routing_group_index(l4proto: u8, ipversion: u8) -> u32 {
    let udp = (l4proto == L4ProtoType::Udp as u8) as u32;
    let v6 = (ipversion == IpVersionType::V6 as u8) as u32;
    udp * 2 + v6
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PortRange {
    pub port_start: u16,
    pub port_end: u16,
}

/// Match type of a `match_set` entry, aligned with dae-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MatchType {
    DomainSet = 0,
    IpSet = 1,
    SourceIpSet = 2,
    Port = 3,
    SourcePort = 4,
    L4Proto = 5,
    IpVersion = 6,
    Mac = 7,
    ProcessName = 8,
    Dscp = 9,
    Fallback = 10,
    MustRules = 11,
    Upstream = 12,
    QType = 13,
}

impl MatchType {
    /// Convert from `u8`; returns `None` for unknown values.
    #[inline(always)]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::DomainSet),
            1 => Some(Self::IpSet),
            2 => Some(Self::SourceIpSet),
            3 => Some(Self::Port),
            4 => Some(Self::SourcePort),
            5 => Some(Self::L4Proto),
            6 => Some(Self::IpVersion),
            7 => Some(Self::Mac),
            8 => Some(Self::ProcessName),
            9 => Some(Self::Dscp),
            10 => Some(Self::Fallback),
            11 => Some(Self::MustRules),
            12 => Some(Self::Upstream),
            13 => Some(Self::QType),
            _ => None,
        }
    }
}

/// The value union inside `match_set`.
#[derive(Clone, Copy)]
#[repr(C)]
pub union MatchSetValue {
    pub raw: [u8; 16],
    pub index: u32,
    pub port_range: PortRange,
    pub l4proto_type: L4ProtoType,
    pub ip_version: IpVersionType,
    pub pname: [u32; TASK_COMM_LEN / 4],
    pub dscp: u8,
}

impl Default for MatchSetValue {
    fn default() -> Self {
        Self { raw: [0; 16] }
    }
}

/// eBPF routing rule entry, layout-matched with dae-core's `struct match_set`.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct MatchSet {
    pub value: MatchSetValue,
    pub not: u8,
    pub match_type: u8,
    pub outbound: u8,
    pub must: u8,
    pub mark: u32,
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for MatchSet {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for MatchSetValue {}

impl core::fmt::Debug for MatchSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MatchSet")
            .field("match_type", &self.match_type)
            .field("not", &self.not)
            .field("outbound", &self.outbound)
            .field("must", &self.must)
            .field("mark", &self.mark)
            .finish()
    }
}
