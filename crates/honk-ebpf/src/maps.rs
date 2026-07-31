use aya_ebpf::Global;
use aya_ebpf::bindings::__be32;
use aya_ebpf::btf_maps::{Array, HashMap, LpmTrie, PerCpuArray, RingBuf, SockMap};
use aya_ebpf::macros::btf_map;
use honk_ebpf_common::conn::{ConnState, ConntrackArgs, MAX_CONN_STATE_NUM, ParseTransportCtx};
use honk_ebpf_common::event::DaeEvent;
use honk_ebpf_common::redirect_need::{
    DomainRouting, MAX_MATCH_SET_LEN, PIDName, RoutingHandoffEntry, TuplesKey,
};
use honk_ebpf_common::route::{MatchSet, ROUTING_META_MAP_LEN};
use honk_ebpf_common::{DaeParam, RedirectEntry, RedirectTuple};

use crate::route::{RouteCtx, WanEgressRouteScratch};
use crate::transport::ParsedPacket;

/// Maximum LPM trie size: 65,536 entries.
/// Reduced from 2,048,000 to stay under kernel memory limits.
/// Each entry consumes ~20 bytes of kernel memory, so 65,536 entries
/// ≈ 1.3 MB per LPM map.
pub const MAX_LPM_SIZE: usize = 65536;
pub const MAX_ROUTING_HANDOFF_NUM: usize = 65536;
pub const MAX_LPM_NUM: usize = MAX_MATCH_SET_LEN + 8;
pub const MAX_COOKIE_PID_PNAME_MAPPING_NUM: usize = 65536;
pub const MAX_DOMAIN_ROUTING_NUM: usize = 65536;

// Global variable: corresponds to the C `const volatile struct dae_param PARAM = {};`.
#[unsafe(no_mangle)]
pub static PARAM: Global<DaeParam> = Global::new(DaeParam {
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
});

/// WAN interface ifindex used by the egress program to identify locally-
/// generated packets that the bonding driver forwards onto the bond master.
#[unsafe(no_mangle)]
pub static WAN_IFINDEX: Global<u32> = Global::new(0);

/// dae0peer interface ifindex used by the sk_lookup program to identify
/// proxy-bound packets that have entered the isolated dae netns.
#[unsafe(no_mangle)]
pub static DAE0PEER_IFINDEX: Global<u32> = Global::new(0);

#[btf_map]
pub static OUTBOUND_CONNECTIVITY_MAP: Array<u64, 1536, 0> = Array::new();

#[btf_map]
pub static LISTEN_SOCKET_MAP: SockMap<16> = SockMap::new();

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live
/// entries instead of locking max_entries up front (~8 MB empty instead of
/// ~8 MB per 64K capacity).  Eviction is owned by the userspace janitor
/// (state-based timeouts), never by silent kernel LRU eviction — an evicted
/// entry here breaks reply rewriting for live flows.
pub static REDIRECT_TRACK: HashMap<RedirectTuple, RedirectEntry, 65536, 1> = HashMap::new();

#[btf_map]
/// Plain hash with BPF_F_NO_PREALLOC: swept by the userspace janitor (30 s
/// timeout).
pub static ROUTING_HANDOFF_MAP: HashMap<TuplesKey, RoutingHandoffEntry, MAX_ROUTING_HANDOFF_NUM, 1> =
    HashMap::new();

#[btf_map]
pub static ROUTING_MAP: Array<MatchSet, MAX_MATCH_SET_LEN, 0> = Array::new();

/// Routing meta block.
///
/// Slot 0 holds the active rule count; slots `[1..ROUTING_META_MAP_LEN)`
/// hold the four (l4proto × ipversion) group bitmaps — see
/// `honk_ebpf_common::route::ROUTING_META_MAP_LEN` for the exact layout.
/// Userspace publishes the group bitmaps first and the count last, so the
/// count remains the atomic switch of the two-phase routing commit.
#[btf_map]
pub static ROUTING_META_MAP: Array<u32, ROUTING_META_MAP_LEN, 0> = Array::new();

#[btf_map]
pub static DOMAIN_ROUTING_MAP: HashMap<[__be32; 4], DomainRouting, MAX_DOMAIN_ROUTING_NUM, 1> =
    HashMap::new();

#[btf_map]
pub static DEST_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static SOURCE_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static MAC_LPM_ROUTING_MAP: LpmTrie<[__be32; 4], DomainRouting, MAX_LPM_SIZE, 1> =
    LpmTrie::new();

#[btf_map]
pub static COOKIE_PID_MAP: HashMap<u64, PIDName, MAX_COOKIE_PID_PNAME_MAPPING_NUM, 1> =
    HashMap::new();

// Must be pinned in userspace.
// Plain hash with BPF_F_NO_PREALLOC: kernel memory scales with live entries
// instead of pinning ~84 MB for 512K capacity up front.  The datapath
// expires entries lazily on hit and the userspace janitor sweeps with
// state-based timeouts; the kernel never evicts on its own (silent LRU
// eviction could re-route or break live flows mid-flight).  Inserts under
// kernel memory pressure can fail — the overflow counter + fail-closed
// path covers that.
#[btf_map]
pub static CONN_STATE_MAP: HashMap<TuplesKey, ConnState, { MAX_CONN_STATE_NUM as usize }, 1> =
    HashMap::new();

/// Occupancy gauge for CONN_STATE_MAP (per-CPU to keep the insert path
/// contention-free): slot `OCCUPANCY_INSERTS` counts successful inserts,
/// slot `OCCUPANCY_EBPF_DELETES` counts datapath-side deletes.  Userspace
/// combines these with its own janitor-delete accounting to estimate live
/// occupancy between sweeps.
#[btf_map]
pub static CONN_STATE_OCCUPANCY: PerCpuArray<u64, 2> = PerCpuArray::new();

// key=0: UDP conn overflow count; key=1: TCP conn overflow count.
#[btf_map]
pub static BPF_STATS_MAP: Array<u64, 2> = Array::new();

/// Per-outbound traffic counters (per-CPU to avoid cross-CPU contention on
/// the per-packet update path).  Index:
/// `honk_ebpf_common::outbound_stats_index(outbound, counter)` — four `u64`
/// counters per outbound (tx_packets, tx_bytes, rx_packets, rx_bytes) for
/// each of the 256 possible `u8` outbound indices.  tx is accounted at
/// `lan_ingress` when the routing decision lands, rx at `dae0_ingress` on
/// the reply path.  Userspace aggregates the per-CPU slots when reading.
#[btf_map]
pub static OUTBOUND_STATS: PerCpuArray<u64, { honk_ebpf_common::OUTBOUND_STATS_MAP_LEN as usize }> =
    PerCpuArray::new();

#[btf_map]
pub static EVENT_RINGBUF: RingBuf<DaeEvent, 262144> = RingBuf::new();

#[btf_map]
pub static PKT_SCRATCH_KEY: PerCpuArray<ParsedPacket, 1> = PerCpuArray::new();

#[btf_map]
pub static ROUTE_CTX_SCRATCH_MAP: PerCpuArray<RouteCtx, 1> = PerCpuArray::new();

#[btf_map]
pub static WAN_EGRESS_ROUTE_SCRATCH_MAP: PerCpuArray<WanEgressRouteScratch, 1> = PerCpuArray::new();

#[btf_map]
pub static CONNTRACK_ARGS_MAP: PerCpuArray<ConntrackArgs, 1> = PerCpuArray::new();

#[btf_map]
pub static PARSE_CTX_MAP: PerCpuArray<ParseTransportCtx, 1> = PerCpuArray::new();
