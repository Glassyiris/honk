use aya_ebpf_bindings::bindings::{__be16, __u16};

use crate::{TASK_COMM_LEN, dae_ip::In6Addr};

pub const MAX_MATCH_SET_LEN: usize = 128;
pub const ROUTING_BITMAP_WORDS_PER_GENERATION: usize = MAX_MATCH_SET_LEN / 32;
pub const ROUTING_BITMAP_GENERATIONS: usize = 2;
pub const ROUTING_BITMAP_WORDS: usize =
    ROUTING_BITMAP_WORDS_PER_GENERATION * ROUTING_BITMAP_GENERATIONS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPPort {
    pub ip: In6Addr,
    pub port: __be16,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RoutingResult {
    pub mark: u32,
    pub must: u8,
    pub mac: [u8; 6],
    pub outbound: u8,
    pub pname: [u8; 16],
    pub pid: u32,
    pub dscp: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct TuplesKey {
    pub src_ip: In6Addr,
    pub dst_ip: In6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub l4proto: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Tuples {
    pub five: TuplesKey,
    pub dscp: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RoutingHandoffEntry {
    pub last_seen_ns: u64,
    pub result: RoutingResult,
    /// Copy of the flow's `ConnState::decision_cookie` at handoff time, so
    /// the NFQUEUE decision path can pair a consumed handoff with the
    /// conn_state it is about to rewrite.  Zero for flows that never
    /// entered the staging path.  Fills the former tail padding; the map
    /// value size is unchanged.
    pub decision_cookie: u32,
}

const _HANDOFF_ENTRY_SIZE: () = assert!(core::mem::size_of::<RoutingHandoffEntry>() == 48);
const _HANDOFF_ENTRY_COOKIE_OFFSET: () =
    assert!(core::mem::offset_of!(RoutingHandoffEntry, decision_cookie) == 44);

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PortRange {
    pub port_start: __u16,
    pub port_end: __u16,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DomainRouting {
    pub bitmap: [u32; ROUTING_BITMAP_WORDS],
}

impl DomainRouting {
    pub fn for_generation(&self, generation: u32) -> Self {
        let mut shifted = Self::default();
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        if offset + ROUTING_BITMAP_WORDS_PER_GENERATION <= shifted.bitmap.len() {
            shifted.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
                .copy_from_slice(&self.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        }
        shifted
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IPPortProto {
    pub ip: In6Addr,
    pub port: __be16,
    pub proto: u8,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PIDName {
    pub last_seen_ns: u64,
    pub pid: u32,
    pub pname: [u8; TASK_COMM_LEN],
}

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TuplesKey {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for RoutingHandoffEntry {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for DomainRouting {}
#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for PIDName {}
