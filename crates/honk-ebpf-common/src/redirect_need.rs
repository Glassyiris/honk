use aya_ebpf_bindings::bindings::{__be16, __u16};

use crate::{TASK_COMM_LEN, dae_ip::In6Addr};

pub const MAX_MATCH_SET_LEN: usize = 128;

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
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct PortRange {
    pub port_start: __u16,
    pub port_end: __u16,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DomainRouting {
    pub bitmap: [u32; MAX_MATCH_SET_LEN / 32],
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

unsafe impl aya::Pod for TuplesKey {}
unsafe impl aya::Pod for RoutingHandoffEntry {}
unsafe impl aya::Pod for DomainRouting {}
unsafe impl aya::Pod for PIDName {}
