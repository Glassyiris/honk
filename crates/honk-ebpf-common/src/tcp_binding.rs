//! Running-kernel offsets required by the non-sleepable TCP request proof hooks.

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct TcpBindingOffsets {
    pub skb_head: u32,
    pub skb_network_header: u32,
    pub skb_transport_header: u32,
    pub skb_tail: u32,
    pub skb_mark: u32,
    pub skb_priority: u32,
    pub socket_cookie: u32,
    pub request_rcv_isn: u32,
}

const _: () = assert!(core::mem::size_of::<TcpBindingOffsets>() == 32);
const _: () = assert!(core::mem::align_of::<TcpBindingOffsets>() == 4);
const _: () = assert!(core::mem::offset_of!(TcpBindingOffsets, request_rcv_isn) == 28);

#[cfg(not(target_arch = "bpf"))]
unsafe impl aya::Pod for TcpBindingOffsets {}
