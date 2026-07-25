// Matches the C enum dae_event_type.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaeEventType {
    Blocked = 0,         // DAE_EVENT_BLOCKED
    UdpConnOverflow = 1, // DAE_EVENT_UDP_CONN_OVERFLOW
    TcpConnOverflow = 2, // DAE_EVENT_TCP_CONN_OVERFLOW
    /// A TC ingress packet could not be assigned to the transparent
    /// listener. For this event only, [`DaeEvent::pid`] carries `-errno`.
    TproxyAssignFailure = 3,
}

// Matches the C struct dae_event.
// Total size 72 bytes, alignment 8 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DaeEvent {
    pub timestamp: u64,  // __u64 timestamp
    pub type_: u32,      // __u32 type (underscore because `type` is a Rust keyword)
    pub pid: u32,        // __u32 pid
    pub pname: [u8; 16], // __u8 pname[16]
    pub outbound: u8,    // __u8 outbound
    pub l4proto: u8,     // __u8 l4proto
    pub pad: [u8; 2],    // __u8 pad[2]
    pub sip: [u32; 4],   // __u32 sip[4] (four u32 chunks for IPv4 or IPv6)
    pub dip: [u32; 4],   // __u32 dip[4]
    pub sport: u16,      // __u16 sport
    pub dport: u16,      // __u16 dport
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum TcpState {
    TcpStateActive = 0,
    TcpStateClosing = 1,
}
