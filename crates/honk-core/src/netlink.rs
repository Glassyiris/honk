//! Minimal synchronous rtnetlink client (NETLINK_ROUTE) over `libc`.
//!
//! Replaces the engine's `ip`/`nsenter` shell-outs: veth pair creation,
//! link up/down/netns-move, v4/v6 addresses, routes (incl. table 100 +
//! RTN_LOCAL), fwmark rules, and static neighbours. Message headers use
//! the stable kernel ABI layouts directly (the musl libc crate does not
//! export all of them); each request waits for the kernel's
//! NLMSG_ERROR ack.
//!
//! Netlink sockets are namespace-bound at creation: a socket opened
//! inside a scoped `setns` operates on that namespace, which is how the
//! daens-internal setup works without `nsenter`.

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

// ---- kernel ABI (stable) --------------------------------------------------

const AF_INET: i32 = libc::AF_INET;
const AF_INET6: i32 = libc::AF_INET6;
const NETLINK_ROUTE: i32 = 0;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_REPLACE: u16 = 0x100;

const NLMSG_ERROR: u16 = 2;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELRULE: u16 = 33;
const RTM_NEWRULE: u16 = 32;
const RTM_NEWNEIGH: u16 = 28;

const ARPHRD_ETHER: u16 = 1;
const IFF_UP: u32 = 0x1;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_GATEWAY: u16 = 5;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;

const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;

const NUD_PERMANENT: u16 = 0x80;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const FR_ACT_TO_TBL: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NdMsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

const NLMSG_ALIGNTO: usize = 4;

fn align(len: usize) -> usize {
    len.div_ceil(NLMSG_ALIGNTO) * NLMSG_ALIGNTO
}

#[derive(Clone, Debug)]
enum Attr {
    U32(u32),
    Bytes(Vec<u8>),
    Str(String),
    Nested(Vec<(u16, Attr)>),
}

fn attr_payload(attr: &Attr, out: &mut Vec<u8>) {
    match attr {
        Attr::U32(v) => out.extend_from_slice(&v.to_ne_bytes()),
        Attr::Bytes(b) => out.extend_from_slice(b),
        Attr::Str(s) => {
            out.extend_from_slice(s.as_bytes());
            out.push(0);
        }
        Attr::Nested(children) => {
            for (ty, child) in children {
                put_attr(out, *ty, child);
            }
        }
    }
}

fn put_attr(buf: &mut Vec<u8>, rta_type: u16, attr: &Attr) {
    let mut payload = Vec::new();
    attr_payload(attr, &mut payload);
    let len = (4 + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&rta_type.to_ne_bytes());
    buf.extend_from_slice(&payload);
    while !buf.len().is_multiple_of(NLMSG_ALIGNTO) {
        buf.push(0);
    }
}

fn pod_bytes<T>(v: &T) -> &[u8] {
    // SAFETY: used only with #[repr(C)] POD message headers defined above.
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn ifinfo(ifindex: i32, flags: u32, change: u32) -> IfInfoMsg {
    IfInfoMsg {
        ifi_family: 0,
        ifi_pad: 0,
        ifi_type: ARPHRD_ETHER,
        ifi_index: ifindex,
        ifi_flags: flags,
        ifi_change: change,
    }
}

/// One synchronous NETLINK_ROUTE connection.
pub(crate) struct NlSock {
    fd: OwnedFd,
    seq: u32,
}

impl NlSock {
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: plain socket creation; OwnedFd takes ownership.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // A netlink reply that never comes must not hang engine startup.
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        // SAFETY: standard setsockopt on the fresh socket.
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: addr is a valid sockaddr_nl.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, seq: 0 })
    }

    /// Receive one datagram: EINTR is retried, a truncated read grows the
    /// buffer (up to 1 MiB) and retries, a timeout is a hard error.
    fn recv_one(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        const MAX_BUF: usize = 1 << 20;
        loop {
            // SAFETY: buf is a valid writable region of buf.len() bytes.
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_iov = &mut iov;
            hdr.msg_iovlen = 1;
            let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut hdr, 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if hdr.msg_flags & libc::MSG_TRUNC != 0 {
                let next = (buf.len() * 2).min(MAX_BUF);
                if next == buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "netlink message exceeds 1 MiB",
                    ));
                }
                buf.resize(next, 0);
                continue;
            }
            return Ok(n as usize);
        }
    }

    /// Send one request and wait for the kernel ack (NLMSG_ERROR with
    /// error 0).
    fn request(
        &mut self,
        msg_type: u16,
        flags: u16,
        header: &[u8],
        attrs: &[(u16, Attr)],
    ) -> io::Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&[0u8; 4]); // length, patched below
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(header);
        for (ty, attr) in attrs {
            put_attr(&mut buf, *ty, attr);
        }
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // SAFETY: buf holds a well-formed nlmsghdr blob.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut resp = vec![0u8; 4096];
        loop {
            let n = self.recv_one(&mut resp)?;
            let mut off = 0usize;
            while off + 16 <= n {
                // nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4)
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hseq == seq && htype == NLMSG_ERROR {
                    let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                    if err == 0 {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-err));
                }
                let next = align(hlen);
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
    }

    /// Create a veth pair (`name` ↔ `peer_name`).
    pub(crate) fn add_veth_pair(&mut self, name: &str, peer: &str) -> io::Result<()> {
        let header = ifinfo(0, 0, 0);
        // Peer payload: its own ifinfomsg followed by IFLA_IFNAME.
        let mut peer_payload = pod_bytes(&ifinfo(0, 0, 0)).to_vec();
        put_attr(&mut peer_payload, IFLA_IFNAME, &Attr::Str(peer.to_string()));

        let attrs = [
            (IFLA_IFNAME, Attr::Str(name.to_string())),
            (
                IFLA_LINKINFO,
                Attr::Nested(vec![
                    (IFLA_INFO_KIND, Attr::Str("veth".to_string())),
                    (
                        IFLA_INFO_DATA,
                        Attr::Nested(vec![(VETH_INFO_PEER, Attr::Bytes(peer_payload))]),
                    ),
                ]),
            ),
        ];
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Bring a link up (or down).
    pub(crate) fn set_link_up(&mut self, ifindex: u32, up: bool) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, if up { IFF_UP } else { 0 }, IFF_UP);
        self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    /// Move a link into the namespace held by `ns_fd`.
    pub(crate) fn set_link_netns_fd(&mut self, ifindex: u32, ns_fd: &OwnedFd) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        let fd_no = ns_fd.as_raw_fd() as u32;
        let attrs = [(IFLA_NET_NS_FD, Attr::U32(fd_no))];
        let r = self.request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &attrs,
        );
        tracing::debug!(ifindex, fd_no, ok = r.is_ok(), "set_link_netns_fd");
        r
    }

    /// Delete a link by index.
    pub(crate) fn del_link(&mut self, ifindex: u32) -> io::Result<()> {
        let header = ifinfo(ifindex as i32, 0, 0);
        self.request(
            RTM_DELLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            pod_bytes(&header),
            &[],
        )
    }

    /// Add (or remove) an address on an interface.
    pub(crate) fn addr_op(
        &mut self,
        add: bool,
        ifindex: u32,
        family: u8,
        addr: &[u8],
        prefix: u8,
    ) -> io::Result<()> {
        let header = IfAddrMsg {
            ifa_family: family,
            ifa_prefixlen: prefix,
            ifa_flags: 0,
            ifa_scope: RT_SCOPE_UNIVERSE,
            ifa_index: ifindex,
        };
        let attrs = [
            (IFA_LOCAL, Attr::Bytes(addr.to_vec())),
            (IFA_ADDRESS, Attr::Bytes(addr.to_vec())),
        ];
        let (ty, flags) = if add {
            (
                RTM_NEWADDR,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            )
        } else {
            (RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, pod_bytes(&header), &attrs)
    }

    /// Add a route. `dst` is (network, prefix) or None for default.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_route(
        &mut self,
        family: u8,
        table: u32,
        route_type: u8,
        scope: u8,
        proto: u8,
        dst: Option<(&[u8], u8)>,
        gateway: Option<&[u8]>,
        oif: Option<u32>,
    ) -> io::Result<()> {
        let header = RtMsg {
            rtm_family: family,
            rtm_dst_len: dst.map(|(_, p)| p).unwrap_or(0),
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: if table <= 255 { table as u8 } else { 0 },
            rtm_protocol: proto,
            rtm_scope: scope,
            rtm_type: route_type,
            rtm_flags: 0,
        };
        let mut attrs: Vec<(u16, Attr)> = Vec::new();
        if table > 255 {
            attrs.push((RTA_TABLE, Attr::U32(table)));
        }
        if let Some((net, _)) = dst {
            attrs.push((RTA_DST, Attr::Bytes(net.to_vec())));
        }
        if let Some(gw) = gateway {
            attrs.push((RTA_GATEWAY, Attr::Bytes(gw.to_vec())));
        }
        if let Some(idx) = oif {
            attrs.push((RTA_OIF, Attr::U32(idx)));
        }
        self.request(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }

    /// Add/delete a fwmark → table rule.
    fn rule_fwmark(&mut self, add: bool, family: u8, fwmark: u32, table: u32) -> io::Result<()> {
        // fib_rule_hdr: family, dst_len, src_len, tos, table, res1, res2,
        // action, flags(u32)
        let header: [u8; 12] = [
            family,
            0,
            0,
            0,
            if table <= 255 { table as u8 } else { 0 },
            0,
            0,
            FR_ACT_TO_TBL,
            0,
            0,
            0,
            0,
        ];
        let mut attrs: Vec<(u16, Attr)> = vec![
            (FRA_FWMARK, Attr::U32(fwmark)),
            (FRA_FWMASK, Attr::U32(u32::MAX)),
        ];
        if table > 255 {
            attrs.push((FRA_TABLE, Attr::U32(table)));
        }
        let (ty, flags) = if add {
            (RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)
        } else {
            (RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK)
        };
        self.request(ty, flags, &header, &attrs)
    }

    pub(crate) fn add_rule_fwmark(
        &mut self,
        family: u8,
        fwmark: u32,
        table: u32,
    ) -> io::Result<()> {
        self.rule_fwmark(true, family, fwmark, table)
    }

    pub(crate) fn del_rule_fwmark(
        &mut self,
        family: u8,
        fwmark: u32,
        table: u32,
    ) -> io::Result<()> {
        self.rule_fwmark(false, family, fwmark, table)
    }

    /// Replace a static neighbour entry (IP → MAC, permanent).
    pub(crate) fn neigh_replace(
        &mut self,
        ifindex: u32,
        family: u8,
        ip: &[u8],
        mac: &[u8; 6],
    ) -> io::Result<()> {
        let header = NdMsg {
            ndm_family: family,
            ndm_pad1: 0,
            ndm_pad2: 0,
            ndm_ifindex: ifindex as i32,
            ndm_state: NUD_PERMANENT,
            ndm_flags: 0,
            ndm_type: 0,
        };
        let attrs = [
            (NDA_DST, Attr::Bytes(ip.to_vec())),
            (NDA_LLADDR, Attr::Bytes(mac.to_vec())),
        ];
        self.request(
            RTM_NEWNEIGH,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            pod_bytes(&header),
            &attrs,
        )
    }
}

/// Address families and route enums re-exported for call sites.
pub(crate) const FAM_V4: u8 = AF_INET as u8;
pub(crate) const FAM_V6: u8 = AF_INET6 as u8;
pub(crate) const ROUTE_UNICAST: u8 = RTN_UNICAST;
pub(crate) const ROUTE_LOCAL: u8 = RTN_LOCAL;
pub(crate) const PROTO_STATIC: u8 = RTPROT_STATIC;
pub(crate) const SCOPE_LINK: u8 = RT_SCOPE_LINK;
pub(crate) const SCOPE_UNIVERSE: u8 = RT_SCOPE_UNIVERSE;
pub(crate) const SCOPE_HOST: u8 = RT_SCOPE_HOST;

/// Read an interface's ifindex from /sys (namespace-relative).
pub(crate) fn ifindex_of(name: &str) -> io::Result<u32> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?;
    s.trim()
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read an interface's MAC from /sys (namespace-relative).
pub(crate) fn mac_of(name: &str) -> io::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad MAC"));
    }
    for (i, p) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(p, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }
    Ok(mac)
}

impl NlSock {
    /// Look up a link by name (RTM_GETLINK dump, filtered client-side).
    /// Works in any namespace — unlike /sys, which is view-per-mount and
    /// shows the host's devices even inside a scoped setns.
    ///
    /// The whole dump is always drained before returning: an early return
    /// would leave the dump's tail in the socket buffer and poison the
    /// next request's reads (observed: the second call saw a stale
    /// NLMSG_DONE and reported an empty link list).
    pub(crate) fn get_link(&mut self, name: &str) -> io::Result<(u32, [u8; 6])> {
        const RTM_GETLINK: u16 = 18;
        const NLM_F_DUMP: u16 = 0x300;
        const NLMSG_DONE: u16 = 3;
        self.seq += 1;
        let seq = self.seq;
        let header = ifinfo(0, 0, 0);
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(pod_bytes(&header));
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        // SAFETY: buf holds a well-formed nlmsghdr blob.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut resp = vec![0u8; 8192];
        let mut found: Option<(u32, [u8; 6])> = None;
        loop {
            let n = self.recv_one(&mut resp)?;
            let mut done = false;
            let mut off = 0usize;
            while off + 16 <= n {
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                if hlen < 16 {
                    break;
                }
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hseq != seq {
                    break;
                }
                if htype == NLMSG_DONE {
                    done = true;
                    break;
                }
                if htype == NLMSG_ERROR {
                    let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                    return Err(io::Error::from_raw_os_error(-err));
                }
                if htype == RTM_NEWLINK && hlen >= 16 + 16 {
                    // ifinfomsg follows the nlmsghdr; attributes after that.
                    let ifi = &resp[off + 16..off + hlen];
                    let ifindex = i32::from_ne_bytes(ifi[4..8].try_into().unwrap());
                    let mut ifname: Option<String> = None;
                    let mut mac: Option<[u8; 6]> = None;
                    let mut aoff = 16;
                    while aoff + 4 <= ifi.len() {
                        let alen =
                            u16::from_ne_bytes(ifi[aoff..aoff + 2].try_into().unwrap()) as usize;
                        let atype = u16::from_ne_bytes(ifi[aoff + 2..aoff + 4].try_into().unwrap());
                        if alen < 4 || aoff + alen > ifi.len() {
                            break;
                        }
                        let payload = &ifi[aoff + 4..aoff + alen];
                        match atype {
                            IFLA_IFNAME => {
                                // attr payload is NUL-terminated
                                let end = payload
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(payload.len());
                                ifname =
                                    Some(String::from_utf8_lossy(&payload[..end]).into_owned());
                            }
                            IFLA_ADDRESS if payload.len() == 6 => {
                                mac = Some(payload.try_into().unwrap());
                            }
                            _ => {}
                        }
                        aoff += align(alen);
                    }
                    if ifname.as_deref() == Some(name)
                        && let Some(mac) = mac
                    {
                        found = Some((ifindex as u32, mac));
                    }
                }
                let next = align(hlen);
                if next == 0 {
                    break;
                }
                off += next;
            }
            if done {
                return found.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("link '{name}' not found"))
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_alignment() {
        let mut buf = Vec::new();
        put_attr(&mut buf, IFLA_IFNAME, &Attr::Str("dae0".into()));
        // header 4 + payload 5 (with NUL) = 9 → aligned to 12
        assert_eq!(buf.len(), 12);
        assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 9);
        assert_eq!(&buf[4..9], b"dae0\0");

        let mut buf = Vec::new();
        put_attr(&mut buf, RTA_OIF, &Attr::U32(7));
        assert_eq!(buf.len(), 8);
        assert_eq!(u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]), 7);
    }

    #[test]
    fn nested_attr() {
        let mut buf = Vec::new();
        put_attr(
            &mut buf,
            IFLA_LINKINFO,
            &Attr::Nested(vec![
                (IFLA_INFO_KIND, Attr::Str("veth".into())),
                (IFLA_INFO_DATA, Attr::Bytes(vec![1, 2, 3])),
            ]),
        );
        let outer = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(buf.len(), align(outer));
        assert!(outer > 4);
    }

    #[test]
    fn sock_open_close() {
        let _ = NlSock::new().expect("netlink socket");
    }

    #[test]
    fn get_link_lo() {
        let mut nl = NlSock::new().unwrap();
        let (idx, _mac) = nl.get_link("lo").expect("lo must exist");
        assert_eq!(idx, 1);
    }

    /// Whether daens is unavailable or the switch succeeds, the calling
    /// thread must come back in its original namespace (P1a regression).
    #[test]
    fn netns_with_daens_restores_namespace() {
        let before = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        let _ = crate::with_daens_netns("test", || Ok(()));
        let after = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        assert_eq!(before, after);
    }

    const RTM_GETRULE: u16 = 34;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_DONE: u16 = 3;

    /// Dump (fwmark, fwmask, table) of every rule in the current namespace.
    fn rule_dump(nl: &mut NlSock) -> io::Result<Vec<(u32, u32, u32)>> {
        nl.seq += 1;
        let seq = nl.seq;
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&RTM_GETRULE.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&[0u8; 12]); // fib_rule_hdr
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());
        // SAFETY: buf holds a well-formed nlmsghdr blob.
        let sent = unsafe {
            libc::send(
                nl.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = Vec::new();
        let mut resp = vec![0u8; 8192];
        'outer: loop {
            let n = nl.recv_one(&mut resp)?;
            let mut off = 0usize;
            while off + 16 <= n {
                let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
                let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
                let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
                if hseq == seq {
                    match htype {
                        NLMSG_DONE => break 'outer,
                        NLMSG_ERROR => {
                            let err =
                                i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                            if err != 0 {
                                return Err(io::Error::from_raw_os_error(-err));
                            }
                            break 'outer;
                        }
                        RTM_NEWRULE if hlen >= 16 + 12 => {
                            let hdr = &resp[off + 16..off + hlen];
                            let mut table = u32::from(hdr[4]);
                            let mut mark = 0u32;
                            let mut mask = 0u32;
                            let mut aoff = 12;
                            while aoff + 4 <= hdr.len() {
                                let alen =
                                    u16::from_ne_bytes(hdr[aoff..aoff + 2].try_into().unwrap())
                                        as usize;
                                let atype =
                                    u16::from_ne_bytes(hdr[aoff + 2..aoff + 4].try_into().unwrap());
                                if alen < 4 || aoff + alen > hdr.len() {
                                    break;
                                }
                                let payload = &hdr[aoff + 4..aoff + alen];
                                if payload.len() == 4 {
                                    let v = u32::from_ne_bytes(payload.try_into().unwrap());
                                    match atype {
                                        FRA_FWMARK => mark = v,
                                        FRA_FWMASK => mask = v,
                                        FRA_TABLE => table = v,
                                        _ => {}
                                    }
                                }
                                aoff += align(alen);
                            }
                            out.push((mark, mask, table));
                        }
                        _ => {}
                    }
                }
                let next = align(hlen);
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
        Ok(out)
    }

    /// Root-only roundtrip over every NlSock op the engine uses. Run with:
    /// `just test-netns`.
    #[test]
    #[ignore = "requires root; run via just test-netns"]
    fn netns_link_addr_route_rule_neigh_roundtrip() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: requires root");
            return;
        }
        const MARK: u32 = 0x0800_0099;
        const TABLE: u32 = 100;
        let mut nl = NlSock::new().unwrap();
        // Idempotent start: drop leftovers from an interrupted earlier run.
        let _ = nl.del_rule_fwmark(FAM_V4, MARK, TABLE);
        if let Ok((idx, _)) = nl.get_link("honkt0") {
            let _ = nl.del_link(idx);
        }

        let result = (|| -> io::Result<()> {
            nl.add_veth_pair("honkt0", "honkt1")?;
            let (idx, _mac) = nl.get_link("honkt0")?;
            nl.set_link_up(idx, true)?;
            nl.addr_op(true, idx, FAM_V4, &[10, 254, 99, 1], 32)?;
            nl.add_route(
                FAM_V4,
                TABLE,
                ROUTE_UNICAST,
                SCOPE_LINK,
                PROTO_STATIC,
                Some((&[198, 51, 100, 0], 24)),
                None,
                Some(idx),
            )?;
            nl.add_rule_fwmark(FAM_V4, MARK, TABLE)?;
            let rules = rule_dump(&mut nl)?;
            assert!(
                rules.contains(&(MARK, u32::MAX, TABLE)),
                "fwmark rule with full mask missing from dump: {rules:?}"
            );
            nl.neigh_replace(idx, FAM_V4, &[198, 51, 100, 1], &[0x02, 0, 0, 0, 0, 1])?;
            Ok(())
        })();

        let _ = nl.del_rule_fwmark(FAM_V4, MARK, TABLE);
        if let Ok((idx, _)) = nl.get_link("honkt0") {
            let _ = nl.del_link(idx);
        }
        result.unwrap();
    }
}
