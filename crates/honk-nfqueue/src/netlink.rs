//! Raw netlink (NETLINK_NETFILTER) message construction and parsing shared
//! by the nfqueue listener and the nftables ruleset.
//!
//! Everything is hand-rolled: the crate deliberately has no libnftnl/nft
//! dependency, so messages are built byte-exact against the kernel UAPI.
//! All multi-byte netlink attribute payloads crossing into nftables/nfqueue
//! are big-endian unless noted; the nlmsghdr itself is native-endian.

use std::io;

pub const NETLINK_NETFILTER: libc::c_int = 12;

pub const NFNL_SUBSYS_QUEUE: u16 = 3;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;

pub const NFNL_MSG_BATCH_BEGIN: u16 = 16;
pub const NFNL_MSG_BATCH_END: u16 = 17;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_CREATE: u16 = 0x400;

pub const NLA_F_NESTED: u16 = 0x8000;

pub const NLMSG_HDRLEN: usize = 16;
pub const NFGENMSG_LEN: usize = 4;
pub const NLA_HDRLEN: usize = 4;

pub const NFPROTO_INET: u8 = 1;

/// nfgenmsg resource id for nftables batch bookkeeping messages.
pub const NFNL_BATCH_RES_ID: u16 = NFNL_SUBSYS_NFTABLES;

pub fn align4(n: usize) -> usize {
    n.div_ceil(4) * 4
}

/// Append one nlmsghdr + nfgenmsg header; returns the offset of nlmsg_len
/// so the caller can patch it once attributes are appended.
pub fn put_msg_header(
    buf: &mut Vec<u8>,
    msg_type: u16,
    flags: u16,
    seq: u32,
    family: u8,
    res_id: u16,
) -> usize {
    let start = buf.len();
    buf.extend_from_slice(&[0u8; 4]); // nlmsg_len, patched later
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid (kernel fills)
    buf.push(family);
    buf.push(0); // NFNETLINK_V0
    buf.extend_from_slice(&res_id.to_be_bytes());
    start
}

/// Patch the nlmsg_len of the message starting at `start`.
pub fn seal_msg(buf: &mut [u8], start: usize) {
    let len = (buf.len() - start) as u32;
    buf[start..start + 4].copy_from_slice(&len.to_ne_bytes());
}

/// Append one netlink attribute (4-byte aligned).
pub fn put_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = (NLA_HDRLEN + payload.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    let pad = align4(payload.len()) - payload.len();
    buf.extend(std::iter::repeat_n(0u8, pad));
}

/// Begin a nested attribute; returns the offset of its nla_len for
/// [`seal_nested`].
pub fn put_nested(buf: &mut Vec<u8>, attr_type: u16) -> usize {
    let start = buf.len();
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&(attr_type | NLA_F_NESTED).to_ne_bytes());
    start
}

pub fn seal_nested(buf: &mut [u8], start: usize) {
    let len = (buf.len() - start) as u16;
    buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
}

pub fn put_attr_str(buf: &mut Vec<u8>, attr_type: u16, s: &str) {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    put_attr(buf, attr_type, &bytes);
}

pub fn put_attr_be32(buf: &mut Vec<u8>, attr_type: u16, v: u32) {
    put_attr(buf, attr_type, &v.to_be_bytes());
}

pub fn put_attr_be16(buf: &mut Vec<u8>, attr_type: u16, v: u16) {
    put_attr(buf, attr_type, &v.to_be_bytes());
}

pub fn put_attr_be64(buf: &mut Vec<u8>, attr_type: u16, v: u64) {
    put_attr(buf, attr_type, &v.to_be_bytes());
}

/// One parsed netlink attribute (payload slice borrows the message buffer).
#[derive(Debug, Clone, Copy)]
pub struct Attr<'a> {
    pub attr_type: u16,
    pub payload: &'a [u8],
}

/// Iterate the attributes in `buf` (already positioned at the first
/// attribute). Malformed lengths end iteration instead of erroring: a
/// truncated kernel message is simply not what we asked for.
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

pub fn attrs(buf: &[u8]) -> AttrIter<'_> {
    AttrIter { buf }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        if self.buf.len() < NLA_HDRLEN {
            return None;
        }
        let len = u16::from_ne_bytes([self.buf[0], self.buf[1]]) as usize;
        if len < NLA_HDRLEN || len > self.buf.len() {
            return None;
        }
        let attr_type = u16::from_ne_bytes([self.buf[2], self.buf[3]]) & !NLA_F_NESTED;
        let payload = &self.buf[NLA_HDRLEN..len];
        // Same tail-padding allowance as split_messages.
        let advance = align4(len).min(self.buf.len());
        self.buf = &self.buf[advance..];
        Some(Attr { attr_type, payload })
    }
}

/// One received netlink message: header fields plus the body after the
/// nlmsghdr.
#[derive(Debug)]
pub struct NlMsg<'a> {
    pub msg_type: u16,
    pub seq: u32,
    pub body: &'a [u8],
}

/// Split a received datagram into its netlink messages.
pub fn split_messages(mut buf: &[u8]) -> Vec<NlMsg<'_>> {
    let mut out = Vec::new();
    while buf.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        // align4(len) may exceed the remaining bytes on the last message of
        // a datagram (the kernel does not pad the tail); treat both as end.
        if len < NLMSG_HDRLEN || len > buf.len() {
            break;
        }
        let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
        let seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
        out.push(NlMsg {
            msg_type,
            seq,
            body: &buf[NLMSG_HDRLEN..len],
        });
        let advance = align4(len).min(buf.len());
        buf = &buf[advance..];
    }
    out
}

/// Parse the NLMSG_ERROR payload: the kernel's error code (0 = ACK).
pub fn parse_error(body: &[u8]) -> Option<i32> {
    if body.len() < 4 {
        return None;
    }
    Some(i32::from_ne_bytes([body[0], body[1], body[2], body[3]]))
}

/// Create a bound NETLINK_NETFILTER socket. `nl_pid` 0 lets the kernel
/// assign the port id.
pub fn netlink_socket(nonblocking: bool) -> io::Result<i32> {
    let flags = if nonblocking {
        libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC
    } else {
        libc::SOCK_RAW | libc::SOCK_CLOEXEC
    };
    let fd = unsafe { libc::socket(libc::AF_NETLINK, flags, NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// Blocking sendmsg of a complete datagram on a netlink socket.
pub fn send(fd: i32, buf: &[u8]) -> io::Result<()> {
    let ret = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret as usize != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short netlink send",
        ));
    }
    Ok(())
}

/// Blocking receive of one datagram.
pub fn recv(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let ret = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret as usize)
}

/// Send `buf` and wait for the NLMSG_ERROR ACK matching `seq` (0 = ok).
pub fn send_and_ack(fd: i32, buf: &[u8], seq: u32) -> io::Result<()> {
    send(fd, buf)?;
    let mut rbuf = vec![0u8; 65536];
    loop {
        let n = recv(fd, &mut rbuf)?;
        for msg in split_messages(&rbuf[..n]) {
            if msg.msg_type != NLMSG_ERROR || msg.seq != seq {
                continue;
            }
            let code = parse_error(msg.body).unwrap_or(-(libc::EIO));
            if code == 0 {
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(-code));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nla_round_trip_and_alignment() {
        let mut buf = Vec::new();
        put_attr_str(&mut buf, 1, "abc");
        put_attr_be32(&mut buf, 2, 0x0102_0304);
        put_attr(&mut buf, 3, &[17]);
        let got: Vec<(u16, Vec<u8>)> = attrs(&buf)
            .map(|a| (a.attr_type, a.payload.to_vec()))
            .collect();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (1, b"abc\0".to_vec()));
        assert_eq!(got[1], (2, vec![1, 2, 3, 4]));
        assert_eq!(got[2], (3, vec![17]));
    }

    #[test]
    fn nested_attr_round_trip() {
        let mut buf = Vec::new();
        let nest = put_nested(&mut buf, 9);
        put_attr_be16(&mut buf, 1, 320);
        seal_nested(&mut buf, nest);
        let top: Vec<Attr<'_>> = attrs(&buf).collect();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].attr_type, 9);
        let inner: Vec<Attr<'_>> = attrs(top[0].payload).collect();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].attr_type, 1);
        assert_eq!(inner[0].payload, [0x01, 0x40]);
    }

    #[test]
    fn message_split_and_error_parse() {
        // NLMSG_ERROR carries no nfgenmsg: body = i32 error + orig header.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // len, patched
        buf.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&77u32.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&(-11i32).to_ne_bytes()); // -EAGAIN
        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());
        let msgs = split_messages(&buf);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].msg_type, NLMSG_ERROR);
        assert_eq!(msgs[0].seq, 77);
        assert_eq!(parse_error(msgs[0].body), Some(-11));
    }
}
