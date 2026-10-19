//! Raw AF_PACKET capture and replay for the real-kernel TCP fixtures.

use anyhow::{Context, ensure};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(in crate::control::tests) fn hold_synack(fd: libc::c_int, hold: bool) -> anyhow::Result<()> {
    let mut instruction = libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0,
    };
    let filter = libc::sock_fprog {
        len: 1,
        filter: &mut instruction,
    };
    let unused: libc::c_int = 0;
    let (option, value, length) = if hold {
        (
            libc::SO_ATTACH_FILTER,
            (&filter as *const libc::sock_fprog).cast(),
            std::mem::size_of_val(&filter),
        )
    } else {
        (
            libc::SO_DETACH_FILTER,
            (&unused as *const libc::c_int).cast(),
            std::mem::size_of_val(&unused),
        )
    };
    ensure!(
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, option, value, length as _) } == 0,
        "gate SYNACK: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

pub(in crate::control::tests) fn packet_socket() -> anyhow::Result<OwnedFd> {
    let protocol = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    ensure!(
        fd >= 0,
        "open packet capture: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The next queued frame's length, or `None` once the non-blocking socket is drained.
pub(in crate::control::tests) fn recv_frame(
    fd: &OwnedFd,
    buffer: &mut [u8],
) -> anyhow::Result<Option<usize>> {
    let length = unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if length >= 0 {
        return Ok(Some(length as usize));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error.into())
}

/// Source IP, destination IP and TCP header+payload of an Ethernet frame carrying
/// TCP over the given IP family; `None` for anything else.
pub(in crate::control::tests) fn tcp_segment(
    frame: &[u8],
    ipv6: bool,
) -> Option<(&[u8], &[u8], &[u8])> {
    let (source, destination, transport) = match frame.get(12..14)? {
        [0x08, 0x00] if !ipv6 && frame.len() >= 34 && frame[23] == 6 => (
            &frame[26..30],
            &frame[30..34],
            14 + (frame[14] as usize & 15) * 4,
        ),
        [0x86, 0xdd] if ipv6 && frame.len() >= 54 && frame[20] == 6 => {
            (&frame[22..38], &frame[38..54], 54)
        }
        _ => return None,
    };
    let tcp = frame.get(transport..)?;
    (tcp.len() >= 20).then_some((source, destination, tcp))
}

fn tcp_offset(frame: &[u8], ipv6: bool) -> anyhow::Result<usize> {
    let (_, _, tcp) =
        tcp_segment(frame, ipv6).context("frame is not TCP over the expected family")?;
    Ok(frame.len() - tcp.len())
}

/// The sequence number of a captured SYN, which is the client's ISN.
pub(in crate::control::tests) fn syn_isn(frame: &[u8], ipv6: bool) -> anyhow::Result<u32> {
    let at = tcp_offset(frame, ipv6)? + 4;
    Ok(u32::from_be_bytes(frame[at..at + 4].try_into()?))
}

/// A copy of `frame` carrying another ISN; `Wire::replay` recomputes the checksum.
pub(in crate::control::tests) fn with_syn_isn(
    frame: &[u8],
    ipv6: bool,
    isn: u32,
) -> anyhow::Result<Vec<u8>> {
    let at = tcp_offset(frame, ipv6)? + 4;
    let mut frame = frame.to_vec();
    frame[at..at + 4].copy_from_slice(&isn.to_be_bytes());
    Ok(frame)
}

/// A copy of `frame` from another client port.
pub(in crate::control::tests) fn with_source_port(
    frame: &[u8],
    ipv6: bool,
    port: u16,
) -> anyhow::Result<Vec<u8>> {
    let at = tcp_offset(frame, ipv6)?;
    let mut frame = frame.to_vec();
    frame[at..at + 2].copy_from_slice(&port.to_be_bytes());
    Ok(frame)
}

pub(in crate::control::tests) struct Wire {
    fd: OwnedFd,
    address: libc::sockaddr_ll,
}

impl Wire {
    pub(in crate::control::tests) fn on(interface: &str) -> anyhow::Result<Self> {
        let fd = packet_socket()?;
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as _;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = crate::netlink::NlSock::new()?.get_link(interface)?.0 as _;
        ensure!(
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } == 0,
            "bind packet capture: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self { fd, address })
    }

    /// The next captured TCP frame of the given family accepted by `wanted`.
    async fn capture(&self, ipv6: bool, wanted: impl Fn(&[u8]) -> bool) -> anyhow::Result<Vec<u8>> {
        let mut bytes = [0u8; 2048];
        loop {
            let Some(length) = recv_frame(&self.fd, &mut bytes)? else {
                tokio::task::yield_now().await;
                continue;
            };
            let frame = &bytes[..length];
            let Some((_, _, tcp)) = tcp_segment(frame, ipv6) else {
                continue;
            };
            if wanted(tcp) {
                return Ok(frame.to_vec());
            }
        }
    }

    pub(in crate::control::tests) async fn synack(
        &self,
        source: SocketAddr,
        target: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        self.capture(source.is_ipv6(), |tcp| {
            u16::from_be_bytes([tcp[0], tcp[1]]) == target.port()
                && u16::from_be_bytes([tcp[2], tcp[3]]) == source.port()
                && tcp[13] & 0x12 == 0x12
        })
        .await
    }

    /// The client's pure SYN, captured on the client's own edge.
    pub(in crate::control::tests) async fn syn(
        &self,
        source: SocketAddr,
        target: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        self.capture(source.is_ipv6(), |tcp| {
            u16::from_be_bytes([tcp[0], tcp[1]]) == source.port()
                && u16::from_be_bytes([tcp[2], tcp[3]]) == target.port()
                && tcp[13] & 0x12 == 0x02
        })
        .await
    }

    pub(in crate::control::tests) fn replay(&self, frame: &[u8]) -> anyhow::Result<()> {
        // AF_PACKET can observe CHECKSUM_PARTIAL before the veth completes it.
        let mut frame = frame.to_vec();
        let (transport, length, mut sum) = if frame[12..14] == [0x08, 0x00] {
            let header = (frame[14] as usize & 15) * 4;
            let length = u16::from_be_bytes([frame[16], frame[17]]) as usize - header;
            (
                14 + header,
                length,
                checksum_sum(&frame[26..34]) + 6 + length as u32,
            )
        } else {
            let length = u16::from_be_bytes([frame[18], frame[19]]) as usize;
            (54, length, checksum_sum(&frame[22..54]) + 6 + length as u32)
        };
        frame[transport + 16..transport + 18].fill(0);
        sum += checksum_sum(&frame[transport..transport + length]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        frame[transport + 16..transport + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let mut address = self.address;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&frame[..6]);
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as _,
            )
        };
        ensure!(
            sent == frame.len() as isize,
            "replay captured SYNACK: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

fn checksum_sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|word| u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32)
        .sum()
}
