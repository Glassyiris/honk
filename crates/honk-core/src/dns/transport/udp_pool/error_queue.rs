//! Linux quotes the failed UDP datagram in the socket error queue.

use std::io::{self, IoSliceMut};
use std::os::fd::{AsRawFd, RawFd};

use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use tokio::io::Interest;
use tokio::net::UdpSocket;

pub(super) fn enable(socket: &socket2::Socket, ipv6: bool) -> io::Result<()> {
    if ipv6 {
        setsockopt(socket, sockopt::Ipv6RecvErr, &true)
    } else {
        setsockopt(socket, sockopt::Ipv4RecvErr, &true)
    }
    .map_err(io::Error::from)
}

pub(super) async fn receive_datagram(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<usize> {
    // Tokio recv also consumes ERROR readiness; an EAGAIN there can hide a
    // still-queued ICMP quote from the separate error-queue reader.
    socket
        .async_io(Interest::READABLE, || {
            nix::sys::socket::recv(socket.as_raw_fd(), buffer, MsgFlags::MSG_DONTWAIT)
                .map_err(io::Error::from)
        })
        .await
}

pub(super) async fn receive(
    socket: &UdpSocket,
    quote: &mut [u8],
) -> io::Result<(usize, Option<io::Error>)> {
    socket
        .async_io(Interest::ERROR, || receive_one(socket.as_raw_fd(), quote))
        .await
}

fn receive_one(fd: RawFd, quote: &mut [u8]) -> io::Result<(usize, Option<io::Error>)> {
    let mut iov = [IoSliceMut::new(quote)];
    let mut control = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6);
    let message = recvmsg::<SockaddrStorage>(
        fd,
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;
    if message.flags.contains(MsgFlags::MSG_CTRUNC) {
        return Ok((0, None));
    }
    for control in message.cmsgs().map_err(io::Error::from)? {
        let error = match control {
            ControlMessageOwned::Ipv4RecvErr(error, _)
            | ControlMessageOwned::Ipv6RecvErr(error, _) => error,
            _ => continue,
        };
        if let Ok(errno) = i32::try_from(error.ee_errno)
            && errno > 0
        {
            // Truncation after the complete DNS question does not affect attribution.
            return Ok((message.bytes, Some(io::Error::from_raw_os_error(errno))));
        }
    }
    Ok((0, None))
}
