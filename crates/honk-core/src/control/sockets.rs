use super::*;
use crate::dns::wire::extract_ips_from_dns_response;

#[cfg(target_os = "linux")]
const IPV6_TRANSPARENT_OPT: libc::c_int = libc::IPV6_TRANSPARENT;
#[cfg(target_os = "linux")]
const IPV6_RECVORIGDSTADDR_OPT: libc::c_int = 74;
#[cfg(target_os = "linux")]
const IPV6_ORIGDSTADDR_OPT: libc::c_int = 74;
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST_OPT: libc::c_int = 80;

/// Bind the transparent TCP TPROXY listener.
///
/// Go dae alignment ("listen and serve in dae netns", cmd/run.go:367): in
/// real eBPF mode the socket is created, configured and bound inside daens
/// via a scoped `crate::with_daens_netns` switch.  A socket is pinned to the
/// netns it was created in, so afterwards any (host-netns) worker thread may
/// accept on it; connection handling and upstream dialing run in the host
/// netns, while replies to the client are written back on the daens-resident
/// socket so the kernel routes them via dae0peer → host dae0_ingress
/// (REDIRECT_TRACK rewrite) to the LAN.  In mock mode there is no daens and
/// the listener is bound in the current (host) netns.
pub(super) fn bind_tproxy_tcp(addr: SocketAddr, _mark: u32) -> anyhow::Result<TcpListener> {
    #[cfg(target_os = "linux")]
    if daens_netns_exists() {
        return crate::with_daens_netns("bind TPROXY TCP listener", || build_tproxy_tcp(addr));
    }
    build_tproxy_tcp(addr)
}

/// Whether the daens namespace has been set up.  Only real eBPF mode creates
/// it (mock mode and tests stay entirely in the host netns), so its presence
/// is the switch between "bind inside daens" and "bind here".
#[cfg(target_os = "linux")]
fn daens_netns_exists() -> bool {
    std::path::Path::new(crate::DAENS_NS_PATH).exists()
}

fn build_tproxy_tcp(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_cloexec(true)?;
    socket.set_reuse_address(true)?;
    if domain == Domain::IPV6 {
        // Keep the v6 listener v6-only so it does not conflict with the v4 listener.
        socket.set_only_v6(true)?;
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;
        if addr.is_ipv4() {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IP_TRANSPARENT): {}",
                    std::io::Error::last_os_error()
                );
            }
        } else {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT_OPT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IPV6_TRANSPARENT): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        // SO_MARK is intentionally not set.  With the eBPF bpf_sk_assign
        // datapath the listener does not need a policy-route mark; replies
        // are routed back to the client through the daens main table
        // (default via dae0peer), which only steers fwmark'd packets into
        // the tproxy table.
    }

    socket.bind(&addr.into())?;
    socket.listen(128)?;

    Ok(TcpListener::from_std(socket.into())?)
}

/// Clear the packet mark on a socket so that locally generated replies are
/// routed through the ordinary routing table, not the TPROXY policy route.
pub(super) fn set_so_mark_zero(fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let zero: libc::c_uint = 0;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &zero as *const _ as *const libc::c_void,
            std::mem::size_of_val(&zero) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
    }
    Ok(())
}

/// Bind the transparent UDP TPROXY socket.
///
/// Bound inside daens like the TCP listener (scoped `with_daens_netns`
/// switch; falls back to the current netns in mock mode) so the daens-side
/// TC/sk_lookup programs deliver datagrams to it in its own namespace.
/// Replies to clients are sent through dedicated daens-resident reply
/// sockets (see `new_udp_reply_socket` / the cached DNS reply sockets
/// below), not through this listener socket.
pub(super) fn bind_tproxy_udp(addr: SocketAddr, _mark: u32) -> anyhow::Result<UdpSocket> {
    #[cfg(target_os = "linux")]
    if daens_netns_exists() {
        return crate::with_daens_netns("bind TPROXY UDP listener", || build_tproxy_udp(addr));
    }
    build_tproxy_udp(addr)
}

fn build_tproxy_udp(addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_cloexec(true)?;
    socket.set_reuse_address(true)?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }

    #[cfg(target_os = "linux")]
    unsafe {
        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;
        if addr.is_ipv4() {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IP_TRANSPARENT): {}",
                    std::io::Error::last_os_error()
                );
            }
            // IP_RECVORIGDSTADDR is required to retrieve the original destination
            // of TPROXY UDP datagrams (the eBPF path replaces the destination with
            // the local tproxy listener address).
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IP_RECVORIGDSTADDR): {}",
                    std::io::Error::last_os_error()
                );
            }
        } else {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT_OPT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IPV6_TRANSPARENT): {}",
                    std::io::Error::last_os_error()
                );
            }
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_RECVORIGDSTADDR_OPT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IPV6_RECVORIGDSTADDR): {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        // SO_MARK is intentionally not set here because the UDP listener does
        // not need a routing mark.  Clear it explicitly in case the underlying
        // socket inherited a mark from a previous binding.
        set_so_mark_zero(socket.as_raw_fd())?;
    }

    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// Send a UDP reply for a TPROXY-received datagram using the original
/// destination address as the source.  The client expects the response to come
/// from the address it sent the query to (e.g. the bridge gateway at port 53),
/// not from the local tproxy listener port.
pub(super) async fn send_udp_reply_from_orig_dst(
    data: &[u8],
    client_addr: SocketAddr,
    original_dst: SocketAddr,
) -> io::Result<usize> {
    // Fast path: reuse the cached per-family transparent socket instead of
    // paying socket()+setsockopt+bind per reply. Only usable when the reply
    // source port is the DNS port — the DNS controller always reconstructs
    // the original destination with port 53. Anything else (or a failure to
    // create the cached socket) falls through to the one-shot socket below.
    #[cfg(target_os = "linux")]
    if original_dst.port() == 53 {
        match send_dns_reply_cached(data, client_addr, original_dst).await {
            Some(Ok(n)) => {
                debug!(
                    "UDP reply sent to {} from {} ({} bytes)",
                    client_addr, original_dst, n
                );
                return Ok(n);
            }
            Some(Err(e)) => {
                warn!(
                    "UDP reply to {} from {} failed: {}",
                    client_addr, original_dst, e
                );
                return Err(e);
            }
            None => { /* cached socket unavailable — one-shot fallback */ }
        }
    }

    let udp = new_udp_reply_socket(original_dst)?;
    match udp.send_to(data, client_addr).await {
        Ok(n) => {
            debug!(
                "UDP reply sent to {} from {} ({} bytes)",
                client_addr, original_dst, n
            );
            Ok(n)
        }
        Err(e) => {
            warn!(
                "UDP reply to {} from {} failed: {}",
                client_addr, original_dst, e
            );
            Err(e)
        }
    }
}

/// Create a one-shot transparent UDP socket bound to `original_dst` for a
/// single UDP reply.
///
/// Go "anyfrom" semantics: in real eBPF mode the socket is created inside
/// the daens netns via a scoped `crate::with_daens_netns` switch, so its
/// reply packets egress dae0peer and take the host dae0_ingress rewrite path
/// back to the LAN client.  A socket is pinned to the netns it was created
/// in, so after creation it may be used from any (host-netns) worker thread.
/// In mock mode there is no daens and the socket is created in the current
/// (host) netns.
#[cfg(target_os = "linux")]
pub(super) fn new_udp_reply_socket(original_dst: SocketAddr) -> io::Result<UdpSocket> {
    if daens_netns_exists() {
        return crate::with_daens_netns("create UDP reply socket", || {
            build_udp_reply_socket(original_dst).map_err(anyhow::Error::from)
        })
        .map_err(into_io_error);
    }
    build_udp_reply_socket(original_dst)
}

/// Non-Linux fallback: no daens netns exists; create the socket in the
/// current namespace.
#[cfg(not(target_os = "linux"))]
pub(super) fn new_udp_reply_socket(original_dst: SocketAddr) -> io::Result<UdpSocket> {
    build_udp_reply_socket(original_dst)
}

/// Flatten a `with_daens_netns` error back into an `io::Error`, preserving
/// the original `io::Error` (and its kind) when the scoped closure produced
/// one.
#[cfg(target_os = "linux")]
fn into_io_error(e: anyhow::Error) -> io::Error {
    e.downcast::<io::Error>()
        .unwrap_or_else(|e| io::Error::other(e.to_string()))
}

fn build_udp_reply_socket(original_dst: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if original_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    unsafe {
        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;
        if original_dst.is_ipv4() {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            let ret = libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT_OPT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    socket.bind(&original_dst.into())?;
    UdpSocket::from_std(socket.into())
}

// Sending every DNS response through a fresh transparent socket costs
// socket()+setsockopt+bind per reply. DNS replies always originate from
// port 53 (the DNS controller reconstructs the destination with port 53),
// so one cached socket per address family bound to :53 serves every reply;
// the per-reply source address is supplied via IP_PKTINFO / IPV6_PKTINFO
// ancillary data on each sendmsg — the same "anyfrom" mechanism Go dae
// uses. The transparent setsockopts therefore run once per socket instead
// of once per reply.
//
// Netns note: the process always stays in the host netns.  Each cached
// socket is created inside daens via a scoped `crate::with_daens_netns`
// switch (Go anyfrom semantics: the reply socket must live in daens so its
// packets egress dae0peer → host dae0_ingress rewrite → LAN; mock mode has
// no daens and creates it in the host netns).  A socket is pinned to the
// netns it was created in no matter which worker thread sends through it —
// creation in daens, use from anywhere.
#[cfg(target_os = "linux")]
static DNS_REPLY_SOCK_V4: Mutex<Option<Arc<UdpSocket>>> = Mutex::new(None);
#[cfg(target_os = "linux")]
static DNS_REPLY_SOCK_V6: Mutex<Option<Arc<UdpSocket>>> = Mutex::new(None);

/// Source port every DNS reply is sent from (the port clients send queries to).
#[cfg(target_os = "linux")]
const DNS_REPLY_SOURCE_PORT: u16 = 53;

#[cfg(target_os = "linux")]
fn dns_reply_socket_cache(is_v6: bool) -> &'static Mutex<Option<Arc<UdpSocket>>> {
    if is_v6 {
        &DNS_REPLY_SOCK_V6
    } else {
        &DNS_REPLY_SOCK_V4
    }
}

/// Create the cached transparent UDP reply socket for one address family.
/// Same socket setup as the one-shot path, but bound to :53 so the per-send
/// pktinfo source address only has to supply the source IP.
///
/// Like the one-shot path, the socket is created inside daens via a scoped
/// `crate::with_daens_netns` switch when daens exists (Go anyfrom semantics)
/// and is pinned to daens afterwards; sends may run on any worker thread.
/// Mock mode has no daens and creates the socket in the current netns.
#[cfg(target_os = "linux")]
fn new_dns_reply_socket(is_v6: bool) -> io::Result<UdpSocket> {
    if daens_netns_exists() {
        return crate::with_daens_netns("create cached DNS reply socket", || {
            build_dns_reply_socket(is_v6).map_err(anyhow::Error::from)
        })
        .map_err(into_io_error);
    }
    build_dns_reply_socket(is_v6)
}

#[cfg(target_os = "linux")]
fn build_dns_reply_socket(is_v6: bool) -> io::Result<UdpSocket> {
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    if is_v6 {
        socket.set_only_v6(true)?;
    }

    unsafe {
        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;
        let (level, opt) = if is_v6 {
            (libc::SOL_IPV6, IPV6_TRANSPARENT_OPT)
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT)
        };
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let bind_addr = if is_v6 {
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            DNS_REPLY_SOURCE_PORT,
        )
    } else {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            DNS_REPLY_SOURCE_PORT,
        )
    };
    socket.bind(&bind_addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// Get the cached DNS reply socket for the family, creating it lazily on
/// first use.
#[cfg(target_os = "linux")]
fn get_dns_reply_socket(is_v6: bool) -> io::Result<Arc<UdpSocket>> {
    let cache = dns_reply_socket_cache(is_v6);
    if let Some(sock) = cache.lock().unwrap().as_ref() {
        return Ok(Arc::clone(sock));
    }
    // Create outside the lock; if a racing creator won, reuse its socket
    // and drop ours.
    let new_sock = Arc::new(new_dns_reply_socket(is_v6)?);
    let mut guard = cache.lock().unwrap();
    if let Some(sock) = guard.as_ref() {
        return Ok(Arc::clone(sock));
    }
    *guard = Some(Arc::clone(&new_sock));
    Ok(new_sock)
}

/// Replace the cached socket after a send failure — unless another thread
/// already replaced it, in which case the fresh one is returned. The old
/// socket may be stale (dead interface state), so the caller retries once
/// with the returned socket before reporting an error.
#[cfg(target_os = "linux")]
fn replace_dns_reply_socket(is_v6: bool, old: &Arc<UdpSocket>) -> io::Result<Arc<UdpSocket>> {
    let cache = dns_reply_socket_cache(is_v6);
    let mut guard = cache.lock().unwrap();
    if let Some(cur) = guard.as_ref()
        && !Arc::ptr_eq(cur, old)
    {
        return Ok(Arc::clone(cur));
    }
    let new_sock = Arc::new(new_dns_reply_socket(is_v6)?);
    *guard = Some(Arc::clone(&new_sock));
    Ok(new_sock)
}

/// Try to send a DNS reply through the cached per-family transparent socket.
///
/// Returns `None` when the cached path is unavailable (socket creation
/// failed) and the caller should fall back to a one-shot socket. On a send
/// failure the cached socket is rebuilt once and the send retried once
/// before the error is reported.
#[cfg(target_os = "linux")]
async fn send_dns_reply_cached(
    data: &[u8],
    client_addr: SocketAddr,
    original_dst: SocketAddr,
) -> Option<io::Result<usize>> {
    let is_v6 = original_dst.is_ipv6();
    let sock = match get_dns_reply_socket(is_v6) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "cached DNS reply socket unavailable ({}); falling back to one-shot",
                e
            );
            return None;
        }
    };
    let first = sock
        .async_io(Interest::WRITABLE, || {
            sendmsg_with_src(sock.as_raw_fd(), data, original_dst.ip(), client_addr)
        })
        .await;
    match first {
        Ok(n) => return Some(Ok(n)),
        Err(e) => {
            debug!(
                "cached DNS reply socket send failed ({}); rebuilding once",
                e
            );
        }
    }
    let sock = match replace_dns_reply_socket(is_v6, &sock) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "cached DNS reply socket rebuild failed ({}); falling back to one-shot",
                e
            );
            return None;
        }
    };
    Some(
        sock.async_io(Interest::WRITABLE, || {
            sendmsg_with_src(sock.as_raw_fd(), data, original_dst.ip(), client_addr)
        })
        .await,
    )
}

/// Send a datagram to `dst` with `src_ip` as the source address via pktinfo
/// ancillary data. The source port is the socket's bound port (53).
#[cfg(target_os = "linux")]
fn sendmsg_with_src(
    fd: RawFd,
    data: &[u8],
    src_ip: std::net::IpAddr,
    dst: SocketAddr,
) -> io::Result<usize> {
    let dst_addr = socket2::SockAddr::from(dst);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // Sized for the largest pktinfo payload (in6_pktinfo) + cmsg header.
    let mut cmsg_buf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = dst_addr.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = dst_addr.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;

    let payload_len = match src_ip {
        std::net::IpAddr::V4(_) => std::mem::size_of::<libc::in_pktinfo>(),
        std::net::IpAddr::V6(_) => std::mem::size_of::<libc::in6_pktinfo>(),
    };
    // Exact control length for a single cmsg (a receive buffer would use the
    // full buffer length instead).
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(payload_len as _) } as _;

    unsafe {
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if hdr.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pktinfo cmsg buffer too small",
            ));
        }
        match src_ip {
            std::net::IpAddr::V4(ip) => {
                (*hdr).cmsg_level = libc::IPPROTO_IP;
                (*hdr).cmsg_type = libc::IP_PKTINFO;
                (*hdr).cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
                let pktinfo = libc::CMSG_DATA(hdr) as *mut libc::in_pktinfo;
                (*pktinfo).ipi_ifindex = 0;
                (*pktinfo).ipi_spec_dst = libc::in_addr {
                    s_addr: u32::from(ip).to_be(),
                };
                (*pktinfo).ipi_addr = libc::in_addr { s_addr: 0 };
            }
            std::net::IpAddr::V6(ip) => {
                (*hdr).cmsg_level = libc::IPPROTO_IPV6;
                (*hdr).cmsg_type = libc::IPV6_PKTINFO;
                (*hdr).cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
                let pktinfo = libc::CMSG_DATA(hdr) as *mut libc::in6_pktinfo;
                (*pktinfo).ipi6_addr = libc::in6_addr {
                    s6_addr: ip.octets(),
                };
                (*pktinfo).ipi6_ifindex = 0;
            }
        }
        let n = libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

/// Receive a UDP datagram from a TPROXY socket together with its original
/// destination address.  Requires `IP_RECVORIGDSTADDR` to be set on the socket.
pub(super) async fn recv_from_with_orig_dst(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    socket
        .async_io(Interest::READABLE, || {
            recvmsg_origdst(socket.as_raw_fd(), buf)
        })
        .await
}

fn recvmsg_origdst(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut cmsg_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    #[cfg(target_env = "musl")]
    {
        msg.msg_controllen = cmsg_buf.len() as u32;
    }
    #[cfg(not(target_env = "musl"))]
    {
        msg.msg_controllen = cmsg_buf.len();
    }

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let src = sockaddr_to_std(&src_addr, msg.msg_namelen)?;

    let mut orig_dst = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR {
                let sin = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let ip = std::net::Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                let port = u16::from_be((*sin).sin_port);
                orig_dst = Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
                break;
            }
            if (*cmsg).cmsg_level == libc::SOL_IPV6 && (*cmsg).cmsg_type == IPV6_ORIGDSTADDR_OPT {
                let sin6 = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let ip = std::net::Ipv6Addr::from((*sin6).sin6_addr.s6_addr);
                let port = u16::from_be((*sin6).sin6_port);
                orig_dst = Some(SocketAddr::new(std::net::IpAddr::V6(ip), port));
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let orig_dst = match orig_dst {
        Some(d) => d,
        None => {
            // When eBPF delivers the packet directly to the TPROXY listener,
            // the kernel may not supply IP_ORIGDSTADDR.  The transparent socket
            // was bound to the original destination, so its local address is a
            // usable fallback (same fallback used for TCP in serve_connection).
            let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut local_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            if unsafe {
                libc::getsockname(
                    fd,
                    &mut local as *mut _ as *mut libc::sockaddr,
                    &mut local_len,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            sockaddr_to_std(&local, local_len)?
        }
    };

    Ok((n as usize, src, orig_dst))
}

fn sockaddr_to_std(addr: &libc::sockaddr_storage, len: libc::socklen_t) -> io::Result<SocketAddr> {
    if len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short sockaddr"));
    }
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            if len < std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in",
                ));
            }
            let sin = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            if len < std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short sockaddr_in6",
                ));
            }
            let sin6 = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown address family",
        )),
    }
}

pub(super) fn get_original_dst(stream: &TcpStream) -> anyhow::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        let mut ss_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut ss_len) < 0 {
            anyhow::bail!("getsockname: {}", std::io::Error::last_os_error());
        }

        if ss.ss_family as libc::c_int == libc::AF_INET {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut addr_len,
            );
            if ret != 0 {
                anyhow::bail!(
                    "getsockopt(SO_ORIGINAL_DST): {}",
                    std::io::Error::last_os_error()
                );
            }
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
        }

        if ss.ss_family as libc::c_int == libc::AF_INET6 {
            let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
            let mut addr6_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let ret = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                IP6T_SO_ORIGINAL_DST_OPT,
                &mut addr6 as *mut _ as *mut libc::c_void,
                &mut addr6_len,
            );
            if ret != 0 {
                anyhow::bail!(
                    "getsockopt(IP6T_SO_ORIGINAL_DST): {}",
                    std::io::Error::last_os_error()
                );
            }
            let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            return Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port));
        }

        anyhow::bail!("unsupported socket address family {}", ss.ss_family)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        anyhow::bail!("TPROXY destination retrieval is only supported on Linux")
    }
}

/// Heuristic check for a DNS query payload.
/// Used as a fallback when the eBPF bpf_sk_assign path does not preserve
/// IP_ORIGDSTADDR for UDP datagrams: any DNS-shaped payload received on the
/// TPROXY listener is treated as a DNS query destined for port 53.
pub(super) fn is_dns_payload(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    // QR bit must be 0 (query).
    data[2] & 0x80 == 0
}

/// Exact mirror of the DNS controller's UDP acceptance condition
/// (`dns_control::is_dns_query` is private to that module).
///
/// `handle_udp_dns` consumes a datagram iff this returns true: the port-53 /
/// DNS-payload check in `serve_udp_connection` only decides whether the
/// original destination is rewritten to port 53 before the same payload test
/// runs (and `is_dns_query` already implies a DNS-shaped payload). Datagrams
/// failing this check are guaranteed to fall through the DNS fast path, so
/// the UDP fast path may safely skip the DNS controller for them.
pub(super) fn might_be_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    // QR bit must be 0 (query).
    if data[2] & 0x80 != 0 {
        return false;
    }
    crate::dns::forwarder::parse_dns_question(data).is_some()
}

/// UDP datapath fast path: forward a datagram belonging to an established
/// endpoint inline in the accept loop.
///
/// Runs on the reusable receive buffer — no task spawn, no heap copy, no
/// QUIC sniffer, no concurrency permit. Returns `true` when the datagram was
/// fully handled (forwarded or dropped) and the accept loop can move on to
/// the next packet; `false` when it must take the slow path
/// (`serve_udp_connection`): new-flow setup or a possible DNS query.
///
/// Semantics match the endpoint-reuse branch of `serve_udp_connection`
/// (same drop pre-checks, `mark_sent`/`refresh`, no stats accounting);
/// skipping the QUIC sniffer on hits is safe because an established
/// endpoint means routing for this flow was already decided when its first
/// packet took the slow path.
pub(super) async fn udp_fast_path(
    udp_pool: &UdpEndpointPool,
    data: &[u8],
    client_addr: SocketAddr,
    original_dst: SocketAddr,
) -> bool {
    // Same drop pre-checks as serve_udp_connection: honk-internal subnet and
    // broadcast/multicast traffic must never be proxied.
    if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
        trace!(
            "Skipping honk-internal UDP {} -> {}",
            client_addr, original_dst
        );
        return true;
    }
    if is_broadcast_or_multicast(&original_dst.ip()) {
        trace!(
            "Skipping broadcast/multicast UDP {} -> {}",
            client_addr, original_dst
        );
        return true;
    }

    // Anything the DNS controller would consume takes the slow path (exact
    // acceptance condition, not an approximation — see might_be_dns_query).
    if might_be_dns_query(data) {
        return false;
    }

    // Only established flows are forwarded inline; a miss means a new flow
    // whose first packet needs the slow path (sniff, handoff, route, dial).
    let Some(ep) = udp_pool.get(client_addr, original_dst) else {
        return false;
    };

    debug!("UDP endpoint reuse for {} -> {}", client_addr, original_dst);
    // Routing-cache probe: preserves the lazy TTL invalidation side effect
    // of the slow-path hit branch (the value itself is only logged there).
    if let Some(_cached_outbound) = ep.get_cached_routing(original_dst) {
        debug!(
            "UDP routing cache hit for {} -> {}",
            client_addr, original_dst
        );
    }
    ep.mark_sent();
    ep.refresh();
    ep.tracker_upload(data.len() as u64);
    if let Err(e) = ep.proxy_socket.send_packet(data).await {
        warn!(
            "UDP fast path send to {} for {} -> {} failed: {}",
            ep.relay_addr, client_addr, original_dst, e
        );
        // A dead transport (session/stream closed) can never deliver for
        // this endpoint again; mark it dead so the next datagram creates a
        // fresh endpoint instead of black-holing until the timeouts reap it.
        ep.kill();
    }
    true
}

use crate::dns::forwarder::DomainResolveNotifier;

/// Bridges DNS resolution to eBPF DOMAIN_ROUTING_MAP updates.
///
/// When the DNS forwarder resolves a domain (cache miss → upstream),
/// this notifier extracts the resolved IP addresses and pushes them
/// into the eBPF domain routing table so that future connections to
/// those IPs can be matched against domain-based rules in eBPF
/// without requiring userspace intervention.
///
/// Only domain/geosite rules produce map entries (via rule bitmaps).
/// Domains that fall through to the routing default intentionally get
/// no entry — connection-time routing still sees the full 5-tuple.
pub struct DnsBpfNotifier {
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    router: Arc<RwLock<Router>>,
}

impl DnsBpfNotifier {
    pub fn new(ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>, router: Arc<RwLock<Router>>) -> Self {
        Self { ebpf, router }
    }
}

impl DomainResolveNotifier for DnsBpfNotifier {
    fn on_domain_resolved(&self, domain: &str, response: &[u8]) {
        use crate::control::routing_matcher::DOMAIN_BITMAPS;
        use crate::ebpf::maps::cidr_to_lpm_key;
        use honk_ebpf_common::DomainRouting;

        let ips = extract_ips_from_dns_response(response);
        if ips.is_empty() {
            return;
        }

        let rule_name = {
            let router = self.router.blocking_read();
            match router.route_domain(domain) {
                Some(m) => m.rule_name.to_string(),
                None => return,
            }
        };

        let bitmaps: Vec<DomainRouting> = {
            let db = DOMAIN_BITMAPS.read();
            db.get(&rule_name).cloned().unwrap_or_default()
        };
        if bitmaps.is_empty() {
            return;
        }
        let mut merged = DomainRouting { bitmap: [0u32; 4] };
        for bm in &bitmaps {
            for i in 0..4 {
                merged.bitmap[i] |= bm.bitmap[i];
            }
        }

        let mut ebpf = self.ebpf.blocking_write();
        for ip in &ips {
            let prefix = match ip {
                std::net::IpAddr::V4(_) => format!("{ip}/32"),
                std::net::IpAddr::V6(_) => format!("{ip}/128"),
            };
            if let Ok(lpm_key) = cidr_to_lpm_key(&prefix)
                && let Err(e) = ebpf.add_domain_ip_bitmap(&lpm_key, &merged)
            {
                debug!(
                    "DNS BPF update: failed to push {} for {} (rule '{}'): {}",
                    ip, domain, rule_name, e
                );
            }
        }

        debug!(
            "DNS BPF update: domain={} rule='{}' ips={:?}",
            domain, rule_name, ips
        );
    }
}
