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

/// Whether the daens namespace is fully set up (FD-owned namespace +
/// policy routing live). Only real eBPF mode creates it (mock mode and
/// tests stay entirely in the host netns), so this flag is the switch
/// between "bind inside daens" and "bind here".
#[cfg(target_os = "linux")]
fn daens_netns_exists() -> bool {
    crate::DAENS_READY.load(std::sync::atomic::Ordering::Acquire)
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
    // The listener absorbs every proxied UDP datagram before the receive
    // loop drains it; the ~208 KiB default overflows instantly at
    // tunnel-saturating rates and the kernel drops the rest before we ever
    // see it. Same 8 MiB as the QUIC sockets (rmem_max is raised to 16 MiB
    // at startup).
    let _ = socket.set_recv_buffer_size(8 << 20);

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
            // Preserve the address in the packet header when ORIGDST is not
            // available, so only an exact DNS query can reconstruct :53.
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IP_PKTINFO): {}",
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
            // IPv6 mirrors IPv4's IP_PKTINFO provenance fallback.
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
            if ret != 0 {
                anyhow::bail!(
                    "setsockopt(IPV6_RECVPKTINFO): {}",
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

// Accommodate two IPv6-sized ancillary records (ORIGDST + PKTINFO). The
// capacity is checked through CMSG_SPACE before every recvmsg rather than
// relying on the literal remaining correct for all libc ABIs.
const CMSG_CONTROL_CAPACITY: usize = 256;

/// Raw recvmsg control storage whose first byte is naturally aligned for a
/// `cmsghdr`. The zero-length field carries `cmsghdr`'s ABI alignment without
/// consuming cmsg capacity.
#[repr(C)]
struct CmsgStorage {
    _alignment: [libc::cmsghdr; 0],
    bytes: [u8; CMSG_CONTROL_CAPACITY],
}

impl CmsgStorage {
    fn new() -> Self {
        // SAFETY: raw cmsg storage is initialized to zero before recvmsg.
        unsafe { std::mem::zeroed() }
    }
}

fn cmsg_len(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_LEN as the platform ABI macro wrapper.
    unsafe { libc::CMSG_LEN(data_len as _) as usize }
}

fn cmsg_space(data_len: usize) -> usize {
    // SAFETY: libc exposes CMSG_SPACE as the platform ABI macro wrapper.
    unsafe { libc::CMSG_SPACE(data_len as _) as usize }
}

pub(super) fn cmsg_control_capacity_is_sufficient() -> bool {
    let Some(required) = cmsg_space(std::mem::size_of::<libc::sockaddr_in6>())
        .checked_add(cmsg_space(std::mem::size_of::<libc::in6_pktinfo>()))
    else {
        return false;
    };
    CMSG_CONTROL_CAPACITY >= required
}

/// Provenance captured for one UDP datagram before any destination is
/// selected.  The listener's address is deliberately retained separately: a
/// wildcard bind is not an original destination and must not become one.
#[derive(Clone, Copy, Debug)]
pub(super) struct UdpRecvMeta {
    pub(super) original_dst_cmsg: Option<SocketAddr>,
    pub(super) packet_dst_ip: Option<std::net::IpAddr>,
    pub(super) local_addr: SocketAddr,
}

/// Receive a UDP datagram and preserve every destination provenance source.
/// `IP_RECVORIGDSTADDR` / `IPV6_RECVORIGDSTADDR` provide the authoritative
/// address; packet-info and the listener address are retained only as guarded
/// fallbacks by [`udp_original_dst`].
pub(super) async fn recv_from_with_orig_dst(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, UdpRecvMeta)> {
    let local_addr = socket.local_addr()?;
    socket
        .async_io(Interest::READABLE, || {
            recvmsg_origdst(socket.as_raw_fd(), buf, local_addr)
        })
        .await
}

fn recvmsg_origdst(
    fd: RawFd,
    buf: &mut [u8],
    local_addr: SocketAddr,
) -> io::Result<(usize, SocketAddr, UdpRecvMeta)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    if !cmsg_control_capacity_is_sufficient() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg control buffer cannot hold IPv6 ORIGDST and PKTINFO",
        ));
    }
    // CmsgStorage makes this pointer naturally aligned for libc's cmsghdr
    // access; CMSG_SPACE capacity above ensures neither IPv6 record crowds
    // the other out.
    let mut cmsg_buf = CmsgStorage::new();
    if !(cmsg_buf.bytes.as_ptr() as usize).is_multiple_of(std::mem::align_of::<libc::cmsghdr>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg control storage is not cmsghdr-aligned",
        ));
    }
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.bytes.as_mut_ptr() as *mut libc::c_void;
    #[cfg(target_env = "musl")]
    {
        msg.msg_controllen = cmsg_buf.bytes.len() as u32;
    }
    #[cfg(not(target_env = "musl"))]
    {
        msg.msg_controllen = cmsg_buf.bytes.len();
    }

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let src = sockaddr_to_std(&src_addr, msg.msg_namelen)?;
    #[cfg(target_env = "musl")]
    let returned_control_len = msg.msg_controllen as usize;
    #[cfg(not(target_env = "musl"))]
    let returned_control_len = msg.msg_controllen;
    // Only kernel-returned bytes are trusted. A larger value can never make
    // the parser read past our actual allocation.
    let control_len = returned_control_len.min(cmsg_buf.bytes.len());
    let (original_dst_cmsg, packet_dst_ip) =
        parse_cmsg_control(&cmsg_buf.bytes[..control_len], msg.msg_flags)?;

    Ok((
        n as usize,
        src,
        UdpRecvMeta {
            original_dst_cmsg,
            packet_dst_ip,
            local_addr,
        },
    ))
}

/// Parse the returned ancillary byte range without looking past
/// `msg_controllen`. Every recognized record must be complete and decodable;
/// malformed provenance is an InvalidData error, never a missing-metadata
/// fallback. The production buffer is cmsghdr-aligned, while unaligned reads
/// here keep this validator safe for any slice used by focused tests.
pub(super) fn parse_cmsg_control(
    control: &[u8],
    msg_flags: libc::c_int,
) -> io::Result<(Option<SocketAddr>, Option<std::net::IpAddr>)> {
    if msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg control data truncated",
        ));
    }

    let header_len = cmsg_len(0);
    let mut offset = 0;
    let mut original_dst_cmsg = None;
    let mut packet_dst_ip = None;
    while offset < control.len() {
        if control.len() - offset < header_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated cmsghdr",
            ));
        }
        // SAFETY: the header-sized range was checked above. read_unaligned
        // avoids assuming alignment for callers other than recvmsg storage.
        let cmsg = unsafe {
            std::ptr::read_unaligned(control.as_ptr().add(offset).cast::<libc::cmsghdr>())
        };
        #[cfg(target_env = "musl")]
        let record_len = cmsg.cmsg_len as usize;
        #[cfg(not(target_env = "musl"))]
        let record_len = cmsg.cmsg_len;
        let data_len = record_len.checked_sub(header_len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "cmsg_len shorter than cmsghdr")
        })?;
        let data_start = offset + header_len;
        let data_end = data_start
            .checked_add(data_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cmsg length overflow"))?;
        let data = control
            .get(data_start..data_end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated cmsg payload"))?;

        if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_ORIGDSTADDR {
            if original_dst_cmsg.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate ORIGDST cmsg",
                ));
            }
            let original_dst = original_dst_from_cmsg(cmsg.cmsg_level, cmsg.cmsg_type, data)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed IPv4 ORIGDST cmsg")
                })?;
            original_dst_cmsg = Some(original_dst);
        } else if cmsg.cmsg_level == libc::SOL_IPV6 && cmsg.cmsg_type == IPV6_ORIGDSTADDR_OPT {
            if original_dst_cmsg.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate ORIGDST cmsg",
                ));
            }
            let original_dst = original_dst_from_cmsg(cmsg.cmsg_level, cmsg.cmsg_type, data)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed IPv6 ORIGDST cmsg")
                })?;
            original_dst_cmsg = Some(original_dst);
        } else if (cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_PKTINFO)
            || (cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_PKTINFO)
        {
            if packet_dst_ip.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate PKTINFO cmsg",
                ));
            }
            let packet_dst = packet_dst_ip_from_cmsg(cmsg.cmsg_level, cmsg.cmsg_type, data)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed PKTINFO cmsg")
                })?;
            packet_dst_ip = Some(packet_dst);
        }

        let next = offset
            .checked_add(cmsg_space(data_len))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cmsg alignment overflow"))?;
        if next > control.len() {
            // The final record may omit tail alignment padding, but an
            // unfinished record before more returned bytes is malformed.
            if data_end == control.len() {
                break;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated cmsg alignment padding",
            ));
        }
        offset = next;
    }

    Ok((original_dst_cmsg, packet_dst_ip))
}

fn original_dst_from_cmsg(
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: &[u8],
) -> Option<SocketAddr> {
    if cmsg_level == libc::IPPROTO_IP && cmsg_type == libc::IP_ORIGDSTADDR {
        if data.len() != std::mem::size_of::<libc::sockaddr_in>() {
            return None;
        }
        let sin = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::sockaddr_in>()) };
        if sin.sin_family as libc::c_int != libc::AF_INET {
            return None;
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        return Some(SocketAddr::new(
            std::net::IpAddr::V4(ip),
            u16::from_be(sin.sin_port),
        ));
    }
    if cmsg_level == libc::SOL_IPV6 && cmsg_type == IPV6_ORIGDSTADDR_OPT {
        if data.len() != std::mem::size_of::<libc::sockaddr_in6>() {
            return None;
        }
        let sin6 = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::sockaddr_in6>()) };
        if sin6.sin6_family as libc::c_int != libc::AF_INET6 {
            return None;
        }
        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
        return Some(SocketAddr::new(
            std::net::IpAddr::V6(ip),
            u16::from_be(sin6.sin6_port),
        ));
    }
    None
}

pub(super) fn packet_dst_ip_from_cmsg(
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
    data: &[u8],
) -> Option<std::net::IpAddr> {
    if cmsg_level == libc::IPPROTO_IP && cmsg_type == libc::IP_PKTINFO {
        if data.len() != std::mem::size_of::<libc::in_pktinfo>() {
            return None;
        }
        let pktinfo = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::in_pktinfo>()) };
        return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
            u32::from_be(pktinfo.ipi_addr.s_addr),
        )));
    }
    if cmsg_level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_PKTINFO {
        if data.len() != std::mem::size_of::<libc::in6_pktinfo>() {
            return None;
        }
        let pktinfo =
            unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<libc::in6_pktinfo>()) };
        return Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            pktinfo.ipi6_addr.s6_addr,
        )));
    }
    None
}

/// Select a real original destination without inventing one from UDP payload
/// shape. An ORIGDST cmsg is authoritative; PKTINFO can only supply an IP for
/// a validated DNS query on port 53; a specifically bound listener is the
/// final fallback. Wildcard listeners with no valid metadata fail closed.
pub(super) fn udp_original_dst(meta: &UdpRecvMeta, data: &[u8]) -> Option<SocketAddr> {
    // A present ORIGDST cmsg is authoritative. An unspecified ORIGDST is
    // invalid provenance, so do not downgrade it to pktinfo/local fallback.
    if let Some(original_dst) = meta.original_dst_cmsg {
        return (!original_dst.ip().is_unspecified()).then_some(original_dst);
    }
    if is_exact_dns_query(data)
        && let Some(packet_dst_ip) = meta.packet_dst_ip
        && !packet_dst_ip.is_unspecified()
    {
        return Some(SocketAddr::new(packet_dst_ip, 53));
    }
    (!meta.local_addr.ip().is_unspecified()).then_some(meta.local_addr)
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

/// Strict DNS query validation shared by provenance, the controller, and
/// both UDP dispatch paths. It accepts exactly one fully encoded question,
/// walks every RR declared by the header, consumes the entire datagram, and
/// requires the controller's `parse_dns_question` consumer to accept it.
pub(super) fn is_exact_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 || data[2] & 0x80 != 0 {
        return false;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    if qdcount != 1 {
        return false;
    }
    let counts = [
        u16::from_be_bytes([data[6], data[7]]) as usize,
        u16::from_be_bytes([data[8], data[9]]) as usize,
        u16::from_be_bytes([data[10], data[11]]) as usize,
    ];
    let mut pos = 12;
    // Label starts observed while walking question/owner names. Compression
    // pointers may only land on these boundaries (not header/RDATA/interior
    // label bytes). Unparsed RDATA is intentionally not scanned.
    let mut label_boundaries = vec![false; data.len()];

    if !skip_strict_dns_name(data, &mut pos, &mut label_boundaries)
        || pos.checked_add(4).is_none_or(|end| end > data.len())
    {
        return false;
    }
    pos += 4; // QTYPE + QCLASS

    for count in counts {
        for _ in 0..count {
            if !skip_strict_dns_name(data, &mut pos, &mut label_boundaries)
                || pos.checked_add(10).is_none_or(|end| end > data.len())
            {
                return false;
            }
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10; // TYPE + CLASS + TTL + RDLENGTH
            let Some(rdata_end) = pos.checked_add(rdlength) else {
                return false;
            };
            if rdata_end > data.len() {
                return false;
            }
            pos = rdata_end;
        }
    }

    if pos != data.len() {
        return false;
    }

    // Keep the shared predicate inside the controller's actual parseable set
    // so root/binary names fall back to ordinary UDP instead of SERVFAIL.
    crate::dns::forwarder::parse_dns_question(data).is_some()
}

/// Bounds-safe name walk that enforces the RFC expanded-name limit and
/// restricts compression pointers to previously observed label boundaries.
fn skip_strict_dns_name(data: &[u8], pos: &mut usize, label_boundaries: &mut [bool]) -> bool {
    let mut cursor = *pos;
    let mut expanded = 0usize;
    let mut jumped = false;
    let mut depth = 0usize;

    loop {
        if depth > 128 || cursor >= data.len() || cursor >= label_boundaries.len() {
            return false;
        }

        if jumped {
            if !label_boundaries[cursor] {
                return false;
            }
        } else {
            label_boundaries[cursor] = true;
        }

        let label_len = data[cursor];
        if label_len == 0 {
            if expanded.checked_add(1).is_none_or(|v| v > 255) {
                return false;
            }
            if !jumped {
                *pos = cursor + 1;
            }
            return true;
        }

        if label_len & 0xc0 == 0xc0 {
            let Some(&next) = data.get(cursor + 1) else {
                return false;
            };
            let target = (((label_len & 0x3f) as usize) << 8) | next as usize;
            // Pointers name an earlier observed label start only.
            if target >= cursor || target >= label_boundaries.len() || !label_boundaries[target] {
                return false;
            }
            if !jumped {
                *pos = cursor + 2;
            }
            jumped = true;
            cursor = target;
            depth += 1;
            continue;
        }

        if label_len > 63 {
            return false;
        }

        let label_octets = 1 + label_len as usize;
        expanded = match expanded.checked_add(label_octets) {
            Some(v) if v <= 255 => v,
            _ => return false,
        };
        let Some(next_pos) = cursor.checked_add(label_octets) else {
            return false;
        };
        if next_pos > data.len() {
            return false;
        }
        cursor = next_pos;
    }
}

/// UDP datapath fast path: classify/drop and, for a live Ready endpoint,
/// perform a bounded synchronous `try_enqueue` in the accept loop.
///
/// Runs on the reusable receive buffer with no task spawn, no QUIC sniffer,
/// and no slow-path concurrency permit. Ready hits may copy into the
/// bounded per-flow queue (permits first). Returns `true` when the datagram
/// was fully handled (enqueued, drop-newest, or dropped by pre-checks) and
/// the accept loop can move on; `false` when it must take the slow path:
/// Initializing followers, new-flow setup, or a possible DNS query.
///
/// This function is the sole production owner of endpoint hit/miss
/// accounting. Skipping the QUIC sniffer on Ready hits is safe because
/// routing for this flow was already decided when its first packet took the
/// slow path.
pub(super) async fn udp_fast_path(
    udp_pool: &UdpEndpointPool,
    stats: &StatsManager,
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

    // Only traffic the controller can consume takes the DNS slow path. The
    // shared strict predicate guards any PKTINFO-derived port 53; DNS-shaped
    // traffic to every other authoritative port remains ordinary UDP.
    if original_dst.port() == 53 && is_exact_dns_query(data) {
        return false;
    }

    // The receive loop only performs a synchronous bounded enqueue. Transport
    // I/O belongs exclusively to the per-endpoint driver, so a blocked send
    // on one flow cannot delay classification of another datagram.
    let Some(result) = udp_pool.fast_path_enqueue(client_addr, original_dst, data, stats) else {
        stats.record_udp_endpoint_miss();
        return false;
    };
    if matches!(result, EndpointReservation::QueueClosed) {
        return true;
    }
    stats.record_udp_endpoint_hit();

    debug!(
        "UDP endpoint enqueue for {} -> {}",
        client_addr, original_dst
    );
    // Keep the cache's lazy TTL invalidation behavior without sending from
    // the receive loop. The driver owns mark_sent, refresh and byte counts
    // after a real PacketTransport send succeeds.
    if let Some(ep) = udp_pool.get(client_addr, original_dst)
        && ep.get_cached_routing(original_dst).is_some()
    {
        debug!(
            "UDP routing cache hit for {} -> {}",
            client_addr, original_dst
        );
    }
    debug_assert!(matches!(
        result,
        EndpointReservation::Enqueued | EndpointReservation::QueueFull
    ));
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
