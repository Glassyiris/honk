//! Low-level outbound networking helpers.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::net::TcpStream;

const EINPROGRESS: i32 = libc::EINPROGRESS;

/// Set `SO_MARK` best-effort. In production honk runs as root (eBPF load
/// requires it) so the mark always applies; unprivileged environments (CI,
/// local tests) get EPERM, where we log once and continue unmarked — the
/// bypass is irrelevant there because no eBPF datapath is loaded.
/// Non-EPERM errors are real failures and propagate.
#[cfg(target_os = "linux")]
pub fn set_mark_best_effort(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    match socket.set_mark(mark) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                tracing::debug!("SO_MARK denied (unprivileged); continuing without bypass mark");
            });
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Create a TCP stream to `addr`, optionally setting `SO_MARK` before the
/// handshake so the local eBPF datapath treats it as control-plane traffic
/// and does not re-route it.
pub async fn connect_marked_addr(
    addr: SocketAddr,
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    if let Some(mark) = mark {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        #[cfg(target_os = "linux")]
        {
            set_mark_best_effort(&socket, mark)?;
            unsafe {
                let fd = socket.as_raw_fd();
                let keepidle: libc::c_int = 60;
                let keepintvl: libc::c_int = 10;
                let keepcnt: libc::c_int = 3;
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPIDLE,
                    &keepidle as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPINTVL,
                    &keepintvl as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_KEEPCNT,
                    &keepcnt as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        match socket.connect(&addr.into()) {
            Ok(()) => {
                let std_stream: std::net::TcpStream = socket.into();
                TcpStream::from_std(std_stream)
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(EINPROGRESS) =>
            {
                let std_stream: std::net::TcpStream = socket.into();
                let stream = TcpStream::from_std(std_stream)?;
                tokio::time::timeout(connect_timeout, stream.writable())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
                if let Some(e) = stream.take_error()? {
                    return Err(e);
                }
                Ok(stream)
            }
            Err(e) => Err(e),
        }
    } else {
        let domain = if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_keepalive(true)?;
        #[cfg(target_os = "linux")]
        unsafe {
            let fd = socket.as_raw_fd();
            let keepidle: libc::c_int = 60;
            let keepintvl: libc::c_int = 10;
            let keepcnt: libc::c_int = 3;
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                &keepidle as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                &keepintvl as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                &keepcnt as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        match socket.connect(&addr.into()) {
            Ok(()) => {
                let std_stream: std::net::TcpStream = socket.into();
                TcpStream::from_std(std_stream)
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(EINPROGRESS) =>
            {
                let std_stream: std::net::TcpStream = socket.into();
                let stream = TcpStream::from_std(std_stream)?;
                tokio::time::timeout(connect_timeout, stream.writable())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
                if let Some(e) = stream.take_error()? {
                    return Err(e);
                }
                Ok(stream)
            }
            Err(e) => Err(e),
        }
    }
}

/// Resolve `addr` (`host:port`) and connect to the first available address
/// with the given optional `SO_MARK`.
pub async fn connect_marked(
    addr: &str,
    mark: Option<u32>,
    connect_timeout: Duration,
) -> io::Result<TcpStream> {
    // Server hostnames are resolved through the bootstrap resolver when one
    // is configured, so proxy-server DNS does not depend on the regular
    // (potentially self-intercepted) DNS path — see `bootstrap` module docs.
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    let ips = crate::bootstrap::resolve(host).await?;
    let mut last_err = None;
    for ip in ips {
        match connect_marked_addr(SocketAddr::new(ip, port), mark, connect_timeout).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address")))
}

/// Connect to a proxy server from the control plane, bypassing eBPF re-routing.
pub async fn connect_outbound(addr: &str, connect_timeout: Duration) -> io::Result<TcpStream> {
    connect_marked(
        addr,
        Some(honk_ebpf_common::DAE_BYPASS_MARK),
        connect_timeout,
    )
    .await
}

/// Bind a UDP socket with `SO_MARK` set so the local eBPF datapath treats it
/// as control-plane traffic and does not re-route it (Go dae `SoMarkFromDae`
/// parity).  Use for every UDP socket the control plane originates — proxy
/// relay sockets, direct UDP, DNS upstream — otherwise `wan_egress` would
/// classify and redirect the packets back into daens, creating a loop.
pub async fn udp_marked_bind(bind_addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    set_mark_best_effort(&socket, honk_ebpf_common::DAE_BYPASS_MARK)?;
    socket.bind(&bind_addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Bind a loopback UDP socket for a local protocol bridge (QUIC UDP sessions
/// are re-exported to the relay as loopback datagrams). Loopback traffic does
/// not traverse the interfaces the eBPF datapath attaches to, so the mark is
/// best-effort: fall back to a plain bind when `SO_MARK` is not permitted
/// (e.g. tests running unprivileged).
pub async fn udp_loopback_bind() -> io::Result<tokio::net::UdpSocket> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("hardcoded loopback address");
    match udp_marked_bind(loopback).await {
        Ok(socket) => Ok(socket),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            tokio::net::UdpSocket::bind(loopback).await
        }
        Err(e) => Err(e),
    }
}
