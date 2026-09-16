use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{Endpoint, EndpointConfig};

/// Bind a non-blocking UDP socket with `SO_MARK` set so the local eBPF
/// datapath treats QUIC packets to the proxy server as control-plane traffic
/// and does not re-route them (same bypass as `util::udp_marked_bind`; QUIC
/// needs ownership of the raw socket, so it cannot reuse that helper).
///
/// Public so protocol handlers that wrap the socket themselves (Hysteria2's
/// salamander obfuscation) can reuse the same marking logic.
pub fn marked_udp_socket(ipv6: bool) -> io::Result<std::net::UdpSocket> {
    let bind_addr: SocketAddr = if ipv6 {
        "[::]:0".parse().expect("hardcoded IPv6 bind address")
    } else {
        "0.0.0.0:0".parse().expect("hardcoded IPv4 bind address")
    };
    crate::util::marked_udp_socket(bind_addr)
}

/// Create a client-only quinn [`Endpoint`] on a marked UDP socket for the
/// given address family.
///
/// The endpoint advertises `max_udp_payload_size = 1252` instead of quinn's
/// 1472: on PPPoE/tunneled last miles, larger downlink UDP datagrams are
/// silently black-holed (measured on a CN PPPoE line: ≤1260B echoes pass,
/// 1280B all lost), which kills every QUIC handshake whose ServerHello
/// flight exceeds the threshold. 1252 matches quic-go's default; going
/// lower (e.g. the RFC minimum 1200) shrinks the server's flight allowance
/// below its anti-amplification budget (3× the client Initial) and can
/// deadlock handshakes against large certificate chains.
pub fn client_endpoint(ipv6: bool) -> io::Result<Endpoint> {
    client_endpoint_with_mtu(ipv6, 1252)
}

pub(super) fn clamp_quic_payload_size(mtu: u16) -> u16 {
    mtu.clamp(1200, 65527)
}

pub(super) fn default_gso_enabled(max_udp_payload_size: u16) -> bool {
    max_udp_payload_size > 1252
}
pub(super) const MAX_QUIC_GSO_SEGMENTS: usize = 16;

pub(super) fn gso_transmit_segments(enabled: bool, kernel_max: usize) -> usize {
    if enabled {
        kernel_max.min(MAX_QUIC_GSO_SEGMENTS)
    } else {
        1
    }
}

/// [`client_endpoint`] with an explicit advertised `max_udp_payload_size`.
///
/// An explicit MTU above the conservative 1252 default opts into UDP GSO:
/// the operator has already declared that the path carries larger datagrams.
/// `HONK_QUIC_GSO=0|1` overrides that policy process-wide.
pub fn client_endpoint_with_mtu(ipv6: bool, max_udp_payload_size: u16) -> io::Result<Endpoint> {
    let max_udp_payload_size = clamp_quic_payload_size(max_udp_payload_size);
    let socket = marked_udp_socket(ipv6)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
    let io = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
    let inner = quinn::udp::UdpSocketState::new((&*io).into())?;
    static GSO_OVERRIDE: std::sync::LazyLock<Option<bool>> = std::sync::LazyLock::new(|| {
        std::env::var("HONK_QUIC_GSO")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    });
    let gso = (*GSO_OVERRIDE).unwrap_or_else(|| default_gso_enabled(max_udp_payload_size));
    let socket = Arc::new(NoGsoUdpSocket { io, inner, gso });
    Endpoint::new_with_abstract_socket(
        endpoint_config_with_mtu(max_udp_payload_size)?,
        None,
        socket,
        runtime,
    )
}

/// EndpointConfig advertising `max_udp_payload_size` (see `client_endpoint`
/// for why 1252 is the safe default on PMTU-black-holed last miles).
pub(crate) fn endpoint_config_with_mtu(mtu: u16) -> io::Result<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(clamp_quic_payload_size(mtu))
        .map_err(io::Error::other)?;
    Ok(config)
}

/// GSO policy. The safe 1252-byte default sends one datagram per syscall,
/// dodging PPPoE uplinks that drop later segments of a GSO super-packet.
/// Explicit larger MTUs enable batches capped at 16 segments because those
/// paths have already opted out of the black-hole-safe default.
/// `HONK_QUIC_GSO=0|1` forces either mode.
///
/// This is quinn's own `runtime/tokio.rs` socket with only
/// [`max_transmit_segments`](quinn::AsyncUdpSocket::max_transmit_segments)
/// made policy-driven; ECN, GRO receives, and pktinfo stay unchanged.
#[derive(Debug)]
struct NoGsoUdpSocket {
    io: Arc<tokio::net::UdpSocket>,
    inner: quinn::udp::UdpSocketState,
    gso: bool,
}

impl quinn::AsyncUdpSocket for NoGsoUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(NoGsoUdpPoller {
            socket: Arc::clone(&self.io),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            match self.io.try_io(tokio::io::Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(res) => return Poll::Ready(Ok(res)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        gso_transmit_segments(self.gso, self.inner.max_gso_segments())
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

#[derive(Debug)]
struct NoGsoUdpPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for NoGsoUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}
