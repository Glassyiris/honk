use crate::control::udp_endpoint::UdpEndpointPool;
use crate::control::{ControlPlane, ControlPlaneHandle};
use crate::dns::{self, DnsResolver};
use crate::ebpf::mock::MockEbpfBackend;
use crate::proxy::ProxyRegistry;
use crate::routing::Router;
use crate::stats::StatsManager;
use honk_config::Config;
use honk_config::node::{Group, GroupPolicy, Node, OutboundConfig};
use honk_config::types::NodeProtocol;
#[cfg(feature = "ebpf")]
use honk_ebpf_common::DAE_BYPASS_MARK;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// A minimal DNS query payload for "a.com" (A record).
pub(in crate::control) fn dns_query_payload() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    q.extend_from_slice(&[
        0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ]);
    q
}

pub(in crate::control) fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: the returned slice borrows `value` and has its exact layout size.
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}
pub(in crate::control) type CapturedTcpTarget =
    Arc<std::sync::Mutex<Option<(SocketAddr, Option<String>)>>>;

#[derive(Debug, Clone)]
pub(in crate::control) enum UdpTestMode {
    #[cfg(feature = "ebpf")]
    TcpConnect,
    DialError,
    SendError,
    /// Records real application-send attempts made by the production
    /// PacketTransport call path.
    CountSends(Arc<std::sync::atomic::AtomicUsize>),
    /// Counts dial and send attempts while making the first application send
    /// ambiguous. A later candidate must never be tried after that send.
    CountFirstSendError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialAndSend {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    CountDialError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitError {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
    PreparedCommitHold {
        dials: Arc<std::sync::atomic::AtomicUsize>,
        commits: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    Success,
    DnsResponse {
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    DnsResponseCaptureTarget(Arc<parking_lot::Mutex<Option<SocketAddr>>>),
    #[cfg(feature = "ebpf")]
    KernelSocket(Arc<UdpSocket>),
    TcpHold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    TcpCaptureTarget(CapturedTcpTarget),
    UdpCaptureTarget(CapturedTcpTarget),
    Hold {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    HoldAndCount {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
    },
    HoldAndCountDialAndSend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dials: Arc<std::sync::atomic::AtomicUsize>,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    },
}

#[derive(Debug)]
struct UdpTestTransport {
    mode: UdpTestMode,
    relay: SocketAddr,
    /// Last DNS query sent in a `DnsResponse` mode, answered once by `recv_packet`.
    sent: std::sync::Mutex<Option<Vec<u8>>>,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketTransport for UdpTestTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.relay
    }

    async fn send_packet(&self, _data: &[u8]) -> std::io::Result<()> {
        match &self.mode {
            UdpTestMode::SendError => Err(std::io::Error::other("first UDP send failed")),
            UdpTestMode::CountSends(sends) => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            UdpTestMode::CountFirstSendError { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::other("ambiguous first UDP send failure"))
            }
            UdpTestMode::CountDialAndSend { sends, .. }
            | UdpTestMode::HoldAndCountDialAndSend { sends, .. }
            | UdpTestMode::PreparedCommitError { sends, .. }
            | UdpTestMode::PreparedCommitHold { sends, .. } => {
                sends.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            #[cfg(feature = "ebpf")]
            UdpTestMode::KernelSocket(socket) => {
                socket.send_to(_data, self.relay).await?;
                Ok(())
            }
            UdpTestMode::DnsResponse { .. } | UdpTestMode::DnsResponseCaptureTarget(_) => {
                *self.sent.lock().expect("sent query") = Some(_data.to_vec());
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        #[cfg(feature = "ebpf")]
        if let UdpTestMode::KernelSocket(socket) = &self.mode {
            let (size, _) = socket.recv_from(buf).await?;
            return Ok((size, self.relay));
        }
        if matches!(
            self.mode,
            UdpTestMode::DnsResponse { .. } | UdpTestMode::DnsResponseCaptureTarget(_)
        ) {
            // Echo the query as a NOERROR answer (QR set, question intact).
            let sent = self.sent.lock().expect("sent query").take();
            if let Some(mut response) = sent {
                response[2] |= 0x80;
                buf[..response.len()].copy_from_slice(&response);
                return Ok((response.len(), self.relay));
            }
            return std::future::pending().await;
        }
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }
}

#[derive(Debug)]
pub(in crate::control) struct UdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for UdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }
}

#[cfg(feature = "ebpf")]
#[derive(Debug)]
pub(super) struct KernelUdpReplySocketFactory;

#[cfg(feature = "ebpf")]
impl crate::control::udp_endpoint::UdpReplySocketFactory for KernelUdpReplySocketFactory {
    fn create(&self, original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        let domain = if original_dst.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        if original_dst.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        } else {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_mark(DAE_BYPASS_MARK)?;
        socket.bind(&original_dst.into())?;
        UdpSocket::from_std(socket.into())
    }
}

#[derive(Debug)]
pub(super) struct FailingUdpTestReplySocketFactory;

impl crate::control::udp_endpoint::UdpReplySocketFactory for FailingUdpTestReplySocketFactory {
    fn create(&self, _original_dst: SocketAddr) -> std::io::Result<UdpSocket> {
        Err(std::io::Error::other("scripted anyfrom setup failure"))
    }
}

#[derive(Debug)]
pub(in crate::control) struct UdpTestHandler {
    pub(in crate::control) mode: UdpTestMode,
}

#[async_trait::async_trait]
impl honk_outbound::proxy::TcpOutbound for UdpTestHandler {
    async fn dial(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
        let stream = match &self.mode {
            #[cfg(feature = "ebpf")]
            UdpTestMode::TcpConnect => TcpStream::connect(target).await?,
            UdpTestMode::TcpHold { entered, release } => {
                let stream = honk_outbound::util::connect_marked(
                    &target.to_string(),
                    None,
                    _connect_timeout,
                )
                .await?;
                entered.notify_one();
                release.notified().await;
                stream
            }
            UdpTestMode::TcpCaptureTarget(captured) => {
                *captured.lock().expect("dial target") =
                    Some((target, target_domain.map(str::to_owned)));
                TcpStream::connect(target).await?
            }
            _ => anyhow::bail!("TCP dial is not used by the UDP lifecycle tests"),
        };
        Ok(honk_outbound::proxy::ProxyStream {
            stream: Box::new(stream),
            target_addr: target,
            target_domain: target_domain.map(str::to_owned),
        })
    }
}

#[async_trait::async_trait]
impl honk_outbound::proxy::PacketOutbound for UdpTestHandler {
    async fn dial_udp_transport(
        &self,
        _node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        _connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn honk_outbound::proxy::PacketTransport>> {
        if let UdpTestMode::DnsResponseCaptureTarget(captured) = &self.mode {
            *captured.lock() = Some(target);
        }
        if let UdpTestMode::UdpCaptureTarget(captured) = &self.mode {
            *captured.lock().expect("UDP dial target") =
                Some((target, target_domain.map(str::to_owned)));
        }
        match &self.mode {
            UdpTestMode::Hold { entered, release } => {
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::HoldAndCount {
                entered,
                release,
                dials,
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::CountFirstSendError { dials, .. }
            | UdpTestMode::CountDialAndSend { dials, .. }
            | UdpTestMode::CountDialError { dials }
            | UdpTestMode::PreparedCommitError { dials, .. }
            | UdpTestMode::PreparedCommitHold { dials, .. } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            UdpTestMode::HoldAndCountDialAndSend {
                entered,
                release,
                dials,
                ..
            } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entered.notify_one();
                release.notified().await;
            }
            UdpTestMode::DnsResponse { dials } => {
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        match &self.mode {
            UdpTestMode::DialError | UdpTestMode::CountDialError { .. } => {
                Err(anyhow::anyhow!("UDP dial failed"))
            }
            _ => Ok(Arc::new(UdpTestTransport {
                mode: self.mode.clone(),
                relay: target,
                sent: std::sync::Mutex::new(None),
            })),
        }
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<honk_outbound::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<honk_outbound::proxy::PreparedUdpTransport> {
        let transport = self
            .dial_udp_transport(
                runtime.node.as_ref(),
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
        if let UdpTestMode::PreparedCommitError { commits, .. } = &self.mode {
            let commits = Arc::clone(commits);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                async move {
                    let _transport = transport;
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Err(anyhow::anyhow!(
                        "scripted prepared transport commit failure"
                    ))
                },
            ));
        }
        if let UdpTestMode::PreparedCommitHold {
            commits,
            entered,
            release,
            ..
        } = &self.mode
        {
            let commits = Arc::clone(commits);
            let entered = Arc::clone(entered);
            let release = Arc::clone(release);
            return Ok(honk_outbound::proxy::PreparedUdpTransport::new(
                async move {
                    entered.notify_one();
                    release.notified().await;
                    commits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(transport)
                },
            ));
        }
        Ok(honk_outbound::proxy::PreparedUdpTransport::ready(transport))
    }
}

pub(in crate::control) fn udp_test_forwarder() -> Arc<crate::dns::forwarder::DnsForwarder> {
    let router = Arc::new(
        crate::dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    Arc::new(
        crate::dns::forwarder::DnsForwarder::new(
            Arc::new(crate::dns::upstream_pool::UpstreamPool::new(&[], router.clone()).unwrap()),
            Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(1))),
            router,
        )
        .with_cache_enabled(false),
    )
}
pub(super) fn udp_test_config(
    default_outbound: &str,
    nodes: Vec<Node>,
    groups: Vec<Group>,
) -> Config {
    let mut config = Config {
        nodes,
        groups,
        ..Default::default()
    };
    config.routing.default_outbound = if let Some(node) = config
        .nodes
        .iter()
        .find(|node| node.name == default_outbound)
        && !matches!(default_outbound, "direct" | "block")
    {
        let name = format!("{default_outbound}-route");
        config.groups.push(Group {
            name: name.clone(),
            nodes: vec![node.id],
            ..Default::default()
        });
        name
    } else {
        default_outbound.into()
    };
    config
}

pub(in crate::control) fn udp_test_node() -> Node {
    let mut node = Node {
        name: "udp-test".into(),
        outbound: honk_config::node::OutboundConfig::from_protocol(
            honk_config::types::NodeProtocol::Socks5,
        ),
        address: "127.0.0.1".into(),
        port: 9,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

pub(super) fn udp_test_handle(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
) -> ControlPlaneHandle {
    udp_test_handle_with_reply_factory(config, mode, capacity, Arc::new(UdpTestReplySocketFactory))
}

/// Uses ControlPlane's production endpoint pool unchanged. The blocked-dial
/// death test needs this so the callback installed during ControlPlane::new
/// owns the same pool that contains the real Initializing reservation.
pub(super) fn udp_test_handle_with_default_pool(
    config: Config,
    mode: UdpTestMode,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap()
    .spawn_handle()
}

pub(super) fn udp_test_handle_with_reply_factory(
    config: Config,
    mode: UdpTestMode,
    capacity: usize,
    reply_socket_factory: Arc<dyn crate::control::udp_endpoint::UdpReplySocketFactory>,
) -> ControlPlaneHandle {
    let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
    let mut registry = honk_outbound::proxy::ProxyRegistry::new();
    let handler = Arc::new(UdpTestHandler { mode });
    registry.register(
        honk_outbound::proxy::ProtocolEntry::new(
            honk_config::types::NodeProtocol::Socks5,
            handler.clone(),
        )
        .with_packet(handler),
    );
    let mut control_plane = ControlPlane::new(
        config,
        Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
        router,
        Arc::new(registry),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
        udp_test_forwarder(),
    )
    .unwrap();
    control_plane.udp_pool = Arc::new(UdpEndpointPool::with_reply_socket_factory(
        capacity,
        reply_socket_factory,
    ));
    control_plane.spawn_handle()
}

pub(in crate::control) fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub(super) async fn serve_test_udp(handle: &ControlPlaneHandle) -> anyhow::Result<()> {
    serve_test_udp_to(
        handle,
        addr("10.0.0.2:53000"),
        addr("203.0.113.2:443"),
        b"UDP test packet",
    )
    .await
}

pub(super) async fn serve_test_udp_to(
    handle: &ControlPlaneHandle,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .expect("test slow permit");
    let reservation =
        handle
            .udp_pool
            .reserve_or_enqueue(client, dst, payload, slow_permit, &handle.stats);
    match reservation {
        crate::control::udp_endpoint::EndpointReservation::Initializing(lease) => {
            handle.serve_udp_connection(lease).await
        }
        crate::control::udp_endpoint::EndpointReservation::Enqueued
        | crate::control::udp_endpoint::EndpointReservation::CapacityRejected
        | crate::control::udp_endpoint::EndpointReservation::QueueFull
        | crate::control::udp_endpoint::EndpointReservation::QueueClosed
        | crate::control::udp_endpoint::EndpointReservation::IdentityMismatch => Ok(()),
    }
}

pub(super) fn assert_udp_outbound(
    stats: &Arc<StatsManager>,
    outbound: &str,
    total_connections: u32,
    active_connections: u32,
    errors: u32,
) {
    let snapshot = stats.snapshot();
    let actual = snapshot
        .get(outbound)
        .unwrap_or_else(|| panic!("missing outbound stats for {outbound}"));
    assert_eq!(actual.total_conns, total_connections);
    assert_eq!(actual.active_conns, active_connections);
    assert_eq!(actual.errors, errors);
}

pub(in crate::control) fn canonical_socks5(
    name: &str,
    address: &str,
    port: u16,
    subscription_id: Option<uuid::Uuid>,
) -> Node {
    let mut node = Node {
        name: name.to_owned(),
        address: address.to_owned(),
        port,
        outbound: OutboundConfig::from_protocol(NodeProtocol::Socks5),
        subscription_id,
        ..Default::default()
    };
    node.id = node.derive_id();
    node
}

pub(in crate::control) fn control_plane(config: Config) -> ControlPlane {
    ControlPlane::new(
        config,
        Box::new(MockEbpfBackend::new()),
        Router::new(&[], "direct").expect("test router"),
        Arc::new(ProxyRegistry::default_resolver().expect("test proxy registry")),
        DnsResolver::new(&honk_config::dns::DnsConfig::default()).expect("test DNS resolver"),
        test_dns_forwarder(),
    )
    .expect("test control plane")
}

pub(in crate::control) fn test_dns_forwarder() -> Arc<dns::forwarder::DnsForwarder> {
    let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(100)));
    let router = Arc::new(
        dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
            rules: vec![],
            fallback: "default".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    let upstream_pool = Arc::new(
        dns::upstream_pool::UpstreamPool::new(
            &[honk_config::dns::DnsUpstream {
                name: "default".into(),
                address: "8.8.8.8:53".into(),
                protocol: honk_config::types::DnsProtocol::Udp,
                tls_server_name: None,
                outbound: None,
            }],
            router.clone(),
        )
        .unwrap(),
    );
    dns::forwarder::DnsForwarder::new(upstream_pool, cache, router)
        .with_cache_enabled(false)
        .into()
}

pub(in crate::control) fn changed_routing_config() -> Config {
    let mut config = Config::default();
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: "reload-change".into(),
            condition: honk_config::routing::RoutingCondition {
                domain: vec!["reload.example".into()],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    config
}

pub(in crate::control) fn score_reload_config(revision: u64) -> Config {
    let nodes = [("score-a", 9), ("score-b", 10)].map(|(name, port)| {
        let mut node = Node {
            name: name.into(),
            outbound: honk_config::node::OutboundConfig::from_protocol(NodeProtocol::Socks5),
            address: format!("127.0.0.1:{port}"),
            host: "127.0.0.1".into(),
            port,
            ..Default::default()
        };
        node.id = node.derive_id();
        node
    });
    let mut config = Config::default();
    config
        .routing
        .rules
        .push(honk_config::routing::RoutingRule {
            name: format!("score-reload-{revision}"),
            condition: honk_config::routing::RoutingCondition {
                domain: vec![format!("score-{revision}.example")],
                ..Default::default()
            },
            outbound: honk_config::routing::RoutingOutbound::Simple("direct".into()),
            priority: 0,
            must: false,
            mark: 0,
        });
    config.nodes = nodes.to_vec();
    config.groups = vec![Group {
        name: "score".into(),
        policy: GroupPolicy::Score,
        nodes: nodes.iter().map(|node| node.id).collect(),
        ..Default::default()
    }];
    config
}

#[cfg(feature = "native-api")]
pub(in crate::control) struct NativeFlowApi {
    pub(in crate::control) flows: Arc<crate::observe::flows::FlowStore>,
    addr: SocketAddr,
    client: reqwest::Client,
    server: crate::native_api::NativeServer,
}

#[cfg(feature = "native-api")]
impl NativeFlowApi {
    pub(in crate::control) async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = Config::default();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.listen = addr.to_string();
        config.experimental.native_api.secret = "native-flow-test".into();
        config.ensure_builtin_nodes();
        let mut control = control_plane(config);
        let state = Arc::new(
            crate::native_api::NativeState::new(
                &mut control,
                addr,
                std::time::SystemTime::now(),
                std::time::Instant::now(),
            )
            .await
            .unwrap(),
        );
        let native = Arc::clone(&state.observation);
        native.attach_for_test();
        let flows = Arc::clone(&native.core.flows);
        Self {
            flows,
            addr,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            server: crate::native_api::NativeServer::start(listener, state),
        }
    }

    pub(in crate::control) async fn detail(&self, id: &str) -> serde_json::Value {
        self.client
            .get(format!("http://{}/api/v1/flows/{id}", self.addr))
            .bearer_auth("native-flow-test")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    pub(in crate::control) async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

const QUIC_PEER_STREAM_WINDOW: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::control) enum QuicUdpMode {
    Hysteria2,
    TuicDatagram,
    TuicStream,
}

#[derive(Debug)]
pub(in crate::control) struct QuicUdpPacket {
    pub(in crate::control) connection: u64,
    pub(in crate::control) session: u32,
    pub(in crate::control) target: SocketAddr,
    pub(in crate::control) mapping: SocketAddr,
    pub(in crate::control) payload: Vec<u8>,
    pub(in crate::control) carrier: quinn::Connection,
    next_reply: Arc<std::sync::atomic::AtomicU16>,
}

#[derive(Default)]
pub(in crate::control) struct QuicStreamHold {
    pub(in crate::control) entered: tokio::sync::Notify,
    pub(in crate::control) release: tokio::sync::Notify,
    pub(in crate::control) truncated: tokio::sync::Notify,
}

pub(in crate::control) struct QuicUdpPeer {
    pub(in crate::control) node: Node,
    pub(in crate::control) packets: tokio::sync::mpsc::UnboundedReceiver<QuicUdpPacket>,
    pub(in crate::control) closed: tokio::sync::mpsc::UnboundedReceiver<u64>,
    mode: QuicUdpMode,
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl QuicUdpPeer {
    pub(in crate::control) async fn start(
        mode: QuicUdpMode,
        bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        Self::start_with_stream_hold(mode, bind, None).await
    }

    pub(in crate::control) async fn start_with_stream_hold(
        mode: QuicUdpMode,
        bind: SocketAddr,
        hold: Option<Arc<QuicStreamHold>>,
    ) -> anyhow::Result<Self> {
        use tokio_rustls::rustls::{self, pki_types::PrivatePkcs8KeyDer};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let mut tls = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.into()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
        tls.alpn_protocols = vec![if mode == QuicUdpMode::Hysteria2 {
            b"h3".to_vec()
        } else {
            b"tuic".to_vec()
        }];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        if mode == QuicUdpMode::TuicStream {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .datagram_receive_buffer_size(None);
        }
        if hold.is_some() {
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .stream_receive_window(QUIC_PEER_STREAM_WINDOW.into());
        }
        let endpoint = quinn::Endpoint::server(config, bind)?;
        let address = endpoint.local_addr()?;
        let quic = honk_config::node::QuicOptions {
            tls: honk_config::node::TlsOptions {
                skip_cert_verify: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut node = Node {
            name: format!("source-{mode:?}"),
            host: address.ip().to_string(),
            address: address.to_string(),
            port: address.port(),
            outbound: if mode == QuicUdpMode::Hysteria2 {
                OutboundConfig::Hysteria2(honk_config::node::Hysteria2Config {
                    auth: Some("source-test-password".into()),
                    disable_mtu_discovery: Some(true),
                    quic,
                    ..Default::default()
                })
            } else {
                OutboundConfig::Tuic(honk_config::node::TuicConfig {
                    uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
                    password: Some("source-test-password".into()),
                    quic,
                    ..Default::default()
                })
            },
            ..Default::default()
        };
        node.id = node.derive_id();
        let (events, packets) = tokio::sync::mpsc::unbounded_channel();
        let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
        let listener = endpoint.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let mut serial = 0;
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Some(incoming) = incoming else { break; };
                        serial += 1;
                        let events = events.clone();
                        let hold = hold.clone();
                        let closed_tx = closed_tx.clone();
                        connections.spawn(async move {
                            let connection = incoming.await?;
                            run_quic_udp_peer(mode, serial, connection, address.ip(), events, hold).await?;
                            let _ = closed_tx.send(serial);
                            Ok::<_, anyhow::Error>(())
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap()??;
                    }
                }
            }
            while let Some(result) = connections.join_next().await {
                result??;
            }
            Ok(())
        });
        Ok(Self {
            node,
            packets,
            closed,
            mode,
            endpoint,
            task,
        })
    }

    pub(in crate::control) async fn reply(
        &self,
        packet: &QuicUdpPacket,
        source: SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let id = packet
            .next_reply
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        send_quic_udp_reply(
            self.mode,
            &packet.carrier,
            packet.session,
            id,
            source,
            payload,
        )
        .await
    }

    pub(in crate::control) async fn close(self) -> anyhow::Result<()> {
        self.endpoint.close(0u32.into(), b"test finished");
        self.task.await??;
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

// These bytes are independent of the outbound codecs: RFC 9000 varints,
// Hysteria2's textual address and TUIC v5's sing address discriminants.
fn quic_peer_varint(input: &mut &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(!input.is_empty(), "missing QUIC varint");
    let width = 1usize << (input[0] >> 6);
    anyhow::ensure!(input.len() >= width, "short QUIC varint");
    let value = input[..width].iter().enumerate().fold(0usize, |n, (i, b)| {
        (n << 8) | usize::from(if i == 0 { b & 63 } else { *b })
    });
    *input = &input[width..];
    Ok(value)
}

fn decode_quic_udp_request(
    mode: QuicUdpMode,
    wire: &[u8],
) -> anyhow::Result<(u32, SocketAddr, Vec<u8>)> {
    if mode == QuicUdpMode::Hysteria2 {
        anyhow::ensure!(
            wire.len() >= 9 && wire[6..8] == [0, 1],
            "fragmented/short Hy2 fixture packet"
        );
        let session = u32::from_be_bytes(wire[..4].try_into()?);
        let mut rest = &wire[8..];
        let size = quic_peer_varint(&mut rest)?;
        anyhow::ensure!(rest.len() >= size, "short Hy2 address");
        let target = std::str::from_utf8(&rest[..size])?.parse()?;
        return Ok((session, target, rest[size..].to_vec()));
    }
    anyhow::ensure!(
        wire.len() >= 11 && wire[..2] == [5, 2] && wire[6..8] == [1, 0],
        "invalid TUIC fixture packet"
    );
    let session = u32::from(u16::from_be_bytes(wire[2..4].try_into()?));
    let size = usize::from(u16::from_be_bytes(wire[8..10].try_into()?));
    let (ip, offset) = match wire[10] {
        1 => {
            anyhow::ensure!(wire.len() >= 17, "short TUIC IPv4 address");
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(
                    &wire[11..15],
                )?)),
                15,
            )
        }
        2 => {
            anyhow::ensure!(wire.len() >= 29, "short TUIC IPv6 address");
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(
                    &wire[11..27],
                )?)),
                27,
            )
        }
        _ => anyhow::bail!("fixture expects numeric TUIC target"),
    };
    let port = u16::from_be_bytes(wire[offset..offset + 2].try_into()?);
    if wire.len() < offset + 2 + size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "TUIC fixture payload truncated",
        )
        .into());
    }
    anyhow::ensure!(wire.len() == offset + 2 + size, "TUIC payload length");
    Ok((
        session,
        SocketAddr::new(ip, port),
        wire[offset + 2..].to_vec(),
    ))
}

async fn send_quic_udp_reply(
    mode: QuicUdpMode,
    conn: &quinn::Connection,
    session: u32,
    packet: u16,
    source: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut wire = Vec::new();
    if mode == QuicUdpMode::Hysteria2 {
        wire.extend_from_slice(&session.to_be_bytes());
        wire.extend_from_slice(&packet.to_be_bytes());
        wire.extend_from_slice(&[0, 1]);
        let address = source.to_string();
        anyhow::ensure!(address.len() < 64, "fixture address varint");
        wire.push(address.len() as u8);
        wire.extend_from_slice(address.as_bytes());
    } else {
        wire.extend_from_slice(&[5, 2]);
        wire.extend_from_slice(&(session as u16).to_be_bytes());
        wire.extend_from_slice(&packet.to_be_bytes());
        wire.extend_from_slice(&[1, 0]);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        match source.ip() {
            std::net::IpAddr::V4(ip) => {
                wire.push(1);
                wire.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                wire.push(2);
                wire.extend_from_slice(&ip.octets());
            }
        }
        wire.extend_from_slice(&source.port().to_be_bytes());
    }
    wire.extend_from_slice(payload);
    if mode == QuicUdpMode::TuicStream {
        let mut stream = conn.open_uni().await?;
        stream.write_all(&wire).await?;
        stream.finish()?;
    } else {
        conn.send_datagram(wire.into())?;
    }
    Ok(())
}

async fn run_quic_udp_peer(
    mode: QuicUdpMode,
    serial: u64,
    conn: quinn::Connection,
    bind: std::net::IpAddr,
    events: tokio::sync::mpsc::UnboundedSender<QuicUdpPacket>,
    hold: Option<Arc<QuicStreamHold>>,
) -> anyhow::Result<()> {
    let mut sockets =
        std::collections::HashMap::<u32, (Arc<UdpSocket>, Arc<std::sync::atomic::AtomicU16>)>::new(
        );
    let mut tasks = tokio::task::JoinSet::<anyhow::Result<()>>::new();
    let (wire_tx, mut wire_rx) = tokio::sync::mpsc::unbounded_channel();
    loop {
        let wire = tokio::select! {
            biased;
            _ = conn.closed() => break,
            result = tasks.join_next(), if !tasks.is_empty() => { result.unwrap()??; continue; }
            request = conn.accept_bi(), if mode == QuicUdpMode::Hysteria2 => {
                let (mut send, mut recv) = request?;
                tasks.spawn(async move {
                    let request = recv.read_to_end(8192).await?;
                    anyhow::ensure!(request.windows(20).any(|v| v == b"source-test-password"), "Hy2 auth credential");
                    // QPACK literal :status=233, hysteria-udp=true, hysteria-cc-rx=0.
                    let headers = b"\x00\x00\x5f\x09\x03233\x27\x05hysteria-udp\x04true\x27\x07hysteria-cc-rx\x010";
                    send.write_all(&[1, headers.len() as u8]).await?;
                    send.write_all(headers).await?;
                    send.finish()?;
                    Ok(())
                });
                continue;
            }
            request = conn.accept_uni() => {
                let mut recv = request?;
                let sender = wire_tx.clone();
                let carrier = conn.clone();
                let hold = hold.clone();
                tasks.spawn(async move {
                    if mode == QuicUdpMode::Hysteria2 {
                        let mut buffer = [0; 1024];
                        while recv.read(&mut buffer).await?.is_some() {}
                    } else {
                        let mut head = [0; 2];
                        recv.read_exact(&mut head).await?;
                        match head {
                            [5, 0] => {
                                let mut auth = [0; 48];
                                recv.read_exact(&mut auth).await?;
                                let mut expected = [0; 32];
                                carrier.export_keying_material(&mut expected, &auth[..16], b"source-test-password")
                                    .map_err(|e| anyhow::anyhow!("TLS exporter: {e:?}"))?;
                                anyhow::ensure!(auth[16..] == expected, "TUIC auth token");
                            }
                            [5, 2] => {
                                if let Some(hold) = hold {
                                    hold.entered.notify_one();
                                    hold.release.notified().await;
                                }
                                let body = match recv.read_to_end(65536).await {
                                    Ok(body) => body,
                                    Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(_))) => return Ok(()),
                                    Err(error) => return Err(error.into()),
                                };
                                let mut wire = head.to_vec();
                                wire.extend_from_slice(&body);
                                sender.send(wire)?;
                            }
                            [5, 3] | [5, 4] => {}
                            _ => anyhow::bail!("unexpected TUIC command"),
                        }
                    }
                    Ok(())
                });
                continue;
            }
            wire = conn.read_datagram(), if mode != QuicUdpMode::TuicStream => {
                let wire = wire?;
                if mode != QuicUdpMode::Hysteria2 && wire.first() == Some(&5) && wire.get(1) == Some(&4) { continue; }
                wire.to_vec()
            }
            wire = wire_rx.recv() => wire.expect("peer stream sender retained"),
        };
        let (session, target, payload) = match decode_quic_udp_request(mode, &wire) {
            Ok(packet) => packet,
            Err(error) => {
                if let Some(hold) = &hold
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
                {
                    hold.truncated.notify_one();
                    continue;
                }
                return Err(error);
            }
        };
        let (socket, next_reply) = if let Some((socket, counter)) = sockets.get(&session) {
            (Arc::clone(socket), Arc::clone(counter))
        } else {
            let socket =
                Arc::new(honk_outbound::util::udp_marked_bind(SocketAddr::new(bind, 0)).await?);
            let counter = Arc::new(std::sync::atomic::AtomicU16::new(0));
            sockets.insert(session, (Arc::clone(&socket), Arc::clone(&counter)));
            let next_reply = Arc::clone(&counter);
            let receiver = Arc::clone(&socket);
            let carrier = conn.clone();
            tasks.spawn(async move {
                let mut buffer = [0; 65536];
                loop {
                    let (size, source) = receiver.recv_from(&mut buffer).await?;
                    let id = next_reply.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    send_quic_udp_reply(mode, &carrier, session, id, source, &buffer[..size])
                        .await?;
                }
            });
            (socket, counter)
        };
        socket.send_to(&payload, target).await?;
        events.send(QuicUdpPacket {
            connection: serial,
            session,
            target,
            mapping: socket.local_addr()?,
            payload,
            carrier: conn.clone(),
            next_reply,
        })?;
    }
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        match result {
            Err(error) if error.is_cancelled() => {}
            Ok(Err(_)) if conn.close_reason().is_some() => {}
            result => result??,
        }
    }
    Ok(())
}
