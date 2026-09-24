use super::*;
use crate::control::tests::support::canonical_socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WAIT: Duration = Duration::from_secs(20);

mod dns_failure;
mod retention;
#[cfg(feature = "rprx")]
mod xudp;

pub(super) fn enable_udp_provenance(
    v4: &[Arc<UdpSocket>],
    v6: &[Arc<UdpSocket>],
) -> anyhow::Result<()> {
    // Ordinary mock wildcard sockets lack ORIGDST; use real kernel metadata,
    // as transparent production sockets do, without inventing remote destinations.
    for socket in v4 {
        nix::sys::socket::setsockopt(
            socket.as_ref(),
            nix::sys::socket::sockopt::Ipv4OrigDstAddr,
            &true,
        )?;
    }
    for socket in v6 {
        nix::sys::socket::setsockopt(
            socket.as_ref(),
            nix::sys::socket::sockopt::Ipv6OrigDstAddr,
            &true,
        )?;
    }
    Ok(())
}

struct Fixture {
    commands: mpsc::Sender<ControlCommand>,
    phase: watch::Receiver<EnginePhase>,
    native: Arc<crate::native_api::observation::NativeObservation>,
    tracker: Arc<crate::connection_tracker::ConnectionTracker>,
    backend: Arc<RwLock<Box<dyn EbpfBackend>>>,
    groups: honk_outbound::group::SharedGroupManager,
    alive: Arc<honk_outbound::alive::AliveDialerSet>,
    cache_db: Option<Arc<crate::state::cache::CacheDb>>,
    dns_service: crate::dns::DnsService,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<(ControlPlane, anyhow::Result<()>)>,
    api: crate::native_api::NativeServer,
    http: reqwest::Client,
    base: String,
    tproxy: SocketAddr,
    dns: SocketAddr,
    peer: tokio::net::TcpListener,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Fixture {
    async fn start() -> anyhow::Result<Self> {
        Self::start_with(|_, _| {}).await
    }

    async fn start_with(configure: impl FnOnce(&mut Config, SocketAddr)) -> anyhow::Result<Self> {
        let peer = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut config = Config::default();
        config.ensure_builtin_nodes();
        let node = canonical_socks5("peer", "127.0.0.1", peer.local_addr()?.port(), None);
        config.groups = vec![Group {
            name: "target".into(),
            nodes: vec![node.id],
            policy: honk_config::node::GroupPolicy::Fallback,
            ..Default::default()
        }];
        config.nodes.push(node);
        config.routing.default_outbound = "target".into();
        config.global.tproxy_port = free_port();
        config.global.nfqueue_enable = false;
        config.global.store_subscribe = false;
        config.experimental.cache_file.enabled = Some(false);
        config.global.dial_mode = "ip".into();
        config.global.connect_timeout_ms = 30_000;
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        config.global.check_interval_secs = 3600;
        config.global.bootstrap_resolver = "127.0.0.1:9".into();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        let tproxy = SocketAddr::from(([127, 0, 0, 1], config.global.tproxy_port));
        let dns = SocketAddr::from(([127, 0, 0, 1], free_port()));
        config.dns.bind = format!("tcp://{dns}");
        config.dns.upstream[0].address = "127.0.0.1:9".into();
        config.dns.upstream[0].outbound = Some("direct".into());
        config.experimental.native_api.enabled = true;
        config.experimental.native_api.allow_anonymous_loopback = true;
        configure(&mut config, peer.local_addr()?);
        let traffic_geo = crate::routing::GeoRequirements::for_traffic(&config.routing.rules);
        let dns_geo = crate::dns::routing::DnsRouter::geo_requirements(&config.dns);
        let sources = crate::routing::GeoSourceSet::load_captured(
            &traffic_geo.union(&dns_geo),
            std::path::Path::new(&config.global.data_dir),
            // Pin test inputs, not a developer's ambient DAE_LOCATION_ASSET directory.
            |path| {
                std::fs::read(
                    std::path::Path::new(&config.global.data_dir).join(path.file_name().unwrap()),
                )
                .map(Arc::from)
            },
        )?;
        let router = Router::new_with_geo_sources(
            &config.routing.rules,
            &config.routing.default_outbound,
            &sources,
        )?;
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_with_geo_sources(
            &config.dns,
            &sources,
        )?);
        let proxy = Arc::new(ProxyRegistry::default_resolver()?);
        let upstream = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router.clone(),
                Some(proxy.clone()),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
                config.dns.strategy,
            )?,
        );
        let hosts = crate::dns::forwarder::HostsSourceSet::load(&config.dns)?.parse()?;
        let policy = crate::dns::policy::PolicyId::from_config_with_artifacts(
            &config.dns,
            &hosts.fingerprint(),
            &dns_router.geo_fingerprint(),
        )?;
        let forwarder = Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                upstream.clone(),
                Arc::new(tokio::sync::Mutex::new(crate::dns::cache::DnsCache::new(
                    100,
                ))),
                dns_router,
            )
            .with_configured_upstreams(&config.dns)
            .with_cache_enabled(config.dns.cache.enabled)
            .with_policy_id(policy)
            .with_hosts_snapshot(hosts),
        );
        let state = config
            .experimental
            .cache_file
            .stores_selections()
            .then(|| crate::state::StateDb::open(std::path::Path::new(&config.global.data_dir)))
            .transpose()?
            .map(Arc::new);
        let mut plane = ControlPlane::new_with_upstream_pool(
            config,
            Box::new(crate::ebpf::mock::MockEbpfBackend::new()),
            router,
            proxy,
            forwarder,
            upstream,
        )?;
        plane.init_cache_db(state, None).await;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::native(),
        )));
        plane.start_datapath_flags_coordinator()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = crate::native_api::NativeState::new(
            &mut plane,
            address,
            std::time::SystemTime::now(),
            std::time::Instant::now(),
        )
        .await?;
        let phase = plane.observe_phase();
        let native = plane.native_observation();
        let commands = plane.command_sender();
        let tracker = plane.connection_tracker();
        let backend = plane.ebpf_handle();
        let groups = plane.group_manager();
        let dns_service = plane.dns_service();
        let shutdown = plane.shutdown_requested.clone();
        let alive = plane.alive_set();
        let cache_db = plane.cache_db();
        alive.pause_health_checks().await?;
        let api = crate::native_api::NativeServer::start(listener, Arc::new(state));
        let task = tokio::spawn(async move {
            let result = plane.run().await;
            (plane, result)
        });
        let fixture = Self {
            commands,
            phase,
            native,
            tracker,
            backend,
            groups,
            alive,
            cache_db,
            dns_service,
            shutdown,
            task,
            api,
            http: reqwest::Client::builder()
                .no_proxy()
                .timeout(WAIT)
                .build()?,
            base: format!("http://{address}/api/v1"),
            tproxy,
            dns,
            peer,
        };
        tokio::time::timeout(WAIT, async {
            loop {
                if *fixture.phase.borrow() == EnginePhase::Running
                    && fixture.native.probes.running()
                {
                    break;
                }
                assert!(
                    !fixture.task.is_finished(),
                    "mock command owner stopped before admission"
                );
                tokio::task::yield_now().await;
            }
        })
        .await?;
        fixture.alive.pause_health_checks().await?;
        Ok(fixture)
    }

    async fn connect_tcp(&self) -> anyhow::Result<TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind("127.0.0.1:0".parse()?)?;
        let client = socket.local_addr()?;
        let tuples = crate::control::connection::build_tuples_key(
            self.tproxy.ip(),
            self.tproxy.port(),
            client.ip(),
            client.port(),
            6,
        );
        self.backend.write().await.tcp_conn_state_store(
            &tuples,
            &honk_ebpf_common::ConnState {
                state: honk_ebpf_common::conn::TcpState::TcpStateActive as u8,
                last_seen_ns: crate::control::janitor::monotonic_now_ns()?,
                ..Default::default()
            },
        )?;
        Ok(tokio::time::timeout(WAIT, socket.connect(self.tproxy)).await??)
    }

    async fn transition(&self, resume: bool) -> Result<(), super::super::client::ControlError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let command = if resume {
            ControlCommand::Resume { reply }
        } else {
            ControlCommand::Suspend { reply }
        };
        self.commands.send(command).await.unwrap();
        tokio::time::timeout(WAIT, response).await.unwrap().unwrap()
    }

    async fn get(&self, path: &str) -> serde_json::Value {
        let response = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.unwrap()
    }

    async fn socks_peer(&self) -> TcpStream {
        socks_peer(&self.peer).await
    }

    async fn finish(self, failure: bool) -> ControlPlane {
        if !self.task.is_finished() {
            self.shutdown.store(true, Ordering::Release);
            let _ = self.commands.send(ControlCommand::Shutdown).await;
        }
        let (plane, result) = tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.is_err(),
            failure,
            "unexpected lifecycle result: {result:?}"
        );
        self.api.shutdown().await;
        plane
    }
}

async fn socks_peer(listener: &tokio::net::TcpListener) -> TcpStream {
    tokio::time::timeout(WAIT, async {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0; 2];
            if stream.read_exact(&mut hello).await.is_err() {
                continue;
            }
            assert_eq!(hello[0], 5);
            let mut methods = vec![0; hello[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            return stream;
        }
    })
    .await
    .expect("timed out accepting a SOCKS greeting")
}

async fn socks_request(stream: &mut TcpStream) -> u8 {
    tokio::time::timeout(WAIT, async {
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 5);
        assert_eq!(header[2], 0);
        let length = match header[3] {
            1 => 4,
            4 => 16,
            3 => stream.read_u8().await.unwrap() as usize,
            _ => panic!("invalid SOCKS destination"),
        };
        let mut target = vec![0; length + 2];
        stream.read_exact(&mut target).await.unwrap();
        header[1]
    })
    .await
    .expect("timed out receiving the SOCKS request")
}

async fn complete_socks(stream: &mut TcpStream) {
    tokio::time::timeout(WAIT, async {
        assert_eq!(socks_request(stream).await, 1);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
    })
    .await
    .expect("timed out completing the SOCKS handshake");
}

async fn closed(stream: &mut TcpStream) {
    let mut byte = [0];
    let read = tokio::time::timeout(WAIT, stream.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0)) || read.is_err(),
        "transport remained usable: {read:?}"
    );
}

async fn prepare_loopback_epoch(
    plane: &mut ControlPlane,
    resuming: bool,
) -> anyhow::Result<(RuntimeEpoch, SocketAddr)> {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    tcp.set_nonblocking(true)?;
    let dns = dns_listener::BoundDnsListener::bind(&honk_config::dns::DnsBindEndpoint::parse(
        "udp://127.0.0.1:0",
    )?)?;
    let address = dns.local_addr();
    let epoch = plane
        .prepare_epoch(
            BoundListeners {
                tcp4: tokio::io::unix::AsyncFd::new(tcp)?,
                tcp6: None,
                udp4: Vec::new(),
                udp6: Vec::new(),
                dns: Some(dns),
                nfqueue_enabled: false,
            },
            resuming,
        )
        .await?;
    Ok((epoch, address))
}

async fn suspended_loopback_plane() -> anyhow::Result<ControlPlane> {
    let mut config = Config::default();
    config.ensure_builtin_nodes();
    config.global.nfqueue_enable = false;
    config.dns.strategy = honk_config::dns::DnsStrategy::Ipv4Only;
    let mut plane = crate::control::tests::support::control_plane(config);
    plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::native(),
    )));
    plane.start_datapath_flags_coordinator()?;
    let (epoch, _) = prepare_loopback_epoch(&mut plane, false).await?;
    let mut epoch = Some(epoch);
    plane.open_epoch(epoch.as_mut().unwrap(), false).await?;
    let authorizations = crate::subscription::SubscriptionAuthorizations::new(&[])?;
    let mut commands = plane.command_rx.take().unwrap();
    plane
        .suspend_epoch(&mut epoch, &mut commands, &authorizations)
        .await?;
    plane.command_rx = Some(commands);
    assert!(epoch.is_none());
    Ok(plane)
}

#[tokio::test]
async fn resumed_epoch_admits_dns_before_ingress_publication() -> anyhow::Result<()> {
    let mut plane = suspended_loopback_plane().await?;
    assert!(plane.rebuild_suspended_runtime().await?.accepted());
    let (epoch, address) = prepare_loopback_epoch(&mut plane, true).await?;
    let mut epoch = Some(epoch);
    assert!(plane.dns_controller.try_admit_query(true).is_err());
    // Hold the publication writer so admission is checked before any ready write.
    let backend = plane.ebpf.clone();
    let publication = backend.write().await;
    let controller = plane.dns_controller.clone();
    let mut opening = Box::pin(plane.open_epoch(epoch.as_mut().unwrap(), true));
    assert!(futures::poll!(opening.as_mut()).is_pending());
    drop(
        controller
            .try_admit_query(true)
            .expect("DNS must admit before ingress publication can proceed"),
    );
    drop(publication);
    opening.await?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    let query = crate::dns::forwarder::build_dns_query("resume.example", 28);
    client.send_to(&query, address).await?;
    let mut answer = [0; 512];
    let (size, source) = tokio::time::timeout(WAIT, client.recv_from(&mut answer)).await??;
    assert_eq!(source, address);
    assert!(size >= 12);
    assert_eq!(&answer[..2], &query[..2]);
    assert_ne!(answer[2] & 0x80, 0);
    assert_eq!(answer[3] & 0x0f, 0, "resumed DNS must answer NOERROR");
    assert_eq!(&answer[6..8], &[0, 0], "ipv4only answers AAAA locally");
    let authorizations = crate::subscription::SubscriptionAuthorizations::new(&[])?;
    let mut commands = plane.command_rx.take().unwrap();
    plane
        .suspend_epoch(&mut epoch, &mut commands, &authorizations)
        .await?;
    plane.finalize_shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn dns_resume_rejection_keeps_candidate_epoch_fenced_and_owned() -> anyhow::Result<()> {
    let mut plane = suspended_loopback_plane().await?;
    // A drained runtime without a fresh publication is not eligible to resume.
    let (epoch, address) = prepare_loopback_epoch(&mut plane, true).await?;
    let mut epoch = Some(epoch);
    let error = plane
        .open_epoch(epoch.as_mut().unwrap(), true)
        .await
        .expect_err("unready DNS must reject ingress reopening");
    assert!(matches!(
        error.downcast_ref::<crate::dns::runtime::DnsPauseError>(),
        Some(crate::dns::runtime::DnsPauseError::NotReady)
    ));
    assert!(plane.drain_tracker.should_reject());
    assert!(plane.dns_controller.try_admit_query(true).is_err());
    plane
        .ebpf
        .write()
        .await
        .clear_listener_sockets()
        .expect("datapath admission must remain closed after DNS resume rejection");
    let authorizations = crate::subscription::SubscriptionAuthorizations::new(&[])?;
    let mut commands = plane.command_rx.take().unwrap();
    plane
        .suspend_epoch(&mut epoch, &mut commands, &authorizations)
        .await?;
    assert!(epoch.is_none());
    assert_eq!(plane.drain_tracker.active_count(), 0);
    let _rebound = UdpSocket::bind(address).await?;
    plane.finalize_shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn mock_commands_close_live_and_pre_id_tcp_preserving_api_history() -> anyhow::Result<()> {
    let fixture = Fixture::start().await?;
    let mut active = fixture.connect_tcp().await?;
    active.write_all(b"retained counters").await?;
    let mut peer = fixture.socks_peer().await;
    complete_socks(&mut peer).await;
    let mut payload = [0; 17];
    tokio::time::timeout(WAIT, peer.read_exact(&mut payload))
        .await
        .expect("timed out receiving pre-suspend TCP payload at the SOCKS peer")?;
    assert_eq!(&payload, b"retained counters");
    peer.write_all(&payload).await?;
    tokio::time::timeout(WAIT, active.read_exact(&mut payload))
        .await
        .expect("timed out receiving pre-suspend TCP echo at the client")?;
    let mut before_id = fixture.connect_tcp().await?;
    before_id.write_all(b"pending").await?;
    let mut dialing_peer = fixture.socks_peer().await;
    assert_eq!(
        fixture.tracker.snapshot().len(),
        1,
        "second handshake must still be pre-ID"
    );
    let runtime = fixture.get("/runtime").await;
    let history = tokio::time::timeout(WAIT, async {
        loop {
            let history = fixture.get("/runtime/traffic/history").await;
            if !history["samples"].as_array().unwrap().is_empty() {
                break history;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    fixture.transition(false).await.unwrap();
    assert_eq!(*fixture.phase.borrow(), EnginePhase::Suspended);
    let refused = fixture
        .http
        .get(format!(
            "{}/dns/query?domain=paused.example&type=A",
            fixture.base
        ))
        .send()
        .await?;
    assert_eq!(refused.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.headers()["retry-after"], "1");
    assert_eq!(
        refused.json::<serde_json::Value>().await?["error"]["code"],
        "temporarily_unavailable"
    );
    closed(&mut active).await;
    closed(&mut peer).await;
    closed(&mut before_id).await;
    closed(&mut dialing_peer).await;
    assert!(fixture.tracker.snapshot().is_empty());
    assert!(fixture.transition(false).await.is_err());
    assert_eq!(
        fixture.get("/runtime").await["instance_id"],
        runtime["instance_id"]
    );
    fixture.transition(true).await.unwrap();
    let after = fixture.get("/runtime/traffic/history").await;
    assert!(
        after["samples"]
            .as_array()
            .unwrap()
            .contains(&history["samples"][0])
    );
    assert_eq!(
        fixture.get("/runtime").await["instance_id"],
        runtime["instance_id"]
    );
    assert!(fixture.transition(true).await.is_err());
    let plane = fixture.finish(false).await;
    assert_eq!(plane.drain_tracker.active_count(), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn failed_resume_dns_bind_remains_fenced_and_can_retry() -> anyhow::Result<()> {
    let fixture = Fixture::start().await?;
    fixture.transition(false).await.unwrap();
    let occupied = tokio::net::TcpListener::bind(fixture.dns).await?;
    assert!(fixture.transition(true).await.is_err());
    assert_eq!(*fixture.phase.borrow(), EnginePhase::Suspended);
    assert!(
        fixture
            .backend
            .write()
            .await
            .set_datapath_ready(true)
            .is_err()
    );
    assert!(!fixture.task.is_finished());
    drop(occupied);
    fixture.transition(true).await.unwrap();
    assert_eq!(*fixture.phase.borrow(), EnginePhase::Running);
    fixture.finish(false).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn suspend_quiescence_failure_is_fatal_not_suspended() -> anyhow::Result<()> {
    let fixture = Fixture::start().await?;
    fixture.backend.write().await.arm_quiesce_fault();
    assert!(fixture.transition(false).await.is_err());
    let backend = fixture.backend.clone();
    fixture.finish(true).await;
    assert!(backend.write().await.set_datapath_ready(true).is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn mock_suspend_retires_live_udp_association_without_replay() -> anyhow::Result<()> {
    let fixture = Fixture::start().await?;
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.send_to(b"lifecycle-udp", fixture.tproxy).await?;
    let mut association = tokio::time::timeout(WAIT, fixture.socks_peer()).await?;
    assert_eq!(socks_request(&mut association).await, 3);
    let port = relay.local_addr()?.port().to_be_bytes();
    association
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])
        .await?;
    let mut packet = [0; 128];
    let (length, source) = tokio::time::timeout(WAIT, relay.recv_from(&mut packet)).await??;
    assert!(packet[..length].ends_with(b"lifecycle-udp"));
    relay.send_to(&packet[..length], source).await?;
    let mut answer = [0; 128];
    let (size, _) = tokio::time::timeout(WAIT, client.recv_from(&mut answer)).await??;
    assert_eq!(&answer[..size], b"lifecycle-udp");
    assert!(
        fixture
            .tracker
            .snapshot()
            .iter()
            .any(|entry| entry.network == "udp")
    );
    fixture.transition(false).await.unwrap();
    closed(&mut association).await;
    assert!(fixture.tracker.snapshot().is_empty());
    fixture.transition(true).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), relay.recv_from(&mut packet))
            .await
            .is_err()
    );
    fixture.finish(false).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires transparent-listener permissions; run in the isolated lifecycle gate"]
async fn ordinary_shutdown_preserves_live_tcp_until_graceful_completion() -> anyhow::Result<()> {
    let mut fixture = Fixture::start().await?;
    let mut client = fixture.connect_tcp().await?;
    client.write_all(b"request").await?;
    let mut peer = fixture.socks_peer().await;
    complete_socks(&mut peer).await;
    let mut request = [0; 7];
    tokio::time::timeout(WAIT, peer.read_exact(&mut request))
        .await
        .expect("timed out receiving graceful-shutdown TCP request at the SOCKS peer")?;
    assert_eq!(&request, b"request");
    fixture.shutdown.store(true, Ordering::Release);
    fixture.commands.send(ControlCommand::Shutdown).await?;
    tokio::time::timeout(
        WAIT,
        fixture
            .phase
            .wait_for(|phase| *phase == EnginePhase::Draining),
    )
    .await??;
    tokio::time::sleep(Duration::from_millis(100)).await;
    peer.write_all(b"final response").await?;
    let mut response = [0; 14];
    tokio::time::timeout(WAIT, client.read_exact(&mut response)).await??;
    assert_eq!(&response, b"final response");
    drop(client);
    drop(peer);
    let plane = fixture.finish(false).await;
    assert_eq!(plane.drain_tracker.active_count(), 0);
    Ok(())
}
