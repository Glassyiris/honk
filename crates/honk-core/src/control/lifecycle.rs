use super::runtime::{
    CriticalTaskExit, OutboundHealthPublisher, accept_tcp_with_admission, run_tcp_admission_scaler,
};
use super::udp_ingress::{UdpLoopState, udp_listener_loop};
use super::*;
use std::collections::HashSet;
#[cfg(feature = "native-api")]
use std::sync::atomic::Ordering;
use tokio::sync::watch;
use tokio::task::JoinSet;

mod teardown;

const STAGE_TIMEOUT: Duration = Duration::from_secs(10);

struct BoundListeners {
    tcp4: tokio::io::unix::AsyncFd<std::net::TcpListener>,
    tcp6: Option<tokio::io::unix::AsyncFd<std::net::TcpListener>>,
    udp4: Vec<Arc<UdpSocket>>,
    udp6: Vec<Arc<UdpSocket>>,
    dns: Option<dns_listener::BoundDnsListener>,
    nfqueue_enabled: bool,
}

struct RuntimeEpoch {
    listeners: BoundListeners,
    stop: watch::Sender<bool>,
    ingress: JoinSet<()>,
    tcp: JoinSet<()>,
    maintenance: [Option<tokio::task::JoinHandle<()>>; 7],
    dns: Option<dns_listener::DnsListener>,
    janitor: Option<tokio::task::JoinHandle<()>>,
    removals: Option<tokio::task::JoinHandle<()>>,
    removal_errors: mpsc::UnboundedReceiver<anyhow::Error>,
    critical_errors: mpsc::UnboundedReceiver<anyhow::Error>,
    health_updates: Option<HealthUpdates>,
    #[cfg(feature = "ebpf")]
    queue: Option<NfqueueRuntime>,
}

impl Drop for RuntimeEpoch {
    fn drop(&mut self) {
        for task in self.maintenance.iter().flatten() {
            task.abort();
        }
    }
}

type HealthUpdateKey = (uuid::Uuid, u32, u32);

struct HealthUpdates {
    pending: Arc<parking_lot::Mutex<Option<HashSet<HealthUpdateKey>>>>,
    wake: Arc<tokio::sync::Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HealthUpdates {
    fn start(plane: &ControlPlane) -> Self {
        let pending = Arc::new(parking_lot::Mutex::new(Some(HashSet::new())));
        let wake = Arc::new(tokio::sync::Notify::new());
        let callback_pending = Arc::clone(&pending);
        let callback_wake = Arc::clone(&wake);
        plane
            .alive_set
            .set_ebpf_callback(Box::new(move |node, _, domain, family, _| {
                let mut pending = callback_pending.lock();
                if let Some(pending) = pending.as_mut() {
                    pending.insert((node, domain, family));
                    callback_wake.notify_one();
                }
            }));
        let publisher = Arc::new(OutboundHealthPublisher::new(
            plane.ebpf.clone(),
            plane.config.clone(),
            plane.group_manager.clone(),
            plane.alive_set.clone(),
        ));
        let task_pending = Arc::clone(&pending);
        let task_wake = Arc::clone(&wake);
        let task = tokio::spawn(async move {
            loop {
                task_wake.notified().await;
                let updates = {
                    let mut pending = task_pending.lock();
                    let Some(pending) = pending.as_mut() else {
                        return;
                    };
                    std::mem::take(pending)
                };
                for (node, domain, family) in updates {
                    if task_pending.lock().is_none() {
                        return;
                    }
                    Arc::clone(&publisher).publish(node, domain, family).await;
                }
            }
        });
        Self {
            pending,
            wake,
            task: Some(task),
        }
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        self.pending.lock().take();
        self.wake.notify_one();
        joined(&mut self.task).await
    }
}

impl ControlPlane {
    async fn bind_runtime_listeners(&self) -> anyhow::Result<BoundListeners> {
        let config = self.config.read().await;
        let tproxy_port = config.global.tproxy_port;
        let tproxy_mark = config.global.tproxy_mark;
        let udp_nfqueue_enabled = config.global.nfqueue_enable
            && self.ebpf.read().await.observe_datapath().kind == crate::ebpf::DatapathKind::Real;
        let dns_bind_endpoint = config
            .dns
            .bind_endpoint()
            .map_err(|error| anyhow::anyhow!("invalid dns.bind: {error}"))?;
        drop(config);
        #[cfg(feature = "ebpf")]
        {
            let _reload = self.reload_lock.lock().await;
            self.warn_lan_self_protection().await;
        }
        let bound_dns_listener = dns_bind_endpoint
            .as_ref()
            .map(dns_listener::BoundDnsListener::bind)
            .transpose()
            .map_err(|error| anyhow::anyhow!("bind dns.bind listener: {error}"))?;
        let tcp4_addr = SocketAddr::new("0.0.0.0".parse()?, tproxy_port);
        let tcp6_addr = SocketAddr::new("::".parse()?, tproxy_port);
        let udp4_addr = tcp4_addr;
        let udp6_addr = tcp6_addr;

        let tcp4_listener =
            tokio::io::unix::AsyncFd::new(bind_tproxy_tcp(tcp4_addr, tproxy_mark)?)?;
        info!("Control plane listening for TPROXY TCPv4 on {}", tcp4_addr);

        let tcp6_listener = match bind_tproxy_tcp(tcp6_addr, tproxy_mark).and_then(|listener| {
            tokio::io::unix::AsyncFd::new(listener).map_err(anyhow::Error::from)
        }) {
            Ok(l) => {
                info!("Control plane listening for TPROXY TCPv6 on {}", tcp6_addr);
                Some(l)
            }
            Err(e) => {
                // Same rule as the UDPv6 listeners: only a host without an
                // IPv6 stack may continue with the slot empty (the published
                // v4 fd fallback cannot accept v6 flows).
                let no_ipv6 = e
                    .downcast_ref::<io::Error>()
                    .and_then(|error| error.raw_os_error())
                    == Some(libc::EAFNOSUPPORT);
                if no_ipv6 {
                    warn!("TPROXY TCPv6 listener unavailable: {}", e);
                    None
                } else {
                    return Err(e.context("bind TPROXY TCPv6 listener"));
                }
            }
        };

        // Parallel UDP listeners: the eBPF datapath hashes each flow's tuple
        // into one of UDP_LISTENER_COUNT sockets per family (sk_lookup.rs);
        // each socket gets its own receive loop task below, so flows drain
        // in parallel across runtime workers.
        const UDP_LISTENER_COUNT: usize = 4;
        let udp4_sockets: Vec<Arc<UdpSocket>> =
            bind_tproxy_udp_listeners(udp4_addr, UDP_LISTENER_COUNT)?
                .into_iter()
                .map(Arc::new)
                .collect();
        info!(
            "Control plane listening for TPROXY UDPv4 x{} on {}",
            udp4_sockets.len(),
            udp4_addr
        );

        let udp6_sockets: Vec<Arc<UdpSocket>> =
            match bind_tproxy_udp_listeners(udp6_addr, UDP_LISTENER_COUNT) {
                Ok(sockets) => {
                    let sockets: Vec<Arc<UdpSocket>> = sockets.into_iter().map(Arc::new).collect();
                    info!(
                        "Control plane listening for TPROXY UDPv6 x{} on {}",
                        sockets.len(),
                        udp6_addr
                    );
                    sockets
                }
                Err(e) => {
                    // Only a host without an IPv6 stack may run with empty
                    // sk_lookup slots; any other failure would black-hole
                    // proxied IPv6 UDP until restart (slots are published
                    // once), so fail startup and let the supervisor retry.
                    let no_ipv6 = e
                        .downcast_ref::<io::Error>()
                        .and_then(|error| error.raw_os_error())
                        == Some(libc::EAFNOSUPPORT);
                    if no_ipv6 {
                        warn!("TPROXY UDPv6 listener unavailable: {}", e);
                        Vec::new()
                    } else {
                        return Err(e.context("bind TPROXY UDPv6 listener group"));
                    }
                }
            };

        #[cfg(all(test, feature = "native-api"))]
        tests::enable_udp_provenance(&udp4_sockets, &udp6_sockets)?;

        Ok(BoundListeners {
            tcp4: tcp4_listener,
            tcp6: tcp6_listener,
            udp4: udp4_sockets,
            udp6: udp6_sockets,
            dns: bound_dns_listener,
            nfqueue_enabled: udp_nfqueue_enabled,
        })
    }

    async fn configure_health_loop(&mut self) {
        let alive_set = self.alive_set.clone();
        let interval_secs = {
            let c = self.config.read().await;
            c.global.check_interval_secs
        };
        let check_timeout = std::time::Duration::from_secs(5);

        {
            let c = self.config.read().await;
            honk_outbound::tls::set_tls_mode(&c.global.tls_implementation);
            honk_outbound::tls::set_utls_imitate(&c.global.utls_imitate);
        }

        // Configure HTTP-based health checks from config (Go: TcpCheckOption).
        {
            let c = self.config.read().await;
            let check_url = c.global.tcp_check_url.first().cloned().unwrap_or_default();
            let check_method = if c.global.tcp_check_http_method.is_empty() {
                "HEAD".to_string()
            } else {
                c.global.tcp_check_http_method.clone()
            };
            if !check_url.is_empty() {
                let prober = Arc::new(ProxyHttpProber::new(
                    self.config.clone(),
                    self.proxy_registry.clone(),
                    self.runtime_registry.clone(),
                    check_method.clone(),
                    self.group_manager.clone(),
                ));
                alive_set
                    .set_http_probe(prober, check_url, check_method)
                    .await;
            } else {
                info!(
                    "HTTP health check disabled (no tcp_check_url configured), using TCP connect"
                );
            }
        }

        // Configure UDP health checks (Go: UdpCheckOption): each probe
        // cycle sends one DNS query through the node's own UDP data
        // path, so nodes with working TCP but broken UDP (e.g. an
        // AnyTLS server without UoT) are marked dead for the UDP
        // domains and excluded from UDP selection.
        {
            let dns_raw = {
                let c = self.config.read().await;
                c.global.udp_check_dns.clone()
            };
            let quic_url = {
                let c = self.config.read().await;
                if c.groups
                    .iter()
                    .any(|group| group.policy == honk_config::node::GroupPolicy::Score)
                {
                    c.global.tcp_check_url.first().cloned().unwrap_or_default()
                } else {
                    String::new()
                }
            };
            let resolver: crate::outbound::ResolveHook = {
                let controller = self.dns_controller.clone();
                Arc::new(move |host: String, port: u16| {
                    let controller = controller.clone();
                    Box::pin(async move {
                        controller.resolve_domain(&host).await.map(|addresses| {
                            addresses
                                .into_iter()
                                .map(|ip| std::net::SocketAddr::new(ip, port))
                                .collect()
                        })
                    })
                })
            };
            let dns_probe = UdpDnsProbeTarget::new(dns_raw, Some(resolver.clone()));
            match tokio::time::timeout(check_timeout, dns_probe.resolve()).await {
                Ok(Ok((target, _))) => info!("UDP health check enabled (dns={})", target),
                _ => info!("UDP DNS health target initialization deferred to later health checks"),
            }
            let quic_score_target =
                (!quic_url.is_empty()).then(|| QuicScoreProbeTarget::new(quic_url, Some(resolver)));
            alive_set.set_udp_probe(Arc::new(ProxyUdpProber::new(
                self.config.clone(),
                self.proxy_registry.clone(),
                self.runtime_registry.clone(),
                self.stats.clone(),
                dns_probe,
                quic_score_target,
                self.group_manager.clone(),
            )));
        }

        info!(
            "Starting health check loop (interval={}s, timeout={}s)",
            interval_secs,
            check_timeout.as_secs()
        );
        let period = Duration::from_secs(interval_secs);
        self.health_task = Some(alive_set.spawn_health_check_loop(period, check_timeout));
    }

    async fn prepare_epoch(&mut self, listeners: BoundListeners) -> anyhow::Result<RuntimeEpoch> {
        use std::os::fd::AsRawFd;
        let tcp4 = listeners.tcp4.as_raw_fd();
        let tcp6 = listeners.tcp6.as_ref().map_or(tcp4, AsRawFd::as_raw_fd);
        let udp4: Vec<_> = listeners
            .udp4
            .iter()
            .map(|socket| socket.as_raw_fd())
            .collect();
        let udp6: Vec<_> = listeners
            .udp6
            .iter()
            .map(|socket| socket.as_raw_fd())
            .collect();
        self.ebpf
            .write()
            .await
            .publish_listener_sockets(tcp4, tcp6, &udp4, &udp6)?;
        let (critical_tx, critical_errors) = mpsc::unbounded_channel();
        let (removal_tx, removal_errors) = mpsc::unbounded_channel();
        let (stop, _) = watch::channel(false);
        let mut epoch = RuntimeEpoch {
            dns: None,
            listeners,
            stop,
            ingress: JoinSet::new(),
            tcp: JoinSet::new(),
            maintenance: std::array::from_fn(|_| None),
            janitor: None,
            removals: None,
            removal_errors,
            critical_errors,
            health_updates: None,
            #[cfg(feature = "ebpf")]
            queue: None,
        };
        let prepared = async {
            if let Some(bound) = epoch.listeners.dns.take() {
                epoch.dns = Some(bound.spawn(
                    self.dns_controller.clone(),
                    self.concurrency_limit.clone(),
                    self.stats.clone(),
                    self.drain_tracker.clone(),
                    #[cfg(feature = "native-api")]
                    self.native.clone(),
                    #[cfg(feature = "native-api")]
                    self.diagnostics.clone(),
                )?);
            }
            #[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
            let record_flows = self.native.is_some()
                && self
                    .config
                    .read()
                    .await
                    .experimental
                    .native_api
                    .record_flows;
            let state = UdpLoopState::new(self, daens_netns_exists());
            for (socket, family) in epoch
                .listeners
                .udp4
                .iter()
                .map(|socket| (socket, "v4"))
                .chain(epoch.listeners.udp6.iter().map(|socket| (socket, "v6")))
            {
                let state = state.clone();
                let socket = Arc::clone(socket);
                let batch = sockets::UdpRecvBatch::new()?;
                #[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
                let mut batch = batch;
                #[cfg(all(feature = "native-api", feature = "ebpf", target_os = "linux"))]
                if record_flows && batch.enable_trace(&socket, None).is_err() {
                    let trace = self.ebpf.write().await.receive_trace();
                    if let Err(error) = batch.enable_trace(&socket, trace) {
                        warn!(family, %error, "UDP receive trace unavailable");
                    }
                }
                let mut stopping = epoch.stop.subscribe();
                let mut exit = CriticalTaskExit {
                    name: "udp_listener_loop",
                    fatal_tx: critical_tx.clone(),
                    expected: false,
                };
                epoch.ingress.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = stopping.changed() => exit.expected_stop(),
                        _ = udp_listener_loop(state, socket, family, batch) => {},
                    }
                });
            }
            epoch.removals = Some(spawn_udp_removal_worker(
                self.udp_pool.clone(),
                self.ebpf.clone(),
                self.connection_tracker.clone(),
                removal_tx,
            ));
            epoch.janitor = Some(
                BpfJanitor::new(self.ebpf.clone(), self.tcp_flow_pins.clone()).spawn_supervised(
                    CriticalTaskExit {
                        name: "bpf_janitor",
                        fatal_tx: critical_tx,
                        expected: false,
                    },
                    epoch.stop.subscribe(),
                ),
            );
            epoch.health_updates = Some(HealthUpdates::start(self));
            #[cfg(feature = "ebpf")]
            {
                let sequence_ready = if epoch.listeners.nfqueue_enabled {
                    self.rotate_udp_decision_generation().await?
                } else {
                    false
                };
                match self
                    .start_nfqueue_runtime(epoch.listeners.nfqueue_enabled, sequence_ready)
                    .await
                {
                    Ok(queue) => epoch.queue = queue,
                    Err(error) => {
                        self.degrade_nfqueue_startup(&mut epoch.listeners.nfqueue_enabled, error)
                            .await
                    }
                }
                if let Some(queue) = epoch.queue.as_mut()
                    && let Err(error) = queue.check_startup_health().await
                {
                    self.cleanup_nfqueue_startup_failure(&mut epoch.queue).await;
                    epoch.queue = None;
                    self.degrade_nfqueue_startup(
                        &mut epoch.listeners.nfqueue_enabled,
                        error.into(),
                    )
                    .await;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = prepared {
            // Preparation has not opened admission. Cleanup must not borrow the
            // terminal process shutdown path or discard retained API owners.
            if let Err(cleanup) = self.stop_network_epoch(Some(&mut epoch)).await {
                return Err(anyhow::Error::new(EpochCleanupFailure(cleanup)).context(error));
            }
            return Err(error);
        }
        Ok(epoch)
    }

    async fn open_epoch(&mut self, epoch: &mut RuntimeEpoch) -> anyhow::Result<()> {
        #[cfg(feature = "ebpf")]
        let queue_ready = epoch
            .queue
            .as_ref()
            .is_some_and(|queue| queue.sequence_ready);
        #[cfg(not(feature = "ebpf"))]
        let queue_ready = false;
        self.initialize_datapath_flags(epoch.listeners.nfqueue_enabled, queue_ready)
            .await?;
        #[cfg(feature = "ebpf")]
        if let Some(queue) = epoch.queue.as_ref()
            && queue.sequence_ready
        {
            queue.pending.open_admission();
        }
        self.ebpf.write().await.set_datapath_ready(true)?;
        self.drain_tracker.stop_rejecting();
        Ok(())
    }

    async fn start_epoch_maintenance(&self, epoch: &mut RuntimeEpoch) {
        let registry = self.runtime_registry.clone();
        let dns = self.dns_controller.runtime_provider();
        let groups = self.group_manager.clone();
        epoch.maintenance = [
            self.udp_pool.spawn_janitor(),
            self.sniffer_pool.spawn_janitor(),
            super::tcp_sniff::spawn_sniff_neg_cache_janitor(self.tcp_sniff_neg_cache.clone()),
            self.connection_pool.spawn_janitor(),
            tokio::spawn(run_tcp_admission_scaler(
                self.concurrency_limit.clone(),
                self.resource_budget,
                self.stats.clone(),
                self.tcp_admission_target.clone(),
            )),
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(honk_outbound::runtime::TLS_REAP_INTERVAL);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let now = std::time::Instant::now();
                    registry.read().reap_idle_resources(now);
                    dns.current().reap_idle_resources(now);
                }
            }),
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tick.tick().await;
                    let manager = groups.read().clone();
                    manager.observe_transport_quality();
                }
            }),
        ]
        .map(Some);
        self.start_preconnect().await;
        let generation = self.runtime_registry.read().clone();
        self.start_udp_warm_coordinator(generation.clone()).await;
        self.start_selector_warm_coordinator(generation).await;
    }
}

#[derive(Debug, thiserror::Error)]
#[error("runtime candidate cleanup failed: {0}")]
struct EpochCleanupFailure(#[source] anyhow::Error);

async fn cleanup_stage<T>(future: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::pin!(future);
    match tokio::time::timeout(STAGE_TIMEOUT, &mut future).await {
        Ok(result) => result,
        Err(_) => {
            // Retain the same future: its blocking tasks and transport joins
            // remain owned even when the transition can no longer succeed.
            let _ = future.await?;
            anyhow::bail!("runtime cleanup exceeded its stop deadline")
        }
    }
}

async fn joined(task: &mut Option<tokio::task::JoinHandle<()>>) -> anyhow::Result<()> {
    let Some(handle) = task.as_mut() else {
        return Ok(());
    };
    let result = tokio::time::timeout(STAGE_TIMEOUT, &mut *handle).await;
    let result = match result {
        Ok(result) => result.map_err(anyhow::Error::from),
        Err(_) => {
            // A timeout is a failed transition, not permission to detach a
            // blocking child. The epoch keeps ownership until its join settles.
            let _ = handle.await;
            Err(anyhow::anyhow!(
                "owned runtime task exceeded its stop deadline"
            ))
        }
    };
    task.take();
    result
}

pub(super) async fn abort_and_join(
    task: &mut Option<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    if let Some(handle) = task.as_ref() {
        handle.abort();
    }
    match joined(task).await {
        Err(error)
            if error
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_cancelled) =>
        {
            Ok(())
        }
        result => result,
    }
}

fn retain_error(target: &mut Option<anyhow::Error>, result: anyhow::Result<()>) {
    if let Err(error) = result {
        target.get_or_insert(error);
    }
}

enum EpochEvent {
    Command(Option<ControlCommand>),
    Accepted(
        io::Result<(
            TcpStream,
            SocketAddr,
            &'static str,
            tokio::sync::OwnedSemaphorePermit,
        )>,
    ),
    Fatal(anyhow::Error),
    #[cfg(feature = "ebpf")]
    TokenExhausted,
    Reaped,
}

impl RuntimeEpoch {
    async fn next(
        &mut self,
        plane: &ControlPlane,
        commands: &mut mpsc::Receiver<ControlCommand>,
    ) -> EpochEvent {
        tokio::select! {
            biased;
            error = self.removal_errors.recv() => EpochEvent::Fatal(error.unwrap_or_else(|| anyhow::anyhow!("UDP removal owner stopped"))),
            error = self.critical_errors.recv() => EpochEvent::Fatal(error.unwrap_or_else(|| anyhow::anyhow!("critical runtime owner stopped"))),
            event = async {
                #[cfg(feature = "ebpf")]
                { match wait_nfqueue_event(&mut self.queue, &plane.ebpf).await {
                    NfqueueRuntimeEvent::Fatal(error) => EpochEvent::Fatal(error),
                    NfqueueRuntimeEvent::TokenExhausted => EpochEvent::TokenExhausted,
                } }
                #[cfg(not(feature = "ebpf"))]
                { std::future::pending::<EpochEvent>().await }
            } => event,
            command = commands.recv() => EpochEvent::Command(command),
            result = self.tcp.join_next(), if !self.tcp.is_empty() => match result {
                Some(Err(error)) if !error.is_cancelled() => EpochEvent::Fatal(error.into()),
                _ => EpochEvent::Reaped,
            },
            result = accept_tcp_with_admission(&self.listeners.tcp4, self.listeners.tcp6.as_ref(), plane.concurrency_limit.clone(), plane.stats.clone()), if !plane.drain_tracker.should_reject() => EpochEvent::Accepted(result),
        }
    }
}

impl ControlPlane {
    async fn fence_runtime(&self) -> anyhow::Result<()> {
        let mut error = None;
        retain_error(
            &mut error,
            self.ebpf.write().await.set_datapath_ready(false),
        );
        self.drain_tracker.start_rejecting();
        if let Some(flags) = self.datapath_flags.as_ref() {
            retain_error(&mut error, flags.fence_nfqueue().await);
        }
        error.map_or(Ok(()), Err)
    }

    fn shutdown_pending(&self) -> bool {
        #[cfg(feature = "native-api")]
        {
            self.shutdown_requested.load(Ordering::Acquire)
        }
        #[cfg(not(feature = "native-api"))]
        {
            false
        }
    }

    pub(super) async fn run_lifecycle(&mut self) -> anyhow::Result<()> {
        let mut commands = self
            .command_rx
            .take()
            .expect("control command receiver already taken");
        let mut authorizations = crate::subscription::SubscriptionAuthorizations::new(
            &self.config.read().await.subscriptions,
        )?;
        let mut epoch = None;
        let startup = async {
            let listeners = self.bind_runtime_listeners().await?;
            epoch = Some(self.prepare_epoch(listeners).await?);
            self.configure_health_loop().await;
            self.open_epoch(epoch.as_mut().expect("startup epoch"))
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let mut fatal = startup.err();
        if fatal.is_none() {
            self.start_epoch_maintenance(epoch.as_mut().expect("startup epoch"))
                .await;
            #[cfg(feature = "native-api")]
            self.publish_phase(EnginePhase::Running);
            #[cfg(target_os = "linux")]
            if let Err(error) =
                libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready])
            {
                warn!(%error, "sd_notify readiness failed");
            }
        }
        while fatal.is_none() && !self.shutdown_pending() {
            let event = match epoch.as_mut() {
                Some(active) => active.next(self, &mut commands).await,
                None => EpochEvent::Command(commands.recv().await),
            };
            match event {
                EpochEvent::Command(command) => {
                    let Some(command) = command else {
                        break;
                    };
                    let drain = self.drain_tracker.clone();
                    if !self
                        .dispatch_control_command(command, &drain, &mut authorizations)
                        .await
                    {
                        break;
                    }
                }
                EpochEvent::Fatal(error) => fatal = Some(error),
                #[cfg(feature = "ebpf")]
                EpochEvent::TokenExhausted => {
                    if let Some(queue) = epoch.as_mut().and_then(|epoch| epoch.queue.as_mut())
                        && let Err(error) = self.recover_nfqueue_token_exhaustion(queue).await
                    {
                        fatal = Some(error);
                    }
                }
                EpochEvent::Reaped => {}
                EpochEvent::Accepted(Ok((stream, address, family, permit))) => {
                    if self.drain_tracker.should_reject() {
                        continue;
                    }
                    if let Err(error) = set_so_mark_zero(&stream) {
                        warn!(%error, "failed to clear accepted socket bypass mark");
                    }
                    let handle = self.spawn_handle();
                    let guard = ConnectionGuard::new(self.drain_tracker.clone());
                    let flow = self.stats.track_tcp_flow();
                    epoch
                        .as_mut()
                        .expect("accepted epoch")
                        .tcp
                        .spawn(async move {
                            let (_permit, _guard, _flow) = (permit, guard, flow);
                            if let Err(error) = handle.serve_connection(stream, address).await {
                                debug!(%error, family, "TCP connection ended");
                            }
                        });
                }
                EpochEvent::Accepted(Err(error)) => {
                    error!(%error, "TPROXY TCP accept failed");
                    if error.raw_os_error() == Some(libc::EMFILE) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        if fatal.is_some() {
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
        }
        #[cfg(feature = "native-api")]
        self.publish_phase(if fatal.is_some() {
            EnginePhase::Failed
        } else {
            EnginePhase::Draining
        });
        retain_error(&mut fatal, self.fence_runtime().await);
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(STAGE_TIMEOUT).await;
        }
        // No watcher can reattach after this terminal boundary.
        retain_error(&mut fatal, self.ebpf.write().await.detach_hooks());
        if self.health_task.is_some() {
            retain_error(
                &mut fatal,
                cleanup_stage(async {
                    self.alive_set
                        .shutdown_health_checks()
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await,
            );
        }
        retain_error(&mut fatal, joined(&mut self.health_task).await);
        #[cfg(feature = "native-api")]
        if let Some(native) = &self.native
            && !native.probes.paused()
        {
            retain_error(
                &mut fatal,
                cleanup_stage(async { native.probes.pause().await.map_err(anyhow::Error::from) })
                    .await,
            );
        }
        #[cfg(feature = "clash-api")]
        {
            let mut slot = self.ui_download.lock().await;
            if let Some(download) = slot.as_mut() {
                retain_error(&mut fatal, cleanup_stage(download.stop_and_join()).await);
            }
            slot.take();
        }
        if fatal.is_none() && self.is_datapath_healthy() && epoch.is_some() {
            retain_error(&mut fatal, self.drain_tracker.drain().await.map(|_| ()));
        }
        retain_error(&mut fatal, self.stop_network_epoch(epoch.as_mut()).await);
        if let Some(flags) = &self.datapath_flags {
            retain_error(&mut fatal, flags.disable().await);
        }
        retain_error(&mut fatal, self.finalize_shutdown().await);
        fatal.map_or(Ok(()), Err)
    }
}

#[cfg(all(test, feature = "native-api"))]
mod tests;
