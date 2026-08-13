use super::*;

pub(super) struct UdpDriverStart {
    pub(super) first: QueuedDatagram,
    pub(super) followers: Vec<QueuedDatagram>,
}

/// Channels that establish the driver barrier. The initializer creates the
/// anyfrom socket, spawns this driver, awaits `ready`, commits the map entry,
/// then transfers the retained initial flight and waits for `first_ack`.
pub(in crate::control) struct UdpDriverHandle {
    ready: Option<oneshot::Receiver<()>>,
    start: Option<oneshot::Sender<UdpDriverStart>>,
    first_ack: Option<oneshot::Receiver<io::Result<()>>>,
    /// Test-only cancellation handle; production ownership remains in the
    /// pool's driver registry until terminal shutdown joins every task.
    #[cfg(test)]
    task: Option<tokio::task::AbortHandle>,
}

/// Owns every terminal driver action. Its synchronous Drop runs after normal
/// completion, panic unwind, and Tokio task abort; token-and-generation-safe
/// retirement makes a stale driver harmless to a replacement mapping.
struct UdpDriverCleanupGuard {
    pool: Arc<UdpEndpointPool>,
    key: EndpointKey,
    generation: u64,
    decision_token: u32,
    endpoint: Arc<UdpEndpoint>,
}

impl UdpDriverCleanupGuard {
    fn new(
        pool: Arc<UdpEndpointPool>,
        key: EndpointKey,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
    ) -> Self {
        Self {
            pool,
            key,
            generation,
            decision_token,
            endpoint,
        }
    }
}

pub(super) struct UdpDriverContext {
    pub(super) endpoint: Arc<UdpEndpoint>,
    pub(super) queue_rx: mpsc::Receiver<QueuedDatagram>,
    pub(super) reply_socket: Arc<UdpSocket>,
    pub(super) reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    pub(super) client_addr: SocketAddr,
    pub(super) client_dst: SocketAddr,
    pub(super) alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) outbound_tracker: OutboundTracker,
}

impl Drop for UdpDriverCleanupGuard {
    fn drop(&mut self) {
        self.endpoint.release();
        self.pool
            .retire_if_same(self.key, self.decision_token, self.generation);
    }
}

impl UdpDriverHandle {
    pub(in crate::control) async fn wait_ready(&mut self) -> io::Result<()> {
        self.ready
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver ready already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before ready"))
    }

    #[cfg(test)]
    pub(in crate::control) fn start(&mut self, first: QueuedDatagram) -> io::Result<()> {
        self.start_with_followers(first, Vec::new())
    }

    pub(in crate::control) fn start_with_followers(
        &mut self,
        first: QueuedDatagram,
        followers: Vec<QueuedDatagram>,
    ) -> io::Result<()> {
        self.start
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver start already consumed"))?
            .send(UdpDriverStart { first, followers })
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))
    }

    pub(in crate::control) async fn wait_first_ack(&mut self) -> io::Result<()> {
        self.first_ack
            .take()
            .ok_or_else(|| io::Error::other("UDP endpoint driver first ack already consumed"))?
            .await
            .map_err(|_| io::Error::other("UDP endpoint driver exited before first send"))?
    }

    #[cfg(test)]
    pub(super) fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl UdpEndpointPool {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) fn spawn_driver(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        client_dst: SocketAddr,
        generation: u64,
        decision_token: u32,
        endpoint: Arc<UdpEndpoint>,
        queue_rx: mpsc::Receiver<QueuedDatagram>,
        reply_socket: Arc<UdpSocket>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        outbound_name: String,
    ) -> UdpDriverHandle {
        let key = EndpointKey::new(client_addr, client_dst);
        let outbound_tracker = stats.outbound_tracker(&outbound_name);
        let (ready_tx, ready) = oneshot::channel();
        let (start, start_rx) = oneshot::channel();
        let (first_ack_tx, first_ack) = oneshot::channel();
        let pool = Arc::clone(self);
        let mut drivers = self.drivers.lock();
        while let Some(result) = drivers.tasks.try_join_next() {
            if let Err(error) = result {
                debug!("UDP endpoint driver join failed: {}", error);
            }
        }
        if drivers.closed {
            drop(ready_tx);
            drop(start_rx);
            drop(first_ack_tx);
            return UdpDriverHandle {
                ready: Some(ready),
                start: Some(start),
                first_ack: Some(first_ack),
                #[cfg(test)]
                task: None,
            };
        }
        let task = drivers.tasks.spawn(async move {
            // Construct before every await so abort and panic take the same
            // cleanup path as an ordinary driver return.
            let _cleanup = UdpDriverCleanupGuard::new(
                Arc::clone(&pool),
                key,
                generation,
                decision_token,
                Arc::clone(&endpoint),
            );
            let _ = ready_tx.send(());
            let initial = match start_rx.await {
                Ok(initial) => initial,
                Err(_) => return,
            };
            let result = run_endpoint_driver(
                UdpDriverContext {
                    endpoint: Arc::clone(&endpoint),
                    queue_rx,
                    reply_socket,
                    reply_socket_factory: Arc::clone(&pool.reply_socket_factory),
                    client_addr,
                    client_dst,
                    alive_set,
                    stats,
                    outbound_tracker,
                },
                initial,
                first_ack_tx,
            )
            .await;
            if let Err(error) = result {
                debug!(
                    "UDP endpoint driver {} -> {} stopped: {}",
                    client_addr, client_dst, error
                );
            }
        });
        drop(drivers);
        #[cfg(not(test))]
        drop(task);
        UdpDriverHandle {
            ready: Some(ready),
            start: Some(start),
            first_ack: Some(first_ack),
            #[cfg(test)]
            task: Some(task),
        }
    }
}

pub(super) async fn run_endpoint_driver(
    context: UdpDriverContext,
    initial: UdpDriverStart,
    first_ack: oneshot::Sender<io::Result<()>>,
) -> io::Result<()> {
    let UdpDriverContext {
        endpoint,
        queue_rx,
        reply_socket,
        reply_socket_factory,
        client_addr,
        client_dst,
        alive_set,
        stats,
        outbound_tracker,
    } = context;
    // Sniffing may have consumed later QUIC Initial fragments from the queue.
    // Send that retained prefix before the untouched receiver queue so the
    // server sees the original flight in order without waiting for a PTO.
    let UdpDriverStart { first, followers } = initial;
    let mut initial_result = send_one(&endpoint, &stats, &outbound_tracker, first, true).await;
    if initial_result.is_ok() {
        for follower in followers {
            if let Err(error) =
                send_one(&endpoint, &stats, &outbound_tracker, follower, false).await
            {
                initial_result = Err(error);
                break;
            }
        }
    }
    match initial_result {
        Ok(()) => {
            let _ = first_ack.send(Ok(()));
        }
        Err(error) => {
            if !endpoint.dead.load(Ordering::Acquire) {
                let ipver = if client_dst.is_ipv4() {
                    honk_outbound::alive::IpVersion::V4
                } else {
                    honk_outbound::alive::IpVersion::V6
                };
                alive_set.report_unavailable_traffic(
                    endpoint.node_id,
                    honk_outbound::alive::ProbeDomain::DataUdp,
                    ipver,
                );
            }
            let _ = first_ack.send(Err(io::Error::new(error.kind(), error.to_string())));
            return Err(error);
        }
    }

    let sender = send_followers(
        Arc::clone(&endpoint),
        queue_rx,
        Arc::clone(&stats),
        outbound_tracker.clone(),
    );
    let receiver = receive_loop(
        Arc::clone(&endpoint),
        reply_socket,
        reply_socket_factory,
        client_addr,
        client_dst,
        Arc::clone(&alive_set),
        stats,
        outbound_tracker,
    );
    tokio::pin!(sender);
    tokio::pin!(receiver);
    let result = tokio::select! {
        result = &mut sender => result,
        result = &mut receiver => result,
    };
    if result.is_err() && !endpoint.dead.load(Ordering::Acquire) {
        let ipver = if client_dst.is_ipv4() {
            honk_outbound::alive::IpVersion::V4
        } else {
            honk_outbound::alive::IpVersion::V6
        };
        alive_set.report_unavailable_traffic(
            endpoint.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            ipver,
        );
    }
    result
}

async fn send_followers(
    endpoint: Arc<UdpEndpoint>,
    mut queue_rx: mpsc::Receiver<QueuedDatagram>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    while let Some(packet) = queue_rx.recv().await {
        send_one(&endpoint, &stats, &outbound_tracker, packet, false).await?;
    }
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "UDP endpoint queue closed",
    ))
}

async fn send_one(
    endpoint: &UdpEndpoint,
    stats: &StatsManager,
    outbound_tracker: &OutboundTracker,
    packet: QueuedDatagram,
    first: bool,
) -> io::Result<()> {
    // This is the application-send linearization point. Node death that wins
    // before it prevents any transport call; death after it is ambiguous, so
    // this driver never retries the packet or starts later followers.
    endpoint.begin_send_attempt()?;
    let started = first.then(Instant::now);
    let sent = tokio::time::timeout(TRANSPORT_SEND_TIMEOUT, async {
        if first {
            endpoint
                .proxy_socket
                .send_packet_confirmed(&packet.data)
                .await
        } else {
            endpoint.proxy_socket.send_packet(&packet.data).await
        }
    })
    .await;
    let result = match sent {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "UDP PacketTransport send timed out",
        )),
    };
    if let Some(started) = started {
        stats.record_udp_first_send_latency(started.elapsed());
    }
    match result {
        Ok(()) => {
            endpoint.refresh();
            endpoint.tracker_upload(packet.data.len() as u64);
            outbound_tracker.add_bytes(packet.data.len() as u64, 0);
            Ok(())
        }
        Err(error) => {
            if first {
                stats.record_udp_first_send_failure();
            }
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_loop(
    endpoint: Arc<UdpEndpoint>,
    reply_socket: Arc<UdpSocket>,
    reply_socket_factory: Arc<dyn UdpReplySocketFactory>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    let ipver = if client_dst.is_ipv4() {
        honk_outbound::alive::IpVersion::V4
    } else {
        honk_outbound::alive::IpVersion::V6
    };
    // The normal fixed-target path keeps using the pre-created socket without
    // allocating. Full-cone sources populate this small endpoint-local cache.
    let mut alternate_reply_sockets = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let received = tokio::time::timeout(
            REPLY_IDLE_TIMEOUT,
            endpoint.proxy_socket.recv_packet(&mut buf),
        )
        .await;
        let (n, source) = match received {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "UDP endpoint reply idle timeout",
                ));
            }
        };
        if source != endpoint.relay_addr
            && !endpoint.proxy_socket.allows_full_cone_replies()
            && !endpoint.validate_reply_peer(source)
        {
            debug!(
                "UDP endpoint driver rejecting unexpected reply peer {}",
                source
            );
            continue;
        }
        if source.is_ipv4() != client_addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP reply source {} and client {} use different address families",
                    source, client_addr
                ),
            ));
        }
        let reply_socket = if source == client_dst {
            reply_socket.as_ref()
        } else {
            let index = match alternate_reply_sockets
                .iter()
                .position(|(cached_source, _)| *cached_source == source)
            {
                Some(index) => index,
                None => {
                    if alternate_reply_sockets.len() >= MAX_REPLY_SOCKETS_PER_ENDPOINT - 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "UDP endpoint reply-source socket cache is full",
                        ));
                    }
                    let socket = reply_socket_factory.create(source)?;
                    alternate_reply_sockets.push((source, socket));
                    alternate_reply_sockets.len() - 1
                }
            };
            &alternate_reply_sockets[index].1
        };
        reply_socket.send_to(&buf[..n], client_addr).await?;
        endpoint.mark_reply();
        if let Some(elapsed) = endpoint.take_first_reply_metric() {
            stats.record_udp_first_reply_latency(elapsed);
        }
        endpoint.tracker_download(n as u64);
        outbound_tracker.add_bytes(0, n as u64);
        if endpoint.take_alive_report_slot() {
            alive_set.report_available_traffic(
                endpoint.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                ipver,
            );
        }
    }
}

pub(super) fn monotonic_nanos() -> i64 {
    // Use std Instant as monotonic clock (handles suspend correctly).
    // We only need relative comparisons, so offset from a fixed epoch is fine.
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_nanos() as i64
}

pub(super) fn nanos_from_dur(d: Duration) -> i64 {
    d.as_nanos() as i64
}
