mod reply;
#[cfg(all(test, feature = "rprx"))]
pub(super) use reply::SourceReplyTarget;
use reply::{SourceReplyDisposition, deliver_source_reply};

use super::driver::{REPLY_IDLE_TIMEOUT, TRANSPORT_SEND_TIMEOUT};
use super::*;
#[cfg(feature = "rprx")]
use honk_config::node::VlessUdpPath;
use honk_outbound::PacketTransport;
use honk_outbound::proxy::hysteria2::{Hy2UdpTransport, Hysteria2Handler};
use honk_outbound::proxy::tuic::{TuicHandler, TuicUdpTransport};
#[cfg(feature = "rprx")]
use honk_outbound::proxy::vless::{VLessHandler, VlessXudpTransport};
use honk_outbound::proxy::{
    MultiTargetTransport, PreparedUdpTransport, ProxyRegistry, QuicSendAttempt,
};
use honk_outbound::runtime::{NodeRuntime, OutboundRuntimeRegistry};

const MAX_RETIRED_REPLY_PEERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::control) enum SourcePath {
    #[cfg(feature = "rprx")]
    Vless(VlessUdpPath),
    Hysteria2,
    Tuic,
    /// Protocols whose registry entry has a shared-source slot.
    Shared,
}

pub(in crate::control) enum PreparedSourceTransport {
    #[cfg(feature = "rprx")]
    Vless(PreparedUdpTransport<VlessXudpTransport>),
    Hysteria2(PreparedUdpTransport<Hy2UdpTransport>),
    Tuic(PreparedUdpTransport<TuicUdpTransport>),
    Shared(PreparedUdpTransport<dyn MultiTargetTransport>),
}

impl PreparedSourceTransport {
    async fn commit(self) -> anyhow::Result<SourceTransport> {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(prepared) => prepared.commit().await.map(SourceTransport::Vless),
            Self::Hysteria2(prepared) => prepared.commit().await.map(SourceTransport::Hysteria2),
            Self::Tuic(prepared) => prepared.commit().await.map(SourceTransport::Tuic),
            Self::Shared(prepared) => prepared.commit().await.map(SourceTransport::Shared),
        }
    }
}

enum SourceTransport {
    #[cfg(feature = "rprx")]
    Vless(Arc<VlessXudpTransport>),
    Hysteria2(Arc<Hy2UdpTransport>),
    Tuic(Arc<TuicUdpTransport>),
    Shared(Arc<dyn MultiTargetTransport>),
}

impl SourceTransport {
    fn packet_transport(&self) -> &dyn PacketTransport {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(transport) => transport.as_ref(),
            Self::Hysteria2(transport) => transport.as_ref(),
            Self::Tuic(transport) => transport.as_ref(),
            Self::Shared(transport) => transport.as_ref(),
        }
    }

    fn observe_reuse(&self) {
        use honk_outbound::runtime::flow_observation::{self, FlowEvent, ResolutionLocation};

        let Some(observer) = flow_observation::current() else {
            return;
        };
        let server_addr = match self {
            #[cfg(feature = "rprx")]
            Self::Vless(_) => return,
            Self::Hysteria2(transport) => Some(transport.server_addr()),
            Self::Tuic(transport) => Some(transport.server_addr()),
            Self::Shared(transport) => transport.carrier_addr(),
        };
        observer.publish(FlowEvent::TransportAttached {
            server_addr,
            resolution_location: ResolutionLocation::Reused,
        });
    }

    fn is_vless(&self) -> bool {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(_) => true,
            Self::Hysteria2(_) | Self::Tuic(_) | Self::Shared(_) => false,
        }
    }

    async fn send_to(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Hysteria2(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Tuic(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Shared(transport) => {
                transport
                    .send_to(target, target_domain, data, confirmed, admitted)
                    .await
            }
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct ReplyAdmissionHook {
    pub(super) entered: Notify,
    pub(super) release: Notify,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReplyProjection {
    ActualPeer,
    RewriteTo(SocketAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::control) struct SourceScope {
    runtime: usize,
    client: SocketAddr,
    path: SourcePath,
    reply: ReplyProjection,
}

impl SourceScope {
    pub(super) fn new(
        runtime: &Arc<NodeRuntime>,
        client: SocketAddr,
        path: SourcePath,
        reply_destination: Option<SocketAddr>,
    ) -> Self {
        Self {
            runtime: Arc::as_ptr(runtime) as usize,
            client: normalize_socket_addr(client),
            path,
            reply: reply_destination
                .map(normalize_socket_addr)
                .map(ReplyProjection::RewriteTo)
                .unwrap_or(ReplyProjection::ActualPeer),
        }
    }
}

fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr) => addr
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), addr.port()))
            .unwrap_or(SocketAddr::V6(addr)),
        addr => addr,
    }
}

#[derive(Clone, Copy)]
pub(super) enum SourceRetirement {
    Neutral(ScoreOutcome),
    Failure(ScoreOutcome),
}

struct SourceState {
    retirement: Option<SourceRetirement>,
    attachments: usize,
    bindings: usize,
    active_sender: u64,
    intentional_sender: u64,
    retired_reply_peers: HashSet<SocketAddr>,
    foreign_replies_disabled: bool,
    active_foreign_reply: Option<SocketAddr>,
    /// The last view's endpoint slot, kept until the receiver and transport drop so
    /// retiring sources cannot overlap new endpoints beyond the descriptor partition.
    retained_endpoint_permit: Option<OwnedSemaphorePermit>,
}

impl SourceState {
    fn mark_intentional_sender(&mut self, view: u64) {
        if self.active_sender == view {
            self.intentional_sender = view;
        }
    }
}

pub(super) struct SourceOwner {
    id: u64,
    scope: SourceScope,
    transport: SourceTransport,
    _runtime: Arc<NodeRuntime>,
    state: Mutex<SourceState>,
    ready: AtomicBool,
    retire_notify: Notify,
    sent: AtomicBool,
    receive_started: AtomicBool,
    has_reply: AtomicBool,
    send_gate: tokio::sync::Mutex<()>,
    next_view: AtomicU64,
    receive_notify: Notify,
    next_alive_report_at: AtomicI64,
    pool: std::sync::Weak<UdpEndpointPool>,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    node_id: uuid::Uuid,
    health_family: honk_outbound::alive::IpVersion,
    node_tracker: OutboundTracker,
    stats: Arc<StatsManager>,
    _source_permit: OwnedSemaphorePermit,
    #[cfg(test)]
    send_timeout_nanos: AtomicU64,
    #[cfg(test)]
    pub(super) foreign_reply_hook: Mutex<Option<Arc<ReplyAdmissionHook>>>,
}

impl SourceOwner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u64,
        scope: SourceScope,
        transport: SourceTransport,
        runtime: Arc<NodeRuntime>,
        pool: &Arc<UdpEndpointPool>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        node_id: uuid::Uuid,
        health_family: honk_outbound::alive::IpVersion,
        node_tracker: OutboundTracker,
        stats: Arc<StatsManager>,
        source_permit: OwnedSemaphorePermit,
    ) -> Arc<Self> {
        Arc::new(Self {
            id,
            scope,
            transport,
            _runtime: runtime,
            state: Mutex::new(SourceState {
                retirement: None,
                attachments: 1,
                bindings: 0,
                active_sender: 0,
                intentional_sender: 0,
                retired_reply_peers: HashSet::new(),
                foreign_replies_disabled: false,
                active_foreign_reply: None,
                retained_endpoint_permit: None,
            }),
            ready: AtomicBool::new(true),
            retire_notify: Notify::new(),
            sent: AtomicBool::new(false),
            receive_started: AtomicBool::new(false),
            has_reply: AtomicBool::new(false),
            receive_notify: Notify::new(),
            next_alive_report_at: AtomicI64::new(0),
            pool: Arc::downgrade(pool),
            send_gate: tokio::sync::Mutex::new(()),
            next_view: AtomicU64::new(1),
            alive_set,
            node_id,
            health_family,
            node_tracker,
            stats,
            _source_permit: source_permit,
            #[cfg(test)]
            send_timeout_nanos: AtomicU64::new(0),
            #[cfg(test)]
            foreign_reply_hook: Mutex::new(None),
        })
    }

    fn attach(self: &Arc<Self>) -> Option<SourceAttachment> {
        let mut state = self.state.lock();
        if state.retirement.is_some() {
            return None;
        }
        state.attachments = state
            .attachments
            .checked_add(1)
            .expect("source attachment count overflow");
        Some(SourceAttachment {
            owner: Arc::clone(self),
            committed: false,
        })
    }

    fn commit_attachment(&self, target: SocketAddr) -> bool {
        let target = normalize_socket_addr(target);
        let mut state = self.state.lock();
        if state.retirement.is_some() || state.active_foreign_reply == Some(target) {
            return false;
        }
        debug_assert_ne!(state.attachments, 0);
        state.attachments -= 1;
        state.bindings = state
            .bindings
            .checked_add(1)
            .expect("source binding count overflow");
        state.retired_reply_peers.remove(&target);
        state.retained_endpoint_permit = None;
        true
    }

    fn drop_attachment(&self) {
        let retire = {
            let mut state = self.state.lock();
            debug_assert_ne!(state.attachments, 0);
            state.attachments -= 1;
            if state.retirement.is_none() && state.bindings == 0 && state.attachments == 0 {
                state.retirement = Some(SourceRetirement::Neutral(ScoreOutcome::Cancelled));
                true
            } else {
                false
            }
        };
        if retire {
            self.signal_retiring();
        }
    }

    fn release_binding(&self, endpoint_permit: Option<OwnedSemaphorePermit>) {
        let retire = {
            let mut state = self.state.lock();
            debug_assert_ne!(state.bindings, 0);
            state.bindings -= 1;
            let retire =
                state.retirement.is_none() && state.bindings == 0 && state.attachments == 0;
            if retire {
                state.retirement = Some(SourceRetirement::Neutral(ScoreOutcome::Cancelled));
            }
            // Covers the source's descriptors while no view is bound, including a
            // pending attachment that may still be cancelled: the next bound view
            // brings its own permit.
            if state.bindings == 0 {
                state.retained_endpoint_permit = endpoint_permit;
            }
            retire
        };
        if retire {
            self.signal_retiring();
        }
    }

    fn signal_retiring(&self) {
        self.ready.store(false, Ordering::Release);
        self.retire_notify.notify_waiters();
    }

    fn start_retiring(&self, retirement: SourceRetirement) -> bool {
        let changed = {
            let mut state = self.state.lock();
            if state.retirement.is_some() {
                false
            } else {
                state.retirement = Some(retirement);
                true
            }
        };
        if changed {
            self.signal_retiring();
        }
        changed
    }

    fn start_retiring_without_reply(&self) -> bool {
        let changed = {
            let mut state = self.state.lock();
            if state.retirement.is_some()
                || !self.sent.load(Ordering::Acquire)
                || self.has_reply.load(Ordering::Acquire)
            {
                false
            } else {
                state.retirement = Some(SourceRetirement::Failure(ScoreOutcome::Timeout));
                true
            }
        };
        if changed {
            self.signal_retiring();
        }
        changed
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn begin_receive(&self) {
        if !self.receive_started.swap(true, Ordering::AcqRel) {
            self.receive_notify.notify_waiters();
        }
    }

    fn note_sent(&self) {
        self.sent.store(true, Ordering::Release);
    }

    pub(super) fn fail(&self, outcome: ScoreOutcome) {
        if let Some(pool) = self.pool.upgrade() {
            pool.fail_source(self, outcome);
        }
    }
    #[cfg(test)]
    pub(super) fn set_send_timeout_for_test(&self, timeout: Duration) {
        self.send_timeout_nanos.store(
            u64::try_from(timeout.as_nanos()).expect("source test timeout fits u64 nanos"),
            Ordering::Release,
        );
    }

    #[cfg(test)]
    pub(super) async fn hold_send_gate_for_test(&self) -> impl Drop + '_ {
        self.send_gate.lock().await
    }

    pub(super) fn handle_transport_error(&self, error: &io::Error) -> bool {
        #[cfg(feature = "rprx")]
        if self.transport.is_vless() {
            {
                let mut state = self.state.lock();
                if !honk_outbound::proxy::vless::is_vless_source_post_admission_cancel(error) {
                    state.intentional_sender = 0;
                    return false;
                }
                // Sender and receiver can observe the same terminal before retirement linearizes.
                if state.intentional_sender == 0 {
                    return false;
                }
            }
            if let Some(pool) = self.pool.upgrade() {
                pool.retire_interrupted_source(self);
            }
            return true;
        }
        #[cfg(not(feature = "rprx"))]
        let _ = error;
        false
    }
    fn note_reply(&self) {
        let state = self.state.lock();
        if state.retirement.is_none() {
            self.has_reply.store(true, Ordering::Release);
        }
    }

    fn report_available(&self) {
        let state = self.state.lock();
        if state.retirement.is_some() {
            return;
        }
        let now = monotonic_nanos();
        self.has_reply.store(true, Ordering::Release);
        if now < self.next_alive_report_at.load(Ordering::Relaxed) {
            return;
        }
        self.next_alive_report_at.store(
            now + nanos_from_dur(TRAFFIC_ALIVE_REPORT_INTERVAL),
            Ordering::Relaxed,
        );
        self.alive_set.report_available_traffic(
            self.node_id,
            honk_outbound::alive::ProbeDomain::DataUdp,
            self.health_family,
        );
    }

    fn flow_idle_expired(&self) {
        if let Some(pool) = self.pool.upgrade()
            && self.start_retiring_without_reply()
        {
            pool.finish_source_failure(self, ScoreOutcome::Timeout);
        }
    }

    fn idle_expired(&self) {
        if let Some(pool) = self.pool.upgrade() {
            if !self.sent.load(Ordering::Acquire) {
                pool.retire_source_neutral(self, ScoreOutcome::Cancelled);
            } else if self.has_reply.load(Ordering::Acquire) {
                pool.retire_replied_source(self);
            } else {
                pool.fail_source(self, ScoreOutcome::Timeout);
            }
        }
    }
}

pub(in crate::control) struct SourceAttachment {
    owner: Arc<SourceOwner>,
    committed: bool,
}

impl SourceAttachment {
    fn commit(&mut self, target: SocketAddr) -> bool {
        if self.committed || !self.owner.commit_attachment(target) {
            return false;
        }
        self.committed = true;
        true
    }

    #[cfg(test)]
    pub(super) fn owner(&self) -> Arc<SourceOwner> {
        Arc::clone(&self.owner)
    }
}

impl Drop for SourceAttachment {
    fn drop(&mut self) {
        if !self.committed {
            self.owner.drop_attachment();
        }
    }
}

pub(in crate::control) enum SourcePreparation {
    Reused(SourceAttachment),
    Fresh {
        scope: SourceScope,
        prepared: PreparedSourceTransport,
        source_permit: OwnedSemaphorePermit,
        runtime: Arc<NodeRuntime>,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        node_id: uuid::Uuid,
        node_name: String,
        health_family: honk_outbound::alive::IpVersion,
    },
}

impl SourcePreparation {
    #[cfg(all(test, feature = "rprx"))]
    pub(super) fn attached_owner(&self) -> Option<Arc<SourceOwner>> {
        match self {
            Self::Reused(attachment) => Some(attachment.owner()),
            Self::Fresh { .. } => None,
        }
    }

    pub(in crate::control) async fn commit(
        self,
        pool: &Arc<UdpEndpointPool>,
    ) -> anyhow::Result<SourceAttachment> {
        match self {
            Self::Reused(attachment) => {
                if attachment.owner.is_ready() {
                    attachment.owner.transport.observe_reuse();
                    Ok(attachment)
                } else {
                    Err(honk_outbound::proxy::PacketRejection::Cancelled.into())
                }
            }
            Self::Fresh {
                scope,
                prepared,
                source_permit,
                runtime,
                alive_set,
                stats,
                node_id,
                node_name,
                health_family,
            } => {
                let mut prepared = Some(prepared);
                let mut transport = None;
                loop {
                    if pool.terminal.load(Ordering::Acquire) {
                        return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                    }
                    let changed = pool.source_changed.notified();
                    if let Some(owner) = pool
                        .sources
                        .get(&scope)
                        .map(|entry| Arc::clone(entry.value()))
                    {
                        if let Some(attachment) = owner.attach() {
                            owner.transport.observe_reuse();
                            return Ok(attachment);
                        }
                        changed.await;
                        continue;
                    }

                    if let Some(prepared) = prepared.take() {
                        transport = Some(prepared.commit().await?);
                    }

                    {
                        let mut tasks = pool.source_tasks.lock();
                        while let Some(result) = tasks.tasks.try_join_next() {
                            if let Err(error) = result {
                                debug!("UDP source receiver join failed: {}", error);
                            }
                        }
                        if tasks.closed || pool.terminal.load(Ordering::Acquire) {
                            return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
                        }
                        match pool.sources.entry(scope.clone()) {
                            dashmap::mapref::entry::Entry::Occupied(entry) => {
                                let owner = Arc::clone(entry.get());
                                drop(entry);
                                drop(tasks);
                                if let Some(attachment) = owner.attach() {
                                    owner.transport.observe_reuse();
                                    return Ok(attachment);
                                }
                            }
                            dashmap::mapref::entry::Entry::Vacant(entry) => {
                                let owner = SourceOwner::new(
                                    pool.next_source_owner.fetch_add(1, Ordering::Relaxed),
                                    scope.clone(),
                                    transport.expect("prepared source transport"),
                                    runtime,
                                    pool,
                                    alive_set,
                                    node_id,
                                    health_family,
                                    stats.outbound_tracker(
                                        &node_name,
                                        crate::stats::OutboundKind::Node,
                                    ),
                                    stats,
                                    source_permit,
                                );
                                entry.insert(Arc::clone(&owner));
                                drop(tasks.tasks.spawn(run_source_receiver(
                                    Arc::clone(pool),
                                    Arc::clone(&owner),
                                )));
                                drop(tasks);
                                return Ok(SourceAttachment {
                                    owner,
                                    committed: false,
                                });
                            }
                        }
                    }
                    changed.await;
                }
            }
        }
    }
}

pub(super) struct SourceEndpoint {
    owner: Arc<SourceOwner>,
    view: u64,
    retired: AtomicBool,
    target: SocketAddr,
    target_domain: Option<Box<str>>,
    reply_socket: Arc<ReplySocket>,
    flow_tracker: OutboundTracker,
    binding: Mutex<SourceEndpointBinding>,
}

struct SourceEndpointBinding {
    attachment: Option<SourceAttachment>,
    bound: bool,
    retirement: Option<SourceRetirement>,
    endpoint_permit: Option<OwnedSemaphorePermit>,
}

impl SourceEndpoint {
    pub(super) fn new(
        attachment: SourceAttachment,
        target: SocketAddr,
        target_domain: Option<&str>,
        reply_socket: Arc<ReplySocket>,
        flow_tracker: OutboundTracker,
    ) -> Self {
        let view = attachment.owner.next_view.fetch_add(1, Ordering::Relaxed);
        Self {
            owner: Arc::clone(&attachment.owner),
            view,
            retired: AtomicBool::new(false),
            target,
            target_domain: target_domain.map(Box::from),
            reply_socket,
            flow_tracker,
            binding: Mutex::new(SourceEndpointBinding {
                attachment: Some(attachment),
                bound: false,
                retirement: None,
                endpoint_permit: None,
            }),
        }
    }

    #[cfg(all(test, feature = "native-api"))]
    pub(super) fn owner_id(&self) -> u64 {
        self.owner.id
    }

    pub(super) fn score_retirement(&self) -> Option<SourceRetirement> {
        let binding = self.binding.lock();
        if binding.bound {
            self.owner.state.lock().retirement
        } else {
            binding.retirement
        }
    }

    #[cfg(all(test, feature = "rprx"))]
    pub(super) fn hold_binding_for_test(&self) -> impl Drop + '_ {
        self.binding.lock()
    }

    #[cfg(all(test, feature = "rprx"))]
    pub(super) fn mark_send_active_for_test(&self) {
        self.owner.state.lock().active_sender = self.view;
    }

    pub(super) fn commit_binding(&self, endpoint_permit: OwnedSemaphorePermit) -> bool {
        let mut binding = self.binding.lock();
        let Some(attachment) = binding.attachment.as_mut() else {
            return false;
        };
        if !attachment.commit(self.target) {
            return false;
        }
        binding.attachment.take();
        binding.bound = true;
        binding.endpoint_permit = Some(endpoint_permit);
        true
    }

    pub(super) fn retire(&self, dead: &AtomicBool) {
        let mut binding = self.binding.lock();
        binding.attachment.take();
        {
            let mut state = self.owner.state.lock();
            if matches!(self.owner.scope.reply, ReplyProjection::ActualPeer) {
                let peer = normalize_socket_addr(self.target);
                if state.retired_reply_peers.len() < MAX_RETIRED_REPLY_PEERS {
                    state.retired_reply_peers.insert(peer);
                } else if !state.retired_reply_peers.contains(&peer) {
                    // ponytail: after 64 retired peers, disable only unbound foreign replies for this source lifetime.
                    state.foreign_replies_disabled = true;
                }
            }
            if binding.bound {
                state.mark_intentional_sender(self.view);
                binding.retirement = state.retirement;
            }
            // Publish intent before a sender can observe retirement and drop its send.
            self.retired.store(true, Ordering::Release);
            dead.store(true, Ordering::Release);
        }
        if binding.bound {
            binding.bound = false;
            self.owner.release_binding(binding.endpoint_permit.take());
        }
    }

    pub(super) fn reply_admitted(&self, owner_id: u64) -> bool {
        let state = self.owner.state.lock();
        self.owner.id == owner_id
            && state.retirement.is_none()
            && !self.retired.load(Ordering::Acquire)
    }

    pub(super) fn reply_socket(&self) -> &Arc<ReplySocket> {
        &self.reply_socket
    }

    pub(super) fn record_reply(&self, len: u64) {
        self.flow_tracker.add_bytes(0, len);
    }

    pub(super) async fn send<'a>(
        &'a self,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
        record_start: bool,
        attempt: &mut Option<QuicSendAttempt<'a>>,
    ) -> io::Result<Option<Instant>> {
        let _send = self.owner.send_gate.lock().await;
        let reusable = match &self.owner.transport {
            #[cfg(feature = "rprx")]
            SourceTransport::Vless(transport) => transport.source_send_usable().await,
            SourceTransport::Hysteria2(_)
            | SourceTransport::Tuic(_)
            | SourceTransport::Shared(_) => true,
        };
        let mut active = {
            let mut state = self.owner.state.lock();
            if self.retired.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "UDP flow retired before source send",
                ));
            }
            if state.retirement.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "UDP source retired before send",
                ));
            }
            if self.owner.transport.is_vless()
                && !self.owner.sent.load(Ordering::Acquire)
                && data.is_empty()
            {
                return Err(honk_outbound::proxy::PacketRejection::InvalidSize.into());
            }
            if reusable {
                state.intentional_sender = 0;
            }
            state.active_sender = self.view;
            ActiveSourceSend {
                owner: &self.owner,
                view: self.view,
                clear_intent: false,
            }
        };
        if !self.owner.transport.is_vless() {
            *attempt = Some(QuicSendAttempt::new(self.packet_transport()));
        }
        let started_at = record_start.then(Instant::now);
        self.owner.begin_receive();
        let result = self
            .owner
            .transport
            .send_to(
                self.target,
                self.target_domain.as_deref(),
                data,
                confirmed,
                admitted,
            )
            .await;
        if result.is_ok() {
            active.clear_intent = true;
            self.owner.note_sent();
        } else if let Err(error) = &result {
            active.clear_intent = !self.owner.handle_transport_error(error);
        }
        result.map(|()| started_at)
    }

    pub(super) fn send_timeout(&self) -> Duration {
        #[cfg(test)]
        {
            let timeout = self.owner.send_timeout_nanos.load(Ordering::Acquire);
            if timeout != 0 {
                return Duration::from_nanos(timeout);
            }
        }
        self.packet_transport().send_timeout()
    }

    pub(super) fn packet_transport(&self) -> &dyn PacketTransport {
        self.owner.transport.packet_transport()
    }

    pub(super) fn fail(&self, outcome: ScoreOutcome) {
        self.owner.fail(outcome);
    }

    pub(super) fn flow_idle_expired(&self) {
        self.owner.flow_idle_expired();
    }
}

struct ActiveSourceSend<'a> {
    owner: &'a SourceOwner,
    view: u64,
    clear_intent: bool,
}

impl Drop for ActiveSourceSend<'_> {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock();
        if state.active_sender == self.view {
            state.active_sender = 0;
        }
        if self.clear_intent && state.intentional_sender == self.view {
            state.intentional_sender = 0;
        }
    }
}

impl Drop for SourceEndpoint {
    fn drop(&mut self) {
        let binding = self.binding.get_mut();
        binding.attachment.take();
        if binding.bound {
            self.owner.state.lock().mark_intentional_sender(self.view);
            binding.bound = false;
            self.owner.release_binding(binding.endpoint_permit.take());
        }
    }
}

struct SourceReplyLease {
    pool: Arc<UdpEndpointPool>,
    owner: Arc<SourceOwner>,
}

impl Drop for SourceReplyLease {
    fn drop(&mut self) {
        self.owner
            .start_retiring(SourceRetirement::Neutral(ScoreOutcome::Cancelled));
        match self.pool.sources.entry(self.owner.scope.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) if entry.get().id == self.owner.id => {
                entry.remove();
            }
            _ => {}
        }
        self.pool.source_changed.notify_waiters();
    }
}

async fn run_source_receiver(pool: Arc<UdpEndpointPool>, owner: Arc<SourceOwner>) {
    let _reply_lease = SourceReplyLease {
        pool: Arc::clone(&pool),
        owner: Arc::clone(&owner),
    };
    let mut buf = [0u8; 65536];
    let mut alternate_reply_sockets = Vec::new();

    loop {
        let retired = owner.retire_notify.notified();
        let receive_started = owner.receive_notify.notified();
        if !owner.is_ready() {
            return;
        }
        if owner.receive_started.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            biased;
            _ = retired => return,
            _ = receive_started => {}
        }
    }

    let reply_idle_timeout = tokio::time::sleep(REPLY_IDLE_TIMEOUT);
    tokio::pin!(reply_idle_timeout);
    loop {
        let retired = owner.retire_notify.notified();
        if !owner.is_ready() {
            return;
        }
        tokio::select! {
            biased;
            _ = retired => return,
            packet = owner.transport.packet_transport().recv_packet(&mut buf) => {
                let (len, peer) = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        if !owner.handle_transport_error(&error) {
                            owner.fail(ScoreOutcome::from_io_error(&error));
                        }
                        return;
                    }
                };
                match deliver_source_reply(
                    &pool,
                    &owner,
                    peer,
                    &buf[..len],
                    &mut alternate_reply_sockets,
                ).await {
                    SourceReplyDisposition::Delivered if owner.is_ready() => {
                        owner.report_available();
                        reply_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
                    }
                    SourceReplyDisposition::Observed if owner.is_ready() => {
                        owner.note_reply();
                        reply_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
                    }
                    SourceReplyDisposition::Delivered | SourceReplyDisposition::Observed => {}
                    SourceReplyDisposition::Drop => {}
                }
            }
            _ = reply_idle_timeout.as_mut() => {
                owner.idle_expired();
                return;
            }
        }
    }
}

impl UdpEndpointPool {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::control) async fn prepare_source(
        self: &Arc<Self>,
        registry: &ProxyRegistry,
        generation: Arc<OutboundRuntimeRegistry>,
        runtime: Arc<NodeRuntime>,
        client: SocketAddr,
        path: SourcePath,
        reply_destination: Option<SocketAddr>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
        stats: Arc<StatsManager>,
        health_family: honk_outbound::alive::IpVersion,
        speculative: bool,
    ) -> anyhow::Result<SourcePreparation> {
        let scope = SourceScope::new(&runtime, client, path, reply_destination);
        loop {
            if generation.is_shutdown() || self.terminal.load(Ordering::Acquire) {
                return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
            }
            let changed = self.source_changed.notified();
            if let Some(owner) = self
                .sources
                .get(&scope)
                .map(|entry| Arc::clone(entry.value()))
            {
                if let Some(attachment) = owner.attach() {
                    return Ok(SourcePreparation::Reused(attachment));
                }
                changed.await;
                continue;
            }

            let source_permit =
                self.source_slots.clone().try_acquire_owned().map_err(|_| {
                    anyhow::Error::new(honk_outbound::proxy::PacketRejection::Capacity)
                })?;
            let prepared = {
                let operation = std::pin::pin!(async {
                    match path {
                        #[cfg(feature = "rprx")]
                        SourcePath::Vless(path) => {
                            let global_id =
                                runtime.vless_source_id(scope.client, path, reply_destination)?;
                            VLessHandler::prepare_source_udp(
                                Arc::clone(&runtime),
                                target,
                                target_domain,
                                connect_timeout,
                                global_id,
                            )
                            .await
                            .map(PreparedSourceTransport::Vless)
                        }
                        SourcePath::Hysteria2 => Hysteria2Handler::new()
                            .prepare_udp_source(
                                Arc::clone(&runtime),
                                target,
                                target_domain,
                                connect_timeout,
                                speculative,
                            )
                            .await
                            .map(PreparedSourceTransport::Hysteria2),
                        SourcePath::Tuic => TuicHandler::new()
                            .prepare_udp_source(
                                Arc::clone(&runtime),
                                target,
                                target_domain,
                                connect_timeout,
                                speculative,
                            )
                            .await
                            .map(PreparedSourceTransport::Tuic),
                        SourcePath::Shared => registry
                            .prepare_shared_source(
                                Arc::clone(&runtime),
                                target,
                                target_domain,
                                connect_timeout,
                                speculative,
                            )
                            .await
                            .map(PreparedSourceTransport::Shared),
                    }
                });
                generation
                    .scope_dials(runtime.scope_tasks(runtime.transport_quality().scope(operation)))
                    .await?
            };
            if generation.is_shutdown() {
                return Err(honk_outbound::proxy::PacketRejection::Cancelled.into());
            }
            return Ok(SourcePreparation::Fresh {
                scope,
                prepared,
                source_permit,
                runtime: Arc::clone(&runtime),
                alive_set,
                stats,
                node_id: runtime.node.id,
                node_name: runtime.node.name.clone(),
                health_family,
            });
        }
    }

    fn retire_replied_source(&self, owner: &SourceOwner) {
        self.retire_source_neutral(owner, ScoreOutcome::Timeout);
    }

    #[cfg(feature = "rprx")]
    fn retire_interrupted_source(&self, owner: &SourceOwner) {
        self.retire_source_neutral(owner, ScoreOutcome::Cancelled);
    }

    fn source_settlement_endpoints(
        &self,
        owner: &SourceOwner,
    ) -> Vec<(EndpointKey, u32, u64, Arc<UdpEndpoint>)> {
        self.endpoints
            .iter()
            .filter_map(|entry| match entry.value() {
                EndpointEntry::Ready(ready)
                    if matches!(
                        &ready.endpoint.transport,
                        EndpointTransport::Source(source)
                            if source.owner.id == owner.id && source.score_retirement().is_some()
                    ) =>
                {
                    Some((
                        *entry.key(),
                        ready.decision_token,
                        ready.generation,
                        Arc::clone(&ready.endpoint),
                    ))
                }
                _ => None,
            })
            .collect()
    }

    fn retire_source_neutral(&self, owner: &SourceOwner, no_reply: ScoreOutcome) {
        if !owner.start_retiring(SourceRetirement::Neutral(no_reply)) {
            return;
        }
        let stale = self.source_settlement_endpoints(owner);
        for (key, token, generation, endpoint) in stale {
            #[cfg(feature = "native-api")]
            endpoint.finish_native_source(SourceRetirement::Neutral(no_reply));
            endpoint.finish_score(no_reply);
            self.retire_if_same(key, token, generation);
        }
    }

    fn fail_source(&self, owner: &SourceOwner, outcome: ScoreOutcome) {
        let outcome = if outcome == ScoreOutcome::NodeFailure {
            ScoreOutcome::shared_node_failure()
        } else {
            outcome
        };
        if owner.start_retiring(SourceRetirement::Failure(outcome)) {
            self.finish_source_failure(owner, outcome);
        }
    }

    fn finish_source_failure(&self, owner: &SourceOwner, outcome: ScoreOutcome) {
        let terminal = self.terminal.load(Ordering::Acquire);
        let outcome = if terminal {
            ScoreOutcome::Shutdown
        } else {
            outcome
        };
        let stale = self.source_settlement_endpoints(owner);
        for (_, _, _, endpoint) in &stale {
            #[cfg(feature = "native-api")]
            endpoint.finish_native_source(SourceRetirement::Failure(outcome));
            endpoint.finish_score(outcome);
        }
        for (key, token, generation, _) in stale {
            self.retire_if_same(key, token, generation);
        }
        if !terminal {
            owner.alive_set.report_unavailable_traffic(
                owner.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                owner.health_family,
            );
        }
    }
}
