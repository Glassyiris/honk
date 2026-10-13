use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

use super::*;
use crate::proxy::uot::AddrFraming;
use crate::proxy::{MultiTargetTransport, PacketTransport};

#[cfg(test)]
use super::{
    CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_SYNACK, INBOUND_PAYLOAD_BUDGET,
    InboundPayloadBudget, PaddingScheme, PaddingState, WRITER_CONTROL_RESERVED, WRITER_IO_TIMEOUT,
    WRITER_QUEUE_CAP, read_frame, write_frame,
};
#[cfg(test)]
use crate::session::ManagedSession as _;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use tokio::io::AsyncReadExt;

/// Framed non-connect UoT v2 transport over a multiplexed AnyTLS stream: the
/// request names the first destination, then every datagram in both directions
/// is a v1 address packet, so one stream carries all destinations of a client
/// source and replies keep their real source. The request and first datagram
/// share one PSH; later datagrams go straight to the session writer. Inbound
/// bytes arrive directly from the demux through a bounded queue; saturation
/// retires the sid rather than corrupting the UoT byte stream.
pub(crate) struct AnyTlsUotTransport {
    pub(super) session: Arc<AnyTlsSession>,
    pub(super) sid: u32,
    pub(super) receive: tokio::sync::Mutex<UotReceiveState>,
    /// UoT v2 request, atomically consumed when its first datagram is queued.
    pub(super) setup: tokio::sync::Mutex<Option<bytes::Bytes>>,
    /// The open-time destination: the default for ordinary sends and the only
    /// domain a reply source may project back to.
    pub(super) target: SocketAddr,
    pub(super) target_domain: Option<String>,
    /// Stream-slot capacity, held for the transport's life.
    pub(super) _permit: crate::session::SessionPermit<AnyTlsSession>,
}

pub(super) struct UotReceiveState {
    rx: mpsc::Receiver<StreamEvent>,
    buffered: bytes::BytesMut,
    credit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl UotReceiveState {
    pub(super) fn new(rx: mpsc::Receiver<StreamEvent>) -> Self {
        Self {
            rx,
            buffered: bytes::BytesMut::new(),
            credit: None,
        }
    }

    /// Return the pool credit of `bytes` consumed from `buffered`.
    fn release(&mut self, bytes: usize) {
        let credit = self
            .credit
            .as_mut()
            .expect("buffered UoT bytes own payload credit");
        drop(
            credit
                .split(bytes)
                .expect("UoT credit covers consumed frame"),
        );
        if credit.num_permits() == 0 {
            self.credit = None;
        }
    }
}

// The largest valid buffered state is one byte short of a maximum v1
// domain-form datagram followed by one full AnyTLS PSH.
const UOT_MAX_V1_HEADER_BYTES: usize = 1 + 1 + u8::MAX as usize + 2 + 2;
const UOT_MAX_BUFFERED_BYTES: usize =
    UOT_MAX_V1_HEADER_BYTES + u16::MAX as usize + u16::MAX as usize - 1;
// anytls-go 0.0.13 relays through sing v0.5.1's 16 KiB UDP buffer; a larger
// UoT packet makes the reference server close the logical stream.
const UOT_MAX_PACKET_SIZE: usize = 16 * 1024;

/// Per-stream UoT demux queue depth. At ~1.2KB per datagram, 4096 entries
/// absorb a ~40ms burst at 100k pps while the reply handler drains. A full
/// queue retires only this sid; arbitrary chunks cannot be dropped safely.
pub(super) const UOT_DRAIN_QUEUE_CAP: usize = 4096;

impl Drop for AnyTlsUotTransport {
    fn drop(&mut self) {
        self.session.end_uot_stream(self.sid, true);
    }
}

impl std::fmt::Debug for AnyTlsUotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsUotTransport")
            .field("sid", &self.sid)
            .field("target", &self.target)
            .finish()
    }
}

impl AnyTlsUotTransport {
    /// The one send path of `send_packet`, `send_packet_confirmed` and
    /// `send_to`. `admitted` is set once the frame is owned by the session
    /// writer; waiting before that (cancellable, setup kept) never sets it,
    /// and a confirmed wait after it is not replayed on cancellation.
    async fn send_inner(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        crate::proxy::uot::validate_packet_len(data, UOT_MAX_PACKET_SIZE)?;
        self.session.ensure_stream_registered(self.sid)?;
        let mut setup = self.setup.lock().await;
        let Some(request) = setup.as_ref() else {
            drop(setup);
            let packet =
                AddrFraming::UOT_V1.encode(&[], target, domain, data, UOT_MAX_PACKET_SIZE)?;
            let permit = self.session.acquire_data_permit(packet.len()).await?;
            let completed = self.enqueue(packet, permit, confirmed)?;
            admit(admitted);
            return self.flushed(completed).await;
        };

        let packet =
            AddrFraming::UOT_V1.encode(request, target, domain, data, UOT_MAX_PACKET_SIZE)?;
        let permit = self.session.acquire_data_permit(packet.len()).await?;
        let completed = self.enqueue(packet, permit, confirmed)?;
        setup.take();
        drop(setup);
        admit(admitted);
        self.flushed(completed).await
    }

    fn enqueue(
        &self,
        packet: bytes::Bytes,
        permit: DataPermit,
        confirmed: bool,
    ) -> std::io::Result<Option<tokio::sync::oneshot::Receiver<bool>>> {
        if confirmed {
            self.session
                .enqueue_confirmed_data_with_permit(self.sid, packet, permit)
                .map(Some)
        } else {
            self.session
                .enqueue_data_with_permit(self.sid, packet, permit)
                .map(|()| None)
        }
    }

    async fn flushed(
        &self,
        completed: Option<tokio::sync::oneshot::Receiver<bool>>,
    ) -> std::io::Result<()> {
        match completed {
            Some(completed) => self.session.wait_for_confirmed_data(completed).await,
            None => Ok(()),
        }
    }
}

fn admit(admitted: Option<&AtomicBool>) {
    if let Some(admitted) = admitted {
        admitted.store(true, Ordering::Release);
    }
}

#[async_trait]
impl PacketTransport for AnyTlsUotTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    /// Every packet carries its real source, so a peer other than the dialed
    /// target (e.g. the address a server resolved a name to) is authoritative.
    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(
            self.target,
            self.target_domain.as_deref(),
            data,
            false,
            None,
        )
        .await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(self.target, self.target_domain.as_deref(), data, true, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut receive = self.receive.lock().await;
        loop {
            if let Some(frame) = AddrFraming::UOT_V1.take_frame(
                &mut receive.buffered,
                buf,
                self.target,
                self.target_domain.as_deref(),
            )? {
                receive.release(frame.wire_len);
                if let Some(packet) = frame.packet {
                    return Ok(packet);
                }
                continue;
            }

            let event = receive.rx.recv().await.ok_or_else(|| {
                self.session
                    .session_error(std::io::ErrorKind::UnexpectedEof, "UoT stream closed")
            })?;
            match event {
                StreamEvent::Data(data) => {
                    if receive.buffered.len().saturating_add(data.len()) > UOT_MAX_BUFFERED_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "UoT stream frame exceeds buffer limit",
                        ));
                    }
                    let (data, credit) = data.into_parts();
                    receive.buffered.extend_from_slice(&data);
                    if let Some(held) = receive.credit.as_mut() {
                        held.merge(credit);
                    } else {
                        receive.credit = Some(credit);
                    }
                }
                StreamEvent::Fin => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "UoT stream closed by server",
                    ));
                }
                StreamEvent::Error(error) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        error,
                    ));
                }
            }
        }
    }
}

#[async_trait]
impl MultiTargetTransport for AnyTlsUotTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        self.send_inner(target, domain, data, confirmed, admitted)
            .await?;
        // The stream's own observation belongs to whoever opened it; each
        // flow sharing the stream reports its own first flush in its context.
        if confirmed && let Some(observer) = crate::runtime::flow_observation::current() {
            observer.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
        }
        Ok(())
    }
}

#[cfg(test)]
mod uot_transport_tests;

impl AnyTlsHandler {
    /// Prepare an AnyTLS UoT transport on an explicitly captured pool without
    /// publishing a detached session or starting the janitor. The injected
    /// dial seam keeps cancellation observable in tests.
    pub(super) async fn dial_udp_transport_speculative_for_pool_with<F, Fut>(
        node: &Node,
        pool: Arc<AnyTlsPool>,
        target: SocketAddr,
        target_domain: Option<&str>,
        runtime: Option<Arc<crate::runtime::NodeRuntime>>,
        dial: F,
    ) -> anyhow::Result<PreparedUdpTransport<AnyTlsUotTransport>>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = anyhow::Result<Arc<AnyTlsSession>>> + Send,
    {
        if !crate::descriptor::network_allows_udp(node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }
        pool.sessions.bind_current_dial_admission_if_unbound();

        let (session, permit, detached) = match pool.checkout_speculative().await? {
            SpeculativeCheckout::Shared { session, permit } => (session, permit, None),
            SpeculativeCheckout::Detached(mut reservation) => {
                let session = tokio::select! {
                    result = dial() => result?,
                    _ = reservation.cancelled() => {
                        anyhow::bail!("AnyTLS speculative dial cancelled by pool shutdown")
                    }
                };
                let permit = reservation.attach(&session)?;
                (session, permit, Some(reservation))
            }
        };

        let transport = session
            .open_packet(permit, target, target_domain)
            .await
            .map_err(|error| match error {
                crate::session::OpenError::Session(error)
                | crate::session::OpenError::Draining(error)
                | crate::session::OpenError::Refused(error) => error,
            })?;

        let commit_node = node.clone();
        Ok(PreparedUdpTransport::new(async move {
            if let Some(reservation) = detached {
                reservation.commit()?;
            }
            if runtime.is_some() {
                Self::ensure_janitor(&commit_node, &pool, runtime);
            }
            Ok(transport)
        }))
    }

    async fn dial_udp_transport_typed(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<AnyTlsUotTransport>> {
        let pool = runtime.anytls_pool()?;
        let node = Arc::clone(&runtime.node);
        if !crate::descriptor::network_allows_udp(&node) {
            anyhow::bail!("node '{}' does not allow UDP", node.name);
        }

        if !runtime.is_ephemeral() {
            Self::ensure_janitor(&node, &pool, Some(Arc::clone(&runtime)));
        }
        let dial_node = Arc::clone(&node);
        let dial_runtime = Arc::clone(&runtime);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        pool.open_with(
            move || {
                let node = Arc::clone(&dial_node);
                let runtime = Arc::clone(&dial_runtime);
                let addr = dial_addr.clone();
                let padding_state = Arc::clone(&padding_state);
                let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
                async move {
                    let tls_connector = runtime.anytls_tls_connector()?;
                    runtime
                        .transport_quality()
                        .scope(dial_session(
                            &node,
                            &addr,
                            connect_timeout,
                            Some(tls_connector),
                            padding_state,
                            inbound_payload_budget,
                        ))
                        .await
                }
            },
            move |session, permit| {
                let domain = target_domain.map(str::to_string);
                async move { session.open_packet(permit, target, domain.as_deref()).await }
            },
        )
        .await
    }

    async fn dial_udp_transport_speculative_typed(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport<AnyTlsUotTransport>> {
        let pool = runtime.anytls_pool()?;
        let node = Arc::clone(&runtime.node);
        let dial_node = Arc::clone(&node);
        let dial_runtime = Arc::clone(&runtime);
        let dial_addr = format!("{}:{}", node.host(), node.port);
        let padding_state = pool.padding_state();
        let inbound_payload_budget = pool.inbound_payload_budget();
        runtime
            .scope_tasks(Self::dial_udp_transport_speculative_for_pool_with(
                node.as_ref(),
                pool,
                target,
                target_domain,
                Some(Arc::clone(&runtime)),
                move || async move {
                    let tls_connector = dial_runtime.anytls_tls_connector()?;
                    let padding_state = Arc::clone(&padding_state);
                    let inbound_payload_budget = Arc::clone(&inbound_payload_budget);
                    dial_runtime
                        .transport_quality()
                        .scope(dial_session(
                            dial_node.as_ref(),
                            &dial_addr,
                            connect_timeout,
                            Some(tls_connector),
                            padding_state,
                            inbound_payload_budget,
                        ))
                        .await
                },
            ))
            .await
    }

    /// One UoT stream for every destination of a client source, on the
    /// node's own pool: ordinary checkout, or the provisional reservation
    /// that publishes only at commit. A dropped preparation unregisters its
    /// stream.
    pub(crate) async fn prepare_udp_source(
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        // The open-time flow observation would credit every later flow's
        // first flush to the opener; confirmed sends report in their own
        // context instead.
        let source = |transport: Arc<AnyTlsUotTransport>| -> Arc<dyn MultiTargetTransport> {
            transport.session.end_observation(transport.sid);
            transport
        };
        if speculative {
            let prepared = Self::dial_udp_transport_speculative_typed(
                runtime,
                target,
                target_domain,
                connect_timeout,
            )
            .await?;
            return Ok(erase_prepared(prepared, source));
        }
        let transport =
            Self::dial_udp_transport_typed(runtime, target, target_domain, connect_timeout).await?;
        Ok(PreparedUdpTransport::ready(source(transport)))
    }
}

/// Re-type a prepared transport for its consumer; promotion still runs in
/// the original `commit`.
fn erase_prepared<T: ?Sized + Send + Sync + 'static>(
    prepared: PreparedUdpTransport<AnyTlsUotTransport>,
    erase: fn(Arc<AnyTlsUotTransport>) -> Arc<T>,
) -> PreparedUdpTransport<T> {
    PreparedUdpTransport::new(async move { prepared.commit().await.map(erase) })
}

#[async_trait]
impl SharedSourceOutbound for AnyTlsHandler {
    async fn prepare_shared_source(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
        speculative: bool,
    ) -> anyhow::Result<PreparedUdpTransport<dyn MultiTargetTransport>> {
        Self::prepare_udp_source(runtime, target, target_domain, connect_timeout, speculative).await
    }
}

#[async_trait]
impl PacketOutbound for AnyTlsHandler {
    async fn dial_udp_transport(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let owner = crate::runtime::NodeRuntime::try_ephemeral_guarded(node)?;
        let transport = self
            .dial_udp_transport_runtime(owner.runtime(), target, target_domain, connect_timeout)
            .await?;
        Ok(crate::proxy::packet_transport_with_owner(transport, owner))
    }

    async fn dial_udp_transport_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<Arc<dyn PacketTransport>> {
        let transport =
            Self::dial_udp_transport_typed(runtime, target, target_domain, connect_timeout).await?;
        Ok(transport)
    }

    async fn dial_udp_transport_speculative_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<PreparedUdpTransport> {
        let prepared = Self::dial_udp_transport_speculative_typed(
            runtime,
            target,
            target_domain,
            connect_timeout,
        )
        .await?;
        Ok(erase_prepared(prepared, |transport| {
            transport as Arc<dyn PacketTransport>
        }))
    }
}
