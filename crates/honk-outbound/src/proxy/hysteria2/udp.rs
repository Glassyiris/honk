use super::*;

/// Framed UDP transport over the shared Hysteria2 QUIC connection: UDP
/// message datagrams go straight onto the connection and inbound datagrams
/// arrive through the session demux queue.
pub struct Hy2UdpTransport {
    pub(super) state: Arc<Hy2ConnState>,
    pub(super) session_id: u32,
    pub(super) packet_id: AtomicU16,
    pub(super) rx: tokio::sync::Mutex<mpsc::Receiver<UdpInbound>>,
    pub(super) defrag: tokio::sync::Mutex<Defragmenter>,
    pub(super) addr: String,
    pub(super) target_domain_len: Option<usize>,
    pub(super) max_datagram: usize,
    pub(super) target: SocketAddr,
    pub(super) request_observer:
        parking_lot::Mutex<Option<crate::runtime::flow_observation::FlowObserver>>,
}

impl std::fmt::Debug for Hy2UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hy2UdpTransport")
            .field("session_id", &self.session_id)
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for Hy2UdpTransport {
    fn drop(&mut self) {
        self.state.sessions.lock().remove(&self.session_id);
        self.state.open.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl PacketTransport for Hy2UdpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn allows_full_cone_replies(&self) -> bool {
        true
    }
    fn send_timeout(&self) -> Duration {
        self.state.path_health.send_timeout()
    }
    fn record_quic_send_started(&self) -> QuicSendToken {
        self.state.path_health.record_send_started(&self.state.conn)
    }
    fn record_quic_send_success(&self, token: QuicSendToken) {
        self.state
            .path_health
            .record_send_success(token, &self.state.conn);
    }
    fn record_quic_send_timeout(&self, token: QuicSendToken) {
        if self
            .state
            .path_health
            .record_send_timeout(token, &self.state.conn)
        {
            crate::quic::record_quic_send_timeout();
        }
    }
    fn record_quic_send_failure(&self, token: QuicSendToken) {
        self.state.path_health.record_send_failure(token);
    }

    fn quic_path_stalled(&self) -> bool {
        self.state.path_health.is_stalled()
    }
    fn send_timeout_is_congestion(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send_to(self.target, self.target_domain(), data, None)
            .await
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let msg = self.rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    crate::proxy::NodeFailure(
                        self.state
                            .conn
                            .close_reason()
                            .map(anyhow::Error::new)
                            .unwrap_or_else(|| anyhow::anyhow!("hysteria2 connection closed")),
                    ),
                )
            })?;
            let peer = match msg.addr {
                crate::proxy::addr::SocksAddr::V4(peer) => peer.into(),
                crate::proxy::addr::SocksAddr::V6(peer) => peer.into(),
                crate::proxy::addr::SocksAddr::Domain(domain, port)
                    if self
                        .target_domain()
                        .is_some_and(|expected| domain.eq_ignore_ascii_case(expected))
                        && port == self.target.port() =>
                {
                    self.target
                }
                crate::proxy::addr::SocksAddr::Domain(_, _) => continue,
            };
            let complete = self.defrag.lock().await.feed(
                msg.packet_id,
                msg.frag_id,
                msg.frag_total,
                Some(peer),
                msg.data,
            );
            if let Some((data, peer)) = complete {
                if data.len() > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hysteria2 packet exceeds buffer",
                    ));
                }
                buf[..data.len()].copy_from_slice(&data);
                return Ok((data.len(), peer));
            }
        }
    }
}

impl Hy2UdpTransport {
    pub fn server_addr(&self) -> SocketAddr {
        self.state.conn.remote_address()
    }

    fn target_domain(&self) -> Option<&str> {
        self.target_domain_len.map(|len| &self.addr[..len])
    }

    pub async fn send_to(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        admitted: Option<&AtomicBool>,
    ) -> io::Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        // Scoped so the 2 KiB address buffer is not kept in the future across
        // the send awaits: the enclosing driver future is shared by every
        // ordinary UDP transport and is moved on every packet.
        let packets = {
            let mut address;
            let addr = if target == self.target && target_domain == self.target_domain() {
                self.addr.as_str()
            } else {
                address = [0u8; MAX_ADDRESS_LENGTH as usize];
                let mut cursor = io::Cursor::new(address.as_mut_slice());
                if let Some(domain) = target_domain {
                    write!(cursor, "{domain}:{}", target.port())?;
                } else {
                    write!(cursor, "{target}")?;
                }
                let len = cursor.position() as usize;
                std::str::from_utf8(&address[..len]).expect("formatted address is UTF-8")
            };
            self.state.touch();
            let packet_id = self
                .packet_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            fragment_udp_message(self.session_id, packet_id, addr, data, self.max_datagram)
                .map_err(io::Error::other)?
        };
        for packet in packets {
            self.state
                .conn
                .send_datagram_wait(bytes::Bytes::from(packet))
                .await
                .map_err(io::Error::other)
                .map_err(crate::proxy::quic_carrier_io_error)?;
            if let Some(admitted) = admitted {
                admitted.store(true, Ordering::Release);
            }
        }
        let captured = self.request_observer.lock().take();
        if let Some(observer) = crate::runtime::flow_observation::current().or(captured) {
            observer.milestone_once(crate::runtime::flow_observation::Milestone::TargetRequestSent);
        }
        Ok(())
    }
}
