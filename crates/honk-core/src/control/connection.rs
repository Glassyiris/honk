use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::group::{SelectionNetwork, SelectionPlanMode};
use honk_config::types::NodeProtocol;
use std::collections::{HashMap, HashSet};

/// Result from the eBPF routing handoff map lookup.
#[derive(Debug, Clone)]
struct HandoffResult {
    outbound: u8,
    mark: u32,
    must: u8,
    decision_token: u32,
    dscp: u8,
    mac: [u8; 6],
    pname: [u8; 16],
    pid: u32,
}

impl From<RoutingHandoffEntry> for HandoffResult {
    fn from(entry: RoutingHandoffEntry) -> Self {
        Self {
            outbound: entry.result.outbound,
            mark: entry.result.mark,
            must: entry.result.must,
            decision_token: entry.result.decision_token,
            dscp: entry.result.dscp,
            mac: entry.result.mac,
            pname: entry.result.pname,
            pid: entry.result.pid,
        }
    }
}

impl HandoffResult {
    /// Convert the eBPF process name byte array to an optional string.
    /// Treats the array as NUL-terminated or fixed-length, trimming trailing
    /// NULs and whitespace.
    fn process_name(&self) -> Option<String> {
        let bytes: Vec<u8> = self.pname.iter().copied().take_while(|&b| b != 0).collect();
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Resolve the process executable path from /proc. The process may have
    /// exited between the cgroup hook and now — any failure just omits the
    /// field. Off the runtime workers: even a /proc readlink is blocking I/O.
    async fn process_path(&self) -> Option<String> {
        if self.pid == 0 {
            return None;
        }
        let pid = self.pid;
        tokio::task::spawn_blocking(move || {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        })
        .await
        .ok()
        .flatten()
    }

    /// Convert the eBPF MAC address to canonical lower-case colon form.
    fn mac_address(&self) -> Option<String> {
        if self.mac == [0u8; 6] {
            return None;
        }
        Some(
            self.mac
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct TcpFlowKey {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    l4proto: u8,
}

impl TcpFlowKey {
    pub(super) fn from_tuples(tuples: &TuplesKey) -> Self {
        Self {
            src_ip: *tuples.src_ip.as_bytes(),
            dst_ip: *tuples.dst_ip.as_bytes(),
            src_port: tuples.src_port,
            dst_port: tuples.dst_port,
            l4proto: tuples.l4proto,
        }
    }

    pub(super) fn from_redirect(tuple: &RedirectTuple) -> Self {
        Self {
            src_ip: *tuple.src_ip.as_bytes(),
            dst_ip: *tuple.dst_ip.as_bytes(),
            src_port: tuple.src_port,
            dst_port: tuple.dst_port,
            l4proto: tuple.l4proto,
        }
    }
}

#[derive(Default)]
pub(super) struct TcpFlowPins {
    inner: parking_lot::Mutex<HashMap<TcpFlowKey, usize>>,
}

impl TcpFlowPins {
    fn retain(&self, key: TcpFlowKey) {
        *self.inner.lock().entry(key).or_default() += 1;
    }

    fn release(&self, key: TcpFlowKey) -> Option<bool> {
        let mut pins = self.inner.lock();
        let owners = pins.get_mut(&key)?;
        if *owners > 1 {
            *owners -= 1;
            Some(false)
        } else {
            pins.remove(&key);
            Some(true)
        }
    }

    pub(super) fn snapshot(&self) -> HashSet<TcpFlowKey> {
        self.inner.lock().keys().copied().collect()
    }

    #[cfg(test)]
    pub(super) fn retain_for_test(&self, key: TcpFlowKey) {
        self.retain(key);
    }

    #[cfg(test)]
    pub(super) fn release_for_test(&self, key: TcpFlowKey) -> Option<bool> {
        self.release(key)
    }
}

struct TcpFlowGuard {
    stream: TcpStream,
    tuples: TuplesKey,
    pin_key: Option<TcpFlowKey>,
    pins: Arc<TcpFlowPins>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    tracker_id: Option<String>,
}

impl TcpFlowGuard {
    fn new(
        stream: TcpStream,
        tuples: TuplesKey,
        pins: Arc<TcpFlowPins>,
        ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
        tracker: Arc<ConnectionTracker>,
    ) -> Self {
        let pin_key = TcpFlowKey::from_tuples(&tuples);
        pins.retain(pin_key);
        Self {
            stream,
            tuples,
            pin_key: Some(pin_key),
            pins,
            ebpf,
            tracker,
            tracker_id: None,
        }
    }

    fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    fn track(&mut self, entry: crate::connection_tracker::ConnectionEntry) {
        assert!(
            self.tracker_id.is_none(),
            "TCP flow tracker attached more than once"
        );
        self.tracker_id = Some(self.tracker.register(entry));
    }

    fn untrack(&mut self) {
        if let Some(id) = self.tracker_id.take() {
            self.tracker.remove(&id);
        }
    }

    fn release_pin(&mut self) -> Option<bool> {
        let key = self.pin_key.take()?;
        match self.pins.release(key) {
            Some(last_owner) => Some(last_owner),
            None => {
                error!(?key, "TCP flow pin release found no owner");
                None
            }
        }
    }

    async fn retire(mut self) {
        self.untrack();
        let now_ns = match super::janitor::monotonic_now_ns() {
            Ok(now_ns) => now_ns,
            Err(error) => {
                error!(%error, "TCP flow retirement could not read monotonic clock");
                return;
            }
        };
        let retire_cutoff_ns = now_ns.saturating_sub(1);
        let ebpf = Arc::clone(&self.ebpf);
        let mut backend = ebpf.write().await;
        if self.release_pin() != Some(true) {
            return;
        }

        let current = match backend.tcp_conn_state_lookup(&self.tuples) {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow retirement lookup failed");
                return;
            }
        };
        match backend.conn_state_remove_if_unchanged(&[(self.tuples, current)], retire_cutoff_ns) {
            Ok(removed) => {
                if removed != 0 {
                    crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
                }
                debug!(removed, ?self.tuples, "TCP flow conn-state retired");
            }
            Err(error) => {
                error!(%error, ?self.tuples, "TCP flow conditional retirement failed");
            }
        }
    }
}

impl Drop for TcpFlowGuard {
    fn drop(&mut self) {
        self.untrack();
        self.release_pin();
    }
}

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}
fn connection_chains(mut selection_chain: Vec<String>, node_name: &str) -> Vec<String> {
    if selection_chain.last().map(String::as_str) != Some(node_name) {
        selection_chain.push(node_name.to_owned());
    }
    selection_chain.reverse();
    selection_chain
}

pub(super) struct ConnectionGuard {
    drain: Arc<DrainTracker>,
}

impl ConnectionGuard {
    pub(super) fn new(drain: Arc<DrainTracker>) -> Self {
        drain.increment();
        Self { drain }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.drain.decrement();
    }
}

/// Shared context bundle passed to every connection handler.
/// Bundles all shared fields under a single `Arc` to eliminate
/// per-field atomic reference-count overhead on the hot path.
#[derive(Clone)]
pub(super) struct ControlPlaneHandle {
    pub(super) config: Arc<RwLock<Config>>,
    pub(super) router: Arc<RwLock<Router>>,
    pub(super) proxy_registry: Arc<ProxyRegistry>,
    pub(super) runtime_registry: honk_outbound::runtime::SharedRuntimeRegistry,
    pub(super) dns_resolver: Arc<DnsResolver>,
    pub(super) group_manager: SharedGroupManager,
    pub(super) stats: Arc<StatsManager>,
    pub(super) ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    pub(super) udp_pool: Arc<UdpEndpointPool>,
    #[cfg(feature = "ebpf")]
    pub(super) pending_udp_verdicts: Option<Arc<crate::control::nfqueue::PendingUdpVerdicts>>,
    pub(super) tcp_sniff_neg_cache: Arc<crate::control::tcp_sniff::TcpSniffNegCache>,
    pub(super) sniffer_pool: Arc<crate::control::packet_sniffer::PacketSnifferPool>,
    pub(super) dns_controller: Arc<crate::control::dns_control::DnsController>,
    pub(super) alive_set: Arc<AliveDialerSet>,
    pub(super) connection_pool: Arc<ConnectionPool>,
    pub(super) connection_tracker: Arc<ConnectionTracker>,
    pub(super) tcp_flow_pins: Arc<TcpFlowPins>,
    /// Shared clash mode state (None when the clash API is disabled).
    pub(super) mode_state: Option<crate::mode::SharedModeState>,
}

/// Build the eBPF conntrack key for a flow: IPs as 16-byte v4-mapped
/// addresses, ports in host byte order, `l4proto` as the IANA number.
pub(crate) fn build_tuples_key(
    dst_ip: std::net::IpAddr,
    dst_port: u16,
    src_ip: std::net::IpAddr,
    src_port: u16,
    l4proto: u8,
) -> TuplesKey {
    // mem::zeroed, NOT TuplesKey::default(): the struct has 3 implicit
    // padding bytes after l4proto (37 field bytes in a 40-byte repr(C)
    // layout), and Rust does not guarantee padding is zeroed on field-wise
    // initialization.  The kernel hashes all 40 key bytes, and the datapath
    // writes keys from a zeroed scratch buffer — a garbage-padded userspace
    // key never matches (lookups/deletes silently ENOENT).
    let mut key: TuplesKey = unsafe { std::mem::zeroed() };
    match dst_ip {
        std::net::IpAddr::V4(ip) => {
            key.dst_ip[10] = 0xff;
            key.dst_ip[11] = 0xff;
            key.dst_ip[12..16].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => key.dst_ip.copy_from_slice(&ip.octets()),
    }
    match src_ip {
        std::net::IpAddr::V4(ip) => {
            key.src_ip[10] = 0xff;
            key.src_ip[11] = 0xff;
            key.src_ip[12..16].copy_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => key.src_ip.copy_from_slice(&ip.octets()),
    }
    key.dst_port = dst_port;
    key.src_port = src_port;
    key.l4proto = l4proto;
    key
}

#[cfg(any(feature = "ebpf", test))]
fn final_udp_rule_mark(routed_direct: bool, final_outbound: &str, routed_mark: u32) -> u32 {
    if final_outbound == "direct" && !routed_direct {
        0
    } else {
        routed_mark
    }
}

impl ControlPlaneHandle {
    /// `/proc/<pid>/exe` is display-only enrichment. Never hold first-packet
    /// delivery behind the blocking pool used to resolve it.
    fn spawn_process_path_enrichment(&self, conn_id: String, handoff: Option<&HandoffResult>) {
        let Some(handoff) = handoff.filter(|handoff| handoff.pid != 0).cloned() else {
            return;
        };
        let tracker = Arc::clone(&self.connection_tracker);
        tokio::spawn(async move {
            if let Some(process_path) = handoff.process_path().await {
                tracker.update_process_path(&conn_id, process_path);
            }
        });
    }
    /// Look up the eBPF routing handoff entry for a connection, consuming it.
    ///
    /// Only a read lock is taken: `routing_handoff_take` performs raw bpf()
    /// map operations, which the kernel serializes internally — no userspace
    /// backend state is touched.  The lock's sole role here is to keep the
    /// backend (and its map fds) alive against `cleanup()`, which takes the
    /// write lock.
    async fn lookup_handoff(&self, tuples: &TuplesKey) -> Option<HandoffResult> {
        self.ebpf
            .read()
            .await
            .routing_handoff_take(tuples)
            .ok()
            .flatten()
            .map(Into::into)
    }

    /// Staged UDP transitions consume their handoff atomically at commit, so
    /// initialization may only inspect it. Legacy socket ingress keeps the
    /// existing take-once behavior.
    async fn lookup_udp_handoff(
        &self,
        tuples: &TuplesKey,
        decision_token: u32,
    ) -> anyhow::Result<Option<HandoffResult>> {
        if decision_token == 0 {
            return Ok(self.lookup_handoff(tuples).await);
        }
        let entry = self
            .ebpf
            .read()
            .await
            .routing_handoff_lookup(tuples)?
            .ok_or_else(|| anyhow::anyhow!("staged UDP flow has no routing handoff"))?;
        if entry.result.decision_token != decision_token {
            anyhow::bail!(
                "staged UDP handoff token mismatch: expected {}, found {}",
                decision_token,
                entry.result.decision_token
            );
        }
        Ok(Some(entry.into()))
    }

    async fn adopt_tcp_flow(
        &self,
        stream: TcpStream,
        tuples: TuplesKey,
    ) -> anyhow::Result<(TcpFlowGuard, Option<HandoffResult>)> {
        let backend = self.ebpf.read().await;
        match backend.tcp_conn_state_lookup(&tuples) {
            Ok(Some(_)) => {}
            Ok(None) => anyhow::bail!("accepted TCP flow has no conn-state: {tuples:?}"),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "accepted TCP flow conn-state lookup failed for {tuples:?}: {error}"
                ));
            }
        }

        let flow = TcpFlowGuard::new(
            stream,
            tuples,
            Arc::clone(&self.tcp_flow_pins),
            Arc::clone(&self.ebpf),
            Arc::clone(&self.connection_tracker),
        );
        let handoff = backend
            .routing_handoff_take(&tuples)
            .ok()
            .flatten()
            .map(Into::into);
        Ok((flow, handoff))
    }

    async fn outbound_index_to_name(&self, index: u8) -> String {
        match OutboundIndex::from_user(index as u32) {
            OutboundIndex::Direct => "direct".into(),
            OutboundIndex::Block => "block".into(),
            OutboundIndex::MustRules => "must_rules".into(),
            OutboundIndex::ControlPlaneRouting => "control_plane_routing".into(),
            _ => {
                let config = self.config.read().await;
                // Map user index back to the group name (same order as
                // outbound_name_to_id above).
                let user_idx = index.saturating_sub(OutboundIndex::UserBase as u8);
                config
                    .groups
                    .get(user_idx as usize)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| config.routing.default_outbound.clone())
            }
        }
    }

    #[cfg(feature = "ebpf")]
    async fn outbound_name_to_index(&self, outbound_name: &str) -> u8 {
        match outbound_name {
            "direct" => OutboundIndex::Direct as u8,
            "block" => OutboundIndex::Block as u8,
            "must_rules" => OutboundIndex::MustRules as u8,
            "control_plane_routing" => OutboundIndex::ControlPlaneRouting as u8,
            _ => {
                let config = self.config.read().await;
                config
                    .groups
                    .iter()
                    .position(|group| group.name == outbound_name)
                    .and_then(|index| u8::try_from(index).ok())
                    .and_then(|index| (OutboundIndex::UserBase as u8).checked_add(index))
                    .unwrap_or(OutboundIndex::ControlPlaneRouting as u8)
            }
        }
    }

    /// Clash mode override (approximate clash semantics), applied after the
    /// eBPF handoff / userspace Router produced an outbound and before
    /// `resolve_outbound_nodes`:
    ///
    /// - mode `Direct` forces `direct`;
    /// - mode `Global` forces the current GLOBAL selection (a group or node
    ///   name, resolved via the normal path; when it resolves to nothing the
    ///   original routing result is kept);
    /// - `block` results and `must` results (dae `(must)` rules / eBPF
    ///   handoff must flag) are never overridden — both are final routing
    ///   decisions that mode switches must not bypass.
    async fn apply_mode_override(&self, outbound_name: String, must: bool) -> String {
        let Some(ref mode_state) = self.mode_state else {
            return outbound_name;
        };
        if must || outbound_name == "block" {
            return outbound_name;
        }
        let state = { mode_state.read().clone() };
        // The GLOBAL selection needs a config lookup to decide whether it
        // resolves to a group/node; only do it in Global mode.
        let mut selection_resolvable = false;
        if state.is_global() && !state.global_selection.is_empty() {
            let selection = &state.global_selection;
            selection_resolvable = *selection == "direct" || *selection == "block" || {
                let config = self.config.read().await;
                config.groups.iter().any(|g| g.name == *selection)
                    || config.nodes.iter().any(|n| n.name == *selection)
            };
            if !selection_resolvable {
                debug!(
                    "clash Global selection '{}' does not resolve; keeping routed outbound '{}'",
                    selection, outbound_name
                );
            }
        }
        state.override_outbound(&outbound_name, false, selection_resolvable)
    }

    pub(super) async fn serve_connection(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        debug!("TPROXY TCP connection from {}", client_addr);

        let original_dst = match get_original_dst(&stream) {
            Ok(d) => d,
            Err(e) => {
                // When the eBPF datapath delivers the SYN directly with
                // bpf_sk_assign(), the kernel does not set SO_ORIGINAL_DST.
                // The transparent socket's local address is the original
                // destination, so fall back to that.
                match stream.local_addr() {
                    Ok(d) => {
                        trace!(
                            "SO_ORIGINAL_DST unavailable for {} ({}); using local_addr {}",
                            client_addr, e, d
                        );
                        d
                    }
                    Err(le) => {
                        warn!(
                            "Failed to get original destination for {}: {}; local_addr also failed: {}",
                            client_addr, e, le
                        );
                        return Err(anyhow::anyhow!(
                            "original destination unavailable for {}: {} (local_addr: {})",
                            client_addr,
                            e,
                            le
                        ));
                    }
                }
            }
        };
        debug!("Original destination: {}", original_dst);
        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            6, // TCP
        );
        let (mut flow, handoff) = self.adopt_tcp_flow(stream, tuples).await?;

        if let Ok(true) = self
            .dns_controller
            .handle_tcp_dns(flow.stream_mut(), client_addr, original_dst)
            .await
        {
            return Ok(());
        }

        let dial_mode = {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .ok()
                .unwrap_or(DialMode::DomainPlusPlus)
        };

        let connect_timeout = {
            let config = self.config.read().await;
            std::time::Duration::from_millis(config.global.connect_timeout_ms)
        };

        // Skip sniffing if eBPF routing already decided with must flag
        // (must rules are final — no domain sniffing needed, matches Go dae).
        // In ip mode we never sniff because we always dial by original_dst.
        let mut skip_sniff = matches!(dial_mode, DialMode::Ip);
        if let Some(ref ho) = handoff {
            // Must-rules: eBPF already made a final routing decision.
            // Domain sniffing is unnecessary and costly — skip it.
            if !skip_sniff
                && ho.must != 0
                && ho.outbound != OutboundIndex::ControlPlaneRouting as u8
            {
                debug!(
                    "Skip TCP sniffing by must-rule for {} (outbound={})",
                    original_dst, ho.outbound
                );
                skip_sniff = true;
            }
            let cache_key = (original_dst, ho.outbound);
            let now = std::time::Instant::now();
            if !skip_sniff && self.tcp_sniff_neg_cache.should_skip_sniff(&cache_key, now) {
                debug!("Skip TCP sniffing by negative cache for {}", original_dst);
                skip_sniff = true;
            }
        }

        let sniff_result = if skip_sniff {
            sniffing::SniffResult::unknown()
        } else {
            sniffing::sniff_tcp(flow.stream_mut()).await
        };
        let mut domain = sniff_result.domain.clone();
        if let Some(ref d) = domain {
            debug!("SNI sniffed domain: {}", d);
        }

        // Domain mode verifies that the sniffed domain actually resolves to the
        // original destination IP. If not, fall back to IP mode for this flow.
        if matches!(dial_mode, DialMode::Domain)
            && let Some(ref d) = domain
        {
            let verified = self.verify_domain_reality(d, original_dst.ip()).await;
            if !verified {
                debug!(
                    "Sniffed domain {} failed reality check against {}, falling back to IP",
                    d,
                    original_dst.ip()
                );
                domain = None;
            }
        }

        if !skip_sniff && let Some(ref ho) = handoff {
            let cache_key = (original_dst, ho.outbound);
            let now = std::time::Instant::now();
            if domain.is_some() {
                self.tcp_sniff_neg_cache.clear_sniff_negative(&cache_key);
            } else {
                self.tcp_sniff_neg_cache.note_sniff_failure(cache_key, now);
            }
        }

        let conn_info = ConnectionInfo {
            domain: domain.clone(),
            dst_ip: original_dst.ip(),
            dst_port: original_dst.port(),
            src_ip: client_addr.ip(),
            src_port: client_addr.port(),
            protocol: "tcp",
            process_name: handoff.as_ref().and_then(|ho| ho.process_name()),
            mac: handoff.as_ref().and_then(|ho| ho.mac_address()),
            dscp: handoff.as_ref().map(|ho| ho.dscp),
        };

        // prefer all 'direct' need handoff, even if in complex chain select 'direct' outbound
        let reroute_by_sniffed_domain =
            Self::should_reroute_sniffed_domain(dial_mode, domain.as_deref(), handoff.as_ref());
        let (outbound_name, must) = if let Some(ho) = &handoff {
            debug!(
                "eBPF handoff: outbound={}, mark=0x{:x}, dscp={}",
                ho.outbound, ho.mark, ho.dscp
            );
            if ho.outbound == OutboundIndex::ControlPlaneRouting as u8 || reroute_by_sniffed_domain
            {
                let router = self.router.read().await;
                let (name, must) = router.route_with_must(&conn_info);
                (name.to_string(), must)
            } else {
                (self.outbound_index_to_name(ho.outbound).await, ho.must != 0)
            }
        } else {
            let router = self.router.read().await;
            let (name, must) = router.route_with_must(&conn_info);
            (name.to_string(), must)
        };

        // Matched-rule identity for the /connections display. The userspace
        // Router mirrors the eBPF-compiled rules, so this names eBPF-decided
        // flows as well (display-only; the handoff decision above stands).
        let matched_rule = {
            let router = self.router.read().await;
            router
                .route_full(&conn_info)
                .map(|m| (m.rule_type.to_string(), m.rule_payload.to_string()))
        };

        // Clash mode override (Direct/Global); no-op when the clash API is
        // disabled or mode is Rule. Must-rule and block results are never
        // overridden.
        let outbound_name = self.apply_mode_override(outbound_name, must).await;

        // For userspace-routed flows with a sniffed domain, write the resolved
        // IP back into eBPF DOMAIN_ROUTING_MAP so the next connection to the
        // same IP can be fast-pathed by eBPF domain rules instead of being
        // sniffed again.
        if let Some(domain) = &domain
            && Self::should_write_sniffed_domain_bitmap(handoff.as_ref(), reroute_by_sniffed_domain)
        {
            self.push_sniffed_domain_bitmap(&conn_info, domain, original_dst.ip())
                .await;
        }

        self.stats.record_connection(&outbound_name);

        let ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (mut candidates, selection_mode, selection_chain) = {
            let config = self.config.read().await;
            let gm = self.group_manager.read();
            let (candidates, selection_mode) = if let Some(group) = config
                .groups
                .iter()
                .find(|group| group.name == outbound_name)
            {
                let plan = gm.selection_plan_for_domain(&group.name, ProbeDomain::Tcp, ipver);
                (
                    plan.nodes.into_iter().cloned().collect::<Vec<_>>(),
                    plan.mode,
                )
            } else {
                (
                    resolve_outbound_nodes(&config, &gm, &outbound_name, ProbeDomain::Tcp, ipver),
                    SelectionPlanMode::Authoritative,
                )
            };
            let selection_chain =
                gm.selection_chain_for_network(&outbound_name, SelectionNetwork::Tcp);
            (candidates, selection_mode, selection_chain)
        };
        // Only an unmeasured URLTest group is allowed to speculate. Its
        // candidate set is bounded before spawning so a large group cannot
        // turn one client flow into an unbounded dial storm.
        if selection_mode == SelectionPlanMode::ColdUrlTest {
            candidates.truncate(3);
        } else {
            candidates.truncate(1);
        }
        // Pin this flow to the runtime generation admitted with its
        // candidate selection: every dial, pool backfill, and permit below
        // uses this snapshot, never a post-reload replacement.
        let runtime_generation = self.runtime_registry.read().clone();

        // If eBPF already decided this flow should go direct (not just punted
        // it to userspace), skip userspace proxy dial, DNS, and relay entirely.
        // For ControlPlaneRouting handoffs we must relay in userspace even if
        // the final routing decision is direct, because eBPF has not installed
        // the flow state needed to forward the accepted socket.
        let ebpf_offload = outbound_name == "direct"
            && handoff
                .as_ref()
                .map(|ho| {
                    ho.outbound == OutboundIndex::Direct as u8
                        && ho.mark != 0
                        && ho.outbound != OutboundIndex::ControlPlaneRouting as u8
                })
                .unwrap_or(false);
        if ebpf_offload {
            debug!(
                network = "tcp",
                outbound = %outbound_name,
                ip = %original_dst,
                src = %client_addr,
                ebpf_offload = true,
                "TCP offloaded to eBPF: {} -> {}",
                client_addr,
                original_dst,
            );
            self.stats.record_close(&outbound_name);
            return Ok(());
        }

        if candidates.is_empty() {
            warn!(
                "No available candidate nodes for outbound '{}' ({})",
                outbound_name, client_addr
            );
            // Trigger emergency probes to recover dead nodes (leaf
            // expansion: sub-group tags carry no probe state).
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name);
            self.stats.record_close(&outbound_name);
            return Ok(());
        }

        // SOCKS5, Trojan, Shadowsocks, and AnyTLS support domain-based routing
        // (ATYP_DOMAIN). They resolve the domain on the proxy server side, so
        // client-side DNS is unnecessary. Direct/block use the original_dst IP
        // directly — no DNS needed.
        let all_domain_capable = candidates.iter().all(|node| {
            matches!(
                node.protocol,
                NodeProtocol::Direct
                    | NodeProtocol::Block
                    | NodeProtocol::Socks5
                    | NodeProtocol::Trojan
                    | NodeProtocol::SS
                    | NodeProtocol::AnyTLS
            )
        });

        // Resolve the target IP for dialing. Pass the sniffed domain to the
        // proxy when available (used for domain-based routing in SOCKS5 etc.).
        let (resolved_target, target_domain) = if let Some(ref domain) = domain {
            if all_domain_capable {
                debug!(
                    "Skipping DNS for {} (domain-capable proxy, {} candidates)",
                    domain,
                    candidates.len()
                );
                (original_dst, Some(domain.clone()))
            } else {
                // One or more candidates are direct/block — need DNS resolution.
                // Resolve both IPv4 and IPv6, preferring the version that
                // matches original_dst. Apply configurable timeout.
                let is_v6 = original_dst.is_ipv6();
                let dns_timeout = std::time::Duration::from_millis(
                    self.config.read().await.global.dns_resolve_timeout_ms,
                );
                match tokio::time::timeout(dns_timeout, self.dns_resolver.resolve(domain)).await {
                    Ok(Ok(resolved)) => {
                        // Prefer AAAA records for v6 original_dst, A records for v4.
                        let preferred_ip = if is_v6 {
                            resolved
                                .ipv6
                                .first()
                                .or_else(|| resolved.ipv4.first())
                                .copied()
                        } else {
                            resolved
                                .ipv4
                                .first()
                                .or_else(|| resolved.ipv6.first())
                                .copied()
                        };
                        match preferred_ip {
                            Some(ip) => {
                                let resolved_addr = SocketAddr::new(ip, original_dst.port());
                                debug!(
                                    "DNS resolved {} -> {} ({})",
                                    domain,
                                    resolved_addr,
                                    if is_v6 { "v6-prefer" } else { "v4-prefer" }
                                );
                                (resolved_addr, Some(domain.clone()))
                            }
                            None => {
                                debug!("DNS returned no IPs for {}, using original dst", domain);
                                (original_dst, Some(domain.clone()))
                            }
                        }
                    }
                    _ => {
                        debug!("DNS timed out or failed for {}, using original dst", domain);
                        (original_dst, Some(domain.clone()))
                    }
                }
            }
        } else {
            (original_dst, None)
        };

        let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
        let candidate_refs: Vec<&Node> = candidates.iter().collect();
        let raced = self
            .race_candidates(
                &candidate_refs,
                resolved_target,
                target_domain.clone(),
                &outbound_name,
                connect_timeout,
                Arc::clone(&runtime_generation),
                ipver,
                cold_urltest,
            )
            .await;
        let (mut proxy_stream, node): (crate::proxy::ProxyStream, Node) = match raced {
            Some((stream, idx)) => (stream, candidates[idx].clone()),
            None => {
                // Exactly one retry when the just-reported failure may have
                // moved the plan (URLTest strike demotion). Same-plan
                // outcomes (Selector pin, Fallback pin on a still-alive
                // node, single-node outbound) yield the identical candidate
                // and are not retried.
                let mut retried: Option<(crate::proxy::ProxyStream, Node)> = None;
                if selection_mode == SelectionPlanMode::Authoritative && candidates.len() == 1 {
                    let group_manager = self.group_manager.read().clone();
                    let plan = group_manager.selection_plan_for_domain(
                        &outbound_name,
                        ProbeDomain::Tcp,
                        ipver,
                    );
                    if !plan.nodes.is_empty() && plan.nodes[0].id != candidates[0].id {
                        let nodes = &plan.nodes[..plan.nodes.len().min(3)];
                        retried = self
                            .race_candidates(
                                nodes,
                                resolved_target,
                                target_domain.clone(),
                                &outbound_name,
                                connect_timeout,
                                Arc::clone(&runtime_generation),
                                ipver,
                                false,
                            )
                            .await
                            .map(|(stream, idx)| (stream, nodes[idx].clone()));
                    }
                }
                match retried {
                    Some(pair) => pair,
                    None => {
                        self.stats.record_close(&outbound_name);
                        return Ok(());
                    }
                }
            }
        };

        let dscp_val = handoff.as_ref().map(|ho| ho.dscp).unwrap_or(0);

        let conn_id = uuid::Uuid::new_v4().to_string();
        // Clash-shaped matched rule + dial chain for /connections: rule and
        // rulePayload describe the RULE (type + own payload, "Fallback" =
        // fallback), while metadata.host keeps the connection's domain.
        // chains is the selection path leaf-first ([leaf, .., topGroup]).
        let (rule, rule_payload) = matched_rule
            .clone()
            .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
        let chains = connection_chains(selection_chain, &node.name);
        // Live byte counters shared with the relay task: it increments them
        // as data flows so /connections shows real-time totals instead of a
        // single close-time (never-visible) update.
        let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        flow.track(crate::connection_tracker::ConnectionEntry {
            id: conn_id.clone(),
            source: client_addr.to_string(),
            destination: resolved_target.to_string(),
            proxy: node.name.clone(),
            rule,
            rule_payload,
            chains,
            upload: conn_upload.clone(),
            download: conn_download.clone(),
            start_time: std::time::Instant::now(),
            domain: target_domain.clone(),
            network: "tcp".to_string(),
            process: handoff.as_ref().and_then(|ho| ho.process_name()),
            process_path: None,
        });
        self.spawn_process_path_enrichment(conn_id, handoff.as_ref());

        debug!(
            network = "tcp",
            outbound = %outbound_name,
            dialer = %node.name,
            sniffed = target_domain.as_deref().unwrap_or(""),
            ip = %resolved_target,
            dscp = dscp_val,
            src = %client_addr,
            "TCP connection: {} <-> {}", client_addr, resolved_target,
        );

        if !sniff_result.buffered.is_empty() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = proxy_stream.stream.write_all(&sniff_result.buffered).await {
                warn!("Failed to write sniffed bytes to proxy: {}", e);
                self.stats.record_error(&outbound_name);
                self.stats.record_close(&outbound_name);
                return Ok(());
            }
        }

        // Zero-copy fast path: a direct dial yields plain `TcpStream`s on
        // both ends, so relay through `splice(2)` (with automatic lossless
        // fallback to the copy relay when the kernel rejects it). TLS- or
        // protocol-wrapped proxy streams keep the userspace copy relay.
        // Both paths update the connection's live byte counters as data flows.
        let conn_progress = Some((conn_upload.clone(), conn_download.clone()));
        let relay_result = match proxy_stream.into_tcp_stream() {
            Ok(upstream) => {
                relay::splice::relay_splice(
                    flow.stream_mut(),
                    upstream,
                    client_addr,
                    resolved_target,
                    conn_progress,
                )
                .await
            }
            Err(proxy_stream) => {
                relay::splice::relay_auto(
                    flow.stream_mut(),
                    proxy_stream.stream,
                    client_addr,
                    resolved_target,
                    conn_progress,
                )
                .await
            }
        };
        flow.retire().await;

        match relay_result {
            Ok(relay_stats) => {
                self.stats.record_bytes(
                    &outbound_name,
                    relay_stats.client_to_proxy,
                    relay_stats.proxy_to_client,
                );
                self.stats.record_close(&outbound_name);

                // Deposit a fresh connection for future reuse. Ready-capable
                // handlers get a fully-dialed, target-bound stream (handshake
                // paid here, off the critical path); others get a bare TCP
                // to the proxy server.
                if outbound_name != "direct" && outbound_name != "block" {
                    let node = node.clone();
                    let node_addr = format!("{}:{}", node.host(), node.port);
                    let pool = self.connection_pool.clone();
                    let registry = self.proxy_registry.clone();
                    let target_domain = target_domain.clone();
                    let generation = Arc::clone(&runtime_generation);
                    tokio::spawn(async move {
                        let (ready_capable, bare_capable) = registry
                            .find(node.protocol)
                            .map(|entry| {
                                (
                                    (entry.descriptor.pool_ready_streams)(&node),
                                    (entry.descriptor.pool_bare_tcp)(&node),
                                )
                            })
                            .unwrap_or((false, false));
                        if ready_capable {
                            let key = ConnectionPool::ready_key(
                                &node_addr,
                                resolved_target,
                                target_domain.as_deref(),
                            );
                            // Only hot targets earn a speculative ready
                            // dial; a one-off flow gets none.
                            if !pool.note_target(&key) {
                                return;
                            }
                            match registry
                                .dial_runtime(
                                    generation,
                                    node.id,
                                    resolved_target,
                                    target_domain.as_deref(),
                                    connect_timeout,
                                )
                                .await
                            {
                                Ok(stream) => {
                                    pool.deposit_ready(&key, stream).await;
                                }
                                Err(e) => {
                                    debug!(
                                        "Pool deposit: ready dial to {} via {} failed: {}",
                                        resolved_target, node_addr, e
                                    );
                                }
                            }
                            return;
                        }
                        if !bare_capable {
                            // Multiplexed protocols pool whole sessions
                            // instead; a bare TCP is useless to them.
                            return;
                        }
                        match honk_outbound::util::connect_outbound(&node_addr, connect_timeout)
                            .await
                        {
                            Ok(stream) => {
                                if is_tcp_stream_alive(&stream) {
                                    pool.deposit_tcp(&node_addr, stream).await;
                                } else {
                                    debug!("Pool deposit: stream to {} is dead", node_addr);
                                }
                            }
                            Err(e) => {
                                debug!("Pool deposit: connect to {} failed: {}", node_addr, e);
                            }
                        }
                    });
                }
            }
            Err(e) => {
                // The relay updates these atomics as every read/splice completes.
                // Preserve bytes moved before an I/O failure rather than turning
                // the whole flow into a synthetic zero-byte success.
                self.stats.record_bytes(
                    &outbound_name,
                    conn_upload.load(std::sync::atomic::Ordering::Relaxed),
                    conn_download.load(std::sync::atomic::Ordering::Relaxed),
                );
                let io_err = e.downcast_ref::<std::io::Error>();
                if let Some(io_err) = io_err {
                    if relay::is_ignorable_connection_error(io_err) {
                        debug!(
                            "TCP relay closed for {} -> {}: {}",
                            client_addr, resolved_target, io_err
                        );
                    } else {
                        warn!(
                            "Relay error for {} -> {}: {}",
                            client_addr, resolved_target, e
                        );
                    }
                } else {
                    warn!(
                        "Relay error for {} -> {}: {}",
                        client_addr, resolved_target, e
                    );
                }
                self.stats.record_error(&outbound_name);
                self.stats.record_close(&outbound_name);
            }
        }

        if let (Some(ref ho), Some(ref domain)) = (handoff, sniff_result.domain)
            && (ho.outbound >= OutboundIndex::UserBase as u8
                || ho.outbound == OutboundIndex::Direct as u8)
        {
            let mut ebpf = self.ebpf.write().await;
            let ob = if ho.outbound == OutboundIndex::Direct as u8 {
                OutboundIndex::Direct
            } else {
                OutboundIndex::from_user(ho.outbound as u32)
            };
            if let Err(e) = ebpf.add_domain_route(domain, ob) {
                debug!("Failed to add domain route for {}: {}", domain, e);
            }
        }

        Ok(())
    }

    /// Verify that a sniffed domain actually resolves to the given IP address.
    ///
    /// This is used by `dial_mode: domain` to prevent routing based on a fake
    /// SNI sent by the client. Both IPv4 and IPv6 results are checked.
    ///
    /// When the connection is dual-stack but our resolver only returns the
    /// other family (common when the DNS strategy suppresses AAAA — e.g.
    /// `ipversion_prefer: 4` with A answers present, or an only-mode), the
    /// check **trusts the SNI** instead of discarding it.
    /// Falling back to IP-only would mis-route CDN IPv6 (e.g. `tracker.m-team.cc`
    /// on Cloudflare AAAA) via `dport(443) → proxy` despite
    /// `domain(keyword: m-team) → direct`.
    async fn verify_domain_reality(&self, domain: &str, expected: std::net::IpAddr) -> bool {
        let dns_timeout = std::time::Duration::from_millis(
            self.config.read().await.global.dns_resolve_timeout_ms,
        );
        match tokio::time::timeout(dns_timeout, self.dns_resolver.resolve(domain)).await {
            Ok(Ok(resolved)) => {
                match domain_reality_outcome(expected, &resolved.ipv4, &resolved.ipv6) {
                    RealityOutcome::ExactMatch => true,
                    RealityOutcome::OtherFamilyOnly => {
                        debug!(
                            "Domain reality check: {} has no records for {}; other family present — trusting SNI (got v4={:?} v6={:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        true
                    }
                    RealityOutcome::Mismatch => {
                        debug!(
                            "Domain reality check failed: {} does not resolve to {} (got {:?} {:?})",
                            domain, expected, resolved.ipv4, resolved.ipv6
                        );
                        false
                    }
                }
            }
            Ok(Err(e)) => {
                debug!(
                    "Domain reality check failed: unable to resolve {}: {}",
                    domain, e
                );
                false
            }
            Err(_) => {
                debug!("Domain reality check timed out for {}", domain);
                false
            }
        }
    }

    fn should_reroute_sniffed_domain(
        dial_mode: DialMode,
        domain: Option<&str>,
        handoff: Option<&HandoffResult>,
    ) -> bool {
        !matches!(dial_mode, DialMode::Ip)
            && domain.is_some()
            && handoff.is_some_and(|handoff| {
                handoff.must == 0 && handoff.outbound != OutboundIndex::Block as u8
            })
    }

    fn should_write_sniffed_domain_bitmap(
        handoff: Option<&HandoffResult>,
        reroute_by_sniffed_domain: bool,
    ) -> bool {
        reroute_by_sniffed_domain
            || handoff
                .map(|handoff| handoff.outbound == OutboundIndex::ControlPlaneRouting as u8)
                .unwrap_or(true)
    }

    pub(super) async fn serve_udp_connection(&self, lease: UdpInitLease) -> anyhow::Result<()> {
        #[cfg(feature = "ebpf")]
        let pending_cleanup = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        let cancellation = lease.wait_cancellation();
        tokio::select! {
            _ = cancellation => {
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup {
                    verdicts.cancel(*identity).await?;
                }
                Ok(())
            }
            result = self.initialize_udp_connection(lease) => {
                let Err(error) = result else {
                    return Ok(());
                };
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending_cleanup
                    && let Err(cancel_error) = verdicts.cancel(*identity).await
                {
                    return Err(error.context(format!(
                        "staged UDP cleanup also failed: {cancel_error}"
                    )));
                }
                Err(error)
            }
        }
    }

    async fn initialize_udp_connection(&self, mut lease: UdpInitLease) -> anyhow::Result<()> {
        let client_addr = lease.client_addr();
        let original_dst = lease.original_dst();
        let data = lease.first_payload();
        #[cfg(feature = "ebpf")]
        let pending = if lease.decision_token() == 0 {
            None
        } else {
            let verdicts = self
                .pending_udp_verdicts
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("staged UDP lease has no verdict owner"))?;
            Some((
                verdicts,
                crate::control::nfqueue::PendingUdpVerdicts::identity_for_lease(&lease),
            ))
        };
        #[cfg(not(feature = "ebpf"))]
        if lease.decision_token() != 0 {
            anyhow::bail!("staged UDP lease requires the ebpf feature");
        }
        debug!(
            "UDP datagram from {} -> {} ({} bytes, decision token {})",
            client_addr,
            original_dst,
            data.len(),
            lease.decision_token()
        );

        let dial_mode = {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .ok()
                .unwrap_or(DialMode::DomainPlusPlus)
        };

        // These checks remain after reservation because DNS and sniffing
        // share this initializer. A staged early exit must retire its held
        // originals immediately.
        if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
            trace!(
                "Skipping honk-internal UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }
        if is_broadcast_or_multicast(&original_dst.ip()) {
            trace!(
                "Skipping broadcast/multicast UDP {} -> {}",
                client_addr, original_dst
            );
            #[cfg(feature = "ebpf")]
            if let Some((verdicts, identity)) = &pending {
                verdicts.cancel(*identity).await?;
            }
            return Ok(());
        }

        if !lease.dns_checked() {
            match self
                .dns_controller
                .handle_udp_dns(&data, client_addr, original_dst)
                .await
            {
                Ok(true) => {
                    #[cfg(feature = "ebpf")]
                    if let Some((verdicts, identity)) = &pending {
                        verdicts.cancel(*identity).await?;
                    }
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => {
                    // Keep ordinary UDP forwarding available when DNS control
                    // declines with an error, matching the pre-Task3 path.
                    warn!(
                        "DNS controller error for UDP {} -> {}; continuing UDP: {}",
                        client_addr, original_dst, error
                    );
                }
            }
        }

        let mut quic_domain: Option<String>;
        let mut follower_rx = None;
        let mut sniffed_followers = Vec::new();
        {
            use crate::control::packet_sniffer::QuicSniffOutcome;
            let sniffer_key =
                crate::control::packet_sniffer::PacketSnifferKey::new(client_addr, original_dst);
            let mut outcome = if self.sniffer_pool.is_dcid_failed(&sniffer_key) {
                QuicSniffOutcome::NotQuic
            } else {
                self.sniffer_pool.feed_quic_initial(sniffer_key, &data)
            };
            // A fragmented ClientHello: collect the rest of the Initial
            // flight from the follower queue before deciding.  Deciding on
            // an Incomplete CH could offload or relay a flow whose SNI —
            // still in flight — would have picked another outbound.
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                follower_rx = lease.take_queue_receiver();
                if let Some(rx) = follower_rx.as_mut() {
                    (outcome, sniffed_followers) =
                        self.collect_initial_fragments(sniffer_key, rx).await;
                }
            }
            if matches!(outcome, QuicSniffOutcome::Incomplete) {
                debug!(
                    "QUIC ClientHello unresolved within budget; dropping for retransmit {} -> {}",
                    client_addr, original_dst
                );
                #[cfg(feature = "ebpf")]
                if let Some((verdicts, identity)) = &pending {
                    verdicts.cancel(*identity).await?;
                }
                return Ok(());
            }
            quic_domain = outcome.into_domain();
        }
        if matches!(dial_mode, DialMode::Domain)
            && let Some(domain) = &quic_domain
            && !self.verify_domain_reality(domain, original_dst.ip()).await
        {
            debug!(
                "QUIC domain {} failed reality check against {}, falling back to IP",
                domain,
                original_dst.ip()
            );
            quic_domain = None;
        }

        let route_started_at = std::time::Instant::now();
        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            17, // UDP
        );
        let handoff = self
            .lookup_udp_handoff(&tuples, lease.decision_token())
            .await?;
        let conn_info = ConnectionInfo {
            domain: quic_domain.clone(),
            dst_ip: original_dst.ip(),
            dst_port: original_dst.port(),
            src_ip: client_addr.ip(),
            src_port: client_addr.port(),
            protocol: "udp",
            process_name: handoff.as_ref().and_then(|ho| ho.process_name()),
            mac: handoff.as_ref().and_then(|ho| ho.mac_address()),
            dscp: handoff.as_ref().map(|ho| ho.dscp),
        };

        let reroute_by_sniffed_domain = Self::should_reroute_sniffed_domain(
            dial_mode,
            quic_domain.as_deref(),
            handoff.as_ref(),
        );
        let (userspace_outbound, userspace_must, userspace_mark, matched_rule) = {
            let router = self.router.read().await;
            if let Some(route) = router.route_full(&conn_info) {
                (
                    route.outbound_name.to_string(),
                    route.must,
                    route.mark,
                    Some((route.rule_type.to_string(), route.rule_payload.to_string())),
                )
            } else {
                (router.route(&conn_info).to_string(), false, 0, None)
            }
        };
        let (routed_outbound, must, routed_mark) = if let Some(ho) = &handoff {
            debug!(
                "eBPF handoff UDP: outbound={}, token={}",
                ho.outbound, ho.decision_token
            );
            if ho.outbound == OutboundIndex::ControlPlaneRouting as u8 || reroute_by_sniffed_domain
            {
                (userspace_outbound, userspace_must, userspace_mark)
            } else {
                (
                    self.outbound_index_to_name(ho.outbound).await,
                    ho.must != 0,
                    ho.mark,
                )
            }
        } else {
            (userspace_outbound, userspace_must, userspace_mark)
        };
        #[cfg(feature = "ebpf")]
        let routed_direct = routed_outbound == "direct";
        let outbound_name = self.apply_mode_override(routed_outbound, must).await;
        #[cfg(feature = "ebpf")]
        let final_rule_mark = final_udp_rule_mark(routed_direct, &outbound_name, routed_mark);
        #[cfg(not(feature = "ebpf"))]
        let _ = routed_mark;
        self.stats
            .record_udp_route_latency(route_started_at.elapsed());
        #[cfg(feature = "ebpf")]
        if let Some((verdicts, identity)) = &pending {
            match outbound_name.as_str() {
                "direct" => {
                    verdicts
                        .activate_direct(*identity, &mut lease, final_rule_mark)
                        .await?;
                    if let Some(domain) = &quic_domain
                        && Self::should_write_sniffed_domain_bitmap(
                            handoff.as_ref(),
                            reroute_by_sniffed_domain,
                        )
                    {
                        self.push_sniffed_domain_bitmap(&conn_info, domain, original_dst.ip())
                            .await;
                    }
                    return Ok(());
                }
                "block" => {
                    verdicts.block(*identity, &mut lease).await?;
                    return Ok(());
                }
                _ => {
                    let final_outbound = self.outbound_name_to_index(&outbound_name).await;
                    verdicts
                        .activate_proxy(*identity, &lease, final_outbound, final_rule_mark)
                        .await?;
                }
            }
        }
        // This guard is created exactly once and is transferred to Ready only
        // after a real driver has reached its barrier.
        lease.set_connection_guard(self.stats.track_connection(&outbound_name));

        let requested_ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (plan, selection_chain) = {
            let config = self.config.read().await;
            let gm = self.group_manager.read();
            let plan = resolve_udp_outbound_plan(&config, &gm, &outbound_name, requested_ipver);
            let selection_chain =
                gm.selection_chain_for_network(&outbound_name, SelectionNetwork::Udp);
            (plan, selection_chain)
        };

        if plan.nodes.is_empty() {
            warn!(
                "No available candidate nodes for UDP outbound '{}' ({})",
                outbound_name, client_addr
            );
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name);
            return Ok(());
        }

        let connect_timeout = {
            let config = self.config.read().await;
            std::time::Duration::from_millis(config.global.connect_timeout_ms)
        };

        // Cold URLTest preparation owns no endpoint state: no lease binding,
        // reply socket, driver, tracker, or application packet exists until
        // a single eligible transport winner has been drained and accepted.
        let scheduler_ipver = plan.ipver;
        let plan_mode = plan.mode;
        let runtime_generation = self.runtime_registry.read().clone();
        let prepare: UdpPrepare<honk_outbound::proxy::PreparedUdpTransport> = {
            let registry = self.proxy_registry.clone();
            let stats = self.stats.clone();
            Arc::new(move |node: Node| {
                let registry = registry.clone();
                let stats = stats.clone();
                let runtime_generation = Arc::clone(&runtime_generation);
                Box::pin(async move {
                    let dial_started_at = std::time::Instant::now();
                    let result = if plan_mode == SelectionPlanMode::ColdUrlTest {
                        registry
                            .dial_udp_transport_speculative(
                                runtime_generation,
                                node.id,
                                original_dst,
                                None,
                                connect_timeout,
                            )
                            .await
                    } else {
                        registry
                            .dial_udp_transport_runtime(
                                runtime_generation,
                                node.id,
                                original_dst,
                                None,
                                connect_timeout,
                            )
                            .await
                            .map(honk_outbound::proxy::PreparedUdpTransport::ready)
                    };
                    stats.record_udp_dial_latency(dial_started_at.elapsed());
                    result
                })
            })
        };
        let callbacks = UdpStaggerCallbacks {
            is_eligible: {
                let group_manager = self.group_manager.clone();
                Arc::new(move |node| {
                    group_manager.read().is_node_selectable_for_domain(
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                Arc::new(move |node| {
                    alive_set.report_unavailable_traffic(
                        node.id,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    );
                    alive_set.record_dial_failure(node.id, ProbeDomain::DataUdp, scheduler_ipver);
                    alive_set.notify_check_tcp(node.id);
                })
            },
            on_attempt: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_attempt())
            },
            on_winner: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_winner())
            },
            on_cancellation: {
                let stats = self.stats.clone();
                Arc::new(move || stats.record_udp_stagger_cancellation())
            },
        };
        let Some((node, prepared_transport)) =
            prepare_udp_plan(plan_mode, plan.nodes, prepare, callbacks).await
        else {
            debug!(
                "All UDP transport preparations failed for '{}'",
                outbound_name
            );
            self.stats.record_error(&outbound_name);
            return Ok(());
        };

        // The prepared winner is bound only after every speculative loser has
        // been aborted/drained. Close the death-before-bind race again before
        // creating any endpoint state or allowing the Task 3 driver to send.
        if !lease.bind_selected_node(node.id) {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before winner bind"
            ));
        }
        if !lease.still_initializing()
            || !self.group_manager.read().is_node_selectable_for_domain(
                node.id,
                ProbeDomain::DataUdp,
                scheduler_ipver,
            )
        {
            lease.clear_selected_node();
            return Err(anyhow::anyhow!(
                "UDP winner '{}' became ineligible before endpoint setup",
                node.name
            ));
        }
        // Promotion is explicit and still pre-publication: detached AnyTLS
        // sessions and QUIC clients become generation-owned only for the
        // finalized winner.
        let transport = prepared_transport.commit().await?;

        // Both capacity (at reservation time) and anyfrom creation happen
        // after the winner is finalized and before the only first send. Any
        // failure is fail-closed; there is no listener-socket fallback.
        let reply_ready_started = std::time::Instant::now();
        let reply_socket = match self.udp_pool.create_reply_socket(original_dst) {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                self.stats
                    .record_udp_reply_ready_latency(reply_ready_started.elapsed());
                self.stats.record_error(&outbound_name);
                return Err(error.into());
            }
        };
        self.stats
            .record_udp_reply_ready_latency(reply_ready_started.elapsed());

        let relay_addr = transport.relay_addr();
        let endpoint = Arc::new(UdpEndpoint::new(transport, relay_addr, node.id));
        endpoint.record_pending_reply_peer(relay_addr);

        let conn_id = uuid::Uuid::new_v4().to_string();
        let (rule, rule_payload) = matched_rule
            .clone()
            .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
        let chains = connection_chains(selection_chain, &node.name);
        let (conn_upload, conn_download) = endpoint.byte_counters();
        self.connection_tracker
            .register(crate::connection_tracker::ConnectionEntry {
                id: conn_id.clone(),
                source: client_addr.to_string(),
                destination: original_dst.to_string(),
                proxy: node.name.clone(),
                rule,
                rule_payload,
                chains,
                upload: conn_upload,
                download: conn_download,
                start_time: std::time::Instant::now(),
                domain: quic_domain.clone(),
                network: "udp".to_string(),
                process: handoff.as_ref().and_then(|ho| ho.process_name()),
                process_path: None,
            });
        endpoint.set_tracker(conn_id.clone());
        if !lease.set_tracker_id(conn_id.clone()) {
            // The generation was cancelled between route selection and
            // registration. No pool entry owns this tracker, so retire it
            // directly rather than leaking it.
            self.connection_tracker.remove(&conn_id);
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before tracker attachment"
            ));
        }

        let queue_rx = match follower_rx {
            // Already taken while collecting a fragmented ClientHello.
            Some(rx) => rx,
            None => lease.take_queue_receiver().ok_or_else(|| {
                anyhow::anyhow!("UDP initializer lost its bounded queue before driver start")
            })?,
        };
        let mut driver = self.udp_pool.spawn_driver(
            client_addr,
            original_dst,
            lease.generation(),
            lease.decision_token(),
            Arc::clone(&endpoint),
            queue_rx,
            reply_socket,
            self.alive_set.clone(),
            self.stats.clone(),
            outbound_name.clone(),
        );
        driver.wait_ready().await?;
        if !lease.still_initializing() {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was retired before ready commit"
            ));
        }
        if !lease.commit_ready(Arc::clone(&endpoint)) {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before ready commit"
            ));
        }
        let first = lease.take_first().ok_or_else(|| {
            anyhow::anyhow!("UDP initializer lost its first packet before driver start")
        })?;
        driver.start_with_followers(first, sniffed_followers)?;
        self.spawn_process_path_enrichment(conn_id, handoff.as_ref());
        if let Err(error) = driver.wait_first_ack().await {
            // PacketTransport Err and timeout are ambiguous: the winner may
            // have received part of the initial flight, so never replay it.
            self.stats.record_error(&outbound_name);
            return Err(error.into());
        }
        debug!(
            "Proxying UDP {} -> {} via {} (endpoint driver ready)",
            client_addr, original_dst, node.name
        );
        Ok(())
    }

    /// Publish the matched sniffed-domain bitmap so later route-time
    /// decisions can use the learned destination IP. Best-effort: a write
    /// failure never fails the flow.
    async fn push_sniffed_domain_bitmap(
        &self,
        conn_info: &ConnectionInfo,
        domain: &str,
        dst_ip: std::net::IpAddr,
    ) {
        let (rule_name, bitmaps) = {
            let router = self.router.read().await;
            match router.route_full(conn_info) {
                Some(matched) => {
                    let rule_name = matched.rule_name.to_string();
                    let bitmaps = {
                        let db = DOMAIN_BITMAPS.read();
                        db.get(&rule_name).cloned().unwrap_or_default()
                    };
                    (rule_name, bitmaps)
                }
                None => return,
            }
        };
        if bitmaps.is_empty() {
            return;
        }
        let mut merged = DomainRouting::default();
        for bm in &bitmaps {
            for (word, value) in merged.bitmap.iter_mut().zip(bm.bitmap) {
                *word |= value;
            }
        }
        let prefix_len = if dst_ip.is_ipv4() { 32 } else { 128 };
        let prefix = format!("{dst_ip}/{prefix_len}");
        let Ok(lpm_key) = cidr_to_lpm_key(&prefix) else {
            return;
        };
        let mut ebpf = self.ebpf.write().await;
        match ebpf.add_domain_ip_bitmap(&lpm_key, &merged) {
            Ok(()) => debug!(
                "DOMAIN_ROUTING_MAP updated: {} -> {} (rule '{}')",
                dst_ip, domain, rule_name
            ),
            Err(error) => warn!(
                "Failed to update DOMAIN_ROUTING_MAP for {} ({}): {}",
                dst_ip, domain, error
            ),
        }
    }

    /// A fragmented ClientHello: feed queued follower Initials to the
    /// sniffer until it resolves, or the packet/time budget runs out.
    /// Fragments of one flight arrive back-to-back, so the budget is small
    /// and the common single-Initial path never enters this loop. Retained
    /// followers are returned in receive order for the canonical UDP
    /// endpoint driver.
    async fn collect_initial_fragments(
        &self,
        sniffer_key: crate::control::packet_sniffer::PacketSnifferKey,
        rx: &mut tokio::sync::mpsc::Receiver<crate::control::udp_endpoint::QueuedDatagram>,
    ) -> (
        crate::control::packet_sniffer::QuicSniffOutcome,
        Vec<crate::control::udp_endpoint::QueuedDatagram>,
    ) {
        use crate::control::packet_sniffer::QuicSniffOutcome;
        const MAX_FRAGMENTS: u32 = 8;
        const MAX_WAIT: Duration = Duration::from_millis(250);
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        let mut outcome = QuicSniffOutcome::Incomplete;
        let mut collected = Vec::with_capacity(MAX_FRAGMENTS as usize);
        for _ in 0..MAX_FRAGMENTS {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(datagram)) => {
                    outcome = self
                        .sniffer_pool
                        .feed_quic_initial(sniffer_key, datagram.payload());
                    collected.push(datagram);
                    if !matches!(outcome, QuicSniffOutcome::Incomplete) {
                        break;
                    }
                }
                _ => break,
            }
        }
        (outcome, collected)
    }

    /// Race the candidate dials: the first success wins, losers are
    /// cancelled, and fresh connections for losers are deposited into the
    /// pool (≤2 per race, off the critical path). Failures are reported via
    /// traffic-based thresholds to avoid killing a node from a single
    /// transient failure. Returns the winning stream and its index into
    /// `candidates`; `None` means every candidate failed (already logged) —
    /// close-accounting stays with the caller.
    #[allow(clippy::too_many_arguments)]
    async fn race_candidates(
        &self,
        candidates: &[&Node],
        resolved_target: SocketAddr,
        target_domain: Option<String>,
        outbound_name: &str,
        connect_timeout: Duration,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        ipver: IpVersion,
        cold_urltest: bool,
    ) -> Option<(crate::proxy::ProxyStream, usize)> {
        let dial_deadline = {
            let config = self.config.read().await;
            let per_node_ms = config.global.connect_timeout_ms.max(1000);
            let overall_ms = (per_node_ms * 4).max(10000);
            tokio::time::Instant::now() + std::time::Duration::from_millis(overall_ms)
        };
        let ctx = self.clone();
        let target = resolved_target;
        let outbound = outbound_name.to_string();

        let mut set = tokio::task::JoinSet::new();
        for (idx, node) in candidates.iter().enumerate() {
            let ctx = ctx.clone();
            let node = (*node).clone();
            let target_domain = target_domain.clone();
            let generation = Arc::clone(&runtime_generation);
            set.spawn(async move {
                if cold_urltest {
                    // Absolute releases make only candidate zero immediate;
                    // unreleased work has no dial permit and abort_all()
                    // cancels it before it can start.
                    wait_for_cold_urltest_release(idx).await;
                }
                let start = std::time::Instant::now();
                let per_dial_timeout = connect_timeout * 3;
                let result = tokio::time::timeout(
                    per_dial_timeout,
                    Self::dial_pooled(
                        &ctx.proxy_registry,
                        &ctx.connection_pool,
                        &generation,
                        &node,
                        target,
                        target_domain.as_deref(),
                        connect_timeout,
                    ),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "dial timed out after {:?}",
                        per_dial_timeout
                    ))
                });
                let elapsed = start.elapsed();
                (result, idx, elapsed)
            });
        }

        let mut last_err: Option<(String, String)> = None;
        let mut first_err: Option<(String, String)> = None;
        let mut timeout_count: usize = 0;
        let mut winner: Option<(crate::proxy::ProxyStream, usize)> = None;
        let mut remaining = set.len();

        loop {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            match tokio::time::timeout_at(dial_deadline, set.join_next()).await {
                Ok(Some(task_result)) => match task_result {
                    Ok((Ok((stream, fresh)), idx, elapsed)) => {
                        let node = &candidates[idx];
                        ctx.alive_set
                            .report_available_traffic(node.id, ProbeDomain::Tcp, ipver);
                        // Real-traffic degradation fast path: a fresh
                        // network dial far above the node's own EMA
                        // counts toward strike demotion (3 in a row);
                        // the emergency probe verifies the suspicion.
                        if fresh
                            && ctx.alive_set.report_dial_latency(
                                node.id,
                                ProbeDomain::Tcp,
                                ipver,
                                elapsed,
                            )
                        {
                            ctx.alive_set.notify_check_tcp(node.id);
                        }
                        winner = Some((stream, idx));
                        set.abort_all();
                        break;
                    }
                    Ok((Err(e), idx, _elapsed)) => {
                        let node = &candidates[idx];
                        debug!("Parallel dial to {} failed: {}", node.name, e);
                        ctx.stats.record_error(&outbound);
                        ctx.alive_set
                            .report_unavailable_traffic(node.id, ProbeDomain::Tcp, ipver);
                        ctx.alive_set
                            .record_dial_failure(node.id, ProbeDomain::Tcp, ipver);
                        ctx.alive_set.notify_check_tcp(node.id);
                        let msg = e.to_string();
                        if msg.starts_with("dial timed out after") {
                            timeout_count += 1;
                        }
                        if first_err.is_none() {
                            first_err = Some((msg.clone(), node.name.clone()));
                        }
                        if remaining == 0 {
                            last_err = Some((msg, node.name.clone()));
                        }
                    }
                    Err(_join_err) => {}
                },
                Ok(None) => break,
                Err(_elapsed) => {
                    set.abort_all();
                    warn!(
                        "Overall dial deadline reached for outbound '{}' ({} candidates, {} remaining)",
                        outbound_name,
                        candidates.len(),
                        remaining
                    );
                    break;
                }
            }
        }

        // Drain any remaining aborted tasks to avoid JoinSet drop panic.
        while (set.join_next().await).is_some() {}

        // Deposit fresh connections for losing candidates into the pool
        // so the pool stays warm after a parallel-dial race. Limit to 2 deposits
        // per race to avoid thundering herd on the proxy servers.
        // Ready-capable handlers get a fully-dialed stream (handshake
        // included, paid off the critical path); others get a bare TCP.
        if outbound_name != "direct"
            && outbound_name != "block"
            && let Some((_, winning_idx)) = &winner
        {
            let mut deposit_count = 0u32;
            for (idx, node) in candidates.iter().enumerate() {
                if idx == *winning_idx {
                    continue;
                }
                if deposit_count >= 2 {
                    break;
                }
                let node = (*node).clone();
                let node_addr = format!("{}:{}", node.host(), node.port);
                let pool = ctx.connection_pool.clone();
                let registry = ctx.proxy_registry.clone();
                let target_domain = target_domain.clone();
                let generation = Arc::clone(&runtime_generation);
                tokio::spawn(async move {
                    let (ready_capable, bare_capable) = registry
                        .find(node.protocol)
                        .map(|entry| {
                            (
                                (entry.descriptor.pool_ready_streams)(&node),
                                (entry.descriptor.pool_bare_tcp)(&node),
                            )
                        })
                        .unwrap_or((false, false));
                    if ready_capable {
                        let key =
                            ConnectionPool::ready_key(&node_addr, target, target_domain.as_deref());
                        // Only hot targets earn a speculative ready
                        // dial; a one-off flow gets none.
                        let Some(_warm_guard) = pool.try_begin_warm(&key) else {
                            return;
                        };
                        let _dial_permit = generation.acquire_dial_permit().await;
                        match registry
                            .dial_runtime(
                                generation,
                                node.id,
                                target,
                                target_domain.as_deref(),
                                connect_timeout,
                            )
                            .await
                        {
                            Ok(stream) => {
                                pool.deposit_ready(&key, stream).await;
                            }
                            Err(e) => {
                                debug!(
                                    "Post-race pool deposit: ready dial to {} via {} failed: {}",
                                    target, node_addr, e
                                );
                            }
                        }
                        return;
                    }
                    if !bare_capable {
                        // Multiplexed protocols pool whole sessions
                        // instead; a bare TCP is useless to them.
                        return;
                    }
                    let _dial_permit = generation.acquire_dial_permit().await;
                    match honk_outbound::util::connect_outbound(&node_addr, connect_timeout).await {
                        Ok(stream) => {
                            if is_tcp_stream_alive(&stream) {
                                pool.deposit_tcp(&node_addr, stream).await;
                            } else {
                                debug!("Post-race pool deposit: stream to {} is dead", node_addr);
                            }
                        }
                        Err(e) => {
                            debug!(
                                "Post-race pool deposit: connect to {} failed: {}",
                                node_addr, e
                            );
                        }
                    }
                });
                deposit_count += 1;
            }
        }

        match winner {
            Some((s, idx)) => Some((s, idx)),
            None => {
                if let Some((last_msg, last_name)) = last_err {
                    let (first_msg, first_name) =
                        first_err.unwrap_or_else(|| (last_msg.clone(), last_name.clone()));
                    if outbound_name == "direct" || outbound_name == "block" {
                        debug!(
                            "Direct/block dial to {} failed ({}): {}",
                            resolved_target, last_name, last_msg
                        );
                    } else {
                        warn!(
                            "All {} candidate(s) failed to dial {} ({} timed out; first error from '{}': {}; last error from '{}': {})",
                            candidates.len(),
                            resolved_target,
                            timeout_count,
                            first_name,
                            first_msg,
                            last_name,
                            last_msg
                        );
                    }
                }
                None
            }
        }
    }

    /// Dial through a node using the TCP connection pool.
    ///
    /// Acquisition order:
    /// 1. a pooled *ready* stream (full handshake already completed for
    ///    this exact node+target) — skips both the TCP connect and the
    ///    protocol handshake;
    /// 2. a pooled raw `TcpStream` to the proxy server — skips the TCP
    ///    connect, protocol handshake still runs via `dial_with_tcp()`;
    /// 3. a fresh full `dial()`.
    ///
    /// Set `HONK_POOL_DISABLE=1` to bypass both pools entirely (fresh dial
    /// every time) — an A/B switch for diagnosing pool-related stalls.
    ///
    /// Returns the stream plus `fresh_network`: false ONLY on a ready-pool
    /// acquire (local pool pop, no network round trip); bare-pool
    /// handshakes, warm logical streams, and fresh dials all perform ≥1
    /// round trip through the node and report true.
    async fn dial_pooled(
        registry: &ProxyRegistry,
        pool: &ConnectionPool,
        generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<(crate::proxy::ProxyStream, bool)> {
        static POOL_DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let pool_disabled = *POOL_DISABLED.get_or_init(|| {
            std::env::var("HONK_POOL_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });

        let addr = format!("{}:{}", node.host(), node.port);
        let entry = registry
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;

        if !pool_disabled && (entry.descriptor.pool_ready_streams)(node) {
            let key = ConnectionPool::ready_key(&addr, target, target_domain);
            if let Some(stream) = pool.acquire_ready(&key).await {
                tracing::debug!(
                    "Pooled ready stream via {} acquired for {} (handshake skipped)",
                    addr,
                    target
                );
                return Ok((stream, false));
            }
        }

        // Ready streams paid their connect and protocol handshake before
        // entering this path. For a pool miss, gate only work that can open
        // a physical connection: a warm generation-owned QUIC/AnyTLS runtime
        // merely opens a logical stream on its retained transport.
        let reuses_generation_transport = entry.descriptor.has_generation_runtime(node)
            && generation
                .get(&node.id)
                .is_some_and(|runtime| runtime.is_warm_or_stateless());
        let _dial_permit = if matches!(node.protocol, NodeProtocol::Direct | NodeProtocol::Block)
            || reuses_generation_transport
        {
            None
        } else {
            Some(generation.acquire_dial_permit().await)
        };

        // A raw pooled TCP still needs its protocol handshake. Multiplexed
        // protocols opt out because their node runtime owns the transport.
        if !pool_disabled
            && (entry.descriptor.pool_bare_tcp)(node)
            && let Some(tcp) = pool.acquire_tcp(&addr).await
        {
            tracing::debug!("Pooled TCP to {} acquired for {}", addr, target);
            return entry
                .tcp
                .dial_with_tcp(node, target, target_domain, tcp, connect_timeout)
                .await
                .map(|stream| (stream, true));
        }

        // Pool miss (or pools disabled) — fresh connect through the
        // flow's pinned generation. A candidate absent from the generation
        // (e.g. a hand-built test config without the built-in nodes
        // injected) falls back to the stateless node-based dial.
        tracing::debug!("Fresh TCP connect to {} for {}", addr, target);
        if generation.get(&node.id).is_some() {
            registry
                .dial_runtime(
                    Arc::clone(generation),
                    node.id,
                    target,
                    target_domain,
                    connect_timeout,
                )
                .await
                .map(|stream| (stream, true))
        } else {
            entry
                .tcp
                .dial(node, target, target_domain, connect_timeout)
                .await
                .map(|stream| (stream, true))
        }
    }
}

/// Outcome of comparing a connection destination IP against DNS answers for
/// the sniffed domain (`dial_mode: domain` reality check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RealityOutcome {
    /// Exact IP present in the same-family answer set.
    ExactMatch,
    /// No answers for the connection's family, but the other family has
    /// records — trust SNI (Happy Eyeballs / Ipv4Only DNS / single-stack auth).
    OtherFamilyOnly,
    /// Same-family answers exist but do not contain the destination, or the
    /// domain did not resolve at all.
    Mismatch,
}

/// Pure reality-check decision (unit-tested). See [`ControlPlane::verify_domain_reality`].
pub(super) fn domain_reality_outcome(
    expected: std::net::IpAddr,
    ipv4: &[std::net::IpAddr],
    ipv6: &[std::net::IpAddr],
) -> RealityOutcome {
    match expected {
        std::net::IpAddr::V4(v4) => {
            if ipv4.iter().any(|ip| ip == &std::net::IpAddr::V4(v4)) {
                RealityOutcome::ExactMatch
            } else if ipv4.is_empty() && !ipv6.is_empty() {
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
        std::net::IpAddr::V6(v6) => {
            if ipv6.iter().any(|ip| ip == &std::net::IpAddr::V6(v6)) {
                RealityOutcome::ExactMatch
            } else if ipv6.is_empty() && !ipv4.is_empty() {
                // The m-team.cc / Cloudflare IPv6 case: client dials AAAA anycast
                // while our resolver (often Ipv4Only) only has A records.
                RealityOutcome::OtherFamilyOnly
            } else {
                RealityOutcome::Mismatch
            }
        }
    }
}

#[cfg(test)]
mod sniffed_domain_routing_tests {
    use super::*;

    fn handoff(outbound: u8, must: u8) -> HandoffResult {
        HandoffResult {
            outbound,
            must,
            mark: 0,
            decision_token: 0,
            dscp: 0,
            mac: [0; 6],
            pname: [0; 16],
            pid: 0,
        }
    }

    #[test]
    fn udp_direct_mark_preserves_rule_and_clears_override() {
        assert_eq!(final_udp_rule_mark(true, "direct", 0x1234), 0x1234);
        assert_eq!(final_udp_rule_mark(false, "direct", 0x1234), 0);
        assert_eq!(final_udp_rule_mark(false, "proxy", 0x1234), 0x1234);
    }

    #[test]
    fn udp_domain_modes_reroute_preliminary_group_handoffs() {
        let group = handoff(OutboundIndex::UserBase as u8, 0);
        for mode in [
            DialMode::Domain,
            DialMode::DomainPlus,
            DialMode::DomainPlusPlus,
        ] {
            assert!(ControlPlaneHandle::should_reroute_sniffed_domain(
                mode,
                Some("www.youtube.com"),
                Some(&group)
            ));
        }
    }

    #[test]
    fn tcp_domain_writeback_includes_preliminary_handoffs() {
        for outbound in [OutboundIndex::Direct as u8, OutboundIndex::UserBase as u8] {
            assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
                Some(&handoff(outbound, 0)),
                true,
            ));
        }
        assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
            Some(&handoff(OutboundIndex::ControlPlaneRouting as u8, 0)),
            false,
        ));
        assert!(ControlPlaneHandle::should_write_sniffed_domain_bitmap(
            None, false,
        ));
        assert!(!ControlPlaneHandle::should_write_sniffed_domain_bitmap(
            Some(&handoff(OutboundIndex::Direct as u8, 0)),
            false,
        ));
    }

    #[test]
    fn udp_domain_reroute_preserves_final_decisions() {
        let group = handoff(OutboundIndex::UserBase as u8, 0);
        assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
            DialMode::Ip,
            Some("www.youtube.com"),
            Some(&group)
        ));
        assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
            DialMode::DomainPlusPlus,
            None,
            Some(&group)
        ));
        assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
            DialMode::DomainPlusPlus,
            Some("www.youtube.com"),
            Some(&handoff(OutboundIndex::Block as u8, 0))
        ));
        assert!(!ControlPlaneHandle::should_reroute_sniffed_domain(
            DialMode::DomainPlusPlus,
            Some("www.youtube.com"),
            Some(&handoff(OutboundIndex::UserBase as u8, 1))
        ));
    }

    #[tokio::test]
    async fn handoff_process_fields_decode_and_fail_closed() {
        let mut ho = handoff(OutboundIndex::UserBase as u8, 0);
        assert_eq!(ho.process_name(), None, "zeroed pname means no process");
        assert_eq!(ho.process_path().await, None, "pid 0 means no process");

        ho.pname[..4].copy_from_slice(b"curl");
        assert_eq!(ho.process_name().as_deref(), Some("curl"));

        ho.pid = std::process::id();
        assert!(ho.process_path().await.is_some());
        // A dead/invalid pid just omits the path instead of erroring.
        ho.pid = u32::MAX;
        assert_eq!(ho.process_path().await, None);
    }
}

#[cfg(test)]
mod cold_urltest_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn cold_urltest_releases_candidates_progressively_and_cancels_waiters() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..3 {
            let started = Arc::clone(&started);
            tasks.spawn(async move {
                wait_for_cold_urltest_release(index).await;
                started.fetch_add(1, Ordering::AcqRel);
            });
        }
        tokio::task::yield_now().await;
        assert_eq!(
            started.load(Ordering::Acquire),
            1,
            "only the first candidate is immediate"
        );
        tokio::time::advance(COLD_URLTEST_STAGGER).await;
        tokio::task::yield_now().await;
        assert_eq!(
            started.load(Ordering::Acquire),
            2,
            "the second candidate releases after one delay"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        tokio::time::advance(COLD_URLTEST_STAGGER * 2).await;
        tokio::task::yield_now().await;
        assert_eq!(
            started.load(Ordering::Acquire),
            2,
            "cancelled unreleased candidate must not start"
        );
    }
}

#[cfg(test)]
mod tcp_flow_lifecycle_tests {
    use super::*;
    use crate::connection_tracker::ConnectionEntry;
    use crate::ebpf::mock::MockEbpfBackend;
    use honk_ebpf_common::RedirectTuple;
    use honk_ebpf_common::conn::{ConnState, TcpState};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;

    fn forward_tuple() -> TuplesKey {
        build_tuples_key(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            50_000,
            6,
        )
    }

    fn reverse_tuple() -> TuplesKey {
        build_tuples_key(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            50_000,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            443,
            6,
        )
    }

    fn set_padding(tuple: &mut TuplesKey, padding: [u8; 3]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                padding.as_ptr(),
                (tuple as *mut TuplesKey).cast::<u8>().add(37),
                padding.len(),
            );
        }
    }

    fn backend() -> Arc<RwLock<Box<dyn EbpfBackend>>> {
        Arc::new(RwLock::new(Box::new(MockEbpfBackend::new())))
    }

    fn tracked_entry(id: &str) -> ConnectionEntry {
        ConnectionEntry {
            id: id.to_string(),
            source: "192.0.2.1:50000".to_string(),
            destination: "203.0.113.2:443".to_string(),
            proxy: "direct".to_string(),
            rule: "Fallback".to_string(),
            rule_payload: String::new(),
            chains: vec!["direct".to_string()],
            upload: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            download: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            start_time: std::time::Instant::now(),
            domain: None,
            network: "tcp".to_string(),
            process: None,
            process_path: None,
        }
    }

    async fn tcp_pair() -> anyhow::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let connect = TcpStream::connect(addr);
        let (accepted, peer) = tokio::join!(listener.accept(), connect);
        Ok((accepted?.0, peer?))
    }

    #[test]
    fn directional_key_ignores_padding_and_refcounts_owners() {
        let mut first = forward_tuple();
        let mut second = forward_tuple();
        set_padding(&mut first, [1, 2, 3]);
        set_padding(&mut second, [4, 5, 6]);
        let key = TcpFlowKey::from_tuples(&first);

        assert_eq!(key, TcpFlowKey::from_tuples(&second));
        assert_eq!(
            key,
            TcpFlowKey::from_redirect(&RedirectTuple::from_tuples(&first))
        );
        let reverse = TcpFlowKey::from_tuples(&reverse_tuple());
        assert_ne!(key, reverse);

        let pins = TcpFlowPins::default();
        pins.retain(key);
        pins.retain(key);
        pins.retain(reverse);
        assert_eq!(pins.snapshot().len(), 2);
        assert_eq!(pins.release(key), Some(false));
        assert!(pins.snapshot().contains(&key));
        assert_eq!(pins.release(key), Some(true));
        assert!(!pins.snapshot().contains(&key));
        assert!(pins.snapshot().contains(&reverse));
        assert_eq!(pins.release(key), None);
        assert_eq!(pins.release(reverse), Some(true));
        assert!(pins.snapshot().is_empty());
    }

    #[tokio::test]
    async fn tcp_flow_guard_abort_releases_pin_tracker_and_socket() -> anyhow::Result<()> {
        let (stream, mut peer) = tcp_pair().await?;
        let pins = Arc::new(TcpFlowPins::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let mut flow = TcpFlowGuard::new(
            stream,
            forward_tuple(),
            Arc::clone(&pins),
            backend(),
            Arc::clone(&tracker),
        );
        flow.track(tracked_entry("abort"));
        assert_eq!(pins.snapshot().len(), 1);
        assert_eq!(tracker.snapshot().len(), 1);

        let task = tokio::spawn(async move {
            let _flow = flow;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(pins.snapshot().is_empty());
        assert!(tracker.snapshot().is_empty());

        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn tcp_retire_waits_for_final_owner() -> anyhow::Result<()> {
        let tuple = forward_tuple();
        let backend = backend();
        backend.write().await.tcp_conn_state_store(
            &tuple,
            &ConnState {
                state: TcpState::TcpStateActive as u8,
                last_seen_ns: 0,
                ..Default::default()
            },
        )?;
        let pins = Arc::new(TcpFlowPins::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let (first_stream, _first_peer) = tcp_pair().await?;
        let (second_stream, _second_peer) = tcp_pair().await?;
        let first = TcpFlowGuard::new(
            first_stream,
            tuple,
            Arc::clone(&pins),
            Arc::clone(&backend),
            Arc::clone(&tracker),
        );
        let second = TcpFlowGuard::new(
            second_stream,
            tuple,
            Arc::clone(&pins),
            Arc::clone(&backend),
            tracker,
        );

        first.retire().await;
        assert!(
            backend
                .read()
                .await
                .tcp_conn_state_lookup(&tuple)?
                .is_some()
        );
        assert!(pins.snapshot().contains(&TcpFlowKey::from_tuples(&tuple)));

        second.retire().await;
        assert!(
            backend
                .read()
                .await
                .tcp_conn_state_lookup(&tuple)?
                .is_none()
        );
        assert!(pins.snapshot().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn tcp_retire_preserves_newer_incarnation() -> anyhow::Result<()> {
        let tuple = forward_tuple();
        let reverse = reverse_tuple();
        let old = ConnState {
            state: TcpState::TcpStateActive as u8,
            last_seen_ns: 0,
            ..Default::default()
        };
        let backend = backend();
        {
            let mut backend = backend.write().await;
            backend.tcp_conn_state_store(&tuple, &old)?;
            backend.tcp_conn_state_store(&reverse, &old)?;
        }

        let pins = Arc::new(TcpFlowPins::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let (stream, mut peer) = tcp_pair().await?;
        let mut flow = TcpFlowGuard::new(
            stream,
            tuple,
            Arc::clone(&pins),
            Arc::clone(&backend),
            Arc::clone(&tracker),
        );
        flow.track(tracked_entry("replacement"));

        let mut backend_guard = backend.write().await;
        let retire = tokio::spawn(flow.retire());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !tracker.snapshot().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        backend_guard.tcp_conn_state_store(
            &tuple,
            &ConnState {
                last_seen_ns: u64::MAX,
                ..old
            },
        )?;
        drop(backend_guard);
        retire.await?;

        let backend = backend.read().await;
        assert_eq!(
            backend
                .tcp_conn_state_lookup(&tuple)?
                .expect("replacement state")
                .last_seen_ns,
            u64::MAX
        );
        assert!(backend.tcp_conn_state_lookup(&reverse)?.is_some());
        drop(backend);
        assert!(pins.snapshot().is_empty());
        assert!(tracker.snapshot().is_empty());
        let mut byte = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??,
            0
        );
        Ok(())
    }
}

#[cfg(test)]
mod dial_permit_scope_tests {
    use super::*;

    #[tokio::test]
    async fn ready_pool_hit_does_not_wait_for_physical_dial_permit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let mut node = Node {
            name: "ready-socks".into(),
            protocol: NodeProtocol::Socks5,
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            ..Default::default()
        };
        node.id = node.derive_id();
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing(
                &[node.clone()],
                1,
                None,
            )
            .unwrap()
            .0,
        );
        let _held = generation.acquire_dial_permit().await;
        let pool = ConnectionPool::new();
        let key =
            ConnectionPool::ready_key(&format!("{}:{}", node.host(), node.port), target, None);
        pool.deposit_ready(
            &key,
            crate::proxy::ProxyStream {
                stream: Box::new(tcp),
                target_addr: target,
                target_domain: None,
            },
        )
        .await;
        let registry = ProxyRegistry::default_resolver().unwrap();

        let (stream, fresh) = tokio::time::timeout(
            Duration::from_millis(100),
            ControlPlaneHandle::dial_pooled(
                &registry,
                &pool,
                &generation,
                &node,
                target,
                None,
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("ready stream must bypass an exhausted physical-dial gate")
        .unwrap();
        assert!(
            !fresh,
            "a ready-pool acquire performs no network round trip"
        );

        drop(stream);
        server.abort();
    }
}
