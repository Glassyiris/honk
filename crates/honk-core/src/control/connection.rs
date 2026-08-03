use super::udp_dial::{UdpPrepare, UdpStaggerCallbacks, prepare_udp_plan};
use super::*;
use crate::control::udp_endpoint::{UdpEndpoint, UdpInitLease};
use crate::group::SelectionPlanMode;

/// Result from the eBPF routing handoff map lookup.
#[derive(Debug, Clone)]
struct HandoffResult {
    outbound: u8,
    mark: u32,
    must: u8,
    dscp: u8,
    mac: [u8; 6],
    pname: [u8; 16],
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

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
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
    pub(super) tcp_sniff_neg_cache: Arc<crate::control::tcp_sniff::TcpSniffNegCache>,
    pub(super) sniffer_pool: Arc<crate::control::packet_sniffer::PacketSnifferPool>,
    pub(super) dns_controller: Arc<crate::control::dns_control::DnsController>,
    pub(super) alive_set: Arc<AliveDialerSet>,
    pub(super) connection_pool: Arc<ConnectionPool>,
    pub(super) connection_tracker: Arc<ConnectionTracker>,
    /// Shared clash mode state (None when the clash API is disabled).
    pub(super) mode_state: Option<crate::mode::SharedModeState>,
}

/// Check whether a connected TCP stream is still alive via SO_ERROR.
///
/// Returns true if the socket is healthy (no pending error).
pub(super) fn is_tcp_stream_alive(stream: &TcpStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut err: libc::c_int = 0;
    let mut err_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut _ as *mut libc::c_void,
            &mut err_len,
        )
    };
    ret == 0 && err == 0
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

impl ControlPlaneHandle {
    /// Look up the eBPF routing handoff entry for a connection, consuming it.
    ///
    /// Only a read lock is taken: `routing_handoff_take` performs raw bpf()
    /// map operations, which the kernel serializes internally — no userspace
    /// backend state is touched.  The lock's sole role here is to keep the
    /// backend (and its map fds) alive against `cleanup()`, which takes the
    /// write lock.
    async fn lookup_handoff(&self, tuples: &TuplesKey) -> Option<HandoffResult> {
        let ebpf = self.ebpf.read().await;
        let entry = ebpf.routing_handoff_take(tuples).ok().flatten();
        drop(ebpf);

        entry.map(|entry| HandoffResult {
            outbound: entry.result.outbound,
            mark: entry.result.mark,
            must: entry.result.must,
            dscp: entry.result.dscp,
            mac: entry.result.mac,
            pname: entry.result.pname,
        })
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
        mut stream: TcpStream,
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

        if let Ok(true) = self
            .dns_controller
            .handle_tcp_dns(&mut stream, client_addr, original_dst)
            .await
        {
            return Ok(());
        }

        let tuples = build_tuples_key(
            original_dst.ip(),
            original_dst.port(),
            client_addr.ip(),
            client_addr.port(),
            6, // TCP
        );

        let handoff = self.lookup_handoff(&tuples).await;

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
            sniffing::sniff_tcp(&mut stream).await
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

        // Determine outbound: prefer eBPF handoff, fall back to userspace
        // Router. `must` marks dae `(must)`-rule results (handoff must flag
        // or a must-matched userspace rule) — final decisions exempt from
        // the clash mode override below.
        //
        // Domain dial modes (domain / domain+ / domain++): an eBPF decision
        // made without domain knowledge (e.g. fallback direct for an
        // unlearned IP) is preliminary — once a domain is sniffed (and, in
        // `domain` mode, verified), re-run the userspace router with it so
        // domain rules apply.  must and block results stay final; only Ip
        // mode takes the handoff decision as-is.
        let reroute_by_sniffed_domain = !matches!(dial_mode, DialMode::Ip)
            && domain.is_some()
            && handoff
                .as_ref()
                .is_some_and(|ho| ho.must == 0 && ho.outbound != OutboundIndex::Block as u8);
        let (outbound_name, must) = if let Some(ref ho) = handoff {
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
        if let Some(ref domain) = domain {
            let is_userspace_route = handoff
                .as_ref()
                .map(|ho| ho.outbound == OutboundIndex::ControlPlaneRouting as u8)
                .unwrap_or(true);
            if is_userspace_route {
                let router = self.router.read().await;
                if let Some(matched) = router.route_full(&conn_info) {
                    let bitmaps = {
                        let db = DOMAIN_BITMAPS.read();
                        db.get(matched.rule_name).cloned().unwrap_or_default()
                    };
                    if !bitmaps.is_empty() {
                        let mut merged = DomainRouting::default();
                        for bm in &bitmaps {
                            for (word, value) in merged.bitmap.iter_mut().zip(bm.bitmap) {
                                *word |= value;
                            }
                        }
                        let prefix_len = if original_dst.ip().is_ipv4() { 32 } else { 128 };
                        let prefix = format!("{}/{}", original_dst.ip(), prefix_len);
                        if let Ok(lpm_key) = cidr_to_lpm_key(&prefix) {
                            let mut ebpf = self.ebpf.write().await;
                            match ebpf.add_domain_ip_bitmap(&lpm_key, &merged) {
                                Err(e) => {
                                    debug!(
                                        "Failed to update DOMAIN_ROUTING_MAP for {}: {}",
                                        original_dst.ip(),
                                        e
                                    );
                                }
                                _ => {
                                    debug!(
                                        "DOMAIN_ROUTING_MAP updated: {} -> {} (rule '{}')",
                                        original_dst.ip(),
                                        domain,
                                        matched.rule_name
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        self.stats.record_connection(&outbound_name);

        let ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let (mut candidates, selection_mode) = {
            let config = self.config.read().await;
            let gm = self.group_manager.read();
            if let Some(group) = config
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
            }
        };
        // Only an unmeasured URLTest group is allowed to speculate. Its
        // candidate set is bounded before spawning so a large group cannot
        // turn one client flow into an unbounded dial storm.
        if selection_mode == SelectionPlanMode::ColdUrlTest {
            candidates.truncate(3);
        } else {
            candidates.truncate(1);
        }

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
            let group_nodes = self
                .group_manager
                .read()
                .leaf_node_names_in_group(&outbound_name);
            for node_name in group_nodes {
                self.alive_set.notify_check_tcp(&node_name);
            }
            self.stats.record_error(&outbound_name);
            self.stats.record_close(&outbound_name);
            return Ok(());
        }

        // SOCKS5, Trojan, Shadowsocks, and AnyTLS support domain-based routing
        // (ATYP_DOMAIN). They resolve the domain on the proxy server side, so
        // client-side DNS is unnecessary. Direct/block use the original_dst IP
        // directly — no DNS needed.
        let all_domain_capable = outbound_name == "direct"
            || outbound_name == "block"
            || candidates.iter().all(|node| {
                use honk_config::types::NodeProtocol;
                matches!(
                    node.protocol,
                    NodeProtocol::Socks5
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

        // Try each candidate node in parallel (happy-eyeballs style).
        // Each task first checks the connection pool: a *ready* stream
        // (protocol handshake already completed for this exact node+target)
        // is reused directly as the data channel; a raw pooled TCP to the
        // proxy server saves the connect RTT and still performs the
        // protocol-level handshake (SOCKS5 CONNECT, etc.).
        // Failed nodes are reported via traffic-based thresholds to avoid
        // killing a node from a single transient failure.
        // The first successful dial wins; remaining tasks are cancelled.
        // An overall deadline prevents blocking indefinitely when all nodes
        // are unreachable or extremely slow.
        let dial_deadline = {
            let config = self.config.read().await;
            let per_node_ms = config.global.connect_timeout_ms.max(1000);
            let overall_ms = (per_node_ms * 4).max(10000);
            tokio::time::Instant::now() + std::time::Duration::from_millis(overall_ms)
        };
        let (mut proxy_stream, node): (crate::proxy::ProxyStream, &Node) = {
            let ctx = self.clone();
            let target = resolved_target;
            let target_domain = target_domain.clone();
            let outbound = outbound_name.clone();

            let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
            let mut set = tokio::task::JoinSet::new();
            for (idx, node) in candidates.iter().enumerate() {
                let ctx = ctx.clone();
                let node = (*node).clone();
                let target_domain = target_domain.clone();
                set.spawn(async move {
                    if cold_urltest {
                        // Absolute releases make only candidate zero immediate;
                        // unreleased work has no dial permit and abort_all()
                        // cancels it before it can start.
                        wait_for_cold_urltest_release(idx).await;
                    }
                    let start = std::time::Instant::now();
                    let per_dial_timeout = connect_timeout * 3;
                    // Built-in direct/block dials are local connects bounded
                    // by the connection admission limit; dead direct peers
                    // must not starve the proxied-dial budget.
                    let _dial_permit = if node.name == "direct" || node.name == "block" {
                        None
                    } else {
                        Some(ConnectionPool::acquire_dial_permit().await)
                    };
                    let result = tokio::time::timeout(
                        per_dial_timeout,
                        Self::dial_pooled(
                            &ctx.proxy_registry,
                            &ctx.connection_pool,
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
                    Ok(Some(task_result)) => {
                        match task_result {
                            Ok((Ok(stream), idx, _elapsed)) => {
                                let node = &candidates[idx];
                                let ipver = if original_dst.is_ipv6() {
                                    IpVersion::V6
                                } else {
                                    IpVersion::V4
                                };
                                ctx.alive_set.report_available_traffic(
                                    &node.name,
                                    ProbeDomain::Tcp,
                                    ipver,
                                );
                                winner = Some((stream, idx));
                                set.abort_all();
                                break;
                            }
                            Ok((Err(e), idx, _elapsed)) => {
                                let node = &candidates[idx];
                                debug!("Parallel dial to {} failed: {}", node.name, e);
                                ctx.stats.record_error(&outbound);
                                let ipver = if original_dst.is_ipv6() {
                                    IpVersion::V6
                                } else {
                                    IpVersion::V4
                                };
                                ctx.alive_set.report_unavailable_traffic(
                                    &node.name,
                                    ProbeDomain::Tcp,
                                    ipver,
                                );
                                ctx.alive_set.record_dial_failure(
                                    &node.name,
                                    ProbeDomain::Tcp,
                                    ipver,
                                );
                                ctx.alive_set.notify_check_tcp(&node.name);
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
                            Err(_join_err) => {
                                // Task was cancelled (abort_all) or panicked — ignore.
                            }
                        }
                    }
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
                    let node = node.clone();
                    let node_addr = format!("{}:{}", node.host(), node.port);
                    let pool = ctx.connection_pool.clone();
                    let registry = ctx.proxy_registry.clone();
                    let target_domain = target_domain.clone();
                    tokio::spawn(async move {
                        let caps = honk_outbound::runtime::OutboundCapabilities::for_node(&node);
                        let (ready_capable, bare_capable) = registry
                            .find(node.protocol)
                            .map(|h| {
                                (
                                    h.pool_ready_streams(&node) && caps.tcp && !caps.multiplexed,
                                    h.pool_bare_tcp(&node),
                                )
                            })
                            .unwrap_or((false, false));
                        if ready_capable {
                            let key = ConnectionPool::ready_key(
                                &node_addr,
                                target,
                                target_domain.as_deref(),
                            );
                            // Only hot targets earn a speculative ready
                            // dial; a one-off flow gets none.
                            let Some(_warm_guard) = pool.try_begin_warm(&key) else {
                                return;
                            };
                            let _dial_permit = ConnectionPool::acquire_dial_permit().await;
                            match registry
                                .dial(&node, target, target_domain.as_deref(), connect_timeout)
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
                        let _dial_permit = ConnectionPool::acquire_dial_permit().await;
                        match honk_outbound::util::connect_outbound(&node_addr, connect_timeout)
                            .await
                        {
                            Ok(stream) => {
                                if is_tcp_stream_alive(&stream) {
                                    pool.deposit_tcp(&node_addr, stream).await;
                                } else {
                                    debug!(
                                        "Post-race pool deposit: stream to {} is dead",
                                        node_addr
                                    );
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
                Some((s, idx)) => (s, &candidates[idx]),
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
                    // Per-candidate failures already counted as errors above;
                    // only balance the active-connections counter here.
                    self.stats.record_close(&outbound_name);
                    return Ok(());
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
        let chains = {
            let gm = self.group_manager.read();
            let mut chain = gm.selection_chain(&outbound_name);
            // Groups without a formed selection (LoadBalance, cold URLTest)
            // stop at the group tag — append the actual dialed leaf.
            if chain.last() != Some(&node.name) {
                chain.push(node.name.clone());
            }
            chain.reverse();
            chain
        };
        // Live byte counters shared with the relay task: it increments them
        // as data flows so /connections shows real-time totals instead of a
        // single close-time (never-visible) update.
        let conn_upload = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        self.connection_tracker
            .register(crate::connection_tracker::ConnectionEntry {
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
            });

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
                self.connection_tracker.remove(&conn_id);
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
                    stream,
                    upstream,
                    client_addr,
                    resolved_target,
                    conn_progress,
                )
                .await
            }
            Err(proxy_stream) => {
                relay::splice::relay_auto(
                    stream,
                    proxy_stream.stream,
                    client_addr,
                    resolved_target,
                    conn_progress,
                )
                .await
            }
        };

        match relay_result {
            Ok(relay_stats) => {
                self.connection_tracker.remove(&conn_id);
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
                    tokio::spawn(async move {
                        let caps = honk_outbound::runtime::OutboundCapabilities::for_node(&node);
                        let (ready_capable, bare_capable) = registry
                            .find(node.protocol)
                            .map(|h| {
                                (
                                    h.pool_ready_streams(&node) && caps.tcp && !caps.multiplexed,
                                    h.pool_bare_tcp(&node),
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
                                .dial(
                                    &node,
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
                self.connection_tracker.remove(&conn_id);
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

        // Event-driven lifecycle: the userspace relay has ended, so this
        // flow's conntrack entries are dead state — retire both directions
        // now instead of leaving them to the datapath/janitor timeouts
        // (the model dae's SessionManager releaseFlow uses).  Late FIN/ACK
        // stragglers hitting an empty entry simply pass through, which is
        // harmless for a closed flow.
        let mut reversed = tuples;
        std::mem::swap(&mut reversed.src_ip, &mut reversed.dst_ip);
        std::mem::swap(&mut reversed.src_port, &mut reversed.dst_port);
        {
            let mut ebpf = self.ebpf.write().await;
            let mut removed = 0u32;
            for key in [&tuples, &reversed] {
                if ebpf.tcp_conn_state_remove(key).is_ok() {
                    removed += 1;
                    crate::ebpf::USERSPACE_CONN_STATE_DELETES
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            debug!(
                "conn-state retire: {} -> {} removed {} entr(ies)",
                client_addr, resolved_target, removed
            );
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

    pub(super) async fn serve_udp_connection(
        &self,
        lease: UdpInitLease,
        udp_socket: Arc<UdpSocket>,
    ) -> anyhow::Result<()> {
        let mut cancellation = lease.cancellation();
        tokio::select! {
            _ = cancellation.changed() => {
                // Dropping the uncommitted lease removes only its generation.
                Ok(())
            }
            result = self.initialize_udp_connection(lease, udp_socket) => result,
        }
    }

    async fn initialize_udp_connection(
        &self,
        mut lease: UdpInitLease,
        udp_socket: Arc<UdpSocket>,
    ) -> anyhow::Result<()> {
        let client_addr = lease.client_addr();
        let original_dst = lease.original_dst();
        let data = lease.first_payload();
        debug!(
            "TPROXY UDP datagram from {} -> {} ({} bytes)",
            client_addr,
            original_dst,
            data.len()
        );

        let connect_timeout = {
            let config = self.config.read().await;
            std::time::Duration::from_millis(config.global.connect_timeout_ms)
        };

        let dial_mode = {
            let config = self.config.read().await;
            config
                .global
                .dial_mode
                .parse::<DialMode>()
                .ok()
                .unwrap_or(DialMode::DomainPlusPlus)
        };

        // These checks remain after the reservation only because DNS and
        // sniffing historically lived in this slow handler. Their early exit
        // drops the lease and therefore releases every reservation resource.
        if is_honk_internal_addr(&original_dst.ip()) || is_honk_internal_addr(&client_addr.ip()) {
            trace!(
                "Skipping honk-internal UDP {} -> {}",
                client_addr, original_dst
            );
            return Ok(());
        }
        if is_broadcast_or_multicast(&original_dst.ip()) {
            trace!(
                "Skipping broadcast/multicast UDP {} -> {}",
                client_addr, original_dst
            );
            return Ok(());
        }

        if !lease.dns_checked() {
            match self
                .dns_controller
                .handle_udp_dns(&udp_socket, &data, client_addr, original_dst)
                .await
            {
                Ok(true) => return Ok(()),
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

        let mut quic_domain: Option<String> = None;
        {
            let sniffer_key =
                crate::control::packet_sniffer::PacketSnifferKey::new(client_addr, original_dst);
            if !self.sniffer_pool.is_dcid_failed(&sniffer_key) {
                quic_domain = self.sniffer_pool.feed_quic_initial(sniffer_key, &data);
            }
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
        let handoff = self.lookup_handoff(&tuples).await;
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
        let (outbound_name, outbound_index, must) = if let Some(ho) = &handoff {
            debug!("eBPF handoff UDP: outbound={}", ho.outbound);
            if ho.outbound == OutboundIndex::ControlPlaneRouting as u8 || reroute_by_sniffed_domain
            {
                let router = self.router.read().await;
                let (name, must) = router.route_with_must(&conn_info);
                (name.to_string(), 0, must)
            } else {
                (
                    self.outbound_index_to_name(ho.outbound).await,
                    ho.outbound,
                    ho.must != 0,
                )
            }
        } else {
            let router = self.router.read().await;
            let (name, must) = router.route_with_must(&conn_info);
            (name.to_string(), 0, must)
        };
        let outbound_name = self.apply_mode_override(outbound_name, must).await;

        let matched_rule = {
            let router = self.router.read().await;
            router
                .route_full(&conn_info)
                .map(|m| (m.rule_type.to_string(), m.rule_payload.to_string()))
        };
        self.stats
            .record_udp_route_latency(route_started_at.elapsed());
        // This guard is created exactly once and is transferred to Ready only
        // after a real driver has reached its barrier.
        lease.set_connection_guard(self.stats.track_connection(&outbound_name));

        let requested_ipver = if original_dst.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        let plan = {
            let config = self.config.read().await;
            let gm = self.group_manager.read();
            resolve_udp_outbound_plan(&config, &gm, &outbound_name, requested_ipver)
        };

        if plan.nodes.is_empty() {
            warn!(
                "No available candidate nodes for UDP outbound '{}' ({})",
                outbound_name, client_addr
            );
            let group_nodes = self
                .group_manager
                .read()
                .leaf_node_names_in_group(&outbound_name);
            for node_name in group_nodes {
                self.alive_set.notify_check_tcp(&node_name);
            }
            self.stats.record_error(&outbound_name);
            return Ok(());
        }

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
                        &node.name,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    )
                })
            },
            on_dial_error: {
                let alive_set = self.alive_set.clone();
                Arc::new(move |node| {
                    alive_set.report_unavailable_traffic(
                        &node.name,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    );
                    alive_set.record_dial_failure(
                        &node.name,
                        ProbeDomain::DataUdp,
                        scheduler_ipver,
                    );
                    alive_set.notify_check_tcp(&node.name);
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
        if !lease.bind_selected_node(&node.name) {
            return Err(anyhow::anyhow!(
                "UDP initializer generation was cancelled before winner bind"
            ));
        }
        if !lease.still_initializing()
            || !self.group_manager.read().is_node_selectable_for_domain(
                &node.name,
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
        // sessions become generation-owned only for the finalized winner.
        let transport = prepared_transport.commit()?;

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
        let endpoint = Arc::new(UdpEndpoint::new(transport, relay_addr, node.name.clone()));
        endpoint.record_pending_reply_peer(relay_addr);
        endpoint.cache_routing_result(original_dst, outbound_index);

        let conn_id = uuid::Uuid::new_v4().to_string();
        let (rule, rule_payload) = matched_rule
            .clone()
            .unwrap_or_else(|| ("Fallback".to_string(), String::new()));
        let chains = {
            let gm = self.group_manager.read();
            let mut chain = gm.selection_chain(&outbound_name);
            if chain.last() != Some(&node.name) {
                chain.push(node.name.clone());
            }
            chain.reverse();
            chain
        };
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

        let queue_rx = lease.take_queue_receiver().ok_or_else(|| {
            anyhow::anyhow!("UDP initializer lost its bounded queue before driver start")
        })?;
        let mut driver = self.udp_pool.spawn_driver(
            client_addr,
            original_dst,
            lease.generation(),
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
        driver.start(first)?;
        if let Err(error) = driver.wait_first_ack().await {
            // PacketTransport Err and timeout are both ambiguous: the winner
            // may have received data, so never replay this packet elsewhere.
            self.stats.record_error(&outbound_name);
            return Err(error.into());
        }
        debug!(
            "Proxying UDP {} -> {} via {} (endpoint driver ready)",
            client_addr, original_dst, node.name
        );
        Ok(())
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
    async fn dial_pooled(
        registry: &ProxyRegistry,
        pool: &ConnectionPool,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: Duration,
    ) -> anyhow::Result<crate::proxy::ProxyStream> {
        // The built-in block node shares NodeProtocol::HTTP with direct;
        // reject here before find() resolves it to DirectHandler (and before
        // any pool lookup under its meaningless ":0" address).
        if node.name == "block" {
            use crate::proxy::ProxyHandler as _;
            return crate::proxy::block::BlockHandler::new()
                .dial(node, target, target_domain, connect_timeout)
                .await;
        }
        static POOL_DISABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let pool_disabled = *POOL_DISABLED.get_or_init(|| {
            std::env::var("HONK_POOL_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        });

        let addr = format!("{}:{}", node.host(), node.port);
        let handler = registry
            .find(node.protocol)
            .ok_or_else(|| anyhow::anyhow!("No handler for protocol {:?}", node.protocol))?;

        if !pool_disabled {
            // Ready pool: a fully-dialed stream bound to this exact
            // node+target. Reused directly as the data channel.
            if handler.pool_ready_streams(node) {
                let key = ConnectionPool::ready_key(&addr, target, target_domain);
                if let Some(stream) = pool.acquire_ready(&key).await {
                    tracing::debug!(
                        "Pooled ready stream via {} acquired for {} (handshake skipped)",
                        addr,
                        target
                    );
                    return Ok(stream);
                }
            }

            // Bare pool: raw TCP to the proxy server. Multiplexed
            // protocols opt out (pool_bare_tcp): their session pool
            // already holds warm connections and a bare hit would force
            // a new mux session per flow.
            if handler.pool_bare_tcp(node)
                && let Some(tcp) = pool.acquire_tcp(&addr).await
            {
                tracing::debug!("Pooled TCP to {} acquired for {}", addr, target);
                return handler
                    .dial_with_tcp(node, target, target_domain, tcp, connect_timeout)
                    .await;
            }
        }

        // Pool miss (or pools disabled) — fresh connect
        tracing::debug!("Fresh TCP connect to {} for {}", addr, target);
        handler
            .dial(node, target, target_domain, connect_timeout)
            .await
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
            dscp: 0,
            mac: [0; 6],
            pname: [0; 16],
        }
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
