use super::routing::connection_chains;
use crate::control::*;
use crate::group::{SelectionNetwork, SelectionPlanMode};
use honk_config::types::NodeProtocol;

const COLD_URLTEST_STAGGER: Duration = Duration::from_millis(200);

/// Wait until this candidate's absolute cold-URLTest release offset. The
/// first candidate starts immediately; sleeping candidates have not acquired
/// a dial permit and are cancelled with their enclosing `JoinSet`.
async fn wait_for_cold_urltest_release(index: usize) {
    if index != 0 {
        tokio::time::sleep(COLD_URLTEST_STAGGER.saturating_mul(index as u32)).await;
    }
}

impl ControlPlaneHandle {
    pub(in crate::control) async fn serve_connection(
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

        let (dial_mode, connect_timeout, dns_resolve_timeout, overall_dial_timeout) = {
            let config = self.config.read().await;
            let connect_timeout_ms = config.global.connect_timeout_ms;
            (
                config
                    .global
                    .dial_mode
                    .parse::<DialMode>()
                    .ok()
                    .unwrap_or(DialMode::DomainPlusPlus),
                Duration::from_millis(connect_timeout_ms),
                Duration::from_millis(config.global.dns_resolve_timeout_ms),
                Duration::from_millis((connect_timeout_ms.max(1000) * 4).max(10000)),
            )
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
            let verified = self
                .verify_domain_reality(d, original_dst.ip(), client_addr.ip())
                .await;
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
        let (userspace_outbound, userspace_must, matched_rule) = {
            let router = self.router.read().await;
            match router.route_full(&conn_info) {
                Some(matched) => (
                    matched.outbound_name.to_owned(),
                    matched.must,
                    Some((
                        matched.rule_type.to_owned(),
                        matched.rule_payload.to_owned(),
                    )),
                ),
                None => (router.default_outbound().to_owned(), false, None),
            }
        };
        let (outbound_name, must) = if let Some(ho) = &handoff {
            debug!(
                "eBPF handoff: outbound={}, mark=0x{:x}, dscp={}",
                ho.outbound, ho.mark, ho.dscp
            );
            if ho.outbound == OutboundIndex::ControlPlaneRouting as u8 || reroute_by_sniffed_domain
            {
                (userspace_outbound, userspace_must)
            } else {
                (self.outbound_index_to_name(ho.outbound).await, ho.must != 0)
            }
        } else {
            (userspace_outbound, userspace_must)
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
                match tokio::time::timeout(
                    dns_resolve_timeout,
                    self.dns_resolver
                        .resolve_for_source(domain, client_addr.ip()),
                )
                .await
                {
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
                overall_dial_timeout,
                Arc::clone(&runtime_generation),
                ipver,
                cold_urltest,
            )
            .await;
        let (mut proxy_stream, node) = match raced {
            Some(pair) => pair,
            None => {
                // Exactly one retry for an authoritative single-candidate
                // failure, racing the URLTest latency-ordered top-3: when
                // the just-recorded strike moved the pick the incumbent is
                // replaced; otherwise it re-races alongside its alternates
                // — a lone transient failure leaves no strike and must not
                // hard-fail the flow. Non-URLTest plans and single-leaf
                // outcomes yield no retry candidates and fail the flow.
                let mut retried: Option<(crate::proxy::ProxyStream, Node)> = None;
                if selection_mode == SelectionPlanMode::Authoritative && candidates.len() == 1 {
                    let group_manager = self.group_manager.read().clone();
                    let retry_nodes = group_manager.urltest_retry_candidates(
                        &outbound_name,
                        ProbeDomain::Tcp,
                        ipver,
                    );
                    if retry_nodes.len() > 1
                        || retry_nodes
                            .first()
                            .is_some_and(|n| n.id != candidates[0].id)
                    {
                        retried = self
                            .race_candidates(
                                &retry_nodes,
                                resolved_target,
                                target_domain.clone(),
                                &outbound_name,
                                connect_timeout,
                                overall_dial_timeout,
                                Arc::clone(&runtime_generation),
                                ipver,
                                false,
                            )
                            .await;
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

    /// Race the candidate dials: the first success wins, losers are
    /// cancelled, and fresh connections for losers are deposited into the
    /// pool (≤2 per race, off the critical path). Failures are reported via
    /// traffic-based thresholds to avoid killing a node from a single
    /// transient failure. Returns the winning stream and its already-owned
    /// node; `None` means every candidate failed (already logged) — close
    /// accounting stays with the caller.
    #[allow(clippy::too_many_arguments)]
    async fn race_candidates(
        &self,
        candidates: &[&Node],
        resolved_target: SocketAddr,
        target_domain: Option<String>,
        outbound_name: &str,
        connect_timeout: Duration,
        overall_dial_timeout: Duration,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
        ipver: IpVersion,
        cold_urltest: bool,
    ) -> Option<(crate::proxy::ProxyStream, Node)> {
        let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
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
                (result, idx, elapsed, node)
            });
        }

        let mut last_err: Option<(String, String)> = None;
        let mut first_err: Option<(String, String)> = None;
        let mut timeout_count: usize = 0;
        let mut winner: Option<(crate::proxy::ProxyStream, usize, Node)> = None;
        let mut remaining = set.len();

        loop {
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            match tokio::time::timeout_at(dial_deadline, set.join_next()).await {
                Ok(Some(task_result)) => match task_result {
                    Ok((Ok((stream, fresh)), idx, elapsed, node)) => {
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
                        winner = Some((stream, idx, node));
                        set.abort_all();
                        break;
                    }
                    Ok((Err(e), _idx, _elapsed, node)) => {
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
            && let Some((_, winning_idx, _)) = &winner
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
            Some((stream, _, node)) => Some((stream, node)),
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

#[cfg(test)]
#[path = "cold_urltest_tests.rs"]
mod cold_urltest_tests;
#[cfg(test)]
#[path = "dial_permit_scope_tests.rs"]
mod dial_permit_scope_tests;
