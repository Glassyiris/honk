use super::*;

impl AliveDialerSet {
    /// Probe a single node's TCP reachability.
    ///
    /// When an HTTP prober is configured (Go: `TcpCheckOption`), this resolves
    /// the check URL's hostname to IPs and sends an HTTP request through the
    /// proxy node, validating the status code.
    /// Falls back to raw TCP connect when no prober is set.
    pub async fn probe_node(&self, node_id: &str, timeout: Duration) -> bool {
        let addr = self.registered.read().get(node_id).cloned();
        let Some(addr) = addr else { return false };

        // Clone the Arc out of the lock before awaiting (parking_lot guard is !Send).
        let prober_opt = self.http_prober.read().clone();
        if let Some(ref prober) = prober_opt {
            return self.probe_node_http(node_id, &addr, timeout, prober).await;
        }

        self.probe_node_tcp(node_id, &addr, timeout).await
    }

    /// HTTP-based health check: resolves the check URL hostname, dials through
    /// the proxy node, and validates the HTTP response status code.
    async fn probe_node_http(
        &self,
        node_id: &str,
        node_addr: &str,
        timeout: Duration,
        prober: &HttpProberRef,
    ) -> bool {
        let check_url = self.check_url.read().clone();
        if check_url.is_empty() {
            return self.probe_node_tcp(node_id, node_addr, timeout).await;
        }

        let hostname = match Self::parse_url_host(&check_url) {
            Some(h) => h,
            None => {
                tracing::warn!(
                    "Invalid check URL '{}', falling back to TCP probe",
                    check_url
                );
                return self.probe_node_tcp(node_id, node_addr, timeout).await;
            }
        };

        // Use cached IPs from startup (Go: TcpCheckOption.Ip46).
        // Avoids repeated DNS resolution which can fail transiently and
        // cascade into all nodes being marked dead simultaneously.
        // dae-format literal fallback IPs are merged in so a DNS failure
        // alone never leaves the probe without targets.
        let cached = self.check_url_ips.read().clone();
        let addrs: Vec<SocketAddr> = if cached.is_empty() {
            // Cache miss — try one-time resolution as fallback.
            match tokio::net::lookup_host(format!("{}:80", hostname)).await {
                Ok(it) => {
                    let ips = Self::merge_check_addrs(it.collect(), &check_url);
                    *self.check_url_ips.write() = ips.clone();
                    ips
                }
                Err(e) => {
                    tracing::warn!(
                        "Health check DNS resolution failed for '{}' (node '{}'): {}",
                        hostname,
                        node_id,
                        e
                    );
                    Self::merge_check_addrs(Vec::new(), &check_url)
                }
            }
        } else {
            cached
        };

        if addrs.is_empty() {
            tracing::warn!(
                "Health check found no addresses for '{}' (node '{}')",
                hostname,
                node_id
            );
            return false;
        }

        // Try up to 3 addresses per family, stopping at the first success:
        // the family-death threshold is 1 probe failure, so a single stale
        // cached address (e.g. a v6 answer from a long-gone DNS cache entry)
        // would otherwise pin the whole family as dead forever.
        let mut by_family: [Vec<SocketAddr>; 2] = [Vec::new(), Vec::new()];
        for a in &addrs {
            let idx = if a.is_ipv4() { 0 } else { 1 };
            if by_family[idx].len() < 3 {
                by_family[idx].push(*a);
            }
        }

        let mut any_ok = false;
        for (idx, family_addrs) in by_family.iter().enumerate() {
            let ipver = if idx == 0 {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            if family_addrs.is_empty() {
                self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
                continue;
            }

            let mut family_ok = false;
            for a in family_addrs {
                match tokio::time::timeout(timeout, prober.probe_http(node_id, *a)).await {
                    Ok(Ok(elapsed)) => {
                        tracing::debug!(
                            "HTTP health check succeeded for node '{}' via {} ({}ms)",
                            node_id,
                            a,
                            elapsed.as_millis()
                        );
                        self.record_probe_latency(node_id, ProbeDomain::Tcp, ipver, elapsed);
                        any_ok = true;
                        family_ok = true;
                        break;
                    }
                    Ok(Err(err_msg)) => {
                        tracing::debug!(
                            "HTTP health check failed for node '{}' via {}: {}",
                            node_id, a, err_msg
                        );
                    }
                    Err(_) => {
                        tracing::debug!(
                            "HTTP health check timed out for node '{}' via {} after {:?}",
                            node_id, a, timeout
                        );
                    }
                }
            }
            if !family_ok {
                self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
            }
        }

        if any_ok {
            tracing::info!("Node '{}' is alive after HTTP health check", node_id);
        } else {
            tracing::warn!(
                "Node '{}' failed HTTP health check against all addresses ({})",
                node_id,
                node_addr
            );
        }

        any_ok
    }

    /// Raw TCP connect health check (fallback when no HTTP prober configured).
    async fn probe_node_tcp(&self, node_id: &str, node_addr: &str, timeout: Duration) -> bool {
        let addr = node_addr.to_string();
        let addrs: Vec<_> = match tokio::net::lookup_host(&addr).await {
            Ok(it) => it.collect(),
            Err(e) => {
                tracing::warn!(
                    "Health check DNS resolution failed for node '{}' ({}): {}",
                    node_id,
                    addr,
                    e
                );
                self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
                self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
                return false;
            }
        };

        if addrs.is_empty() {
            tracing::warn!(
                "Health check found no addresses for node '{}' ({})",
                node_id,
                addr
            );
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
            return false;
        }

        // Pick at most one address per IP version
        let mut probe_addrs: Vec<SocketAddr> = Vec::new();
        let mut any_v4 = false;
        let mut any_v6 = false;
        for a in &addrs {
            if a.is_ipv4() {
                if !any_v4 {
                    any_v4 = true;
                    probe_addrs.push(*a);
                }
            } else if !any_v6 {
                any_v6 = true;
                probe_addrs.push(*a);
            }
            if probe_addrs.len() >= IpVersion::count() {
                break;
            }
        }

        let mut any_ok = false;
        for a in &probe_addrs {
            let ipver = if a.is_ipv4() {
                IpVersion::V4
            } else {
                IpVersion::V6
            };

            let start = Instant::now();
            let result = tokio::time::timeout(
                timeout,
                crate::util::connect_marked_addr(*a, self.so_mark, timeout),
            )
            .await;
            let elapsed = start.elapsed();

            match result {
                Ok(Ok(_stream)) => {
                    tracing::debug!(
                        "Health check probe succeeded for node '{}' via {} ({}ms)",
                        node_id,
                        a,
                        elapsed.as_millis()
                    );
                    self.record_probe_latency(node_id, ProbeDomain::Tcp, ipver, elapsed);
                    any_ok = true;
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        "Health check probe failed for node '{}' via {}: {}",
                        node_id,
                        a,
                        e
                    );
                    self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
                }
                Err(_) => {
                    tracing::debug!(
                        "Health check probe timed out for node '{}' via {} after {:?}",
                        node_id,
                        a,
                        timeout
                    );
                    self.mark_dead_for(node_id, ProbeDomain::Tcp, ipver);
                }
            }
        }

        if !any_v4 {
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V4);
        }
        if !any_v6 {
            self.mark_dead_for(node_id, ProbeDomain::Tcp, IpVersion::V6);
        }

        if any_ok {
            tracing::info!("Node '{}' is alive after TCP health check", node_id);
        } else {
            tracing::warn!(
                "Node '{}' failed TCP health check against all addresses ({})",
                node_id,
                addr
            );
        }

        any_ok
    }

    /// Probe a single node's UDP data path (Go: UdpCheck) through the
    /// installed [`UdpProber`]: honk-core routes a minimal DNS query through
    /// the proxy handler's `dial_udp` and awaits the answer.
    ///
    /// Success marks BOTH UDP domains (DataUdp + DnsUdp, v4+v6) alive and
    /// records the round-trip latency for URLTest ranking; failure records
    /// one probe failure against each (probe threshold 3, exponential
    /// backoff via `mark_unavailable_internal`). TCP state is never
    /// touched. Without an installed prober this is a no-op returning
    /// `false`, and no state is recorded — nodes keep the legacy
    /// TCP-fallback selection semantics (see
    /// [`AliveDialerSet::has_udp_state`]).
    pub async fn probe_node_udp(&self, node_id: &str, timeout: Duration) -> bool {
        // Clone the Arc out of the lock before awaiting (parking_lot guard
        // is !Send).
        let prober_opt = self.udp_prober.read().clone();
        let Some(ref prober) = prober_opt else {
            return false;
        };

        const UDP_DOMAINS: [ProbeDomain; 2] = [ProbeDomain::DataUdp, ProbeDomain::DnsUdp];
        const IPVERS: [IpVersion; 2] = [IpVersion::V4, IpVersion::V6];
        match tokio::time::timeout(timeout, prober.probe_udp(node_id)).await {
            Ok(Ok(elapsed)) => {
                tracing::debug!(
                    "UDP health check succeeded for node '{}' ({}ms)",
                    node_id,
                    elapsed.as_millis()
                );
                for domain in UDP_DOMAINS {
                    for ipver in IPVERS {
                        self.mark_alive_for_latency(node_id, domain, ipver, elapsed);
                    }
                }
                true
            }
            Ok(Err(err_msg)) => {
                tracing::debug!(
                    "UDP health check failed for node '{}': {}",
                    node_id,
                    err_msg
                );
                for domain in UDP_DOMAINS {
                    for ipver in IPVERS {
                        self.mark_dead_for(node_id, domain, ipver);
                    }
                }
                false
            }
            Err(_) => {
                tracing::debug!(
                    "UDP health check timed out for node '{}' after {:?}",
                    node_id,
                    timeout
                );
                for domain in UDP_DOMAINS {
                    for ipver in IPVERS {
                        self.mark_dead_for(node_id, domain, ipver);
                    }
                }
                false
            }
        }
    }

    pub async fn run_health_check_cycle(self: &Arc<Self>, timeout: Duration) {
        self.run_health_check_cycle_concurrent(timeout, 1).await;
    }

    /// Run health check cycle with concurrent probing.
    ///
    /// Uses a `JoinSet` with a semaphore to limit concurrency (default 10,
    /// matching sing-box).  Nodes in backoff cooldown or permanently stopped
    /// are skipped.  Emergency probes triggered via `trigger_probe` bypass
    /// the semaphore and are handled separately.
    pub async fn run_health_check_cycle_concurrent(
        self: &Arc<Self>,
        timeout: Duration,
        concurrency: usize,
    ) {
        // Refresh cached check URL IPs at start of each full cycle.
        // Matches Go's TcpCheckOptionRaw.Reset().
        self.refresh_check_ips().await;

        let nodes: Vec<String> = self.registered.read().keys().cloned().collect();
        if nodes.is_empty() {
            return;
        }

        let concurrency = concurrency.max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut join_set = tokio::task::JoinSet::new();

        for id in nodes {
            // URLTest idle suspension: skip nodes whose groups are all idle
            // (lazy start: never-active groups start suspended).
            if self.is_probe_suspended(&id) {
                tracing::trace!("Skipping health check for '{}' (URLTest groups idle)", id);
                continue;
            }
            let idx = alive_index(ProbeDomain::Tcp, IpVersion::V4);
            let state = self.read_state(&id, idx);
            // Skip permanently-backed-off nodes (Go: probeBackoff.stopped).
            if state.stopped || Instant::now() < state.cooldown_until {
                continue;
            }
            let this = self.clone();
            let id = id.clone();
            let permit = semaphore.clone();
            join_set.spawn(async move {
                let _p = permit.acquire().await;
                this.probe_node(&id, timeout).await;
                // UDP data-path probe (Go: UdpCheck) after the TCP probe,
                // gated on the UDP domain's own backoff so a chronically
                // broken UDP path backs off exponentially (and eventually
                // stops) instead of re-probing every cycle. No-op without
                // an installed UdpProber.
                if this.should_probe(&id, ProbeDomain::DataUdp, IpVersion::V4) {
                    this.probe_node_udp(&id, timeout).await;
                }
            });
        }

        while join_set.join_next().await.is_some() {}
    }

    /// Get recent probe history for a node for API/UI consumption.
    ///
    /// Returns the last `MAX_PROBE_HISTORY` probe records for the given
    /// node, domain, and IP version.  Returns an empty `Vec` if no history
    /// exists.
    pub fn get_probe_history(
        &self,
        node_id: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<ProbeRecord> {
        let idx = alive_index(domain, ipver);
        let key = (node_id.to_string(), idx);
        self.probe_history
            .read()
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    pub fn spawn_health_check_loop(
        self: &Arc<Self>,
        interval: Duration,
        timeout: Duration,
    ) -> tokio::task::JoinHandle<()> {
        self.spawn_health_check_loop_concurrent(interval, timeout, 10)
    }

    /// Spawn a health check loop with configurable concurrency.
    ///
    /// Uses `run_health_check_cycle_concurrent` with the given `concurrency`
    /// for the periodic cycle. Emergency probes (triggered via `trigger_probe`)
    /// are still handled inline without concurrency limiting.
    pub fn spawn_health_check_loop_concurrent(
        self: &Arc<Self>,
        interval: Duration,
        timeout: Duration,
        concurrency: usize,
    ) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        let mut trigger_rx = self.take_trigger_rx();
        let concurrency = concurrency.max(1);
        tokio::spawn(async move {
            // ── Anti-thundering-herd: stagger the first health check by a
            // random delay within [0, min(5s, interval/4)] to avoid all
            // nodes probing the proxy server simultaneously at startup.
            // Matches Go dae's initialConnectivityCheckJitterWindow logic.
            let stagger_max = std::cmp::min(interval / 4, std::time::Duration::from_secs(5));
            if stagger_max > std::time::Duration::ZERO {
                let jitter_ms =
                    (rand::random::<u64>() % stagger_max.as_millis().max(1) as u64) as u64;
                tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
            }

            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        this.run_health_check_cycle_concurrent(timeout, concurrency).await;
                    }
                    node = async {
                        match trigger_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Some(id) = node {
                            {
                                let mut states = this.states.write();
                                if let Some(entry) = states.get_mut(&id) {
                                    for e in entry.iter_mut() {
                                        e.cooldown_until = Instant::now();
                                    }
                                }
                            }
                            this.probe_node(&id, timeout).await;
                        }
                    }
                }
            }
        })
    }
}
