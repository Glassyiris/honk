use super::*;

impl ControlPlane {
    /// Stop and join the prior generation's warm coordinator. Aborting the
    /// parent drops its JoinSet, so in-flight child dispatches are cancelled
    /// without becoming health or per-outbound error events.
    pub(super) async fn stop_udp_warm_coordinator(&self) {
        let handle = self.udp_warm_task.lock().await.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    /// Start a warm coordinator bound to one immutable runtime generation.
    /// A zero count releases the prior UDP retention set without creating a
    /// task or touching attempt metrics. Positive counts re-rank after every
    /// probe cycle.
    pub(super) async fn start_udp_warm_coordinator(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) {
        if generation.is_shutdown() {
            return;
        }
        let count = self.config.read().await.global.udp_warm_node_count;
        if count == 0 {
            reconcile_udp_warm_retention(&[], &generation, &self.stats, &self.udp_warm_ids).await;
            return;
        }
        let connect_timeout = {
            let config = self.config.read().await;
            Duration::from_millis(config.global.connect_timeout_ms)
        };
        let proxy_registry = self.proxy_registry.clone();
        let dispatch = Arc::new(move |generation, node_id| {
            let proxy_registry = proxy_registry.clone();
            async move {
                proxy_registry
                    .warm_udp(generation, node_id, connect_timeout)
                    .await
            }
        });
        let handle = tokio::spawn(run_udp_warm_coordinator(
            self.config.clone(),
            self.group_manager.clone(),
            generation,
            self.stats.clone(),
            dispatch,
            self.udp_warm_ids.clone(),
        ));
        *self.udp_warm_task.lock().await = Some(handle);
    }

    pub(super) async fn stop_selector_warm_coordinator(&self) {
        let handle = self.selector_warm_task.lock().await.take();
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }

    /// Pin every configured Selector leaf in this immutable runtime
    /// generation. Choice changes wake the task immediately; the periodic
    /// pass repairs independently lost sessions and consumed bare sockets.
    pub(super) async fn start_selector_warm_coordinator(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) {
        if generation.is_shutdown() {
            return;
        }
        let handle = tokio::spawn(run_selector_warm_coordinator(SelectorWarmCoordinator {
            config: self.config.clone(),
            group_manager: self.group_manager.clone(),
            notify: self.selector_warm_notify.clone(),
            resources: SelectorWarmResources {
                generation,
                proxy_registry: self.proxy_registry.clone(),
                connection_pool: self.connection_pool.clone(),
                stats: self.stats.clone(),
                selected_ids: self.selector_warm_ids.clone(),
                bare_warm: self.selector_bare_warm.clone(),
            },
        }));
        *self.selector_warm_task.lock().await = Some(handle);
    }

    /// Atomically publish a rebuilt router, config, group manager, outbound
    /// runtime generation, DNS runtime, and exact eBPF routing plan. Build
    /// failures leave the current generation untouched; an eBPF push failure
    /// replays the exact active plan before admission resumes. SIGHUP and
    /// subscription merges share this command-channel-serialized path.
    pub(super) async fn apply_runtime_config(
        &self,
        new_config: Config,
        drain: &DrainTracker,
    ) -> bool {
        let current_config = self.config.read().await.clone();
        let restart_required = restart_required_changes(&current_config, &new_config);
        if !restart_required.is_empty() {
            error!(
                fields = ?restart_required,
                "reload rejected: changed fields require process restart"
            );
            return false;
        }
        let old_plan = self.active_routing_plan.read().clone();

        // Build the candidate completely before mutating live state.
        let new_router = match Router::new(
            &new_config.routing.rules,
            &new_config.routing.default_outbound,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build new router: {}", e);
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let pinned_router = match Router::new(
            &new_config.routing.rules,
            &new_config.routing.default_outbound,
        ) {
            Ok(router) => Arc::new(router),
            Err(error) => {
                error!(%error, "Failed to build pinned DNS traffic router");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let old_group_manager = self.group_manager.read().clone();
        let new_group_manager = Arc::new(GroupManager::with_alive_set(
            &new_config.groups,
            &new_config.nodes,
            Some(Arc::clone(&self.alive_set)),
        ));
        new_group_manager.migrate_selector_choices_from(&old_group_manager);
        // Build the outbound generation before DNS so every new runtime
        // snapshot captures its own immutable node/session ownership.
        // Nodes whose config survived the reload unchanged reuse the
        // current generation's runtime (live sessions stay up); the
        // transfer is recorded on the old generation only at the commit
        // point below, so an aborted build leaves its ownership untouched.
        let dial_limit = self
            .resource_budget
            .clamp_dials(new_config.global.max_concurrent_dials);
        let (new_runtime_registry, reused_runtime_ids) =
            match honk_outbound::runtime::OutboundRuntimeRegistry::build_reusing_with_dial_ceiling(
                &new_config.nodes,
                dial_limit,
                self.resource_budget.transient_dials,
                Some(&self.runtime_registry.read()),
            ) {
                Ok((registry, reused)) => (Arc::new(registry), reused),
                Err(e) => {
                    error!("Failed to build runtime registry (reload aborted): {}", e);
                    self.stop_reload_rejection_if_healthy(drain);
                    return false;
                }
            };
        let (new_dns_forwarder, new_upstream_pool) = match self
            .build_dns_forwarder(
                &new_config,
                Arc::clone(&pinned_router),
                Arc::clone(&new_group_manager),
                Arc::clone(&new_runtime_registry),
            )
            .await
        {
            Ok(runtime) => runtime,
            Err(e) => {
                error!("Failed to build DNS forwarder: {}", e);
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let new_outbound_id_map = build_outbound_id_map(&new_config);
        let old_connectivity =
            group_connectivity_snapshot(&current_config, &old_group_manager, &self.alive_set);
        let new_connectivity =
            group_connectivity_snapshot(&new_config, &new_group_manager, &self.alive_set);
        let bootstrap = new_config.global.bootstrap_resolver.clone();
        let direct_target = super::direct_check_addr(&bootstrap);
        let direct_target_socket = match direct_target.parse() {
            Ok(target) => target,
            Err(error) => {
                error!(%error, "Failed to prepare direct health-check target");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let bootstrap_resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&bootstrap);
        let new_plan = match Self::compile_routing_plan(&new_config, &new_router) {
            Ok(plan) => Arc::new(plan),
            Err(error) => {
                error!(%error, "Failed to compile routing publication");
                self.stop_reload_rejection_if_healthy(drain);
                return false;
            }
        };
        let push_result = new_plan.result();
        let generation = crate::dns::runtime::RuntimeGeneration::new(
            self.dns_controller
                .runtime_provider()
                .current_generation()
                .get()
                .saturating_add(1),
        );
        let old_projection_snapshot = {
            let current = self.dns_controller.runtime_provider().acquire();
            Arc::clone(current.runtime().routing_projection())
        };
        let projection_snapshot = Arc::new(crate::dns::runtime::RoutingProjectionSnapshot::new(
            generation.get(),
            Arc::clone(&pinned_router),
            push_result.domain_bitmaps,
        ));
        let old_domain_routes = self
            .dns_controller
            .project_routes(&old_projection_snapshot)
            .into_iter()
            .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
            .collect::<Vec<_>>();
        let new_domain_routes = self
            .dns_controller
            .project_routes(&projection_snapshot)
            .into_iter()
            .map(|(ip, bitmap)| (crate::ebpf::maps::ip_addr_to_lpm_key(ip), bitmap))
            .collect::<Vec<_>>();
        let new_runtime =
            crate::dns::runtime::DnsRuntime::new(crate::dns::runtime::DnsRuntimeParts {
                generation,
                forwarder: Arc::clone(&new_dns_forwarder),
                routing_projection: Arc::clone(&projection_snapshot),
                outbound_runtime: Some(Arc::clone(&new_runtime_registry)),
                transport: new_upstream_pool,
            });

        let route_count = new_router.route_count();
        let old_static_flags = direct_offload_static_bit(&current_config, &old_plan);
        let new_static_flags = direct_offload_static_bit(&new_config, &new_plan);
        let datapath_flags = if let Some(handle) = self.datapath_flags.clone() {
            handle
        } else {
            if current_config.experimental.udp_nfqueue.enabled
                || new_config.experimental.udp_nfqueue.enabled
            {
                error!("datapath flags writer is unavailable during NFQUEUE reload");
                return false;
            }
            let mode_state = self.mode_state.clone().unwrap_or_else(|| {
                Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new(
                    "Rule", "Proxy",
                )))
            });
            let handle =
                crate::mode::DatapathFlagsHandle::new(Arc::clone(&self.ebpf), mode_state, None);
            if let Err(error) = handle.initialize(old_static_flags, false, false).await {
                error!(%error, "failed to initialize reload-scoped datapath flags writer");
                return false;
            }
            handle
        };
        if let Err(error) = datapath_flags.fence_nfqueue().await {
            error!(%error, "failed to fence NFQUEUE before reload");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            self.close_and_drain_pending_udp_admission().await;
            return false;
        }
        drain.start_rejecting();
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.cancel_all().await;
        }
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(
                &datapath_flags,
                old_static_flags,
                drain,
            )
            .await;
            return false;
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain before reload commit");
            self.restore_datapath_flags_after_rejected_reload(
                &datapath_flags,
                old_static_flags,
                drain,
            )
            .await;
            return false;
        }
        let old_registry_result = {
            let mut router_guard = self.router.write().await;
            let mut config_guard = self.config.write().await;
            let mut ebpf = self.ebpf.write().await;
            let mut group_guard = self.group_manager.write();
            let mut outbound_guard = self.outbound_id_map.write();
            let mut plan_guard = self.active_routing_plan.write();
            let mut runtime_guard = self.runtime_registry.write();
            'publication: {
                let provider = self.dns_controller.runtime_provider();
                let publication = provider.prepare_publication(new_runtime);

                let transition_group_count =
                    current_config.groups.len().max(new_config.groups.len());
                if let Err(error) = open_group_connectivity(ebpf.as_mut(), transition_group_count) {
                    let restore = publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                    error!(%error, ?restore, "Failed to open group connectivity for reload transition");
                    break 'publication Err(());
                }
                let active_generation = match ebpf.active_routing_generation() {
                    Ok(generation) => generation,
                    Err(error) => {
                        error!(%error, "Failed to read active routing generation");
                        break 'publication Err(());
                    }
                };
                let next_generation =
                    active_generation ^ (honk_ebpf_common::ROUTING_GENERATION_COUNT as u32 - 1);
                if let Err(error) =
                    ebpf.stage_domain_routing_generation(next_generation, &new_domain_routes)
                {
                    let restore = publish_group_connectivity(ebpf.as_mut(), &old_connectivity);
                    error!(%error, ?restore, "Failed to stage learned domain routes");
                    break 'publication Err(());
                }
                if let Err(error) = routing_matcher::RoutingMatcherBuilder::push_transition(
                    ebpf.as_mut(),
                    Some(&old_plan),
                    &new_plan,
                ) {
                    let replay = ebpf
                        .stage_domain_routing_generation(next_generation, &old_domain_routes)
                        .and_then(|_| {
                            routing_matcher::RoutingMatcherBuilder::push_transition(
                                ebpf.as_mut(),
                                Some(&old_plan),
                                &old_plan,
                            )
                            .map(|_| ())
                        })
                        .and_then(|_| publish_group_connectivity(ebpf.as_mut(), &old_connectivity));
                    match replay {
                        Ok(()) => {
                            error!(
                                %error,
                                "Failed to push routing to eBPF; exact active plan replayed"
                            );
                        }
                        Err(replay_error) => {
                            error!(
                                %error,
                                %replay_error,
                                "Routing push and active-plan replay failed; datapath unhealthy"
                            );
                            self.datapath_healthy
                                .store(false, std::sync::atomic::Ordering::Release);
                            self.drain_tracker.start_rejecting();
                        }
                    }
                    break 'publication Err(());
                }

                if let Err(error) = publish_group_connectivity(ebpf.as_mut(), &new_connectivity) {
                    warn!(
                        %error,
                        "Failed to publish exact group connectivity after reload; remaining slots stay fail-open"
                    );
                }
                let old_registry =
                    std::mem::replace(&mut *runtime_guard, Arc::clone(&new_runtime_registry));
                // Commit point for runtime reuse: only now, with the successor
                // published, does the old generation record the transfer and
                // skip those runtimes at drain/shutdown.
                old_registry.mark_moved_out(reused_runtime_ids);
                publication.commit();
                *router_guard = new_router;
                *config_guard = new_config;
                *group_guard = Arc::clone(&new_group_manager);
                *outbound_guard = new_outbound_id_map;
                *plan_guard = Arc::clone(&new_plan);
                // The projection worker takes eBPF before its generation fence;
                // install the snapshot under the same lock so no old batch can
                // enter the newly activated datapath generation.
                self.dns_controller
                    .update_projection_snapshot(projection_snapshot);
                Ok(old_registry)
            }
        };
        let old_registry = match old_registry_result {
            Ok(old_registry) => old_registry,
            Err(()) => {
                self.restore_datapath_flags_after_rejected_reload(
                    &datapath_flags,
                    old_static_flags,
                    drain,
                )
                .await;
                return false;
            }
        };

        routing_matcher::RoutingMatcherBuilder::activate_projection(&new_plan);
        honk_outbound::bootstrap::set_global(bootstrap_resolver);
        self.alive_set.set_direct_check_addr(direct_target);
        honk_outbound::urltest::set_urltest_direct_target(direct_target_socket);
        install_interrupt_callback(
            &new_group_manager,
            &self.group_manager,
            &self.connection_tracker,
        );
        install_selector_warm_callback(&new_group_manager, &self.selector_warm_notify);
        // No new generation-owned work may start on the old snapshot. Its
        // DNS runtime still owns it until old leases and transports retire;
        // only then do the pools enter graceful session drain.
        old_registry.begin_retirement();
        self.stop_udp_warm_coordinator().await;
        self.stop_selector_warm_coordinator().await;
        self.start_udp_warm_coordinator(Arc::clone(&new_runtime_registry))
            .await;
        self.start_selector_warm_coordinator(new_runtime_registry)
            .await;
        if let Some(ref db) = self.cache_db {
            let db_cb = Arc::clone(db);
            new_group_manager.set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
            })));
        }
        {
            let config = self.config.read().await;
            let _ = sync_health_check_nodes(&self.alive_set, &config);
            self.alive_set
                .sync_urltest_groups(&urltest_group_registrations(&config));
            self.alive_set
                .sync_group_check_urls(&group_check_url_registrations(&config));
        }
        if let Err(error) = datapath_flags.set_static(new_static_flags).await {
            error!(%error, "failed to publish reloaded datapath flags");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return false;
        }
        self.open_pending_udp_admission();
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return false;
        }
        info!("Configuration applied — {} routes active", route_count);

        self.stop_reload_rejection_if_healthy(drain);
        true
    }

    async fn restore_datapath_flags_after_rejected_reload(
        &self,
        datapath_flags: &crate::mode::DatapathFlagsHandle,
        old_static_flags: u32,
        drain: &DrainTracker,
    ) {
        if let Err(error) = datapath_flags.set_static(old_static_flags).await {
            error!(%error, "failed to restore datapath flags after rejected reload");
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        if !self.is_datapath_healthy() {
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        self.open_pending_udp_admission();
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after rejected reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        drain.stop_rejecting();
    }

    fn open_pending_udp_admission(&self) {
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.open_admission();
        }
    }

    async fn close_and_drain_pending_udp_admission(&self) {
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.cancel_all().await;
        }
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain after NFQUEUE reopen failure");
        }
        #[cfg(feature = "ebpf")]
        if let Some(pending) = self.pending_udp_verdicts.as_ref() {
            pending.wait_empty().await;
        }
        if !self.udp_pool.wait_for_retirements().await {
            warn!("UDP endpoint retirements did not drain after NFQUEUE reopen failure");
        }
    }

    /// End reload admission once the datapath is known healthy.
    fn stop_reload_rejection_if_healthy(&self, drain: &DrainTracker) {
        if self.is_datapath_healthy() {
            drain.stop_rejecting();
        } else {
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
        }
    }

    /// Merge freshly fetched subscription nodes into the running config,
    /// replacing the previous node set of `subscription_id`, and run the
    /// shared rebuild pipeline.
    ///
    /// Production callers go through `ControlCommand::MergeSubscription` on
    /// the command channel (which keeps merges serialized against SIGHUP
    /// reloads); this public wrapper exists so integration tests can drive a
    /// merge without binding the TPROXY accept loop.
    pub async fn merge_subscription_nodes(&self, subscription_id: uuid::Uuid, nodes: Vec<Node>) {
        let new_config = {
            let current = self.config.read().await;
            config_with_subscription_nodes(&current, subscription_id, nodes)
        };
        let drain = DrainTracker::new();
        self.apply_runtime_config(new_config, &drain).await;
    }

    /// Build a DNS forwarder from an explicit config (used by the reload
    /// pipeline's build phase — must not read live state, so the caller can
    /// abort before commit without having mutated anything).
    async fn build_dns_forwarder(
        &self,
        config: &Config,
        router: Arc<Router>,
        group_manager: Arc<GroupManager>,
        runtime_generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) -> anyhow::Result<(
        Arc<crate::dns::forwarder::DnsForwarder>,
        Arc<crate::dns::upstream_pool::UpstreamPool>,
    )> {
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
            &config.dns,
        )?);
        let dns_upstream_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy_and_bootstrap(
                &config.dns.upstream,
                dns_router.clone(),
                Some(self.proxy_registry.clone()),
                config.nodes.clone(),
                config.groups.clone(),
                honk_outbound::bootstrap::BootstrapResolver::parse(
                    &config.global.bootstrap_resolver,
                ),
            )?
            .with_runtime_generation(runtime_generation)
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            // Same SharedGroupManager + traffic Router cells as the data path
            // (dae: Route DNS server IP; explicit `-> tag` still forces a group).
            .with_group_manager_snapshot(group_manager)
            .with_traffic_router_snapshot(router),
        );
        let forwarder = Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                Arc::clone(&dns_upstream_pool) as Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
                self.dns_controller.cache().await,
                dns_router,
            )
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            .with_strategy(config.dns.strategy.clone())
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(&config.dns)?
            .with_hosts_from_config(&config.dns)?,
        );
        Ok((forwarder, dns_upstream_pool))
    }

    /// Rebuild the [`GroupManager`] from the current config after a reload.
    ///
    /// A fresh manager is installed into the shared cell so every holder
    /// (control plane, per-connection handles, clash API) picks up new or
    /// changed groups at once. Runtime selector choices migrate by group
    /// name (choices whose group or selected node vanished are dropped);
    /// cache.db-backed choices survive because every change is persisted
    /// at set time, so no cache.db restore runs here. The alive set's
    /// health-check registrations and URLTest group table are refreshed to
    /// match the new group membership, and the node → eBPF outbound id map
    /// (`outbound_id_map`, already refreshed by the reload path) is built
    /// from the same config, keeping the two consistent.
    pub async fn reload_group_manager(&self) {
        let (groups, nodes) = {
            let config = self.config.read().await;
            (config.groups.clone(), config.nodes.clone())
        };
        let new_gm = GroupManager::with_alive_set(&groups, &nodes, Some(self.alive_set.clone()));
        // Migrate runtime choices before wiring callbacks: migration must
        // not fire persistence or connection interruption.
        new_gm.migrate_selector_choices_from(&self.group_manager.read());
        install_interrupt_callback(&new_gm, &self.group_manager, &self.connection_tracker);
        if let Some(ref db) = self.cache_db {
            let db_cb = db.clone();
            new_gm.set_persist_callback(Some(Arc::new(move |group, node| {
                db_cb.save_selector_choice(group, node);
            })));
        }
        *self.group_manager.write() = Arc::new(new_gm);

        // Refresh health-check registrations and the URLTest idle table to
        // match the new group membership.
        let config = self.config.read().await;
        let (added, removed) = sync_health_check_nodes(&self.alive_set, &config);
        self.alive_set
            .sync_urltest_groups(&urltest_group_registrations(&config));
        self.alive_set
            .sync_group_check_urls(&group_check_url_registrations(&config));
        info!(
            "Group manager rebuilt: {} group(s), health checks +{}/-{} node(s)",
            config.groups.len(),
            added,
            removed,
        );
    }
}
/// Fields whose current consumers are process-scoped and therefore cannot be
/// swapped safely by the runtime generation publication. A rejected reload
/// has not mutated any live state.
use super::reload_policy::restart_required_changes;

use super::reload_warm::*;

pub(super) use super::reload_subscription::config_with_subscription_nodes;

use super::reload_connectivity::{
    group_connectivity_snapshot, open_group_connectivity, publish_group_connectivity,
};

pub(super) use super::reload_connectivity::{
    build_outbound_id_map, group_datapath_alive, install_interrupt_callback,
    install_selector_warm_callback,
};

pub(crate) fn resolve_outbound_nodes(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> Vec<Node> {
    if let Some(node) = config.builtin_node(outbound_name) {
        return vec![node];
    }
    if let Some(node) = config.nodes.iter().find(|n| n.name == outbound_name) {
        return vec![node.clone()];
    }
    for group in &config.groups {
        if group.name == outbound_name {
            let mut nodes =
                group_manager.select_nodes_in_order_for_domain(&group.name, domain, ipver);
            // Fallback: IPv6 targets may still be forwarded through nodes that
            // are only reachable over IPv4 (common for proxy servers with only
            // an A record). Try IPv4 alive candidates before giving up.
            if nodes.is_empty() && ipver == IpVersion::V6 {
                nodes = group_manager.select_nodes_in_order_for_domain(
                    &group.name,
                    domain,
                    IpVersion::V4,
                );
                if !nodes.is_empty() {
                    warn!(
                        "resolve_outbound_nodes: group '{}' has no IPv6 alive node; falling back to IPv4 alive candidates",
                        group.name
                    );
                }
            }
            if nodes.is_empty() {
                warn!(
                    "resolve_outbound_nodes: group '{}' has no available node (ipver={:?})",
                    group.name, ipver
                );
                // When all nodes in a group are dead and `final` is configured,
                // recursively resolve the fallback outbound.
                if let Some(final_name) = group_manager.get_final_outbound(&group.name) {
                    info!(
                        "Group '{}' has no alive nodes, falling back to final outbound '{}'",
                        group.name, final_name
                    );
                    return resolve_outbound_nodes(
                        config,
                        group_manager,
                        &final_name,
                        domain,
                        ipver,
                    );
                }
            }
            return nodes.into_iter().cloned().collect();
        }
    }
    warn!(
        "Outbound '{}' not found, falling back to direct",
        outbound_name
    );
    vec![Config::builtin_direct_node()]
}

/// Concrete UDP candidates plus the provenance and IP family selected by
/// the final outbound resolution. This companion does not change the legacy
/// TCP/DNS `resolve_outbound_nodes` API.
#[derive(Debug, Clone)]
pub(super) struct ResolvedUdpPlan {
    pub(super) mode: honk_outbound::group::SelectionPlanMode,
    pub(super) nodes: Vec<Node>,
    pub(super) ipver: IpVersion,
}

/// Resolve UDP candidates without inferring policy from candidate count.
///
/// A group plan supplies the authoritative/cold provenance directly. Empty
/// groups may follow `final_outbound`, in which case the terminal outbound's
/// mode and resolved IP version replace the outer plan. Recursive final
/// chains are bounded and cycle-safe; a missing final target retains the
/// historical direct fallback, while a cycle/depth breach fails closed.
pub(super) fn resolve_udp_outbound_plan(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    ipver: IpVersion,
) -> ResolvedUdpPlan {
    resolve_udp_outbound_plan_inner(
        config,
        group_manager,
        outbound_name,
        ipver,
        0,
        &mut Vec::new(),
    )
}

fn resolve_udp_outbound_plan_inner(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    ipver: IpVersion,
    depth: usize,
    visited: &mut Vec<String>,
) -> ResolvedUdpPlan {
    if let Some(node) = config.builtin_node(outbound_name) {
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![node],
            ipver,
        };
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == outbound_name) {
        let mut selected_ipver = ipver;
        let nodes = if group_manager.is_node_selectable_for_domain(
            node.id,
            ProbeDomain::DataUdp,
            selected_ipver,
        ) {
            vec![node.clone()]
        } else if ipver == IpVersion::V6
            && group_manager.is_node_selectable_for_domain(
                node.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            )
        {
            selected_ipver = IpVersion::V4;
            vec![node.clone()]
        } else {
            vec![]
        };
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes,
            ipver: selected_ipver,
        };
    }
    let Some(group) = config
        .groups
        .iter()
        .find(|group| group.name == outbound_name)
    else {
        warn!(
            "UDP outbound '{}' not found, falling back to direct",
            outbound_name
        );
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![Config::builtin_direct_node()],
            ipver,
        };
    };
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH
        || visited.iter().any(|name| name == outbound_name)
    {
        warn!(
            "UDP final outbound resolution for '{}' stopped at recursive cycle/depth",
            outbound_name
        );
        return ResolvedUdpPlan {
            mode: honk_outbound::group::SelectionPlanMode::Authoritative,
            nodes: vec![],
            ipver,
        };
    }

    visited.push(outbound_name.to_owned());
    let mut selected_ipver = ipver;
    let mut plan =
        group_manager.selection_plan_for_domain(&group.name, ProbeDomain::DataUdp, selected_ipver);
    // Proxy servers frequently have only an A record. Preserve that concrete
    // fallback family for traffic health feedback rather than reporting the
    // original IPv6 destination family.
    if plan.nodes.is_empty() && ipver == IpVersion::V6 {
        plan = group_manager.selection_plan_for_domain(
            &group.name,
            ProbeDomain::DataUdp,
            IpVersion::V4,
        );
        if !plan.nodes.is_empty() {
            selected_ipver = IpVersion::V4;
            warn!(
                "UDP group '{}' has no IPv6 alive node; falling back to IPv4 alive candidates",
                group.name
            );
        }
    }
    if !plan.nodes.is_empty() {
        visited.pop();
        return ResolvedUdpPlan {
            mode: plan.mode,
            nodes: plan.nodes.into_iter().cloned().collect(),
            ipver: selected_ipver,
        };
    }

    if let Some(final_name) = group_manager.get_final_outbound(&group.name) {
        info!(
            "UDP group '{}' has no available node; falling back to final outbound '{}'",
            group.name, final_name
        );
        let terminal = resolve_udp_outbound_plan_inner(
            config,
            group_manager,
            &final_name,
            ipver,
            depth + 1,
            visited,
        );
        visited.pop();
        return terminal;
    }
    visited.pop();
    ResolvedUdpPlan {
        mode: plan.mode,
        nodes: vec![],
        ipver: selected_ipver,
    }
}
