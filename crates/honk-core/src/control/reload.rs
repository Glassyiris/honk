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

        // ── Phase 1: build everything (no live-state mutation) ──
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
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return false;
        }
        self.open_pending_udp_admission();
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
        if let Err(error) = datapath_flags.reopen_nfqueue().await {
            error!(%error, "failed to reopen NFQUEUE after rejected reload");
            self.close_and_drain_pending_udp_admission().await;
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
            drain.start_rejecting();
            self.drain_tracker.start_rejecting();
            return;
        }
        self.open_pending_udp_admission();
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
fn restart_required_changes(current: &Config, candidate: &Config) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let dns_bind_changed = match (current.dns.bind_endpoint(), candidate.dns.bind_endpoint()) {
        (Ok(current), Ok(candidate)) => current != candidate,
        _ => current.dns.bind != candidate.dns.bind,
    };
    if dns_bind_changed {
        changed.push("dns.bind");
    }
    let old_global = &current.global;
    let new_global = &candidate.global;
    if old_global.tproxy_port != new_global.tproxy_port {
        changed.push("global.tproxy_port");
    }
    if old_global.tproxy_mark != new_global.tproxy_mark {
        changed.push("global.tproxy_mark");
    }
    if old_global.tproxy_port_protect != new_global.tproxy_port_protect {
        changed.push("global.tproxy_port_protect");
    }
    if old_global.pprof_port != new_global.pprof_port {
        changed.push("global.pprof_port");
    }
    if old_global.so_mark_from_dae != new_global.so_mark_from_dae {
        changed.push("global.so_mark_from_dae");
    }
    if old_global.log_level != new_global.log_level {
        changed.push("global.log_level");
    }
    if old_global.lan_interface != new_global.lan_interface {
        changed.push("global.lan_interface");
    }
    if old_global.wan_interface != new_global.wan_interface {
        changed.push("global.wan_interface");
    }
    if old_global.auto_config_kernel_parameter != new_global.auto_config_kernel_parameter {
        changed.push("global.auto_config_kernel_parameter");
    }
    if old_global.data_dir != new_global.data_dir {
        changed.push("global.data_dir");
    }
    if old_global.store_subscribe != new_global.store_subscribe {
        changed.push("global.store_subscribe");
    }

    let old_api = &current.experimental.clash_api;
    let new_api = &candidate.experimental.clash_api;
    if old_api.external_controller != new_api.external_controller {
        changed.push("experimental.clash_api.external_controller");
    }
    if old_api.external_ui != new_api.external_ui {
        changed.push("experimental.clash_api.external_ui");
    }
    if old_api.secret != new_api.secret {
        changed.push("experimental.clash_api.secret");
    }
    if old_api.default_mode != new_api.default_mode {
        changed.push("experimental.clash_api.default_mode");
    }
    if serde_json::to_value(&current.experimental.cache_file).ok()
        != serde_json::to_value(&candidate.experimental.cache_file).ok()
    {
        changed.push("experimental.cache_file");
    }
    if current.experimental.udp_nfqueue.enabled != candidate.experimental.udp_nfqueue.enabled {
        changed.push("experimental.udp_nfqueue.enabled");
    }
    changed
}

const SELECTOR_WARM_RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct SelectorWarmResources {
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    proxy_registry: Arc<ProxyRegistry>,
    connection_pool: Arc<ConnectionPool>,
    stats: Arc<StatsManager>,
    selected_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    bare_warm: Arc<parking_lot::Mutex<std::collections::HashMap<uuid::Uuid, String>>>,
}

struct SelectorWarmCoordinator {
    config: Arc<tokio::sync::RwLock<Config>>,
    group_manager: crate::group::SharedGroupManager,
    notify: Arc<tokio::sync::Notify>,
    resources: SelectorWarmResources,
}

/// One configured leaf per Selector, preserving config order and deduplicating
/// nodes shared by several groups. The group manager intentionally resolves
/// the configured choice rather than liveness-falling away from it.
pub(super) fn selector_warm_candidates(
    config: &Config,
    group_manager: &GroupManager,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
) -> Vec<Node> {
    if generation.is_shutdown() {
        return Vec::new();
    }
    let configured: std::collections::HashSet<uuid::Uuid> =
        config.nodes.iter().map(|node| node.id).collect();
    let mut seen = std::collections::HashSet::new();
    config
        .groups
        .iter()
        .filter(|group| group.policy == GroupPolicy::Selector)
        .filter_map(|group| group_manager.selector_warm_node(&group.name))
        .filter(|node| {
            !matches!(node.protocol, NodeProtocol::Direct | NodeProtocol::Block)
                && configured.contains(&node.id)
                && generation.get(&node.id).is_some()
                && seen.insert(node.id)
        })
        .cloned()
        .collect()
}

async fn run_selector_warm_coordinator(context: SelectorWarmCoordinator) {
    let SelectorWarmCoordinator {
        config,
        group_manager,
        notify,
        resources,
    } = context;
    loop {
        if resources.generation.is_shutdown() {
            return;
        }
        let (connect_timeout, candidates) = {
            let config = config.read().await;
            let manager = group_manager.read().clone();
            (
                Duration::from_millis(config.global.connect_timeout_ms),
                selector_warm_candidates(&config, &manager, &resources.generation),
            )
        };
        reconcile_selector_warm(candidates, &resources, connect_timeout).await;
        if resources.generation.is_shutdown() {
            return;
        }
        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(SELECTOR_WARM_RECONCILE_INTERVAL) => {}
        }
    }
}

async fn reconcile_selector_warm(
    candidates: Vec<Node>,
    resources: &SelectorWarmResources,
    connect_timeout: Duration,
) {
    let SelectorWarmResources {
        generation,
        connection_pool,
        stats,
        selected_ids,
        bare_warm,
        ..
    } = resources;
    let desired: std::collections::HashSet<uuid::Uuid> =
        candidates.iter().map(|node| node.id).collect();
    let previous = selected_ids.lock().clone();
    for node_id in previous.difference(&desired) {
        if let Some(runtime) = generation.get(node_id) {
            runtime
                .release_warm(honk_outbound::runtime::WarmRetention::Selector)
                .await;
        }
        stats.clear_warm(*node_id, crate::stats::WarmReason::Selector);
    }
    *selected_ids.lock() = desired.clone();

    let stale_bare: Vec<String> = {
        let mut retained = bare_warm.lock();
        let stale: Vec<uuid::Uuid> = retained
            .keys()
            .filter(|id| !desired.contains(id))
            .copied()
            .collect();
        stale
            .into_iter()
            .filter_map(|id| retained.remove(&id))
            .collect()
    };
    for addr in stale_bare {
        connection_pool.purge_bare(&addr);
    }

    let mut pending = candidates.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < 4 {
            let Some(node) = pending.next() else {
                break;
            };
            tasks.spawn(warm_selector_candidate(
                node,
                resources.clone(),
                connect_timeout,
            ));
        }
        if tasks.is_empty() {
            break;
        }
        let _ = tasks.join_next().await;
    }
}

async fn warm_selector_candidate(
    node: Node,
    resources: SelectorWarmResources,
    connect_timeout: Duration,
) {
    let SelectorWarmResources {
        generation,
        proxy_registry,
        connection_pool,
        stats,
        bare_warm,
        ..
    } = resources;
    // Purge a moved endpoint before redial: failure must not keep the old
    // socket pinned under a stable node ID.
    let supports_bare = (honk_outbound::descriptor::descriptor(node.protocol).pool_bare_tcp)(&node);
    let bare_addr = supports_bare.then(|| format!("{}:{}", node.host(), node.port));
    let stale = {
        let mut retained = bare_warm.lock();
        match (retained.get(&node.id), bare_addr.as_ref()) {
            (Some(old), Some(current)) if old == current => None,
            (Some(_), _) => retained.remove(&node.id),
            (None, _) => None,
        }
    };
    if let Some(stale) = stale {
        connection_pool.purge_bare(&stale);
        stats.clear_warm(node.id, crate::stats::WarmReason::Selector);
    }
    match proxy_registry
        .warm_session(Arc::clone(&generation), node.id, connect_timeout)
        .await
    {
        Ok(honk_outbound::proxy::WarmOutcome::Ready) => {
            if let Some(addr) = bare_warm.lock().remove(&node.id) {
                connection_pool.purge_bare(&addr);
            }
            stats.mark_warm(node.id, crate::stats::WarmReason::Selector);
        }
        Ok(honk_outbound::proxy::WarmOutcome::NotApplicable) => {
            let Some(addr) = bare_addr else {
                return;
            };
            if !connection_pool.has_live_bare_entry(&addr) {
                let stream =
                    match honk_outbound::util::connect_outbound(&addr, connect_timeout).await {
                        Ok(stream) if !generation.is_shutdown() && is_tcp_stream_alive(&stream) => {
                            stream
                        }
                        Ok(_) => return,
                        Err(error) => {
                            debug!(node = %node.name, %error, "Selector warm bare TCP failed");
                            return;
                        }
                    };
                connection_pool.deposit_tcp(&addr, stream).await;
            }
            if connection_pool.has_live_bare_entry(&addr) {
                let old = bare_warm.lock().insert(node.id, addr.clone());
                if let Some(old) = old.filter(|old| old != &addr) {
                    connection_pool.purge_bare(&old);
                }
                stats.mark_warm(node.id, crate::stats::WarmReason::Selector);
            }
        }
        Err(error) if generation.is_shutdown() => {
            debug!(node = %node.name, %error, "Selector warm generation ended");
        }
        Err(error) => {
            debug!(node = %node.name, %error, "Selector warm session failed");
        }
    }
}

/// Select warm candidates: the top `count` UDP leaves (latency order, capped
/// at three) of every configured group, for both IP versions. This replaces
/// winner-only warming: each pass re-evaluates the latency order, so freshly
/// measured fast leaves get reusable session state before they win a
/// selection. Cold URLTest groups contribute their full ranked list. UUIDs
/// are deduplicated across groups; direct/block leaves and nodes without a
/// reusable UDP-capable generation runtime stay out.
///
/// On top of the per-group top-N, a process-wide cap of `4 × count` keeps
/// retained resources bounded as the group count grows. The merged set is
/// re-ranked by global UDP latency and truncated, sacrificing only the
/// slowest leaves.
pub(super) fn udp_warm_candidates(
    config: &Config,
    group_manager: &GroupManager,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    count: usize,
) -> Vec<uuid::Uuid> {
    if count == 0 || generation.is_shutdown() {
        return Vec::new();
    }
    let per_group = count.min(3);
    let total_cap = count.saturating_mul(4);
    let configured_ids: std::collections::HashSet<uuid::Uuid> =
        config.nodes.iter().map(|node| node.id).collect();
    let mut selected: Vec<(uuid::Uuid, Duration)> = Vec::new();
    for group in &config.groups {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            let mut leaves = group_manager.ranked_udp_leaves(&group.name, ipver, per_group);
            // `flatten_candidates` covers sub-groups but not a bare `final:`
            // hop — resolve one final hop so final-only groups still warm
            // their terminal leaves.
            if leaves.is_empty()
                && let Some(final_name) = group_manager.get_final_outbound(&group.name)
            {
                leaves = group_manager.ranked_udp_leaves(&final_name, ipver, per_group);
            }
            for node in leaves {
                if matches!(
                    node.protocol,
                    honk_config::types::NodeProtocol::Direct
                        | honk_config::types::NodeProtocol::Block
                ) {
                    continue;
                }
                if !configured_ids.contains(&node.id) {
                    continue;
                }
                let Some(runtime) = generation.get(&node.id) else {
                    continue;
                };
                if !runtime.udp_capable
                    || !honk_outbound::descriptor::descriptor(node.protocol)
                        .has_generation_runtime()
                {
                    continue;
                }
                let latency = group_manager.udp_latency(node, ipver);
                match selected.iter_mut().find(|(id, _)| *id == node.id) {
                    Some(entry) => entry.1 = entry.1.min(latency),
                    None => selected.push((node.id, latency)),
                }
            }
        }
    }
    // Stable sort: unmeasured leaves (Duration::MAX) keep their per-group
    // order below every measured one.
    selected.sort_by_key(|(_, latency)| *latency);
    selected.truncate(total_cap);
    selected.into_iter().map(|(id, _)| id).collect()
}

async fn reconcile_udp_warm_retention(
    candidates: &[uuid::Uuid],
    generation: &Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: &Arc<StatsManager>,
    retained_ids: &Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
) {
    let desired: std::collections::HashSet<uuid::Uuid> = candidates.iter().copied().collect();
    let previous = retained_ids.lock().clone();
    for node_id in previous.difference(&desired) {
        if let Some(runtime) = generation.get(node_id) {
            runtime
                .release_warm(honk_outbound::runtime::WarmRetention::Udp)
                .await;
        }
        stats.clear_warm(*node_id, crate::stats::WarmReason::Udp);
    }
    *retained_ids.lock() = desired;
}

/// Periodic warm coordinator: one immediate pass, then another after each
/// completed dispatch batch plus `check_interval` (floored at 10s). Every pass
/// re-ranks the per-group top-N from current probe data; handlers reuse live
/// sessions/clients, so repeat dispatch is cheap. Exits when the count is
/// disabled or the generation turns terminal (reload/shutdown replaces it).
async fn run_udp_warm_coordinator<F, Fut>(
    config: Arc<tokio::sync::RwLock<Config>>,
    group_manager: crate::group::SharedGroupManager,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: Arc<StatsManager>,
    dispatch: Arc<F>,
    retained_ids: Arc<parking_lot::Mutex<std::collections::HashSet<uuid::Uuid>>>,
) where
    F: Fn(Arc<honk_outbound::runtime::OutboundRuntimeRegistry>, uuid::Uuid) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = anyhow::Result<honk_outbound::proxy::WarmOutcome>> + Send + 'static,
{
    loop {
        if generation.is_shutdown() {
            return;
        }
        let (interval, count, candidates) = {
            let cfg = config.read().await.clone();
            let count = cfg.global.udp_warm_node_count;
            let interval = Duration::from_secs(cfg.global.check_interval_secs.max(10));
            let manager = group_manager.read().clone();
            let candidates = udp_warm_candidates(&cfg, &manager, &generation, count);
            (interval, count, candidates)
        };
        if count == 0 {
            reconcile_udp_warm_retention(&[], &generation, &stats, &retained_ids).await;
            return;
        }
        reconcile_udp_warm_retention(&candidates, &generation, &stats, &retained_ids).await;
        run_udp_warm_dispatches(
            candidates,
            generation.clone(),
            stats.clone(),
            dispatch.clone(),
        )
        .await;
        if generation.is_shutdown() {
            return;
        }
        tokio::time::sleep(interval).await;
    }
}

/// Execute generation-owned warm dispatches with exactly the fixed aggregate
/// metrics contract. Neither cancellation nor a terminal generation mutates
/// outbound health or per-node error state.
async fn run_udp_warm_dispatches<F, Fut>(
    candidates: Vec<uuid::Uuid>,
    generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    stats: Arc<StatsManager>,
    dispatch: Arc<F>,
) where
    F: Fn(Arc<honk_outbound::runtime::OutboundRuntimeRegistry>, uuid::Uuid) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = anyhow::Result<honk_outbound::proxy::WarmOutcome>> + Send + 'static,
{
    if candidates.is_empty() {
        return;
    }
    let mut pending = candidates.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < 4 {
            let Some(node_id) = pending.next() else {
                break;
            };
            let generation = Arc::clone(&generation);
            let stats = Arc::clone(&stats);
            let dispatch = Arc::clone(&dispatch);
            tasks.spawn(async move {
                stats.record_udp_warm_attempt();
                match dispatch(generation.clone(), node_id).await {
                    Ok(honk_outbound::proxy::WarmOutcome::Ready) => {
                        stats.record_udp_warm_success();
                        stats.mark_warm(node_id, crate::stats::WarmReason::Udp);
                    }
                    Ok(honk_outbound::proxy::WarmOutcome::NotApplicable) => {}
                    Err(err) if generation.is_shutdown() => {
                        debug!("UDP warm ended with terminal generation: {err}");
                    }
                    Err(err) => {
                        debug!("UDP warm failed: {err}");
                        stats.record_udp_warm_failure();
                    }
                }
            });
        }
        if tasks.is_empty() {
            break;
        }
        if let Some(Err(err)) = tasks.join_next().await
            && err.is_panic()
            && !generation.is_shutdown()
        {
            debug!("UDP warm dispatch panicked: {err}");
            stats.record_udp_warm_failure();
        }
    }
}

/// Build the config produced by merging one subscription's freshly fetched
/// nodes: every node previously delivered by that subscription is replaced
/// (matched by `subscription_id`), group memberships derived from replaced
/// nodes are pruned, and filter-based membership is re-resolved against the
/// merged node set. Nodes from other subscriptions and static config nodes
/// are untouched. Re-merging the same subscription is idempotent — nodes
/// are replaced, never duplicated.
pub(super) fn config_with_subscription_nodes(
    current: &Config,
    subscription_id: uuid::Uuid,
    nodes: Vec<Node>,
) -> Config {
    let mut config = current.clone();
    config
        .nodes
        .retain(|n| n.subscription_id != Some(subscription_id));
    config.nodes.extend(nodes);
    // Stable node IDs may survive a rename or move between subscriptions, so
    // prune dead members and rebuild filter-derived membership from provenance.
    let live: std::collections::HashSet<uuid::Uuid> = config.nodes.iter().map(|n| n.id).collect();
    for group in &mut config.groups {
        group.nodes.retain(|id| live.contains(id));
    }
    honk_config::parser::resolve_group_filters(
        &mut config.groups,
        &config.nodes,
        &config.subscriptions,
    );
    config
}

/// Recursively collect the member node ids of a group, expanding nested
/// sub-groups (`Group.groups`). Config-level twin of the GroupManager's
/// leaf expansion — the config may still contain group cycles (the
/// GroupManager cuts them on its own copy), so a visited guard and the
/// shared depth cap apply here too.
fn collect_group_leaf_ids<'a>(
    group: &'a Group,
    groups_by_name: &std::collections::HashMap<&'a str, &'a Group>,
    depth: usize,
    visited: &mut Vec<&'a str>,
    out: &mut std::collections::BTreeSet<uuid::Uuid>,
) {
    if depth >= honk_outbound::group::MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
        return;
    }
    visited.push(group.name.as_str());
    out.extend(group.nodes.iter().copied());
    for tag in &group.groups {
        if let Some(sub) = groups_by_name.get(tag.as_str()) {
            collect_group_leaf_ids(sub, groups_by_name, depth + 1, visited, out);
        }
    }
    visited.pop();
}

/// Group lookup by name for [`collect_group_leaf_ids`].
fn groups_by_name(config: &Config) -> std::collections::HashMap<&str, &Group> {
    config.groups.iter().map(|g| (g.name.as_str(), g)).collect()
}

/// Nodes that should be health-checked: members of any group — with
/// nested sub-groups expanded to their leaf nodes (Selector members are
/// probed too — alive display + failure discovery — not just URLTest
/// members). Ungrouped nodes are skipped unless no groups exist at all.
/// Returns `(NodeId, node name, address)` triples.
fn health_check_targets(config: &Config) -> Vec<(uuid::Uuid, String, String)> {
    let by_name = groups_by_name(config);
    let group_node_ids: std::collections::BTreeSet<uuid::Uuid> = config
        .groups
        .iter()
        .flat_map(|g| {
            let mut ids = std::collections::BTreeSet::new();
            collect_group_leaf_ids(g, &by_name, 0, &mut Vec::new(), &mut ids);
            ids
        })
        .collect();
    config
        .nodes
        .iter()
        .filter(|n| group_node_ids.is_empty() || group_node_ids.contains(&n.id))
        .map(|n| (n.id, n.name.clone(), n.address.clone()))
        .collect()
}

/// Synchronize alive-set health-check registrations with the config's
/// group membership: register nodes that are new or whose name/address
/// changed, remove nodes that left the checked set. Unchanged
/// registrations keep their probe state and grace period. Returns
/// `(added, removed)` counts.
pub(super) fn sync_health_check_nodes(
    alive_set: &AliveDialerSet,
    config: &Config,
) -> (usize, usize) {
    let desired: std::collections::HashMap<uuid::Uuid, (String, String)> =
        health_check_targets(config)
            .into_iter()
            .map(|(id, name, addr)| (id, (name, addr)))
            .collect();
    let current = alive_set.registered_nodes();
    let mut added = 0usize;
    for (id, (name, addr)) in &desired {
        let unchanged = current
            .get(id)
            .is_some_and(|r| &r.name == name && &r.address == addr);
        if !unchanged {
            alive_set.register_node(*id, name.clone(), addr.clone());
            added += 1;
        }
    }
    let mut removed = 0usize;
    for id in current.keys() {
        if !desired.contains_key(id) {
            alive_set.remove_node(*id);
            removed += 1;
        }
    }
    (added, removed)
}

/// URLTest group registrations for the alive set's idle-suspension table:
/// `(group name, member NodeIds, idle timeout)` per URLTest group.
/// Members shared with any non-URLTest group (Selector, LoadBalance,
/// Fallback) are excluded — those are probed unconditionally, same as
/// Selector members. Nested sub-groups are expanded to their leaf nodes
/// (health state lives on real nodes). Used identically at startup and on
/// config reload.
pub(super) fn urltest_group_registrations(
    config: &Config,
) -> Vec<(String, Vec<uuid::Uuid>, Option<Duration>)> {
    let by_name = groups_by_name(config);
    let leaf_ids = |g: &Group| {
        let mut ids = std::collections::BTreeSet::new();
        collect_group_leaf_ids(g, &by_name, 0, &mut Vec::new(), &mut ids);
        ids
    };
    let always_probed_node_ids: std::collections::BTreeSet<uuid::Uuid> = config
        .groups
        .iter()
        .filter(|g| g.policy != GroupPolicy::URLTest)
        .flat_map(&leaf_ids)
        .collect();
    config
        .groups
        .iter()
        .filter(|g| g.policy == GroupPolicy::URLTest)
        .map(|group| {
            let members: Vec<uuid::Uuid> = leaf_ids(group)
                .into_iter()
                .filter(|id| !always_probed_node_ids.contains(id))
                .collect();
            (
                group.name.clone(),
                members,
                group.idle_timeout.map(std::time::Duration::from_secs),
            )
        })
        .collect()
}

/// Build `(group name, check_url)` for every group with a custom
/// `check_url` (sing-box urltest `url` option) — the input to
/// [`AliveDialerSet::sync_group_check_urls`]. Selector groups are
/// excluded (their check_url is ignored, sing-box parity). Members are
/// resolved dynamically each probe cycle through the group manager (the
/// url member resolver installed in `ControlPlane`), so sub-group picks
/// never go stale here.
pub(super) fn group_check_url_registrations(config: &Config) -> Vec<(String, String)> {
    config
        .groups
        .iter()
        .filter(|g| g.policy != GroupPolicy::Selector && g.check_url.is_some())
        .map(|group| {
            (
                group.name.clone(),
                group.check_url.clone().unwrap_or_default(),
            )
        })
        .collect()
}

/// Wire the `interrupt_connections` callback into a group manager: when a
/// group's selected node changes, close its tracked connections so they
/// re-dial through the new node. The callback reads the *current* manager
/// through the shared cell, so it keeps working after a reload swaps the
/// manager out. Tracked connections record the dialed leaf node name, so
/// the target set covers the group name, its member tags, and every leaf
/// reachable through nested sub-groups.
pub(super) fn install_interrupt_callback(
    group_manager: &GroupManager,
    group_manager_cell: &SharedGroupManager,
    tracker: &Arc<ConnectionTracker>,
) {
    let cell = group_manager_cell.clone();
    let tracker = tracker.clone();
    group_manager.set_interrupt_callback(Some(Arc::new(move |group_name: &str| {
        let gm = cell.read().clone();
        let mut targets: std::collections::HashSet<String> =
            gm.node_names_in_group(group_name).into_iter().collect();
        targets.extend(gm.leaf_node_names_in_group(group_name));
        targets.insert(group_name.to_string());
        let mut closed = 0usize;
        for snap in tracker.snapshot() {
            if targets.contains(&snap.proxy) {
                tracker.remove(&snap.id);
                closed += 1;
            }
        }
        if closed > 0 {
            info!(
                "interrupt_connections: closed {} connection(s) for group '{}'",
                closed, group_name
            );
        }
    })));
}

/// Wake the Selector warm coordinator after a manual choice changes. The
/// task re-resolves every Selector so shared/nested leaves stay reference
/// correct without putting async work in the synchronous group callback.
pub(super) fn install_selector_warm_callback(
    group_manager: &GroupManager,
    notify: &Arc<tokio::sync::Notify>,
) {
    let notify = Arc::clone(notify);
    group_manager.set_selector_change_callback(Some(Arc::new(move || {
        notify.notify_one();
    })));
}

/// Build the NodeId → eBPF outbound id map used for
/// `OUTBOUND_CONNECTIVITY_MAP` pushes. Numbering matches
/// `push_routing_to_ebpf`: direct=0, block=1, group i → `UserBase + i`;
/// group member nodes inherit their group's id (first group wins when a
/// node is in several groups), with nested sub-groups expanded to their
/// leaves so a leaf dialed via a sub-group still maps to the top group's
/// slot. Nodes outside any group have no eBPF outbound id and are absent
/// from the map.
pub(super) fn build_outbound_id_map(config: &Config) -> std::collections::HashMap<uuid::Uuid, u8> {
    let by_name = groups_by_name(config);
    let mut map = std::collections::HashMap::new();
    for (i, group) in config.groups.iter().enumerate() {
        let id = OutboundIndex::UserBase as u8 + i as u8;
        let mut leaf_ids = std::collections::BTreeSet::new();
        collect_group_leaf_ids(group, &by_name, 0, &mut Vec::new(), &mut leaf_ids);
        for node_id in leaf_ids {
            map.entry(node_id).or_insert(id);
        }
    }
    map
}

type GroupConnectivity = (u8, u32, u32, bool);

fn group_connectivity_snapshot(
    config: &Config,
    group_manager: &GroupManager,
    alive_set: &crate::outbound::AliveDialerSet,
) -> Vec<GroupConnectivity> {
    let mut snapshot = Vec::with_capacity(config.groups.len() * 6);
    for (index, group) in config.groups.iter().enumerate() {
        let outbound = OutboundIndex::UserBase as u8 + index as u8;
        let leaves = group_manager.leaf_nodes_in_group(&group.name);
        for (domain_index, domain) in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp]
            .into_iter()
            .enumerate()
        {
            for (ip_index, ipver) in [IpVersion::V4, IpVersion::V6].into_iter().enumerate() {
                let any_alive = leaves
                    .iter()
                    .any(|node| alive_set.is_alive_for(node.id, domain, ipver));
                snapshot.push((outbound, domain_index as u32, ip_index as u32, any_alive));
            }
        }
    }
    snapshot
}

fn publish_group_connectivity(
    ebpf: &mut dyn EbpfBackend,
    snapshot: &[GroupConnectivity],
) -> anyhow::Result<()> {
    for &(outbound, domain, ipver, alive) in snapshot {
        ebpf.set_outbound_alive(outbound, domain, ipver, alive)?;
    }
    Ok(())
}

fn open_group_connectivity(ebpf: &mut dyn EbpfBackend, group_count: usize) -> anyhow::Result<()> {
    for index in 0..group_count {
        let offset = u8::try_from(index)
            .map_err(|_| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        let outbound = (OutboundIndex::UserBase as u8)
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("too many outbound groups: {group_count}"))?;
        for domain in 0..3 {
            for ipver in 0..2 {
                ebpf.set_outbound_alive(outbound, domain, ipver, true)?;
            }
        }
    }
    Ok(())
}

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

#[cfg(test)]
mod atomic_reload_tests {
    use super::*;
    use crate::control::udp_endpoint::{EndpointReservation, UdpEndpoint};
    use crate::dns;
    use crate::ebpf::RoutingPushPhase;
    use crate::ebpf::mock::MockEbpfBackend;
    use crate::stats::StatsManager;

    #[test]
    fn subscription_store_toggle_requires_restart() {
        let current = Config::default();
        let mut replacement = current.clone();
        replacement.global.store_subscribe = !current.global.store_subscribe;

        assert_eq!(
            restart_required_changes(&current, &replacement),
            vec!["global.store_subscribe"]
        );
    }

    #[test]
    fn udp_nfqueue_toggle_requires_restart() {
        let current = Config::default();
        let mut replacement = current.clone();
        replacement.experimental.udp_nfqueue.enabled = !current.experimental.udp_nfqueue.enabled;

        assert_eq!(
            restart_required_changes(&current, &replacement),
            vec!["experimental.udp_nfqueue.enabled"]
        );
    }

    #[test]
    fn semantically_equivalent_dns_bind_does_not_require_restart() {
        let mut current = Config::default();
        current.dns.bind = "127.0.0.1:53".into();
        let mut replacement = current.clone();
        replacement.dns.bind = "udp://127.0.0.1:53".into();

        assert!(restart_required_changes(&current, &replacement).is_empty());
    }

    #[test]
    fn dns_bind_transport_change_requires_restart() {
        let mut current = Config::default();
        current.dns.bind = "udp://127.0.0.1:53".into();
        let mut replacement = current.clone();
        replacement.dns.bind = "tcp+udp://127.0.0.1:53".into();

        assert_eq!(
            restart_required_changes(&current, &replacement),
            vec!["dns.bind"]
        );
    }

    #[test]
    fn enabling_dns_bind_requires_restart() {
        let current = Config::default();
        let mut replacement = current.clone();
        replacement.dns.bind = "tcp://127.0.0.1:0".into();

        assert_eq!(
            restart_required_changes(&current, &replacement),
            vec!["dns.bind"]
        );
    }

    #[test]
    fn data_directory_change_requires_restart() {
        let current = Config::default();
        let mut replacement = current.clone();
        replacement.global.data_dir = "/srv/honk".into();

        assert_eq!(
            restart_required_changes(&current, &replacement),
            vec!["global.data_dir"]
        );
    }

    fn test_dns_forwarder() -> std::sync::Arc<dns::forwarder::DnsForwarder> {
        let cache = Arc::new(tokio::sync::Mutex::new(dns::cache::DnsCache::new(100)));
        let router = Arc::new(
            dns::routing::DnsRouter::new(&honk_config::dns::DnsRouting {
                rules: vec![],
                fallback: "default".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let upstream_pool = Arc::new(
            dns::upstream_pool::UpstreamPool::new(
                &[honk_config::dns::DnsUpstream {
                    name: "default".into(),
                    address: "8.8.8.8:53".into(),
                    protocol: honk_config::types::DnsProtocol::Udp,
                    tls_server_name: None,
                    outbound: None,
                }],
                router.clone(),
            )
            .unwrap(),
        );
        dns::forwarder::DnsForwarder::new(upstream_pool, cache, router)
            .with_cache_enabled(false)
            .into()
    }
    #[test]
    fn group_connectivity_follows_reordered_outbound_ids() {
        let a = Node {
            id: uuid::Uuid::new_v4(),
            name: "a".into(),
            ..Default::default()
        };
        let b = Node {
            id: uuid::Uuid::new_v4(),
            name: "b".into(),
            ..Default::default()
        };
        let group = |name: &str, node: &Node| Group {
            name: name.into(),
            policy: GroupPolicy::Selector,
            nodes: vec![node.id],
            ..Default::default()
        };
        let mut config = Config {
            nodes: vec![a.clone(), b.clone()],
            groups: vec![group("ga", &a), group("gb", &b)],
            ..Default::default()
        };
        let alive = Arc::new(crate::outbound::AliveDialerSet::new());
        alive.report_unavailable_forced(a.id, ProbeDomain::DataUdp, IpVersion::V4);

        let original_manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        let original = group_connectivity_snapshot(&config, &original_manager, &alive);
        assert!(original.contains(&(OutboundIndex::UserBase as u8, 2, 0, false)));
        assert!(original.contains(&(OutboundIndex::UserBase as u8 + 1, 2, 0, true)));

        config.groups.swap(0, 1);
        let reordered_manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        let reordered = group_connectivity_snapshot(&config, &reordered_manager, &alive);
        assert!(reordered.contains(&(OutboundIndex::UserBase as u8, 2, 0, true)));
        assert!(reordered.contains(&(OutboundIndex::UserBase as u8 + 1, 2, 0, false)));

        let mut backend = MockEbpfBackend::new();
        publish_group_connectivity(&mut backend, &original).unwrap();
        open_group_connectivity(&mut backend, 2).unwrap();
        assert!(
            backend
                .get_outbound_alive(OutboundIndex::UserBase as u8 + 1, 2, 0)
                .unwrap()
        );
        publish_group_connectivity(&mut backend, &reordered).unwrap();
        assert!(
            !backend
                .get_outbound_alive(OutboundIndex::UserBase as u8 + 1, 2, 0)
                .unwrap()
        );
    }

    async fn test_cp() -> ControlPlane {
        let mut control_plane = ControlPlane::new(
            Config::default(),
            Box::new(MockEbpfBackend::new()),
            Router::new(&[], "direct").unwrap(),
            std::sync::Arc::new(ProxyRegistry::default_resolver().unwrap()),
            DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
            test_dns_forwarder(),
        )
        .unwrap();
        control_plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", "Proxy"),
        )));
        control_plane.start_datapath_flags_coordinator().unwrap();
        control_plane
            .initialize_datapath_flags(false, false)
            .await
            .unwrap();
        control_plane
    }

    #[tokio::test]
    async fn reload_clamps_dials_to_startup_descriptor_reservation() {
        let cp = test_cp().await;
        let ceiling = cp.resource_budget.transient_dials;
        let mut config = cp.config_handle().read().await.clone();
        config.global.max_concurrent_dials = usize::MAX;

        assert!(cp.apply_runtime_config(config, &DrainTracker::new()).await);
        assert_eq!(cp.runtime_registry.read().dial_limit(), ceiling);
    }

    /// A reload whose build phase fails (invalid upstream address) must abort
    /// without touching the live config — the atomicity guarantee of the
    /// two-phase apply.
    #[tokio::test]
    async fn build_failure_leaves_live_config_untouched() {
        let cp = test_cp().await;
        let before = cp.config_handle().read().await.global.check_interval_secs;

        // An upstream with an empty address fails DnsEndpoint::parse during
        // build_dns_forwarder — the reload must abort before commit.
        let mut bad = Config::default();
        bad.global.check_interval_secs += 1;
        bad.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "broken".into(),
            address: String::new(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];

        let drain = DrainTracker::new();
        cp.apply_runtime_config(bad, &drain).await;

        let after = cp.config_handle().read().await.global.check_interval_secs;
        assert_eq!(before, after, "failed build must not swap the live config");
    }

    #[tokio::test]
    async fn reload_cancels_initializing_generation_before_swap_and_keeps_ready_endpoint() {
        use honk_outbound::proxy::PacketTransport;
        use std::io;
        use std::sync::Mutex;
        use tokio::sync::Notify;

        /// Minimal scripted transport local to this reload test so we can
        /// prove a real driver survives production cancel/reload.
        #[derive(Debug)]
        struct ReloadTestTransport {
            relay: std::net::SocketAddr,
            sent: Mutex<Vec<Vec<u8>>>,
            progress: Notify,
        }

        #[async_trait::async_trait]
        impl PacketTransport for ReloadTestTransport {
            fn relay_addr(&self) -> std::net::SocketAddr {
                self.relay
            }

            async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
                self.sent.lock().unwrap().push(data.to_vec());
                self.progress.notify_waiters();
                Ok(())
            }

            async fn recv_packet(
                &self,
                _buf: &mut [u8],
            ) -> io::Result<(usize, std::net::SocketAddr)> {
                // Leave receive pending for the life of the driver.
                std::future::pending().await
            }
        }

        impl ReloadTestTransport {
            async fn wait_for_send_count(&self, count: usize) {
                loop {
                    if self.sent.lock().unwrap().len() >= count {
                        return;
                    }
                    self.progress.notified().await;
                }
            }

            fn sent_packets(&self) -> Vec<Vec<u8>> {
                self.sent.lock().unwrap().clone()
            }
        }

        let cp = test_cp().await;
        let pool = cp.udp_pool.clone();
        let stats = Arc::new(StatsManager::new());
        let ready_client: std::net::SocketAddr = "10.0.0.1:53000".parse().unwrap();
        let initializing_client: std::net::SocketAddr = "10.0.0.2:53000".parse().unwrap();
        let dst: std::net::SocketAddr = "203.0.113.2:443".parse().unwrap();
        let relay: std::net::SocketAddr = "192.0.2.10:1080".parse().unwrap();

        let ready_permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let mut ready_lease = match pool.reserve_or_enqueue(
            ready_client,
            dst,
            b"ready-first",
            ready_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("ready fixture must reserve an initializing entry"),
        };
        let transport = Arc::new(ReloadTestTransport {
            relay,
            sent: Mutex::new(Vec::new()),
            progress: Notify::new(),
        });
        let ready_endpoint = Arc::new(UdpEndpoint::new(
            transport.clone() as Arc<dyn PacketTransport>,
            relay,
            uuid::Uuid::from_u128(0x1ead9),
        ));
        let queue_rx = ready_lease.take_queue_receiver().unwrap();
        let reply_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut driver = pool.spawn_driver(
            ready_client,
            dst,
            ready_lease.generation(),
            ready_lease.decision_token(),
            Arc::clone(&ready_endpoint),
            queue_rx,
            reply_socket,
            Arc::new(honk_outbound::alive::AliveDialerSet::new()),
            Arc::clone(&stats),
            "ready-node".into(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), driver.wait_ready())
            .await
            .expect("driver must become ready")
            .unwrap();
        assert!(ready_lease.commit_ready(Arc::clone(&ready_endpoint)));
        driver
            .start(ready_lease.take_first().unwrap())
            .expect("driver start");
        tokio::time::timeout(std::time::Duration::from_secs(1), driver.wait_first_ack())
            .await
            .expect("driver must send the first packet")
            .unwrap();
        // Production drops a committed lease after the first-send ack; only
        // the Ready driver, not an initializer guard, survives into reload.
        drop(ready_lease);

        let init_permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let initializing_lease = match pool.reserve_or_enqueue(
            initializing_client,
            dst,
            b"initializing",
            init_permit,
            &stats,
        ) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("reload fixture must reserve an initializing entry"),
        };
        let mut cancellation = initializing_lease.cancellation();
        let initializer = tokio::spawn(async move {
            cancellation
                .changed()
                .await
                .expect("reload must broadcast initializer cancellation");
            drop(initializing_lease);
        });

        let mut new_config = Config::default();
        new_config.global.check_interval_secs += 1;
        let drain = DrainTracker::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            cp.apply_runtime_config(new_config, &drain),
        )
        .await
        .expect("reload must complete");
        initializer.await.unwrap();
        assert!(pool.get(initializing_client, dst).is_none());
        assert!(
            Arc::ptr_eq(&pool.get(ready_client, dst).unwrap(), &ready_endpoint),
            "ordinary reload must not retire Ready endpoint drivers"
        );

        // After production reload cancellation the Ready driver must still
        // accept and deliver a steady packet (or at least enqueue+transport).
        let follower_permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(ready_client, dst, b"after-reload", follower_permit, &stats,),
            EndpointReservation::Enqueued
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            transport.wait_for_send_count(2),
        )
        .await
        .expect("Ready endpoint driver must survive reload");
        assert_eq!(
            transport.sent_packets(),
            vec![b"ready-first".to_vec(), b"after-reload".to_vec()]
        );

        let replacement_permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        assert!(matches!(
            pool.reserve_or_enqueue(
                initializing_client,
                dst,
                b"next-generation",
                replacement_permit,
                &stats,
            ),
            EndpointReservation::Initializing(_)
        ));
        assert_eq!(
            cp.config_handle().read().await.global.check_interval_secs,
            Config::default().global.check_interval_secs + 1
        );
        pool.remove(ready_client, dst);
        pool.remove(initializing_client, dst);
    }

    #[tokio::test(start_paused = true)]
    async fn reload_timeout_keeps_runtime_and_restores_admission() {
        let cp = Arc::new(test_cp().await);
        let pool = cp.udp_pool.clone();
        let stats = Arc::new(StatsManager::new());
        let client: std::net::SocketAddr = "10.0.0.9:53000".parse().unwrap();
        let dst: std::net::SocketAddr = "203.0.113.9:443".parse().unwrap();
        let slow_permit = Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let lease = match pool.reserve_or_enqueue(client, dst, b"held", slow_permit, &stats) {
            EndpointReservation::Initializing(lease) => lease,
            _ => panic!("timeout fixture must hold a real initializer lease"),
        };
        let mut cancellation = lease.cancellation();
        let before = cp.config_handle().read().await.global.check_interval_secs;
        let mut next = Config::default();
        next.global.check_interval_secs += 1;
        let drain = Arc::new(DrainTracker::new());
        let reloading_cp = Arc::clone(&cp);
        let reloading_drain = Arc::clone(&drain);
        let reloader = tokio::spawn(async move {
            reloading_cp
                .apply_runtime_config(next, reloading_drain.as_ref())
                .await;
        });

        cancellation
            .changed()
            .await
            .expect("reload must cancel the held initializer before waiting");
        assert!(
            drain.should_reject(),
            "reload must fail closed while it waits"
        );
        tokio::time::advance(Duration::from_secs(5) + Duration::from_millis(1)).await;
        reloader.await.unwrap();

        assert_eq!(
            cp.config_handle().read().await.global.check_interval_secs,
            before,
            "a timed-out initializer must prevent the runtime/config swap"
        );
        assert!(
            !drain.should_reject(),
            "an aborted reload must restore admission after its timeout"
        );
        assert_eq!(
            pool.len(),
            1,
            "the real initializer remains held until its owner drops it"
        );
        drop(lease);
        assert!(pool.is_empty());
    }

    /// A valid reload commits: config is swapped and eBPF routing is pushed.
    #[tokio::test]
    async fn valid_reload_commits() {
        let expected_interval = Config::default().global.check_interval_secs + 1;
        let cp = test_cp().await;
        let before_runtime = cp.dns_controller.runtime_provider().acquire();
        let cache = before_runtime.runtime().cache();
        assert_eq!(
            before_runtime.runtime().routing_projection().generation(),
            0
        );
        drop(before_runtime);
        let mut good = Config::default();
        good.global.check_interval_secs = expected_interval;
        let drain = DrainTracker::new();
        cp.apply_runtime_config(good, &drain).await;
        assert_eq!(
            cp.config_handle().read().await.global.check_interval_secs,
            expected_interval,
            "valid reload should swap the live config"
        );
        let after_runtime = cp.dns_controller.runtime_provider().acquire();
        assert!(Arc::ptr_eq(&after_runtime.runtime().cache(), &cache));
        assert_eq!(after_runtime.runtime().routing_projection().generation(), 1);
    }

    #[tokio::test]
    async fn routing_push_failure_replays_old_plan_and_keeps_userspace_generation() {
        let cp = test_cp().await;
        cp.ebpf
            .write()
            .await
            .inject_routing_fault(RoutingPushPhase::Meta, 1)
            .unwrap();
        let mut replacement = Config::default();
        replacement.global.check_interval_secs += 1;

        cp.apply_runtime_config(replacement, &DrainTracker::new())
            .await;

        assert_eq!(
            cp.config_handle().read().await.global.check_interval_secs,
            Config::default().global.check_interval_secs,
        );
        assert!(cp.is_datapath_healthy());
        assert!(!cp.drain_tracker.should_reject());
    }

    #[tokio::test]
    async fn domain_route_staging_failure_keeps_the_active_generation() {
        let cp = test_cp().await;
        let before = cp.ebpf.read().await.active_routing_generation().unwrap();
        cp.ebpf
            .write()
            .await
            .inject_routing_fault(RoutingPushPhase::DomainRouting, 1)
            .unwrap();
        let mut replacement = Config::default();
        replacement.global.check_interval_secs += 1;

        cp.apply_runtime_config(replacement, &DrainTracker::new())
            .await;
        assert_eq!(
            cp.ebpf.read().await.active_routing_generation().unwrap(),
            before
        );
        assert_eq!(
            cp.config_handle().read().await.global.check_interval_secs,
            Config::default().global.check_interval_secs,
        );
        assert!(cp.is_datapath_healthy());
        assert!(!cp.drain_tracker.should_reject());
    }

    #[tokio::test]
    async fn replay_failure_marks_unhealthy_and_rejects_connections() {
        let cp = test_cp().await;
        cp.ebpf
            .write()
            .await
            .inject_routing_fault(RoutingPushPhase::Meta, 2)
            .unwrap();

        cp.apply_runtime_config(Config::default(), &DrainTracker::new())
            .await;

        assert!(!cp.is_datapath_healthy());
        assert!(cp.drain_tracker.should_reject());

        let mut invalid = Config::default();
        invalid.dns.upstream[0].address.clear();
        cp.apply_runtime_config(invalid, &DrainTracker::new()).await;
        cp.apply_runtime_config(Config::default(), &DrainTracker::new())
            .await;

        assert!(!cp.is_datapath_healthy());
        assert!(cp.drain_tracker.should_reject());
    }

    #[tokio::test]
    async fn default_udp_warm_is_disabled_without_a_task_or_metrics() {
        let cp = test_cp().await;
        let generation = cp.runtime_registry.read().clone();

        cp.start_udp_warm_coordinator(generation).await;

        assert!(
            cp.udp_warm_task.lock().await.is_none(),
            "the default zero count must not spawn udp_warm_task"
        );
        let snapshot = cp.stats.udp_snapshot();
        assert_eq!(
            (
                snapshot.warm_attempts,
                snapshot.warm_successes,
                snapshot.warm_failures
            ),
            (0, 0, 0),
            "the strict no-op must not touch warm metrics"
        );
    }

    #[test]
    fn selector_warm_candidates_follow_configured_leaves_and_deduplicate() {
        let node = |name: &str, protocol| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let anytls = node("selector-anytls", NodeProtocol::AnyTLS);
        let socks = node("selector-socks", NodeProtocol::Socks5);
        let direct = node("selector-direct", NodeProtocol::Direct);
        let groups = vec![
            Group {
                name: "first".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![anytls.id, direct.id],
                ..Default::default()
            },
            Group {
                name: "shared".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![anytls.id],
                ..Default::default()
            },
            Group {
                name: "child".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![socks.id],
                ..Default::default()
            },
            Group {
                name: "parent".into(),
                policy: GroupPolicy::Selector,
                groups: vec!["child".into()],
                ..Default::default()
            },
        ];
        let config = Config {
            nodes: vec![anytls.clone(), socks.clone(), direct],
            groups,
            ..Default::default()
        };
        let manager = GroupManager::new(&config.groups, &config.nodes);
        let generation =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            selector_warm_candidates(&config, &manager, &generation)
                .into_iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            vec![anytls.id, socks.id]
        );
    }

    #[tokio::test]
    async fn selector_choice_switch_replaces_bare_tcp_pin_immediately() {
        let first_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_socket = first_listener.local_addr().unwrap();
        let second_socket = second_listener.local_addr().unwrap();
        let first_addr = first_socket.to_string();
        let second_addr = second_socket.to_string();
        let first = Node {
            id: uuid::Uuid::new_v4(),
            name: "selector-first".into(),
            protocol: NodeProtocol::Socks5,
            address: first_addr.clone(),
            host: first_socket.ip().to_string(),
            port: first_socket.port(),
            ..Default::default()
        };
        let second = Node {
            id: uuid::Uuid::new_v4(),
            name: "selector-second".into(),
            protocol: NodeProtocol::Socks5,
            address: second_addr.clone(),
            host: second_socket.ip().to_string(),
            port: second_socket.port(),
            ..Default::default()
        };
        let config = Config {
            nodes: vec![first.clone(), second.clone()],
            groups: vec![Group {
                name: "manual".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![first.id, second.id],
                ..Default::default()
            }],
            ..Default::default()
        };
        let manager = Arc::new(GroupManager::new(&config.groups, &config.nodes));
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap(),
        );
        assert_eq!(
            selector_warm_candidates(&config, &manager, &generation)
                .into_iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            vec![first.id]
        );
        let cp = test_cp().await;
        *cp.config.write().await = config;
        *cp.group_manager.write() = Arc::clone(&manager);
        *cp.runtime_registry.write() = Arc::clone(&generation);
        install_selector_warm_callback(&manager, &cp.selector_warm_notify);

        cp.start_selector_warm_coordinator(Arc::clone(&generation))
            .await;
        let (first_server, _) =
            tokio::time::timeout(Duration::from_secs(1), first_listener.accept())
                .await
                .expect("first selector must preconnect")
                .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cp.connection_pool.has_live_bare_entry(&first_addr) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        manager.set_selector_choice("manual", "selector-second");
        let (second_server, _) =
            tokio::time::timeout(Duration::from_secs(1), second_listener.accept())
                .await
                .expect("choice change must preconnect immediately")
                .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while cp.connection_pool.has_live_bare_entry(&first_addr)
                || !cp.connection_pool.has_live_bare_entry(&second_addr)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("choice change must replace the old pin");

        drop((first_server, second_server));
        cp.stop_selector_warm_coordinator().await;
        generation.shutdown().await;
    }

    #[tokio::test]
    async fn changed_selector_bare_endpoint_is_purged_before_failed_replacement() {
        let old_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_socket = old_listener.local_addr().unwrap();
        let old_addr = old_socket.to_string();
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "selector-moved".into(),
            protocol: NodeProtocol::Socks5,
            address: old_addr.clone(),
            host: old_socket.ip().to_string(),
            port: old_socket.port(),
            ..Default::default()
        };
        let generation = Arc::new(
            honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                .unwrap(),
        );
        let cp = test_cp().await;
        let resources = SelectorWarmResources {
            generation: Arc::clone(&generation),
            proxy_registry: cp.proxy_registry.clone(),
            connection_pool: cp.connection_pool.clone(),
            stats: cp.stats.clone(),
            selected_ids: cp.selector_warm_ids.clone(),
            bare_warm: cp.selector_bare_warm.clone(),
        };

        warm_selector_candidate(node.clone(), resources.clone(), Duration::from_secs(1)).await;
        let (old_server, _) = tokio::time::timeout(Duration::from_secs(1), old_listener.accept())
            .await
            .expect("initial selector must preconnect")
            .unwrap();
        assert!(cp.connection_pool.has_live_bare_entry(&old_addr));
        assert_eq!(cp.selector_bare_warm.lock().get(&node.id), Some(&old_addr));

        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_socket = unavailable.local_addr().unwrap();
        drop(unavailable);
        let mut moved = node.clone();
        moved.address = unavailable_socket.to_string();
        moved.host = unavailable_socket.ip().to_string();
        moved.port = unavailable_socket.port();
        warm_selector_candidate(moved, resources, Duration::from_millis(100)).await;

        assert!(!cp.connection_pool.has_live_bare_entry(&old_addr));
        assert!(!cp.selector_bare_warm.lock().contains_key(&node.id));
        assert_eq!(
            cp.stats
                .warm_snapshot(&generation, &cp.connection_pool)
                .selector_nodes,
            0
        );

        drop(old_server);
        generation.shutdown().await;
    }

    #[test]
    fn udp_warm_candidates_only_use_authoritative_group_leaves() {
        let node = |name: &str, protocol| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let anytls = node("anytls", honk_config::types::NodeProtocol::AnyTLS);
        let nested_warmable = node("socks", honk_config::types::NodeProtocol::AnyTLS);
        let cold = node("cold", honk_config::types::NodeProtocol::VMess);
        let standalone = node("standalone", honk_config::types::NodeProtocol::VMess);
        let groups = vec![
            Group {
                name: "first".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![anytls.id],
                ..Default::default()
            },
            Group {
                name: "nested".into(),
                policy: GroupPolicy::Selector,
                nodes: vec![nested_warmable.id],
                ..Default::default()
            },
            Group {
                name: "parent".into(),
                policy: GroupPolicy::Selector,
                groups: vec!["nested".into()],
                ..Default::default()
            },
            Group {
                name: "via-final".into(),
                policy: GroupPolicy::Selector,
                final_outbound: Some("parent".into()),
                ..Default::default()
            },
            Group {
                name: "cold-urltest".into(),
                policy: GroupPolicy::URLTest,
                nodes: vec![cold.id],
                ..Default::default()
            },
            Group {
                name: "direct-final".into(),
                policy: GroupPolicy::Selector,
                final_outbound: Some("direct".into()),
                ..Default::default()
            },
        ];
        let mut config = Config::default();
        config.routing.default_outbound = "direct".into();
        config.nodes = vec![anytls.clone(), nested_warmable.clone(), cold, standalone];
        config.groups = groups;
        let manager = GroupManager::new(&config.groups, &config.nodes);
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 8),
            vec![anytls.id, nested_warmable.id],
            "V4/V6 and final/nested paths deduplicate UUIDs; cold/standalone stay out, \
             direct-final contributes nothing"
        );
        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 1),
            vec![anytls.id, nested_warmable.id],
            "the count is a per-group cap; the process-wide cap (4x) does not bind here"
        );
        assert!(udp_warm_candidates(&config, &manager, &runtime, 0).is_empty());
    }

    #[test]
    fn udp_warm_candidates_bound_capacity_and_exclude_explicitly_dead_udp_leaves() {
        let node = |name: &str| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: honk_config::types::NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let dead = node("dead-udp");
        let selected = node("selected");
        let second = node("second");
        let config = Config {
            nodes: vec![dead.clone(), selected.clone(), second.clone()],
            groups: vec![
                Group {
                    name: "first".into(),
                    policy: GroupPolicy::Selector,
                    nodes: vec![dead.id, selected.id],
                    ..Default::default()
                },
                Group {
                    name: "second".into(),
                    policy: GroupPolicy::Selector,
                    nodes: vec![second.id],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let alive = Arc::new(crate::outbound::AliveDialerSet::new());
        for ipver in [IpVersion::V4, IpVersion::V6] {
            alive.report_unavailable_forced(dead.id, ProbeDomain::DataUdp, ipver);
            alive.report_unavailable_forced(dead.id, ProbeDomain::DnsUdp, ipver);
        }
        let manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, usize::MAX),
            vec![selected.id, second.id],
            "an unbounded configured count only returns selectable leaves once across V4/V6"
        );
        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 1),
            vec![selected.id, second.id],
            "a per-group cap of one keeps the best live leaf of every group"
        );
    }

    #[test]
    fn udp_warm_candidates_enforce_a_process_wide_latency_ordered_cap() {
        // Six groups of two leaves: the per-group top-2 alone would retain
        // twelve transports; the process-wide cap (4 x count = 8) keeps only
        // the globally fastest.
        let mut nodes = Vec::new();
        let mut groups = Vec::new();
        for g in 0..6 {
            let mut ids = Vec::new();
            for i in 0..2 {
                let node = Node {
                    id: uuid::Uuid::new_v4(),
                    name: format!("n{g}-{i}"),
                    protocol: honk_config::types::NodeProtocol::AnyTLS,
                    address: "127.0.0.1:9".into(),
                    ..Default::default()
                };
                ids.push(node.id);
                nodes.push(node);
            }
            groups.push(Group {
                name: format!("g{g}"),
                policy: GroupPolicy::Selector,
                nodes: ids,
                ..Default::default()
            });
        }
        // Global latency order: n0-0 fastest (1ms) ... n5-1 slowest (12ms).
        let alive = Arc::new(crate::outbound::AliveDialerSet::new());
        for (index, node) in nodes.iter().enumerate() {
            alive.record_probe_latency(
                node.id,
                ProbeDomain::DataUdp,
                IpVersion::V4,
                Duration::from_millis(index as u64 + 1),
            );
        }
        let config = Config {
            nodes,
            groups,
            ..Default::default()
        };
        let manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        let candidates = udp_warm_candidates(&config, &manager, &runtime, 2);
        let expected: Vec<_> = config.nodes.iter().take(8).map(|n| n.id).collect();
        assert_eq!(candidates, expected);
    }

    #[test]
    fn udp_warm_candidates_do_not_mutate_group_selection_state() {
        let node = |name: &str| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: honk_config::types::NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let (lb_a, lb_b, lb_c) = (node("lb-a"), node("lb-b"), node("lb-c"));
        let (fallback_a, fallback_b, cold) = (node("fallback-a"), node("fallback-b"), node("cold"));
        let fallback = Group {
            name: "fallback".into(),
            policy: GroupPolicy::Fallback,
            nodes: vec![fallback_a.id, fallback_b.id],
            interrupt_connections: true,
            ..Default::default()
        };
        let config = Config {
            nodes: vec![
                lb_a.clone(),
                lb_b.clone(),
                lb_c.clone(),
                fallback_a.clone(),
                fallback_b.clone(),
                cold.clone(),
            ],
            groups: vec![
                Group {
                    name: "load-balance".into(),
                    policy: GroupPolicy::LoadBalance,
                    nodes: vec![lb_a.id, lb_b.id, lb_c.id],
                    ..Default::default()
                },
                Group {
                    name: "cold-urltest".into(),
                    policy: GroupPolicy::URLTest,
                    nodes: vec![cold.id],
                    ..Default::default()
                },
                fallback,
            ],
            ..Default::default()
        };
        let alive = Arc::new(crate::outbound::AliveDialerSet::new());
        alive.register_urltest_group(
            "cold-urltest",
            std::slice::from_ref(&cold.id),
            Some(Duration::from_secs(60)),
        );
        let manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        // Advance LB once and set the fallback pin before observing warm-up.
        assert_eq!(
            manager
                .selection_plan_for_domain("load-balance", ProbeDomain::DataUdp, IpVersion::V4)
                .nodes[0]
                .id,
            lb_a.id
        );
        assert_eq!(
            manager
                .selection_plan_for_domain("fallback", ProbeDomain::DataUdp, IpVersion::V4)
                .nodes[0]
                .id,
            fallback_a.id
        );
        let interrupts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_interrupts = Arc::clone(&interrupts);
        manager.set_interrupt_callback(Some(Arc::new(move |_| {
            callback_interrupts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })));
        for ipver in [IpVersion::V4, IpVersion::V6] {
            for domain in [ProbeDomain::DataUdp, ProbeDomain::DnsUdp] {
                alive.report_unavailable_forced(fallback_a.id, domain, ipver);
            }
        }
        assert!(alive.is_urltest_group_idle("cold-urltest"));
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 4),
            vec![lb_a.id, lb_b.id, lb_c.id, cold.id, fallback_b.id],
            "per-group top-three plus cold URLTest and the live fallback leaf,              UUID-deduplicated across V4/V6"
        );
        assert!(alive.is_urltest_group_idle("cold-urltest"));
        assert_eq!(
            manager.get_fallback_selection_for_network(
                "fallback",
                crate::group::SelectionNetwork::Udp,
            ),
            Some("fallback-a".into())
        );
        assert_eq!(interrupts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            manager
                .selection_plan_for_domain("load-balance", ProbeDomain::DataUdp, IpVersion::V4)
                .nodes[0]
                .id,
            lb_b.id,
            "warm discovery must not consume the next real round-robin pick"
        );
    }

    #[tokio::test]
    async fn udp_warm_coordinator_limits_concurrency_and_keeps_shutdown_errors_neutral() {
        let nodes: Vec<Node> = (0..5)
            .map(|n| Node {
                id: uuid::Uuid::new_v4(),
                name: format!("node-{n}"),
                protocol: honk_config::types::NodeProtocol::Socks5,
                address: "127.0.0.1:9".into(),
                ..Default::default()
            })
            .collect();
        let ids = nodes.iter().map(|node| node.id).collect::<Vec<_>>();
        let generation =
            Arc::new(honk_outbound::runtime::OutboundRuntimeRegistry::build(&nodes).unwrap());
        let stats = Arc::new(StatsManager::new());
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dispatch = {
            let active = active.clone();
            let peak = peak.clone();
            Arc::new(move |_generation, _id| {
                let active = active.clone();
                let peak = peak.clone();
                async move {
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(honk_outbound::proxy::WarmOutcome::Ready)
                }
            })
        };
        run_udp_warm_dispatches(ids, Arc::clone(&generation), stats.clone(), dispatch).await;
        assert_eq!(peak.load(std::sync::atomic::Ordering::SeqCst), 4);
        let snapshot = stats.udp_snapshot();
        assert_eq!(
            (
                snapshot.warm_attempts,
                snapshot.warm_successes,
                snapshot.warm_failures
            ),
            (5, 5, 0)
        );

        generation.shutdown().await;
        let neutral_stats = Arc::new(StatsManager::new());
        let neutral_dispatch = Arc::new(|_generation, _id| async {
            Err(anyhow::anyhow!("old generation was shut down"))
        });
        run_udp_warm_dispatches(
            vec![nodes[0].id],
            generation,
            neutral_stats.clone(),
            neutral_dispatch,
        )
        .await;
        let neutral = neutral_stats.udp_snapshot();
        assert_eq!(
            (
                neutral.warm_attempts,
                neutral.warm_successes,
                neutral.warm_failures
            ),
            (1, 0, 0)
        );
    }

    #[tokio::test]
    async fn udp_warm_dispatch_metrics_distinguish_live_and_terminal_errors_and_panics() {
        #[derive(Clone, Copy)]
        enum Outcome {
            Ready,
            NotApplicable,
            LiveError,
            TerminalError,
            LivePanic,
            TerminalPanic,
        }

        let cases = [
            ("ready", Outcome::Ready, 1, 0),
            ("not-applicable", Outcome::NotApplicable, 0, 0),
            ("live-error", Outcome::LiveError, 0, 1),
            ("terminal-error", Outcome::TerminalError, 0, 0),
            ("live-panic", Outcome::LivePanic, 0, 1),
            ("terminal-panic", Outcome::TerminalPanic, 0, 0),
        ];
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-node".into(),
            protocol: honk_config::types::NodeProtocol::Socks5,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };

        for (name, outcome, expected_successes, expected_failures) in cases {
            let generation = Arc::new(
                honk_outbound::runtime::OutboundRuntimeRegistry::build(std::slice::from_ref(&node))
                    .unwrap(),
            );
            let stats = Arc::new(StatsManager::new());
            let dispatch = Arc::new(
                move |generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
                      _node_id: uuid::Uuid| async move {
                    match outcome {
                        Outcome::Ready => Ok(honk_outbound::proxy::WarmOutcome::Ready),
                        Outcome::NotApplicable => {
                            Ok(honk_outbound::proxy::WarmOutcome::NotApplicable)
                        }
                        Outcome::LiveError => Err(anyhow::anyhow!("live warm error")),
                        Outcome::TerminalError => {
                            generation.shutdown().await;
                            Err(anyhow::anyhow!("terminal warm error"))
                        }
                        Outcome::LivePanic => panic!("live warm panic"),
                        Outcome::TerminalPanic => {
                            generation.shutdown().await;
                            panic!("terminal warm panic")
                        }
                    }
                },
            );

            run_udp_warm_dispatches(vec![node.id], generation, Arc::clone(&stats), dispatch).await;
            let snapshot = stats.udp_snapshot();
            assert_eq!(
                (
                    snapshot.warm_attempts,
                    snapshot.warm_successes,
                    snapshot.warm_failures,
                ),
                (1, expected_successes, expected_failures),
                "{name} outcome must update only its fixed aggregate metric"
            );
        }
    }

    #[tokio::test]
    async fn reload_retires_only_the_old_warm_generation_and_starts_the_new_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct WarmCancellation(Arc<AtomicUsize>);

        impl Drop for WarmCancellation {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[derive(Debug)]
        struct BlockingWarmHandler {
            started: tokio::sync::mpsc::UnboundedSender<Arc<honk_outbound::runtime::NodeRuntime>>,
            cancelled: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl honk_outbound::proxy::TcpOutbound for BlockingWarmHandler {
            async fn dial(
                &self,
                _node: &Node,
                _target: std::net::SocketAddr,
                _target_domain: Option<&str>,
                _connect_timeout: Duration,
            ) -> anyhow::Result<honk_outbound::proxy::ProxyStream> {
                anyhow::bail!("not used by the warm coordinator")
            }
        }

        #[async_trait::async_trait]
        impl honk_outbound::proxy::WarmableOutbound for BlockingWarmHandler {
            async fn warm(
                &self,
                runtime: Arc<honk_outbound::runtime::NodeRuntime>,
                _connect_timeout: Duration,
                _requirement: honk_outbound::proxy::WarmRequirement,
            ) -> anyhow::Result<()> {
                self.started
                    .send(runtime)
                    .expect("warm coordinator receiver must stay open");
                let _cancel = WarmCancellation(self.cancelled.clone());
                std::future::pending::<()>().await;
                unreachable!("pending warm dispatch was unexpectedly completed")
            }
        }

        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-node".into(),
            protocol: honk_config::types::NodeProtocol::AnyTLS,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let mut config = Config::default();
        config.global.udp_warm_node_count = 1;
        config.routing.default_outbound = "warm-group".into();
        config.nodes = vec![node.clone()];
        config.groups = vec![Group {
            name: "warm-group".into(),
            policy: GroupPolicy::Selector,
            nodes: vec![node.id],
            ..Default::default()
        }];
        let router = Router::new(&config.routing.rules, &config.routing.default_outbound).unwrap();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancelled = Arc::new(AtomicUsize::new(0));
        let mut proxy_registry = ProxyRegistry::new();
        let warm_handler = Arc::new(BlockingWarmHandler {
            started: started_tx,
            cancelled: cancelled.clone(),
        });
        proxy_registry.register(
            honk_outbound::proxy::ProtocolEntry::new(
                honk_config::types::NodeProtocol::AnyTLS,
                warm_handler.clone(),
            )
            .with_warmable(warm_handler),
        );
        let mut cp = ControlPlane::new(
            config.clone(),
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(proxy_registry),
            DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
            test_dns_forwarder(),
        )
        .unwrap();
        cp.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", "Proxy"),
        )));
        cp.start_datapath_flags_coordinator().unwrap();
        cp.initialize_datapath_flags(false, false).await.unwrap();

        let old_generation = cp.runtime_registry.read().clone();
        assert_eq!(
            udp_warm_candidates(
                &config,
                &cp.group_manager.read(),
                &old_generation,
                config.global.udp_warm_node_count,
            ),
            vec![node.id]
        );
        cp.start_udp_warm_coordinator(Arc::clone(&old_generation))
            .await;
        let old_runtime = tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .expect("old warm must start")
            .expect("old runtime");
        assert!(Arc::ptr_eq(
            &old_runtime,
            &old_generation.get(&node.id).unwrap()
        ));

        // A failed build must not retire the old task or its generation.
        let mut bad = config.clone();
        bad.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "invalid".into(),
            address: String::new(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];
        cp.apply_runtime_config(bad, &DrainTracker::new()).await;
        assert!(!old_generation.is_shutdown());
        assert_eq!(cancelled.load(Ordering::SeqCst), 0);

        cp.apply_runtime_config(config, &DrainTracker::new()).await;
        let new_runtime = tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .expect("new warm must start after reload")
            .expect("new runtime");
        let new_generation = cp.runtime_registry.read().clone();
        assert!(old_generation.is_shutdown());
        assert!(
            cancelled.load(Ordering::SeqCst) >= 1,
            "old warm must exit after its generation becomes terminal"
        );
        assert!(
            Arc::ptr_eq(&old_runtime, &new_runtime),
            "an unchanged node reuses the old generation's NodeRuntime"
        );
        assert!(Arc::ptr_eq(
            &new_runtime,
            &new_generation.get(&node.id).unwrap()
        ));

        cp.stop_udp_warm_coordinator().await;
        new_generation.shutdown().await;
    }
}
