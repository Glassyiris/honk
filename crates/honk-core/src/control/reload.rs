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
    /// A zero count is a strict no-op: no task is created and no warm metrics
    /// are touched.
    pub(super) async fn start_udp_warm_coordinator(
        &self,
        generation: Arc<honk_outbound::runtime::OutboundRuntimeRegistry>,
    ) {
        if generation.is_shutdown() {
            return;
        }
        let config = self.config.read().await.clone();
        let count = config.global.udp_warm_node_count;
        if count == 0 {
            return;
        }
        let group_manager = self.group_manager.read().clone();
        let candidates = udp_warm_candidates(&config, &group_manager, &generation, count);
        if candidates.is_empty() {
            return;
        }
        let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
        let proxy_registry = self.proxy_registry.clone();
        let dispatch = Arc::new(move |generation, node_id| {
            let proxy_registry = proxy_registry.clone();
            async move {
                proxy_registry
                    .warm_udp(generation, node_id, connect_timeout)
                    .await
            }
        });
        let handle = tokio::spawn(run_udp_warm_dispatches(
            candidates,
            generation,
            self.stats.clone(),
            dispatch,
        ));
        *self.udp_warm_task.lock().await = Some(handle);
    }

    /// Atomically publish a rebuilt router, config, group manager, outbound
    /// runtime generation, DNS runtime, and exact eBPF routing plan. Build
    /// failures leave the current generation untouched; an eBPF push failure
    /// replays the exact active plan before admission resumes. SIGHUP and
    /// subscription merges share this command-channel-serialized path.
    pub(super) async fn apply_runtime_config(&self, new_config: Config, drain: &DrainTracker) {
        let current_config = self.config.read().await.clone();
        let restart_required = restart_required_changes(&current_config, &new_config);
        if !restart_required.is_empty() {
            error!(
                fields = ?restart_required,
                "reload rejected: changed fields require process restart"
            );
            return;
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
                return;
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
                return;
            }
        };
        let new_group_manager = Arc::new(GroupManager::with_alive_set(
            &new_config.groups,
            &new_config.nodes,
            Some(Arc::clone(&self.alive_set)),
        ));
        new_group_manager.migrate_selector_choices_from(&self.group_manager.read());
        // Build the outbound generation before DNS so every new runtime
        // snapshot captures its own immutable node/session ownership.
        let new_runtime_registry = Arc::new(
            match honk_outbound::runtime::OutboundRuntimeRegistry::build(&new_config.nodes) {
                Ok(r) => r,
                Err(e) => {
                    error!("Failed to build runtime registry (reload aborted): {}", e);
                    self.stop_reload_rejection_if_healthy(drain);
                    return;
                }
            },
        );
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
                return;
            }
        };
        let policy_id = match crate::dns::policy::PolicyId::from_config(&new_config.dns) {
            Ok(policy_id) => policy_id,
            Err(error) => {
                error!(%error, "Failed to build DNS policy identity");
                self.stop_reload_rejection_if_healthy(drain);
                return;
            }
        };
        let new_outbound_id_map = build_outbound_id_map(&new_config);
        let bootstrap = new_config.global.bootstrap_resolver.clone();
        let direct_target = super::direct_check_addr(&bootstrap);
        let direct_target_socket = match direct_target.parse() {
            Ok(target) => target,
            Err(error) => {
                error!(%error, "Failed to prepare direct health-check target");
                self.stop_reload_rejection_if_healthy(drain);
                return;
            }
        };
        let bootstrap_resolver = honk_outbound::bootstrap::BootstrapResolver::parse(&bootstrap);
        let new_plan = match Self::compile_routing_plan(&new_config, &new_router) {
            Ok(plan) => Arc::new(plan),
            Err(error) => {
                error!(%error, "Failed to compile routing publication");
                self.stop_reload_rejection_if_healthy(drain);
                return;
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
        let (persistence, old_projection_snapshot) = {
            let current = self.dns_controller.runtime_provider().acquire();
            (
                Arc::clone(current.runtime().persistence()),
                Arc::clone(current.runtime().routing_projection()),
            )
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
                router: Arc::clone(&pinned_router),
                group_manager: Arc::clone(&new_group_manager),
                policy_id,
                routing_projection: Arc::clone(&projection_snapshot),
                cache: self.dns_controller.cache().await,
                persistence,
                outbound_runtime: Some(Arc::clone(&new_runtime_registry)),
                transport: new_upstream_pool,
            });

        let route_count = new_router.route_count();
        // All fallible preparation is complete. Fence only the atomic routing
        // publication: existing Ready UDP endpoints remain independently
        // serviceable, while new TCP/UDP slow-path admissions cannot observe a
        // half-published eBPF/runtime generation.
        drain.start_rejecting();
        if !self.udp_pool.cancel_initializers_and_wait().await {
            warn!("UDP initializers did not drain before reload commit");
            self.stop_reload_rejection_if_healthy(drain);
            return;
        }
        let old_registry = {
            let mut router_guard = self.router.write().await;
            let mut config_guard = self.config.write().await;
            let mut ebpf = self.ebpf.write().await;
            let mut group_guard = self.group_manager.write();
            let mut outbound_guard = self.outbound_id_map.write();
            let mut plan_guard = self.active_routing_plan.write();
            let mut runtime_guard = self.runtime_registry.write();
            let provider = self.dns_controller.runtime_provider();
            let publication = provider.prepare_publication(new_runtime);

            let active_generation = match ebpf.active_routing_generation() {
                Ok(generation) => generation,
                Err(error) => {
                    error!(%error, "Failed to read active routing generation");
                    self.stop_reload_rejection_if_healthy(drain);
                    return;
                }
            };
            let next_generation =
                active_generation ^ (honk_ebpf_common::ROUTING_GENERATION_COUNT as u32 - 1);
            if let Err(error) =
                ebpf.stage_domain_routing_generation(next_generation, &new_domain_routes)
            {
                error!(%error, "Failed to stage learned domain routes");
                self.stop_reload_rejection_if_healthy(drain);
                return;
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
                    });
                match replay {
                    Ok(()) => {
                        error!(
                            %error,
                            "Failed to push routing to eBPF; exact active plan replayed"
                        );
                        self.stop_reload_rejection_if_healthy(drain);
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
                return;
            }

            let old_registry =
                std::mem::replace(&mut *runtime_guard, Arc::clone(&new_runtime_registry));
            publication.commit();
            *router_guard = new_router;
            *config_guard = new_config;
            *group_guard = Arc::clone(&new_group_manager);
            *outbound_guard = new_outbound_id_map;
            *plan_guard = Arc::clone(&new_plan);
            old_registry
        };

        self.dns_controller
            .update_projection_snapshot(projection_snapshot);
        routing_matcher::RoutingMatcherBuilder::activate_projection(&new_plan);
        honk_outbound::bootstrap::set_global(bootstrap_resolver);
        self.alive_set.set_direct_check_addr(direct_target);
        honk_outbound::urltest::set_urltest_direct_target(direct_target_socket);
        install_interrupt_callback(
            &new_group_manager,
            &self.group_manager,
            &self.connection_tracker,
        );
        // No new generation-owned work may start on the old snapshot. Its
        // DNS runtime still owns it until old leases and transports retire;
        // only then do the pools enter graceful session drain.
        old_registry.begin_retirement();
        self.stop_udp_warm_coordinator().await;
        self.start_udp_warm_coordinator(new_runtime_registry).await;
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
        info!("Configuration applied — {} routes active", route_count);

        self.stop_reload_rejection_if_healthy(drain);
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
            .with_strategy(config.dns.strategy.clone())
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(&config.dns)?,
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
    changed
}

/// Select the real current DataUdp leaves of configured groups for one warm
/// generation. This deliberately reuses the data-plane resolver, preserving
/// nested/final choices and UDP liveness; cold URLTest plans, synthetic
/// direct/block leaves, standalone nodes, and missing runtime entries stay
/// out. UUID order is first occurrence in configured group, V4, then V6
/// order and the supplied budget counts dispatches, not successes.
pub(super) fn udp_warm_candidates(
    config: &Config,
    group_manager: &GroupManager,
    generation: &honk_outbound::runtime::OutboundRuntimeRegistry,
    budget: usize,
) -> Vec<uuid::Uuid> {
    if budget == 0 || generation.is_shutdown() {
        return Vec::new();
    }
    let configured_ids: std::collections::HashSet<uuid::Uuid> =
        config.nodes.iter().map(|node| node.id).collect();
    let mut selected = Vec::with_capacity(budget.min(config.nodes.len()));
    let mut seen = std::collections::HashSet::new();
    for group in &config.groups {
        for ipver in [IpVersion::V4, IpVersion::V6] {
            let plan = resolve_udp_outbound_plan_peek(config, group_manager, &group.name, ipver);
            if plan.mode == honk_outbound::group::SelectionPlanMode::ColdUrlTest {
                continue;
            }
            for node in plan.nodes {
                if node.name == "direct" || node.name == "block" {
                    continue;
                }
                if !configured_ids.contains(&node.id) || generation.get(&node.id).is_none() {
                    continue;
                }
                if seen.insert(node.id) {
                    selected.push(node.id);
                    if selected.len() == budget {
                        return selected;
                    }
                }
            }
        }
    }
    selected
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
    Fut: std::future::Future<Output = anyhow::Result<honk_outbound::proxy::UdpWarmStatus>>
        + Send
        + 'static,
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
                    Ok(
                        honk_outbound::proxy::UdpWarmStatus::Ready
                        | honk_outbound::proxy::UdpWarmStatus::AlreadyReady,
                    ) => stats.record_udp_warm_success(),
                    Ok(honk_outbound::proxy::UdpWarmStatus::NotApplicable) => {}
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
    // Group membership is filter-derived state: drop dangling IDs left
    // behind by replaced subscription nodes (refreshed parses mint fresh
    // UUIDs), then re-resolve filters against the merged node set.
    let live: std::collections::HashSet<uuid::Uuid> = config.nodes.iter().map(|n| n.id).collect();
    for group in &mut config.groups {
        group.nodes.retain(|id| live.contains(id));
    }
    honk_config::parser::resolve_group_filters(&mut config.groups, &config.nodes);
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
/// Returns `(node name, address)` pairs.
fn health_check_targets(config: &Config) -> Vec<(String, String)> {
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
        .map(|n| (n.name.clone(), n.address.clone()))
        .collect()
}

/// Synchronize alive-set health-check registrations with the config's
/// group membership: register nodes that are new or whose address changed,
/// remove nodes that left the checked set. Unchanged registrations keep
/// their probe state and grace period. Returns `(added, removed)` counts.
pub(super) fn sync_health_check_nodes(
    alive_set: &AliveDialerSet,
    config: &Config,
) -> (usize, usize) {
    let desired: std::collections::HashMap<String, String> =
        health_check_targets(config).into_iter().collect();
    let current = alive_set.registered_nodes();
    let mut added = 0usize;
    for (name, addr) in &desired {
        if current.get(name) != Some(addr) {
            alive_set.register_node(name.clone(), addr.clone());
            added += 1;
        }
    }
    let mut removed = 0usize;
    for name in current.keys() {
        if !desired.contains_key(name) {
            alive_set.remove_node(name);
            removed += 1;
        }
    }
    (added, removed)
}

/// URLTest group registrations for the alive set's idle-suspension table:
/// `(group name, member node names, idle timeout)` per URLTest group.
/// Members shared with any non-URLTest group (Selector, LoadBalance,
/// Fallback) are excluded — those are probed unconditionally, same as
/// Selector members. Nested sub-groups are expanded to their leaf nodes
/// (health state lives on real nodes). Used identically at startup and on
/// config reload.
pub(super) fn urltest_group_registrations(
    config: &Config,
) -> Vec<(String, Vec<String>, Option<Duration>)> {
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
            let members: Vec<String> = leaf_ids(group)
                .into_iter()
                .filter(|id| !always_probed_node_ids.contains(id))
                .filter_map(|id| config.nodes.iter().find(|n| n.id == id))
                .map(|n| n.name.clone())
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
                tracker.close_connection(&snap.id);
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

/// Build the node name → eBPF outbound id map used for
/// `OUTBOUND_CONNECTIVITY_MAP` pushes. Numbering matches
/// `push_routing_to_ebpf`: direct=0, block=1, group i → `UserBase + i`;
/// group member nodes inherit their group's id (first group wins when a
/// node is in several groups), with nested sub-groups expanded to their
/// leaves so a leaf dialed via a sub-group still maps to the top group's
/// slot. Nodes outside any group have no eBPF outbound id and are absent
/// from the map.
pub(super) fn build_outbound_id_map(config: &Config) -> std::collections::HashMap<String, u8> {
    let by_name = groups_by_name(config);
    let mut map = std::collections::HashMap::new();
    for (i, group) in config.groups.iter().enumerate() {
        let id = OutboundIndex::UserBase as u8 + i as u8;
        let mut leaf_ids = std::collections::BTreeSet::new();
        collect_group_leaf_ids(group, &by_name, 0, &mut Vec::new(), &mut leaf_ids);
        for node_id in leaf_ids {
            if let Some(node) = config.nodes.iter().find(|n| n.id == node_id) {
                map.entry(node.name.clone()).or_insert(id);
            }
        }
    }
    map
}

pub(super) fn resolve_outbound_nodes(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    domain: ProbeDomain,
    ipver: IpVersion,
) -> Vec<Node> {
    if outbound_name == "direct" || outbound_name == "block" {
        return vec![Node {
            name: outbound_name.into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
            ..Default::default()
        }];
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
    vec![Node {
        name: "direct".into(),
        protocol: honk_config::types::NodeProtocol::HTTP,
        ..Default::default()
    }]
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

/// Select whether recursive UDP plan resolution is serving traffic or only
/// observing it for warm-up. The complete final/nesting/family fallback walk
/// is shared; only the GroupManager selection effects differ.
#[derive(Clone, Copy)]
enum UdpResolutionEffects {
    Apply,
    Peek,
}

fn direct_udp_plan(name: &str, ipver: IpVersion) -> ResolvedUdpPlan {
    ResolvedUdpPlan {
        mode: honk_outbound::group::SelectionPlanMode::Authoritative,
        nodes: vec![Node {
            name: name.into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
            ..Default::default()
        }],
        ipver,
    }
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
        UdpResolutionEffects::Apply,
    )
}

/// Resolve the same UDP plan as the data path without causing any group
/// selection side effects. Warm-up may read liveness and current choices, but
/// must not consume a round-robin cursor, wake URLTest, write a cache, or
/// interrupt active connections.
fn resolve_udp_outbound_plan_peek(
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
        UdpResolutionEffects::Peek,
    )
}

fn resolve_udp_outbound_plan_inner(
    config: &Config,
    group_manager: &GroupManager,
    outbound_name: &str,
    ipver: IpVersion,
    depth: usize,
    visited: &mut Vec<String>,
    effects: UdpResolutionEffects,
) -> ResolvedUdpPlan {
    if outbound_name == "direct" || outbound_name == "block" {
        return direct_udp_plan(outbound_name, ipver);
    }
    if let Some(node) = config.nodes.iter().find(|node| node.name == outbound_name) {
        let mut selected_ipver = ipver;
        let nodes = if group_manager.is_node_selectable_for_domain(
            &node.name,
            ProbeDomain::DataUdp,
            selected_ipver,
        ) {
            vec![node.clone()]
        } else if ipver == IpVersion::V6
            && group_manager.is_node_selectable_for_domain(
                &node.name,
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
        return direct_udp_plan("direct", ipver);
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
    let mut plan = match effects {
        UdpResolutionEffects::Apply => group_manager.selection_plan_for_domain(
            &group.name,
            ProbeDomain::DataUdp,
            selected_ipver,
        ),
        UdpResolutionEffects::Peek => group_manager.peek_selection_plan_for_domain(
            &group.name,
            ProbeDomain::DataUdp,
            selected_ipver,
        ),
    };
    // Proxy servers frequently have only an A record. Preserve that concrete
    // fallback family for traffic health feedback rather than reporting the
    // original IPv6 destination family.
    if plan.nodes.is_empty() && ipver == IpVersion::V6 {
        plan = match effects {
            UdpResolutionEffects::Apply => group_manager.selection_plan_for_domain(
                &group.name,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            ),
            UdpResolutionEffects::Peek => group_manager.peek_selection_plan_for_domain(
                &group.name,
                ProbeDomain::DataUdp,
                IpVersion::V4,
            ),
        };
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
            effects,
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

    fn test_cp() -> ControlPlane {
        ControlPlane::new(
            Config::default(),
            Box::new(MockEbpfBackend::new()),
            Router::new(&[], "direct").unwrap(),
            std::sync::Arc::new(ProxyRegistry::default_resolver().unwrap()),
            DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
            test_dns_forwarder(),
        )
        .unwrap()
    }

    /// A reload whose build phase fails (invalid upstream address) must abort
    /// without touching the live config — the atomicity guarantee of the
    /// two-phase apply.
    #[tokio::test]
    async fn build_failure_leaves_live_config_untouched() {
        let cp = test_cp();
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

        let cp = test_cp();
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
            "ready-node".into(),
        ));
        let queue_rx = ready_lease.take_queue_receiver().unwrap();
        let reply_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mut driver = pool.spawn_driver(
            ready_client,
            dst,
            ready_lease.generation(),
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
        let cp = Arc::new(test_cp());
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
        let cp = test_cp();
        let before_runtime = cp.dns_controller.runtime_provider().acquire();
        let persistence_id = before_runtime.runtime().persistence().identity();
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
        assert_eq!(
            after_runtime.runtime().persistence().identity(),
            persistence_id
        );
        assert_eq!(after_runtime.runtime().routing_projection().generation(), 1);
    }

    #[tokio::test]
    async fn routing_push_failure_replays_old_plan_and_keeps_userspace_generation() {
        let cp = test_cp();
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
        let cp = test_cp();
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
        let cp = test_cp();
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
        let cp = test_cp();
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
    fn udp_warm_candidates_only_use_authoritative_group_leaves() {
        let node = |name: &str, protocol| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol,
            address: "127.0.0.1:9".into(),
            ..Default::default()
        };
        let anytls = node("anytls", honk_config::types::NodeProtocol::AnyTLS);
        let socks = node("socks", honk_config::types::NodeProtocol::Socks5);
        let cold = node("cold", honk_config::types::NodeProtocol::HTTP);
        let standalone = node("standalone", honk_config::types::NodeProtocol::HTTP);
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
                nodes: vec![socks.id],
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
        config.nodes = vec![anytls.clone(), socks.clone(), cold, standalone];
        config.groups = groups;
        let manager = GroupManager::new(&config.groups, &config.nodes);
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 8),
            vec![anytls.id, socks.id],
            "V4/V6 and final/nested paths deduplicate UUIDs; cold/direct/standalone stay out"
        );
        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 1),
            vec![anytls.id]
        );
        assert!(udp_warm_candidates(&config, &manager, &runtime, 0).is_empty());
    }

    #[test]
    fn udp_warm_candidates_bound_capacity_and_exclude_explicitly_dead_udp_leaves() {
        let node = |name: &str| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
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
            alive.report_unavailable_forced(&dead.name, ProbeDomain::DataUdp, ipver);
            alive.report_unavailable_forced(&dead.name, ProbeDomain::DnsUdp, ipver);
        }
        let manager =
            GroupManager::with_alive_set(&config.groups, &config.nodes, Some(Arc::clone(&alive)));
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, usize::MAX),
            vec![selected.id, second.id],
            "an unbounded configured budget only returns selectable leaves once across V4/V6"
        );
        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 1),
            vec![selected.id],
            "the first live leaf is retained while the budget still bounds dispatches"
        );
    }

    #[test]
    fn udp_warm_candidates_do_not_mutate_group_selection_state() {
        let node = |name: &str| Node {
            id: uuid::Uuid::new_v4(),
            name: name.into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
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
            std::slice::from_ref(&cold.name),
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
                alive.report_unavailable_forced(&fallback_a.name, domain, ipver);
            }
        }
        assert!(alive.is_urltest_group_idle("cold-urltest"));
        let runtime =
            honk_outbound::runtime::OutboundRuntimeRegistry::build(&config.nodes).unwrap();

        assert_eq!(
            udp_warm_candidates(&config, &manager, &runtime, 4),
            vec![lb_b.id, fallback_b.id],
            "V4/V6 observe the same next LB pick and UUID-deduplicate it"
        );
        assert!(alive.is_urltest_group_idle("cold-urltest"));
        assert_eq!(
            manager.get_fallback_selection("fallback"),
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
                protocol: honk_config::types::NodeProtocol::HTTP,
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
                    Ok(honk_outbound::proxy::UdpWarmStatus::Ready)
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

        generation.shutdown();
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
            AlreadyReady,
            NotApplicable,
            LiveError,
            TerminalError,
            LivePanic,
            TerminalPanic,
        }

        let cases = [
            ("ready", Outcome::Ready, 1, 0),
            ("already-ready", Outcome::AlreadyReady, 1, 0),
            ("not-applicable", Outcome::NotApplicable, 0, 0),
            ("live-error", Outcome::LiveError, 0, 1),
            ("terminal-error", Outcome::TerminalError, 0, 0),
            ("live-panic", Outcome::LivePanic, 0, 1),
            ("terminal-panic", Outcome::TerminalPanic, 0, 0),
        ];
        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-node".into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
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
                        Outcome::Ready => Ok(honk_outbound::proxy::UdpWarmStatus::Ready),
                        Outcome::AlreadyReady => {
                            Ok(honk_outbound::proxy::UdpWarmStatus::AlreadyReady)
                        }
                        Outcome::NotApplicable => {
                            Ok(honk_outbound::proxy::UdpWarmStatus::NotApplicable)
                        }
                        Outcome::LiveError => Err(anyhow::anyhow!("live warm error")),
                        Outcome::TerminalError => {
                            generation.shutdown();
                            Err(anyhow::anyhow!("terminal warm error"))
                        }
                        Outcome::LivePanic => panic!("live warm panic"),
                        Outcome::TerminalPanic => {
                            generation.shutdown();
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
        impl honk_outbound::proxy::ProxyHandler for BlockingWarmHandler {
            fn protocol(&self) -> honk_config::types::NodeProtocol {
                honk_config::types::NodeProtocol::HTTP
            }

            async fn warm_udp(
                &self,
                runtime: Arc<honk_outbound::runtime::NodeRuntime>,
                _connect_timeout: Duration,
            ) -> anyhow::Result<honk_outbound::proxy::UdpWarmStatus> {
                self.started
                    .send(runtime)
                    .expect("warm coordinator receiver must stay open");
                let _cancel = WarmCancellation(self.cancelled.clone());
                std::future::pending::<()>().await;
                unreachable!("pending warm dispatch was unexpectedly completed")
            }

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

        let node = Node {
            id: uuid::Uuid::new_v4(),
            name: "warm-node".into(),
            protocol: honk_config::types::NodeProtocol::HTTP,
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
        proxy_registry.register(Box::new(BlockingWarmHandler {
            started: started_tx,
            cancelled: cancelled.clone(),
        }));
        let cp = ControlPlane::new(
            config.clone(),
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(proxy_registry),
            DnsResolver::new(&honk_config::dns::DnsConfig::default()).unwrap(),
            test_dns_forwarder(),
        )
        .unwrap();

        let old_generation = cp.runtime_registry.read().clone();
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
            !Arc::ptr_eq(&old_runtime, &new_runtime),
            "the reload must not reuse an old NodeRuntime"
        );
        assert!(Arc::ptr_eq(
            &new_runtime,
            &new_generation.get(&node.id).unwrap()
        ));

        cp.stop_udp_warm_coordinator().await;
        new_generation.shutdown();
    }
}
