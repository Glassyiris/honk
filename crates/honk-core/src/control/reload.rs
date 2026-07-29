use super::*;

impl ControlPlane {
    /// Apply a rebuilt config to the running control plane: swap the
    /// userspace router and the shared config, refresh the node→outbound id
    /// map, rebuild the GroupManager (migrating runtime selector choices),
    /// recreate the DNS forwarder, and push routing into eBPF (two-phase
    /// commit in `build_and_push`), then rebuild learned domain routes.
    ///
    /// This is the single rebuild pipeline shared by the SIGHUP
    /// `ReloadConfig` path and background `MergeSubscription` merges; both
    /// are serialized through the command channel, so concurrent reloads and
    /// merges can never interleave. New connections are rejected briefly
    /// while the swap happens.
    /// Apply a rebuilt config to the running control plane, as an atomic
    /// two-phase commit:
    ///
    /// 1. **Build** — construct the new Router, DNS forwarder and outbound id
    ///    map from `new_config` *without touching any live state*. Any failure
    ///    here aborts with the current generation fully intact.
    /// 2. **Commit** — push routing into eBPF (itself two-phase: the routing
    ///    meta is written last, so a push failure never activates a partial
    ///    ruleset), then swap config/router/DNS/group state in one critical
    ///    section. A push failure aborts before any userspace field changes.
    ///
    /// This removes the old stepwise replacement window where a mid-pipeline
    /// failure left a new config with an old DNS forwarder and a half-updated
    /// datapath. New connections are rejected briefly while the swap happens.
    pub(super) async fn apply_runtime_config(&self, new_config: Config, drain: &DrainTracker) {
        drain.start_rejecting();
        // Brief pause for in-flight connection setup
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // ── Phase 1: build everything (no live-state mutation) ──
        let new_router = match Router::new(
            &new_config.routing.rules,
            &new_config.routing.default_outbound,
        ) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to build new router: {}", e);
                drain.stop_rejecting();
                return;
            }
        };
        let new_dns_forwarder = match self.build_dns_forwarder(&new_config).await {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to build DNS forwarder: {}", e);
                drain.stop_rejecting();
                return;
            }
        };
        let new_outbound_id_map = build_outbound_id_map(&new_config);
        let bootstrap = new_config.global.bootstrap_resolver.clone();
        let direct_target = super::direct_check_addr(&bootstrap);

        // ── Phase 2a: push routing into eBPF; abort without touching userspace ──
        let route_count = new_router.route_count();
        {
            let mut ebpf = self.ebpf.write().await;
            if let Err(e) = Self::push_routing_to_ebpf(&new_config, &new_router, &mut ebpf) {
                error!(
                    "Failed to push routing to eBPF (reload aborted, current generation intact): {}",
                    e
                );
                drain.stop_rejecting();
                return;
            }
        }

        // ── Phase 2b: commit userspace state in one critical section ──
        *self.router.write().await = new_router;
        *self.config.write().await = new_config;
        // Refresh the bootstrap resolver for proxy-server hostname lookups.
        honk_outbound::bootstrap::set_global(honk_outbound::bootstrap::BootstrapResolver::parse(
            &bootstrap,
        ));
        // direct's probe target follows the bootstrap resolver.
        self.alive_set.set_direct_check_addr(direct_target.clone());
        honk_outbound::urltest::set_urltest_direct_target(
            direct_target
                .parse()
                .expect("direct check addr is a SocketAddr"),
        );
        *self.outbound_id_map.write() = new_outbound_id_map;
        self.dns_controller.set_forwarder(new_dns_forwarder).await;
        // Rebuild the GroupManager (reads the just-swapped config; migrates
        // runtime selector choices) and refresh health-check registrations.
        self.reload_group_manager().await;
        // Rebuild learned domain→IP routes with the new rule-index bitmaps.
        self.dns_controller.rebuild_domain_routes().await;
        info!("Configuration applied — {} routes active", route_count);

        drain.stop_rejecting();
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
    ) -> anyhow::Result<std::sync::Arc<crate::dns::forwarder::DnsForwarder>> {
        let dns_router = Arc::new(crate::dns::routing::DnsRouter::new_from_dns_config(
            &config.dns,
        )?);
        let dns_upstream_pool = Arc::new(
            crate::dns::upstream_pool::UpstreamPool::new_with_proxy(
                &config.dns.upstream,
                dns_router.clone(),
                Some(self.proxy_registry.clone()),
                config.nodes.clone(),
                config.groups.clone(),
            )?
            .with_timeouts(
                std::time::Duration::from_millis(config.global.dns_resolve_timeout_ms),
                std::time::Duration::from_millis(config.global.connect_timeout_ms),
            )
            // Same SharedGroupManager + traffic Router cells as the data path
            // (dae: Route DNS server IP; explicit `-> tag` still forces a group).
            .with_group_manager(self.group_manager.clone())
            .with_traffic_router(self.router.clone()),
        );
        Ok(Arc::new(
            crate::dns::forwarder::DnsForwarder::new(
                dns_upstream_pool as Arc<dyn crate::dns::forwarder::DnsUpstreamPool>,
                self.dns_controller.cache().await,
                dns_router,
            )
            .with_strategy(config.dns.strategy.clone())
            .with_cache_enabled(config.dns.cache.enabled)
            .with_cache_ttl(config.dns.cache.ttl.min(u64::from(u32::MAX)) as u32)
            .with_policy_from_config(&config.dns)?,
        ))
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

#[cfg(test)]
mod atomic_reload_tests {
    use super::*;
    use crate::dns;
    use crate::ebpf::mock::MockEbpfBackend;

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
        let before = cp.config_handle().read().await.global.log_level.clone();

        // An upstream with an empty address fails DnsEndpoint::parse during
        // build_dns_forwarder — the reload must abort before commit.
        let mut bad = Config::default();
        bad.global.log_level = "trace".into();
        bad.dns.upstream = vec![honk_config::dns::DnsUpstream {
            name: "broken".into(),
            address: String::new(),
            protocol: honk_config::types::DnsProtocol::Udp,
            tls_server_name: None,
            outbound: None,
        }];

        let drain = DrainTracker::new();
        cp.apply_runtime_config(bad, &drain).await;

        let after = cp.config_handle().read().await.global.log_level.clone();
        assert_eq!(before, after, "failed build must not swap the live config");
    }

    /// A valid reload commits: config is swapped and eBPF routing is pushed.
    #[tokio::test]
    async fn valid_reload_commits() {
        let cp = test_cp();
        let mut good = Config::default();
        good.global.log_level = "trace".into();
        let drain = DrainTracker::new();
        cp.apply_runtime_config(good, &drain).await;
        assert_eq!(
            cp.config_handle().read().await.global.log_level,
            "trace",
            "valid reload should swap the live config"
        );
    }
}
