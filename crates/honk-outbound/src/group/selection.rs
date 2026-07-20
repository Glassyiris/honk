use super::*;

impl GroupManager {
    pub fn new(groups: &[Group], nodes: &[Node]) -> Self {
        Self::with_alive_set(groups, nodes, None)
    }

    pub fn with_alive_set(
        groups: &[Group],
        nodes: &[Node],
        alive_set: Option<Arc<AliveDialerSet>>,
    ) -> Self {
        let mut group_map: HashMap<String, Group> =
            groups.iter().map(|g| (g.name.clone(), g.clone())).collect();
        break_group_cycles(&mut group_map);
        Self {
            groups: group_map,
            nodes: nodes.iter().map(|n| (n.id, n.clone())).collect(),
            alive_set,
            urltest_cache: RwLock::new(HashMap::new()),
            lb_counters: groups
                .iter()
                .map(|g| (g.name.clone(), AtomicUsize::new(0)))
                .collect(),
            fallback_cache: RwLock::new(HashMap::new()),
            last_used: RwLock::new(HashMap::new()),
            selector_choice: RwLock::new(HashMap::new()),
            persist_callback: RwLock::new(None),
            interrupt_callback: RwLock::new(None),
        }
    }

    /// Select a single node from a group (TCP, IPv4).
    pub fn select_node(&self, name: &str) -> Option<&Node> {
        self.select_node_for_domain(name, ProbeDomain::Tcp, IpVersion::V4)
    }

    /// Select a single alive node for the given domain and IP version.
    pub fn select_node_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Option<&Node> {
        let group = self.groups.get(group_name)?;
        self.mark_used(group_name);
        let mut visited = Vec::new();
        self.pick_in_group(group, domain, ipver, &mut visited, 0)
    }

    /// Select a single alive node, excluding one by name (for failover retry).
    pub fn select_node_excluded(
        &self,
        name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
        excluded_node_name: &str,
    ) -> Option<&Node> {
        let group = self.groups.get(name)?;
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(group, domain, ipver, &mut visited, 0);
        let candidates: Vec<Candidate> = self
            .filter_alive_candidates(candidates, domain, ipver)
            .into_iter()
            .filter(|c| c.node.name != excluded_node_name)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        Some(
            self.pick_best_by_latency(
                &candidates,
                group,
                SelectionNetwork::from_probe_domain(domain),
                ipver,
            )
            .node,
        )
    }

    /// Select candidate node(s) for dialing.
    ///
    /// Selection is **authoritative** (sing-box semantics): a group's policy
    /// pick is the node traffic actually goes through — the list has exactly
    /// one entry for every policy, so the manual Selector choice and the
    /// URLTest winner are honored instead of being lost to a parallel race.
    /// The only multi-entry case is a URLTest group with no measurement
    /// data at all (cold start), where racing all alive candidates is the
    /// fastest way to find a working node before the first selection forms.
    ///
    /// With nested groups, candidates are the flattened leaves (each
    /// sub-group contributes its own policy's current pick), so dialing is
    /// always against concrete leaf nodes.
    pub fn select_nodes_in_order_for_domain(
        &self,
        group_name: &str,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<&Node> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        self.mark_used(group_name);
        let mut visited = Vec::new();
        let candidates = self.flatten_candidates(group, domain, ipver, &mut visited, 0);
        let candidates = self.filter_alive_candidates(candidates, domain, ipver);
        if candidates.is_empty() {
            return vec![];
        }
        let network = SelectionNetwork::from_probe_domain(domain);
        match group.policy {
            GroupPolicy::Selector => vec![self.pick_selector(&candidates, group)],
            GroupPolicy::URLTest => {
                // Cold start: no latency data on any candidate — race all
                // alive candidates to land the first connection quickly.
                let any_data = candidates
                    .iter()
                    .any(|c| self.node_latency(c.node, network, ipver) != Duration::MAX);
                if any_data {
                    vec![self.pick_urltest(&candidates, group, network, ipver)]
                } else {
                    self.order_by_latency(candidates, network, ipver)
                        .into_iter()
                        .map(|c| c.node)
                        .collect()
                }
            }
            GroupPolicy::LoadBalance => vec![self.pick_load_balance(&candidates, group)],
            GroupPolicy::Fallback => vec![self.pick_fallback(&candidates, group)],
        }
    }

    /// Get the group's policy.
    pub fn get_group_policy(&self, name: &str) -> Option<GroupPolicy> {
        self.groups.get(name).map(|g| g.policy)
    }

    /// Get the `final_outbound` fallback name, if configured.
    pub fn get_final_outbound(&self, group_name: &str) -> Option<String> {
        self.groups
            .get(group_name)
            .and_then(|g| g.final_outbound.clone())
    }

    /// Whether this group has been idle longer than its `idle_timeout`.
    pub fn is_group_idle(&self, group_name: &str) -> bool {
        let group = match self.groups.get(group_name) {
            Some(g) => g,
            None => return false,
        };
        let idle_timeout = match group.idle_timeout {
            Some(t) if t > 0 => Duration::from_secs(t),
            _ => return false,
        };
        self.last_used
            .read()
            .unwrap()
            .get(group_name)
            .map(|t| t.elapsed() >= idle_timeout)
            .unwrap_or(true)
    }

    /// Member tags of a group: direct member node names followed by nested
    /// sub-group tags (deduplicated, declaration order within each kind).
    ///
    /// This is the member list a dashboard shows (the clash `all` field):
    /// sing-box nested groups drill down layer by layer, so sub-groups
    /// appear under their own tag, not expanded to leaves. Use
    /// [`GroupManager::leaf_node_names_in_group`] where the real nodes
    /// underneath matter (health checks, eBPF connectivity aggregation).
    pub fn node_names_in_group(&self, group_name: &str) -> Vec<String> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        self.member_tags(group)
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// All leaf node names reachable from a group, expanding nested
    /// sub-groups recursively (deduplicated, cycle-guarded). Unlike
    /// [`GroupManager::node_names_in_group`] — which lists display tags —
    /// this resolves to the real nodes whose health state drives probing
    /// and eBPF connectivity pushes.
    pub fn leaf_node_names_in_group(&self, group_name: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut visited: Vec<&str> = Vec::new();
        self.collect_leaf_names(group_name, 0, &mut visited, &mut out);
        out
    }

    fn collect_leaf_names<'a>(
        &'a self,
        group_name: &'a str,
        depth: usize,
        visited: &mut Vec<&'a str>,
        out: &mut Vec<String>,
    ) {
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group_name) {
            return;
        }
        let Some(group) = self.groups.get(group_name) else {
            return;
        };
        visited.push(group_name);
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !out.contains(&n.name)
            {
                out.push(n.name.clone());
            }
        }
        for tag in &group.groups {
            self.collect_leaf_names(tag, depth + 1, visited, out);
        }
        visited.pop();
    }

    /// The selection chain from a group down to the leaf its current
    /// selections resolve to: `[group, ..sub-group tags.., leaf node]`.
    ///
    /// Each step uses the group's current selection for its policy
    /// (Selector: runtime choice → `default` → first member tag; URLTest:
    /// cached TCP selection; Fallback: pinned tag). The chain stops at the
    /// first group without a formed selection (a URLTest group before any
    /// measurement, or LoadBalance which has no stable pick to report).
    /// Intended for debugging/introspection — the clash `now` field keeps
    /// showing the immediate member tag.
    pub fn selection_chain(&self, group_name: &str) -> Vec<String> {
        let mut chain = vec![group_name.to_string()];
        let mut current = group_name.to_string();
        for _ in 0..MAX_GROUP_DEPTH {
            let Some(group) = self.groups.get(&current) else {
                break;
            };
            let next: Option<String> = match group.policy {
                GroupPolicy::Selector => self
                    .selector_choice
                    .read()
                    .unwrap()
                    .get(&group.name)
                    .cloned()
                    .or_else(|| group.default.clone())
                    .or_else(|| self.member_tags(group).first().map(|s| s.to_string())),
                GroupPolicy::URLTest => self.get_urltest_selection(&group.name),
                GroupPolicy::Fallback => self.get_fallback_selection(&group.name),
                // Round-robin has no stable selection to report.
                GroupPolicy::LoadBalance => None,
            };
            let Some(tag) = next else { break };
            if tag == current || chain.contains(&tag) {
                break; // cycle guard
            }
            chain.push(tag.clone());
            current = tag;
        }
        chain
    }

    /// Flattened members for an explicit delay test: one `(tag, leaf)`
    /// pair per member — direct members under their node name, sub-groups
    /// under their tag with the leaf their policy currently selects (or,
    /// when the sub-group has no alive leaf, its first leaf in declaration
    /// order, so an explicit test can discover recovery). Members sharing
    /// a leaf appear once (first tag wins) to avoid duplicate measurement.
    pub fn delay_test_members(&self, group_name: &str) -> Vec<(String, Node)> {
        let Some(group) = self.groups.get(group_name) else {
            return vec![];
        };
        let mut out: Vec<(String, Node)> = Vec::new();
        let mut seen: Vec<uuid::Uuid> = Vec::new();
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !seen.contains(&n.id)
            {
                seen.push(n.id);
                out.push((n.name.clone(), n.clone()));
            }
        }
        for tag in &group.groups {
            let Some(sub) = self.groups.get(tag.as_str()) else {
                continue;
            };
            let mut visited = Vec::new();
            let leaf = self
                .pick_in_group(sub, ProbeDomain::Tcp, IpVersion::V4, &mut visited, 0)
                .or_else(|| {
                    let mut visited = Vec::new();
                    self.first_leaf(sub, &mut visited, 0)
                });
            if let Some(leaf) = leaf
                && !seen.contains(&leaf.id)
            {
                seen.push(leaf.id);
                out.push((tag.clone(), leaf.clone()));
            }
        }
        out
    }

    /// First leaf node reachable from a group in declaration order,
    /// ignoring alive state. Cycle/depth-guarded like the selection paths.
    fn first_leaf<'a>(
        &'a self,
        group: &'a Group,
        visited: &mut Vec<&'a str>,
        depth: usize,
    ) -> Option<&'a Node> {
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return None;
        }
        visited.push(group.name.as_str());
        let mut result = group.nodes.iter().find_map(|id| self.nodes.get(id));
        if result.is_none() {
            for tag in &group.groups {
                if let Some(sub) = self.groups.get(tag.as_str()) {
                    result = self.first_leaf(sub, visited, depth + 1);
                    if result.is_some() {
                        break;
                    }
                }
            }
        }
        visited.pop();
        result
    }

    /// Borrowed member tags of a group (direct node names, then sub-group
    /// tags; deduplicated). Missing sub-group tags are skipped.
    fn member_tags<'a>(&'a self, group: &'a Group) -> Vec<&'a str> {
        let mut out: Vec<&'a str> = Vec::new();
        for id in &group.nodes {
            if let Some(n) = self.nodes.get(id)
                && !out.contains(&n.name.as_str())
            {
                out.push(n.name.as_str());
            }
        }
        for tag in &group.groups {
            if self.groups.contains_key(tag.as_str()) && !out.contains(&tag.as_str()) {
                out.push(tag.as_str());
            }
        }
        out
    }

    /// Set the selected node for a Selector group at runtime.
    ///
    /// On an actual change: the persist callback (cache.db persistence) and
    /// — when the group has `interrupt_connections` — the interrupt
    /// callback are invoked.
    pub fn set_selector_choice(&self, group_name: &str, node_name: &str) {
        {
            let mut choices = self.selector_choice.write().unwrap();
            if choices.get(group_name).map(String::as_str) == Some(node_name) {
                return; // unchanged
            }
            choices.insert(group_name.to_string(), node_name.to_string());
        }
        if let Some(ref cb) = *self.persist_callback.read().unwrap() {
            cb(group_name, node_name);
        }
        self.maybe_interrupt(group_name);
    }

    /// Install the callback invoked when a Selector group's choice changes
    /// (group_name, node_name). Re-callable; pass `None` to remove.
    pub fn set_persist_callback(&self, cb: Option<PersistCallback>) {
        *self.persist_callback.write().unwrap() = cb;
    }

    /// Install the callback invoked when a group's selected node changes
    /// and the group has `interrupt_connections = true`. Re-callable;
    /// pass `None` to remove.
    pub fn set_interrupt_callback(&self, cb: Option<InterruptCallback>) {
        *self.interrupt_callback.write().unwrap() = cb;
    }

    /// Record group activity: updates the idle-timeout timestamp and wakes
    /// URLTest group health checks in the alive set.
    fn mark_used(&self, group_name: &str) {
        self.last_used
            .write()
            .unwrap()
            .insert(group_name.to_string(), Instant::now());
        if let Some(ref alive) = self.alive_set {
            alive.mark_group_active(group_name);
        }
    }

    /// Fire the interrupt callback when the group opted into connection
    /// interruption on selection changes (`interrupt_connections`).
    fn maybe_interrupt(&self, group_name: &str) {
        let interrupt = self
            .groups
            .get(group_name)
            .map(|g| g.interrupt_connections)
            .unwrap_or(false);
        if !interrupt {
            return;
        }
        if let Some(ref cb) = *self.interrupt_callback.read().unwrap() {
            cb(group_name);
        }
    }

    /// Get the current selected node name for a Selector group.
    pub fn get_selector_choice(&self, group_name: &str) -> Option<String> {
        self.selector_choice
            .read()
            .unwrap()
            .get(group_name)
            .cloned()
    }

    /// Wrap this manager into a [`SharedGroupManager`] cell (see the type's
    /// docs for the hot-swap semantics).
    pub fn into_shared(self) -> SharedGroupManager {
        Arc::new(parking_lot::RwLock::new(Arc::new(self)))
    }

    /// Copy runtime selector choices from a previous instance (used on
    /// config reload). Choices whose group no longer exists, or whose
    /// selected member tag (node name or sub-group tag) is no longer a
    /// member of that group, are dropped. Persist/interrupt callbacks are
    /// not fired — they are wired after migration by the caller.
    pub fn migrate_selector_choices_from(&self, old: &GroupManager) {
        let old_choices = old.selector_choice.read().unwrap().clone();
        if old_choices.is_empty() {
            return;
        }
        let mut migrated = 0usize;
        let mut choices = self.selector_choice.write().unwrap();
        for (group_name, member_tag) in old_choices {
            let still_valid = self
                .groups
                .get(&group_name)
                .map(|g| self.member_tags(g).contains(&member_tag.as_str()))
                .unwrap_or(false);
            if still_valid {
                choices.insert(group_name, member_tag);
                migrated += 1;
            }
        }
        if migrated > 0 {
            tracing::info!(
                "migrated {} selector choice(s) across config reload",
                migrated
            );
        }
    }

    /// Get the current URLTest selected node name for TCP.
    ///
    /// This is the pre-split single-network view kept for API
    /// compatibility; new callers should use
    /// [`GroupManager::get_urltest_selection_for_network`].
    pub fn get_urltest_selection(&self, group_name: &str) -> Option<String> {
        self.get_urltest_selection_for_network(group_name, SelectionNetwork::Tcp)
    }

    /// Get the current URLTest selected member tag for the given network
    /// (a direct member's node name, or a sub-group's tag — this is what
    /// the clash `now` field displays).
    pub fn get_urltest_selection_for_network(
        &self,
        group_name: &str,
        network: SelectionNetwork,
    ) -> Option<String> {
        let cache = self.urltest_cache.read().unwrap();
        cache
            .get(group_name)
            .and_then(|sel| sel.get(network))
            .map(|entry| entry.tag.clone())
    }

    /// Get the current Fallback pinned member tag (for API/display).
    pub fn get_fallback_selection(&self, group_name: &str) -> Option<String> {
        self.fallback_cache.read().unwrap().get(group_name).cloned()
    }

    /// Resolve a group to the single leaf node its policy selects.
    /// `visited`/`depth` thread the cycle/depth guards through nesting.
    fn pick_in_group<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
    ) -> Option<&'a Node> {
        let candidates = self.flatten_candidates(group, domain, ipver, visited, depth);
        let candidates = self.filter_alive_candidates(candidates, domain, ipver);
        if candidates.is_empty() {
            return None;
        }
        let network = SelectionNetwork::from_probe_domain(domain);
        Some(match group.policy {
            GroupPolicy::Selector => self.pick_selector(&candidates, group),
            GroupPolicy::URLTest => self.pick_urltest(&candidates, group, network, ipver),
            GroupPolicy::LoadBalance => self.pick_load_balance(&candidates, group),
            GroupPolicy::Fallback => self.pick_fallback(&candidates, group),
        })
    }

    /// Flatten a group's members into dial candidates: every direct member
    /// node plus, for each nested sub-group, the single leaf the
    /// sub-group's own policy currently selects (recursively, depth-capped
    /// and cycle-guarded). Alive filtering happens afterwards in
    /// [`GroupManager::filter_alive_candidates`].
    fn flatten_candidates<'a>(
        &'a self,
        group: &'a Group,
        domain: ProbeDomain,
        ipver: IpVersion,
        visited: &mut Vec<&'a str>,
        depth: usize,
    ) -> Vec<Candidate<'a>> {
        if depth >= MAX_GROUP_DEPTH || visited.contains(&group.name.as_str()) {
            return Vec::new();
        }
        visited.push(group.name.as_str());
        let mut out: Vec<Candidate<'a>> = group
            .nodes
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|node| Candidate {
                tag: node.name.as_str(),
                node,
                via: None,
            })
            .collect();
        for sub_tag in &group.groups {
            let Some(sub) = self.groups.get(sub_tag.as_str()) else {
                continue;
            };
            // Sub-group participation counts as activity so the parent's
            // traffic keeps the child's health checks awake (URLTest idle
            // sleep is driven by `mark_used`).
            self.mark_used(sub_tag);
            if let Some(leaf) = self.pick_in_group(sub, domain, ipver, visited, depth + 1) {
                out.push(Candidate {
                    tag: sub_tag.as_str(),
                    node: leaf,
                    via: Some(sub_tag.as_str()),
                });
            }
        }
        visited.pop();
        out
    }

    /// Keep only candidates whose leaf node is alive for the probe domain.
    /// With no alive set (tests) everything passes.
    ///
    /// DataUDP aliveness is decided per node: a node is selectable when
    /// DataUDP *or* DnsUDP is alive. A node whose UDP domains are BOTH
    /// explicitly dead is excluded even when its TCP is alive — a TCP-only
    /// node (e.g. an AnyTLS server without UoT) must not keep attracting
    /// UDP flows it cannot carry. The previous set-level
    /// DataUDP → DnsUDP → TCP fallback made such nodes unexcludable.
    /// Nodes with no UDP state at all ([`AliveDialerSet::has_udp_state`]
    /// — never UDP-probed, no UDP traffic reports) instead inherit TCP
    /// liveness, which is what the fallback exists for: setups without
    /// UDP probing keep their previous behaviour.
    fn filter_alive_candidates<'a>(
        &self,
        candidates: Vec<Candidate<'a>>,
        domain: ProbeDomain,
        ipver: IpVersion,
    ) -> Vec<Candidate<'a>> {
        let Some(ref alive) = self.alive_set else {
            return candidates;
        };
        if domain == ProbeDomain::DataUdp {
            return candidates
                .into_iter()
                .filter(|c| {
                    let name = &c.node.name;
                    if alive.has_udp_state(name) {
                        alive.is_alive_for(name, ProbeDomain::DataUdp, ipver)
                            || alive.is_alive_for(name, ProbeDomain::DnsUdp, ipver)
                    } else {
                        alive.is_alive_for(name, ProbeDomain::Tcp, ipver)
                    }
                })
                .collect();
        }
        candidates
            .into_iter()
            .filter(|c| alive.is_alive_for(&c.node.name, domain, ipver))
            .collect()
    }

    /// Selector policy: runtime choice, then `group.default`, then first
    /// alive candidate. Choices match member TAGS — a choice may name a
    /// direct member node or a nested sub-group (sing-box nested-selector
    /// behavior: picking a sub-group defers to that group's own pick,
    /// which flattening already resolved to its leaf).
    fn pick_selector<'a>(&self, candidates: &[Candidate<'a>], group: &Group) -> &'a Node {
        if let Some(choice) = self.selector_choice.read().unwrap().get(&group.name)
            && let Some(c) = candidates.iter().find(|c| c.tag == choice.as_str())
        {
            return c.node;
        }
        if let Some(ref default_name) = group.default
            && let Some(c) = candidates.iter().find(|c| c.tag == default_name.as_str())
        {
            return c.node;
        }
        candidates[0].node
    }

    /// URLTest policy: lowest-latency alive candidate with tolerance-based
    /// stable selection. TCP and UDP keep independent selections (sing-box
    /// `selectedOutboundTCP` / `selectedOutboundUDP`); TCP ranks by TCP
    /// probes, UDP by DataUDP → DnsUDP → TCP probe latency. A sub-group
    /// candidate ranks by its representative leaf's latency, and selection
    /// identity is the member tag (so a sub-group's internal leaf change
    /// does not by itself switch the parent's selection).
    fn pick_urltest<'a>(
        &self,
        candidates: &[Candidate<'a>],
        group: &Group,
        network: SelectionNetwork,
        ipver: IpVersion,
    ) -> &'a Node {
        let tolerance = Duration::from_millis(group.tolerance.max(1));

        // UDP selection with no UDP-specific measurement data mirrors the
        // TCP selection (sing-box `Now()` fallback semantics): with nothing
        // to rank UDP paths by, keep UDP flows on the TCP-chosen member.
        if network == SelectionNetwork::Udp
            && !candidates
                .iter()
                .any(|c| self.udp_specific_latency(c.node, ipver).is_some())
        {
            let tcp_entry = {
                let cache = self.urltest_cache.read().unwrap();
                cache.get(&group.name).and_then(|sel| sel.tcp.clone())
            };
            if let Some(entry) = tcp_entry
                && let Some(&c) = candidates.iter().find(|c| c.tag == entry.tag)
            {
                if self.cache_urltest_selection(group, network, &c, entry.latency) {
                    self.maybe_interrupt(&group.name);
                }
                return c.node;
            }
            // No usable TCP selection yet — fall through to the normal
            // evaluation (which ranks by the latency fallback chain).
        }

        let best = self.pick_best_by_latency(candidates, group, network, ipver);

        {
            let cache = self.urltest_cache.read().unwrap();
            if let Some(current) = cache.get(&group.name).and_then(|sel| sel.get(network))
                && let Some(pos) = candidates.iter().position(|c| c.tag == current.tag)
            {
                let best_latency = self.node_latency(best.node, network, ipver);
                // Only switch if best is significantly (≥ tolerance) faster.
                if best_latency.saturating_add(tolerance) >= current.latency {
                    return candidates[pos].node;
                }
            }
        }

        let latency = self.node_latency(best.node, network, ipver);
        if self.cache_urltest_selection(group, network, &best, latency) {
            self.maybe_interrupt(&group.name);
        }

        best.node
    }

    /// Record `candidate` as the group's URLTest selection for `network`.
    /// Returns true when the selection actually changed (the first-ever
    /// selection is not a change — nothing to interrupt). Change is
    /// detected by member tag: a sub-group swapping its internal leaf
    /// keeps the parent's selection (and its connections) stable.
    fn cache_urltest_selection(
        &self,
        group: &Group,
        network: SelectionNetwork,
        candidate: &Candidate,
        latency: Duration,
    ) -> bool {
        let mut cache = self.urltest_cache.write().unwrap();
        let selections = cache.entry(group.name.clone()).or_default();
        let changed = selections
            .get(network)
            .map(|entry| entry.tag != candidate.tag)
            .unwrap_or(false);
        selections.set(
            network,
            UrlTestEntry {
                node_id: candidate.node.id,
                tag: candidate.tag.to_string(),
                latency,
                updated_at: Instant::now(),
            },
        );
        changed
    }

    /// LoadBalance policy: round-robin over the alive candidates in member
    /// order. Dead members never enter `candidates`, so the rotation skips
    /// them automatically. Each group's counter is independent
    /// (`lb_counters`), and the pick never fires the interrupt callback:
    /// rotation is per-connection by design, so there is no stable
    /// group-level selection whose change would justify closing every
    /// tracked connection of the group (that would defeat load balancing).
    /// Connections to a node that actually dies are reaped by the alive
    /// set's traffic-failure reporting instead.
    fn pick_load_balance<'a>(&self, candidates: &[Candidate<'a>], group: &Group) -> &'a Node {
        let Some(counter) = self.lb_counters.get(&group.name) else {
            return candidates[0].node;
        };
        let idx = counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates[idx].node
    }

    /// Fallback policy: first alive candidate in member order, pinned.
    ///
    /// The pinned member tag is kept while it remains in the alive
    /// candidate set; only its death triggers re-evaluation (next alive in
    /// member order). A recovered higher-preference member does NOT
    /// immediately win the pin back — deliberate hysteresis: failback
    /// flapping (a marginally-preferred member oscillating alive/dead
    /// would yank every connection twice) costs more than staying on a
    /// working lower-preference member until it actually fails.
    fn pick_fallback<'a>(&self, candidates: &[Candidate<'a>], group: &Group) -> &'a Node {
        {
            let cache = self.fallback_cache.read().unwrap();
            if let Some(pinned) = cache.get(&group.name)
                && let Some(&c) = candidates.iter().find(|c| c.tag == pinned.as_str())
            {
                return c.node;
            }
        }
        let first = candidates[0];
        if self.cache_fallback_selection(group, &first) {
            self.maybe_interrupt(&group.name);
        }
        first.node
    }

    /// Pin `candidate` as the group's Fallback selection. Returns true
    /// when the pin actually changed (the first-ever pin is not a change).
    /// The pin is by member tag — a sub-group stays pinned while it has
    /// any alive leaf to offer.
    fn cache_fallback_selection(&self, group: &Group, candidate: &Candidate) -> bool {
        let mut cache = self.fallback_cache.write().unwrap();
        let changed = cache
            .get(&group.name)
            .map(|old| old != candidate.tag)
            .unwrap_or(false);
        cache.insert(group.name.clone(), candidate.tag.to_string());
        changed
    }

    /// Pick the candidate with the lowest probe latency from alive_set.
    fn pick_best_by_latency<'a>(
        &self,
        candidates: &[Candidate<'a>],
        _group: &Group,
        network: SelectionNetwork,
        ipver: IpVersion,
    ) -> Candidate<'a> {
        candidates
            .iter()
            .min_by_key(|c| self.node_latency(c.node, network, ipver))
            .copied()
            .unwrap_or(candidates[0])
    }

    /// Effective selection latency for a node on the given network.
    ///
    /// Ranking uses the **moving average** of recent probe samples (dae's
    /// `min_moving_avg` / `min_avg10` semantics): TCP ranks by the TCP-probe
    /// average. UDP ranks by the DataUDP then DNS-UDP averages only — a node
    /// with no UDP measurement ranks `Duration::MAX` (never its TCP
    /// latency), so UDP-proven nodes always beat UDP-unproven ones; the
    /// all-no-UDP-data case is handled separately by the TCP mirror in
    /// [`GroupManager::pick_urltest`].
    fn node_latency(&self, node: &Node, network: SelectionNetwork, ipver: IpVersion) -> Duration {
        let latency = match network {
            SelectionNetwork::Tcp => self
                .alive_set
                .as_ref()
                .and_then(|a| a.get_avg_latency(&node.name, ProbeDomain::Tcp, ipver)),
            SelectionNetwork::Udp => self
                .alive_set
                .as_ref()
                .and_then(|a| a.get_avg_latency(&node.name, ProbeDomain::DataUdp, ipver))
                .or_else(|| {
                    self.alive_set
                        .as_ref()
                        .and_then(|a| a.get_avg_latency(&node.name, ProbeDomain::DnsUdp, ipver))
                }),
        };
        latency.unwrap_or(Duration::MAX)
    }

    /// UDP-specific probe latency only: DataUDP first, then DNS-UDP (no
    /// TCP fallback). Used to decide whether the UDP selection has any
    /// measurement of its own to rank by.
    fn udp_specific_latency(&self, node: &Node, ipver: IpVersion) -> Option<Duration> {
        let alive = self.alive_set.as_ref()?;
        alive
            .get_last_latency(&node.name, ProbeDomain::DataUdp, ipver)
            .or_else(|| alive.get_last_latency(&node.name, ProbeDomain::DnsUdp, ipver))
    }

    /// Order candidates by (network-aware) latency, lowest first.
    fn order_by_latency<'a>(
        &self,
        mut candidates: Vec<Candidate<'a>>,
        network: SelectionNetwork,
        ipver: IpVersion,
    ) -> Vec<Candidate<'a>> {
        candidates.sort_by_key(|c| self.node_latency(c.node, network, ipver));
        candidates
    }
}

/// Break cycles in the sub-group graph before the manager starts
/// resolving selections.
///
/// DFS over `Group.groups` edges; every back edge (an edge pointing at a
/// group currently on the DFS stack) closes a cycle and is removed from
/// the parent's `groups` list with a warning. Unknown tags are left in
/// place — resolution skips them. The recursion paths additionally carry
/// their own depth/visited guards, so a broken graph can warn but never
/// hang or panic.
fn break_group_cycles(groups: &mut HashMap<String, Group>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Visiting,
        Done,
    }

    fn visit(
        name: &str,
        groups: &HashMap<String, Group>,
        states: &mut HashMap<String, State>,
        cuts: &mut Vec<(String, String)>,
    ) {
        states.insert(name.to_string(), State::Visiting);
        if let Some(group) = groups.get(name) {
            for child in &group.groups {
                if !groups.contains_key(child.as_str()) {
                    continue;
                }
                match states.get(child.as_str()) {
                    None => visit(child, groups, states, cuts),
                    Some(State::Visiting) => cuts.push((name.to_string(), child.clone())),
                    Some(State::Done) => {}
                }
            }
        }
        states.insert(name.to_string(), State::Done);
    }

    let mut states: HashMap<String, State> = HashMap::new();
    let mut cuts: Vec<(String, String)> = Vec::new();
    // Sorted start order keeps edge-cutting deterministic across runs.
    let mut names: Vec<String> = groups.keys().cloned().collect();
    names.sort();
    for name in names {
        if !states.contains_key(&name) {
            visit(&name, groups, &mut states, &mut cuts);
        }
    }
    for (parent, child) in cuts {
        if let Some(group) = groups.get_mut(&parent) {
            let before = group.groups.len();
            group.groups.retain(|t| t != &child);
            if group.groups.len() != before {
                tracing::warn!(
                    "nested group cycle detected: cut edge '{}' -> '{}' to break the loop",
                    parent,
                    child
                );
            }
        }
    }
}
