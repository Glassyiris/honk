//! Compiles user-space routing rules into eBPF MatchSet arrays and populates
//! the BPF maps for hardware-accelerated packet classification.
//!
//! Mirrors the Go `routing_matcher_builder.go` (`control/routing_matcher_builder.go`)
//! in dae-core: each rule is split into type-specific `match_set` entries, and
//! IP/MAC prefixes are stored in LPM trie maps while domain rules are evaluated
//! in userspace (domain is not available during eBPF TCP SYN classification).

use crate::ebpf::{EbpfBackend, LpmKeepSet, maps};
use crate::routing::CompiledRoute;
use honk_config::types::DialMode;
use honk_ebpf_common::*;
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

/// Global cache of domain routing bitmaps from the last eBPF push.
/// Keyed by rule name. DNS snooping reads this to push resolved IPs.
pub static DOMAIN_BITMAPS: LazyLock<parking_lot::RwLock<HashMap<String, Vec<DomainRouting>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(HashMap::new()));

/// Generation counter incremented on each eBPF routing push.
/// Domain route caches use this to detect stale entries after rule reload.
pub static DOMAIN_BITMAPS_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// A single condition present in a compiled route.
#[derive(Debug)]
enum Condition<'a> {
    /// Domain/geosite conditions are represented in eBPF as a `DomainSet`
    /// placeholder. The actual domain→IP mapping is populated by DNS snooping:
    /// when DNS resolves a matching domain, the resolved IPs are inserted into
    /// `DOMAIN_ROUTING_MAP` with the bitmap pointing to this match_set index.
    #[allow(dead_code)]
    Domain {
        suffixes: &'a [String],
        keywords: &'a [String],
        geosite_domains: &'a [crate::routing::GeositeDomain],
    },
    SourceIp {
        nets: &'a [ipnet::IpNet],
    },
    Ip {
        nets: &'a [ipnet::IpNet],
    },
    Mac {
        macs: &'a [String],
    },
    SourcePort {
        ranges: &'a [crate::routing::PortRange],
    },
    Port {
        ranges: &'a [crate::routing::PortRange],
    },
    Protocol {
        protocols: &'a [String],
    },
    IpVersion {
        versions: &'a [u8],
    },
    Dscp {
        values: &'a [u8],
    },
    ProcessName {
        names: &'a [String],
    },
}

/// Result of pushing routing rules to eBPF.
#[derive(Debug, Clone)]
pub struct RoutingPushResult {
    /// Number of MatchSet entries produced.
    pub match_set_count: usize,
    /// Domain routing bitmaps keyed by outbound name.
    /// DNS snooping uses these to push resolved IPs into DOMAIN_ROUTING_MAP.
    pub domain_bitmaps: HashMap<String, Vec<DomainRouting>>,
}

/// LPM update plan for one ruleset generation.
///
/// Entries are merged by their raw 20-byte key so that several rules
/// referencing the same prefix OR their rule-index bits together before the
/// entries reach the backend.  The real backend cannot read-modify-write an
/// LPM trie (a lookup returns the longest-prefix *match*, not the exact
/// entry) and therefore overwrites values; without this merge the last rule
/// pushed for a shared prefix would clobber the earlier ones.
#[derive(Debug, Default)]
struct LpmPushPlan {
    dest: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
    source: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
    mac: HashMap<[u8; 20], (LpmKey, DomainRouting)>,
}

impl LpmPushPlan {
    fn insert(
        map: &mut HashMap<[u8; 20], (LpmKey, DomainRouting)>,
        key: LpmKey,
        bitmap: DomainRouting,
    ) {
        map.entry(maps::lpm_key_bytes(&key))
            .and_modify(|(_, cur)| {
                for (w, b) in cur.bitmap.iter_mut().zip(bitmap.bitmap.iter()) {
                    *w |= b;
                }
            })
            .or_insert((key, bitmap));
    }

    fn add_dest(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.dest, key, bitmap);
    }

    fn add_source(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.source, key, bitmap);
    }

    fn add_mac(&mut self, key: LpmKey, bitmap: DomainRouting) {
        Self::insert(&mut self.mac, key, bitmap);
    }

    /// Push the planned entries into the BPF maps.  These are per-key
    /// overwrites, so entries shared with the previous generation are
    /// replaced in place.  Failures are logged and skipped: a missing LPM
    /// entry degrades the affected rule to a non-match (traffic falls
    /// through to later rules), it cannot drop packets.
    fn apply(&self, ebpf: &mut dyn EbpfBackend) {
        for (key, bitmap) in self.dest.values() {
            if let Err(e) = ebpf.add_dest_lpm_bitmap(key, bitmap) {
                warn!("dest LPM push failed (non-fatal): {}", e);
            }
        }
        for (key, bitmap) in self.source.values() {
            if let Err(e) = ebpf.add_source_lpm_bitmap(key, bitmap) {
                warn!("source LPM push failed (non-fatal): {}", e);
            }
        }
        for (key, bitmap) in self.mac.values() {
            if let Err(e) = ebpf.add_mac_lpm_bitmap(key, bitmap) {
                warn!("mac LPM push failed (non-fatal): {}", e);
            }
        }
    }

    /// Raw key sets of this plan, used to prune entries of previous
    /// generations after the rule-count switch.
    fn keep_set(&self) -> LpmKeepSet {
        LpmKeepSet {
            dest: self.dest.keys().copied().collect(),
            source: self.source.keys().copied().collect(),
            mac: self.mac.keys().copied().collect(),
        }
    }
}

/// Compiles routing rules into eBPF data structures and pushes them
/// to the BPF maps.
pub struct RoutingMatcherBuilder;

impl RoutingMatcherBuilder {
    /// Build MatchSet entries from compiled routing rules and push to eBPF.
    ///
    /// `fallback_outbound` is the configured default outbound (e.g. `direct`).
    /// It is installed as the final `MT_FALLBACK` rule; the eBPF datapath
    /// treats `ControlPlaneRouting` as a logical composition marker, so the
    /// fallback must be a real outbound (Direct, Block, or a user group).
    ///
    /// In `domain`/`domain+`/`domain++` dial modes, generic port-based proxy
    /// rules are pushed with `ControlPlaneRouting` as their final outbound so
    /// that the userspace control plane can sniff the domain first.  eBPF will
    /// still fast-path the flow once DNS snooping populates `DOMAIN_ROUTING_MAP`.
    ///
    /// ## Two-phase commit
    ///
    /// The eBPF route loop evaluates `ROUTING_MAP[0..n)` where `n` is
    /// `ROUTING_META_MAP[0]`.  Clearing the maps first (the old behaviour)
    /// sets `n = 0`, and the datapath drops every new flow until the push
    /// completes (`route()` returns a negative errno → `TC_ACT_SHOT`); with
    /// many rules/CIDRs that window reaches tens to hundreds of milliseconds
    /// on every reload.  Instead we:
    ///
    /// 1. compile the whole ruleset (MatchSets + LPM plan + group bitmaps)
    ///    without touching any map;
    /// 2. overwrite `ROUTING_MAP[0..n)` with the new MatchSets;
    /// 3. publish the new LPM entries (per-key overwrite);
    /// 4. atomically switch by writing the routing meta block LAST:
    ///    the (l4proto × ipversion) group bitmaps at
    ///    `ROUTING_META_MAP[1..]`, then the rule count at
    ///    `ROUTING_META_MAP[0]`;
    /// 5. only then clean up: zero the stale MatchSet slots `[n..128)` and
    ///    prune the LPM keys the new ruleset no longer references.
    ///
    /// Trade-off: between steps 2 and 4 the datapath keeps the *old* rule
    /// count while already seeing *new* MatchSet/LPM contents, so it
    /// evaluates a mix of old and new rules and a flow may briefly be
    /// misrouted.  It is never SHOT-dropped, though: the count always
    /// covers a complete, valid ruleset.
    pub fn build_and_push(
        ebpf: &mut dyn EbpfBackend,
        routes: &[CompiledRoute],
        outbound_name_to_id: &HashMap<String, u8>,
        fallback_outbound: &str,
        dial_mode: DialMode,
    ) -> anyhow::Result<RoutingPushResult> {
        // Phase 1: compile the ruleset without touching any BPF map.
        let mut routes: Vec<&CompiledRoute> = routes.iter().collect();
        routes.sort_by_key(|r| r.priority);

        let mut match_sets: Vec<MatchSet> = Vec::with_capacity(routes.len() * 2);
        let mut domain_bitmaps: HashMap<String, Vec<DomainRouting>> = HashMap::new();
        let mut lpm_plan = LpmPushPlan::default();
        // (l4proto × ipversion) group bitmaps over ROUTING_MAP indices:
        // bit N of group g is set when the MatchSet at index N belongs to
        // group g.  Filled alongside the MatchSets below.
        let mut group_bitmaps: RoutingGroupBitmaps =
            [[0; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];

        for route in routes.iter().take(MAX_MATCH_SET_LEN as usize) {
            // Skip rules whose conditions are unsupported in eBPF.
            // Domain/geosite matching is evaluated by DNS snooping: the
            // DomainSet match type is pushed, and resolved IPs are inserted
            // into DOMAIN_ROUTING_MAP so the eBPF fast path can match them.
            if Self::has_unsupported_ebpf_conditions(route)
                || Self::collect_conditions(route).is_empty()
            {
                debug!(
                    "Skipping eBPF push for rule '{}' (unsupported or empty conditions)",
                    route.name
                );
                continue;
            }
            let outbound = outbound_name_to_id
                .get(route.outbound.as_str())
                .copied()
                .unwrap_or(OutboundIndex::Direct as u8);

            // In domain-aware dial modes, generic port-based proxy rules (no
            // domain/geosite/process condition) cannot be finalized by eBPF
            // because the domain is not known until userspace sniffs it.  Punt
            // those rules to the control plane so domain rules take precedence.
            let punt_to_control_plane = dial_mode != DialMode::Ip
                && !route.ports.is_empty()
                && route.domain_suffixes.is_empty()
                && route.domain_keywords.is_empty()
                && route.geosite_domains.is_empty()
                && route.process_names.is_empty()
                && route.mac_addresses.is_empty()
                && route.dscp_values.is_empty()
                && !route.outbound.eq_ignore_ascii_case("direct")
                && !route.outbound.eq_ignore_ascii_case("block");
            let effective_outbound = if punt_to_control_plane {
                OutboundIndex::ControlPlaneRouting as u8
            } else {
                outbound
            };

            info!(
                "rule '{}' outbound='{}' -> id={} (cp={})",
                route.name, route.outbound, effective_outbound, punt_to_control_plane
            );

            let rule_start = match_sets.len();
            Self::append_rule(
                route,
                effective_outbound,
                route.must,
                route.mark,
                &mut match_sets,
                &mut domain_bitmaps,
                &mut lpm_plan,
            )?;
            // Every MatchSet of this rule's chain shares the same group
            // membership, derived from the chain's L4Proto/IpVersion
            // entries, so the eBPF group pre-filter never splits a chain.
            let group_mask = Self::rule_group_mask(&match_sets[rule_start..]);
            Self::set_group_bits(&mut group_bitmaps, rule_start, match_sets.len(), group_mask);
        }

        // Always install a final fallback entry so unmatched traffic has a
        // defined behavior. The fallback must be a real outbound; using
        // ControlPlaneRouting here is invalid because the eBPF route loop
        // treats it as a logical operator and would leave ctx.result unset,
        // causing the "lan_ingress route fail: -1" drops.
        let fallback_outbound = outbound_name_to_id
            .get(fallback_outbound)
            .copied()
            .unwrap_or(OutboundIndex::Direct as u8);

        // Ensure the fallback fits even if the ruleset is at capacity.
        if match_sets.len() >= MAX_MATCH_SET_LEN as usize {
            warn!(
                "Generated {} match sets exceed eBPF MAX_MATCH_SET_LEN ({}); truncating to make room for fallback",
                match_sets.len(),
                MAX_MATCH_SET_LEN
            );
            match_sets.truncate(MAX_MATCH_SET_LEN as usize - 1);
            // Truncation can cut a rule chain mid-way; drop the group
            // bitmap bits of the removed tail so no group ever skips the
            // fallback slot that reused its index.
            Self::clear_group_bits_from(&mut group_bitmaps, match_sets.len());
        }
        let fallback_idx = match_sets.len();
        match_sets.push(MatchSet {
            value: MatchSetValue { raw: [0; 16] },
            not: 0,
            match_type: MatchType::Fallback as u8,
            outbound: fallback_outbound,
            must: 0,
            mark: 0,
        });
        // The fallback is the terminal rule for every flow: all groups.
        Self::set_group_bits(
            &mut group_bitmaps,
            fallback_idx,
            fallback_idx + 1,
            Self::ALL_GROUPS,
        );

        // Phase 2: publish.  MatchSets first, then the LPM entries they
        // reference, then the routing meta block (group bitmaps + rule
        // count) as the atomic switch.
        ebpf.set_routing_rules(&match_sets)?;
        lpm_plan.apply(ebpf);
        ebpf.set_routing_meta(match_sets.len() as u32, &group_bitmaps)?;

        info!(
            "Pushed {} MatchSet entries to eBPF ROUTING_MAP",
            match_sets.len()
        );

        // Phase 3: post-switch cleanup (best effort).  Failures here only
        // leave inert entries that the next push will overwrite or prune.
        if let Err(e) = ebpf.clear_routing_map_tail(match_sets.len() as u32) {
            warn!("clear_routing_map_tail failed (non-fatal): {}", e);
        }
        if let Err(e) = ebpf.prune_lpm_entries(&lpm_plan.keep_set()) {
            warn!("prune_lpm_entries failed (non-fatal): {}", e);
        }

        {
            let mut db = DOMAIN_BITMAPS.write();
            *db = domain_bitmaps.clone();
            DOMAIN_BITMAPS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Release);
        }

        Ok(RoutingPushResult {
            match_set_count: match_sets.len(),
            domain_bitmaps,
        })
    }

    /// Split one `CompiledRoute` into type-specific MatchSets and record the
    /// corresponding LPM updates into the push plan (no BPF map writes here).
    fn append_rule(
        route: &CompiledRoute,
        outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
        domain_bitmaps: &mut HashMap<String, Vec<DomainRouting>>,
        lpm_plan: &mut LpmPushPlan,
    ) -> anyhow::Result<()> {
        let conditions = Self::collect_conditions(route);
        let n = conditions.len();

        for (i, cond) in conditions.iter().enumerate() {
            let is_last = i == n - 1;
            let sub_outbound = if is_last {
                outbound
            } else {
                OutboundIndex::LogicalAnd as u8
            };

            match cond {
                Condition::SourceIp { nets } => {
                    let idx = match_sets.len() as u32;
                    if let Err(e) = Self::plan_source_lpm_routes(lpm_plan, nets, idx) {
                        warn!("SourceIp LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not: 0,
                        match_type: MatchType::SourceIpSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                Condition::Ip { nets } => {
                    let idx = match_sets.len() as u32;
                    if let Err(e) = Self::plan_dest_lpm_routes(lpm_plan, nets, idx) {
                        warn!("DestIp LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not: 0,
                        match_type: MatchType::IpSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                Condition::Mac { macs } => {
                    let idx = match_sets.len() as u32;
                    if let Err(e) = Self::plan_mac_lpm_routes(lpm_plan, macs, idx) {
                        warn!("Mac LPM planning failed (non-fatal): {}", e);
                    }
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not: 0,
                        match_type: MatchType::Mac as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                Condition::SourcePort { ranges } => {
                    Self::push_port_match_sets(ranges, true, sub_outbound, must, mark, match_sets);
                }
                Condition::Port { ranges } => {
                    Self::push_port_match_sets(ranges, false, sub_outbound, must, mark, match_sets);
                }
                Condition::Protocol { protocols } => {
                    let mask = Self::protocol_mask(protocols);
                    match_sets.push(MatchSet {
                        value: MatchSetValue {
                            l4proto_type: L4ProtoType::from_u8(mask).unwrap_or(L4ProtoType::Tcp),
                        },
                        not: 0,
                        match_type: MatchType::L4Proto as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                Condition::IpVersion { versions } => {
                    let mask = Self::ip_version_mask(versions);
                    match_sets.push(MatchSet {
                        value: MatchSetValue {
                            ip_version: IpVersionType::from_u8(mask).unwrap_or(IpVersionType::V4),
                        },
                        not: 0,
                        match_type: MatchType::IpVersion as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
                Condition::Dscp { values } => {
                    Self::push_dscp_match_sets(values, sub_outbound, must, mark, match_sets);
                }
                Condition::ProcessName { names } => {
                    Self::push_process_name_match_sets(names, sub_outbound, must, mark, match_sets);
                }
                // Domain: push a DomainSet placeholder in ROUTING_MAP.
                // The actual domain→IP mapping will be populated by DNS snooping:
                // when DNS resolves a domain to IPs, those IPs are pushed to
                // DOMAIN_ROUTING_MAP with the bitmap pointing to this match_set.
                Condition::Domain { .. } => {
                    let idx = match_sets.len() as u32;
                    let bitmap = Self::bitmap_for_rule(idx);
                    domain_bitmaps
                        .entry(route.name.clone())
                        .or_default()
                        .push(bitmap);
                    match_sets.push(MatchSet {
                        value: MatchSetValue { raw: [0; 16] },
                        not: 0,
                        match_type: MatchType::DomainSet as u8,
                        outbound: sub_outbound,
                        must: must as u8,
                        mark,
                    });
                }
            }
        }

        Ok(())
    }

    /// Return the list of conditions present in a route, in evaluation order.
    fn collect_conditions<'a>(route: &'a CompiledRoute) -> Vec<Condition<'a>> {
        let mut conditions = Vec::new();

        let has_domain = !route.domain_suffixes.is_empty()
            || !route.domain_keywords.is_empty()
            || !route.geosite_domains.is_empty();
        if has_domain {
            conditions.push(Condition::Domain {
                suffixes: &route.domain_suffixes,
                keywords: &route.domain_keywords,
                geosite_domains: &route.geosite_domains,
            });
        }

        if !route.source_ip_nets.is_empty() {
            conditions.push(Condition::SourceIp {
                nets: &route.source_ip_nets,
            });
        }

        if !route.ip_nets.is_empty() {
            conditions.push(Condition::Ip {
                nets: &route.ip_nets,
            });
        }

        if !route.mac_addresses.is_empty() {
            conditions.push(Condition::Mac {
                macs: &route.mac_addresses,
            });
        }

        if !route.source_ports.is_empty() {
            conditions.push(Condition::SourcePort {
                ranges: &route.source_ports,
            });
        }

        if !route.ports.is_empty() {
            conditions.push(Condition::Port {
                ranges: &route.ports,
            });
        }

        if !route.protocols.is_empty() {
            conditions.push(Condition::Protocol {
                protocols: &route.protocols,
            });
        }

        if !route.ip_versions.is_empty() {
            conditions.push(Condition::IpVersion {
                versions: &route.ip_versions,
            });
        }

        if !route.dscp_values.is_empty() {
            conditions.push(Condition::Dscp {
                values: &route.dscp_values,
            });
        }

        if !route.process_names.is_empty() {
            conditions.push(Condition::ProcessName {
                names: &route.process_names,
            });
        }

        conditions
    }

    /// Returns true if the route contains any condition that cannot be
    /// evaluated by the eBPF datapath and must be left to userspace.
    ///
    /// All conditions we currently generate have an eBPF representation:
    /// domain/geosite via `DomainSet` + DNS snooping, IP/MAC via LPM tries,
    /// ports/protocol/ipversion/dscp directly, and process names via pname.
    fn has_unsupported_ebpf_conditions(_route: &CompiledRoute) -> bool {
        false
    }

    /// Record destination IP prefixes for DEST_LPM_ROUTING_MAP into the plan.
    fn plan_dest_lpm_routes(
        plan: &mut LpmPushPlan,
        nets: &[ipnet::IpNet],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for (i, net) in nets.iter().enumerate() {
            let lpm_key = maps::cidr_to_lpm_key(&net.to_string())?;
            if lpm_key.prefix_len == 0 {
                warn!("dest LPM: zero prefix for {}", net);
            }
            if i < 3 {
                debug!(
                    "dest LPM insert {}: prefix_len={} data={:?}",
                    net, lpm_key.prefix_len, lpm_key.data
                );
            }
            plan.add_dest(lpm_key, bitmap);
        }

        info!(
            "Planned {} destination IP routes for rule {}",
            nets.len(),
            rule_index
        );
        Ok(())
    }

    /// Record source IP prefixes for SOURCE_LPM_ROUTING_MAP into the plan.
    fn plan_source_lpm_routes(
        plan: &mut LpmPushPlan,
        nets: &[ipnet::IpNet],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for net in nets {
            let lpm_key = maps::cidr_to_lpm_key(&net.to_string())?;
            plan.add_source(lpm_key, bitmap);
        }

        info!(
            "Planned {} source IP routes for rule {}",
            nets.len(),
            rule_index
        );
        Ok(())
    }

    /// Record MAC addresses for MAC_LPM_ROUTING_MAP into the plan.
    ///
    /// Each MAC is encoded as an IPv6-like 16-byte prefix with the MAC in
    /// bytes 10–15 and prefix_len=128 (exact match), matching Go dae-core's
    /// approach of storing MAC entries in LPM tries.
    fn plan_mac_lpm_routes(
        plan: &mut LpmPushPlan,
        macs: &[String],
        rule_index: u32,
    ) -> anyhow::Result<()> {
        if macs.is_empty() {
            return Ok(());
        }

        let bitmap = Self::bitmap_for_rule(rule_index);

        for mac_str in macs {
            let mac_bytes = match parse_mac_to_bytes(mac_str) {
                Some(b) => b,
                None => {
                    warn!("Invalid MAC address '{}', skipping", mac_str);
                    continue;
                }
            };

            // Encode MAC as IPv6-like address: MAC occupies bytes 10-15.
            // The LPM trie compares the full 16-byte key with prefix_len=128
            // for exact MAC match.
            let mut addr: [u8; 16] = [0; 16];
            addr[10..16].copy_from_slice(&mac_bytes);

            // Convert to u32 chunks matching the LpmKey data layout.
            let mut data = [0u32; 4];
            for (i, chunk) in addr.chunks(4).enumerate() {
                data[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }

            let lpm_key = LpmKey {
                prefix_len: 128,
                data,
            };
            plan.add_mac(lpm_key, bitmap);
        }

        info!("Planned {} MAC routes for rule {}", macs.len(), rule_index);
        Ok(())
    }

    /// Append one MatchSet per port range, ORing multiple ranges with LogicalOr.
    fn push_port_match_sets(
        ranges: &[crate::routing::PortRange],
        is_source: bool,
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = ranges.len();
        for (i, r) in ranges.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            match_sets.push(MatchSet {
                value: MatchSetValue {
                    port_range: honk_ebpf_common::PortRange {
                        port_start: r.start,
                        port_end: r.end,
                    },
                },
                not: 0,
                match_type: if is_source {
                    MatchType::SourcePort as u8
                } else {
                    MatchType::Port as u8
                },
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    /// Append one MatchSet per DSCP value, ORing multiple values with LogicalOr.
    fn push_dscp_match_sets(
        values: &[u8],
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = values.len();
        for (i, &v) in values.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            match_sets.push(MatchSet {
                value: MatchSetValue { dscp: v },
                not: 0,
                match_type: MatchType::Dscp as u8,
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    /// Append one MatchSet per process name, ORing multiple names with LogicalOr.
    /// Each name is truncated to TASK_COMM_LEN (16 bytes) and stored as [u32; 4].
    fn push_process_name_match_sets(
        names: &[String],
        final_outbound: u8,
        must: bool,
        mark: u32,
        match_sets: &mut Vec<MatchSet>,
    ) {
        let n = names.len();
        for (i, name) in names.iter().enumerate() {
            let is_last = i == n - 1;
            let outbound = if is_last {
                final_outbound
            } else {
                OutboundIndex::LogicalOr as u8
            };
            let mut pname = [0u32; 4];
            let src = name.as_bytes();
            let len = src.len().min(TASK_COMM_LEN);
            // SAFETY: pname is [u32; 4] = 16 bytes, same size as TASK_COMM_LEN.
            let dst = &mut pname as *mut [u32; 4] as *mut u8;
            for (i, &b) in src.iter().enumerate().take(len) {
                unsafe {
                    *dst.add(i) = b;
                }
            }
            match_sets.push(MatchSet {
                value: MatchSetValue { pname },
                not: 0,
                match_type: MatchType::ProcessName as u8,
                outbound,
                must: must as u8,
                mark,
            });
        }
    }

    /// Return a DomainRouting bitmap with a single bit set for `rule_index`.
    fn bitmap_for_rule(rule_index: u32) -> DomainRouting {
        let mut bitmap = [0u32; 4];
        let wi = (rule_index / 32) as usize;
        if wi < bitmap.len() {
            bitmap[wi] = 1u32 << (rule_index % 32);
        }
        DomainRouting { bitmap }
    }

    /// Group mask selecting every (l4proto × ipversion) routing group.
    const ALL_GROUPS: u8 = (1 << ROUTING_GROUP_COUNT) - 1;

    /// Compute the (l4proto × ipversion) group mask of a rule from its
    /// compiled MatchSet chain.
    ///
    /// The chain is scanned — rather than the source conditions — so the
    /// mask is derived from exactly the values `eval_match` will compare
    /// against: an L4Proto entry restricts the rule to the tcp groups iff
    /// `value & Tcp != 0` and to the udp groups iff `value & Udp != 0`;
    /// an IpVersion entry does the same for the address family.  A rule
    /// without such entries can match any flow and belongs to all groups.
    ///
    /// Note the IpVersion dimension currently never narrows: values use
    /// the OR-of-enum encoding (V4=4, V6=6) and `4 & 6 != 0`, so every
    /// stored value matches both versions in `eval_match` as well.
    fn rule_group_mask(chain: &[MatchSet]) -> u8 {
        let mut l4 = 0b11u8; // bit 0: tcp allowed, bit 1: udp allowed
        let mut ip = 0b11u8; // bit 0: v4 allowed, bit 1: v6 allowed
        for ms in chain {
            match MatchType::from_u8(ms.match_type) {
                Some(MatchType::L4Proto) => {
                    let v = unsafe { ms.value.l4proto_type as u8 };
                    let mut allowed = 0u8;
                    if v & (L4ProtoType::Tcp as u8) != 0 {
                        allowed |= 0b01;
                    }
                    if v & (L4ProtoType::Udp as u8) != 0 {
                        allowed |= 0b10;
                    }
                    l4 &= allowed;
                }
                Some(MatchType::IpVersion) => {
                    let v = unsafe { ms.value.ip_version as u8 };
                    let mut allowed = 0u8;
                    if v & (IpVersionType::V4 as u8) != 0 {
                        allowed |= 0b01;
                    }
                    if v & (IpVersionType::V6 as u8) != 0 {
                        allowed |= 0b10;
                    }
                    ip &= allowed;
                }
                _ => {}
            }
        }
        let mut mask = 0u8;
        if l4 & 0b01 != 0 && ip & 0b01 != 0 {
            mask |= 1 << ROUTING_GROUP_TCP4;
        }
        if l4 & 0b01 != 0 && ip & 0b10 != 0 {
            mask |= 1 << ROUTING_GROUP_TCP6;
        }
        if l4 & 0b10 != 0 && ip & 0b01 != 0 {
            mask |= 1 << ROUTING_GROUP_UDP4;
        }
        if l4 & 0b10 != 0 && ip & 0b10 != 0 {
            mask |= 1 << ROUTING_GROUP_UDP6;
        }
        mask
    }

    /// Set the bitmap bits for MatchSet indices `[start, end)` in every
    /// group selected by `group_mask` (bit g = group g).  Bit N of a
    /// group bitmap always refers to the global ROUTING_MAP index N;
    /// MatchSets are never duplicated across groups.
    fn set_group_bits(bitmaps: &mut RoutingGroupBitmaps, start: usize, end: usize, group_mask: u8) {
        for (g, words) in bitmaps.iter_mut().enumerate() {
            if (group_mask >> g) & 1 == 0 {
                continue;
            }
            for idx in start..end {
                let word = idx / 32;
                if word < words.len() {
                    words[word] |= 1u32 << (idx % 32);
                }
            }
        }
    }

    /// Clear the bitmap bits at indices `>= from` in every group.  Used
    /// when ruleset truncation drops MatchSets whose bits were already
    /// recorded.
    fn clear_group_bits_from(bitmaps: &mut RoutingGroupBitmaps, from: usize) {
        for words in bitmaps.iter_mut() {
            for (w, word) in words.iter_mut().enumerate() {
                let base = w * 32;
                if base >= from {
                    *word = 0;
                } else if base + 32 > from {
                    *word &= (1u32 << (from - base)) - 1;
                }
            }
        }
    }

    /// Convert protocol strings to L4 protocol mask (1=TCP, 2=UDP).
    fn protocol_mask(protocols: &[String]) -> u8 {
        if protocols.is_empty() {
            return 0; // match any
        }
        let mut mask = 0u8;
        for proto in protocols {
            match proto.to_lowercase().as_str() {
                "tcp" => mask |= 1,
                "udp" => mask |= 2,
                _ => {}
            }
        }
        mask
    }

    /// Convert IP version values to bitmask (4=1, 6=2).
    fn ip_version_mask(versions: &[u8]) -> u8 {
        if versions.is_empty() {
            return 0;
        }
        let mut mask = 0u8;
        for &v in versions {
            match v {
                4 => mask |= 1,
                6 => mask |= 2,
                _ => {}
            }
        }
        mask
    }
}

/// Parse a MAC address string into a 6-byte array.
///
/// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`,
/// or `aabbccddeeff`.
fn parse_mac_to_bytes(s: &str) -> Option<[u8; 6]> {
    let stripped: String = s
        .chars()
        .filter(|&c| c != ':' && c != '-' && c != '.')
        .collect();
    if stripped.len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for i in 0..6 {
        bytes[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::mock::MockEbpfBackend;

    #[test]
    fn test_protocol_mask() {
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&[]), 0);
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&["tcp".into()]), 1);
        assert_eq!(RoutingMatcherBuilder::protocol_mask(&["udp".into()]), 2);
        assert_eq!(
            RoutingMatcherBuilder::protocol_mask(&["tcp".into(), "udp".into()]),
            3
        );
    }

    #[test]
    fn test_ip_version_mask() {
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[]), 0);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[4]), 1);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[6]), 2);
        assert_eq!(RoutingMatcherBuilder::ip_version_mask(&[4, 6]), 3);
    }

    #[test]
    fn test_bitmap_for_rule() {
        let dr = RoutingMatcherBuilder::bitmap_for_rule(5);
        assert_eq!(dr.bitmap[0], 1 << 5);

        let dr = RoutingMatcherBuilder::bitmap_for_rule(32);
        assert_eq!(dr.bitmap[1], 1 << 0);
    }

    #[test]
    fn test_parse_mac_to_bytes() {
        assert_eq!(
            parse_mac_to_bytes("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("AA-BB-CC-DD-EE-FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("aabb.ccdd.eeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac_to_bytes("aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac_to_bytes("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac_to_bytes(""), None);
    }

    fn make_route(name: &str, outbound: &str) -> CompiledRoute {
        CompiledRoute {
            name: name.into(),
            display: name.into(),
            priority: 0,
            domain_patterns: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_keywords: Vec::new(),
            ip_nets: Vec::new(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            source_ip_nets: Vec::new(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&[]),
            ports: Vec::new(),
            source_ports: Vec::new(),
            protocols: Vec::new(),
            process_names: Vec::new(),
            mac_addresses: Vec::new(),
            geosite_domains: Vec::new(),
            geosite_matcher: Default::default(),
            ip_versions: Vec::new(),
            dscp_values: Vec::new(),
            outbound: outbound.into(),
            must: false,
            mark: 0,
        }
    }

    #[test]
    fn test_push_ip_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("private", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_map.len(), 2); // IpSet + fallback
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        assert!(backend.source_lpm_bitmap.is_empty());
    }

    #[test]
    fn test_push_source_ip_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let route = CompiledRoute {
            source_ip_nets: nets.clone(),
            source_ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("src-lan", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_map.len(), 2);
        assert_eq!(backend.source_lpm_bitmap.len(), 1);
        assert!(backend.dest_lpm_bitmap.is_empty());
    }

    #[test]
    fn test_push_port_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_map.len(), 2);
        let port_rule = backend.routing_map.get(&0).unwrap();
        assert_eq!(port_rule.match_type, MatchType::Port as u8);
        assert_eq!(port_rule.outbound, OutboundIndex::UserBase as u8);
        let fallback = backend.routing_map.get(&1).unwrap();
        assert_eq!(fallback.match_type, MatchType::Fallback as u8);
    }

    #[test]
    fn test_push_port_rule_punted_in_domainpp() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::DomainPlusPlus,
        )
        .unwrap();

        let port_rule = backend.routing_map.get(&0).unwrap();
        assert_eq!(port_rule.match_type, MatchType::Port as u8);
        assert_eq!(
            port_rule.outbound,
            OutboundIndex::ControlPlaneRouting as u8,
            "port-based proxy rule should be punted to userspace in domain++ mode"
        );
    }

    #[test]
    fn test_push_protocol_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            protocols: vec!["udp".into()],
            ..make_route("udp", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_map.len(), 2);
        let proto_rule = backend.routing_map.get(&0).unwrap();
        assert_eq!(proto_rule.match_type, MatchType::L4Proto as u8);
        assert_eq!(proto_rule.outbound, OutboundIndex::UserBase as u8);
    }

    #[test]
    fn test_push_mac_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            mac_addresses: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..make_route("device", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_map.len(), 2);
        assert_eq!(backend.mac_lpm_bitmap.len(), 1);
    }

    #[test]
    fn test_push_domain_rule_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            domain_suffixes: vec!["google.com".into()],
            ..make_route("google", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        let result = RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(result.match_set_count, 2);
        assert!(result.domain_bitmaps.contains_key("google"));
        assert_eq!(
            backend.routing_map.get(&0).unwrap().match_type,
            MatchType::DomainSet as u8
        );
    }

    #[test]
    fn test_push_must_and_mark_to_ebpf() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange { start: 22, end: 22 }],
            must: true,
            mark: 99,
            ..make_route("ssh", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "proxy",
            DialMode::Ip,
        )
        .unwrap();

        let rule = backend.routing_map.get(&0).unwrap();
        assert_eq!(rule.must, 1);
        assert_eq!(rule.mark, 99);
        let fallback = backend.routing_map.get(&1).unwrap();
        assert_eq!(fallback.match_type, MatchType::Fallback as u8);
        assert_eq!(fallback.outbound, OutboundIndex::Direct as u8);
    }

    #[test]
    fn test_push_multiple_rules_and_priority_order() {
        let mut backend = MockEbpfBackend::new();
        let route1 = CompiledRoute {
            priority: 10,
            ports: vec![crate::routing::PortRange { start: 80, end: 80 }],
            ..make_route("http", "proxy")
        };
        let route2 = CompiledRoute {
            priority: 5,
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "direct")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route1, route2],
            &outbound_map,
            "block",
            DialMode::Ip,
        )
        .unwrap();

        // priority 5 first, then priority 10, then fallback
        assert_eq!(backend.routing_map.len(), 3);
        assert_eq!(
            backend.routing_map.get(&0).unwrap().outbound,
            OutboundIndex::Direct as u8
        );
        assert_eq!(
            backend.routing_map.get(&1).unwrap().outbound,
            OutboundIndex::UserBase as u8
        );
    }

    #[test]
    fn test_reload_prunes_stale_lpm_and_rules() {
        // Second push (reload) must not call clear_routes: stale LPM keys are
        // pruned by set difference and the MatchSet tail is cleared, while the
        // rule count always covers a complete ruleset.
        let mut backend = MockEbpfBackend::new();
        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        let nets1: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route1 = CompiledRoute {
            ip_nets: nets1.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets1),
            ..make_route("r1", "direct")
        };
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route1],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        assert_eq!(backend.routing_map.len(), 2); // IpSet + fallback

        // Reload with a different CIDR and fewer rules.
        let nets2: Vec<ipnet::IpNet> = vec!["192.168.0.0/16".parse().unwrap()];
        let route2 = CompiledRoute {
            ip_nets: nets2.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets2),
            ..make_route("r2", "direct")
        };
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route2],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        // The old CIDR is gone, the new one is present, and the bitmap
        // references rule index 0 of the new generation (no OR-accumulation
        // from the previous generation).
        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        let key2 = maps::lpm_key_bytes(&maps::cidr_to_lpm_key("192.168.0.0/16").unwrap());
        let entry = backend.dest_lpm_bitmap.get(&key2).unwrap();
        assert_eq!(entry.bitmap[0], 1);
        assert_eq!(backend.routing_map.len(), 2);
        assert_eq!(backend.routing_meta.get(&0).copied(), Some(2));
    }

    #[test]
    fn test_shared_cidr_across_rules_merges_bits() {
        // Two rules referencing the same CIDR in one push must produce a
        // single LPM entry with both rule bits set (the real backend
        // overwrites LPM values; merging happens in the plan).
        let mut backend = MockEbpfBackend::new();
        let nets: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let route_a = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("a", "direct")
        };
        let route_b = CompiledRoute {
            ip_nets: nets.clone(),
            ip_trie: crate::routing::BinaryLpmTrie::from_nets(&nets),
            ..make_route("b", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route_a, route_b],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.dest_lpm_bitmap.len(), 1);
        let entry = backend.dest_lpm_bitmap.values().next().unwrap();
        assert_eq!(
            entry.bitmap[0], 0b11,
            "shared CIDR must carry both rule indices (0 and 1)"
        );
    }

    #[test]
    fn test_push_does_not_clear_routes_first() {
        // Regression guard for the two-phase commit: build_and_push must not
        // reset the rule count to 0 at any point (the eBPF datapath SHOTs
        // new flows while the count is 0).  With the mock, the observable
        // invariant is that a reload leaves a valid count and no stale maps.
        let mut backend = MockEbpfBackend::new();
        let mut outbound_map = HashMap::new();
        outbound_map.insert("direct".to_string(), OutboundIndex::Direct as u8);

        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange { start: 80, end: 80 }],
            ..make_route("http", "direct")
        };
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            std::slice::from_ref(&route),
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();
        // Reload with the identical ruleset: everything must stay consistent.
        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_meta.get(&0).copied(), Some(2));
        assert_eq!(backend.routing_map.len(), 2);
        assert!(backend.domain_routes.is_empty());
        assert!(backend.ip_routes.is_empty());
    }

    /// Read word `w` of group `g`'s rule bitmap from the mock meta map.
    fn mock_group_word(backend: &MockEbpfBackend, g: u32, w: u32) -> u32 {
        backend
            .routing_meta
            .get(&(1 + g * ROUTING_GROUP_BITMAP_WORDS as u32 + w))
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn test_group_mask_tcp_only_chain() {
        // A chain carrying an L4Proto(tcp) entry belongs to the tcp
        // groups only.
        let chain = [MatchSet {
            value: MatchSetValue {
                l4proto_type: L4ProtoType::Tcp,
            },
            match_type: MatchType::L4Proto as u8,
            ..Default::default()
        }];
        let mask = RoutingMatcherBuilder::rule_group_mask(&chain);
        assert_eq!(mask, (1 << ROUTING_GROUP_TCP4) | (1 << ROUTING_GROUP_TCP6));
    }

    #[test]
    fn test_group_mask_udp_only_chain() {
        let chain = [MatchSet {
            value: MatchSetValue {
                l4proto_type: L4ProtoType::Udp,
            },
            match_type: MatchType::L4Proto as u8,
            ..Default::default()
        }];
        let mask = RoutingMatcherBuilder::rule_group_mask(&chain);
        assert_eq!(mask, (1 << ROUTING_GROUP_UDP4) | (1 << ROUTING_GROUP_UDP6));
    }

    #[test]
    fn test_group_mask_without_proto_entries_covers_all_groups() {
        // No L4Proto/IpVersion entry: the rule can match any flow.
        let port_chain = [MatchSet {
            value: MatchSetValue {
                port_range: honk_ebpf_common::PortRange {
                    port_start: 443,
                    port_end: 443,
                },
            },
            match_type: MatchType::Port as u8,
            ..Default::default()
        }];
        assert_eq!(
            RoutingMatcherBuilder::rule_group_mask(&port_chain),
            RoutingMatcherBuilder::ALL_GROUPS
        );

        let fallback_chain = [MatchSet {
            match_type: MatchType::Fallback as u8,
            ..Default::default()
        }];
        assert_eq!(
            RoutingMatcherBuilder::rule_group_mask(&fallback_chain),
            RoutingMatcherBuilder::ALL_GROUPS
        );
    }

    #[test]
    fn test_group_mask_ipversion_does_not_narrow() {
        // eval_match compares `ipversion & value`; with the OR-of-enum
        // encoding (V4=4, V6=6) every stored value matches both versions
        // (4 & 6 != 0), so an IpVersion entry must not narrow the group
        // mask either — otherwise flows would skip rules eval_match
        // would actually match.
        for version in [IpVersionType::V4, IpVersionType::V6] {
            let chain = [MatchSet {
                value: MatchSetValue {
                    ip_version: version,
                },
                match_type: MatchType::IpVersion as u8,
                ..Default::default()
            }];
            assert_eq!(
                RoutingMatcherBuilder::rule_group_mask(&chain),
                RoutingMatcherBuilder::ALL_GROUPS
            );
        }
    }

    #[test]
    fn test_push_tcp_rule_not_in_udp_groups() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            protocols: vec!["tcp".into()],
            ..make_route("tcp-only", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        // One L4Proto MatchSet at index 0, fallback at index 1.
        assert_eq!(backend.routing_meta.get(&0).copied(), Some(2));
        for g in [ROUTING_GROUP_TCP4, ROUTING_GROUP_TCP6] {
            assert_eq!(
                mock_group_word(&backend, g, 0) & 0b11,
                0b11,
                "tcp group {g} must contain the rule (bit 0) and the fallback (bit 1)"
            );
        }
        for g in [ROUTING_GROUP_UDP4, ROUTING_GROUP_UDP6] {
            assert_eq!(
                mock_group_word(&backend, g, 0) & 0b11,
                0b10,
                "udp group {g} must skip the tcp-only rule but keep the fallback"
            );
        }
    }

    #[test]
    fn test_push_no_proto_rule_in_all_groups() {
        let mut backend = MockEbpfBackend::new();
        let route = CompiledRoute {
            ports: vec![crate::routing::PortRange {
                start: 443,
                end: 443,
            }],
            ..make_route("https", "proxy")
        };

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &[route],
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        // Port rule at index 0 (no protocol constraint) + fallback at 1:
        // every group sees both.
        for g in 0..ROUTING_GROUP_COUNT as u32 {
            assert_eq!(mock_group_word(&backend, g, 0) & 0b11, 0b11, "group {g}");
        }
    }

    #[test]
    fn test_group_bitmap_bits_match_global_indices() {
        // 17 tcp+port rules produce 17 two-entry chains (indices 0..34)
        // plus the fallback at index 34, so the bitmaps cross the first
        // 32-bit word boundary.  Every bit must refer to the global
        // ROUTING_MAP index of its MatchSet — no per-group renumbering.
        let mut backend = MockEbpfBackend::new();
        let routes: Vec<CompiledRoute> = (0..17u16)
            .map(|i| CompiledRoute {
                protocols: vec!["tcp".into()],
                ports: vec![crate::routing::PortRange {
                    start: 1000 + i,
                    end: 1000 + i,
                }],
                ..make_route(&format!("r{i}"), "proxy")
            })
            .collect();

        let mut outbound_map = HashMap::new();
        outbound_map.insert("proxy".to_string(), OutboundIndex::UserBase as u8);

        RoutingMatcherBuilder::build_and_push(
            &mut backend,
            &routes,
            &outbound_map,
            "direct",
            DialMode::Ip,
        )
        .unwrap();

        assert_eq!(backend.routing_meta.get(&0).copied(), Some(35));
        // tcp groups: rule chains fill word 0 and bits 0-1 of word 1,
        // the fallback adds bit 2 of word 1 (global index 34).
        for g in [ROUTING_GROUP_TCP4, ROUTING_GROUP_TCP6] {
            assert_eq!(mock_group_word(&backend, g, 0), u32::MAX, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 1), 0b111, "group {g}");
        }
        // udp groups: only the fallback bit (global index 34 → word 1 bit 2).
        for g in [ROUTING_GROUP_UDP4, ROUTING_GROUP_UDP6] {
            assert_eq!(mock_group_word(&backend, g, 0), 0, "group {g}");
            assert_eq!(mock_group_word(&backend, g, 1), 0b100, "group {g}");
        }
    }

    #[test]
    fn test_clear_group_bits_from() {
        let mut bitmaps: RoutingGroupBitmaps =
            [[u32::MAX; ROUTING_GROUP_BITMAP_WORDS]; ROUTING_GROUP_COUNT];
        RoutingMatcherBuilder::clear_group_bits_from(&mut bitmaps, 34);
        for words in bitmaps.iter() {
            assert_eq!(words[0], u32::MAX);
            assert_eq!(words[1], 0b11);
            assert_eq!(words[2], 0);
            assert_eq!(words[3], 0);
        }
    }
}
