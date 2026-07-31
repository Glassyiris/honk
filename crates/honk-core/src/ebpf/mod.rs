//! eBPF backend abstraction.

pub mod maps;
pub mod mock;
pub mod probe;
#[cfg(feature = "ebpf")]
pub mod real;

use async_trait::async_trait;
use honk_ebpf_common::*;
use std::sync::atomic::AtomicU64;

/// Cumulative conn-state entries deleted by userspace (TCP relay teardown,
/// UDP endpoint reaper), for the janitor's occupancy gauge.  eBPF-side
/// inserts/deletes are counted by the `CONN_STATE_OCCUPANCY` map; deletions
/// initiated from userspace must be accounted separately or the gauge
/// overestimates live occupancy between sweep calibrations.
pub static USERSPACE_CONN_STATE_DELETES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct BpfLoadParams {
    pub tproxy_port: u16,
    pub tproxy_mark: u32,
    pub so_mark: u32,
    pub control_plane_pid: u32,
    pub dae0_ifindex: u32,
    pub lo_ifindex: u32,
    pub dae_netns_id: u32,
    pub dae0peer_mac: [u8; 6],
    pub local_ip: u32,
}

impl Default for BpfLoadParams {
    fn default() -> Self {
        Self {
            tproxy_port: 12345,
            tproxy_mark: 0x0800_0000,
            so_mark: 0,
            control_plane_pid: 0,
            dae0_ifindex: 0,
            lo_ifindex: 0,
            dae_netns_id: 0,
            dae0peer_mac: [0u8; 6],
            local_ip: 0,
        }
    }
}

/// Raw key sets identifying the LPM entries that belong to the current
/// ruleset generation, consumed by [`EbpfBackend::prune_lpm_entries`].
/// Keys are the 20-byte raw `LpmKey` encoding produced by
/// [`maps::lpm_key_bytes`].
#[derive(Debug, Default, Clone)]
pub struct LpmKeepSet {
    /// Keys present in DEST_LPM_ROUTING_MAP for the current generation.
    pub dest: std::collections::HashSet<[u8; 20]>,
    /// Keys present in SOURCE_LPM_ROUTING_MAP for the current generation.
    pub source: std::collections::HashSet<[u8; 20]>,
    /// Keys present in MAC_LPM_ROUTING_MAP for the current generation.
    pub mac: std::collections::HashSet<[u8; 20]>,
}

/// Callback for [`EbpfBackend::conn_state_for_each_chunk`].
pub type ConnStateChunkVisitor<'a> = dyn FnMut(&[(TuplesKey, ConnState)]) + 'a;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPushPhase {
    Rules,
    DestinationLpm,
    SourceLpm,
    MacLpm,
    Meta,
    ClearTail,
    PruneLpm,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMapOperation {
    Set,
    Remove,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainRouteWriteError {
    #[error("domain routing map capacity exhausted")]
    MapFull,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DomainRouteWriteError {
    pub const fn is_map_full(&self) -> bool {
        matches!(self, Self::MapFull)
    }
}

/// Which config list an interface came from; selects the TC programs a
/// dynamic attach installs on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceRole {
    Lan,
    Wan,
    /// Slave port of a configured LAN bridge master: forwarded L2 traffic
    /// never crosses the master's TC hooks, so the LAN programs go on each
    /// slave (mirrors the startup expansion).
    LanBridgeSlave,
    /// Slave of a configured LAN bond master: packets may arrive/leave on
    /// the slave without touching the master's qdiscs, so it gets
    /// lan_ingress + wan_egress (mirrors the startup expansion).
    LanBondSlave,
}

/// Per-direction outcome of a dynamic attach: which hooks are live on the
/// interface after the call (including ones attached earlier).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DynamicHooks {
    pub ingress: bool,
    pub egress: bool,
}

#[async_trait]
pub trait EbpfBackend: Send + Sync {
    fn inject_routing_fault(
        &mut self,
        _phase: RoutingPushPhase,
        _times: usize,
    ) -> anyhow::Result<()> {
        anyhow::bail!("routing fault injection is unsupported")
    }
    #[cfg(test)]
    fn inject_projection_fault(
        &mut self,
        _operation: ProjectionMapOperation,
        _times: usize,
        _map_full: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("projection fault injection is unsupported")
    }
    #[cfg(test)]
    fn projection_map_snapshot(&self) -> Vec<([u8; 20], DomainRouting)> {
        Vec::new()
    }
    #[cfg(test)]
    fn projection_write_log(&self) -> Vec<ProjectionMapOperation> {
        Vec::new()
    }
    #[cfg(test)]
    fn clear_projection_write_log(&mut self) {}
    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn eject(&mut self) {}
    fn inject(&mut self, _params: &BpfLoadParams) -> anyhow::Result<()> {
        Ok(())
    }
    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the dae0peer_ingress TC program after dae0peer has been moved
    /// into the isolated daens namespace.  The attach runs inside a scoped
    /// `with_daens_netns` switch — the process threads always stay in the
    /// host netns — while the dae0peer interface and the TPROXY listener
    /// sockets both live in daens.
    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Attach the sk_lookup program to the isolated daens namespace (also a
    /// scoped switch).  The program overrides socket selection for
    /// proxy-bound packets arriving on dae0peer and delivers them to the
    /// daens-resident TPROXY listener while keeping the original destination
    /// intact.
    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Publish the raw file descriptors of the tproxy listener sockets into the
    /// eBPF listen_socket_map so TC programs can bpf_sk_assign() inbound proxy
    /// traffic directly to the userspace listeners.
    ///
    /// Key mapping matches Go dae-core with the addition of a dedicated IPv6
    /// UDP listener:
    ///   0 -> IPv4 TCP listener
    ///   1 -> IPv4 UDP listener
    ///   2 -> IPv6 TCP listener
    ///   3 -> IPv6 UDP listener
    fn publish_listener_sockets(
        &mut self,
        _tcp4_fd: std::os::unix::io::RawFd,
        _tcp6_fd: std::os::unix::io::RawFd,
        _udp4_fd: std::os::unix::io::RawFd,
        _udp6_fd: std::os::unix::io::RawFd,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()>;

    /// Attach TC programs to a configured interface that appeared after
    /// startup.  Backends dedupe per (ifindex, direction): a direction that
    /// is already hooked is reported, never re-attached, so retrying after
    /// a partial failure cannot stack duplicate hooks.
    fn attach_dynamic_interface(
        &mut self,
        _ifname: &str,
        _role: IfaceRole,
        _single_homed: bool,
    ) -> anyhow::Result<DynamicHooks> {
        Ok(DynamicHooks::default())
    }

    /// Drop any dynamic-attach state for `ifindex` (the device is gone or
    /// was recreated, so its hooks died with it).
    fn forget_dynamic_interface(&mut self, _ifindex: u32) {}

    fn set_param(&mut self, key: ParamKey, value: u32) -> anyhow::Result<()>;
    fn get_param(&self, key: ParamKey) -> anyhow::Result<Option<u32>>;

    fn set_routing_rules(&mut self, rules: &[MatchSet]) -> anyhow::Result<()>;
    /// Publish the routing meta block (`ROUTING_META_MAP`): `count` active
    /// rules plus the per-(l4proto × ipversion)-group bitmaps telling the
    /// datapath which groups each rule index belongs to (see
    /// [`ROUTING_META_MAP_LEN`] for the slot layout).
    ///
    /// This is the atomic switch of the two-phase routing commit and must
    /// run LAST, after the MatchSets and LPM entries it activates.
    /// Backends must write the group bitmap slots (1..) first and the
    /// rule-count slot 0 last, so the datapath never sees a new count
    /// with stale group bitmaps.
    fn set_routing_meta(
        &mut self,
        count: u32,
        group_bitmaps: &RoutingGroupBitmaps,
    ) -> anyhow::Result<()>;
    fn add_domain_route(&mut self, domain: &str, outbound: OutboundIndex) -> anyhow::Result<()>;
    fn add_domain_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()>;
    fn add_source_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_dest_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_source_lpm_bitmap(
        &mut self,
        key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    fn add_mac_lpm_bitmap(&mut self, key: &LpmKey, bitmap: &DomainRouting) -> anyhow::Result<()> {
        let _ = key;
        let _ = bitmap;
        Ok(())
    }
    /// Push a resolved IP → DomainRouting bitmap into DOMAIN_ROUTING_MAP.
    /// Used by DNS snooping to enable eBPF direct routing for known domains.
    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let _ = ip_key;
        let _ = bitmap;
        Ok(())
    }
    /// Overwrite the DOMAIN_ROUTING_MAP entry for `ip_key` (16-byte IP key),
    /// replacing any bitmap left over from a previous rule generation.
    /// Used by the post-push domain-route rebuild; `add_domain_ip_bitmap`
    /// (OR semantics) would accumulate stale rule-index bits across reloads.
    fn set_domain_ip_bitmap(
        &mut self,
        _ip_key: &LpmKey,
        _bitmap: &DomainRouting,
    ) -> Result<(), DomainRouteWriteError> {
        Ok(())
    }
    /// Remove the DOMAIN_ROUTING_MAP entry for `ip_key` (16-byte IP key).
    /// Used by the domain-route rebuild for learned IPs whose domain no
    /// longer matches any domain rule under the current ruleset.
    fn remove_domain_ip_bitmap(&mut self, _ip_key: &LpmKey) -> Result<(), DomainRouteWriteError> {
        Ok(())
    }
    fn add_ip_route(&mut self, prefix: &str, outbound: OutboundIndex) -> anyhow::Result<()>;
    /// Fully reset all routing-related maps (MatchSets, rule count, domain
    /// routing, LPM tries).  NOT used by the routing push path: clearing
    /// first would zero ROUTING_META_MAP[0] and make the eBPF datapath drop
    /// every new flow until the push completes.  Kept for tests and
    /// full-reset scenarios only.
    fn clear_routes(&mut self) -> anyhow::Result<()>;
    /// Zero the ROUTING_MAP slots `[start..MAX_MATCH_SET_LEN)`.
    ///
    /// Post-commit cleanup for the two-phase routing push: it runs *after*
    /// `set_routing_meta(start, ...)` has switched the datapath, so the
    /// cleared slots are already inactive.  This removes stale MatchSets
    /// left over from a previous, longer ruleset.
    fn clear_routing_map_tail(&mut self, _start: u32) -> anyhow::Result<()> {
        Ok(())
    }
    /// Delete dest/source/MAC LPM entries whose raw key is not in `keep`.
    ///
    /// Post-commit cleanup for the two-phase routing push.  This replaces
    /// the former `clear_stale_lpm_entries` (zero-bitmap deletion): LPM
    /// values are now overwritten per key during the push, so stale state
    /// is exactly the set of keys the new ruleset no longer references.
    fn prune_lpm_entries(&mut self, _keep: &LpmKeepSet) -> anyhow::Result<()> {
        Ok(())
    }

    fn tcp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>>;
    fn tcp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()>;
    fn tcp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()>;
    fn udp_conn_state_lookup(&self, key: &TuplesKey) -> anyhow::Result<Option<ConnState>>;
    fn udp_conn_state_store(&mut self, key: &TuplesKey, state: &ConnState) -> anyhow::Result<()>;
    fn udp_conn_state_remove(&mut self, key: &TuplesKey) -> anyhow::Result<()>;

    fn redirect_track_lookup(&self, key: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>>;
    fn redirect_track_store(
        &mut self,
        key: &RedirectTuple,
        entry: &RedirectEntry,
    ) -> anyhow::Result<()>;
    fn redirect_track_remove(&mut self, key: &RedirectTuple) -> anyhow::Result<()>;

    /// Atomically look up and remove the handoff entry for `key`.
    ///
    /// The real backend prefers a single `BPF_MAP_LOOKUP_AND_DELETE_ELEM`
    /// syscall (kernel 4.20+) and falls back to lookup+delete on kernels
    /// without it.  The fallback is not atomic: the eBPF datapath may
    /// re-insert the key between the two syscalls, in which case the fresh
    /// entry is dropped and the flow is re-routed in userspace — harmless
    /// for a best-effort handoff hint.
    ///
    /// Takes `&self` so the per-connection hot path only needs a read lock
    /// on the backend: individual bpf() map operations are serialized by
    /// the kernel and no userspace backend state is touched.  The lock's
    /// only job is to keep the backend (and its map fds) alive against
    /// `cleanup()`, which takes the write lock.
    fn routing_handoff_take(&self, key: &TuplesKey) -> anyhow::Result<Option<RoutingHandoffEntry>>;

    fn cookie_pid_lookup(&self, cookie: u64) -> anyhow::Result<Option<PidPname>>;
    fn cookie_pid_store(&mut self, cookie: u64, entry: &PidPname) -> anyhow::Result<()>;
    fn cookie_pid_remove(&mut self, cookie: &u64) -> anyhow::Result<()>;

    fn set_outbound_alive(
        &mut self,
        outbound: u8,
        domain: u32,
        ipver: u32,
        alive: bool,
    ) -> anyhow::Result<()>;
    fn get_outbound_alive(&self, outbound: u8, domain: u32, ipver: u32) -> anyhow::Result<bool>;

    fn get_outbound_stats(&self, outbound: OutboundIndex) -> anyhow::Result<OutboundStats>;
    fn clear_outbound_stats(&mut self, outbound: OutboundIndex) -> anyhow::Result<()>;
    fn get_bpf_stats(&self, key: u32) -> anyhow::Result<Option<u64>>;

    // CONN_STATE_MAP is a plain hash: the datapath expires entries lazily on
    // hit, and the janitor sweeps it proactively with state-based timeouts
    // (mirroring the datapath's own expiry rules).  The kernel never evicts
    // on its own — silent LRU eviction could re-route or break live flows.

    /// Snapshot all (key, entry) pairs from CONN_STATE_MAP.
    /// Same consistency notes as [`Self::redirect_track_snapshot`].
    fn conn_state_snapshot(&self, out: &mut Vec<(TuplesKey, ConnState)>) -> anyhow::Result<()>;

    /// Remove multiple CONN_STATE_MAP entries (batched when supported).
    fn conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()>;

    /// Visit CONN_STATE_MAP entries in bounded chunks without accumulating
    /// the whole map (524K entries would otherwise spike memory on every
    /// sweep). Backends with `BPF_MAP_LOOKUP_BATCH` stream chunks straight
    /// from the kernel; others fall back to a snapshot chunked into visits
    /// (fine for small/mock maps).
    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let mut entries = Vec::new();
        self.conn_state_snapshot(&mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            visit(chunk);
        }
        Ok(())
    }

    /// Read the datapath's CONN_STATE_MAP occupancy counters:
    /// `(cumulative_inserts, cumulative_ebpf_deletes)`.  Userspace combines
    /// these with its own janitor-delete accounting to estimate live
    /// occupancy between sweeps (see `CONN_STATE_OCCUPANCY` in the eBPF
    /// maps).  Backends without the gauge return `(0, 0)`.
    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        Ok((0, 0))
    }

    /// Snapshot all (key, entry) pairs from REDIRECT_TRACK.
    ///
    /// Batched backends use `BPF_MAP_LOOKUP_BATCH` (one syscall per
    /// 128-entry chunk); others fall back to GET_NEXT_KEY + per-key
    /// lookups.  The snapshot is not atomic: entries inserted or removed
    /// concurrently may be skipped or returned twice.  The janitor
    /// tolerates this — missed entries are retried on the next round and
    /// duplicates are re-validated against the expiry predicate before
    /// deletion.
    fn redirect_track_snapshot(
        &self,
        out: &mut Vec<(RedirectTuple, RedirectEntry)>,
    ) -> anyhow::Result<()>;

    /// Snapshot all (cookie, entry) pairs from COOKIE_PID_MAP.
    /// Same consistency notes as [`Self::redirect_track_snapshot`].
    fn cookie_pid_snapshot(&self, out: &mut Vec<(u64, PidPname)>) -> anyhow::Result<()>;

    /// Snapshot all (key, entry) pairs from ROUTING_HANDOFF_MAP.
    /// Same consistency notes as [`Self::redirect_track_snapshot`].
    fn routing_handoff_snapshot(
        &self,
        out: &mut Vec<(TuplesKey, RoutingHandoffEntry)>,
    ) -> anyhow::Result<()>;

    /// Remove multiple REDIRECT_TRACK entries (one `BPF_MAP_DELETE_BATCH`
    /// syscall per 128-key chunk when supported, per-key deletes
    /// otherwise).  Keys already gone are ignored.
    fn redirect_track_remove_batch(&mut self, keys: &[RedirectTuple]) -> anyhow::Result<()>;
    /// Remove multiple COOKIE_PID_MAP entries (batched when supported).
    fn cookie_pid_remove_batch(&mut self, cookies: &[u64]) -> anyhow::Result<()>;
    /// Remove multiple ROUTING_HANDOFF_MAP entries (batched when supported).
    fn routing_handoff_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()>;

    fn conn_track_lookup(&self, tuple: &ConnTuple) -> anyhow::Result<Option<u32>>;
    fn conn_track_store(&mut self, tuple: &ConnTuple, outbound_idx: u32) -> anyhow::Result<()>;
    fn conn_track_remove(&mut self, tuple: &ConnTuple) -> anyhow::Result<()>;
}
