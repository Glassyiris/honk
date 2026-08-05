use async_trait::async_trait;
use aya::Ebpf;
use aya::EbpfLoader;

use honk_ebpf_common::*;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::{EbpfBackend, LpmKeepSet, maps, probe::BatchCapability};

/// Parse the running kernel version from /proc/version.
/// Returns `(major, minor, patch)` on success; `patch` defaults to 0
/// if the version string only carries two components.
fn kernel_version() -> Option<(u32, u32, u32)> {
    let version = std::fs::read_to_string("/proc/version").ok()?;
    let ver_str = version.split_whitespace().nth(2)?;
    let parts: Vec<&str> = ver_str.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse::<u32>().ok()?;
        let minor = parts[1].parse::<u32>().ok()?;
        let patch = parts
            .get(2)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        Some((major, minor, patch))
    } else {
        None
    }
}

/// Real eBPF backend backed by the aya library and kernel BPF maps.
///
/// Uses raw `bpf()` syscalls via `libc::syscall` for all map data-plane
/// operations.  This avoids aya's `Pod` trait bound, letting us use the
/// project's own `#[repr(C)]` types from the `no_std` `honk-ebpf-common`
/// crate without pulling aya into that crate.
pub struct RealEbpfBackend {
    bpf: Option<Ebpf>,
    pin_root: PathBuf,
    tproxy_port: u16,
    tproxy_mark: u32,
    // Keep TC links alive explicitly.  In some aya versions the link
    // stored inside the Ebpf object is dropped when the program reference goes
    // out of scope, so we hold the owned link here.
    lan_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    lan_egress_link: Option<aya::programs::tc::SchedClassifierLink>,
    /// WAN egress link: intercepts locally-generated traffic before it leaves
    /// the WAN interface so it can be routed through the proxy.
    wan_egress_link: Option<aya::programs::tc::SchedClassifierLink>,
    /// WAN ingress link: refreshes reverse-direction conntrack state for
    /// replies arriving from the WAN (direct-flow keepalive / close tracking).
    /// Skipped in single-homed setups, where lan_ingress already owns the
    /// shared interface's ingress hook.
    wan_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    /// Links installed by dynamic attach (startup bridge and bond slaves,
    /// extra startup interfaces, and the interface watcher), keyed by
    /// (ifindex, is_egress).  Keeping them here
    /// serves three purposes: the fd stays alive until `detach_hooks`, the
    /// watcher can drop dead links when a device vanishes, and the (ifindex,
    /// direction) pair dedupes retries after a partial failure.
    dynamic_links: Vec<(u32, bool, aya::programs::tc::SchedClassifierLink)>,
    /// cgroup sock_create/sock_release links (cookie→PID mapping, control-plane
    /// bypass). Held for the backend lifetime — dropping one detaches the
    /// program in the kernel.
    cgroup_sock_links: Vec<aya::programs::cgroup_sock::CgroupSockLink>,
    /// cgroup connect4/6 + sendmsg4/6 links; same lifetime rule as above.
    cgroup_sock_addr_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    dae0_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    dae0peer_ingress_link: Option<aya::programs::tc::SchedClassifierLink>,
    sk_lookup_link: Option<aya::programs::sk_lookup::SkLookupLink>,
    listeners_published: bool,
    /// Background task that flushes aya-log ring-buffer records.
    log_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Background task that drains EVENT_RINGBUF (DaeEvent) into the log.
    event_flush_handle: Option<tokio::task::JoinHandle<()>>,
    /// Runtime probe for `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (handoff take).
    cap_lookup_and_delete: BatchCapability,
    /// Runtime probe for `BPF_MAP_LOOKUP_BATCH` (janitor map scans).
    cap_lookup_batch: BatchCapability,
    /// Runtime probe for `BPF_MAP_DELETE_BATCH` (janitor batch deletes).
    cap_delete_batch: BatchCapability,
    /// Runtime probe for `BPF_MAP_UPDATE_BATCH` (routing rule pushes).
    cap_update_batch: BatchCapability,
}

/// Detect the first cgroup2 mount point from /proc/mounts.
/// Returns the mount path (e.g. /sys/fs/cgroup) if found.
fn detect_cgroup_path() -> anyhow::Result<String> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[2] == "cgroup2" {
            return Ok(fields[1].to_string());
        }
    }
    anyhow::bail!("cgroup2 not mounted")
}

impl RealEbpfBackend {
    #[inline(always)]
    fn bpf(&self) -> anyhow::Result<&Ebpf> {
        self.bpf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("eBPF object not loaded"))
    }

    #[inline(always)]
    fn bpf_mut(&mut self) -> anyhow::Result<&mut Ebpf> {
        self.bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("eBPF object not loaded"))
    }
}

mod attach;
mod events;
mod iface_watch;
mod syscall;

pub use events::*;
pub use iface_watch::IfaceWatcher;
pub use syscall::*;

fn conn_key(outbound: u8, domain: u32, ipver: u32) -> u32 {
    (outbound as u32)
        .wrapping_mul(6)
        .wrapping_add(domain.wrapping_mul(2))
        .wrapping_add(ipver)
}

/// Number of per-CPU slots the kernel allocates for each per-CPU map value
/// (the possible-CPUs count), parsed from sysfs.
fn possible_cpus() -> usize {
    let raw = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .unwrap_or_else(|_| "0".to_string());
    parse_possible_cpus(raw.trim())
}

/// Parse a `/sys/devices/system/cpu/possible` CPU list ("0-3,8-11") into a
/// CPU count.  Returns at least 1.
fn parse_possible_cpus(list: &str) -> usize {
    let mut n = 0usize;
    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
                    n += b.saturating_sub(a) + 1;
                }
            }
            None => {
                if part.parse::<usize>().is_ok() {
                    n += 1;
                }
            }
        }
    }
    n.max(1)
}

/// Sum `ncpu` native-endian u64 slots out of a per-CPU map value buffer.
/// The kernel pads each per-CPU slot to 8 bytes; u64 values need no extra
/// padding, so the slots are contiguous.
fn sum_percpu_u64(buf: &[u8], ncpu: usize) -> u64 {
    let mut total: u64 = 0;
    for i in 0..ncpu {
        if let Some(slot) = buf.get(i * 8..i * 8 + 8) {
            total = total.wrapping_add(u64::from_ne_bytes(slot.try_into().unwrap()));
        }
    }
    total
}

/// Chunked visitor used by the batch map scanners.
type ChunkVisitor<'a, K, V> = dyn FnMut(&[(K, V)]) -> bool + 'a;

impl RealEbpfBackend {
    fn hash_insert<K: Sized, V: Sized>(&mut self, map: &str, k: &K, v: &V) -> anyhow::Result<()> {
        bpf_hash_insert(self.bpf_mut()?, map, unsafe { as_bytes(k) }, unsafe {
            as_bytes(v)
        })
    }

    fn hash_lookup<K: Sized, V: Sized + Copy>(
        &self,
        map: &str,
        k: &K,
    ) -> anyhow::Result<Option<V>> {
        // Stack buffer — no per-call heap allocation.  The kernel writes
        // exactly size_of::<V>() bytes on a hit, so the value is fully
        // initialized before assume_init().
        let mut val = core::mem::MaybeUninit::<V>::uninit();
        let buf = unsafe {
            core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, core::mem::size_of::<V>())
        };
        match bpf_hash_lookup(self.bpf()?, map, unsafe { as_bytes(k) }, buf)? {
            Some(()) => Ok(Some(unsafe { val.assume_init() })),
            None => Ok(None),
        }
    }

    fn hash_remove<K: Sized>(&mut self, map: &str, k: &K) -> anyhow::Result<()> {
        bpf_hash_delete(self.bpf()?, map, unsafe { as_bytes(k) })
    }

    fn array_set<V: Sized>(&mut self, map: &str, idx: u32, v: &V) -> anyhow::Result<()> {
        bpf_hash_insert(self.bpf_mut()?, map, unsafe { as_bytes(&idx) }, unsafe {
            as_bytes(v)
        })
    }

    fn array_get<V: Sized + Copy>(&self, map: &str, idx: u32) -> anyhow::Result<Option<V>> {
        let mut val = core::mem::MaybeUninit::<V>::uninit();
        let buf = unsafe {
            core::slice::from_raw_parts_mut(val.as_mut_ptr() as *mut u8, core::mem::size_of::<V>())
        };
        match bpf_hash_lookup(self.bpf()?, map, unsafe { as_bytes(&idx) }, buf)? {
            Some(()) => Ok(Some(unsafe { val.assume_init() })),
            None => Ok(None),
        }
    }

    fn collect_keys(&self, map: &str, key_sz: usize) -> anyhow::Result<Vec<Vec<u8>>> {
        bpf_map_keys(self.bpf()?, map, key_sz)
    }

    /// Snapshot all entries of a hash-family map into typed (K, V) pairs.
    ///
    /// Prefers `BPF_MAP_LOOKUP_BATCH` (one syscall per 128-entry chunk);
    /// falls back to a GET_NEXT_KEY walk plus per-key lookups on kernels
    /// without batch support.  See [`EbpfBackend::redirect_track_snapshot`]
    /// for the snapshot consistency notes.
    fn map_snapshot<K: Copy, V: Copy>(
        &self,
        map: &str,
        out: &mut Vec<(K, V)>,
    ) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        if bpf_lookup_batch_scan(bpf, &self.cap_lookup_batch, map, out)? {
            return Ok(());
        }
        for kb in bpf_map_keys(bpf, map, core::mem::size_of::<K>())? {
            if kb.len() < core::mem::size_of::<K>() {
                continue;
            }
            let mut val = core::mem::MaybeUninit::<V>::uninit();
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    val.as_mut_ptr() as *mut u8,
                    core::mem::size_of::<V>(),
                )
            };
            if let Some(()) = bpf_hash_lookup(bpf, map, &kb, buf)? {
                let k = unsafe { core::ptr::read_unaligned(kb.as_ptr() as *const K) };
                out.push((k, unsafe { val.assume_init() }));
            }
        }
        Ok(())
    }

    /// Visit a hash-family map in chunks. Kernels with LOOKUP_BATCH stream
    /// directly from the map; the legacy fallback preserves compatibility.
    fn for_each_map_chunk<K: Copy, V: Copy>(
        &self,
        map: &str,
        chunk_size: usize,
        visit: &mut ChunkVisitor<'_, K, V>,
    ) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        if bpf_lookup_batch_scan_cb(bpf, &self.cap_lookup_batch, map, visit)? {
            return Ok(());
        }
        // Old kernels lack LOOKUP_BATCH. Avoid the snapshot helper here:
        // it would allocate one entry per map element and defeat the janitor
        // memory bound.
        let mut chunk = Vec::with_capacity(chunk_size.max(1));
        for kb in bpf_map_keys(bpf, map, core::mem::size_of::<K>())? {
            let mut value = core::mem::MaybeUninit::<V>::uninit();
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    value.as_mut_ptr() as *mut u8,
                    core::mem::size_of::<V>(),
                )
            };
            if bpf_hash_lookup(bpf, map, &kb, buf)?.is_some() {
                let key = unsafe { core::ptr::read_unaligned(kb.as_ptr() as *const K) };
                chunk.push((key, unsafe { value.assume_init() }));
                if chunk.len() == chunk_size.max(1) {
                    if !visit(&chunk) {
                        return Ok(());
                    }
                    chunk.clear();
                }
            }
        }
        if !chunk.is_empty() {
            visit(&chunk);
        }
        Ok(())
    }

    /// Delete multiple keys from a hash-family map, preferring
    /// `BPF_MAP_DELETE_BATCH` and falling back to per-key deletes.
    fn map_delete_batch<K: Copy>(&mut self, map: &str, keys: &[K]) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        if bpf_delete_batch(bpf, &self.cap_delete_batch, map, keys)? {
            return Ok(());
        }
        for k in keys {
            bpf_hash_delete(bpf, map, unsafe { as_bytes(k) })?;
        }
        Ok(())
    }

    /// Read the existing bitmap for `key` in `map`, OR it with `bm`, and write
    /// it back. Works for both HASH maps and LPM_TRIE maps because the syscall
    /// ABI is identical.
    fn or_update_bitmap(
        bpf: &mut Ebpf,
        map: &str,
        key: &LpmKey,
        bm: &DomainRouting,
    ) -> anyhow::Result<()> {
        Self::or_update_bitmap_raw(bpf, map, unsafe { as_bytes(key) }, bm)
    }

    /// Raw-byte variant of `or_update_bitmap` for callers whose key is not a
    /// full `LpmKey` (e.g. `DOMAIN_ROUTING_MAP` uses only the 16-byte IP data).
    fn or_update_bitmap_raw(
        bpf: &mut Ebpf,
        map: &str,
        key_bytes: &[u8],
        bm: &DomainRouting,
    ) -> anyhow::Result<()> {
        // For LPM trie maps, bpf_map_lookup_elem returns the *longest-prefix match*,
        // not the exact key. OR-ing that value into a new more-specific entry would
        // incorrectly inherit the less-specific rule. Use the supplied bitmap only.
        let mut cur = *bm;
        if !map.contains("LPM") {
            let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
            if let Some(()) = bpf_hash_lookup(bpf, map, key_bytes, &mut buf)? {
                let existing = unsafe { from_bytes::<DomainRouting>(&buf) };
                for i in 0..cur.bitmap.len() {
                    cur.bitmap[i] |= existing.bitmap[i];
                }
            }
        }
        bpf_hash_insert(bpf, map, key_bytes, unsafe { as_bytes(&cur) })
    }
}

#[async_trait]
impl EbpfBackend for RealEbpfBackend {
    fn attach_dynamic_interface(
        &mut self,
        ifname: &str,
        role: super::IfaceRole,
        single_homed: bool,
    ) -> anyhow::Result<super::DynamicHooks> {
        match role {
            super::IfaceRole::Lan => self.attach_lan(ifname, single_homed),
            super::IfaceRole::Wan => {
                self.attach_wan_egress(ifname)?;
                self.attach_wan_ingress(ifname)?;
                Ok(super::DynamicHooks {
                    ingress: true,
                    egress: true,
                })
            }
            super::IfaceRole::WanBondSlave => {
                self.attach_wan_egress(ifname)?;
                Ok(super::DynamicHooks {
                    ingress: false,
                    egress: true,
                })
            }
            super::IfaceRole::LanBridgeSlave | super::IfaceRole::LanBondSlave => {
                self.attach_slave(ifname, role)
            }
        }
    }

    fn forget_dynamic_interface(&mut self, ifindex: u32) {
        // Dropping the links detaches nothing (the device is already gone);
        // it only releases the fds and the dedup state.
        self.dynamic_links.retain(|(i, _, _)| *i != ifindex);
    }

    fn set_datapath_ready(&mut self, ready: bool) -> anyhow::Result<()> {
        if ready && !self.listeners_published {
            anyhow::bail!("listener socket generation is not fully published");
        }
        self.array_set("DATAPATH_STATE_MAP", 0, &u32::from(ready))
    }

    fn set_direct_offload(&mut self, enabled: bool) -> anyhow::Result<()> {
        let flags = if enabled {
            DATAPATH_FLAG_OFFLOAD_DIRECT
        } else {
            0
        };
        self.array_set("DATAPATH_FLAGS_MAP", 0, &flags)
    }

    fn set_param(&mut self, _key: ParamKey, _value: u32) -> anyhow::Result<()> {
        // The Rust eBPF code uses Global<DaeParam> instead of PARAM_MAP.
        // All parameters are set via inject() which writes to the global.
        // Individual set_param calls are no-ops for compatibility.
        Ok(())
    }
    fn get_param(&self, _key: ParamKey) -> anyhow::Result<Option<u32>> {
        Ok(None)
    }

    fn set_routing_rules(&mut self, generation: u32, rules: &[MatchSet]) -> anyhow::Result<()> {
        let base = generation * MAX_MATCH_SET_LEN;
        let keys: Vec<u32> = (base..base + rules.len() as u32).collect();
        if bpf_update_batch(
            self.bpf()?,
            &self.cap_update_batch,
            "ROUTING_MAP",
            &keys,
            rules,
        )? {
            return Ok(());
        }
        for (i, rule) in rules.iter().enumerate() {
            self.array_set("ROUTING_MAP", base + i as u32, rule)?;
        }
        Ok(())
    }

    fn active_routing_generation(&self) -> anyhow::Result<u32> {
        Ok(self
            .array_get::<u32>("ROUTING_META_MAP", ROUTING_META_ACTIVE_GENERATION_SLOT)?
            .unwrap_or(0))
    }
    fn publish_routing_generation(
        &mut self,
        generation: u32,
        count: u32,
        group_bitmaps: &RoutingGroupBitmaps,
    ) -> anyhow::Result<()> {
        for (group, words) in group_bitmaps.iter().enumerate() {
            for (word, value) in words.iter().enumerate() {
                let slot = routing_meta_bitmap_base(generation)
                    + (group * ROUTING_GROUP_BITMAP_WORDS + word) as u32;
                self.array_set("ROUTING_META_MAP", slot, value)?;
            }
        }
        self.array_set(
            "ROUTING_META_MAP",
            routing_meta_count_slot(generation),
            &count,
        )?;
        for (group, bitmap) in group_bitmaps.iter().enumerate() {
            let meta = RoutingGroupMeta {
                rule_count: count,
                bitmap: *bitmap,
            };
            self.array_set(
                "ROUTING_GROUP_META_MAP",
                routing_group_meta_index(generation, group as u32),
                &meta,
            )?;
        }
        self.array_set(
            "ROUTING_META_MAP",
            ROUTING_META_ACTIVE_GENERATION_SLOT,
            &generation,
        )
    }

    fn add_domain_route(&mut self, domain: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let h = maps::fnv1a_hash(domain.as_bytes());
        let key = LpmKey {
            prefix_len: (h >> 32) as u32,
            data: [(h as u32), ((h >> 32) as u32), 0, 0],
        };
        // DOMAIN_ROUTING_MAP key is the 16-byte IP data portion.
        let key_bytes = unsafe { as_bytes(&key.data) };
        let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
        let mut cur: DomainRouting =
            match bpf_hash_lookup(self.bpf()?, "DOMAIN_ROUTING_MAP", key_bytes, &mut buf)? {
                Some(()) => unsafe { from_bytes::<DomainRouting>(&buf) },
                None => DomainRouting::default(),
            };
        let ob = outbound as u32;
        let wi = (ob / 32) as usize;
        if wi < ROUTING_BITMAP_WORDS_PER_GENERATION {
            let generation = self.active_routing_generation()? as usize;
            cur.bitmap[generation * ROUTING_BITMAP_WORDS_PER_GENERATION + wi] |= 1 << (ob % 32);
        }
        bpf_hash_insert(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", key_bytes, unsafe {
            as_bytes(&cur)
        })
    }

    fn add_domain_routing_bitmap(
        &mut self,
        key: &LpmKey,
        bm: &DomainRouting,
    ) -> anyhow::Result<()> {
        let bitmap = bm.for_generation(self.active_routing_generation()?);
        Self::or_update_bitmap(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", key, &bitmap)
    }

    fn add_dest_lpm_bitmap(&mut self, key: &LpmKey, bm: &DomainRouting) -> anyhow::Result<()> {
        bpf_hash_insert(
            self.bpf_mut()?,
            "DEST_LPM_ROUTING_MAP",
            unsafe { as_bytes(key) },
            unsafe { as_bytes(bm) },
        )
    }

    fn add_source_lpm_bitmap(&mut self, key: &LpmKey, bm: &DomainRouting) -> anyhow::Result<()> {
        bpf_hash_insert(
            self.bpf_mut()?,
            "SOURCE_LPM_ROUTING_MAP",
            unsafe { as_bytes(key) },
            unsafe { as_bytes(bm) },
        )
    }

    fn add_mac_lpm_bitmap(&mut self, key: &LpmKey, bm: &DomainRouting) -> anyhow::Result<()> {
        bpf_hash_insert(
            self.bpf_mut()?,
            "MAC_LPM_ROUTING_MAP",
            unsafe { as_bytes(key) },
            unsafe { as_bytes(bm) },
        )
    }

    fn add_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> anyhow::Result<()> {
        let bitmap = bitmap.for_generation(self.active_routing_generation()?);
        let key_bytes = unsafe { as_bytes(&ip_key.data) };
        Self::or_update_bitmap_raw(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", key_bytes, &bitmap)
    }

    fn set_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
        bitmap: &DomainRouting,
    ) -> Result<(), super::DomainRouteWriteError> {
        let generation = self
            .active_routing_generation()
            .map_err(super::DomainRouteWriteError::Other)?;
        let key_bytes = unsafe { as_bytes(&ip_key.data) };
        let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
        let mut current = match bpf_hash_lookup(
            self.bpf().map_err(super::DomainRouteWriteError::Other)?,
            "DOMAIN_ROUTING_MAP",
            key_bytes,
            &mut buf,
        )
        .map_err(super::DomainRouteWriteError::Other)?
        {
            Some(()) => unsafe { from_bytes::<DomainRouting>(&buf) },
            None => DomainRouting::default(),
        };
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        current.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
            .copy_from_slice(&bitmap.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
        let bpf = self
            .bpf_mut()
            .map_err(super::DomainRouteWriteError::Other)?;
        bpf_hash_insert_domain(bpf, "DOMAIN_ROUTING_MAP", key_bytes, unsafe {
            as_bytes(&current)
        })
    }

    fn remove_domain_ip_bitmap(
        &mut self,
        ip_key: &LpmKey,
    ) -> Result<(), super::DomainRouteWriteError> {
        let generation = self
            .active_routing_generation()
            .map_err(super::DomainRouteWriteError::Other)?;
        let key_bytes = unsafe { as_bytes(&ip_key.data) };
        let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
        let Some(()) = bpf_hash_lookup(
            self.bpf().map_err(super::DomainRouteWriteError::Other)?,
            "DOMAIN_ROUTING_MAP",
            key_bytes,
            &mut buf,
        )
        .map_err(super::DomainRouteWriteError::Other)?
        else {
            return Ok(());
        };
        let mut bitmap = unsafe { from_bytes::<DomainRouting>(&buf) };
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
        let bpf = self
            .bpf_mut()
            .map_err(super::DomainRouteWriteError::Other)?;
        if bitmap.bitmap.iter().all(|word| *word == 0) {
            bpf_hash_delete(bpf, "DOMAIN_ROUTING_MAP", key_bytes)
                .map_err(super::DomainRouteWriteError::Other)
        } else {
            bpf_hash_insert_domain(bpf, "DOMAIN_ROUTING_MAP", key_bytes, unsafe {
                as_bytes(&bitmap)
            })
        }
    }

    fn stage_domain_routing_generation(
        &mut self,
        generation: u32,
        entries: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            generation < ROUTING_BITMAP_GENERATIONS as u32,
            "invalid routing generation {generation}"
        );
        let offset = generation as usize * ROUTING_BITMAP_WORDS_PER_GENERATION;
        let keys = self.collect_keys("DOMAIN_ROUTING_MAP", core::mem::size_of::<[u32; 4]>())?;
        for key in keys {
            let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
            let Some(()) = bpf_hash_lookup(self.bpf()?, "DOMAIN_ROUTING_MAP", &key, &mut buf)?
            else {
                continue;
            };
            let mut bitmap = unsafe { from_bytes::<DomainRouting>(&buf) };
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION].fill(0);
            bpf_hash_insert(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", &key, unsafe {
                as_bytes(&bitmap)
            })?;
        }
        for (key, logical) in entries {
            let key_bytes = unsafe { as_bytes(&key.data) };
            let mut buf = vec![0u8; core::mem::size_of::<DomainRouting>()];
            let mut bitmap =
                match bpf_hash_lookup(self.bpf()?, "DOMAIN_ROUTING_MAP", key_bytes, &mut buf)? {
                    Some(()) => unsafe { from_bytes::<DomainRouting>(&buf) },
                    None => DomainRouting::default(),
                };
            bitmap.bitmap[offset..offset + ROUTING_BITMAP_WORDS_PER_GENERATION]
                .copy_from_slice(&logical.bitmap[..ROUTING_BITMAP_WORDS_PER_GENERATION]);
            bpf_hash_insert(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", key_bytes, unsafe {
                as_bytes(&bitmap)
            })?;
        }
        Ok(())
    }

    fn add_ip_route(&mut self, prefix: &str, outbound: OutboundIndex) -> anyhow::Result<()> {
        let lk = maps::cidr_to_lpm_key(prefix)?;
        let mut routing = DomainRouting::default();
        let ob = outbound as u32;
        let wi = (ob / 32) as usize;
        if wi < ROUTING_BITMAP_WORDS_PER_GENERATION {
            routing.bitmap[wi] = 1 << (ob % 32);
        }
        let routing = routing.for_generation(self.active_routing_generation()?);
        let key_bytes = unsafe { as_bytes(&lk.data) };
        bpf_hash_insert(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", key_bytes, unsafe {
            as_bytes(&routing)
        })
    }

    fn clear_routes(&mut self) -> anyhow::Result<()> {
        let d = MatchSet::default();
        for i in 0..ROUTING_MAP_LEN as u32 {
            let _ = self.array_set("ROUTING_MAP", i, &d);
        }
        for i in 0..ROUTING_META_MAP_LEN as u32 {
            let _ = self.array_set("ROUTING_META_MAP", i, &0u32);
        }
        for i in 0..ROUTING_GROUP_META_MAP_LEN as u32 {
            let _ = self.array_set("ROUTING_GROUP_META_MAP", i, &RoutingGroupMeta::default());
        }
        // DOMAIN_ROUTING_MAP is HashMap<[__be32; 4], DomainRouting>: the key
        // is the 16-byte IP data alone, NOT the 20-byte LpmKey.
        for kb in self
            .collect_keys("DOMAIN_ROUTING_MAP", core::mem::size_of::<[u32; 4]>())
            .unwrap_or_default()
        {
            let _ = bpf_hash_delete(self.bpf_mut()?, "DOMAIN_ROUTING_MAP", &kb);
        }
        // Clear per-match-type LPM tries so stale prefixes from the previous
        // ruleset do not influence the new one.
        for map_name in &[
            "DEST_LPM_ROUTING_MAP",
            "SOURCE_LPM_ROUTING_MAP",
            "MAC_LPM_ROUTING_MAP",
        ] {
            for kb in self
                .collect_keys(map_name, core::mem::size_of::<LpmKey>())
                .unwrap_or_default()
            {
                let _ = bpf_hash_delete(self.bpf_mut()?, map_name, &kb);
            }
        }
        Ok(())
    }

    fn prune_lpm_entries(&mut self, keep: &LpmKeepSet) -> anyhow::Result<()> {
        // Keep every key referenced by the active or staged generation.
        // A key retired by the latest switch remains for one transition so a
        // packet that already read the old selector cannot observe its LPM
        // value disappear mid-evaluation.
        for (map_name, keys) in [
            ("DEST_LPM_ROUTING_MAP", &keep.dest),
            ("SOURCE_LPM_ROUTING_MAP", &keep.source),
            ("MAC_LPM_ROUTING_MAP", &keep.mac),
        ] {
            for kb in self.collect_keys(map_name, core::mem::size_of::<LpmKey>())? {
                let mut raw = [0u8; 20];
                if kb.len() >= 20 {
                    raw.copy_from_slice(&kb[..20]);
                }
                if !keys.contains(&raw) {
                    bpf_hash_delete(self.bpf_mut()?, map_name, &kb)?;
                }
            }
        }
        Ok(())
    }

    fn tcp_conn_state_lookup(&self, k: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        self.hash_lookup("CONN_STATE_MAP", k)
    }
    fn tcp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.hash_insert("CONN_STATE_MAP", k, s)
    }
    fn tcp_conn_state_remove(&mut self, k: &TuplesKey) -> anyhow::Result<()> {
        self.hash_remove("CONN_STATE_MAP", k)
    }

    fn udp_conn_state_lookup(&self, k: &TuplesKey) -> anyhow::Result<Option<ConnState>> {
        self.hash_lookup("CONN_STATE_MAP", k)
    }
    fn udp_conn_state_store(&mut self, k: &TuplesKey, s: &ConnState) -> anyhow::Result<()> {
        self.hash_insert("CONN_STATE_MAP", k, s)
    }
    fn udp_conn_state_remove(&mut self, k: &TuplesKey) -> anyhow::Result<()> {
        self.hash_remove("CONN_STATE_MAP", k)
    }

    fn redirect_track_lookup(&self, k: &RedirectTuple) -> anyhow::Result<Option<RedirectEntry>> {
        self.hash_lookup("REDIRECT_TRACK", k)
    }
    fn redirect_track_store(&mut self, k: &RedirectTuple, e: &RedirectEntry) -> anyhow::Result<()> {
        self.hash_insert("REDIRECT_TRACK", k, e)
    }
    fn redirect_track_remove(&mut self, k: &RedirectTuple) -> anyhow::Result<()> {
        self.hash_remove("REDIRECT_TRACK", k)
    }

    fn routing_handoff_take(&self, k: &TuplesKey) -> anyhow::Result<Option<RoutingHandoffEntry>> {
        let bpf = self.bpf()?;
        let key = unsafe { as_bytes(k) };
        let mut val = core::mem::MaybeUninit::<RoutingHandoffEntry>::uninit();
        let buf = unsafe {
            core::slice::from_raw_parts_mut(
                val.as_mut_ptr() as *mut u8,
                core::mem::size_of::<RoutingHandoffEntry>(),
            )
        };
        // Fast path: a single BPF_MAP_LOOKUP_AND_DELETE_ELEM syscall.
        match bpf_lookup_and_delete(
            bpf,
            &self.cap_lookup_and_delete,
            "ROUTING_HANDOFF_MAP",
            key,
            buf,
        )? {
            Some(true) => return Ok(Some(unsafe { val.assume_init() })),
            Some(false) => return Ok(None),
            None => {}
        }
        // Fallback for kernels without LOOKUP_AND_DELETE_ELEM (< 4.20):
        // lookup + delete in two syscalls.  Not atomic — the datapath may
        // re-insert between the calls, dropping a fresh entry; the flow is
        // then re-routed in userspace, which is harmless.
        let entry: Option<RoutingHandoffEntry> = self.hash_lookup("ROUTING_HANDOFF_MAP", k)?;
        if entry.is_some() {
            bpf_hash_delete(bpf, "ROUTING_HANDOFF_MAP", key)?;
        }
        Ok(entry)
    }

    fn cookie_pid_lookup(&self, c: u64) -> anyhow::Result<Option<PidPname>> {
        self.hash_lookup("COOKIE_PID_MAP", &c)
    }
    fn cookie_pid_store(&mut self, c: u64, e: &PidPname) -> anyhow::Result<()> {
        self.hash_insert("COOKIE_PID_MAP", &c, e)
    }
    fn cookie_pid_remove(&mut self, c: &u64) -> anyhow::Result<()> {
        self.hash_remove("COOKIE_PID_MAP", c)
    }

    fn redirect_track_snapshot(
        &self,
        out: &mut Vec<(RedirectTuple, RedirectEntry)>,
    ) -> anyhow::Result<()> {
        self.map_snapshot("REDIRECT_TRACK", out)
    }

    fn redirect_track_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::RedirectTrackChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("REDIRECT_TRACK", chunk_size, visit)
    }

    fn cookie_pid_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::CookiePidChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("COOKIE_PID_MAP", chunk_size, visit)
    }

    fn routing_handoff_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::RoutingHandoffChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        self.for_each_map_chunk("ROUTING_HANDOFF_MAP", chunk_size, visit)
    }

    fn conn_state_snapshot(&self, out: &mut Vec<(TuplesKey, ConnState)>) -> anyhow::Result<()> {
        self.map_snapshot("CONN_STATE_MAP", out)
    }

    fn conn_state_for_each_chunk(
        &self,
        chunk_size: usize,
        visit: &mut crate::ebpf::ConnStateChunkVisitor<'_>,
    ) -> anyhow::Result<()> {
        let bpf = self.bpf()?;
        // Stream chunks straight from the kernel when LOOKUP_BATCH is
        // available; otherwise fall back to the snapshot-based default.
        if syscall::bpf_lookup_batch_scan_cb(bpf, &self.cap_lookup_batch, "CONN_STATE_MAP", visit)?
        {
            return Ok(());
        }
        let mut entries = Vec::new();
        self.map_snapshot("CONN_STATE_MAP", &mut entries)?;
        for chunk in entries.chunks(chunk_size.max(1)) {
            if !visit(chunk) {
                break;
            }
        }
        Ok(())
    }

    fn conn_state_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        self.map_delete_batch("CONN_STATE_MAP", keys)
    }

    fn conn_state_occupancy(&self) -> anyhow::Result<(u64, u64)> {
        let bpf = self.bpf()?;
        // Objects from an older build (supplied via --bpf-object) may not
        // carry the gauge; report zeros instead of failing.
        if bpf.map("CONN_STATE_OCCUPANCY").is_none() {
            return Ok((0, 0));
        }
        let ncpu = possible_cpus();
        let mut slots = [0u64; 2];
        for (i, slot) in [
            honk_ebpf_common::conn::OCCUPANCY_INSERTS,
            honk_ebpf_common::conn::OCCUPANCY_EBPF_DELETES,
        ]
        .into_iter()
        .enumerate()
        {
            let mut buf = vec![0u8; ncpu * 8];
            if let Some(()) = bpf_hash_lookup(
                bpf,
                "CONN_STATE_OCCUPANCY",
                unsafe { as_bytes(&slot) },
                &mut buf,
            )? {
                slots[i] = sum_percpu_u64(&buf, ncpu);
            }
        }
        Ok((slots[0], slots[1]))
    }

    fn cookie_pid_snapshot(&self, out: &mut Vec<(u64, PidPname)>) -> anyhow::Result<()> {
        self.map_snapshot("COOKIE_PID_MAP", out)
    }

    fn routing_handoff_snapshot(
        &self,
        out: &mut Vec<(TuplesKey, RoutingHandoffEntry)>,
    ) -> anyhow::Result<()> {
        self.map_snapshot("ROUTING_HANDOFF_MAP", out)
    }

    fn redirect_track_remove_batch(&mut self, keys: &[RedirectTuple]) -> anyhow::Result<()> {
        self.map_delete_batch("REDIRECT_TRACK", keys)
    }

    fn cookie_pid_remove_batch(&mut self, cookies: &[u64]) -> anyhow::Result<()> {
        self.map_delete_batch("COOKIE_PID_MAP", cookies)
    }

    fn routing_handoff_remove_batch(&mut self, keys: &[TuplesKey]) -> anyhow::Result<()> {
        self.map_delete_batch("ROUTING_HANDOFF_MAP", keys)
    }

    fn conn_state_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, ConnState)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, ConnState>("CONN_STATE_MAP", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove("CONN_STATE_MAP", key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn redirect_track_remove_if_unchanged(
        &mut self,
        entries: &[(RedirectTuple, RedirectEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, RedirectEntry>("REDIRECT_TRACK", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove("REDIRECT_TRACK", key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn cookie_pid_remove_if_unchanged(
        &mut self,
        entries: &[(u64, PidPname)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (cookie, scanned) in entries {
            if self
                .hash_lookup::<_, PidPname>("COOKIE_PID_MAP", cookie)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove("COOKIE_PID_MAP", cookie)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn routing_handoff_remove_if_unchanged(
        &mut self,
        entries: &[(TuplesKey, RoutingHandoffEntry)],
        expired_before_ns: u64,
    ) -> anyhow::Result<u64> {
        let mut removed = 0;
        for (key, scanned) in entries {
            if self
                .hash_lookup::<_, RoutingHandoffEntry>("ROUTING_HANDOFF_MAP", key)?
                .is_some_and(|current| {
                    current.last_seen_ns == scanned.last_seen_ns
                        && current.last_seen_ns <= expired_before_ns
                })
            {
                self.hash_remove("ROUTING_HANDOFF_MAP", key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn set_outbound_alive(&mut self, o: u8, d: u32, ip: u32, alive: bool) -> anyhow::Result<()> {
        let k = conn_key(o, d, ip);
        let v: u64 = if alive { 1 } else { 0 };
        bpf_hash_insert(
            self.bpf_mut()?,
            "OUTBOUND_CONNECTIVITY_MAP",
            unsafe { as_bytes(&k) },
            unsafe { as_bytes(&v) },
        )
    }

    fn get_outbound_alive(&self, o: u8, d: u32, ip: u32) -> anyhow::Result<bool> {
        let k = conn_key(o, d, ip);
        let mut buf = [0u8; 8];
        match bpf_hash_lookup(
            self.bpf()?,
            "OUTBOUND_CONNECTIVITY_MAP",
            unsafe { as_bytes(&k) },
            &mut buf,
        )? {
            Some(()) => Ok(u64::from_ne_bytes(buf) != 0),
            None => Ok(false),
        }
    }

    fn get_outbound_stats(&self, o: OutboundIndex) -> anyhow::Result<OutboundStats> {
        let bpf = self.bpf()?;
        // Objects from an older build (supplied via --bpf-object) may not
        // carry the OUTBOUND_STATS map; report zeros instead of failing.
        if bpf.map("OUTBOUND_STATS").is_none() {
            return Ok(OutboundStats::default());
        }
        let o = o as u8;
        let mut stats = OutboundStats::default();
        let ncpu = possible_cpus();
        let mut buf = vec![0u8; ncpu * core::mem::size_of::<OutboundStatsCounters>()];
        let idx = OutboundStatsCounters::for_outbound(o);
        if let Some(()) =
            bpf_hash_lookup(bpf, "OUTBOUND_STATS", unsafe { as_bytes(&idx) }, &mut buf)?
        {
            let (cpus, _) = buf.as_chunks::<{ core::mem::size_of::<OutboundStatsCounters>() }>();
            for cpu in cpus {
                let counters = unsafe {
                    core::ptr::read_unaligned(cpu.as_ptr().cast::<OutboundStatsCounters>())
                };
                stats.tx_packets = stats.tx_packets.wrapping_add(counters.tx_packets);
                stats.tx_bytes = stats.tx_bytes.wrapping_add(counters.tx_bytes);
                stats.rx_packets = stats.rx_packets.wrapping_add(counters.rx_packets);
                stats.rx_bytes = stats.rx_bytes.wrapping_add(counters.rx_bytes);
            }
        }
        Ok(stats)
    }
    fn clear_outbound_stats(&mut self, o: OutboundIndex) -> anyhow::Result<()> {
        if self.bpf()?.map("OUTBOUND_STATS").is_none() {
            return Ok(());
        }
        let zeros = vec![0u8; possible_cpus() * core::mem::size_of::<OutboundStatsCounters>()];
        let idx = OutboundStatsCounters::for_outbound(o as u8);
        bpf_hash_insert(
            self.bpf_mut()?,
            "OUTBOUND_STATS",
            unsafe { as_bytes(&idx) },
            &zeros,
        )?;
        Ok(())
    }
    fn get_bpf_stats(&self, k: u32) -> anyhow::Result<Option<u64>> {
        self.array_get("BPF_STATS_MAP", k)
    }

    fn conn_track_lookup(&self, _: &ConnTuple) -> anyhow::Result<Option<u32>> {
        Ok(None)
    }
    fn conn_track_store(&mut self, _: &ConnTuple, _: u32) -> anyhow::Result<()> {
        Ok(())
    }
    fn conn_track_remove(&mut self, _: &ConnTuple) -> anyhow::Result<()> {
        Ok(())
    }

    fn detach_hooks(&mut self) -> anyhow::Result<()> {
        // Drop all TC links, which detaches the eBPF programs from the
        // network interfaces and restores normal packet processing.
        info!(
            "Detaching BPF hooks (lan_ingress, lan_egress, wan_egress, wan_ingress, bond slaves, bridge slaves, cgroup, dae0, sk_lookup)"
        );
        self.lan_ingress_link = None;
        self.lan_egress_link = None;
        self.wan_egress_link = None;
        self.wan_ingress_link = None;
        self.dynamic_links.clear();
        self.cgroup_sock_links.clear();
        self.cgroup_sock_addr_links.clear();
        self.dae0_ingress_link = None;
        self.dae0peer_ingress_link = None;
        self.sk_lookup_link = None;
        info!("BPF hooks detached, network restored");
        Ok(())
    }

    fn eject(&mut self) {
        let _ = std::fs::remove_dir_all(&self.pin_root);
    }

    fn inject(&mut self, p: &super::BpfLoadParams) -> anyhow::Result<()> {
        // The Rust eBPF code uses Global<DaeParam> (.rodata).
        // Globals must be set via EbpfLoader::override_global() before load().
        // For now, store local fields; the global defaults (all zeros) suffice
        // for basic operation. Full parameter injection requires restructuring
        // the load flow to set globals via the loader.
        self.tproxy_port = p.tproxy_port;
        self.tproxy_mark = p.tproxy_mark;
        info!(
            "PARAM defaults in effect (tproxy_port={}, tproxy_mark=0x{:x})",
            p.tproxy_port, p.tproxy_mark
        );
        Ok(())
    }

    fn attach_dae0_programs(&mut self) -> anyhow::Result<()> {
        // Ensure clsact qdisc exists on dae0 and dae0peer before attaching the
        // TC programs; otherwise netlink returns EINVAL.
        for iface in &["dae0", "dae0peer"] {
            if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface)
                && !e.to_string().contains("File exists")
            {
                warn!("failed to add clsact qdisc to {}: {}", iface, e);
            }
        }

        // dae0_ingress runs on dae0 (host namespace) and rewrites reply traffic
        // back to the original LAN interface.
        match Self::attach_tc(self.bpf_mut()?, "dae0_ingress", "dae0") {
            Ok(id) => {
                let p: &mut aya::programs::SchedClassifier = self
                    .bpf_mut()?
                    .program_mut("dae0_ingress")
                    .ok_or_else(|| anyhow::anyhow!("dae0_ingress program disappeared"))?
                    .try_into()?;
                self.dae0_ingress_link = Some(
                    p.take_link(id)
                        .map_err(|e| anyhow::anyhow!("failed to take dae0_ingress link: {}", e))?,
                );
                info!("dae0_ingress attached and link held");
            }
            Err(e) => {
                warn!("dae0_ingress attach failed (non-fatal): {}", e);
            }
        }

        Ok(())
    }

    fn attach_dae0peer_ingress(&mut self) -> anyhow::Result<()> {
        // dae0peer lives in the daens namespace; enter it with a scoped
        // `with_daens_netns` switch for the attach (the process otherwise
        // stays in the host netns).  The netlink sockets used by
        // qdisc_add_clsact/attach_tc resolve interface names in the netns
        // they are created in, so both must run inside daens.  The link
        // handle persists after switching back to the host netns.
        crate::with_daens_netns("attach dae0peer_ingress", move || {
            if let Err(e) = aya::programs::tc::qdisc_add_clsact("dae0peer")
                && !e.to_string().contains("File exists")
            {
                warn!("failed to add clsact qdisc to dae0peer: {}", e);
            }

            match Self::attach_tc(self.bpf_mut()?, "dae0peer_ingress", "dae0peer") {
                Ok(id) => {
                    let p: &mut aya::programs::SchedClassifier = self
                        .bpf_mut()?
                        .program_mut("dae0peer_ingress")
                        .ok_or_else(|| anyhow::anyhow!("dae0peer_ingress program disappeared"))?
                        .try_into()?;
                    self.dae0peer_ingress_link = Some(p.take_link(id).map_err(|e| {
                        anyhow::anyhow!("failed to take dae0peer_ingress link: {}", e)
                    })?);
                    info!("dae0peer_ingress attached and link held");
                }
                Err(e) => {
                    warn!("dae0peer_ingress attach failed (non-fatal): {}", e);
                }
            }

            Ok(())
        })
    }

    fn attach_sk_lookup(&mut self) -> anyhow::Result<()> {
        // The sk_lookup program attaches to the daens namespace; run the
        // whole attach inside a scoped `with_daens_netns` switch (the process
        // otherwise stays in the host netns).  The TPROXY listener sockets
        // live in daens too (bound there via a scoped switch at control-plane
        // startup), so proxy-bound packets are assigned to them in their own
        // namespace.  The link handle persists after switching back.
        crate::with_daens_netns("attach tproxy_sk_lookup", move || {
            // FD-owned namespace handle (dup so the OnceLock FD stays put).
            let netns = crate::daens_fd()?
                .try_clone()
                .map_err(|e| anyhow::anyhow!("dup daens fd: {e}"))?;
            let p: &mut aya::programs::SkLookup = self
                .bpf_mut()?
                .program_mut("tproxy_sk_lookup")
                .ok_or_else(|| anyhow::anyhow!("tproxy_sk_lookup program not found"))?
                .try_into()?;
            p.load()
                .map_err(|e| anyhow::anyhow!("load tproxy_sk_lookup: {}", e))?;
            let id = p
                .attach(&netns)
                .map_err(|e| anyhow::anyhow!("attach tproxy_sk_lookup: {}", e))?;
            self.sk_lookup_link = Some(
                p.take_link(id)
                    .map_err(|e| anyhow::anyhow!("take tproxy_sk_lookup link: {}", e))?,
            );
            info!("tproxy_sk_lookup attached to daens namespace");
            Ok(())
        })
    }

    fn publish_listener_sockets(
        &mut self,
        tcp4_fd: RawFd,
        tcp6_fd: RawFd,
        udp4_fds: &[RawFd],
        udp6_fds: &[RawFd],
    ) -> anyhow::Result<()> {
        self.listeners_published = false;
        // Publish the listener FDs so the sk_lookup/dae0peer programs can
        // `bpf_sk_assign` proxy-bound flows. Key mapping: 0=tcp4, 1=tcp6,
        // 2..=UDP4 group, 2+4..=UDP6 group (see sk_lookup.rs). The programs
        // hash the flow tuple into the group, so each socket must sit at its
        // exact slot.
        let mut entries = vec![(0u32, tcp4_fd), (1u32, tcp6_fd)];
        for (i, fd) in udp4_fds.iter().enumerate() {
            entries.push((2 + i as u32, *fd));
        }
        for (i, fd) in udp6_fds.iter().enumerate() {
            entries.push((6 + i as u32, *fd));
        }
        for (key, fd) in entries {
            // SockMap expects a 4-byte socket FD as the value, not an 8-byte pointer.
            let fd_u32 = fd as u32;
            bpf_hash_insert(
                self.bpf_mut()?,
                "LISTEN_SOCKET_MAP",
                unsafe { as_bytes(&key) },
                unsafe { as_bytes(&fd_u32) },
            )
            .map_err(|e| anyhow::anyhow!("listen_socket_map update key={}: {}", key, e))?;
            info!(
                "Published listener fd {} to LISTEN_SOCKET_MAP key {}",
                fd, key
            );
        }
        self.listeners_published = true;
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        // Detach eBPF programs immediately to restore network connectivity.
        self.detach_hooks()?;

        // Stop the aya-log flush task before dropping the Ebpf object.
        if let Some(h) = self.log_flush_handle.take() {
            h.abort();
            let _ = h.await;
        }
        // Stop the DaeEvent ringbuf consumer as well; it owns the
        // EVENT_RINGBUF MapData taken out of the Ebpf object.
        if let Some(h) = self.event_flush_handle.take() {
            h.abort();
            let _ = h.await;
        }

        // Drop the Ebpf object before removing the pin directory so that map fds
        // are closed and the pinned files are no longer busy.
        if let Some(bpf) = self.bpf.take() {
            drop(bpf);
        }

        // Give the kernel a moment to release references to the pinned maps
        // before we try to remove the pin directory.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Clean up the BPF pin directory (maps, programs).  If the kernel still
        // holds a reference this is non-fatal; the next cleanup script run will
        // remove the leftovers, so log it at debug level to keep the run clean.
        if let Err(e) = std::fs::remove_dir_all(&self.pin_root) {
            if e.raw_os_error() == Some(libc::EBUSY) {
                debug!(
                    "BPF pin dir still busy after teardown, will be cleaned up later: {}",
                    e
                );
            } else {
                warn!("cleanup pin dir: {}", e);
            }
        }
        Ok(())
    }
}

impl Drop for RealEbpfBackend {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.pin_root);
    }
}

#[cfg(test)]
mod tests;
