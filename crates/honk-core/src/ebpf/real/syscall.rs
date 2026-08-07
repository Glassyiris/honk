//! Raw extensions for BPF map commands that Aya 0.14 does not expose.
//!
//! Ordinary map reads, writes, deletes, iteration, and per-CPU access use
//! Aya's typed map APIs in `real::mod`. This module is limited to atomic
//! lookup-and-delete and Linux batch commands, while retaining Aya `Pod`
//! bounds so callers cannot pass arbitrary wire layouts.

use super::*;

use aya::Pod;
use aya_obj::generated::bpf_attr;
use aya_obj::generated::bpf_cmd::*;
use std::ffi::c_long;
use std::mem::MaybeUninit;

const ENOENT: c_long = libc::ENOENT as c_long;
pub const BPF_BATCH_CHUNK: usize = 128;

pub enum LookupAndDelete<V> {
    Unsupported,
    Missing,
    Value(V),
}

pub type BatchVisitor<'a, K, V> = dyn FnMut(&[(K, V)]) -> bool + 'a;

pub(super) unsafe fn bpf_syscall(cmd: c_long, attr: &mut bpf_attr) -> Result<(), c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut bpf_attr,
            core::mem::size_of::<bpf_attr>(),
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO) as c_long)
    } else {
        Ok(())
    }
}

fn map_raw_fd(map: &aya::maps::Map) -> RawFd {
    use aya::maps::Map;
    let data: &aya::maps::MapData = match map {
        Map::Array(d)
        | Map::ArrayOfMaps(d)
        | Map::BloomFilter(d)
        | Map::CgroupArray(d)
        | Map::CgroupStorage(d)
        | Map::CgrpStorage(d)
        | Map::CpuMap(d)
        | Map::DevMap(d)
        | Map::DevMapHash(d)
        | Map::HashMap(d)
        | Map::HashOfMaps(d)
        | Map::InodeStorage(d)
        | Map::LpmTrie(d)
        | Map::LruHashMap(d)
        | Map::PerCpuArray(d)
        | Map::PerCpuCgroupStorage(d)
        | Map::PerCpuHashMap(d)
        | Map::PerCpuLruHashMap(d)
        | Map::PerfEventArray(d)
        | Map::ProgramArray(d)
        | Map::Queue(d)
        | Map::ReusePortSockArray(d)
        | Map::RingBuf(d)
        | Map::SockHash(d)
        | Map::SockMap(d)
        | Map::SkStorage(d)
        | Map::Stack(d)
        | Map::StackTraceMap(d)
        | Map::Unsupported(d)
        | Map::XskMap(d) => d,
    };
    data.fd().as_fd().as_raw_fd()
}

fn map_fd(bpf: &Ebpf, name: &str) -> anyhow::Result<RawFd> {
    bpf.map(name)
        .map(map_raw_fd)
        .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
}

pub fn bpf_lookup_and_delete<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    key: &K,
) -> anyhow::Result<LookupAndDelete<V>> {
    if cap.is_unsupported() {
        return Ok(LookupAndDelete::Unsupported);
    }
    let fd = map_fd(bpf, map)?;
    let mut value = MaybeUninit::<V>::uninit();
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key as *const K as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = value.as_mut_ptr() as u64;
    let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_AND_DELETE_ELEM as c_long, &mut attr) };
    if !cap.observe(result) {
        debug!(
            "bpf lookup_and_delete({}) unsupported, using lookup+delete",
            map
        );
        return Ok(LookupAndDelete::Unsupported);
    }
    match result {
        Ok(()) => Ok(LookupAndDelete::Value(unsafe { value.assume_init() })),
        Err(ENOENT) => Ok(LookupAndDelete::Missing),
        Err(error) => Err(anyhow::anyhow!(
            "bpf lookup_and_delete({map}) errno={error}"
        )),
    }
}

/// Delete through a shared Aya map handle. This is only used by the legacy
/// fallback for `routing_handoff_take`, whose public contract deliberately
/// takes `&self` so hot-path callers can retain a backend read lock.
pub fn bpf_delete_shared<K: Pod>(bpf: &Ebpf, map: &str, key: &K) -> anyhow::Result<()> {
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key as *const K as u64;
    match unsafe { bpf_syscall(BPF_MAP_DELETE_ELEM as c_long, &mut attr) } {
        Ok(()) | Err(ENOENT) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("bpf delete({map}) errno={error}")),
    }
}

fn lookup_batch_result(result: Result<(), c_long>, count: u32) -> Result<(usize, bool), c_long> {
    match result {
        Ok(()) => Ok(((count as usize).min(BPF_BATCH_CHUNK), false)),
        Err(ENOENT) => Ok(((count as usize).min(BPF_BATCH_CHUNK), true)),
        Err(error) => Err(error),
    }
}

fn uninitialized<T>(len: usize) -> Vec<MaybeUninit<T>> {
    std::iter::repeat_with(MaybeUninit::uninit)
        .take(len)
        .collect()
}

fn append_initialized<K: Pod, V: Pod>(
    keys: &[MaybeUninit<K>],
    values: &[MaybeUninit<V>],
    count: usize,
    out: &mut Vec<(K, V)>,
) {
    for index in 0..count {
        out.push((unsafe { keys[index].assume_init() }, unsafe {
            values[index].assume_init()
        }));
    }
}

/// Scan a hash-family map with `BPF_MAP_LOOKUP_BATCH` (Linux 5.6+).
/// Returns `false` without changing `out` when the command is unsupported.
pub fn bpf_lookup_batch_scan<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    out: &mut Vec<(K, V)>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let initial_len = out.len();
    let mut keys = uninitialized::<K>(BPF_BATCH_CHUNK);
    let mut values = uninitialized::<V>(BPF_BATCH_CHUNK);
    let mut next_key = MaybeUninit::<K>::uninit();
    let mut previous_key: Option<K> = None;
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = previous_key
            .as_ref()
            .map_or(0, |key| key as *const K as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(result) {
            out.truncate(initial_len);
            debug!(
                "bpf lookup_batch({}) unsupported, using Aya map iteration",
                map
            );
            return Ok(false);
        }
        let (count, terminal) = match lookup_batch_result(result, unsafe { attr.batch.count }) {
            Ok(result) => result,
            Err(error) => {
                out.truncate(initial_len);
                return Err(anyhow::anyhow!("bpf lookup_batch({map}) errno={error}"));
            }
        };
        append_initialized(&keys, &values, count, out);
        if terminal || count < BPF_BATCH_CHUNK {
            return Ok(true);
        }
        previous_key = Some(unsafe { next_key.assume_init() });
    }
}

/// Streaming lookup-batch variant that keeps memory bounded to one chunk.
pub fn bpf_lookup_batch_scan_cb<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    visit: &mut BatchVisitor<'_, K, V>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let mut keys = uninitialized::<K>(BPF_BATCH_CHUNK);
    let mut values = uninitialized::<V>(BPF_BATCH_CHUNK);
    let mut next_key = MaybeUninit::<K>::uninit();
    let mut previous_key: Option<K> = None;
    let mut chunk = Vec::with_capacity(BPF_BATCH_CHUNK);
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = previous_key
            .as_ref()
            .map_or(0, |key| key as *const K as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(result) {
            debug!(
                "bpf lookup_batch({}) unsupported, using Aya map iteration",
                map
            );
            return Ok(false);
        }
        let (count, terminal) = lookup_batch_result(result, unsafe { attr.batch.count })
            .map_err(|error| anyhow::anyhow!("bpf lookup_batch({map}) errno={error}"))?;
        chunk.clear();
        append_initialized(&keys, &values, count, &mut chunk);
        if !chunk.is_empty() && !visit(&chunk) {
            return Ok(true);
        }
        if terminal || count < BPF_BATCH_CHUNK {
            return Ok(true);
        }
        previous_key = Some(unsafe { next_key.assume_init() });
    }
}

/// Delete keys with `BPF_MAP_DELETE_BATCH` (Linux 5.6+).
pub fn bpf_delete_batch<K: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    keys: &[K],
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    if keys.is_empty() {
        return Ok(true);
    }
    let fd = map_fd(bpf, map)?;
    for chunk in keys.chunks(BPF_BATCH_CHUNK) {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.keys = chunk.as_ptr() as u64;
        attr.batch.count = chunk.len() as u32;
        let result = unsafe { bpf_syscall(BPF_MAP_DELETE_BATCH as c_long, &mut attr) };
        if !cap.observe(result) {
            debug!(
                "bpf delete_batch({}) unsupported, using Aya map deletes",
                map
            );
            return Ok(false);
        }
        match result {
            Ok(()) | Err(ENOENT) => {}
            Err(error) => {
                return Err(anyhow::anyhow!("bpf delete_batch({map}) errno={error}"));
            }
        }
    }
    Ok(true)
}

/// Write one bounded chunk with `BPF_MAP_UPDATE_BATCH` (Linux 5.6+).
pub fn bpf_update_batch<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    keys: &[K],
    values: &[V],
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    if keys.is_empty() {
        return Ok(true);
    }
    anyhow::ensure!(
        keys.len() == values.len(),
        "update_batch({map}): keys/values length mismatch"
    );
    anyhow::ensure!(
        keys.len() <= BPF_BATCH_CHUNK,
        "update_batch({map}): limited to {BPF_BATCH_CHUNK} elements per call"
    );
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.batch.map_fd = fd as u32;
    attr.batch.keys = keys.as_ptr() as u64;
    attr.batch.values = values.as_ptr() as u64;
    attr.batch.count = keys.len() as u32;
    let result = unsafe { bpf_syscall(BPF_MAP_UPDATE_BATCH as c_long, &mut attr) };
    if !cap.observe(result) {
        debug!(
            "bpf update_batch({}) unsupported, using Aya array writes",
            map
        );
        return Ok(false);
    }
    result.map_err(|error| anyhow::anyhow!("bpf update_batch({map}) errno={error}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_enoent_preserves_partial_count() {
        for count in [0, 1, 127, 128, 129, 255] {
            let (returned, terminal) = lookup_batch_result(Err(ENOENT), count).unwrap();
            assert!(terminal);
            assert_eq!(returned, (count as usize).min(BPF_BATCH_CHUNK));
        }
    }
}
