use super::*;

// We use `libc::syscall(libc::SYS_bpf, ...)` because libc 0.2 does not
// expose a dedicated `bpf()` wrapper.  Constants come from `aya-obj`
// (already a transitive dependency).

use aya_obj::generated::bpf_attr;
use aya_obj::generated::bpf_cmd::*;
use std::ffi::c_long;

pub const ENOENT: c_long = libc::ENOENT as c_long;

/// Callback invoked once per batch chunk by [`bpf_lookup_batch_scan_cb`].
/// Returning `false` stops the scan early.
pub type BatchVisitor<'a, K, V> = dyn FnMut(&[(K, V)]) -> bool + 'a;

/// Call the `bpf()` syscall.  Returns `Ok(())` on success, `Err(errno)`.
///
/// # Safety
///
/// `attr` must point to a live `bpf_attr` appropriate for `cmd` for the
/// duration of the call.
pub unsafe fn bpf_syscall(cmd: c_long, attr: &mut bpf_attr) -> Result<(), c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut bpf_attr,
            core::mem::size_of::<bpf_attr>(),
        )
    };
    if ret < 0 {
        Err(unsafe { *libc::__errno_location() } as c_long)
    } else {
        Ok(())
    }
}

/// Reinterpret a POD value as its raw bytes.
///
/// # Safety
///
/// `T` must be valid to view as bytes (no padding-sensitive invariants);
/// used only with the `#[repr(C)]` wire types.
pub unsafe fn as_bytes<T: Sized>(t: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(t as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// Read a `T` out of a raw byte slice, possibly unaligned.
///
/// # Safety
///
/// `bytes` must be at least `size_of::<T>()` long and hold a valid `T`.
pub unsafe fn from_bytes<T: Sized + Copy>(bytes: &[u8]) -> T {
    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const T) }
}

/// Extract the raw file descriptor from any `aya::maps::Map` variant.
pub fn map_raw_fd(map: &aya::maps::Map) -> anyhow::Result<RawFd> {
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
    Ok(data.fd().as_fd().as_raw_fd())
}

pub fn map_fd(bpf: &Ebpf, name: &str) -> anyhow::Result<RawFd> {
    map_raw_fd(
        bpf.map(name)
            .ok_or_else(|| anyhow::anyhow!("map '{}' not found", name))?,
    )
}

pub fn map_fd_mut(bpf: &mut Ebpf, name: &str) -> anyhow::Result<RawFd> {
    map_raw_fd(
        bpf.map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("map '{}' not found", name))?,
    )
}

pub const BPF_ANY: u64 = 0;

pub fn bpf_hash_insert(bpf: &mut Ebpf, map: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
    let fd = map_fd_mut(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key.as_ptr() as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = value.as_ptr() as u64;
    attr.__bindgen_anon_2.flags = BPF_ANY;
    unsafe {
        bpf_syscall(BPF_MAP_UPDATE_ELEM as c_long, &mut attr)
            .map_err(|e| anyhow::anyhow!("bpf update({}) errno={}", map, e))?;
    }
    Ok(())
}

pub fn bpf_hash_insert_domain(
    bpf: &mut Ebpf,
    map: &str,
    key: &[u8],
    value: &[u8],
) -> Result<(), super::super::DomainRouteWriteError> {
    let fd = map_fd_mut(bpf, map).map_err(super::super::DomainRouteWriteError::Other)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key.as_ptr() as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = value.as_ptr() as u64;
    attr.__bindgen_anon_2.flags = BPF_ANY;
    match unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM as c_long, &mut attr) } {
        Ok(()) => Ok(()),
        Err(errno) if errno == libc::ENOSPC as c_long => {
            Err(super::super::DomainRouteWriteError::MapFull)
        }
        Err(errno) => Err(super::super::DomainRouteWriteError::Other(anyhow::anyhow!(
            "bpf update({}) errno={}",
            map,
            errno
        ))),
    }
}

pub fn bpf_hash_lookup(
    bpf: &Ebpf,
    map: &str,
    key: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<()>> {
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key.as_ptr() as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = buf.as_mut_ptr() as u64;
    match unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM as c_long, &mut attr) } {
        Ok(()) => Ok(Some(())),
        Err(ENOENT) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("bpf lookup({}) errno={}", map, e)),
    }
}

pub fn bpf_hash_delete(bpf: &Ebpf, map: &str, key: &[u8]) -> anyhow::Result<()> {
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key.as_ptr() as u64;
    match unsafe { bpf_syscall(BPF_MAP_DELETE_ELEM as c_long, &mut attr) } {
        Ok(()) | Err(ENOENT) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("bpf delete({}) errno={}", map, e)),
    }
}

pub fn bpf_map_keys(bpf: &Ebpf, map: &str, key_size: usize) -> anyhow::Result<Vec<Vec<u8>>> {
    let fd = map_fd(bpf, map)?;
    let mut keys: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut next = vec![0u8; key_size];
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.__bindgen_anon_2.map_fd = fd as u32;
        // The previous key always lives in the last slot of `keys`.  The
        // pointer is re-derived every iteration (a push may reallocate the
        // outer Vec), so no per-key clone is needed.
        attr.__bindgen_anon_2.key = keys.last().map_or(0, |k| k.as_ptr() as u64);
        attr.__bindgen_anon_2.__bindgen_anon_1.next_key = next.as_mut_ptr() as u64;
        match unsafe { bpf_syscall(BPF_MAP_GET_NEXT_KEY as c_long, &mut attr) } {
            Ok(()) => keys.push(next),
            Err(ENOENT) => break,
            Err(e) => return Err(anyhow::anyhow!("bpf get_next_key({}) errno={}", map, e)),
        }
    }
    Ok(keys)
}

// aya 0.14 does not wrap these commands, so they go through the same raw
// bpf() layer as the single-element helpers.  Each command's availability
// is probed once per backend via `BatchCapability` (see `ebpf::probe`):
// the first call tries the batch command and latches the verdict; when the
// kernel lacks it the callers below transparently fall back to the
// per-element paths.

/// Entries per chunk for the batched scan/delete helpers.
pub const BPF_BATCH_CHUNK: usize = 128;

/// Try `BPF_MAP_LOOKUP_AND_DELETE_ELEM` (hash maps, kernel 4.20+).
///
/// Returns `Ok(Some(true))` when the entry was found (and deleted; its
/// value is in `buf`), `Ok(Some(false))` on a miss, `Ok(None)` when the
/// kernel lacks the command (Unsupported latched — caller must fall back),
/// and `Err` on a real failure.
pub fn bpf_lookup_and_delete(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    key: &[u8],
    buf: &mut [u8],
) -> anyhow::Result<Option<bool>> {
    if cap.is_unsupported() {
        return Ok(None);
    }
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = key.as_ptr() as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = buf.as_mut_ptr() as u64;
    let res = unsafe { bpf_syscall(BPF_MAP_LOOKUP_AND_DELETE_ELEM as c_long, &mut attr) };
    if !cap.observe(res) {
        debug!(
            "bpf lookup_and_delete({}) unsupported, using lookup+delete",
            map
        );
        return Ok(None);
    }
    match res {
        Ok(()) => Ok(Some(true)),
        Err(ENOENT) => Ok(Some(false)),
        Err(e) => Err(anyhow::anyhow!(
            "bpf lookup_and_delete({}) errno={}",
            map,
            e
        )),
    }
}

/// Decode entries returned by one lookup-batch syscall. Linux writes the
/// processed count even when it returns terminal `ENOENT`.
fn decode_lookup_batch<K: Copy, V: Copy>(
    keys_buf: &[u8],
    vals_buf: &[u8],
    count: u32,
    mut emit: impl FnMut(K, V),
) {
    let ksz = core::mem::size_of::<K>();
    let vsz = core::mem::size_of::<V>();
    for i in 0..(count as usize).min(BPF_BATCH_CHUNK) {
        let key = unsafe { core::ptr::read_unaligned(keys_buf[i * ksz..].as_ptr() as *const K) };
        let value = unsafe { core::ptr::read_unaligned(vals_buf[i * vsz..].as_ptr() as *const V) };
        emit(key, value);
    }
}

/// A terminal `ENOENT` still carries entries in `count`; it merely marks the
/// end of this scan.
fn lookup_batch_result(result: Result<(), c_long>, count: u32) -> Result<(usize, bool), c_long> {
    match result {
        Ok(()) => Ok(((count as usize).min(BPF_BATCH_CHUNK), false)),
        Err(ENOENT) => Ok(((count as usize).min(BPF_BATCH_CHUNK), true)),
        Err(error) => Err(error),
    }
}

/// Scan the whole map into `out` with `BPF_MAP_LOOKUP_BATCH` (hash/LRU-hash
/// maps, kernel 5.6+), one syscall per [`BPF_BATCH_CHUNK`] entries.
///
/// Returns `Ok(true)` when the scan completed via the batch path,
/// `Ok(false)` when the kernel lacks the command (`out` is left unchanged
/// and the caller must fall back), and `Err` on a real failure.
///
/// NOTE: the scan is not an atomic snapshot — entries inserted or deleted
/// concurrently may be skipped or returned twice.  Callers (the map
/// janitor) tolerate this: missed entries are retried on the next round
/// and duplicates are re-validated before deletion.
pub fn bpf_lookup_batch_scan<K: Copy, V: Copy>(
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
    let ksz = core::mem::size_of::<K>();
    let vsz = core::mem::size_of::<V>();
    let mut keys_buf = vec![0u8; BPF_BATCH_CHUNK * ksz];
    let mut vals_buf = vec![0u8; BPF_BATCH_CHUNK * vsz];
    let mut next_key = vec![0u8; ksz];
    // Continuation key from the previous call (out_batch); None = scan from
    // the start of the map.
    let mut in_batch: Option<Vec<u8>> = None;
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = in_batch.as_ref().map_or(0, |b| b.as_ptr() as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys_buf.as_mut_ptr() as u64;
        attr.batch.values = vals_buf.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let res = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(res) {
            out.truncate(initial_len);
            debug!(
                "bpf lookup_batch({}) unsupported, using GET_NEXT_KEY walk",
                map
            );
            return Ok(false);
        }
        let (n, terminal) = match lookup_batch_result(res, unsafe { attr.batch.count }) {
            Ok(result) => result,
            Err(error) => {
                out.truncate(initial_len);
                return Err(anyhow::anyhow!("bpf lookup_batch({}) errno={}", map, error));
            }
        };
        decode_lookup_batch(&keys_buf, &vals_buf, n as u32, |key, value| {
            out.push((key, value))
        });
        if terminal || n < BPF_BATCH_CHUNK {
            return Ok(true);
        }
        in_batch = Some(next_key.clone());
    }
}

/// Streaming variant of [`bpf_lookup_batch_scan`]: invokes `visit` once per
/// chunk instead of accumulating the whole map, so memory stays bounded by
/// `BPF_BATCH_CHUNK` regardless of map size. Same fallback contract —
/// `Ok(false)` when the kernel lacks `BPF_MAP_LOOKUP_BATCH`.
pub fn bpf_lookup_batch_scan_cb<K: Copy, V: Copy>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    visit: &mut BatchVisitor<'_, K, V>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let ksz = core::mem::size_of::<K>();
    let vsz = core::mem::size_of::<V>();
    let mut keys_buf = vec![0u8; BPF_BATCH_CHUNK * ksz];
    let mut vals_buf = vec![0u8; BPF_BATCH_CHUNK * vsz];
    let mut next_key = vec![0u8; ksz];
    let mut in_batch: Option<Vec<u8>> = None;
    let mut chunk: Vec<(K, V)> = Vec::with_capacity(BPF_BATCH_CHUNK);
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = in_batch.as_ref().map_or(0, |b| b.as_ptr() as u64);
        attr.batch.out_batch = next_key.as_mut_ptr() as u64;
        attr.batch.keys = keys_buf.as_mut_ptr() as u64;
        attr.batch.values = vals_buf.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        let res = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if !cap.observe(res) {
            debug!(
                "bpf lookup_batch({}) unsupported, using GET_NEXT_KEY walk",
                map
            );
            return Ok(false);
        }
        let (n, terminal) = match lookup_batch_result(res, unsafe { attr.batch.count }) {
            Ok(result) => result,
            Err(error) => return Err(anyhow::anyhow!("bpf lookup_batch({}) errno={}", map, error)),
        };
        chunk.clear();
        decode_lookup_batch(&keys_buf, &vals_buf, n as u32, |key, value| {
            chunk.push((key, value))
        });
        if !chunk.is_empty() && !visit(&chunk) {
            return Ok(true);
        }
        if terminal || n < BPF_BATCH_CHUNK {
            return Ok(true);
        }
        in_batch = Some(next_key.clone());
    }
}

/// Delete `keys` with `BPF_MAP_DELETE_BATCH` (hash/LRU-hash maps, kernel
/// 5.6+).  Returns `Ok(true)` when the batch path ran (keys already gone
/// are tolerated), `Ok(false)` when the kernel lacks the command.
pub fn bpf_delete_batch<K: Copy>(
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
        let res = unsafe { bpf_syscall(BPF_MAP_DELETE_BATCH as c_long, &mut attr) };
        if !cap.observe(res) {
            debug!(
                "bpf delete_batch({}) unsupported, using per-key deletes",
                map
            );
            return Ok(false);
        }
        match res {
            // ENOENT only means some (or all) keys were already gone.
            Ok(()) | Err(ENOENT) => {}
            Err(e) => return Err(anyhow::anyhow!("bpf delete_batch({}) errno={}", map, e)),
        }
    }
    Ok(true)
}

/// Write `values` at `keys` with `BPF_MAP_UPDATE_BATCH` (array/hash maps,
/// kernel 5.6+), a single syscall.  Returns `Ok(true)` when the batch path
/// ran, `Ok(false)` when the kernel lacks the command.
pub fn bpf_update_batch<K: Copy, V: Copy>(
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
        "update_batch({}): keys/values length mismatch",
        map
    );
    anyhow::ensure!(
        keys.len() <= BPF_BATCH_CHUNK,
        "update_batch({}): limited to {} elements per call",
        map,
        BPF_BATCH_CHUNK
    );
    let fd = map_fd(bpf, map)?;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.batch.map_fd = fd as u32;
    attr.batch.keys = keys.as_ptr() as u64;
    attr.batch.values = values.as_ptr() as u64;
    attr.batch.count = keys.len() as u32;
    let res = unsafe { bpf_syscall(BPF_MAP_UPDATE_BATCH as c_long, &mut attr) };
    if !cap.observe(res) {
        debug!(
            "bpf update_batch({}) unsupported, using per-element updates",
            map
        );
        return Ok(false);
    }
    res.map_err(|e| anyhow::anyhow!("bpf update_batch({}) errno={}", map, e))?;
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

    #[test]
    fn decodes_only_reported_entries() {
        let keys = [10u32, 20, 30];
        let values = [100u32, 200, 300];
        let keys_buf = unsafe {
            core::slice::from_raw_parts(keys.as_ptr() as *const u8, core::mem::size_of_val(&keys))
        };
        let values_buf = unsafe {
            core::slice::from_raw_parts(
                values.as_ptr() as *const u8,
                core::mem::size_of_val(&values),
            )
        };
        let mut decoded = Vec::new();
        decode_lookup_batch(keys_buf, values_buf, 2, |key, value| {
            decoded.push((key, value))
        });
        assert_eq!(decoded, vec![(10, 100), (20, 200)]);
    }
}
