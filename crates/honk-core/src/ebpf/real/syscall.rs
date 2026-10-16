//! Raw extensions for BPF map commands that Aya 0.14 does not expose.
//!
//! Ordinary map reads, writes, deletes, iteration, and per-CPU access use
//! Aya's typed map APIs in `real::mod`. This module owns the atomic and batch
//! commands plus locked access to the persistent UDP token allocator.

use super::*;

use aya::Pod;
use aya_obj::generated::bpf_cmd::*;
use aya_obj::generated::{BPF_ANY, BPF_F_LOCK, bpf_attr, bpf_map_info, bpf_map_type};
use std::ffi::c_long;
use std::mem::MaybeUninit;
use std::path::Path;

const ENOENT: c_long = libc::ENOENT as c_long;
pub const BPF_BATCH_CHUNK: usize = 128;

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

pub(super) fn insert_tcp_live_pin(map: &AyaMapData, incarnation: u64) -> anyhow::Result<()> {
    let value = 1u8;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = map.fd().as_fd().as_raw_fd() as u32;
    attr.__bindgen_anon_2.key = (&incarnation as *const u64) as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = (&value as *const u8) as u64;
    attr.__bindgen_anon_2.flags = aya_obj::generated::BPF_NOEXIST as u64;
    unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::Error::new(std::io::Error::from_raw_os_error(error as i32))
            .context("TCP_LIVE_PINS no-exist insert")
    })
}

pub(super) fn remove_tcp_live_pin(map: &AyaMapData, incarnation: u64) -> anyhow::Result<()> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = map.fd().as_fd().as_raw_fd() as u32;
    attr.__bindgen_anon_2.key = (&incarnation as *const u64) as u64;
    unsafe { bpf_syscall(BPF_MAP_DELETE_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::Error::new(std::io::Error::from_raw_os_error(error as i32))
            .context(format!("TCP_LIVE_PINS release {incarnation}"))
    })
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

fn raw_map_info(fd: RawFd) -> anyhow::Result<bpf_map_info> {
    let mut info: bpf_map_info = unsafe { core::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = fd as u32;
    attr.info.info_len = core::mem::size_of::<bpf_map_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_map_info) as u64;
    unsafe { bpf_syscall(BPF_OBJ_GET_INFO_BY_FD as c_long, &mut attr) }
        .map_err(|error| anyhow::anyhow!("BPF_OBJ_GET_INFO_BY_FD errno={error}"))?;
    Ok(info)
}

fn locked_udp_decision_sequence(fd: RawFd) -> anyhow::Result<UdpDecisionSequence> {
    let key = 0u32;
    let mut value = UdpDecisionSequence::default();
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = (&key as *const u32) as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = (&mut value as *mut UdpDecisionSequence) as u64;
    attr.__bindgen_anon_2.flags = BPF_F_LOCK as u64;
    unsafe { bpf_syscall(BPF_MAP_LOOKUP_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::anyhow!(
            "locked UDP_DECISION_SEQUENCE lookup failed (spin-lock BTF incompatible), errno={error}"
        )
    })?;
    Ok(value)
}

fn update_locked_udp_decision_sequence(
    fd: RawFd,
    value: &UdpDecisionSequence,
) -> anyhow::Result<()> {
    let key = 0u32;
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_2.map_fd = fd as u32;
    attr.__bindgen_anon_2.key = (&key as *const u32) as u64;
    attr.__bindgen_anon_2.__bindgen_anon_1.value = (value as *const UdpDecisionSequence) as u64;
    attr.__bindgen_anon_2.flags = (BPF_ANY | BPF_F_LOCK) as u64;
    unsafe { bpf_syscall(BPF_MAP_UPDATE_ELEM as c_long, &mut attr) }.map_err(|error| {
        anyhow::anyhow!(
            "locked UDP_DECISION_SEQUENCE update failed (spin-lock BTF incompatible), errno={error}"
        )
    })?;
    Ok(())
}

fn validate_udp_decision_sequence_info(info: &bpf_map_info) -> anyhow::Result<()> {
    anyhow::ensure!(
        info.type_ == bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
        "UDP_DECISION_SEQUENCE has incompatible map type {}",
        info.type_
    );
    anyhow::ensure!(
        info.key_size == core::mem::size_of::<u32>() as u32,
        "UDP_DECISION_SEQUENCE has incompatible key size {}",
        info.key_size
    );
    anyhow::ensure!(
        info.value_size == core::mem::size_of::<UdpDecisionSequence>() as u32,
        "UDP_DECISION_SEQUENCE has incompatible value size {}",
        info.value_size
    );
    anyhow::ensure!(
        info.max_entries == 1,
        "UDP_DECISION_SEQUENCE has incompatible max_entries {}",
        info.max_entries
    );
    anyhow::ensure!(
        info.map_flags == 0,
        "UDP_DECISION_SEQUENCE has incompatible map flags 0x{:x}",
        info.map_flags
    );
    anyhow::ensure!(
        info.btf_id != 0 && info.btf_value_type_id != 0,
        "UDP_DECISION_SEQUENCE is missing value BTF"
    );
    Ok(())
}

fn validate_udp_decision_sequence_value(sequence: UdpDecisionSequence) -> anyhow::Result<()> {
    anyhow::ensure!(
        sequence.next <= honk_ebpf_common::NFQUEUE_TOKEN_MASK,
        "UDP_DECISION_SEQUENCE next token exceeds its token space"
    );
    anyhow::ensure!(
        sequence.exhausted <= 1,
        "UDP_DECISION_SEQUENCE has invalid exhausted flag {}",
        sequence.exhausted
    );
    if sequence.exhausted != 0 {
        anyhow::ensure!(
            sequence.next == honk_ebpf_common::NFQUEUE_TOKEN_MASK,
            "UDP_DECISION_SEQUENCE has an inconsistent exhausted flag"
        );
    }
    Ok(())
}

fn validate_udp_decision_sequence_fd(fd: RawFd) -> anyhow::Result<UdpDecisionSequence> {
    let info = raw_map_info(fd)?;
    validate_udp_decision_sequence_info(&info)?;
    let sequence = locked_udp_decision_sequence(fd)?;
    validate_udp_decision_sequence_value(sequence)?;
    Ok(sequence)
}

pub fn validate_pinned_udp_decision_sequence(path: &Path) -> anyhow::Result<()> {
    let map = aya::maps::MapData::from_pin(path)
        .map_err(|error| anyhow::anyhow!("open persistent map '{}': {error}", path.display()))?;
    validate_udp_decision_sequence_fd(map.fd().as_fd().as_raw_fd()).map(|_| ())
}

pub fn validate_loaded_udp_decision_sequence(bpf: &Ebpf) -> anyhow::Result<UdpDecisionSequence> {
    validate_udp_decision_sequence_fd(map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?)
}

#[cfg(test)]
pub(super) fn read_udp_decision_sequence_locked(bpf: &Ebpf) -> anyhow::Result<UdpDecisionSequence> {
    locked_udp_decision_sequence(map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?)
}

pub fn reset_udp_decision_sequence_locked(bpf: &Ebpf, generation: u32) -> anyhow::Result<()> {
    let value = UdpDecisionSequence {
        next: generation << honk_ebpf_common::UDP_DECISION_GENERATION_SHIFT,
        ..Default::default()
    };
    update_locked_udp_decision_sequence(
        map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?,
        &value,
    )
}

#[cfg(test)]
pub(super) fn write_udp_decision_sequence_locked(
    bpf: &Ebpf,
    value: &UdpDecisionSequence,
) -> anyhow::Result<()> {
    update_locked_udp_decision_sequence(
        map_fd(bpf, super::super::UDP_DECISION_SEQUENCE_MAP)?,
        value,
    )
}

pub(super) fn validate_map_layout(
    bpf: &Ebpf,
    name: &str,
    type_: bpf_map_type,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
) -> anyhow::Result<()> {
    let info = raw_map_info(map_fd(bpf, name)?)?;
    anyhow::ensure!(
        info.type_ == type_ as u32
            && info.key_size == key
            && info.value_size == value
            && info.max_entries == entries
            && info.map_flags == flags,
        "map '{name}' has incompatible lifetime layout: type={} key={} value={} entries={} flags={}",
        info.type_,
        info.key_size,
        info.value_size,
        info.max_entries,
        info.map_flags
    );
    Ok(())
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

/// Streaming lookup-batch variant that keeps memory bounded to one chunk.
pub fn bpf_lookup_batch_scan_cb<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    visit: &mut BatchVisitor<'_, K, V>,
) -> anyhow::Result<bool> {
    bpf_lookup_batch_scan_cb_flags(bpf, cap, map, 0, visit)
}

pub(super) fn bpf_lookup_batch_scan_cb_flags<K: Pod, V: Pod>(
    bpf: &Ebpf,
    cap: &BatchCapability,
    map: &str,
    elem_flags: u64,
    visit: &mut BatchVisitor<'_, K, V>,
) -> anyhow::Result<bool> {
    if cap.is_unsupported() {
        return Ok(false);
    }
    let fd = map_fd(bpf, map)?;
    let mut keys = uninitialized::<K>(BPF_BATCH_CHUNK);
    let mut values = uninitialized::<V>(BPF_BATCH_CHUNK);
    // Hash maps return a four-byte opaque bucket cursor, not a key.
    let mut next_cursor = [0u8; 4];
    let mut previous_cursor = [0u8; 4];
    let mut has_cursor = false;
    let mut chunk = Vec::with_capacity(BPF_BATCH_CHUNK);
    loop {
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.batch.map_fd = fd as u32;
        attr.batch.in_batch = if has_cursor {
            previous_cursor.as_ptr() as u64
        } else {
            0
        };
        attr.batch.out_batch = next_cursor.as_mut_ptr() as u64;
        attr.batch.keys = keys.as_mut_ptr() as u64;
        attr.batch.values = values.as_mut_ptr() as u64;
        attr.batch.count = BPF_BATCH_CHUNK as u32;
        attr.batch.elem_flags = elem_flags;
        let result = unsafe { bpf_syscall(BPF_MAP_LOOKUP_BATCH as c_long, &mut attr) };
        if let Err(error) = result {
            anyhow::ensure!(
                !has_cursor || error == ENOENT,
                "bpf lookup_batch({map}) failed after a partial scan: errno={error}"
            );
        }
        if !cap.observe(result) {
            debug!(
                "bpf lookup_batch({}) unsupported; caller must select a safe fallback",
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
        // A successful batch may be short; only ENOENT marks the final batch.
        if terminal {
            return Ok(true);
        }
        if count == 0 {
            anyhow::bail!("bpf lookup_batch({map}) returned an empty nonterminal batch");
        }
        previous_cursor.copy_from_slice(&next_cursor);
        has_cursor = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_sequence_value_stays_compatible_with_rollback_allocator_across_generation_boundary() {
        let mut sequence = UdpDecisionSequence {
            next: udp_decision_token(1, 42).unwrap(),
            ..UdpDecisionSequence::default()
        };
        validate_udp_decision_sequence_value(sequence).unwrap();

        assert_eq!(sequence.exhausted, 0);
        sequence.next += 1;
        assert_eq!(sequence.next, udp_decision_token(1, 43).unwrap());

        sequence.next = udp_decision_token(0, UDP_DECISION_SEQUENCE_MASK).unwrap();
        validate_udp_decision_sequence_value(sequence).unwrap();
        sequence.next += 1;
        assert_eq!(sequence.next, 1 << UDP_DECISION_GENERATION_SHIFT);
        sequence.next += 1;
        assert_eq!(sequence.next, udp_decision_token(1, 1).unwrap());

        let exhausted = UdpDecisionSequence {
            next: NFQUEUE_TOKEN_MASK,
            exhausted: 1,
            ..UdpDecisionSequence::default()
        };
        validate_udp_decision_sequence_value(exhausted).unwrap();
    }

    #[test]
    fn malformed_sequence_values_are_rejected() {
        for malformed in [
            UdpDecisionSequence {
                next: NFQUEUE_TOKEN_MASK + 1,
                ..UdpDecisionSequence::default()
            },
            UdpDecisionSequence {
                exhausted: 2,
                ..UdpDecisionSequence::default()
            },
            UdpDecisionSequence {
                next: UDP_DECISION_SEQUENCE_MASK,
                exhausted: 1,
                ..UdpDecisionSequence::default()
            },
        ] {
            assert!(validate_udp_decision_sequence_value(malformed).is_err());
        }
    }

    #[test]
    fn successful_short_batch_is_not_terminal() {
        for count in [1, BPF_BATCH_CHUNK as u32 - 1] {
            let (returned, terminal) = lookup_batch_result(Ok(()), count).unwrap();
            assert!(!terminal);
            assert_eq!(returned, count as usize);
        }
    }

    #[test]
    fn terminal_enoent_preserves_partial_count() {
        for count in [0, 1, 127, 128, 129, 255] {
            let (returned, terminal) = lookup_batch_result(Err(ENOENT), count).unwrap();
            assert!(terminal);
            assert_eq!(returned, (count as usize).min(BPF_BATCH_CHUNK));
        }
    }

    fn compatible_sequence_info() -> bpf_map_info {
        let mut info: bpf_map_info = unsafe { core::mem::zeroed() };
        info.type_ = bpf_map_type::BPF_MAP_TYPE_ARRAY as u32;
        info.key_size = core::mem::size_of::<u32>() as u32;
        info.value_size = core::mem::size_of::<UdpDecisionSequence>() as u32;
        info.max_entries = 1;
        info.btf_id = 1;
        info.btf_value_type_id = 2;
        info
    }

    #[test]
    fn persistent_sequence_shape_must_match_exactly() {
        let info = compatible_sequence_info();
        validate_udp_decision_sequence_info(&info).unwrap();

        let mut wrong = info;
        wrong.value_size += 4;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.max_entries = 2;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.map_flags = 1;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
        let mut wrong = info;
        wrong.btf_value_type_id = 0;
        assert!(validate_udp_decision_sequence_info(&wrong).is_err());
    }
}
