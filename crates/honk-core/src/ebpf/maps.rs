//! BPF map utilities for honk-core.
//!
//! This module provides LPM trie helpers, batch map operations,
//! and common utility functions used by both real and mock eBPF backends.
//! It does not depend on `aya` directly, making it usable by all backends
//! regardless of whether real eBPF support is compiled in.

use tracing::warn;

pub use honk_ebpf_common::LpmKey;

/// Convert a CIDR prefix string (e.g. `"10.0.0.0/8"`) into an [`LpmKey`].
///
/// IPv4 prefixes are automatically converted to their IPv6-mapped form
/// (`::ffff:x.x.x.x`) with the prefix length adjusted by +96
/// (e.g. /8 → 104), matching kernel LPM trie expectations.
///
/// # Errors
///
/// Returns an error if the prefix string cannot be parsed as a valid
/// IPv4 or IPv6 CIDR.
///
/// # Examples
///
/// ```
/// use honk_core::ebpf::maps::{cidr_to_lpm_key, LpmKey};
///
/// let key = cidr_to_lpm_key("10.0.0.0/8").unwrap();
/// assert_eq!(key.prefix_len, 104);
/// assert_eq!(key.data[3], 0x0000000a);
/// ```
pub fn cidr_to_lpm_key(prefix: &str) -> anyhow::Result<LpmKey> {
    // If no '/' is present, append the default host prefix length.
    let owned: String;
    let prefix_str = if prefix.contains('/') {
        prefix
    } else if prefix.contains(':') {
        owned = format!("{}/128", prefix);
        &owned
    } else {
        owned = format!("{}/32", prefix);
        &owned
    };

    let net: ipnet::IpNet = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid CIDR prefix '{}': {}", prefix, e))?;

    let mut prefix_len = net.prefix_len() as u32;

    let addr_bytes: [u8; 16] = match net.addr() {
        std::net::IpAddr::V4(ipv4) => {
            prefix_len += 96;
            ipv4.to_ipv6_mapped().octets()
        }
        std::net::IpAddr::V6(ipv6) => ipv6.octets(),
    };

    // The kernel LPM trie compares key bytes from MSB to LSB, so the data
    // must be stored in network byte order.  We store each chunk as a native
    // u32 whose little-endian memory layout equals the network-order bytes.
    let mut data = [0u32; 4];
    for (i, chunk) in addr_bytes.chunks(4).enumerate() {
        data[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    Ok(LpmKey { prefix_len, data })
}

/// Encode an [`LpmKey`] as its raw 20-byte map-key form: the native-order
/// `prefix_len` followed by the 16-byte address data.  This matches the
/// `#[repr(C)]` layout the kernel uses for LPM trie keys and lets the
/// routing push plan and the backends use the encoding as a `HashMap` key
/// (`LpmKey` itself does not implement `Hash`/`Eq`).
pub fn lpm_key_bytes(key: &LpmKey) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&key.prefix_len.to_ne_bytes());
    for (i, word) in key.data.iter().enumerate() {
        buf[4 + i * 4..8 + i * 4].copy_from_slice(&word.to_ne_bytes());
    }
    buf
}

/// Parse an IPv4 address string (e.g. `"192.168.1.1"`) to a `u32` in network
/// (big-endian) byte order.
///
/// # Errors
///
/// Returns an error if the string is not a valid dotted-decimal IPv4 address,
/// or if any octet is out of range.
///
/// # Examples
///
/// ```
/// use honk_core::ebpf::maps::parse_ipv4_to_u32;
///
/// assert_eq!(parse_ipv4_to_u32("192.168.1.1").unwrap(), 0xc0a80101);
/// assert_eq!(parse_ipv4_to_u32("10.0.0.0").unwrap(), 0x0a000000);
/// assert!(parse_ipv4_to_u32("not-an-ip").is_err());
/// ```
pub fn parse_ipv4_to_u32(s: &str) -> anyhow::Result<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        anyhow::bail!("Invalid IPv4: {}", s);
    }
    let mut ip: u32 = 0;
    for (i, part) in parts.iter().enumerate() {
        let byte: u8 = part
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid IPv4 octet '{}' in '{}'", part, s))?;
        ip |= (byte as u32) << (24 - i * 8);
    }
    Ok(ip)
}

/// FNV-1a 64-bit hash — must match the eBPF side exactly.
///
/// Used for domain routing lookups with hash-based BPF maps.
/// The constants (offset basis and prime) are the standard FNV-1a-64 values.
///
/// # Examples
///
/// ```
/// use honk_core::ebpf::maps::fnv1a_hash;
///
/// let h1 = fnv1a_hash(b"google.com");
/// let h2 = fnv1a_hash(b"google.com");
/// assert_eq!(h1, h2);
/// assert_ne!(fnv1a_hash(b"example.com"), fnv1a_hash(b"google.com"));
/// ```
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Simulate a BPF `MAP_BATCH_UPDATE` operation by calling `update_fn`
/// sequentially.
///
/// On kernels that do not support the native `BPF_MAP_BATCH_UPDATE` syscall
/// (added in Linux 5.6), userspace must fall back to individual insertions.
/// This function loops from `0..max_entries`, calling `update_fn(i)` for each
/// index.
///
/// If an individual update fails, a warning is logged with the map description
/// and index, and the accumulated count is returned.  This matches the Go
/// reference behaviour in `BpfMapBatchUpdate` (`bpf_utils.go`).
///
/// Returns the number of entries successfully processed.
pub fn bpf_batch_update_simulated(
    map_desc: &str,
    max_entries: u32,
    mut update_fn: impl FnMut(usize) -> anyhow::Result<(Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<usize> {
    let mut count = 0usize;
    for i in 0..(max_entries as usize) {
        match update_fn(i) {
            Ok(_) => count += 1,
            Err(e) => {
                warn!(
                    "Batch update map '{}' at index {}: {} — {} entries processed",
                    map_desc, i, e, count
                );
                return Ok(count);
            }
        }
    }
    Ok(count)
}

/// Simulate a BPF `MAP_BATCH_DELETE` operation by calling `delete_fn` for
/// each key.
///
/// On kernels that do not support the native `BPF_MAP_BATCH_DELETE` syscall,
/// userspace must fall back to individual deletions.  This function iterates
/// over `keys`, calling `delete_fn(key_ref)` for each one.
///
/// Key-not-found errors are benign (a concurrent delete may have removed the
/// entry first); they are logged at `WARN` level and skipped without failing
/// the entire batch.  This behaviour mirrors `BpfMapBatchDelete` in the Go
/// reference (`bpf_utils.go`).
///
/// Returns the number of keys successfully deleted.
pub fn bpf_batch_delete_simulated<K: AsRef<[u8]>>(
    map_desc: &str,
    keys: &[K],
    mut delete_fn: impl FnMut(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<usize> {
    let mut deleted = 0usize;
    for (i, key) in keys.iter().enumerate() {
        match delete_fn(key.as_ref()) {
            Ok(()) => deleted += 1,
            Err(e) => {
                warn!(
                    "Batch delete map '{}' at index {} (key already gone): {} — continuing",
                    map_desc, i, e
                );
                // Non-fatal: key-not-found is expected when entries are
                // concurrently removed.
            }
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_to_lpm_key_ipv4_class_a() {
        let key = cidr_to_lpm_key("10.0.0.0/8").unwrap();
        assert_eq!(key.prefix_len, 104); // 8 + 96
        // ::ffff:10.0.0.0 → last 4 bytes = [0x0a, 0x00, 0x00, 0x00]
        // Stored as little-endian u32 chunks so memory bytes are network order.
        assert_eq!(key.data[0], 0x00000000);
        assert_eq!(key.data[1], 0x00000000);
        assert_eq!(key.data[2], 0xffff0000);
        assert_eq!(key.data[3], 0x0000000a);
    }

    #[test]
    fn test_cidr_to_lpm_key_ipv4_local() {
        let key = cidr_to_lpm_key("192.168.1.0/24").unwrap();
        assert_eq!(key.prefix_len, 120); // 24 + 96
        // ::ffff:192.168.1.0 → last 4 bytes = [0xc0, 0xa8, 0x01, 0x00]
        assert_eq!(key.data[2], 0xffff0000);
        assert_eq!(key.data[3], 0x0001a8c0);
    }

    #[test]
    fn test_cidr_to_lpm_key_ipv4_host() {
        // Bare IP without prefix length defaults to /32
        let key = cidr_to_lpm_key("1.2.3.4").unwrap();
        assert_eq!(key.prefix_len, 128); // 32 + 96
        assert_eq!(key.data[3], 0x04030201);
    }

    #[test]
    fn test_cidr_to_lpm_key_ipv6() {
        let key = cidr_to_lpm_key("2001:db8::/32").unwrap();
        assert_eq!(key.prefix_len, 32); // no +96 shift
        // 2001:0db8:0000:... first 4 bytes = [0x20, 0x01, 0x0d, 0xb8]
        assert_eq!(key.data[0], 0xb80d0120);
        assert_eq!(key.data[1], 0x00000000);
        assert_eq!(key.data[2], 0x00000000);
        assert_eq!(key.data[3], 0x00000000);
    }

    #[test]
    fn test_cidr_to_lpm_key_invalid() {
        assert!(cidr_to_lpm_key("not-a-prefix").is_err());
        assert!(cidr_to_lpm_key("999.999.999.999/32").is_err());
        assert!(cidr_to_lpm_key("10.0.0.0/99").is_err());
    }

    #[test]
    fn test_parse_ipv4_standard() {
        assert_eq!(parse_ipv4_to_u32("192.168.1.1").unwrap(), 0xc0a80101);
        assert_eq!(parse_ipv4_to_u32("10.0.0.0").unwrap(), 0x0a000000);
        assert_eq!(parse_ipv4_to_u32("0.0.0.0").unwrap(), 0x00000000);
        assert_eq!(parse_ipv4_to_u32("255.255.255.255").unwrap(), 0xffffffff);
    }

    #[test]
    fn test_parse_ipv4_loopback() {
        assert_eq!(parse_ipv4_to_u32("127.0.0.1").unwrap(), 0x7f000001);
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert!(parse_ipv4_to_u32("invalid").is_err());
        assert!(parse_ipv4_to_u32("1.2.3").is_err());
        assert!(parse_ipv4_to_u32("1.2.3.4.5").is_err());
        assert!(parse_ipv4_to_u32("256.0.0.0").is_err());
    }

    #[test]
    fn test_fnv1a_hash_deterministic() {
        let h1 = fnv1a_hash(b"google.com");
        let h2 = fnv1a_hash(b"google.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a_hash_different_inputs() {
        let h1 = fnv1a_hash(b"google.com");
        let h2 = fnv1a_hash(b"example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_fnv1a_hash_empty() {
        // FNV-1a-64 offset basis (should be returned unchanged for empty input)
        let h = fnv1a_hash(b"");
        assert_eq!(h, 0xcbf29ce484222325);
    }

    #[test]
    fn test_fnv1a_hash_non_empty() {
        let h = fnv1a_hash(b"a");
        assert_ne!(h, 0xcbf29ce484222325);
        assert_eq!(h, fnv1a_hash(b"a"));
    }

    #[test]
    fn test_fnv1a_hash_case_sensitive() {
        let h1 = fnv1a_hash(b"Google.com");
        let h2 = fnv1a_hash(b"google.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_batch_update_all_succeed() {
        let count =
            bpf_batch_update_simulated("test_map", 5, |i| Ok((vec![i as u8], vec![i as u8 + 100])))
                .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_batch_update_partial_failure() {
        let count = bpf_batch_update_simulated("test_map", 10, |i| {
            if i == 7 {
                anyhow::bail!("simulated key-already-exists at index {}", i);
            }
            Ok((vec![i as u8], vec![i as u8 + 100]))
        })
        .unwrap();
        assert_eq!(count, 7); // 0..7 succeeded, 7 failed
    }

    #[test]
    fn test_batch_update_single_entry() {
        let count = bpf_batch_update_simulated("single_map", 1, |_i| {
            Ok((b"key".to_vec(), b"val".to_vec()))
        })
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_batch_update_empty() {
        let count = bpf_batch_update_simulated("empty_map", 0, |_| unreachable!()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_batch_delete_all_succeed() {
        let keys: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        let mut deleted_indices = Vec::new();

        let count = bpf_batch_delete_simulated("test_map", &keys, |key| {
            deleted_indices.push(key[0] as usize);
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 5);
        assert_eq!(deleted_indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test_batch_delete_key_not_found() {
        let keys: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8]).collect();
        let mut deleted_indices = Vec::new();

        let count = bpf_batch_delete_simulated("test_map", &keys, |key| {
            let idx = key[0] as usize;
            if idx == 2 {
                anyhow::bail!("key not found");
            }
            deleted_indices.push(idx);
            Ok(())
        })
        .unwrap();

        // 4 out of 5 succeeded (index 2 was "not found" → skipped)
        assert_eq!(count, 4);
        assert_eq!(deleted_indices, vec![0, 1, 3, 4]);
    }

    #[test]
    fn test_batch_delete_empty_keys() {
        let keys: &[Vec<u8>] = &[];
        let count = bpf_batch_delete_simulated("empty_map", keys, |_| unreachable!()).unwrap();
        assert_eq!(count, 0);
    }
}
