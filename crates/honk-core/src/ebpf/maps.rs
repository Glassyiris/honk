//! BPF map utilities for honk-core.
//!
//! This module provides LPM trie helpers and common utility functions used
//! by both real and mock eBPF backends. It does not depend on `aya`
//! directly, making it usable by all backends regardless of whether real
//! eBPF support is compiled in.

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

/// Convert an IP address into the exact host-prefix key used by the domain
/// routing LPM map without formatting or parsing a temporary CIDR string.
pub const fn ip_addr_to_lpm_key(ip: std::net::IpAddr) -> LpmKey {
    let (prefix_len, bytes) = match ip {
        std::net::IpAddr::V4(ip) => (128, ip.to_ipv6_mapped().octets()),
        std::net::IpAddr::V6(ip) => (128, ip.octets()),
    };
    LpmKey {
        prefix_len,
        data: [
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        ],
    }
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
}
