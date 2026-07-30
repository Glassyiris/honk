use std::net::{IpAddr, SocketAddr};

use super::AsIsExchangeError;

pub(super) fn new_asis_socket_with_mark(
    destination: SocketAddr,
    mark: impl FnOnce(&socket2::Socket) -> std::io::Result<()>,
) -> Result<socket2::Socket, AsIsExchangeError> {
    let domain = if destination.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)
        .map_err(|source| AsIsExchangeError::Socket { source })?;
    socket
        .set_nonblocking(true)
        .map_err(|source| AsIsExchangeError::Nonblocking { source })?;
    mark(&socket).map_err(|source| AsIsExchangeError::BypassMark { source })?;
    let bind_address = SocketAddr::new(
        if destination.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    socket
        .bind(&bind_address.into())
        .map_err(|source| AsIsExchangeError::Bind { source })?;
    Ok(socket)
}

/// Build a minimal DNS query for the given domain and query type.
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let qname = encode_dns_name(domain);
    let mut query = Vec::with_capacity(12 + qname.len() + 4);

    // Header: ID=0, flags=0x0100 (RD), QDCOUNT=1, rest=0
    query.extend_from_slice(&[0x00, 0x00]); // ID
    query.extend_from_slice(&[0x01, 0x00]); // Flags (recursion desired)
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    query.extend_from_slice(&qname);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    query
}

/// Encode a domain name into DNS label format.
///
/// Example: `"example.com"` → `[0x07, b'e', ..., 0x03, b'c', b'o', b'm', 0x00]`
fn encode_dns_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.split('.') {
        if label.len() > 63 {
            continue; // skip invalid labels
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0x00); // terminator
    encoded
}

/// Parse the first question from a raw DNS query.
///
/// Returns the domain name and QTYPE on success, or `None` if the
/// message is truncated or malformed.
pub fn parse_dns_question(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 16 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12; // skip 12-byte header
    let domain = decode_dns_name(data, &mut pos)?;

    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

    Some((domain, qtype))
}

/// Decode a DNS name starting at `pos`, advancing `pos` past the name.
fn decode_dns_name(data: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut jump_pos = *pos;
    let mut max_jumps = 10; // prevent pointer loops

    loop {
        if jump_pos >= data.len() {
            return None;
        }
        let len = data[jump_pos];

        // Compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            if jump_pos + 2 > data.len() || max_jumps == 0 {
                return None;
            }
            max_jumps -= 1;
            let offset = ((len as usize & 0x3F) << 8) | (data[jump_pos + 1] as usize);
            if !jumped {
                *pos = jump_pos + 2; // advance past the pointer bytes
            }
            jump_pos = offset;
            jumped = true;
            continue;
        }

        if len == 0 {
            if !jumped {
                *pos = jump_pos + 1;
            }
            break;
        }

        if len > 63 {
            return None; // malformed label length
        }

        jump_pos += 1;
        if jump_pos + len as usize > data.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&data[jump_pos..jump_pos + len as usize])
                .ok()?
                .to_ascii_lowercase(),
        );
        jump_pos += len as usize;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Resolve the TTL used for positive cache inserts.
///
/// `configured` is `dns.cache.ttl` / `optimistic_cache_ttl`. Non-zero values
/// win (fixed override); `0` keeps the answer-section minimum.
/// Extract A/AAAA answer IPs from a wire-format DNS response.
pub fn extract_answer_ips(data: &[u8]) -> Vec<IpAddr> {
    crate::dns::wire::extract_ips_from_dns_response(data)
}
