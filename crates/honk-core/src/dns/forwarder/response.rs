use honk_config::dns::DnsStrategy;

use super::message::extract_answer_ips;

/// Build the cache key for a domain and query type.
pub(crate) fn dns_cache_key(domain: &str, qtype: u16) -> String {
    format!("{}:{}", domain, qtype)
}

/// Return `true` if the given query type is hard-filtered at request time.
/// Only the `*_only` strategies filter here; prefer strategies forward both
/// families and suppress at response time instead.
pub(crate) fn is_filtered_qtype(qtype: u16, strategy: &DnsStrategy) -> bool {
    match strategy {
        DnsStrategy::Ipv4Only => qtype == 28, // AAAA
        DnsStrategy::Ipv6Only => qtype == 1,  // A
        DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 | DnsStrategy::Both => false,
    }
}

/// Whether a wire-format response contains at least one address record of
/// the given family (qtype 1 = A, 28 = AAAA).
pub(super) fn response_has_family_ips(response: &[u8], qtype: u16) -> bool {
    extract_answer_ips(response).iter().any(|ip| match qtype {
        1 => ip.is_ipv4(),
        28 => ip.is_ipv6(),
        _ => false,
    })
}

/// Human-readable qtype name for logging.
pub(crate) fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        2 => "NS",
        _ => "OTHER",
    }
}

/// Build a NODATA response (NOERROR, zero answers) for a filtered query,
/// preserving the query's transaction ID and question section.
pub(crate) fn make_empty_response(query: &[u8], domain: &str, qtype: u16) -> Vec<u8> {
    let mut resp = Vec::with_capacity(256);
    // Transaction ID (first two bytes of the query).
    resp.extend_from_slice(&query[0..2.min(query.len())]);
    if query.len() >= 3 {
        // Set QR=1, preserve RD; keep OPCODE/AA/TC bits from the query.
        resp.push((query[2] & 0x7F) | 0x80);
    } else {
        resp.push(0x80);
    }
    // RA=1, RCODE=0.
    resp.push(0x80);
    // QDCOUNT = 1.
    resp.extend_from_slice(&1u16.to_be_bytes());
    // ANCOUNT, NSCOUNT, ARCOUNT = 0.
    resp.extend_from_slice(&[0u8; 6]);
    // Question section: encode domain labels.
    for label in domain.split('.') {
        resp.push(label.len() as u8);
        resp.extend_from_slice(label.as_bytes());
    }
    resp.push(0); // root label
    resp.extend_from_slice(&qtype.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    resp
}
