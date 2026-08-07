//! DoH-style (RFC 8484 JSON, Google/Cloudflare flavor) helpers for the
//! clash API `/dns/query` endpoint: qtype parsing plus a minimal
//! wire-format answer-section parser that renders records as
//! `{"name","type","TTL","data"}` objects.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse a `?type=` query value into a numeric DNS qtype. Accepts common
/// record names (case-insensitive) or a decimal number.
pub fn parse_qtype(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "CAA" => Some(257),
        _ => s.parse::<u16>().ok(),
    }
}

/// Extract the RCODE (low nibble of the flags low byte) from a wire-format
/// DNS response; malformed messages report SERVFAIL (2).
pub fn rcode(resp: &[u8]) -> u8 {
    resp.get(3).map(|b| b & 0x0F).unwrap_or(2)
}

/// One parsed answer record in DoH JSON shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohAnswer {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: String,
}

impl DohAnswer {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "type": self.rtype,
            "TTL": self.ttl,
            "data": self.data,
        })
    }
}

/// Build the DoH-style response document for a resolved wire message.
pub fn response_json(name: &str, qtype: u16, resp: &[u8]) -> serde_json::Value {
    let answers: Vec<serde_json::Value> =
        parse_answers(resp).iter().map(DohAnswer::to_json).collect();
    serde_json::json!({
        "Status": rcode(resp),
        "Question": [{"name": name, "type": qtype}],
        "Answer": answers,
    })
}

/// Parse the answer section of a wire-format DNS response. Truncated or
/// malformed messages yield whatever records could be read (possibly none).
pub fn parse_answers(msg: &[u8]) -> Vec<DohAnswer> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let Some((_, next)) = decode_name(msg, pos) else {
            return out;
        };
        pos = next.saturating_add(4); // QTYPE + QCLASS
        if pos > msg.len() {
            return out;
        }
    }

    for _ in 0..ancount {
        let Some((name, next)) = decode_name(msg, pos) else {
            break;
        };
        pos = next;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata_offset = pos + 10;
        if rdata_offset + rdlength > msg.len() {
            break;
        }
        let rdata = &msg[rdata_offset..rdata_offset + rdlength];
        out.push(DohAnswer {
            name,
            rtype,
            ttl,
            data: format_rdata(msg, rtype, rdata, rdata_offset),
        });
        pos = rdata_offset + rdlength;
    }
    out
}

/// Decode a (possibly compressed) DNS name starting at `start`.
/// Returns the dotted name and the offset just past the name in the
/// original parse direction (past the first compression pointer).
fn decode_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut next = None;
    let mut jumps = 0usize;

    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 2 > msg.len() || jumps >= 10 {
                return None;
            }
            jumps += 1;
            let offset = ((len & 0x3F) << 8) | (msg[pos + 1] as usize);
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = offset;
            continue;
        }
        if len == 0 {
            return Some((labels.join("."), next.unwrap_or(pos + 1)));
        }
        if len > 63 || pos + 1 + len > msg.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&msg[pos + 1..pos + 1 + len])
                .ok()?
                .to_string(),
        );
        pos += 1 + len;
    }
}

/// Render RDATA in the text form DoH clients expect. Unknown record types
/// fall back to RFC 3597 `\# <len> <hex>` generic syntax.
fn format_rdata(msg: &[u8], rtype: u16, rdata: &[u8], rdata_offset: usize) -> String {
    match rtype {
        1 if rdata.len() == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ipv6Addr::from(octets).to_string()
        }
        // CNAME / NS / PTR: a single (possibly compressed) domain name.
        5 | 2 | 12 => decode_name(msg, rdata_offset)
            .map(|(name, _)| name)
            .unwrap_or_else(|| generic_rdata(rdata)),
        // MX: preference + exchange name.
        15 if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            match decode_name(msg, rdata_offset + 2) {
                Some((name, _)) => format!("{} {}", pref, name),
                None => generic_rdata(rdata),
            }
        }
        // TXT: one or more <len><text> character-strings.
        16 => {
            let mut text = String::new();
            let mut pos = 0usize;
            while pos < rdata.len() {
                let seg_len = rdata[pos] as usize;
                pos += 1;
                if pos + seg_len > rdata.len() {
                    return generic_rdata(rdata);
                }
                text.push_str(&String::from_utf8_lossy(&rdata[pos..pos + seg_len]));
                pos += seg_len;
            }
            format!("\"{}\"", text)
        }
        // SRV: priority weight port target.
        33 if rdata.len() >= 7 => {
            let prio = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            match decode_name(msg, rdata_offset + 6) {
                Some((name, _)) => format!("{} {} {} {}", prio, weight, port, name),
                None => generic_rdata(rdata),
            }
        }
        _ => generic_rdata(rdata),
    }
}

/// RFC 3597 generic RDATA representation: `\# <rdlength> <hex>`.
fn generic_rdata(rdata: &[u8]) -> String {
    let hex: String = rdata.iter().map(|b| format!("{:02X}", b)).collect();
    format!("\\# {} {}", rdata.len(), hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-record response for example.com → 93.184.216.34, TTL 300.
    fn a_response() -> Vec<u8> {
        let ttl = 300u32.to_be_bytes();
        vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // qname
            0x00, 0x01, 0x00, 0x01, // qtype A, qclass IN
            0xc0, 0x0c, // name pointer
            0x00, 0x01, 0x00, 0x01, // type A, class IN
            ttl[0], ttl[1], ttl[2], ttl[3], // TTL
            0x00, 0x04, 93, 184, 216, 34, // rdlength + rdata
        ]
    }

    #[test]
    fn parses_a_record_answers() {
        let answers = parse_answers(&a_response());
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rtype, 1);
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[0].data, "93.184.216.34");
    }

    #[test]
    fn rcode_extraction() {
        assert_eq!(rcode(&a_response()), 0);
        let mut nx = a_response();
        nx[3] = 0x83; // NXDOMAIN
        assert_eq!(rcode(&nx), 3);
        assert_eq!(rcode(&[0u8; 3]), 2);
    }

    #[test]
    fn response_json_shape() {
        let v = response_json("example.com", 1, &a_response());
        assert_eq!(v["Status"], 0);
        assert_eq!(v["Question"][0]["name"], "example.com");
        assert_eq!(v["Answer"][0]["data"], "93.184.216.34");
        assert_eq!(v["Answer"][0]["TTL"], 300);
    }

    #[test]
    fn qtype_names_and_numbers() {
        assert_eq!(parse_qtype("A"), Some(1));
        assert_eq!(parse_qtype("aaaa"), Some(28));
        assert_eq!(parse_qtype("HTTPS"), Some(65));
        assert_eq!(parse_qtype("255"), Some(255));
        assert_eq!(parse_qtype("bogus"), None);
    }

    #[test]
    fn txt_and_generic_rdata() {
        // TXT record with two character-strings.
        let mut msg = a_response();
        // Patch answer: type TXT(16), rdata = [3]"foo" [3]"bar"
        let pos = msg.len() - 10 - 4; // start of the 10-byte rr fixed fields (TYPE..)
        msg[pos] = 0x00;
        msg[pos + 1] = 16; // TYPE = TXT
        msg.truncate(pos + 8); // keep through TTL; drop old rdlength + rdata
        let rdata = [3u8, b'f', b'o', b'o', 3, b'b', b'a', b'r'];
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&rdata);
        let answers = parse_answers(&msg);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].data, "\"foobar\"");

        // Unknown type 99 → RFC 3597 generic syntax.
        assert_eq!(generic_rdata(&[0xde, 0xad]), "\\# 2 DEAD");
    }

    #[test]
    fn truncated_message_yields_no_answers() {
        assert!(parse_answers(&[0u8; 5]).is_empty());
        let mut trunc = a_response();
        trunc.truncate(20);
        assert!(parse_answers(&trunc).is_empty());
    }
}
