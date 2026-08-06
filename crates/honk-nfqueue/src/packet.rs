//! NFQA_PACKET attribute parsing and IPv4/IPv6/UDP header parsing.
//!
//! The listener receives the whole L3 packet (NFQNL_COPY_PACKET); this
//! module turns it into a typed [`QueuedPacket`] plus, when the headers
//! allow it, a UDP five-tuple and payload offset.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::netlink;

// nfnetlink_queue attribute ids (enum nfqnl_attr_type, shared by PACKET and
// VERDICT messages).
pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_MARK: u16 = 3;
pub const NFQA_IFINDEX_INDEV: u16 = 5;
pub const NFQA_PAYLOAD: u16 = 10;

const IPPROTO_UDP: u8 = 17;
const IPPROTO_FRAGMENT: u8 = 44;

/// One packet received from an NFQUEUE queue.
#[derive(Debug)]
pub struct QueuedPacket {
    /// Queue the packet arrived on (kernel flow-hash selected it).
    pub queue_num: u16,
    /// Kernel-side packet id; the verdict echoes it back.
    pub packet_id: u32,
    /// skb->mark at queue time (carries NFQUEUE_PENDING_MARK).
    pub mark: u32,
    /// Ingress ifindex (0 when the kernel did not attach it).
    pub in_ifindex: u32,
    /// Whole L3 packet as copied by the kernel.
    pub payload: Vec<u8>,
}

/// A parsed UDP five-tuple plus the offset of the UDP payload inside
/// [`QueuedPacket::payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
}

/// Parse the NFQA attribute block of one NFQA_MSG_PACKET message body.
/// The body starts with the nfgenmsg (4 bytes), then attributes.
/// `queue_num` comes from the message's nfgenmsg res_id.
pub fn parse_packet_msg(body: &[u8], queue_num: u16) -> Option<QueuedPacket> {
    if body.len() < netlink::NFGENMSG_LEN {
        return None;
    }
    let mut packet_id = None;
    let mut mark = 0u32;
    let mut in_ifindex = 0u32;
    let mut payload = None;
    for attr in netlink::attrs(&body[netlink::NFGENMSG_LEN..]) {
        match attr.attr_type {
            NFQA_PACKET_HDR => {
                // struct nfqnl_msg_packet_hdr { __be32 packet_id; __be16 hw_protocol; __u8 hook; }
                if attr.payload.len() >= 4 {
                    packet_id = Some(u32::from_be_bytes(attr.payload[..4].try_into().ok()?));
                }
            }
            NFQA_MARK => {
                if attr.payload.len() >= 4 {
                    mark = u32::from_be_bytes(attr.payload[..4].try_into().ok()?);
                }
            }
            NFQA_IFINDEX_INDEV => {
                if attr.payload.len() >= 4 {
                    in_ifindex = u32::from_be_bytes(attr.payload[..4].try_into().ok()?);
                }
            }
            NFQA_PAYLOAD => payload = Some(attr.payload),
            _ => {}
        }
    }
    Some(QueuedPacket {
        queue_num,
        packet_id: packet_id?,
        mark,
        in_ifindex,
        payload: payload?.to_vec(),
    })
}

/// Parse the UDP five-tuple of an L3 packet.  Returns `None` for
/// non-UDP packets and for fragments that do not carry a full UDP header
/// (non-first fragments, or a fragmented IPv6 packet): the caller falls
/// back to tuple-less handling for those.
pub fn parse_udp_tuple(packet: &[u8]) -> Option<UdpTuple> {
    let version = packet.first()? >> 4;
    match version {
        4 => parse_ipv4_udp(packet),
        6 => parse_ipv6_udp(packet),
        _ => None,
    }
}

fn parse_ipv4_udp(packet: &[u8]) -> Option<UdpTuple> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl + 8 {
        return None;
    }
    // Flags+offset live in bytes 6..8; the low 13 bits are the fragment
    // offset.  Only the first fragment (offset 0) carries the UDP header.
    let frag_field = u16::from_be_bytes([packet[6], packet[7]]);
    if frag_field & 0x1FFF != 0 {
        return None;
    }
    if packet[9] != IPPROTO_UDP {
        return None;
    }
    let udp = &packet[ihl..];
    Some(UdpTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        dst_ip: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload_offset: ihl + 8,
    })
}

fn parse_ipv6_udp(packet: &[u8]) -> Option<UdpTuple> {
    if packet.len() < 48 {
        return None;
    }
    let mut next_header = packet[6];
    let mut offset = 40usize;
    // Walk extension headers; only the ones with a length field can be
    // skipped generically.  A fragment header with a nonzero offset (or M
    // flag) means the UDP header is not here.
    loop {
        match next_header {
            IPPROTO_UDP => break,
            IPPROTO_FRAGMENT => {
                if packet.len() < offset + 8 {
                    return None;
                }
                // Fragment header bytes 2..3: offset (13 bits) + res + M.
                // Only a nonzero offset hides the UDP header.
                let frag_field = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if frag_field & 0xFFF8 != 0 {
                    return None;
                }
                next_header = packet[offset];
                offset += 8;
            }
            // hop-by-hop, destination options, routing: len in 8-octet units
            0 | 43 | 60 => {
                if packet.len() < offset + 2 {
                    return None;
                }
                let hdr_len = (packet[offset + 1] as usize + 1) * 8;
                next_header = packet[offset];
                offset += hdr_len;
            }
            _ => return None,
        }
    }
    if packet.len() < offset + 8 {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);
    let udp = &packet[offset..];
    Some(UdpTuple {
        src_ip: IpAddr::V6(Ipv6Addr::from(src)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(dst)),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload_offset: offset + 8,
    })
}

impl QueuedPacket {
    pub fn udp_tuple(&self) -> Option<UdpTuple> {
        parse_udp_tuple(&self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp_packet(frag_field: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + 4];
        p[0] = 0x45; // v4, IHL 5
        p[6..8].copy_from_slice(&frag_field.to_be_bytes());
        p[9] = IPPROTO_UDP;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[203, 0, 113, 7]);
        p[20..22].copy_from_slice(&53000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[28..32].copy_from_slice(b"data");
        p
    }

    #[test]
    fn parses_ipv4_udp() {
        let p = ipv4_udp_packet(0);
        let t = parse_udp_tuple(&p).unwrap();
        assert_eq!(t.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(t.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(t.src_port, 53000);
        assert_eq!(t.dst_port, 443);
        assert_eq!(&p[t.payload_offset..], b"data");
    }

    #[test]
    fn first_fragment_parses_later_fragments_do_not() {
        // MF set, offset 0: first fragment carries the UDP header.
        assert!(parse_udp_tuple(&ipv4_udp_packet(0x2000)).is_some());
        // Offset != 0: no UDP header here.
        assert!(parse_udp_tuple(&ipv4_udp_packet(0x0008)).is_none());
    }

    #[test]
    fn parses_ipv6_udp_without_extension_headers() {
        let mut p = vec![0u8; 40 + 8 + 3];
        p[0] = 0x60;
        p[6] = IPPROTO_UDP;
        p[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        p[40..42].copy_from_slice(&1234u16.to_be_bytes());
        p[42..44].copy_from_slice(&53u16.to_be_bytes());
        p[48..51].copy_from_slice(b"abc");
        let t = parse_udp_tuple(&p).unwrap();
        assert_eq!(t.src_port, 1234);
        assert_eq!(t.dst_port, 53);
        assert_eq!(&p[t.payload_offset..], b"abc");
    }

    #[test]
    fn ipv6_fragment_offset_rejected() {
        let mut p = vec![0u8; 40 + 8 + 8];
        p[0] = 0x60;
        p[6] = IPPROTO_FRAGMENT;
        // fragment header: next=UDP, frag offset field nonzero
        p[40] = IPPROTO_UDP;
        p[42..44].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse_udp_tuple(&p).is_none());
        // First fragment (offset 0; M set) still carries the UDP header.
        p[42..44].copy_from_slice(&1u16.to_be_bytes());
        p[48..50].copy_from_slice(&1u16.to_be_bytes());
        p[50..52].copy_from_slice(&2u16.to_be_bytes());
        let t = parse_udp_tuple(&p).unwrap();
        assert_eq!(t.src_port, 1);
    }

    #[test]
    fn packet_msg_requires_hdr_and_payload() {
        // nfgenmsg (4) + PACKET_HDR + MARK + PAYLOAD
        let mut body = vec![0u8; 4];
        netlink::put_attr(&mut body, NFQA_PACKET_HDR, &[0, 0, 0, 7, 0x08, 0, 0]);
        netlink::put_attr_be32(&mut body, NFQA_MARK, 0x2000_0000);
        netlink::put_attr(&mut body, NFQA_PAYLOAD, b"l3packet");
        let pkt = parse_packet_msg(&body, 3).unwrap();
        assert_eq!(pkt.packet_id, 7);
        assert_eq!(pkt.queue_num, 3);
        assert_eq!(pkt.mark, 0x2000_0000);
        assert_eq!(pkt.payload, b"l3packet");

        let mut bad = vec![0u8; 4];
        netlink::put_attr(&mut bad, NFQA_MARK, &[0, 0, 0, 0]);
        assert!(parse_packet_msg(&bad, 0).is_none());
    }
}
