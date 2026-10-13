use std::io;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::addr;

pub(crate) const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub(crate) const MAX_PACKET_SIZE: usize = u16::MAX as usize;
#[cfg(any(feature = "rprx", test))]
const MAX_BUFFERED_BYTES: usize = 2 * (2 + MAX_PACKET_SIZE);
pub(crate) const V1_ATYP_V4: u8 = 0x00;
pub(crate) const V1_ATYP_V6: u8 = 0x01;
pub(crate) const V1_ATYP_DOMAIN: u8 = 0x02;

pub(crate) trait UotCodec {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UotV1;

impl UotV1 {
    pub(crate) fn header(data: &[u8]) -> io::Result<Option<(usize, usize)>> {
        if data.is_empty() {
            return Ok(None);
        }
        let address_len = match data[0] {
            V1_ATYP_V4 => 4,
            V1_ATYP_V6 => 16,
            V1_ATYP_DOMAIN => {
                let Some(length) = data.get(1) else {
                    return Ok(None);
                };
                1 + usize::from(*length)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid UoT v1 packet header",
                ));
            }
        };
        let payload_start = 1 + address_len + 2 + 2;
        if data.len() < payload_start {
            return Ok(None);
        }
        let length_at = payload_start - 2;
        let payload_len = u16::from_be_bytes([data[length_at], data[length_at + 1]]) as usize;
        Ok(Some((payload_start, payload_len)))
    }

    /// Encode `prefix` (a pending UoT request, or empty) followed by one v1
    /// packet `[ATYP][address][port][u16 length][payload]` into a single
    /// buffer. Packet ATYPs (IPv4=0, IPv6=1, domain=2) differ from the SOCKS5
    /// numbering of the request address.
    pub(crate) fn encode(
        prefix: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        max_payload: usize,
    ) -> io::Result<Bytes> {
        validate_packet_len(data, max_payload)?;
        if target_domain
            .is_some_and(|domain| domain.is_empty() || domain.len() > usize::from(u8::MAX))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy target domain must contain 1..=255 bytes",
            ));
        }
        let address_len = match (target_domain, target) {
            (Some(domain), _) => 1 + domain.len(),
            (None, SocketAddr::V4(_)) => 4,
            (None, SocketAddr::V6(_)) => 16,
        };
        let mut frame =
            BytesMut::with_capacity(prefix.len() + 1 + address_len + 2 + 2 + data.len());
        frame.extend_from_slice(prefix);
        match (target_domain, target) {
            (Some(domain), _) => {
                frame.put_u8(V1_ATYP_DOMAIN);
                frame.put_u8(domain.len() as u8);
                frame.extend_from_slice(domain.as_bytes());
            }
            (None, SocketAddr::V4(target)) => {
                frame.put_u8(V1_ATYP_V4);
                frame.extend_from_slice(&target.ip().octets());
            }
            (None, SocketAddr::V6(target)) => {
                frame.put_u8(V1_ATYP_V6);
                frame.extend_from_slice(&target.ip().octets());
            }
        }
        frame.put_u16(target.port());
        frame.put_u16(data.len() as u16);
        frame.extend_from_slice(data);
        Ok(frame.freeze())
    }

    /// Real peer of a validated frame whose bytes up to the payload are
    /// `header`. Numeric peers are returned (IPv4-mapped IPv6 as IPv4); a
    /// domain is accepted only when it is the captured `target_domain` and
    /// port, then projected to `target`. Anything else is `None`: the caller
    /// drops the frame without resolving the name.
    pub(crate) fn source(
        header: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> Option<SocketAddr> {
        let port_at = header.len() - 4;
        let port = u16::from_be_bytes([header[port_at], header[port_at + 1]]);
        match header[0] {
            V1_ATYP_V4 => {
                let ip: [u8; 4] = header[1..5].try_into().ok()?;
                Some(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
            }
            V1_ATYP_V6 => {
                let ip: [u8; 16] = header[1..17].try_into().ok()?;
                Some(SocketAddr::new(
                    std::net::Ipv6Addr::from(ip).to_canonical(),
                    port,
                ))
            }
            _ => (port == target.port()
                && target_domain?
                    .as_bytes()
                    .eq_ignore_ascii_case(&header[2..port_at]))
            .then_some(target),
        }
    }
}

impl UotCodec for UotV1 {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>> {
        let Some((payload_start, payload_len)) = Self::header(data)? else {
            return Ok(None);
        };
        let frame_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UoT datagram"))?;
        Ok((data.len() >= frame_end).then_some(FrameBounds {
            payload_start,
            frame_end,
        }))
    }
}

#[cfg(any(feature = "rprx", test))]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UotV2;

/// `connect` is the UoT v2 `isConnect` bit: a connected stream carries bare
/// `[u16 length][payload]` packets, otherwise every packet carries its own
/// address ([`UotV1`] layout) in both directions. The request address is
/// SOCKS5-encoded either way.
pub(crate) fn request(
    connect: bool,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> io::Result<Bytes> {
    let mut request = vec![u8::from(connect)];
    request.extend(addr::encode_address(target, target_domain)?);
    Ok(Bytes::from(request))
}

#[cfg(any(feature = "rprx", test))]
pub(crate) fn encode_packet(data: &[u8], max_payload: usize) -> io::Result<Bytes> {
    validate_packet_len(data, max_payload)?;
    let mut frame = BytesMut::with_capacity(2 + data.len());
    frame.put_u16(data.len() as u16);
    frame.extend_from_slice(data);
    Ok(frame.freeze())
}

pub(crate) fn validate_packet_len(data: &[u8], max_payload: usize) -> io::Result<()> {
    if data.len() > max_payload.min(MAX_PACKET_SIZE) {
        return Err(super::PacketRejection::InvalidSize.into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct FrameBounds {
    pub(crate) payload_start: usize,
    pub(crate) frame_end: usize,
}

#[cfg(any(feature = "rprx", test))]
impl UotCodec for UotV2 {
    fn frame_bounds(data: &[u8]) -> io::Result<Option<FrameBounds>> {
        if data.len() < 2 {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let frame_end = 2usize
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid UoT datagram"))?;
        Ok((data.len() >= frame_end).then_some(FrameBounds {
            payload_start: 2,
            frame_end,
        }))
    }
}

pub(crate) fn copy_frame(
    buffered: &mut BytesMut,
    frame: FrameBounds,
    output: &mut [u8],
) -> io::Result<usize> {
    let payload_len = frame.frame_end - frame.payload_start;
    if payload_len > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UoT datagram exceeds buffer",
        ));
    }
    output[..payload_len].copy_from_slice(&buffered[frame.payload_start..frame.frame_end]);
    buffered.advance(frame.frame_end);
    Ok(payload_len)
}

#[cfg(any(feature = "rprx", test))]
#[derive(Default)]
pub(crate) struct Decoder {
    buffered: BytesMut,
}

#[cfg(any(feature = "rprx", test))]
impl Decoder {
    pub(crate) fn push(&mut self, data: &[u8]) -> io::Result<()> {
        if self.buffered.len().saturating_add(data.len()) > MAX_BUFFERED_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT stream frame exceeds buffer limit",
            ));
        }
        self.buffered.extend_from_slice(data);
        Ok(())
    }

    pub(crate) fn next_packet(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        let Some(frame) = UotV2::frame_bounds(&self.buffered)? else {
            return Ok(None);
        };
        copy_frame(&mut self.buffered, frame, output).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_overlong_domain() {
        let target = "127.0.0.1:53".parse().unwrap();
        assert!(request(true, target, Some(&"a".repeat(255))).is_ok());
        let error = request(true, target, Some(&"a".repeat(256))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn request_mode_byte_and_socks_address() {
        let target = "192.0.2.7:5353".parse().unwrap();
        assert_eq!(
            request(true, target, None).unwrap().as_ref(),
            [1, 1, 192, 0, 2, 7, 0x14, 0xe9]
        );
        assert_eq!(
            request(false, target, Some("a.b")).unwrap().as_ref(),
            [0, 3, 3, b'a', b'.', b'b', 0x14, 0xe9]
        );
    }

    #[test]
    fn codec_supports_full_packets_and_preserves_short_buffer_frames() {
        let payload = vec![0x5a; MAX_PACKET_SIZE];
        let frame = encode_packet(&payload, MAX_PACKET_SIZE).unwrap();
        assert!(encode_packet(&[0; 1], 0).is_err());

        let mut decoder = Decoder::default();
        decoder.push(&frame[..123]).unwrap();
        assert!(decoder.next_packet(&mut []).unwrap().is_none());
        decoder.push(&frame[123..]).unwrap();
        assert!(decoder.next_packet(&mut [0; 1]).is_err());

        let mut output = vec![0; MAX_PACKET_SIZE];
        assert_eq!(
            decoder.next_packet(&mut output).unwrap(),
            Some(MAX_PACKET_SIZE)
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn decoder_preserves_coalesced_packets() {
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&encode_packet(b"first", MAX_PACKET_SIZE).unwrap());
        wire.extend_from_slice(&encode_packet(b"second", MAX_PACKET_SIZE).unwrap());
        let mut decoder = Decoder::default();
        decoder.push(&wire).unwrap();
        let mut output = [0; 8];
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(5));
        assert_eq!(&output[..5], b"first");
        assert_eq!(decoder.next_packet(&mut output).unwrap(), Some(6));
        assert_eq!(&output[..6], b"second");
    }

    #[test]
    fn v1_and_v2_share_the_bounded_codec_contract() {
        let v1 = [V1_ATYP_V4, 1, 2, 3, 4, 0, 53, 0, 3, b'a', b'b', b'c'];
        assert!(UotV1::frame_bounds(&v1[..11]).unwrap().is_none());
        let bounds = UotV1::frame_bounds(&v1).unwrap().unwrap();
        assert_eq!(bounds.payload_start, 9);
        assert_eq!(bounds.frame_end, 12);
        assert!(UotV1::frame_bounds(&[0xff]).is_err());

        let v2 = encode_packet(b"abc", MAX_PACKET_SIZE).unwrap();
        let bounds = UotV2::frame_bounds(&v2).unwrap().unwrap();
        assert_eq!(bounds.payload_start, 2);
        assert_eq!(bounds.frame_end, 5);
    }
}
