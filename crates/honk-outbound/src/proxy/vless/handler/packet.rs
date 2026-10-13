use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::MAX_NATIVE_PACKET_SIZE;
use crate::proxy::uot::{AddrDecoder, AddrFraming, Decoder, MAX_PACKET_SIZE};
use crate::proxy::{AsyncReadWrite, MultiTargetTransport, PacketTransport};

type Reader = tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>;

struct VlessPacketWriter {
    stream: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    /// UoT request, sent in front of the first datagram.
    setup: Option<bytes::Bytes>,
    pending: bool,
}

impl VlessPacketWriter {
    /// A partially written frame cannot be resumed, so an interrupted write
    /// poisons the stream. `observed` publishes the sending flow's first
    /// request milestone once the frame is delivered; `admitted` is set when
    /// the frame starts onto the wire.
    async fn write_frame(
        &mut self,
        frame: &[u8],
        observed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        if self.pending {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "VLESS packet write was interrupted",
            ));
        }
        self.pending = true;
        if let Some(admitted) = admitted {
            admitted.store(true, Ordering::Release);
        }
        let stream = &mut self.stream;
        let write = async {
            stream.write_all(frame).await?;
            stream.flush().await
        };
        if observed {
            crate::runtime::flow_observation::request_write(std::pin::pin!(write)).await?;
        } else {
            write.await?;
        }
        self.setup = None;
        self.pending = false;
        Ok(())
    }
}

async fn read_chunk(stream: &mut Reader, chunk: &mut [u8]) -> std::io::Result<usize> {
    let size = stream.read(chunk).await?;
    if size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "VLESS packet stream closed",
        ));
    }
    Ok(size)
}

/// Native command-UDP: one fixed target, bare `[u16 length][payload]` frames.
pub(super) struct VlessConnectedTransport {
    reader: tokio::sync::Mutex<(Reader, Decoder)>,
    writer: tokio::sync::Mutex<VlessPacketWriter>,
    target: SocketAddr,
}

impl VlessConnectedTransport {
    pub(super) fn new(stream: Box<dyn AsyncReadWrite>, target: SocketAddr) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new((reader, Decoder::default())),
            writer: tokio::sync::Mutex::new(VlessPacketWriter {
                stream: writer,
                setup: None,
                pending: false,
            }),
            target,
        }
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() || data.len() > MAX_NATIVE_PACKET_SIZE {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        let packet = crate::proxy::uot::encode_packet(data, MAX_PACKET_SIZE)?;
        self.writer
            .lock()
            .await
            .write_frame(&packet, false, None)
            .await
    }
}

impl std::fmt::Debug for VlessConnectedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConnectedTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketTransport for VlessConnectedTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let (stream, decoder) = &mut *reader;
        loop {
            if let Some(size) = decoder.next_packet(output)? {
                return Ok((size, self.target));
            }
            let mut chunk = [0; 16 * 1024];
            let size = read_chunk(stream, &mut chunk).await?;
            decoder.push(&chunk[..size])?;
        }
    }
}

/// Non-connect UoT v2 over a VLESS TCP command stream: the request names the
/// first destination, then every datagram in both directions carries its own
/// address, so one stream serves all destinations of a client source and
/// replies keep their real source. The request and first datagram share one
/// write; the open-time target is the default for ordinary sends and the only
/// domain a reply source may project back to.
pub(crate) struct VlessUotTransport {
    reader: tokio::sync::Mutex<(Reader, AddrDecoder)>,
    writer: tokio::sync::Mutex<VlessPacketWriter>,
    target: SocketAddr,
    target_domain: Option<Box<str>>,
}

impl VlessUotTransport {
    pub(super) fn new(
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        request: bytes::Bytes,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new((reader, AddrDecoder::new(AddrFraming::UOT_V1))),
            writer: tokio::sync::Mutex::new(VlessPacketWriter {
                stream: writer,
                setup: Some(request),
                pending: false,
            }),
            target,
            target_domain: target_domain.map(Box::from),
        }
    }

    /// The one send path of `send_packet`, `send_packet_confirmed` and `send_to`.
    async fn send_inner(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        let mut writer = self.writer.lock().await;
        let frame = AddrFraming::UOT_V1.encode(
            writer.setup.as_deref().unwrap_or_default(),
            target,
            domain,
            data,
            MAX_PACKET_SIZE,
        )?;
        writer.write_frame(&frame, confirmed, admitted).await
    }
}

impl std::fmt::Debug for VlessUotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessUotTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketTransport for VlessUotTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(
            self.target,
            self.target_domain.as_deref(),
            data,
            false,
            None,
        )
        .await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send_inner(self.target, self.target_domain.as_deref(), data, true, None)
            .await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let (stream, decoder) = &mut *reader;
        loop {
            if let Some(frame) =
                decoder.next_packet(output, self.target, self.target_domain.as_deref())?
            {
                match frame.packet {
                    Some(packet) => return Ok(packet),
                    None => continue,
                }
            }
            let mut chunk = [0; 16 * 1024];
            let size = read_chunk(stream, &mut chunk).await?;
            decoder.push(&chunk[..size])?;
        }
    }
}

#[async_trait]
impl MultiTargetTransport for VlessUotTransport {
    async fn send_to(
        &self,
        target: SocketAddr,
        domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
    ) -> std::io::Result<()> {
        let domain = crate::proxy::addr::dialed_name(self.target_domain.as_deref(), domain);
        self.send_inner(target, domain, data, confirmed, admitted)
            .await
    }
}
