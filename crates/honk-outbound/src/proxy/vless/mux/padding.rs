//! sing-mux record padding around the H2MUX carrier and its physical preface.
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) const PADDED_RECORDS: u8 = 16;
const MAX_RECORD_DATA: usize = u16::MAX as usize;
pub(super) const H2MUX_BACKEND: u8 = 2;

#[derive(Default)]
struct PaddingReadState {
    records: u8,
    header: [u8; 4],
    header_len: usize,
    data_remaining: usize,
    padding_remaining: usize,
}

#[derive(Default)]
struct PaddingWriteState {
    records: u8,
    pending: Option<Bytes>,
    offset: usize,
}

pub(super) struct PaddingStream<S> {
    inner: S,
    enabled: bool,
    read: PaddingReadState,
    write: PaddingWriteState,
}

impl<S> PaddingStream<S> {
    pub(super) fn new(inner: S, enabled: bool) -> Self {
        Self {
            inner,
            enabled,
            read: PaddingReadState::default(),
            write: PaddingWriteState::default(),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for PaddingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.enabled
            || (self.read.records >= PADDED_RECORDS
                && self.read.data_remaining == 0
                && self.read.padding_remaining == 0
                && self.read.header_len == 0)
        {
            return Pin::new(&mut self.inner).poll_read(cx, output);
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.read.data_remaining != 0 {
                let limit = self.read.data_remaining.min(output.remaining());
                let target = output.initialize_unfilled_to(limit);
                let mut limited = ReadBuf::new(target);
                match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = limited.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        output.advance(read);
                        self.read.data_remaining -= read;
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            if self.read.padding_remaining != 0 {
                let mut scratch = [0; 1024];
                let limit = self.read.padding_remaining.min(scratch.len());
                let mut discard = ReadBuf::new(&mut scratch[..limit]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut discard) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        let read = discard.filled().len();
                        if read == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        self.read.padding_remaining -= read;
                        continue;
                    }
                }
            }

            if self.read.records >= PADDED_RECORDS {
                return Pin::new(&mut self.inner).poll_read(cx, output);
            }

            let header_len = self.read.header_len;
            let mut bytes = [0; 4];
            let mut header = ReadBuf::new(&mut bytes[..4 - header_len]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut header) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let read = header.filled().len();
                    if read == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    self.read.header[header_len..header_len + read]
                        .copy_from_slice(&header.filled()[..read]);
                    self.read.header_len += read;
                    if self.read.header_len != 4 {
                        continue;
                    }
                    self.read.data_remaining =
                        u16::from_be_bytes([self.read.header[0], self.read.header[1]]) as usize;
                    self.read.padding_remaining =
                        u16::from_be_bytes([self.read.header[2], self.read.header[3]]) as usize;
                    self.read.header_len = 0;
                    self.read.records += 1;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> PaddingStream<S> {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(frame) = self.write.pending.as_ref() {
            match Pin::new(&mut self.inner).poll_write(cx, &frame[self.write.offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    self.write.offset += written;
                    if self.write.offset == frame.len() {
                        self.write.pending = None;
                        self.write.offset = 0;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.enabled {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        match self.poll_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if self.write.records >= PADDED_RECORDS {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let data_len = data.len().min(MAX_RECORD_DATA);
        let padding_len = rand::rng().random_range(256..768);
        let mut frame = BytesMut::with_capacity(4 + data_len + padding_len);
        frame.extend_from_slice(&(data_len as u16).to_be_bytes());
        frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
        frame.extend_from_slice(&data[..data_len]);
        frame.resize(frame.len() + padding_len, 0);
        self.write.pending = Some(frame.freeze());
        self.write.records += 1;
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(data_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

pub(super) fn mux_preface(padded: bool) -> Bytes {
    if !padded {
        return Bytes::from_static(&[0, H2MUX_BACKEND]);
    }
    let padding_len = rand::rng().random_range(256..768);
    let mut preface = BytesMut::with_capacity(5 + padding_len);
    preface.extend_from_slice(&[1, H2MUX_BACKEND, 1]);
    preface.extend_from_slice(&(padding_len as u16).to_be_bytes());
    preface.resize(preface.len() + padding_len, 0);
    preface.freeze()
}
