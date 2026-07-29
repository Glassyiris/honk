//! Shadowsocks TCP stream as an inline codec: `AsyncRead`/`AsyncWrite`
//! implemented directly over the server socket, no relay task and no
//! duplex. The control plane's `copy_bidirectional` drives
//! encryption/decryption in the caller's task, removing two task hops and
//! two copies per byte from the old `shadowsocks_relay` data path (single
//! core saturated ~1.15Gbps → target dae's 1.5Gbps+).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::shadowsocks::{AeadCipher, RELAY_BATCH, decrypt_chunks_in_place, seal_chunks_into};

/// Response-prologue driver for 2022 connections: read and validate the
/// server's salt + fixed header (+ first payload chunk) from the read
/// path, not inline in `dial` — servers only answer after the first client
/// payload chunk, so reading the response in `dial` deadlocks.
type PrologueFuture = Pin<
    Box<
        dyn std::future::Future<Output = io::Result<(OwnedReadHalf, AeadCipher, Vec<u8>, Vec<u8>)>>
            + Send,
    >,
>;

/// Stream state for one Shadowsocks TCP connection after the salt/header
/// prologue (which `dial` completes before returning this type).
pub(crate) struct SsStream {
    write_half: OwnedWriteHalf,
    /// Read half, parked inside the pending 2022 prologue future until the
    /// response header has been consumed.
    read_half: Option<OwnedReadHalf>,
    send_cipher: AeadCipher,
    send_nonce: Vec<u8>,
    /// Sealed output waiting to be flushed (poll_write seals once, then
    /// flushes across polls).
    send_buf: Vec<u8>,
    send_off: usize,
    recv_cipher: Option<AeadCipher>,
    recv_nonce: Vec<u8>,
    /// 2022 only: pending response prologue (salt + fixed header).
    recv_prologue: Option<PrologueFuture>,
    recv_pending_len: Option<u16>,
    /// Raw inbound bytes: plaintext at the front (`plain_start..plain_end`),
    /// undecrypted carry right after it (`carry` bytes).
    recv_buf: Vec<u8>,
    plain_start: usize,
    plain_end: usize,
    carry: usize,
}

impl SsStream {
    pub(crate) fn new(
        inner: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        recv_cipher: AeadCipher,
        recv_nonce: Vec<u8>,
    ) -> Self {
        let (read_half, write_half) = inner.into_split();
        Self {
            write_half,
            read_half: Some(read_half),
            send_cipher,
            send_nonce,
            send_buf: Vec::with_capacity(RELAY_BATCH + 8192),
            send_off: 0,
            recv_cipher: Some(recv_cipher),
            recv_nonce,
            recv_prologue: None,
            recv_pending_len: None,
            recv_buf: vec![0u8; RELAY_BATCH + 8192],
            plain_start: 0,
            plain_end: 0,
            carry: 0,
        }
    }

    /// 2022 constructor: the response prologue is deferred to the read
    /// path (see [`PrologueFuture`]).
    pub(crate) fn new_2022(
        inner: TcpStream,
        send_cipher: AeadCipher,
        send_nonce: Vec<u8>,
        prologue: Ss2022Prologue,
    ) -> Self {
        let (read_half, write_half) = inner.into_split();
        let recv_prologue: PrologueFuture = Box::pin(prologue.run(read_half));
        Self {
            write_half,
            read_half: None,
            send_cipher,
            send_nonce,
            send_buf: Vec::with_capacity(RELAY_BATCH + 8192),
            send_off: 0,
            recv_cipher: None,
            recv_nonce: vec![0u8; 12],
            recv_prologue: Some(recv_prologue),
            recv_pending_len: None,
            recv_buf: vec![0u8; RELAY_BATCH + 8192],
            plain_start: 0,
            plain_end: 0,
            carry: 0,
        }
    }

    fn tag_len(&self) -> usize {
        16
    }

    /// Preload decrypted plaintext (the prologue's first response chunk) so
    /// the first `poll_read` serves it before touching the socket.
    pub(crate) fn prefill_plaintext(&mut self, data: &[u8]) {
        self.recv_buf[..data.len()].copy_from_slice(data);
        self.plain_start = 0;
        self.plain_end = data.len();
    }
}

impl std::fmt::Debug for SsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsStream")
            .field("send_pending", &(self.send_buf.len() - self.send_off))
            .field("plain_pending", &(self.plain_end - self.plain_start))
            .field("carry", &self.carry)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Drive a pending 2022 response prologue first.
        if self.recv_prologue.is_some() {
            let this = self.as_mut().get_mut();
            let fut = this.recv_prologue.as_mut().expect("checked above");
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok((read_half, cipher, nonce, first_payload))) => {
                    this.read_half = Some(read_half);
                    this.recv_cipher = Some(cipher);
                    this.recv_nonce = nonce;
                    this.recv_prologue = None;
                    this.prefill_plaintext(&first_payload);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.plain_start == self.plain_end {
            // No buffered plaintext: pull and decrypt the next batch.
            // Greedily drain the socket while data is immediately
            // available — decrypt once per wakeup, not per read call.
            let this = self.as_mut().get_mut();
            let mut filled = 0usize;
            let mut eof = false;
            loop {
                let end = this.carry + filled;
                if end >= this.recv_buf.len() {
                    break; // batch full
                }
                let read_half = this.read_half.as_mut().expect("prologue completed");
                let mut read_buf = ReadBuf::new(&mut this.recv_buf[end..]);
                match Pin::new(read_half).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            eof = true;
                            break;
                        }
                        filled += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        if filled == 0 {
                            return Poll::Pending;
                        }
                        break;
                    }
                }
            }
            if filled == 0 && eof {
                // EOF with no plaintext left.
                return Poll::Ready(Ok(()));
            }
            let total = this.carry + filled;
            let tag_len = this.tag_len();
            let (out_len, rest) = decrypt_chunks_in_place(
                this.recv_cipher.as_ref().expect("prologue completed"),
                &mut this.recv_nonce,
                &mut this.recv_pending_len,
                &mut this.recv_buf,
                total,
                tag_len,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            this.plain_start = 0;
            this.plain_end = out_len;
            this.carry = rest;
            if out_len == 0 {
                // Only an incomplete chunk so far: the socket poll above
                // already registered the waker; it fires when more data
                // arrives. (Waking ourselves here would busy-spin.)
                return Poll::Pending;
            }
        }
        let avail = self.plain_end - self.plain_start;
        let n = avail.min(out.remaining());
        out.put_slice(&self.recv_buf[self.plain_start..self.plain_start + n]);
        self.plain_start += n;
        if self.plain_start == self.plain_end {
            // Plaintext drained: prepend the carry for the next batch.
            let rest = self.carry;
            let plain_end = self.plain_end;
            if rest > 0 {
                self.recv_buf.copy_within(plain_end..plain_end + rest, 0);
            }
            self.plain_start = 0;
            self.plain_end = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.send_off == this.send_buf.len() {
            // Nothing pending: seal the whole caller buffer as chunks.
            this.send_buf.clear();
            this.send_off = 0;
            seal_chunks_into(
                &this.send_cipher,
                &mut this.send_nonce,
                buf,
                &mut this.send_buf,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        }
        while this.send_off < this.send_buf.len() {
            let n = match Pin::new(&mut this.write_half)
                .poll_write(cx, &this.send_buf[this.send_off..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ss stream write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.send_off += n;
        }
        // Fully flushed: reset for the next write.
        this.send_buf.clear();
        this.send_off = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.send_off < this.send_buf.len() {
            let n = match Pin::new(&mut this.write_half)
                .poll_write(cx, &this.send_buf[this.send_off..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ss stream flush write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.send_off += n;
        }
        this.send_buf.clear();
        this.send_off = 0;
        Pin::new(&mut this.write_half).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.write_half).poll_shutdown(cx),
            other => other,
        }
    }
}

/// 2022 response prologue: everything needed to read and validate the
/// server's fixed response header once the request is out.
pub(crate) struct Ss2022Prologue {
    pub(crate) method: super::shadowsocks_2022::Ss2022Method,
    pub(crate) request_salt: Vec<u8>,
}

impl Ss2022Prologue {
    async fn run(
        self,
        mut read_half: OwnedReadHalf,
    ) -> io::Result<(OwnedReadHalf, AeadCipher, Vec<u8>, Vec<u8>)> {
        use super::shadowsocks::increment_nonce;
        use super::shadowsocks_2022::{NONCE_LEN, TAG_LEN, unix_timestamp};
        use anyhow::anyhow;
        let method = &self.method;

        let mut recv_salt = vec![0u8; method.key_len];
        read_half.read_exact(&mut recv_salt).await?;
        let recv_subkey = method.session_subkey(&recv_salt);
        let recv_cipher = method
            .aead(&recv_subkey)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut recv_nonce = vec![0u8; NONCE_LEN];

        let fixed_len = 1 + 8 + method.key_len + 2;
        let mut fixed_buf = vec![0u8; fixed_len + TAG_LEN];
        read_half.read_exact(&mut fixed_buf).await?;
        let fixed = recv_cipher
            .open(&recv_nonce, &fixed_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        increment_nonce(&mut recv_nonce);
        if fixed[0] != super::shadowsocks_2022::HEADER_TYPE_SERVER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad response header type {}", fixed[0]),
            ));
        }
        let ts = u64::from_be_bytes(fixed[1..9].try_into().expect("8-byte timestamp"));
        if unix_timestamp().abs_diff(ts) > 30 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad response timestamp",
            ));
        }
        if fixed[9..9 + method.key_len] != self.request_salt[..] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response request-salt mismatch",
            ));
        }
        let first_len = u16::from_be_bytes([fixed[fixed_len - 2], fixed[fixed_len - 1]]) as usize;

        let mut first = vec![0u8; first_len + TAG_LEN];
        read_half.read_exact(&mut first).await?;
        let first_payload = recv_cipher.open(&recv_nonce, &first).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, anyhow!("{e:?}").to_string())
        })?;
        increment_nonce(&mut recv_nonce);

        Ok((read_half, recv_cipher, recv_nonce, first_payload))
    }
}

/// Flush helper for the legacy prologue path (one-shot sealed write).
pub(crate) async fn write_all_sealed(
    inner: &mut TcpStream,
    cipher: &AeadCipher,
    nonce: &mut [u8],
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(payload.len() + 4096);
    seal_chunks_into(cipher, nonce, payload, &mut out)?;
    inner.write_all(&out).await?;
    Ok(())
}
