use super::*;

// BLAKE2b-256 (RFC 7693) — salamander obfuscation key derivation.

pub(super) const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub(super) const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[allow(clippy::many_single_char_names)]
pub(super) fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for round in &BLAKE2B_SIGMA {
        #[inline(always)]
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }
        g(&mut v, 0, 4, 8, 12, m[round[0]], m[round[1]]);
        g(&mut v, 1, 5, 9, 13, m[round[2]], m[round[3]]);
        g(&mut v, 2, 6, 10, 14, m[round[4]], m[round[5]]);
        g(&mut v, 3, 7, 11, 15, m[round[6]], m[round[7]]);
        g(&mut v, 0, 5, 10, 15, m[round[8]], m[round[9]]);
        g(&mut v, 1, 6, 11, 12, m[round[10]], m[round[11]]);
        g(&mut v, 2, 7, 8, 13, m[round[12]], m[round[13]]);
        g(&mut v, 3, 4, 9, 14, m[round[14]], m[round[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with a 32-byte digest and no key (what Go's `blake2b.Sum256`
/// computes, `salamander.go:50`).
pub(super) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    // Parameter block: digest length 32, key length 0, fanout 1, depth 1.
    h[0] ^= 0x0101_0000 ^ 32;
    let mut t = 0u128;
    // Compress all full 128-byte blocks except the trailing chunk, which is
    // zero-padded into the final block and gets the finalization flag.
    let full_blocks = data.len() / 128;
    let head_len = if data.len().is_multiple_of(128) && full_blocks > 0 {
        (full_blocks - 1) * 128
    } else {
        full_blocks * 128
    };
    let (head, tail) = data.split_at(head_len);
    for chunk in head.chunks_exact(128) {
        let mut block = [0u8; 128];
        block.copy_from_slice(chunk);
        t += 128;
        blake2b_compress(&mut h, &block, t, false);
    }
    let mut last_block = [0u8; 128];
    last_block[..tail.len()].copy_from_slice(tail);
    t += tail.len() as u128;
    blake2b_compress(&mut h, &last_block, t, true);
    let mut out = [0u8; 32];
    for (i, word) in h[..4].iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// Salamander obfuscation (sing-quic hysteria2/salamander.go).

pub(super) const SALAMANDER_SALT_LEN: usize = 8;

/// Encrypt one datagram: 8-byte random salt, then payload XORed with
/// BLAKE2b-256(password ++ salt) cycled (`salamander.go:57-70`).
pub(super) fn salamander_seal(password: &[u8], data: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALAMANDER_SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let mut key_input = Vec::with_capacity(password.len() + SALAMANDER_SALT_LEN);
    key_input.extend_from_slice(password);
    key_input.extend_from_slice(&salt);
    let key = blake2b256(&key_input);
    let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + data.len());
    out.extend_from_slice(&salt);
    out.extend(data.iter().enumerate().map(|(i, b)| b ^ key[i % 32]));
    out
}

/// Decrypt a datagram in place, returning the payload length (the salt is
/// compacted away), or `None` for malformed packets (`salamander.go:42-55`).
pub(super) fn salamander_open(password: &[u8], buf: &mut [u8]) -> Option<usize> {
    if buf.len() <= SALAMANDER_SALT_LEN {
        return None;
    }
    let mut key_input = Vec::with_capacity(password.len() + SALAMANDER_SALT_LEN);
    key_input.extend_from_slice(password);
    key_input.extend_from_slice(&buf[..SALAMANDER_SALT_LEN]);
    let key = blake2b256(&key_input);
    let len = buf.len() - SALAMANDER_SALT_LEN;
    for i in 0..len {
        buf[i] = buf[i + SALAMANDER_SALT_LEN] ^ key[i % 32];
    }
    Some(len)
}

/// quinn `AsyncUdpSocket` that applies salamander obfuscation to every
/// datagram, letting QUIC run transparently over the obfuscated channel
/// (`client.go:275-277`).
///
/// Built directly on a tokio socket (no GSO/GRO segmentation), so every
/// `Transmit`/`RecvMeta` carries exactly one datagram to (de)obfuscate.
#[derive(Debug)]
pub(super) struct SalamanderSocket {
    socket: Arc<tokio::net::UdpSocket>,
    password: Arc<[u8]>,
}

impl SalamanderSocket {
    fn new(ipv6: bool, password: Arc<[u8]>) -> io::Result<Self> {
        let std_socket = crate::quic::marked_udp_socket(ipv6)?;
        let socket = tokio::net::UdpSocket::from_std(std_socket)?;
        Ok(Self {
            socket: Arc::new(socket),
            password,
        })
    }
}

#[derive(Debug)]
pub(super) struct SalamanderPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderPoller {
            socket: Arc::clone(&self.socket),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let packet = salamander_seal(&self.password, transmit.contents);
        self.socket.try_send_to(&packet, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            let mut read_buf = ReadBuf::new(&mut buf[..]);
            match self.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(addr)) => {
                    if let Some(len) = salamander_open(&self.password, read_buf.filled_mut()) {
                        *meta_slot = quinn::udp::RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        count += 1;
                    }
                    // Malformed obfuscated packets are dropped.
                }
                Poll::Ready(Err(e)) => {
                    return if count == 0 {
                        Poll::Ready(Err(e))
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
                Poll::Pending => {
                    return if count == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The tokio socket does not set DONTFRAG; reporting `true` also keeps
    /// quinn's MTU discovery off the obfuscated path (the +8 byte salt would
    /// otherwise skew probe sizes).
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Endpoint factory for salamander-obfuscated QUIC connections.
pub(super) fn salamander_endpoint_factory(
    password: Arc<[u8]>,
) -> impl Fn(bool) -> io::Result<Endpoint> + Send + Sync {
    move |ipv6| {
        let socket = Arc::new(SalamanderSocket::new(ipv6, Arc::clone(&password))?);
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
        Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, socket, runtime)
    }
}
