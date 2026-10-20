//! Real-backend workloads: one production handler and one in-bench loopback
//! peer, driven through the ordinary path (registry dial -> `install_flow`,
//! one association per destination) and through the Shared source path
//! (`prepare_source` -> one association for the client), single destination
//! and same-client two destinations. Pairs differ only in the core path.
//!
//! The peers are tiny echo servers written against the wire formats, not the
//! production codecs: Shadowsocks AEAD (`aes-128-gcm`) over UDP, SOCKS5
//! ASSOCIATE with a UDP relay, plain-TCP Trojan UDP associate. Their cost is
//! the same for both paths of a pair and is part of every ns/pkt.

use super::{Workload, bench_workload, runtime};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use criterion::Criterion;
use hkdf::Hkdf;
use honk_core::control::udp_endpoint::bench_support::real_io::{Backend, IoHarness};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;
const IPV4_ADDR_LEN: usize = 7;

/// Shadowsocks legacy AEAD UDP echo: `salt | AEAD(addr | payload)`, zero
/// nonce, HKDF-SHA1 subkey. Replies to the datagram's source with the same
/// inner address, so the client sees the destination as the reply peer.
async fn shadowsocks_peer() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("peer bind");
    let address = socket.local_addr().expect("peer address");
    // EVP_BytesToKey(MD5) of one block is the whole 16-byte aes-128-gcm key.
    let master = Md5::digest(Backend::PASSWORD.as_bytes());
    let subkey = move |salt: &[u8]| {
        let mut key = [0u8; 16];
        Hkdf::<Sha1>::new(Some(salt), &master)
            .expand(b"ss-subkey", &mut key)
            .expect("hkdf length");
        Aes128Gcm::new_from_slice(&key).expect("subkey")
    };
    tokio::spawn(async move {
        let nonce = Nonce::default();
        let mut buf = [0u8; 2048];
        let mut replies = 0u64;
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.expect("peer recv");
            let body = n - SALT_LEN - TAG_LEN;
            let cipher = subkey(&buf[..SALT_LEN]);
            let tag = Tag::try_from(&buf[n - TAG_LEN..n]).expect("tag");
            cipher
                .decrypt_inout_detached(
                    &nonce,
                    b"",
                    InOutBuf::from(&mut buf[SALT_LEN..SALT_LEN + body]),
                    &tag,
                )
                .expect("client datagram authenticates");
            replies += 1;
            buf[..SALT_LEN].fill(0);
            buf[..8].copy_from_slice(&replies.to_be_bytes());
            let cipher = subkey(&buf[..SALT_LEN]);
            let tag = cipher
                .encrypt_inout_detached(
                    &nonce,
                    b"",
                    InOutBuf::from(&mut buf[SALT_LEN..SALT_LEN + body]),
                )
                .expect("seal");
            buf[SALT_LEN + body..n].copy_from_slice(&tag);
            socket.send_to(&buf[..n], from).await.expect("peer send");
        }
    });
    address
}

/// SOCKS5 server with no auth: each UDP ASSOCIATE gets its own relay socket
/// that echoes every datagram (header included, so the reply names the
/// destination) back to its sender until the control connection closes.
async fn socks5_serve(mut control: TcpStream) -> io::Result<()> {
    let mut greeting = [0u8; 3];
    control.read_exact(&mut greeting).await?;
    control.write_all(&[5, 0]).await?;
    let mut request = [0u8; 10];
    control.read_exact(&mut request).await?;
    let relay = UdpSocket::bind("127.0.0.1:0").await?;
    let mut reply = [5, 0, 0, 1, 127, 0, 0, 1, 0, 0];
    reply[8..].copy_from_slice(&relay.local_addr()?.port().to_be_bytes());
    control.write_all(&reply).await?;
    let mut buf = [0u8; 2048];
    let mut eof = [0u8; 1];
    loop {
        tokio::select! {
            received = relay.recv_from(&mut buf) => {
                let (n, from) = received?;
                relay.send_to(&buf[..n], from).await?;
            }
            closed = control.read(&mut eof) => {
                if closed? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

/// Trojan UDP associate over plain TCP: the request names the first
/// destination; every frame (`ATYP IPv4 | port | len | CRLF | payload`) is
/// echoed back unchanged, so the reply frame names the destination.
async fn trojan_serve(socket: TcpStream) -> io::Result<()> {
    socket.set_nodelay(true)?;
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    // hex(sha224) CRLF cmd addr CRLF
    let mut request = [0u8; 56 + 2 + 1 + IPV4_ADDR_LEN + 2];
    reader.read_exact(&mut request).await?;
    let mut frame = [0u8; 11 + 2048];
    loop {
        reader.read_exact(&mut frame[..11]).await?;
        let len = usize::from(u16::from_be_bytes([frame[7], frame[8]]));
        reader.read_exact(&mut frame[11..11 + len]).await?;
        writer.write_all(&frame[..11 + len]).await?;
    }
}

async fn tcp_peer<F, Fut>(serve: F) -> SocketAddr
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("peer bind");
    let address = listener.local_addr().expect("peer address");
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve(socket));
        }
    });
    address
}

async fn start_peer(backend: Backend) -> SocketAddr {
    match backend {
        Backend::Shadowsocks => shadowsocks_peer().await,
        Backend::Socks5 => tcp_peer(socks5_serve).await,
        Backend::Trojan => tcp_peer(trojan_serve).await,
        _ => unreachable!("no loopback peer for {backend:?}"),
    }
}

fn real(name: &'static str, backend: Backend, shared: bool, destinations: usize) -> Workload {
    let rt = runtime();
    let harness = rt.block_on(async {
        let server = start_peer(backend).await;
        let mut harness = IoHarness::new(destinations).await.expect("harness");
        for destination in 0..destinations {
            if shared {
                harness
                    .install_backend_source(destination, backend, server)
                    .await
                    .expect("install shared source");
            } else {
                harness
                    .install_backend_flow(destination, backend, server)
                    .await
                    .expect("install ordinary flow");
            }
        }
        harness
    });
    Workload {
        name,
        harness,
        rt,
        measured: (0..destinations).collect(),
        background: None,
        gate: None,
    }
}

pub(super) fn bench(c: &mut Criterion) {
    for (protocol, backend) in [
        ("ss", Backend::Shadowsocks),
        ("socks5", Backend::Socks5),
        ("trojan", Backend::Trojan),
    ] {
        for (path, shared) in [("ordinary", false), ("shared", true)] {
            for (shape, destinations) in [("single", 1), ("two_dest", 2)] {
                let name = format!("{protocol}_{path}_{shape}").leak();
                bench_workload(c, real(name, backend, shared, destinations));
            }
        }
    }
}
